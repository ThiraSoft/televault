package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/downloader"
	"github.com/gotd/td/telegram/uploader"
	"github.com/gotd/td/tg"
)

//go:embed web/index.html
var webFS embed.FS

// tgMu serializes Telegram API calls to avoid concurrent request issues.
var tgMu sync.Mutex

func startWeb(ctx context.Context, index *FileIndex, port string) {
	runWithClient(ctx, func(ctx context.Context, client *telegram.Client, api *tg.Client) error {
		webSub, _ := fs.Sub(webFS, "web")
		mux := http.NewServeMux()
		mux.Handle("/", http.FileServer(http.FS(webSub)))
		mux.HandleFunc("/api/files", func(w http.ResponseWriter, r *http.Request) {
			// GET /api/files — list
			// DELETE /api/files/{id}
			if r.Method == http.MethodGet && r.URL.Path == "/api/files" {
				handleListFiles(w, r, index)
				return
			}
			if r.Method == http.MethodDelete {
				handleDeleteFile(w, r, ctx, api, index)
				return
			}
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		})
		mux.HandleFunc("/api/files/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				handleDeleteFile(w, r, ctx, api, index)
				return
			}
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		})
		mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleUpload(w, r, ctx, api, index)
		})
		mux.HandleFunc("/api/download/", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleDownload(w, r, ctx, api, index)
		})
		mux.HandleFunc("/api/sync", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handleSync(w, r, ctx, api, index)
		})

		fmt.Printf("\n  TELEVAULT Web UI\n  http://localhost:%s\n\n", port)
		server := &http.Server{Addr: ":" + port, Handler: mux}
		go func() {
			<-ctx.Done()
			server.Close()
		}()
		return server.ListenAndServe()
	})
}

// --- Handlers ---

func handleListFiles(w http.ResponseWriter, _ *http.Request, index *FileIndex) {
	index.mu.Lock()
	entries := make([]FileEntry, 0, len(index.Files))
	for _, f := range index.Files {
		entries = append(entries, f)
	}
	index.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func handleUpload(w http.ResponseWriter, r *http.Request, ctx context.Context, api *tg.Client, index *FileIndex) {
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Save to temp file
	tmpPath := filepath.Join(os.TempDir(), "vault-web-"+generateID())
	tmp, err := os.Create(tmpPath)
	if err != nil {
		http.Error(w, "temp file: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(tmp, file); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmp.Close()
	defer os.Remove(tmpPath)

	// Encrypt
	encPath, err := encryptFile(tmpPath, header.Filename)
	if err != nil {
		http.Error(w, "encrypt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(encPath)

	// Upload to Telegram
	tgMu.Lock()
	defer tgMu.Unlock()

	remoteName := generateID()
	encInfo, err := os.Stat(encPath)
	if err != nil {
		http.Error(w, "stat: "+err.Error(), http.StatusInternalServerError)
		return
	}

	u := uploader.NewUploader(api)
	f, err := u.FromPath(ctx, encPath)
	if err != nil {
		http.Error(w, "tg upload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	randID, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	updates, err := api.MessagesSendMedia(ctx, &tg.MessagesSendMediaRequest{
		Peer:     &tg.InputPeerSelf{},
		Media:    &tg.InputMediaUploadedDocument{File: f, Attributes: []tg.DocumentAttributeClass{&tg.DocumentAttributeFilename{FileName: remoteName}}},
		Message:  "Vault Secure Storage",
		RandomID: randID.Int64(),
	})
	if err != nil {
		http.Error(w, "tg send: "+err.Error(), http.StatusInternalServerError)
		return
	}

	msgID := extractMsgID(updates)
	if msgID == 0 {
		http.Error(w, "could not get message ID", http.StatusInternalServerError)
		return
	}

	// path = relative path sent by frontend (e.g. "photos/vacation/beach.jpg")
	filePath := r.FormValue("path")
	if filePath == "" {
		filePath = header.Filename
	}

	index.AddNoSave(FileEntry{
		ID: msgID, Name: header.Filename, Path: filePath, RemoteName: remoteName,
		Size: encInfo.Size(), UploadAt: time.Now(),
	})
	if err := index.SaveEncrypted(); err != nil {
		http.Error(w, "save index: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": msgID, "name": header.Filename})
}

func handleDownload(w http.ResponseWriter, r *http.Request, ctx context.Context, api *tg.Client, index *FileIndex) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/download/")
	msgID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	tgMu.Lock()
	defer tgMu.Unlock()

	msgs, err := api.MessagesGetMessages(ctx, []tg.InputMessageClass{&tg.InputMessageID{ID: msgID}})
	if err != nil {
		http.Error(w, "tg: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var doc *tg.Document
	switch m := msgs.(type) {
	case *tg.MessagesMessages:
		if len(m.Messages) > 0 {
			doc = extractDoc(m.Messages[0])
		}
	case *tg.MessagesMessagesSlice:
		if len(m.Messages) > 0 {
			doc = extractDoc(m.Messages[0])
		}
	}
	if doc == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	tmpPath := filepath.Join(os.TempDir(), "vault-web-dl-"+generateID())
	d := downloader.NewDownloader()
	_, err = d.Download(api, &tg.InputDocumentFileLocation{ID: doc.ID, AccessHash: doc.AccessHash, FileReference: doc.FileReference}).ToPath(ctx, tmpPath)
	if err != nil {
		http.Error(w, "download: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(tmpPath)

	// Decrypt to temp
	outDir := os.TempDir()
	outPath, err := decryptFile(tmpPath, outDir)
	if err != nil {
		http.Error(w, "decrypt: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(outPath)

	// Lookup name from index
	name := filepath.Base(outPath)
	index.mu.Lock()
	if entry, ok := index.Files[msgID]; ok {
		name = entry.Name
	}
	index.mu.Unlock()

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, outPath)
}

func handleDeleteFile(w http.ResponseWriter, r *http.Request, ctx context.Context, api *tg.Client, index *FileIndex) {
	idStr := strings.TrimPrefix(r.URL.Path, "/api/files/")
	msgID, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	tgMu.Lock()
	_, err = api.MessagesDeleteMessages(ctx, &tg.MessagesDeleteMessagesRequest{ID: []int{msgID}})
	tgMu.Unlock()
	if err != nil {
		http.Error(w, "tg delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	index.mu.Lock()
	delete(index.Files, msgID)
	err = index.saveEncryptedLocked()
	index.mu.Unlock()
	if err != nil {
		http.Error(w, "save index: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleSync(w http.ResponseWriter, _ *http.Request, ctx context.Context, api *tg.Client, index *FileIndex) {
	tgMu.Lock()
	added, removed, err := webSync(ctx, api, index)
	tgMu.Unlock()
	if err != nil {
		http.Error(w, "sync: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]int{"added": added, "removed": removed})
}

// --- Crypto helpers for web (standalone encrypt/decrypt without CLI output) ---

func encryptFile(srcPath, originalName string) (string, error) {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()
	stat, err := srcFile.Stat()
	if err != nil {
		return "", err
	}

	encPath := filepath.Join(os.TempDir(), "vault-enc-"+generateID())
	dstFile, err := os.Create(encPath)
	if err != nil {
		return "", err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	dstFile.Write(salt)
	encKey, macKey := deriveKeys([]byte(vaultKey), salt)

	header := SecureHeader{
		OriginalName: originalName,
		Size:         stat.Size(),
		Mode:         stat.Mode(),
		CreatedAt:    time.Now(),
	}
	var hBuf bytes.Buffer
	if err := gob.NewEncoder(&hBuf).Encode(header); err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	encHeader := gcm.Seal(nonce, nonce, hBuf.Bytes(), nil)
	binary.Write(dstFile, binary.LittleEndian, uint32(len(encHeader)))
	dstFile.Write(encHeader)

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	dstFile.Write(iv)
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, macKey)
	if _, err := io.Copy(&cipher.StreamWriter{S: stream, W: io.MultiWriter(dstFile, mac)}, srcFile); err != nil {
		dstFile.Close()
		os.Remove(encPath)
		return "", err
	}
	dstFile.Write(mac.Sum(nil))
	dstFile.Close()

	return encPath, nil
}

func decryptFile(encPath, outDir string) (string, error) {
	inFile, err := os.Open(encPath)
	if err != nil {
		return "", err
	}
	defer inFile.Close()

	salt := make([]byte, 16)
	if _, err := io.ReadFull(inFile, salt); err != nil {
		return "", err
	}
	encKey, macKey := deriveKeys([]byte(vaultKey), salt)

	var hLen uint32
	if err := binary.Read(inFile, binary.LittleEndian, &hLen); err != nil {
		return "", err
	}
	if hLen > maxHeaderLen {
		return "", fmt.Errorf("header too large: %d", hLen)
	}
	encH := make([]byte, hLen)
	if _, err := io.ReadFull(inFile, encH); err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(encH) < gcm.NonceSize() {
		return "", fmt.Errorf("header corrupt")
	}
	nonceH, cipherH := encH[:gcm.NonceSize()], encH[gcm.NonceSize():]
	plainH, err := gcm.Open(nil, nonceH, cipherH, nil)
	if err != nil {
		return "", fmt.Errorf("bad password")
	}

	var h SecureHeader
	if err := gob.NewDecoder(bytes.NewReader(plainH)).Decode(&h); err != nil {
		return "", err
	}

	outPath := filepath.Join(outDir, h.OriginalName)
	outFile, err := os.Create(outPath)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(inFile, iv); err != nil {
		outFile.Close()
		os.Remove(outPath)
		return "", err
	}
	mac := hmac.New(sha256.New, macKey)
	limitR := io.LimitReader(inFile, h.Size)
	stream := cipher.NewCTR(block, iv)
	tee := io.TeeReader(limitR, mac)
	reader := &cipher.StreamReader{S: stream, R: tee}

	if _, err := io.Copy(outFile, reader); err != nil {
		outFile.Close()
		os.Remove(outPath)
		return "", err
	}

	expected := make([]byte, 32)
	if _, err := io.ReadFull(inFile, expected); err != nil {
		outFile.Close()
		os.Remove(outPath)
		return "", err
	}
	outFile.Close()

	if !hmac.Equal(mac.Sum(nil), expected) {
		os.Remove(outPath)
		return "", fmt.Errorf("MAC invalid")
	}

	return outPath, nil
}

// webSync is a sync variant that returns counts instead of printing to stdout.
func webSync(ctx context.Context, api *tg.Client, index *FileIndex) (added, removed int, err error) {
	var offsetID int
	limit := 50
	seenIDs := make(map[int]bool)

	for {
		hist, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerSelf{}, Limit: limit, OffsetID: offsetID})
		if err != nil {
			return 0, 0, err
		}

		var msgs []tg.MessageClass
		switch h := hist.(type) {
		case *tg.MessagesMessages:
			msgs = h.Messages
		case *tg.MessagesMessagesSlice:
			msgs = h.Messages
		case *tg.MessagesChannelMessages:
			msgs = h.Messages
		default:
			return 0, 0, fmt.Errorf("unknown type: %T", hist)
		}

		if len(msgs) == 0 {
			break
		}

		for _, m := range msgs {
			if msg, ok := m.(*tg.Message); ok {
				offsetID = msg.ID
			} else if msg, ok := m.(*tg.MessageService); ok {
				offsetID = msg.ID
			}
		}

		for _, m := range msgs {
			msg, ok := m.(*tg.Message)
			if !ok {
				continue
			}
			doc := extractDoc(msg)
			if doc == nil {
				continue
			}
			remoteName := "unknown"
			for _, a := range doc.Attributes {
				if fn, ok := a.(*tg.DocumentAttributeFilename); ok {
					remoteName = fn.FileName
				}
			}
			if !strings.HasSuffix(remoteName, ".vault") {
				continue
			}
			seenIDs[msg.ID] = true
			if _, ok := index.Files[msg.ID]; ok {
				continue
			}

			chunk, cerr := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
				Location: &tg.InputDocumentFileLocation{ID: doc.ID, AccessHash: doc.AccessHash, FileReference: doc.FileReference},
				Offset:   0, Limit: 4096,
			})
			if cerr != nil {
				continue
			}
			var data []byte
			switch c := chunk.(type) {
			case *tg.UploadFile:
				data = c.Bytes
			default:
				continue
			}
			if len(data) < 20 {
				continue
			}

			r := bytes.NewReader(data)
			salt := make([]byte, 16)
			io.ReadFull(r, salt)
			encKey, _ := deriveKeys([]byte(vaultKey), salt)
			var hLen uint32
			binary.Read(r, binary.LittleEndian, &hLen)
			if hLen > maxHeaderLen {
				continue
			}

			if int64(len(data)) < 16+4+int64(hLen) {
				index.AddNoSave(FileEntry{ID: msg.ID, Name: "??? (Need DL)", RemoteName: remoteName, Size: doc.Size, UploadAt: time.Unix(int64(msg.Date), 0)})
				continue
			}

			encH := make([]byte, hLen)
			r.Read(encH)
			block, berr := aes.NewCipher(encKey)
			if berr != nil {
				continue
			}
			gcm, gerr := cipher.NewGCM(block)
			if gerr != nil {
				continue
			}
			if len(encH) < gcm.NonceSize() {
				continue
			}
			nonce, ciphertext := encH[:gcm.NonceSize()], encH[gcm.NonceSize():]
			plainH, perr := gcm.Open(nil, nonce, ciphertext, nil)
			if perr == nil {
				var h SecureHeader
				if err := gob.NewDecoder(bytes.NewReader(plainH)).Decode(&h); err == nil {
					index.AddNoSave(FileEntry{ID: msg.ID, Name: h.OriginalName, RemoteName: remoteName, Size: doc.Size, UploadAt: time.Unix(int64(msg.Date), 0)})
					added++
				}
			}
		}
		if len(msgs) < limit {
			break
		}
	}

	index.mu.Lock()
	for id := range index.Files {
		if !seenIDs[id] {
			delete(index.Files, id)
			removed++
		}
	}
	index.mu.Unlock()

	if err := index.SaveEncrypted(); err != nil {
		return added, removed, err
	}
	return added, removed, nil
}
