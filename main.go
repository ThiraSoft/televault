package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/telegram/downloader"
	"github.com/gotd/td/telegram/uploader"
	"github.com/gotd/td/tg"
	gonanoid "github.com/matoous/go-nanoid/v2"
)

// --- Config ---

var (
	appID    int
	appHash  string
	phoneNum string
	vaultKey string
)

const (
	ITERATIONS = 600000
	VERSION    = "v6.7-ANTI-BAN"
)

func init() {
	appID, _ = strconv.Atoi(os.Getenv("TELEGRAM_APP_ID"))
	appHash = os.Getenv("TELEGRAM_APP_HASH")
	phoneNum = os.Getenv("TELEGRAM_PHONE")
	vaultKey = os.Getenv("VAULT_KEY")
}

// --- Structures ---

type FileEntry struct {
	ID         int       `json:"id"`
	Name       string    `json:"name"`
	RemoteName string    `json:"remote_name"`
	Size       int64     `json:"size"`
	UploadAt   time.Time `json:"uploaded_at"`
}

type FileIndex struct {
	Files map[int]FileEntry `json:"files"`
	Path  string            `json:"-"`
	mu    sync.Mutex        `json:"-"`
}

type SecureHeader struct {
	OriginalName string
	Size         int64
	Mode         os.FileMode
	CreatedAt    time.Time
}

// --- Crypto Core ---

func pbkdf2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	U := make([]byte, hashLen)
	T := make([]byte, hashLen)
	block1 := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		block1[0] = byte(block >> 24)
		block1[1] = byte(block >> 16)
		block1[2] = byte(block >> 8)
		block1[3] = byte(block)
		prf.Reset()
		prf.Write(salt)
		prf.Write(block1)
		copy(U, prf.Sum(nil))
		copy(T, U)
		for r := 1; r < iter; r++ {
			prf.Reset()
			prf.Write(U)
			copy(U, prf.Sum(nil))
			for i := 0; i < hashLen; i++ {
				T[i] ^= U[i]
			}
		}
		dk = append(dk, T...)
	}
	return dk[:keyLen]
}

func deriveKey(password, salt []byte) []byte {
	return pbkdf2(password, salt, ITERATIONS, 32, sha256.New)
}

func generateID() string {
	alphabet := "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	id, _ := gonanoid.Generate(alphabet, 21)
	return id + ".vault"
}

// --- Index Encryption ---

func (idx *FileIndex) SaveEncrypted() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	jsonData, err := json.Marshal(idx.Files)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	key := deriveKey([]byte(vaultKey), salt)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encryptedData := gcm.Seal(nonce, nonce, jsonData, nil)
	f, err := os.Create(idx.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	f.Write(salt)
	f.Write(encryptedData)
	return nil
}

func (idx *FileIndex) LoadEncrypted() error {
	idx.mu.Lock()
	defer idx.mu.Unlock()
	f, err := os.Open(idx.Path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	salt := make([]byte, 16)
	if _, err := io.ReadFull(f, salt); err != nil {
		return err
	}
	key := deriveKey([]byte(vaultKey), salt)
	encryptedData, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(encryptedData) < gcm.NonceSize() {
		return fmt.Errorf("corrupt")
	}
	nonce, ciphertext := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("bad key")
	}
	return json.Unmarshal(plaintext, &idx.Files)
}

// --- Main ---

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}
	if appID == 0 || vaultKey == "" {
		fmt.Println("❌ Erreur config (ENV)")
		return
	}
	index := NewIndex()
	index.LoadEncrypted()
	ctx := context.Background()

	switch os.Args[1] {
	case "upload", "up":
		if len(os.Args) < 3 {
			fmt.Println("Usage: upload <file_or_dir> [file2] ...")
			return
		}
		filesToUpload := gatherFiles(os.Args[2:])
		if len(filesToUpload) == 0 {
			fmt.Println("❌ Aucun fichier trouvé.")
			return
		}
		if len(filesToUpload) > 1 {
			fmt.Printf("📦 Upload batch: %d fichiers\n", len(filesToUpload))
		}
		runWithClient(ctx, func(ctx context.Context, client *telegram.Client, api *tg.Client) error {
			for i, file := range filesToUpload {
				if err := upload(ctx, api, index, file); err != nil {
					fmt.Printf("❌ Echec: %v\n", err)
				}

				// --- ANTI-BAN DELAY ---
				// Si ce n'est pas le dernier fichier, on attend un peu
				if i < len(filesToUpload)-1 {
					// Génère un nombre entre 0 et 4
					n, _ := rand.Int(rand.Reader, big.NewInt(5))
					// Délai total = 2s + (0..4s) = 2 à 6 secondes
					delay := time.Duration(n.Int64()+2) * time.Second
					fmt.Printf("⏳ Pause tactique anti-ban (%s)...\n", delay)
					time.Sleep(delay)
				}
			}
			return nil
		})

	case "download", "dl":
		if len(os.Args) < 3 {
			fmt.Println("Usage: download <id> [id2] ... [out_dir]")
			return
		}

		var ids []int
		outDir := "."

		for _, arg := range os.Args[2:] {
			if id, err := strconv.Atoi(arg); err == nil {
				ids = append(ids, id)
			} else {
				outDir = arg
			}
		}

		if len(ids) == 0 {
			fmt.Println("❌ Aucun ID valide fourni.")
			return
		}

		if len(ids) == 1 {
			fmt.Printf("📥  Download vers '%s'\n", outDir)
		} else {
			fmt.Printf("📥  Batch Download: %d fichiers vers '%s'\n", len(ids), outDir)
		}

		runWithClient(ctx, func(ctx context.Context, client *telegram.Client, api *tg.Client) error {
			for _, id := range ids {
				if err := download(ctx, api, index, id, outDir); err != nil {
					fmt.Printf("❌ Echec: %v\n", err)
				}
			}
			return nil
		})

	case "list", "ls":
		listLocal(index)
	case "sync", "s":
		runWithClient(ctx, func(ctx context.Context, client *telegram.Client, api *tg.Client) error {
			return syncFromTelegram(ctx, api, index)
		})
	case "remove", "rm":
		if len(os.Args) < 3 {
			fmt.Println("Usage: remove <id> [id2] ...")
			return
		}

		var ids []int
		for _, arg := range os.Args[2:] {
			if id, err := strconv.Atoi(arg); err == nil {
				ids = append(ids, id)
			} else {
				fmt.Printf("⚠️ ID invalide ignoré: %s\n", arg)
			}
		}

		if len(ids) == 0 {
			fmt.Println("❌ Aucun ID valide.")
			return
		}

		if len(ids) > 1 {
			fmt.Printf("🗑️  Batch Remove: %d fichiers à supprimer.\n", len(ids))
		}

		runWithClient(ctx, func(ctx context.Context, client *telegram.Client, api *tg.Client) error {
			for _, id := range ids {
				if err := deleteFile(ctx, api, index, id); err != nil {
					fmt.Printf("❌ Echec suppression ID %d: %v\n", id, err)
				}
			}
			return nil
		})
	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println(`Televault ` + VERSION + `
  up, upload <path>...       Encrypted Upload (Recursive)
  dl, download <id>... [out] Decrypted Download (Batch)
  ls, list                  List Index
  s, sync                   Smart Sync
  rm, remove <id>...        Delete File (Batch)`)
}

// --- Helpers Batch ---

func gatherFiles(paths []string) []string {
	var files []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("⚠️ Ignoré (inaccessible): %s\n", path)
			continue
		}
		if info.IsDir() {
			filepath.Walk(path, func(p string, i os.FileInfo, err error) error {
				if err == nil && !i.IsDir() {
					files = append(files, p)
				}
				return nil
			})
		} else {
			files = append(files, path)
		}
	}
	return files
}

// --- Actions ---

func upload(ctx context.Context, api *tg.Client, index *FileIndex, filePath string) error {
	srcFile, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()
	stat, _ := srcFile.Stat()

	tmpPath := filepath.Join(os.TempDir(), "vault-"+generateID())
	dstFile, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	// Crypto
	salt := make([]byte, 16)
	rand.Read(salt)
	dstFile.Write(salt)
	masterKey := deriveKey([]byte(vaultKey), salt)

	// AJOUT MODE DANS LE HEADER
	header := SecureHeader{
		OriginalName: filepath.Base(filePath),
		Size:         stat.Size(),
		Mode:         stat.Mode(),
		CreatedAt:    time.Now(),
	}
	var hBuf bytes.Buffer
	gob.NewEncoder(&hBuf).Encode(header)

	block, _ := aes.NewCipher(masterKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	encHeader := gcm.Seal(nonce, nonce, hBuf.Bytes(), nil)
	binary.Write(dstFile, binary.LittleEndian, uint32(len(encHeader)))
	dstFile.Write(encHeader)

	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	dstFile.Write(iv)
	stream := cipher.NewCTR(block, iv)
	mac := hmac.New(sha256.New, masterKey)
	io.Copy(&cipher.StreamWriter{S: stream, W: io.MultiWriter(dstFile, mac)}, srcFile)
	dstFile.Write(mac.Sum(nil))
	dstFile.Close()
	defer os.Remove(tmpPath)

	// Upload
	remoteName := generateID()
	tmpInfo, _ := os.Stat(tmpPath)
	fmt.Printf("📤 Upload %.2f MB...", float64(tmpInfo.Size())/1024/1024)
	u := uploader.NewUploader(api).WithProgress(progress{total: tmpInfo.Size()})
	f, err := u.FromPath(ctx, tmpPath)
	if err != nil {
		return err
	}

	randID, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	updates, err := api.MessagesSendMedia(ctx, &tg.MessagesSendMediaRequest{
		Peer:     &tg.InputPeerSelf{},
		Media:    &tg.InputMediaUploadedDocument{File: f, Attributes: []tg.DocumentAttributeClass{&tg.DocumentAttributeFilename{FileName: remoteName}}},
		Message:  "🔒 Vault Secure Storage",
		RandomID: randID.Int64(),
	})
	if err != nil {
		return err
	}

	var msgID int
	switch u := updates.(type) {
	case *tg.Updates:
		for _, upd := range u.Updates {
			if m, ok := upd.(*tg.UpdateMessageID); ok {
				msgID = m.ID
				break
			}
			if m, ok := upd.(*tg.UpdateNewMessage); ok {
				if msg, ok := m.Message.(*tg.Message); ok {
					msgID = msg.ID
					break
				}
			}
		}
	case *tg.UpdatesCombined:
		for _, upd := range u.Updates {
			if m, ok := upd.(*tg.UpdateMessageID); ok {
				msgID = m.ID
				break
			}
			if m, ok := upd.(*tg.UpdateNewMessage); ok {
				if msg, ok := m.Message.(*tg.Message); ok {
					msgID = msg.ID
					break
				}
			}
		}
	case *tg.UpdateShortSentMessage:
		msgID = u.ID
	}

	if msgID != 0 {
		index.Add(FileEntry{ID: msgID, Name: filepath.Base(filePath), RemoteName: remoteName, Size: stat.Size(), UploadAt: time.Now()})
		fmt.Printf(" ✓  ID: %d  %s\n", msgID, header.OriginalName)
	} else {
		fmt.Println(" ⚠️ ID perdu (faire sync)")
	}
	return nil
}

func download(ctx context.Context, api *tg.Client, index *FileIndex, msgID int, outDir string) error {
	msgs, err := api.MessagesGetMessages(ctx, []tg.InputMessageClass{&tg.InputMessageID{ID: msgID}})
	if err != nil {
		return err
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
		return fmt.Errorf("not found")
	}

	tmpPath := filepath.Join(os.TempDir(), "vault-dl-"+generateID())
	fmt.Printf("Download (%.2f MB)...  ", float64(doc.Size)/1024/1024)
	d := downloader.NewDownloader()
	_, err = d.Download(api, &tg.InputDocumentFileLocation{ID: doc.ID, AccessHash: doc.AccessHash, FileReference: doc.FileReference}).ToPath(ctx, tmpPath)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	fmt.Print("Decrypt...  ")
	inFile, err := os.Open(tmpPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	salt := make([]byte, 16)
	io.ReadFull(inFile, salt)
	masterKey := deriveKey([]byte(vaultKey), salt)

	var hLen uint32
	binary.Read(inFile, binary.LittleEndian, &hLen)
	encH := make([]byte, hLen)
	io.ReadFull(inFile, encH)

	block, _ := aes.NewCipher(masterKey)
	gcm, _ := cipher.NewGCM(block)

	nonce, ciphertext := encH[:gcm.NonceSize()], encH[gcm.NonceSize():]
	plainH, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("bad password")
	}

	var h SecureHeader
	gob.NewDecoder(bytes.NewReader(plainH)).Decode(&h)

	outPath := filepath.Join(outDir, h.OriginalName)
	if info, err := os.Stat(outDir); err == nil && !info.IsDir() {
		outPath = outDir
	}
	outFile, err := os.Create(outPath)
	if err != nil {
		return err
	}

	iv := make([]byte, aes.BlockSize)
	io.ReadFull(inFile, iv)
	mac := hmac.New(sha256.New, masterKey)
	limitR := io.LimitReader(inFile, h.Size)

	stream := cipher.NewCTR(block, iv)
	tee := io.TeeReader(limitR, mac)
	reader := &cipher.StreamReader{S: stream, R: tee}

	if _, err := io.Copy(outFile, reader); err != nil {
		outFile.Close()
		return err
	}

	expected := make([]byte, 32)
	io.ReadFull(inFile, expected)

	outFile.Close() // Close before chmod

	if !hmac.Equal(mac.Sum(nil), expected) {
		os.Remove(outPath)
		return fmt.Errorf("MAC invalid")
	}

	// RESTAURATION PERMISSIONS
	restoreMode := h.Mode
	if restoreMode == 0 {
		restoreMode = 0o644
	}
	if err := os.Chmod(outPath, restoreMode); err != nil {
		fmt.Printf("⚠️ Impossible de restaurer permissions: %v\n", err)
	}

	fmt.Printf("✓  Saved: %s\n", outPath)
	return nil
}

func deleteFile(ctx context.Context, api *tg.Client, index *FileIndex, msgID int) error {
	fmt.Printf("🗑️  Suppression ID %d... ", msgID)
	_, err := api.MessagesDeleteMessages(ctx, &tg.MessagesDeleteMessagesRequest{
		ID: []int{msgID},
	})
	if err != nil {
		return fmt.Errorf("erreur suppression telegram: %w", err)
	}
	fmt.Print("✓  Supprimé de Telegram.  ")

	index.mu.Lock()
	if _, ok := index.Files[msgID]; ok {
		delete(index.Files, msgID)
	} else {
		fmt.Print("⚠️ Le fichier était absent de l'index local")
	}
	fmt.Println()
	index.mu.Unlock()

	return index.SaveEncrypted()
}

func syncFromTelegram(ctx context.Context, api *tg.Client, index *FileIndex) error {
	fmt.Println("🔄 Smart Sync (Check & Clean)...")
	var offsetID int
	limit := 50
	countNew := 0

	// Map pour lister les fichiers trouvés sur le serveur
	seenIDs := make(map[int]bool)

	for {
		hist, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{Peer: &tg.InputPeerSelf{}, Limit: limit, OffsetID: offsetID})
		if err != nil {
			return err
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
			return fmt.Errorf("unknown messages type: %T", hist)
		}

		if len(msgs) == 0 {
			break
		}

		// Gestion de la pagination (offsetID)
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

			// Identification
			remoteName := "unknown"
			for _, a := range doc.Attributes {
				if fn, ok := a.(*tg.DocumentAttributeFilename); ok {
					remoteName = fn.FileName
				}
			}
			if !strings.HasSuffix(remoteName, ".vault") {
				continue
			}

			// On a vu ce fichier sur le serveur, il est vivant.
			seenIDs[msg.ID] = true

			// S'il est déjà dans l'index, on passe au suivant
			if _, ok := index.Files[msg.ID]; ok {
				continue
			}

			fmt.Printf("\r🔍 Scan nouveau %d...", msg.ID)

			chunk, err := api.UploadGetFile(ctx, &tg.UploadGetFileRequest{
				Location: &tg.InputDocumentFileLocation{ID: doc.ID, AccessHash: doc.AccessHash, FileReference: doc.FileReference},
				Offset:   0, Limit: 4096,
			})
			if err != nil {
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
			r.Read(salt)
			masterKey := deriveKey([]byte(vaultKey), salt)
			var hLen uint32
			binary.Read(r, binary.LittleEndian, &hLen)

			if int64(len(data)) < 16+4+int64(hLen) {
				index.Add(FileEntry{ID: msg.ID, Name: "??? (Need DL)", RemoteName: remoteName, Size: doc.Size, UploadAt: time.Unix(int64(msg.Date), 0)})
				continue
			}

			encH := make([]byte, hLen)
			r.Read(encH)
			block, _ := aes.NewCipher(masterKey)
			gcm, _ := cipher.NewGCM(block)
			if len(encH) < gcm.NonceSize() {
				continue
			}

			nonce, ciphertext := encH[:gcm.NonceSize()], encH[gcm.NonceSize():]
			plainH, err := gcm.Open(nil, nonce, ciphertext, nil)

			if err == nil {
				var h SecureHeader
				gob.NewDecoder(bytes.NewReader(plainH)).Decode(&h)
				index.Add(FileEntry{ID: msg.ID, Name: h.OriginalName, RemoteName: remoteName, Size: doc.Size, UploadAt: time.Unix(int64(msg.Date), 0)})
				countNew++
			}
		}
		if len(msgs) < limit {
			break
		}
	}

	// Nettoyage de l'index : suppression des entrées locales qui ne sont plus sur le serveur
	countDel := 0
	index.mu.Lock()
	for id := range index.Files {
		if !seenIDs[id] {
			delete(index.Files, id)
			countDel++
		}
	}
	index.mu.Unlock()

	index.SaveEncrypted()
	fmt.Printf("\n✓  Sync terminé: %d nouveaux ajoutés, %d orphelins supprimés de l'index.\n", countNew, countDel)
	return nil
}

// --- Helpers ---

func NewIndex() *FileIndex {
	h, _ := os.UserHomeDir()
	path := filepath.Join(h, ".telegram-vault-index.enc")
	return &FileIndex{Files: make(map[int]FileEntry), Path: path}
}

func (idx *FileIndex) Add(e FileEntry) {
	idx.mu.Lock()
	idx.Files[e.ID] = e
	idx.mu.Unlock()
	idx.SaveEncrypted()
}

func listLocal(idx *FileIndex) {
	fmt.Println("ID\tREAL NAME\tTG NAME")
	for _, f := range idx.Files {
		fmt.Printf("%d\t%s\t%s\n", f.ID, f.Name, f.RemoteName)
	}
}

type progress struct{ total int64 }

func (p progress) Chunk(ctx context.Context, state uploader.ProgressState) error {
	fmt.Printf("\r🚀 %.2f%%", float64(state.Uploaded)/float64(p.total)*100)
	return nil
}

func runWithClient(ctx context.Context, f func(context.Context, *telegram.Client, *tg.Client) error) {
	h, _ := os.UserHomeDir()
	path := filepath.Join(h, ".telegram-vault-session")
	client := telegram.NewClient(appID, appHash, telegram.Options{SessionStorage: &session.FileStorage{Path: path}})
	client.Run(ctx, func(ctx context.Context) error {
		client.Auth().IfNecessary(ctx, auth.NewFlow(terminalAuth{phoneNum}, auth.SendCodeOptions{}))
		return f(ctx, client, client.API())
	})
}

type terminalAuth struct{ phone string }

func (a terminalAuth) Phone(_ context.Context) (string, error) { return a.phone, nil }

func (a terminalAuth) Password(_ context.Context) (string, error) {
	fmt.Print("Pwd: ")
	r := bufio.NewReader(os.Stdin)
	l, _ := r.ReadString('\n')
	return strings.TrimSpace(l), nil
}

func (a terminalAuth) Code(_ context.Context, _ *tg.AuthSentCode) (string, error) {
	fmt.Print("Code: ")
	r := bufio.NewReader(os.Stdin)
	l, _ := r.ReadString('\n')
	return strings.TrimSpace(l), nil
}

func (a terminalAuth) SignUp(_ context.Context) (auth.UserInfo, error) { return auth.UserInfo{}, nil }

func (a terminalAuth) AcceptTermsOfService(_ context.Context, _ tg.HelpTermsOfService) error {
	return nil
}

func extractDoc(msg tg.MessageClass) *tg.Document {
	if m, ok := msg.(*tg.Message); ok {
		if med, ok := m.Media.(*tg.MessageMediaDocument); ok {
			if d, ok := med.Document.(*tg.Document); ok {
				return d
			}
		}
	}
	return nil
}
