# Televault

> _Protocol: INFINITE_STORAGE // Security level: PARANOID (Zero-Knowledge)_

Le stockage cloud personnel ultime sur Telegram.
Chiffrement Authentifié du **contenu**, des **métadonnées** et de l'**index local**. Telegram ne voit que des blobs binaires aléatoires.

---

## ⚠️ DISCLAIMER (A LIRE AVANT DE PLEURER)

**L'utilisation de ce logiciel peut entraîner le bannissement définitif de ton compte Telegram.**

Ce tool utilise l'API de Telegram d'une manière qui n'est pas prévue par leurs Conditions d'Utilisation (stockage de fichiers pur et dur).

- **NE PAS UTILISER** avec ton compte personnel principal.
- **NOVA (et le développeur)** déclinent toute responsabilité en cas de perte de données, de ban, ou de crise de nerfs.
- Utilise un compte secondaire (burner) pour tes tests et stockages.

**Tu es prévenu.**

---

## Prérequis

1. Rends-toi sur https://my.telegram.org.
2. Connecte-toi avec ton numéro de téléphone (tu vas recevoir un code sur Telegram, essaie de ne pas le rater).
3. Clique sur le lien **"API development tools"**.
4. Remplis le formulaire :
   - **App title** : Donne un nom à ton appli (sois créatif pour une fois).
   - **Shortname** : Un nom court, sans espaces.
   - Les autres champs (URL, description) sont facultatifs ou tu peux mettre n'importe quoi.
5. Clique sur **"Create application"**.
6. Note précieusement ton **api_id** et ton **api_hash**. Ne les perds pas.

---

## 🚀 Installation

### 1. Variables d'environnement

Ajoute ceci à ton `~/.zshrc` ou `~/.bashrc` :

```bash
# Telegram API (https://my.telegram.org)
export TELEGRAM_APP_ID="12345678"
export TELEGRAM_APP_HASH="ton_hash_secret"
export TELEGRAM_PHONE="+33612345678"

# 🔑 Clé Maître (Si tu la perds, tes données sont perdues à jamais)
export VAULT_KEY="correct-horse-battery-staple-complex-passphrase"
```

### 2. Compilation

```bash
go build -o televault main.go
```

---

## 🎮 Commandes & Raccourcis

### 📤 Upload (Batch & Récursif)

Chiffre et envoie des fichiers ou des dossiers entiers (fichiers par fichiers).

```bash
# Fichier unique
./televault up "Document.pdf"

# Dossier complet (Récursif)
./televault up ./Photos/

# Liste de fichiers
./televault up doc1.txt doc2.txt
```

_Alias : `up`, `upload`_

### 📥 Download (Batch)

Récupère et déchiffre. Accepte plusieurs IDs et un dossier optionnel.

```bash
# Un fichier dans le dossier courant
./televault dl 12345

# Plusieurs fichiers dans un dossier spécifique
./televault dl 12345 67890 111213 ~/Downloads/
```

_Alias : `dl`, `download`_

### 📋 Gestion

```bash
./televault ls         # (list) Voir les fichiers
./televault s          # (sync) Scanner Telegram

# Supprimer plusieurs fichiers d'un coup
./televault rm 12345 67890
```

### 🌐 Interface Web

Lance une interface web locale pour gérer ton vault depuis le navigateur (upload, download, suppression, sync).

```bash
# Port par défaut : 8080
./televault w

# Port custom
./televault w 3000
```

_Alias : `w`, `web`_

Endpoints API disponibles :

| Méthode  | Route              | Description          |
|----------|--------------------|----------------------|
| `GET`    | `/api/files`       | Lister les fichiers  |
| `POST`   | `/api/upload`      | Upload un fichier    |
| `GET`    | `/api/download/:id`| Télécharger un fichier|
| `DELETE` | `/api/files/:id`   | Supprimer un fichier |
| `POST`   | `/api/sync`        | Synchroniser l'index |

---

## 🔐 Cryptographie

- **KDF** : PBKDF2 (HMAC-SHA256, 600,000 itérations).
- **Index Local** : AES-256-GCM.
- **Header Fichier** : AES-256-GCM.
- **Contenu** : AES-256-CTR + HMAC-SHA256 (Encrypt-then-MAC).
- **Anti-Ban** : Délai aléatoire (jitter 2-7s) entre chaque upload batch pour réduire le risque de ban.
- **Dépendances** : `github.com/gotd/td`, `github.com/matoous/go-nanoid/v2`.

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

_Developed by NOVA._
