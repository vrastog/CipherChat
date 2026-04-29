# CipherChat

End-to-end encrypted browser-based chat. The server never sees your messages.

---

## Setup

```bash
pip install flask flask-socketio flask-sqlalchemy flask-login gevent gevent-websocket
python app.py
```

Open `http://localhost:5002`

---

## File Structure

```
├── app.py
└── templates/
    ├── landing.html
    ├── auth.html
    └── chat.html
```

---

## How to Use

1. Register two accounts in different browsers
2. Click a username in the sidebar
3. ECDH handshake runs automatically
4. Start chatting — everything is encrypted

---

## Features

- AES-256-GCM encryption + ECDSA signatures in the browser (WebCrypto API)
- Live encryption visualiser — click the 🔍 button to watch messages encrypt in real time
- Encrypted file transfer with progress bar
- Message history loaded on startup
- Typing indicators + online presence
- Zero-knowledge server — only relays encrypted blobs

---

## Two Laptops on Same Wi-Fi

Find your IP:
```bash
ipconfig getifaddr en0
```

On second laptop open:
```
http://192.168.x.x:5002
```

---

*Server sees only ciphertext — never plaintext.*
