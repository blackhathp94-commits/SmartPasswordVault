# 🔐 SmartPasswordVault

A lightweight personal vault built using **Flask**, **SQLite**, and **Fernet encryption**.  
It allows users to securely store passwords, credit cards, bank details, and documents.

---

## 🚀 Features
- User signup & login (hashed passwords)
- Encrypted storage using **Fernet**
- Store:
  - Password entries
  - Credit cards
  - Bank information
  - Uploaded documents
- Add, edit, delete entries
- SQLite database auto-created on first run

---

## ▶️ How to Run

### 1. Install dependencies
```bash
pip install -r requirements.txt
2. Start the server
python app.py

3. Open in browser
http://127.0.0.1:5000/
