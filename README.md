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
1. Install the dependencies

Open your terminal or command prompt and run:

pip install -r requirements.txt


This installs all libraries listed in requirements.txt.

2. Start the server

Run your Flask (or Python) app:

python app.py


If no errors occur, the server will start running.

3. Open the app in your browser

Go to:

http://127.0.0.1:5000/


