# 🏠 VaultKeeper - Gryffindor-Themed Password Vault

VaultKeeper is a secure, offline, and magical password manager built with Python and Tkinter. Inspired by the Gryffindor house of Hogwarts, this tool allows you to **store**, **retrieve**, and **manage your passwords** with encryption and flair.

> 🔒 Local-only encryption with a custom “Master Spell” password  
> 🧙 Gryffindor theme with spells like "Avada Entry", "Lumos Secret", and "Accio Details"  
> 🧠 Auto-lock feature for enhanced security  
> 🪄 Password generation, search, and reset included

---

## ✨ Features

| Feature                | Description                                                  |
|------------------------|--------------------------------------------------------------|
| 🔐 Secure Storage      | Encrypts passwords using `Fernet` symmetric encryption       |
| 🧪 Master Password     | Derives encryption key using `PBKDF2-HMAC-SHA256`            |
| 📁 Vault File          | Stores secrets in an encrypted `.vault` file (binary)       |
| 📋 Search Vault        | Real-time filter through stored credentials                  |
| 🔁 Reset Entry         | Edit/Update existing entries securely                        |
| ✨ Generate Password   | Strong random passwords using letters, digits, symbols       |
| 📖 Spellbook Tab       | Quick reference to all magical functions                     |
| ⚔️ Settings Tab        | Reset Master Spell (password) anytime                        |
| ⏰ Auto Lock            | Locks vault after 5 minutes of inactivity                    |
| 🖱️ Double-click Entry | View masked password, reveal, or copy to clipboard           |

---

## 🛠️ How It Works

- **Vault Initialization:** First-time users must set a Master Spell (password)
- **Key Derivation:** Uses `PBKDF2-HMAC` + a custom salt to derive encryption key
- **Vault Locking:** All data is encrypted to a `.vault` file on save or update
- **Unlocking:** Users must input the correct Master Spell to decrypt vault

---

## 🔐 Encryption Details

- **Encryption:** AES-128 CBC via [`cryptography.fernet`](https://cryptography.io/en/latest/fernet/)
- **KDF:** `PBKDF2-HMAC-SHA256` with custom static salt
- **Storage Format:** Encrypted binary file with `.vault` extension

---

## 🖥️ Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/vaultkeeper.git
   cd vaultkeeper
   ```

## Screenshots

> ! [Screenshot](Screenshot1.png)

> ! [Screenshot](Screenshot2.png)

> ! [Screenshot](Screenshot3.png)

> ! [Screenshot](Screenshot4.png)

> ! [Screenshot](Screenshot5.png)

> ! [Screenshot](Screenshot6.png)

> ! [Screenshot](Screenshot7.png)

> ! [Screenshot](Screenshot8.png)



## ⚠️ Disclaimer

    This app does not store your master password.

    If you forget the Master Spell, your data cannot be recovered.

    For maximum safety, keep regular backups of your vault file.