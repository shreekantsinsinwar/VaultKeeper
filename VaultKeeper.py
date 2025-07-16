# VaultKeeper.py
# 🏠 A Gryffindor-Themed Password Vault (Tkinter version)

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
from datetime import datetime
import json
import os
import base64
import hashlib
import time
import threading
from tkinter import filedialog

# ---------------- CONFIG ----------------
VAULT_FILE = "vaultkeeper.vault"
AUTO_LOCK_MINUTES = 5
THEME_BG = "#7f0909"     # Gryffindor Red
THEME_FG = "gold"         # Gold Text
SELECTED_TAB_COLOR = "red"

# ---------------- ENCRYPTION HELPERS ----------------
def derive_key(master_password):
    salt = b'gryffindor_salt_2025'
    kdf = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return base64.urlsafe_b64encode(kdf)

def encrypt_data(data, key):
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())

def decrypt_data(token, key):
    f = Fernet(key)
    return json.loads(f.decrypt(token).decode())

# ---------------- MAIN CLASS ----------------
class VaultKeeper:
    def __init__(self, root):
        self.root = root
        self.root.title("VaultKeeper - Gryffindor Password Vault")
        self.root.geometry("800x600")
        self.root.configure(bg=THEME_BG)

        self.key = None
        self.data = []
        self.last_activity = time.time()

        self.check_vault_or_create()
        self.setup_ui()
        self.monitor_idle()

    # ---------- Setup UI Tabs ----------
    def setup_ui(self):
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(expand=1, fill="both")

        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook.Tab', background=THEME_BG, foreground=THEME_FG)

        self.tabs.bind("<<NotebookTabChanged>>", self.on_tab_changed)

        self.setup_add_tab()
        self.setup_vault_tab()
        self.setup_generate_tab()
        self.setup_spellbook_tab()
        self.setup_settings_tab()

    def on_tab_changed(self, event):
        style = ttk.Style()
        style.configure("TNotebook.Tab", foreground=THEME_FG)
        selected_tab_index = self.tabs.index(self.tabs.select())
        style.map("TNotebook.Tab", foreground=[("selected", SELECTED_TAB_COLOR)])

    def setup_add_tab(self):
        self.add_tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(self.add_tab, text="🏠 Engrave in Vault")

        tk.Label(self.add_tab, text="Resource:", fg=THEME_FG, bg=THEME_BG).pack()
        self.res_entry = tk.Entry(self.add_tab, width=40)
        self.res_entry.pack(pady=5)

        tk.Label(self.add_tab, text="Username:", fg=THEME_FG, bg=THEME_BG).pack()
        self.user_entry = tk.Entry(self.add_tab, width=40)
        self.user_entry.pack(pady=5)

        tk.Label(self.add_tab, text="Password:", fg=THEME_FG, bg=THEME_BG).pack()
        self.pass_entry = tk.Entry(self.add_tab, width=40, show="*")
        self.pass_entry.pack(pady=5)

        tk.Label(self.add_tab, text="Category (Optional):", fg=THEME_FG, bg=THEME_BG).pack()
        self.cat_entry = tk.Entry(self.add_tab, width=40)
        self.cat_entry.pack(pady=5)

        tk.Button(self.add_tab, text="🪄 Add to Vault", command=self.save_entry, bg="gold").pack(pady=10)

    def setup_vault_tab(self):
        self.vault_tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(self.vault_tab, text="🔐 My Vault")

        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *args: self.populate_tree())

        tk.Entry(self.vault_tab, textvariable=self.search_var, width=50).pack(pady=5)

        self.tree = ttk.Treeview(self.vault_tab, columns=("Resource", "Username", "Category", "Date"), show="headings")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
        self.tree.pack(expand=1, fill=tk.BOTH)
        self.tree.bind("<Double-1>", self.view_entry)

        btn_frame = tk.Frame(self.vault_tab, bg=THEME_BG)
        btn_frame.pack(pady=5)

        tk.Button(btn_frame, text="💀 Avada Entry", command=self.delete_entry, bg="black", fg="white").pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="♻️ Reset Entry", command=self.edit_entry, bg="gold").pack(side=tk.LEFT, padx=10)

    def edit_entry(self):
        selected = self.tree.focus()
        values = self.tree.item(selected, 'values')
        if not values:
            return
        for entry in self.data:
            if entry['resource'] == values[0] and entry['username'] == values[1]:
                new_pwd = simpledialog.askstring("Reset Password", f"Reset password for {entry['resource']}:", show="*")
                if new_pwd:
                    entry['password'] = new_pwd
                    self.lock_vault()
                    messagebox.showinfo("Updated", "Entry updated successfully!")
                    return

    def setup_generate_tab(self):
        self.gen_tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(self.gen_tab, text="🔮 Spell Generator")

        tk.Label(self.gen_tab, text="Click to Generate Magical Password:", fg=THEME_FG, bg=THEME_BG).pack(pady=10)
        self.gen_pass_var = tk.StringVar()
        tk.Entry(self.gen_tab, textvariable=self.gen_pass_var, width=40).pack(pady=5)
        tk.Button(self.gen_tab, text="✨ Summon Password", command=self.generate_password, bg="gold").pack()

    def setup_spellbook_tab(self):
        self.help_tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(self.help_tab, text="📖 Spellbook")

        spells = [
            ("Engrave in Vault", "Add a new secret"),
            ("Vault", "See all saved secrets"),
            ("Accio Details", "Copy to clipboard"),
            ("Lumos Secret", "Show password"),
            ("Nox Secret", "Hide password"),
            ("Avada Entry", "Delete entry"),
            ("Summon Password", "Generate password"),
            ("Reset Entry", "Edit saved entry"),
            ("Reset Master Spell", "Change the master password")
        ]

        for name, meaning in spells:
            tk.Label(self.help_tab, text=f"{name} → {meaning}", fg=THEME_FG, bg=THEME_BG, font=("Georgia", 12)).pack(anchor="w", padx=10, pady=5)

    def setup_settings_tab(self):
        self.settings_tab = tk.Frame(self.tabs, bg=THEME_BG)
        self.tabs.add(self.settings_tab, text="⚔️ Settings")

        tk.Button(self.settings_tab, text="🔄 Reset Master Spell", command=self.reset_master_password, bg="gold").pack(pady=10)

    def reset_master_password(self):
        new_pwd = simpledialog.askstring("New Master Spell", "Cast your new Master Spell:", show="*")
        if new_pwd:
            self.key = derive_key(new_pwd)
            self.lock_vault()
            messagebox.showinfo("Reset", "Master Spell updated successfully!")

    # ---------- Core Logic ----------
    def check_vault_or_create(self):
        if os.path.exists(VAULT_FILE):
            while True:
                pwd = simpledialog.askstring("Enter Master Spell", "Speak, wizard, the master spell:", show="*")
                if pwd:
                    try:
                        self.key = derive_key(pwd)
                        with open(VAULT_FILE, "rb") as f:
                            encrypted = f.read()
                        self.data = decrypt_data(encrypted, self.key)
                        break
                    except:
                        messagebox.showerror("Wrong Spell", "The spell fizzled! Try again.")
                else:
                    self.root.destroy()
        else:
            pwd = simpledialog.askstring("Set Master Spell", "Speak your spell to guard the vault:", show="*")
            if pwd:
                self.key = derive_key(pwd)
                self.data = []
                self.lock_vault()
            else:
                self.root.destroy()

    def lock_vault(self):
        encrypted = encrypt_data(self.data, self.key)
        with open(VAULT_FILE, "wb") as f:
            f.write(encrypted)

    def save_entry(self):
        res = self.res_entry.get()
        user = self.user_entry.get()
        pwd = self.pass_entry.get()
        cat = self.cat_entry.get()
        date = datetime.now().strftime("%Y-%m-%d %H:%M")

        if not res or not user or not pwd:
            messagebox.showwarning("Missing", "Fields cannot be empty")
            return

        self.data.append({"resource": res, "username": user, "password": pwd, "category": cat, "date": date})
        self.lock_vault()
        self.populate_tree()

        self.res_entry.delete(0, tk.END)
        self.user_entry.delete(0, tk.END)
        self.pass_entry.delete(0, tk.END)
        self.cat_entry.delete(0, tk.END)

    def populate_tree(self):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for entry in reversed(self.data):
            if query in entry['resource'].lower():
                self.tree.insert("", tk.END, values=(entry['resource'], entry['username'], entry['category'], entry['date']))

    def view_entry(self, event):
        selected = self.tree.focus()
        values = self.tree.item(selected, 'values')
        if not values:
            return
        for entry in self.data:
            if entry['resource'] == values[0] and entry['username'] == values[1]:
                top = tk.Toplevel(self.root)
                top.title("🔐 Vault Details")
                top.configure(bg=THEME_BG)

                tk.Label(top, text=f"Resource: {entry['resource']}", fg=THEME_FG, bg=THEME_BG).pack(pady=5)
                tk.Label(top, text=f"Username: {entry['username']}", fg=THEME_FG, bg=THEME_BG).pack(pady=5)

                pwd_var = tk.StringVar(value="*" * len(entry['password']))

                def toggle():
                    if pwd_var.get().startswith("*"):
                        pwd_var.set(entry['password'])
                        toggle_btn.config(text="🌑 Nox Secret")
                    else:
                        pwd_var.set("*" * len(entry['password']))
                        toggle_btn.config(text="✨ Lumos Secret")

                tk.Label(top, text="Password:", fg=THEME_FG, bg=THEME_BG).pack()
                tk.Entry(top, textvariable=pwd_var, width=30).pack()
                toggle_btn = tk.Button(top, text="✨ Lumos Secret", command=toggle)
                toggle_btn.pack(pady=5)

                def copy_pass():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(entry['password'])
                    self.root.update()

                tk.Button(top, text="🪄 Accio Details", command=copy_pass).pack()

    def delete_entry(self):
        selected = self.tree.focus()
        values = self.tree.item(selected, 'values')
        if not values:
            return
        confirm = messagebox.askyesno("Delete", "Really cast Avada Kedavra on this entry?")
        if confirm:
            self.data = [e for e in self.data if not (e['resource'] == values[0] and e['username'] == values[1])]
            self.lock_vault()
            self.populate_tree()

    def generate_password(self):
        import random, string
        chars = string.ascii_letters + string.digits + "@#$%&*+!"
        pwd = ''.join(random.choice(chars) for _ in range(14))
        self.gen_pass_var.set(pwd)

    def monitor_idle(self):
        def loop():
            while True:
                if time.time() - self.last_activity > AUTO_LOCK_MINUTES * 60:
                    messagebox.showinfo("Protego Maxima", "Vault auto-locked after inactivity!")
                    os._exit(0)
                time.sleep(10)

        threading.Thread(target=loop, daemon=True).start()

# ---------------- LAUNCH ----------------
if __name__ == '__main__':
    root = tk.Tk()
    app = VaultKeeper(root)
    root.mainloop()
