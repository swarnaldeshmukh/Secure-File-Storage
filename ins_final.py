import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import datetime

# Folder paths
ENCRYPTED_FOLDER = "Encrypted_Files"
DECRYPTED_FOLDER = "Decrypted_Files"
LOG_FILE = "activity_log.txt"

os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Generate key from password
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Log user actions
def log_action(action, filename, status):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(
            f"{datetime.datetime.now()} | {action} | {filename} | {status}\n"
        )

# Encrypt file
def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    # Ask before deleting original
    confirm = messagebox.askyesno("Confirm", "After encryption, the original file will be deleted. Continue?")
    if not confirm:
        return

    try:
        salt = os.urandom(16)
        key = generate_key_from_password(password, salt)
        fernet = Fernet(key)

        with open(file_path, "rb") as file:
            file_data = file.read()

        encrypted_data = fernet.encrypt(file_data)
        file_name = os.path.basename(file_path) + ".enc"
        save_path = os.path.join(ENCRYPTED_FOLDER, file_name)

        with open(save_path, "wb") as file:
            file.write(salt + encrypted_data)

        # Delete original file
        os.remove(file_path)

        messagebox.showinfo("Success", f"File encrypted and saved to:\n{save_path}\n\nOriginal file deleted.")
        log_action("ENCRYPT", file_name, "SUCCESS")

    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed!\n{str(e)}")
        log_action("ENCRYPT", os.path.basename(file_path), f"FAILED: {str(e)}")

# Decrypt file
def decrypt_file():
    file_path = filedialog.askopenfilename(
        title="Select a file to decrypt", filetypes=[("Encrypted files", "*.enc")]
    )
    if not file_path:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Please enter a password!")
        return

    try:
        with open(file_path, "rb") as file:
            salt = file.read(16)
            encrypted_data = file.read()

        key = generate_key_from_password(password, salt)
        fernet = Fernet(key)

        decrypted_data = fernet.decrypt(encrypted_data)

        original_name = os.path.basename(file_path).replace(".enc", "")
        save_path = os.path.join(DECRYPTED_FOLDER, original_name)

        with open(save_path, "wb") as file:
            file.write(decrypted_data)

        messagebox.showinfo("Success", f"Decrypted file saved to:\n{save_path}")
        log_action("DECRYPT", os.path.basename(file_path), "SUCCESS")

    except Exception as e:
        messagebox.showerror("Error", "Wrong password or corrupted file!")
        log_action("DECRYPT", os.path.basename(file_path), f"FAILED: {str(e)}")

# Show Log in a new popup window
def show_log():
    if not os.path.exists(LOG_FILE):
        messagebox.showinfo("Logs", "No activity recorded yet.")
        return

    log_window = tk.Toplevel(root)
    log_window.title("Activity Log")
    log_window.geometry("600x400")

    text_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, font=("Consolas", 11))
    text_area.pack(fill=tk.BOTH, expand=True)

    with open(LOG_FILE, "r") as file:
        text_area.insert(tk.END, file.read())

    text_area.config(state=tk.DISABLED)  # make it read-only

# GUI setup
root = tk.Tk()
root.title("Secure File Storage with Encryption")
root.geometry("550x350")
root.resizable(False, False)

title_label = tk.Label(root, text="Secure File Storage", font=("Arial", 18, "bold"), fg="navy")
title_label.pack(pady=15)

password_label = tk.Label(root, text="Enter Password:", font=("Arial", 12))
password_label.pack()
password_entry = tk.Entry(root, show="*", width=40, font=("Arial", 12))
password_entry.pack(pady=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=20)

encrypt_button = tk.Button(button_frame, text="Encrypt File", width=18, bg="#4CAF50", fg="white", font=("Arial", 12), command=encrypt_file)
encrypt_button.grid(row=0, column=0, padx=10, pady=5)

decrypt_button = tk.Button(button_frame, text="Decrypt File", width=18, bg="#2196F3", fg="white", font=("Arial", 12), command=decrypt_file)
decrypt_button.grid(row=0, column=1, padx=10, pady=5)

log_button = tk.Button(button_frame, text="Show Log", width=18, bg="#FF9800", fg="white", font=("Arial", 12), command=show_log)
log_button.grid(row=1, column=0, padx=10, pady=5)

exit_button = tk.Button(button_frame, text="Exit", width=18, bg="#f44336", fg="white", font=("Arial", 12), command=root.destroy)
exit_button.grid(row=1, column=1, padx=10, pady=5)

root.mainloop()
