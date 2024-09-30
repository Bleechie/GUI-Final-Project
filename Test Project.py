import tkinter as tk
import random
import string
from cryptography.fernet import Fernet
import os

class PasswordGeneratorApp:
    def __init__(self, window):
        window.title("Password Generator")
        window.configure(bg='#2E2E2E')

        # Generate or load encryption key
        self.key_file = 'key.key'
        self.password_file = 'passwords.txt'
        self.key = self.load_key()

        # Cipher for encryption
        self.cipher = Fernet(self.key)

        # Content frame
        content_frame = tk.Frame(window, bg='#2E2E2E')
        content_frame.pack(fill='both', expand=True, padx=20, pady=20)

        # Password Length Label and Entry
        label = tk.Label(content_frame, text="Password Character Length:", bg='#2E2E2E', fg='#FFFFFF', font=("Helvetica", 16))
        label.pack(pady=20)
        
        self.password_length_entry = tk.Entry(content_frame, bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14))
        self.password_length_entry.pack(pady=10)

        # Generate Password Button
        generate_btn = tk.Button(content_frame, text="Generate Password", bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14), command=self.show_password_window)
        generate_btn.pack(pady=10)

        # View Saved Passwords Button
        view_saved_btn = tk.Button(content_frame, text="View Saved Passwords", bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14), command=self.show_saved_passwords_window)
        view_saved_btn.pack(pady=10)

        # Exit Button
        exit_btn = tk.Button(content_frame, text="Exit", bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14), command=window.quit)
        exit_btn.pack(pady=10)

        # Load saved passwords from file
        self.saved_passwords = self.load_passwords()

    def load_key(self):
        if not os.path.exists(self.key_file):
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
        else:
            with open(self.key_file, 'rb') as key_file:
                key = key_file.read()
        return key

    def encrypt(self, message):
        return self.cipher.encrypt(message.encode()).decode()

    def decrypt(self, encrypted_message):
        return self.cipher.decrypt(encrypted_message.encode()).decode()

    def save_passwords(self):
        with open(self.password_file, 'w') as f:
            for name, password in self.saved_passwords.items():
                encrypted_password = self.encrypt(password)
                f.write(f"{name}:{encrypted_password}\n")

    def load_passwords(self):
        if not os.path.exists(self.password_file):
            return {}
        saved_passwords = {}
        with open(self.password_file, 'r') as f:
            for line in f.readlines():
                name, encrypted_password = line.strip().split(':')
                saved_passwords[name] = self.decrypt(encrypted_password)
        return saved_passwords

    def generate_password(self):
        try:
            length = int(self.password_length_entry.get())
            if length <= 0:
                raise ValueError("Password length must be a positive integer.")
        except ValueError:
            return "Invalid length! Please enter a positive integer."
        characters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(characters) for _ in range(length))

    def show_password_window(self):
        password = self.generate_password()
        if password.startswith("Invalid"):
            error_window = tk.Toplevel()
            error_window.title("Error")
            error_label = tk.Label(error_window, text=password, padx=20, pady=20)
            error_label.pack()
            return
        password_window = tk.Toplevel()
        #password_window.configure(bg='#2E2E2E')
        password_window.title("Generated Password")
        password_label = tk.Label(password_window, text=f"Generated Password: {password}", padx=20, pady=20, font=("Helvetica", 14))
        password_label.pack()
        copy_button = tk.Button(password_window, text="Copy to Clipboard", command=lambda: self.copy_to_clipboard(password), padx=10, pady=5)
        copy_button.pack(pady=10)
        name_label = tk.Label(password_window, text="Assign a Name to this Password:", padx=20, pady=10, font=("Helvetica", 14))
        name_label.pack()
        self.name_entry = tk.Entry(password_window, bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14))
        self.name_entry.pack(pady=10)
        save_button = tk.Button(password_window, text="Save Password", command=lambda: self.save_password(password_window, password), padx=10, pady=5)
        save_button.pack(pady=10)
        ok_button = tk.Button(password_window, text="OK", command=password_window.destroy, padx=10, pady=5)
        ok_button.pack(pady=10)

    def copy_to_clipboard(self, text):
        window.clipboard_clear()
        window.clipboard_append(text)
        window.update()

    def save_password(self, password_window, password):
        name = self.name_entry.get()
        if not name:
            error_label = tk.Label(password_window, text="Please enter a name for the password!", fg="red", font=("Helvetica", 12))
            error_label.pack()
            return
        self.saved_passwords[name] = password
        success_label = tk.Label(password_window, text="Password saved successfully!", fg="green", font=("Helvetica", 12))
        success_label.pack()
        self.save_passwords()

    def show_saved_passwords_window(self):
        saved_window = tk.Toplevel()
        saved_window.title("Saved Passwords")
        if not self.saved_passwords:
            empty_label = tk.Label(saved_window, text="No saved passwords yet.", padx=20, pady=20, font=("Helvetica", 14))
            empty_label.pack()
        else:
            for name, password in self.saved_passwords.items():
                password_frame = tk.Frame(saved_window)
                password_frame.pack(pady=5, padx=20, anchor='w')
                saved_label = tk.Label(password_frame, text=f"{name}: {password}", font=("Helvetica", 14))
                saved_label.pack(side='left')
                copy_btn = tk.Button(password_frame, text="Copy", command=lambda p=password: self.copy_to_clipboard(p))
                copy_btn.pack(side='left', padx=10)
                edit_btn = tk.Button(password_frame, text="Edit", command=lambda n=name: self.edit_password(saved_window, n))
                edit_btn.pack(side='left', padx=10)

    def edit_password(self, parent_window, name):
        parent_window.destroy()
        edit_window = tk.Toplevel()
        edit_window.title("Edit Password")
        edit_label = tk.Label(edit_window, text=f"Editing Password for {name}:", font=("Helvetica", 14))
        edit_label.pack(pady=10)
        new_password_entry = tk.Entry(edit_window, bg='#4B4B4B', fg='#FFFFFF', font=("Helvetica", 14))
        new_password_entry.insert(0, self.saved_passwords[name])
        new_password_entry.pack(pady=10)
        save_btn = tk.Button(edit_window, text="Save", command=lambda: self.save_edited_password(edit_window, name, new_password_entry.get()))
        save_btn.pack(pady=10)

    def save_edited_password(self, window, name, new_password):
        self.saved_passwords[name] = new_password
        self.save_passwords()
        success_label = tk.Label(window, text="Password updated successfully!", fg="green", font=("Helvetica", 12))
        success_label.pack()
        window.destroy()
        self.show_saved_passwords_window()

# Main execution
if __name__ == "__main__":
    window = tk.Tk()
    app = PasswordGeneratorApp(window)
    window.mainloop()
