import tkinter as tk
from tkinter import filedialog, messagebox
import os
import pickle
import hashlib
from src.sphincs import spx_keygen, spx_sign, spx_verify

class SphincsGUIHashAll:
    def __init__(self, root):
        self.root = root
        self.root.title("SPHINCS+ Hash & Sign Tool")
        self.root.geometry("600x400")

        self.sk = None
        self.pk = None
        self.signature = None
        self.file_path = None

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Keys:").grid(row=0, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Generate Key Pair", command=self.generate_keys).grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.root, text="File:").grid(row=1, column=0, padx=5, pady=5)
        self.file_label = tk.Label(self.root, text="No file selected", width=50, anchor="w")
        self.file_label.grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Select File", command=self.select_file).grid(row=1, column=2, padx=5, pady=5)

        tk.Button(self.root, text="Sign File (Hash)", command=self.sign_file_hash).grid(row=2, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Verify File", command=self.verify_file).grid(row=3, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Result:").grid(row=4, column=0, padx=5, pady=5)
        self.result_text = tk.Text(self.root, height=10, width=50, state='disabled')
        self.result_text.grid(row=4, column=1, padx=5, pady=5)

        tk.Button(self.root, text="Save Keys", command=self.save_keys).grid(row=5, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Load Public Key", command=self.load_public_key).grid(row=5, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Save Signature", command=self.save_signature).grid(row=6, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Load Signature", command=self.load_signature).grid(row=6, column=1, padx=5, pady=5)

    def select_file(self):
        """Выбор файла любого типа."""
        self.file_path = filedialog.askopenfilename(title="Select File to Sign or Verify")
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
            self.update_result(f"Selected file: {self.file_path}")

    def generate_keys(self):
        """Генерация ключей."""
        self.sk, self.pk = spx_keygen()
        self.update_result("Keys generated successfully!\n"
                          f"SK: {[x.hex()[:16] + '...' for x in self.sk]}\n"
                          f"PK: {[x.hex()[:16] + '...' for x in self.pk]}")

    def sign_file_hash(self):
        """Подпись хэша файла."""
        if not self.sk:
            messagebox.showerror("Error", "Generate or load secret key first!")
            return
        if not self.file_path:
            messagebox.showerror("Error", "Select a file first!")
            return
        file_hash = self.compute_file_hash(self.file_path)
        self.signature = spx_sign(file_hash, self.sk)
        self.update_result(f"File hash signed! Hash: {file_hash.hex()[:16]}...\n"
                          f"Signature length: {len(self.signature)} elements")

    def verify_file(self):
        """Проверка подписи файла."""
        if not self.pk:
            messagebox.showerror("Error", "Load public key first!")
            return
        if not self.signature:
            messagebox.showerror("Error", "Sign a file or load a signature first!")
            return
        if not self.file_path:
            messagebox.showerror("Error", "Select a file first!")
            return
        file_hash = self.compute_file_hash(self.file_path)
        result = spx_verify(file_hash, self.signature, self.pk)
        self.update_result(f"Verification result: {result}\n"
                          f"Verified hash: {file_hash.hex()[:16]}...")

    def compute_file_hash(self, file_path):
        """Вычисление SHA-256 хэша файла."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.digest()

    def save_keys(self):
        """Сохранение ключей."""
        if not self.sk or not self.pk:
            messagebox.showerror("Error", "Generate keys first!")
            return
        sk_file = filedialog.asksaveasfilename(defaultextension=".sk", title="Save Secret Key")
        pk_file = filedialog.asksaveasfilename(defaultextension=".pk", title="Save Public Key")
        if sk_file and pk_file:
            with open(sk_file, 'wb') as f:
                pickle.dump(self.sk, f)
            with open(pk_file, 'wb') as f:
                pickle.dump(self.pk, f)
            self.update_result(f"Keys saved to {sk_file} and {pk_file}")

    def load_public_key(self):
        """Загрузка публичного ключа."""
        pk_file = filedialog.askopenfilename(title="Load Public Key", filetypes=[("Key files", "*.pk")])
        if pk_file:
            with open(pk_file, 'rb') as f:
                self.pk = pickle.load(f)
            self.sk = None
            self.update_result(f"Public key loaded: {pk_file}\n"
                              f"PK: {[x.hex()[:16] + '...' for x in self.pk]}")

    def save_signature(self):
        """Сохранение подписи в отдельный файл."""
        if not self.signature or not self.file_path:
            messagebox.showerror("Error", "Sign a file first!")
            return
        base_name = os.path.splitext(self.file_path)[0]
        sig_file = filedialog.asksaveasfilename(
            initialfile=f"{os.path.basename(base_name)}.sig",
            title="Save Signature",
            filetypes=[("Signature files", "*.sig")]
        )
        if sig_file:
            with open(sig_file, 'wb') as f:
                pickle.dump(self.signature, f)
            self.update_result(f"Signature saved to {sig_file}")

    def load_signature(self):
        """Загрузка подписи из отдельного файла."""
        sig_file = filedialog.askopenfilename(title="Load Signature", filetypes=[("Signature files", "*.sig")])
        if sig_file:
            with open(sig_file, 'rb') as f:
                self.signature = pickle.load(f)
            self.update_result(f"Signature loaded from {sig_file}")

    def update_result(self, text):
        """Обновление поля результата."""
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = SphincsGUIHashAll(root)
    root.mainloop()