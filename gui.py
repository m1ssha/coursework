import tkinter as tk
from tkinter import filedialog, messagebox
import os
import pickle
import hashlib
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.parameters import get_parameters

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("SPHINCS+ GUI")
        self.root.geometry("700x600")

        self.sk = None
        self.pk = None
        self.signature = None
        self.file_path = None
        self.instance = "128f"
        self.params = get_parameters(self.instance)

        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Набор параметров:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        instances = ["128s", "128f", "192s", "192f", "256s", "256f"]
        self.instance_var = tk.StringVar(value=self.instance)
        self.instance_var.trace("w", self.update_instance)
        tk.OptionMenu(self.root, self.instance_var, *instances).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        tk.Label(self.root, text="Ключи:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        tk.Button(self.root, text="Сгенерировать пару ключей", command=self.generate_keys).grid(row=1, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Файл:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.file_label = tk.Label(self.root, text="Файл не выбран", width=50, anchor="w")
        self.file_label.grid(row=2, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Выбрать файл", command=self.select_file).grid(row=2, column=2, padx=5, pady=5)

        tk.Button(self.root, text="Подписать файл (хэш)", command=self.sign_file_hash).grid(row=3, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Проверить файл", command=self.verify_file).grid(row=4, column=1, padx=5, pady=5)

        tk.Button(self.root, text="Сохранить ключи", command=self.save_keys).grid(row=5, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Загрузить ключи", command=self.load_keys).grid(row=5, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Сохранить подпись", command=self.save_signature).grid(row=6, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Загрузить подпись", command=self.load_signature).grid(row=6, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Результат:").grid(row=7, column=0, padx=5, pady=5, sticky="ne")
        self.result_text = tk.Text(self.root, height=15, width=70, state='disabled')
        self.result_text.grid(row=7, column=1, columnspan=2, padx=5, pady=5)

    def update_instance(self, *args):
        """Обновление выбранного набора параметров."""
        self.instance = self.instance_var.get()
        self.params = get_parameters(self.instance)
        self.update_result(f"Выбран набор параметров: {self.instance}\nПараметры: {self.params}")

    def select_file(self):
        """Выбор файла любого типа."""
        self.file_path = filedialog.askopenfilename(title="Выберите файл для подписи или проверки")
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
            self.update_result(f"Выбран файл: {self.file_path}")

    def generate_keys(self):
        """Генерация ключей с учётом выбранного instance."""
        self.sk, self.pk = spx_keygen(params=self.params)
        self.update_result(f"Ключи успешно сгенерированы!\n"
                          f"Набор параметров: {self.instance}\n"
                          f"Секретный ключ: {[x.hex()[:16] + '...' for x in self.sk]}\n"
                          f"Открытый ключ: {[x.hex()[:16] + '...' for x in self.pk]}")

    def sign_file_hash(self):
        """Подпись хэша файла."""
        if not self.sk:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте или загрузите секретный ключ!")
            return
        if not self.file_path:
            messagebox.showerror("Ошибка", "Сначала выберите файл!")
            return
        file_hash = self.compute_file_hash(self.file_path)
        self.signature = spx_sign(file_hash, self.sk, params=self.params)
        self.update_result(f"Хэш файла подписан!\n"
                          f"Хэш: {file_hash.hex()[:16]}...\n"
                          f"Длина подписи: {sum(len(x) if isinstance(x, bytes) else len(x) for x in self.signature)} байт "
                          f"({len(self.signature)} компонентов)")

    def verify_file(self):
        """Проверка подписи файла (требуется только открытый ключ)."""
        if not self.pk:
            messagebox.showerror("Ошибка", "Сначала загрузите или сгенерируйте открытый ключ!")
            return
        if not self.signature:
            messagebox.showerror("Ошибка", "Сначала подпишите файл или загрузите подпись!")
            return
        if not self.file_path:
            messagebox.showerror("Ошибка", "Сначала выберите файл!")
            return
        file_hash = self.compute_file_hash(self.file_path)
        try:
            result = spx_verify(file_hash, self.signature, self.pk, params=self.params)
            self.update_result(f"Результат проверки: {'Подпись верна' if result else 'Подпись неверна'}\n"
                              f"Проверенный хэш: {file_hash.hex()[:16]}...\n"
                              f"Набор параметров: {self.instance}")
        except Exception as e:
            messagebox.showerror("Ошибка проверки", f"Не удалось проверить: {str(e)}")
            self.update_result(f"Проверка не удалась: {str(e)}\n"
                              f"Набор параметров: {self.instance}")

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
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи!")
            return
        base_name = filedialog.asksaveasfilename(
            defaultextension="",
            title="Сохранить ключи (будут добавлены .sk и .pk)",
            filetypes=[("Все файлы", "*.*")]
        )
        if base_name:
            sk_file = f"{base_name}.sk"
            pk_file = f"{base_name}.pk"
            with open(sk_file, 'wb') as f:
                pickle.dump(self.sk, f)
            with open(pk_file, 'wb') as f:
                pickle.dump(self.pk, f)
            self.update_result(f"Ключи сохранены:\nСекретный ключ: {sk_file}\nОткрытый ключ: {pk_file}")

    def load_keys(self):
        """Загрузка ключей (секретный необязателен)."""
        choice = messagebox.askyesno("Выбор ключа", "Хотите загрузить секретный ключ? (Нет — загрузить только открытый)")
        if choice:
            sk_file = filedialog.askopenfilename(title="Загрузить секретный ключ", filetypes=[("Файлы секретного ключа", "*.sk")])
            if sk_file:
                with open(sk_file, 'rb') as f:
                    self.sk = pickle.load(f)
                self.update_result(f"Секретный ключ загружен: {sk_file}\n"
                                  f"Секретный ключ: {[x.hex()[:16] + '...' for x in self.sk]}")
            else:
                self.update_result("Загрузка секретного ключа отменена.")
        
        pk_file = filedialog.askopenfilename(title="Загрузить открытый ключ", filetypes=[("Файлы открытого ключа", "*.pk")])
        if pk_file:
            with open(pk_file, 'rb') as f:
                self.pk = pickle.load(f)
            self.update_result(self.result_text.get("1.0", tk.END).strip() + 
                              f"\nОткрытый ключ загружен: {pk_file}\n"
                              f"Открытый ключ: {[x.hex()[:16] + '...' for x in self.pk]}")
        else:
            self.update_result(self.result_text.get("1.0", tk.END).strip() + 
                              "\nЗагрузка открытого ключа отменена.")

    def save_signature(self):
        """Сохранение подписи в отдельный файл с информацией об instance."""
        if not self.signature or not self.file_path:
            messagebox.showerror("Ошибка", "Сначала подпишите файл!")
            return
        base_name = os.path.splitext(self.file_path)[0]
        sig_file = filedialog.asksaveasfilename(
            initialfile=f"{os.path.basename(base_name)}.sig",
            title="Сохранить подпись",
            filetypes=[("Файлы подписи", "*.sig")]
        )
        if sig_file:
            sig_data = {
                "instance": self.instance,
                "signature": self.signature
            }
            with open(sig_file, 'wb') as f:
                pickle.dump(sig_data, f)
            self.update_result(f"Подпись сохранена в {sig_file}\n"
                              f"Сохранённый набор параметров: {self.instance}")

    def load_signature(self):
        """Загрузка подписи с автоматическим выбором instance."""
        sig_file = filedialog.askopenfilename(title="Загрузить подпись", filetypes=[("Файлы подписи", "*.sig")])
        if sig_file:
            with open(sig_file, 'rb') as f:
                sig_data = pickle.load(f)
            if isinstance(sig_data, dict) and "instance" in sig_data and "signature" in sig_data:
                loaded_instance = sig_data["instance"]
                self.signature = sig_data["signature"]
                self.instance_var.set(loaded_instance)
                self.instance = loaded_instance
                self.params = get_parameters(self.instance)
                self.update_result(f"Подпись загружена из {sig_file}\n"
                                  f"Длина подписи: {sum(len(x) if isinstance(x, bytes) else len(x) for x in self.signature)} байт "
                                  f"({len(self.signature)} компонентов)\n"
                                  f"Набор параметров автоматически установлен: {loaded_instance}")
            else:
                self.signature = sig_data
                self.update_result(f"Подпись загружена из {sig_file}\n"
                                  f"Длина подписи: {sum(len(x) if isinstance(x, bytes) else len(x) for x in self.signature)} байт "
                                  f"({len(self.signature)} компонентов)\n"
                                  f"Предупреждение: Информация о наборе параметров отсутствует. Используется текущий: {self.instance}")

    def update_result(self, text):
        """Обновление поля результата."""
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()