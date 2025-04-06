import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import pickle
import hashlib
from src.sphincs import spx_keygen, spx_sign, spx_verify
from src.parameters import get_parameters

class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Инструмент SPHINCS+")
        self.root.geometry("800x600")
        self.root.resizable(False, False)

        self.sk = None
        self.pk = None
        self.signature = None
        self.file_path = None
        self.instance = "128f"
        self.params = get_parameters(self.instance)

        self.create_widgets()

    def create_widgets(self):
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10), padding=5)
        style.configure("TLabel", font=("Helvetica", 10))
        style.configure("TCombobox", font=("Helvetica", 10))

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill="both", expand=True)

        param_frame = ttk.LabelFrame(main_frame, text="Параметры", padding="5")
        param_frame.pack(fill="x", pady=5)

        ttk.Label(param_frame, text="Набор параметров:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        instances = ["128s", "128f", "192s", "192f", "256s", "256f"]
        self.instance_var = tk.StringVar(value=self.instance)
        self.instance_var.trace("w", self.update_instance)
        ttk.Combobox(param_frame, textvariable=self.instance_var, values=instances, state="readonly", width=10).grid(row=0, column=1, padx=5, pady=5, sticky="w")

        key_frame = ttk.LabelFrame(main_frame, text="Управление ключами", padding="5")
        key_frame.pack(fill="x", pady=5)

        ttk.Label(key_frame, text="Ключи:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        ttk.Button(key_frame, text="Сгенерировать пару ключей", command=self.generate_keys).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(key_frame, text="Сохранить ключи", command=self.save_keys).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(key_frame, text="Загрузить ключи", command=self.load_keys).grid(row=0, column=3, padx=5, pady=5)

        file_frame = ttk.LabelFrame(main_frame, text="Работа с файлами и подписью", padding="5")
        file_frame.pack(fill="x", pady=5)

        ttk.Label(file_frame, text="Файл:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.file_label = ttk.Label(file_frame, text="Файл не выбран", width=50, anchor="w")
        self.file_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ttk.Button(file_frame, text="Выбрать файл", command=self.select_file).grid(row=0, column=2, padx=5, pady=5)

        ttk.Button(file_frame, text="Подписать файл (хэш)", command=self.sign_file_hash_with_progress).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Проверить файл", command=self.verify_file).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(file_frame, text="Сохранить подпись", command=self.save_signature).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(file_frame, text="Загрузить подпись", command=self.load_signature).grid(row=2, column=2, padx=5, pady=5)

        result_frame = ttk.LabelFrame(main_frame, text="Результат", padding="5")
        result_frame.pack(fill="both", expand=True, pady=5)

        self.result_text = tk.Text(result_frame, height=15, width=70, state='disabled', font=("Courier", 10))
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.result_text.config(yscrollcommand=scrollbar.set)

    def update_instance(self, *args):
        self.instance = self.instance_var.get()
        self.params = get_parameters(self.instance)
        self.update_result(f"Выбран набор параметров: {self.instance}\nПараметры: {self.params}")

    def select_file(self):
        self.file_path = filedialog.askopenfilename(title="Выберите файл для подписи или проверки")
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))
            self.update_result(f"Выбран файл: {self.file_path}")

    def generate_keys(self):
        self.sk, self.pk = spx_keygen(params=self.params)
        self.update_result(f"Ключи успешно сгенерированы!\n"
                          f"Набор параметров: {self.instance}\n"
                          f"Секретный ключ: {[x.hex()[:16] + '...' for x in self.sk]}\n"
                          f"Открытый ключ: {[x.hex()[:16] + '...' for x in self.pk]}")

    def sign_file_hash_with_progress(self):
        """Подпись файла с прогресс-баром в отдельном окне."""
        if not self.sk:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте или загрузите секретный ключ!")
            return
        if not self.file_path:
            messagebox.showerror("Ошибка", "Сначала выберите файл!")
            return

        progress_window = tk.Toplevel(self.root)
        progress_window.title("Подпись файла")
        progress_window.geometry("300x100")
        progress_window.transient(self.root)
        progress_window.grab_set()

        ttk.Label(progress_window, text="Выполняется подпись...").pack(pady=10)
        progress_bar = ttk.Progressbar(progress_window, mode="indeterminate", length=200)
        progress_bar.pack(pady=10)
        progress_bar.start(10)

        def perform_signing():
            file_hash = self.compute_file_hash(self.file_path)
            self.signature = spx_sign(file_hash, self.sk, params=self.params)
            self.update_result(f"Хэш файла подписан!\n"
                              f"Хэш: {file_hash.hex()[:16]}...\n"
                              f"Длина подписи: {sum(len(x) if isinstance(x, bytes) else len(x) for x in self.signature)} байт "
                              f"({len(self.signature)} компонентов)")
            progress_window.destroy()

        self.root.after(100, perform_signing)

    def verify_file(self):
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
        blake2b = hashlib.blake2b()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                blake2b.update(chunk)
        return blake2b.digest()

    def save_keys(self):
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
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, text)
        self.result_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = GUI(root)
    root.mainloop()