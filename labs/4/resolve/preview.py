import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core import DEFAULT_KEY_SIZE, DSACore


class DSAApp(tk.Tk):
    def __init__(self, core: DSACore) -> None:
        super().__init__()
        self.core = core
        self.title("DSA — электронная подпись")
        self.geometry("640x440")
        self.minsize(600, 400)
        self._build()

    def _build(self) -> None:
        keys = ttk.LabelFrame(self, text="Ключи", padding=10)
        keys.pack(fill="x", padx=10, pady=(10, 0))

        row1 = ttk.Frame(keys)
        row1.pack(fill="x")

        ttk.Label(row1, text="Размер").pack(side="left")
        self.key_size = ttk.Combobox(row1, values=["1024", "2048", "3072"], state="readonly", width=8)
        self.key_size.set(str(DEFAULT_KEY_SIZE))
        self.key_size.pack(side="left", padx=(6, 12))

        ttk.Button(row1, text="Сгенерировать новые ключи", command=self._generate).pack(side="left")

        row2 = ttk.Frame(keys)
        row2.pack(fill="x", pady=(8, 0))

        ttk.Button(row2, text="Загрузить закрытый ключ", command=self._load_private).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(row2, text="Загрузить открытый ключ", command=self._load_public).pack(side="left")

        row3 = ttk.Frame(keys)
        row3.pack(fill="x", pady=(8, 0))

        ttk.Button(row3, text="Сохранить закрытый ключ", command=self._save_private).pack(
            side="left", padx=(0, 8)
        )
        ttk.Button(row3, text="Сохранить открытый ключ", command=self._save_public).pack(side="left")

        body = ttk.Frame(self, padding=10)
        body.pack(fill="both", expand=True)

        ttk.Button(body, text="Создать ЭЦП для файла", command=self._sign).pack(anchor="w", pady=(0, 6))
        ttk.Button(body, text="Проверить ЭЦП файла", command=self._verify).pack(anchor="w", pady=(0, 10))

        self.log = scrolledtext.ScrolledText(body, height=14, wrap="word", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True)
        self._log("Ключи сгенерированы. Можно подписать файл.")

    def _log(self, text: str) -> None:
        self.log.insert("end", text + "\n")
        self.log.see("end")

    def _generate(self) -> None:
        try:
            self.core.generate(int(self.key_size.get()))
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return
        self._log(f"Новая пара ключей ({self.key_size.get()} бит).")

    def _load_private(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PEM", "*.pem *.key"), ("All", "*.*")])
        if not path:
            return
        try:
            self.core.load_private(path)
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return
        self._log(f"Закрытый ключ: {os.path.basename(path)}")

    def _load_public(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("PEM", "*.pem *.pub"), ("All", "*.*")])
        if not path:
            return
        try:
            self.core.load_public(path)
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return
        self._log(f"Открытый ключ: {os.path.basename(path)}")

    def _save_private(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Сохранить закрытый ключ",
            defaultextension=".pem",
            filetypes=[("PEM", "*.pem *.key"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            self.core.save_private(path)
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return
        self._log(f"Закрытый ключ сохранён: {os.path.basename(path)}")

    def _save_public(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Сохранить открытый ключ",
            defaultextension=".pem",
            filetypes=[("PEM", "*.pub *.pem"), ("All", "*.*")],
        )
        if not path:
            return
        try:
            self.core.save_public(path)
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return
        self._log(f"Открытый ключ сохранён: {os.path.basename(path)}")

    def _sign(self) -> None:
        data_path = filedialog.askopenfilename(title="Файл для подписи")
        if not data_path:
            return
        sig_path = filedialog.asksaveasfilename(
            title="Сохранить ЭЦП",
            defaultextension=".sig",
            filetypes=[("Signature", "*.sig"), ("All", "*.*")],
        )
        if not sig_path:
            return
        try:
            self.core.sign_file(data_path, sig_path)
        except Exception as exc:
            messagebox.showerror("Подпись", str(exc))
            return
        self._log(f"Подпись создана: {os.path.basename(sig_path)}")
        messagebox.showinfo("Подпись", "ЭЦП сохранена в отдельный файл.")

    def _verify(self) -> None:
        data_path = filedialog.askopenfilename(title="Файл для проверки")
        if not data_path:
            return
        sig_path = filedialog.askopenfilename(
            title="Файл ЭЦП",
            filetypes=[("Signature", "*.sig"), ("All", "*.*")],
        )
        if not sig_path:
            return
        try:
            ok = self.core.verify_file(data_path, sig_path)
        except Exception as exc:
            messagebox.showerror("Проверка", str(exc))
            return
        if ok:
            self._log("Проверка: целостность подтверждена.")
            messagebox.showinfo("Проверка", "ЭЦП верна. Файл не изменён.")
        else:
            self._log("Проверка: подпись неверна или файл изменён.")
            messagebox.showwarning("Проверка", "ЭЦП неверна. Целостность нарушена.")


def run_app(core: DSACore) -> None:
    DSAApp(core).mainloop()
