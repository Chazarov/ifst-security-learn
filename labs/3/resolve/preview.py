import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core import DEFAULT_KEY_SIZE, RSACrypto, format_key_info, get_key_info


class RSAApp(tk.Tk):
    def __init__(self, crypto: RSACrypto) -> None:
        super().__init__()
        self.crypto = crypto

        self.title("RSA — асимметричное шифрование")
        self.geometry("720x560")
        self.minsize(620, 480)

        self._build_header()
        self._build_tabs()

    def _build_header(self) -> None:
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="x")

        ttk.Label(frame, text="RSA шифрование файлов", font=("", 12, "bold")).pack(anchor="w")

        row = ttk.Frame(frame)
        row.pack(fill="x", pady=(8, 0))

        ttk.Label(row, text="Размер ключа:").pack(side="left")
        self.key_size = ttk.Combobox(row, values=["1024", "2048", "4096"], state="readonly", width=8)
        self.key_size.set(str(DEFAULT_KEY_SIZE))
        self.key_size.pack(side="left", padx=(6, 12))

        ttk.Button(row, text="Сгенерировать ключи", command=self._generate_keys).pack(side="left")

    def _build_tabs(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_keys_tab(notebook)
        self._build_files_tab(notebook)
        self._build_info_tab(notebook)

    def _build_keys_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Ключи")

        ttk.Label(tab, text="Экспорт и импорт ключей в XML.").pack(anchor="w", pady=(0, 10))

        export_frame = ttk.LabelFrame(tab, text="Экспорт")
        export_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(export_frame, text="Экспорт открытого ключа", command=self._export_public).pack(
            anchor="w", padx=8, pady=6
        )
        ttk.Button(export_frame, text="Экспорт закрытого ключа", command=self._export_private).pack(
            anchor="w", padx=8, pady=(0, 8)
        )

        import_frame = ttk.LabelFrame(tab, text="Импорт")
        import_frame.pack(fill="x")

        ttk.Button(import_frame, text="Импорт открытого ключа", command=self._import_public).pack(
            anchor="w", padx=8, pady=6
        )
        ttk.Button(import_frame, text="Импорт закрытого ключа", command=self._import_private).pack(
            anchor="w", padx=8, pady=(0, 8)
        )

    def _build_files_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Файлы")

        ttk.Label(tab, text="Шифрование и расшифровка файлов через PKCS1_OAEP.").pack(
            anchor="w", pady=(0, 10)
        )

        ttk.Button(tab, text="Зашифровать файл", command=self._encrypt_file).pack(anchor="w", pady=(0, 8))
        ttk.Button(tab, text="Расшифровать файл", command=self._decrypt_file).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab, text="Журнал:").pack(anchor="w")
        self.log_output = scrolledtext.ScrolledText(tab, height=16, wrap="word", font=("Consolas", 9))
        self.log_output.pack(fill="both", expand=True, pady=(4, 0))

    def _build_info_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Информация")

        ttk.Button(tab, text="Обновить информацию о ключах", command=self._refresh_info).pack(
            anchor="w", pady=(0, 10)
        )

        self.info_output = scrolledtext.ScrolledText(tab, height=20, wrap="word", font=("Consolas", 9))
        self.info_output.pack(fill="both", expand=True)
        self._refresh_info()

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _append_log(self, text: str) -> None:
        self.log_output.insert("end", text + "\n")
        self.log_output.see("end")

    def _generate_keys(self) -> None:
        try:
            key_size = int(self.key_size.get())
            self.crypto.generate_keys(key_size)
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return

        self._refresh_info()
        messagebox.showinfo("Ключи", f"Ключи сгенерированы ({key_size} бит).")

    def _export_public(self) -> None:
        filepath = filedialog.asksaveasfilename(
            title="Сохранить открытый ключ",
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            self.crypto.export_public_key_xml(filepath)
        except Exception as exc:
            messagebox.showerror("Экспорт", str(exc))
            return

        messagebox.showinfo("Экспорт", f"Открытый ключ сохранён:\n{filepath}")

    def _export_private(self) -> None:
        filepath = filedialog.asksaveasfilename(
            title="Сохранить закрытый ключ",
            defaultextension=".xml",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            self.crypto.export_private_key_xml(filepath)
        except Exception as exc:
            messagebox.showerror("Экспорт", str(exc))
            return

        messagebox.showwarning(
            "Экспорт",
            f"Закрытый ключ сохранён:\n{filepath}\n\nХраните закрытый ключ в безопасности.",
        )

    def _import_public(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Открыть файл с открытым ключом",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            self.crypto.import_public_key_xml(filepath)
        except Exception as exc:
            messagebox.showerror("Импорт", str(exc))
            return

        self._refresh_info()
        messagebox.showinfo("Импорт", "Открытый ключ загружен.")

    def _import_private(self) -> None:
        filepath = filedialog.askopenfilename(
            title="Открыть файл с закрытым ключом",
            filetypes=[("XML files", "*.xml"), ("All files", "*.*")],
        )
        if not filepath:
            return

        try:
            self.crypto.import_private_key_xml(filepath)
        except Exception as exc:
            messagebox.showerror("Импорт", str(exc))
            return

        self._refresh_info()
        messagebox.showinfo("Импорт", "Закрытый ключ загружен.")

    def _encrypt_file(self) -> None:
        if not self.crypto.public_key:
            messagebox.showwarning("Шифрование", "Сначала загрузите или сгенерируйте открытый ключ.")
            return

        input_file = filedialog.askopenfilename(title="Выберите файл для шифрования")
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(
            title="Сохранить зашифрованный файл",
            defaultextension=".enc",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not output_file:
            return

        try:
            self.crypto.encrypt_file(input_file, output_file)
        except Exception as exc:
            messagebox.showerror("Шифрование", str(exc))
            return

        self._append_log(f"Зашифрован: {os.path.basename(input_file)}")
        self._append_log(f"  Размер: {os.path.getsize(input_file)} байт")
        self._append_log(f"  Сохранён: {output_file}")
        self._append_log("")

    def _decrypt_file(self) -> None:
        if not self.crypto.private_key:
            messagebox.showwarning("Расшифровка", "Сначала загрузите или сгенерируйте закрытый ключ.")
            return

        input_file = filedialog.askopenfilename(
            title="Выберите зашифрованный файл",
            filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")],
        )
        if not input_file:
            return

        output_file = filedialog.asksaveasfilename(
            title="Сохранить расшифрованный файл",
            filetypes=[("All files", "*.*")],
        )
        if not output_file:
            return

        try:
            self.crypto.decrypt_file(input_file, output_file)
        except Exception as exc:
            messagebox.showerror("Расшифровка", str(exc))
            return

        self._append_log(f"Расшифрован: {os.path.basename(input_file)}")
        self._append_log(f"  Сохранён: {output_file}")
        self._append_log("")

    def _refresh_info(self) -> None:
        info = get_key_info(self.crypto)
        self._set_text(self.info_output, format_key_info(info))


def run_app(crypto: RSACrypto) -> None:
    app = RSAApp(crypto)
    app.mainloop()
