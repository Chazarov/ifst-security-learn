import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from core import (
    ALGORITHMS,
    MODES,
    KeyStore,
    all_ciphertexts_different,
    b64_decode,
    b64_encode,
    decrypt_message,
    demo_ecb_vs_cbc,
    encrypt_all_modes,
    encrypt_message,
)


class CipherApp(tk.Tk):
    def __init__(self, store: KeyStore) -> None:
        super().__init__()
        self.store = store
        self.last_encrypted: bytes | None = None
        self.last_algorithm: str | None = None
        self.last_mode: str | None = None

        self.title("Симметричное шифрование")
        self.geometry("760x620")
        self.minsize(640, 520)

        self._build_keys_panel()
        self._build_tabs()

    def _build_keys_panel(self) -> None:
        frame = ttk.LabelFrame(self, text="Ключи (base64)")
        frame.pack(fill="x", padx=10, pady=(10, 6))

        self.keys_text = tk.Text(frame, height=4, wrap="word", font=("Consolas", 9))
        self.keys_text.pack(fill="x", padx=8, pady=(6, 4))
        self.keys_text.configure(state="disabled")

        ttk.Button(frame, text="Сгенерировать новые ключи", command=self._regenerate_keys).pack(
            anchor="e", padx=8, pady=(0, 8)
        )
        self._refresh_keys_display()

    def _build_tabs(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_encrypt_tab(notebook)
        self._build_all_modes_tab(notebook)
        self._build_decrypt_tab(notebook)
        self._build_demo_tab(notebook)

    def _build_encrypt_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Шифрование")

        ttk.Label(tab, text="Текст:").pack(anchor="w")
        self.encrypt_input = scrolledtext.ScrolledText(tab, height=4, wrap="word")
        self.encrypt_input.pack(fill="x", pady=(4, 10))

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 10))

        ttk.Label(row, text="Алгоритм:").pack(side="left")
        self.encrypt_algorithm = ttk.Combobox(row, values=list(ALGORITHMS), state="readonly", width=8)
        self.encrypt_algorithm.set("AES")
        self.encrypt_algorithm.pack(side="left", padx=(6, 20))

        ttk.Label(row, text="Режим:").pack(side="left")
        self.encrypt_mode = ttk.Combobox(row, values=list(MODES), state="readonly", width=8)
        self.encrypt_mode.set("CBC")
        self.encrypt_mode.pack(side="left", padx=6)

        ttk.Button(tab, text="Зашифровать", command=self._encrypt).pack(anchor="w", pady=(0, 10))

        ttk.Label(tab, text="Результат:").pack(anchor="w")
        self.encrypt_output = scrolledtext.ScrolledText(tab, height=8, wrap="word", font=("Consolas", 9))
        self.encrypt_output.pack(fill="both", expand=True, pady=(4, 0))

    def _build_all_modes_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Все режимы")

        ttk.Label(tab, text="Текст:").pack(anchor="w")
        self.all_modes_input = scrolledtext.ScrolledText(tab, height=4, wrap="word")
        self.all_modes_input.pack(fill="x", pady=(4, 10))

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 10))

        ttk.Label(row, text="Алгоритм:").pack(side="left")
        self.all_modes_algorithm = ttk.Combobox(row, values=list(ALGORITHMS), state="readonly", width=8)
        self.all_modes_algorithm.set("AES")
        self.all_modes_algorithm.pack(side="left", padx=6)

        ttk.Button(tab, text="Зашифровать во всех режимах", command=self._encrypt_all_modes).pack(
            anchor="w", pady=(0, 10)
        )

        ttk.Label(tab, text="Результаты:").pack(anchor="w")
        self.all_modes_output = scrolledtext.ScrolledText(tab, height=14, wrap="word", font=("Consolas", 9))
        self.all_modes_output.pack(fill="both", expand=True, pady=(4, 0))

    def _build_decrypt_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Расшифровка")

        ttk.Label(tab, text="Шифротекст (base64):").pack(anchor="w")
        self.decrypt_input = scrolledtext.ScrolledText(tab, height=4, wrap="word", font=("Consolas", 9))
        self.decrypt_input.pack(fill="x", pady=(4, 10))

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 10))

        ttk.Label(row, text="Алгоритм:").pack(side="left")
        self.decrypt_algorithm = ttk.Combobox(row, values=list(ALGORITHMS), state="readonly", width=8)
        self.decrypt_algorithm.set("AES")
        self.decrypt_algorithm.pack(side="left", padx=(6, 20))

        ttk.Label(row, text="Режим:").pack(side="left")
        self.decrypt_mode = ttk.Combobox(row, values=list(MODES), state="readonly", width=8)
        self.decrypt_mode.set("CBC")
        self.decrypt_mode.pack(side="left", padx=6)

        buttons = ttk.Frame(tab)
        buttons.pack(fill="x", pady=(0, 10))

        ttk.Button(buttons, text="Расшифровать", command=self._decrypt).pack(side="left")
        ttk.Button(buttons, text="Подставить последнее шифрование", command=self._use_last_encrypted).pack(
            side="left", padx=(8, 0)
        )

        ttk.Label(tab, text="Результат:").pack(anchor="w")
        self.decrypt_output = scrolledtext.ScrolledText(tab, height=8, wrap="word")
        self.decrypt_output.pack(fill="both", expand=True, pady=(4, 0))

    def _build_demo_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="ECB vs CBC")

        ttk.Label(
            tab,
            text="Демонстрация на сообщении с повторяющимися блоками (AES).",
        ).pack(anchor="w", pady=(0, 10))

        ttk.Button(tab, text="Запустить демонстрацию", command=self._run_demo).pack(anchor="w", pady=(0, 10))

        self.demo_output = scrolledtext.ScrolledText(tab, height=20, wrap="word", font=("Consolas", 9))
        self.demo_output.pack(fill="both", expand=True)

    def _refresh_keys_display(self) -> None:
        lines = [
            f"AES ключ: {b64_encode(self.store.aes_key)}",
            f"AES IV:   {b64_encode(self.store.aes_iv)}",
            f"DES ключ: {b64_encode(self.store.des_key)}",
            f"DES IV:   {b64_encode(self.store.des_iv)}",
        ]
        self.keys_text.configure(state="normal")
        self.keys_text.delete("1.0", "end")
        self.keys_text.insert("1.0", "\n".join(lines))
        self.keys_text.configure(state="disabled")

    def _regenerate_keys(self) -> None:
        self.store.regenerate()
        self.last_encrypted = None
        self.last_algorithm = None
        self.last_mode = None
        self._refresh_keys_display()
        messagebox.showinfo("Ключи", "Новые ключи сгенерированы.")

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _encrypt(self) -> None:
        text = self.encrypt_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Шифрование", "Введите текст.")
            return

        algorithm = self.encrypt_algorithm.get()
        mode = self.encrypt_mode.get()

        try:
            encrypted = encrypt_message(self.store, text, algorithm, mode)
        except Exception as exc:
            messagebox.showerror("Шифрование", str(exc))
            return

        self.last_encrypted = encrypted
        self.last_algorithm = algorithm
        self.last_mode = mode

        result = "\n".join(
            [
                f"Алгоритм: {algorithm}",
                f"Режим: {mode}",
                f"Исходный текст: {text}",
                f"Длина исходного текста: {len(text.encode('utf-8'))} байт",
                f"Шифротекст (base64): {b64_encode(encrypted)}",
                f"Длина шифротекста: {len(encrypted)} байт",
            ]
        )
        self._set_text(self.encrypt_output, result)

    def _encrypt_all_modes(self) -> None:
        text = self.all_modes_input.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("Все режимы", "Введите текст.")
            return

        algorithm = self.all_modes_algorithm.get()

        try:
            results = encrypt_all_modes(self.store, text, algorithm)
        except Exception as exc:
            messagebox.showerror("Все режимы", str(exc))
            return

        lines = [
            f"Алгоритм: {algorithm}",
            f"Исходный текст: {text}",
            f"Длина исходного текста: {len(text.encode('utf-8'))} байт",
            "",
        ]

        for mode, encrypted in results:
            lines.extend(
                [
                    f"Режим {mode}:",
                    f"  base64: {b64_encode(encrypted)}",
                    f"  длина: {len(encrypted)} байт",
                    "",
                ]
            )

        lines.append("Сравнение длин:")
        for mode, encrypted in results:
            lines.append(f"  {algorithm}-{mode}: {len(encrypted)} байт")

        lines.append("")
        if len(results) >= 2:
            if all_ciphertexts_different(results):
                lines.append("Все режимы дают разный шифротекст.")
            else:
                lines.append("Некоторые режимы дали одинаковый шифротекст.")

        self._set_text(self.all_modes_output, "\n".join(lines))

    def _use_last_encrypted(self) -> None:
        if not self.last_encrypted or not self.last_algorithm or not self.last_mode:
            messagebox.showinfo("Расшифровка", "Нет последнего шифрования.")
            return

        self.decrypt_algorithm.set(self.last_algorithm)
        self.decrypt_mode.set(self.last_mode)
        self._set_text(self.decrypt_input, b64_encode(self.last_encrypted))

    def _decrypt(self) -> None:
        encrypted_b64 = self.decrypt_input.get("1.0", "end").strip()
        if not encrypted_b64:
            messagebox.showwarning("Расшифровка", "Введите шифротекст.")
            return

        algorithm = self.decrypt_algorithm.get()
        mode = self.decrypt_mode.get()

        try:
            ciphertext = b64_decode(encrypted_b64)
            plaintext = decrypt_message(self.store, ciphertext, algorithm, mode)
        except Exception as exc:
            messagebox.showerror("Расшифровка", f"Ошибка: {exc}")
            return

        self._set_text(self.decrypt_output, plaintext)

    def _run_demo(self) -> None:
        demo = demo_ecb_vs_cbc(self.store)

        lines = [
            f"Исходное сообщение: {demo.message!r}",
            f"Длина: {demo.message_len} байт = {demo.message_len // 16} блока по 16 байт",
            "Блок 1 и блок 2 открытого текста одинаковые.",
            "",
            "ECB — каждый блок шифруется отдельно:",
        ]

        for index, block in enumerate(demo.ecb_blocks, start=1):
            lines.append(f"  Блок {index}: {block}")

        lines.extend(
            [
                "",
                f"  Блок 1 == Блок 2 (одинаковый открытый текст): {demo.ecb_plaintext_blocks_equal}",
                "",
                "CBC — каждый блок XOR-ится с предыдущим шифротекстом:",
            ]
        )

        for index, block in enumerate(demo.cbc_blocks, start=1):
            lines.append(f"  Блок {index}: {block}")

        lines.extend(
            [
                "",
                f"  Блок 1 == Блок 2 (одинаковый открытый текст): {demo.cbc_plaintext_blocks_equal}",
                "",
                "Итог: ECB раскрывает повторяющиеся фрагменты, CBC — нет.",
            ]
        )

        self._set_text(self.demo_output, "\n".join(lines))


def run_app(store: KeyStore) -> None:
    app = CipherApp(store)
    app.mainloop()
