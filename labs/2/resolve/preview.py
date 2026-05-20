import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from core import (
    ALGORITHMS,
    DEFAULT_DEMO_MESSAGE,
    MODES,
    KeyStore,
    b64_decode,
    b64_encode,
    decrypt_message,
    demo_ecb_vs_cbc,
    encrypt_message,
    format_ecb_cbc_demo,
    get_key_iv_b64,
    set_key_iv_b64,
)


class CipherApp(tk.Tk):
    def __init__(self, store: KeyStore) -> None:
        super().__init__()
        self.store = store

        self.title("Симметричное шифрование")
        self.geometry("700x540")
        self.minsize(560, 460)

        self._build_keys_bar()
        self._build_tabs()

    def _build_keys_bar(self) -> None:
        frame = ttk.Frame(self, padding=10)
        frame.pack(fill="x")

        row1 = ttk.Frame(frame)
        row1.pack(fill="x")

        ttk.Label(row1, text="Алгоритм").pack(side="left")
        self.algorithm = ttk.Combobox(row1, values=list(ALGORITHMS), state="readonly", width=6)
        self.algorithm.set("AES")
        self.algorithm.pack(side="left", padx=(4, 12))
        self.algorithm.bind("<<ComboboxSelected>>", self._on_algorithm_changed)

        ttk.Label(row1, text="Ключ").pack(side="left")
        self.key_entry = ttk.Entry(row1)
        self.key_entry.pack(side="left", fill="x", expand=True, padx=(4, 12))

        ttk.Label(row1, text="IV").pack(side="left")
        self.iv_entry = ttk.Entry(row1)
        self.iv_entry.pack(side="left", fill="x", expand=True, padx=(4, 12))

        ttk.Button(row1, text="Случайные", command=self._random_keys).pack(side="left", padx=(0, 4))
        ttk.Button(row1, text="Применить", command=self._apply_keys).pack(side="left")

        self._load_keys_to_form()

    def _build_tabs(self) -> None:
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_crypto_tab(notebook)
        self._build_demo_tab(notebook)

    def _build_crypto_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="Шифрование")

        self.crypto_input = scrolledtext.ScrolledText(tab, height=5, wrap="word")
        self.crypto_input.pack(fill="x", pady=(0, 8))

        row = ttk.Frame(tab)
        row.pack(fill="x", pady=(0, 8))

        ttk.Label(row, text="Режим").pack(side="left")
        self.mode = ttk.Combobox(row, values=list(MODES), state="readonly", width=8)
        self.mode.set("CBC")
        self.mode.pack(side="left", padx=(4, 12))

        ttk.Button(row, text="Зашифровать", command=self._encrypt).pack(side="left", padx=(0, 4))
        ttk.Button(row, text="Расшифровать", command=self._decrypt).pack(side="left")

        self.crypto_output = scrolledtext.ScrolledText(tab, height=12, wrap="word", font=("Consolas", 9))
        self.crypto_output.pack(fill="both", expand=True)

    def _build_demo_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=10)
        notebook.add(tab, text="ECB vs CBC")

        self.demo_input = scrolledtext.ScrolledText(tab, height=4, wrap="word")
        self.demo_input.pack(fill="x", pady=(0, 8))
        self.demo_input.insert("1.0", DEFAULT_DEMO_MESSAGE)

        ttk.Button(tab, text="Сравнить", command=self._run_demo).pack(anchor="w", pady=(0, 8))

        self.demo_output = scrolledtext.ScrolledText(tab, height=16, wrap="word", font=("Consolas", 9))
        self.demo_output.pack(fill="both", expand=True)

    def _current_algorithm(self) -> str:
        return self.algorithm.get()

    def _load_keys_to_form(self) -> None:
        key_b64, iv_b64 = get_key_iv_b64(self.store, self._current_algorithm())
        self.key_entry.delete(0, "end")
        self.key_entry.insert(0, key_b64)
        self.iv_entry.delete(0, "end")
        self.iv_entry.insert(0, iv_b64)

    def _on_algorithm_changed(self, _event: tk.Event | None = None) -> None:
        self._load_keys_to_form()

    def _apply_keys(self) -> None:
        try:
            set_key_iv_b64(
                self.store,
                self._current_algorithm(),
                self.key_entry.get(),
                self.iv_entry.get(),
            )
        except Exception as exc:
            messagebox.showerror("Ключи", str(exc))
            return

        messagebox.showinfo("Ключи", "Ключ и IV применены.")

    def _random_keys(self) -> None:
        self.store.regenerate(self._current_algorithm())
        self._load_keys_to_form()

    def _set_text(self, widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.delete("1.0", "end")
        widget.insert("1.0", text)

    def _get_text(self, widget: scrolledtext.ScrolledText) -> str:
        return widget.get("1.0", "end").strip()

    def _encrypt(self) -> None:
        text = self._get_text(self.crypto_input)
        if not text:
            messagebox.showwarning("Шифрование", "Введите текст.")
            return

        algorithm = self._current_algorithm()
        mode = self.mode.get()

        try:
            self._apply_keys_silent()
            encrypted = encrypt_message(self.store, text, algorithm, mode)
        except Exception as exc:
            messagebox.showerror("Шифрование", str(exc))
            return

        self._set_text(
            self.crypto_output,
            "\n".join(
                [
                    f"{algorithm}-{mode}",
                    f"base64: {b64_encode(encrypted)}",
                    f"байт: {len(encrypted)}",
                ]
            ),
        )

    def _decrypt(self) -> None:
        text = self._get_text(self.crypto_input)
        if not text:
            messagebox.showwarning("Расшифровка", "Введите шифротекст в base64.")
            return

        algorithm = self._current_algorithm()
        mode = self.mode.get()

        try:
            self._apply_keys_silent()
            plaintext = decrypt_message(self.store, b64_decode(text), algorithm, mode)
        except Exception as exc:
            messagebox.showerror("Расшифровка", str(exc))
            return

        self._set_text(self.crypto_output, plaintext)

    def _apply_keys_silent(self) -> None:
        set_key_iv_b64(
            self.store,
            self._current_algorithm(),
            self.key_entry.get(),
            self.iv_entry.get(),
        )

    def _run_demo(self) -> None:
        text = self._get_text(self.demo_input)
        algorithm = self._current_algorithm()

        try:
            self._apply_keys_silent()
            demo = demo_ecb_vs_cbc(self.store, text, algorithm)
        except Exception as exc:
            messagebox.showerror("ECB vs CBC", str(exc))
            return

        self._set_text(self.demo_output, format_ecb_cbc_demo(demo))


def run_app(store: KeyStore) -> None:
    app = CipherApp(store)
    app.mainloop()
