import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from core import IMAGE_TYPES, StegoError, extract_message, hide_message


class StegoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Стеганография")
        self.geometry("520x380")
        self.minsize(480, 340)
        self.image_path = tk.StringVar()
        self.password = tk.StringVar()
        self._build()

    def _build(self) -> None:
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Изображение").grid(row=0, column=0, sticky="w")
        ttk.Entry(top, textvariable=self.image_path).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Button(top, text="…", width=3, command=self._pick_image).grid(row=0, column=2)

        ttk.Label(top, text="Пароль").grid(row=1, column=0, sticky="w", pady=(8, 0))
        ttk.Entry(top, textvariable=self.password, show="*").grid(
            row=1, column=1, columnspan=2, sticky="ew", pady=(8, 0)
        )
        top.columnconfigure(1, weight=1)

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        hide_tab = ttk.Frame(notebook, padding=10)
        notebook.add(hide_tab, text="Запись")
        self.hide_text = scrolledtext.ScrolledText(hide_tab, height=8, wrap="word")
        self.hide_text.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Button(hide_tab, text="Скрыть и сохранить копию", command=self._hide).pack(anchor="w")

        read_tab = ttk.Frame(notebook, padding=10)
        notebook.add(read_tab, text="Чтение")
        self.read_text = scrolledtext.ScrolledText(
            read_tab, height=8, wrap="word", font=("Consolas", 9)
        )
        self.read_text.pack(fill="both", expand=True, pady=(0, 8))
        ttk.Button(read_tab, text="Извлечь и расшифровать", command=self._extract).pack(anchor="w")

    def _pick_image(self) -> None:
        path = filedialog.askopenfilename(filetypes=IMAGE_TYPES)
        if path:
            self.image_path.set(path)

    def _hide(self) -> None:
        path = self.image_path.get().strip()
        if not path:
            messagebox.showwarning("Запись", "Выберите изображение.")
            return
        try:
            out = hide_message(path, self.hide_text.get("1.0", "end").strip(), self.password.get())
        except StegoError as exc:
            messagebox.showerror("Запись", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Запись", f"Ошибка: {exc}")
            return
        messagebox.showinfo(
            "Запись",
            f"Сохранено:\n{out}\n\nСравните с исходником в проводнике.",
        )

    def _extract(self) -> None:
        path = self.image_path.get().strip()
        if not path:
            messagebox.showwarning("Чтение", "Выберите изображение.")
            return
        try:
            text = extract_message(path, self.password.get())
        except StegoError as exc:
            messagebox.showerror("Чтение", str(exc))
            return
        except Exception as exc:
            messagebox.showerror("Чтение", f"Ошибка: {exc}")
            return
        self.read_text.delete("1.0", "end")
        self.read_text.insert("1.0", text)
        messagebox.showinfo("Чтение", "Данные успешно извлечены.")


def run_app() -> None:
    StegoApp().mainloop()
