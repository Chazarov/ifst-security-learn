from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from core import Algorithm, Mode

# --- Параметры (настройка под задачу пользователя) ---




print("Доступные алгоритмы: AES, CHACHA20, DES")
algo_str = input("Выберите алгоритм: ").strip().upper()
while algo_str not in (Algorithm.AES.value, Algorithm.CHACHA.value, Algorithm.DES.value):
    print("Неверный алгоритм. Допустимые значения: AES, CHACHA20, DES")
    algo_str = input("Выберите алгоритм: ").strip().upper()
alg = Algorithm(algo_str)


# --- MODE (ECB/CBC) ---

print("\nДоступные режимы: ECB, CBC  (для ChaCha20 режим игнорируется)")
mode_str = input("Выберите режим: ").strip().upper()
while mode_str not in (Mode.ECB.value, Mode.CBC.value):
    print("Неверный режим. Допустимые значения: ECB, CBC")
    mode_str = input("Выберите режим: ").strip().upper()
mode = Mode(mode_str)


# --- KEY (пока вводим строку, потом проверим длину) ---

key_input = None
while key_input is None:
    print("\nВведите ключ в виде строки (максимум 32 символа):")
    ks = input("KEY: ")[:32].encode("utf-8")
    if len(ks) < 8:
        print("Ключ слишком короткий, дополняем до 8 байт.")
        ks = ks.ljust(8, b"0")

    if alg == Algorithm.AES and len(ks) not in (16, 24, 32):
        print("Для AES ключ должен быть 16, 24 или 32 байта.")
        continue
    if alg == Algorithm.DES and len(ks) != 8:
        print("Для DES ключ должен быть 8 байт.")
        continue
    if alg == Algorithm.CHACHA and len(ks) != 32:
        print("Для ChaCha20 ключ должен быть 32 байта.")
        continue

    key_input = ks
KEY = key_input


# --- IV (для AES и DES) ---

iv_input = None
while iv_input is None:
    print("\nВведите IV (для AES требуется 16 байт, для DES 8 байт; введите минимум 8 символов):")
    vs = input("IV: ")[:16].encode("utf-8")
    if len(vs) < 8:
        print("IV слишком короткий, дополняем до 8 байт.")
        vs = vs.ljust(8, b"0")  # фикс: обязательно обновить значение после ljust

    if alg == Algorithm.AES and len(vs) != 16:
        print("Для AES IV должен быть 16 байт.")
        continue
    if alg == Algorithm.DES and len(vs) != 8:
        print("Для DES IV должен быть 8 байт.")
        continue

    # для ChaCha игнорируем проверку IV
    iv_input = vs
IV = iv_input


# --- NONCE (для ChaCha) ---

nonce_input = None
while nonce_input is None:
    print("\nВведите nonce (для ChaCha20 требуется 12 байт; введите минимум 12 символов):")
    ns = input("NONCE: ")[:12].encode("utf-8")
    if len(ns) < 12:
        print("Nonce слишком короткий, дополняем до 12 байт.")
        ns = ns.ljust(12, b"0")  # фикс: обязательно обновить значение после ljust

    if alg == Algorithm.CHACHA and len(ns) != 12:
        print("Для ChaCha20 nonce должен быть 12 байт.")
        continue
    # для AES/DES nonce игнорируется, но можно его просто сохранить

    nonce_input = ns
NONCE = nonce_input


# --- INPUT_FILE ---

print("\nВведите путь к входному файлу:")
inp_path = input("INPUT_FILE: ").strip()
while inp_path == "":
    print("Путь к входному файлу не может быть пустым.")
    inp_path = input("INPUT_FILE: ").strip()
INPUT_FILE = inp_path


# --- OUTPUT_FILE ---

print("\nВведите путь к выходному файлу:")
out_path = input("OUTPUT_FILE: ").strip()
while out_path == "":
    print("Путь к выходному файлу не может быть пустым.")
    out_path = input("OUTPUT_FILE: ").strip()
OUTPUT_FILE = out_path


# --- Дополнительная логичная проверка (для будущего использования) ---

if alg == Algorithm.CHACHA:
    # режим ECB/CBC не должен использоваться с ChaCha20 — это просто логическое замечание
    print("Режим ECB/CBC для ChaCha20 игнорируется; используется потоковый режим.")

# --- Конструктор шифра под выбранный алгоритм/режим ---

def get_cipher(algo_name: Algorithm, mode_name: Mode, key: bytes, iv:bytes, nonce:bytes):
    backend = default_backend()

    if algo_name == "AES":
        if mode_name == "ECB":
            return Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        else:  # CBC
            return Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

    elif algo_name == "DES":
        if mode_name == "ECB":
            return Cipher(algorithms.TripleDES(key), modes.ECB(), backend=backend)
        else:  # CBC
            return Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=backend)

    elif algo_name == Algorithm.CHACHA:
        # ChaCha20 не использует ECB/CBC, только stream с nonce
        return Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)

    raise ValueError("Unsupported algorithm")

# --- Функция шифрования файла блоками ---

def encrypt_file(in_path: str, out_path: str, cipher_factory:Cipher[Any]):
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        encryptor = cipher_factory.encryptor()

        while True:
            chunk = fin.read(4096)
            if not chunk:
                break
            encrypted = encryptor.update(chunk)
            fout.write(encrypted)

        # завершаем шифратор (для режимов с padding)
        final = encryptor.finalize()
        if final:
            fout.write(final)

# --- Выбор шифра и запуск ---

cipher = get_cipher(alg, mode, key_input, iv_input, nonce_input)

print(f"Encrypting with {alg} / {mode}...")
encrypt_file(inp_path, out_path, cipher)
print("Done.")