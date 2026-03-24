from pathlib import Path

from core import Algorithm, Mode, encrypt_file, get_cipher, DataModel
import json

# --- Параметры (настройка под задачу пользователя) ---


cfg_path = Path("data.json")

if cfg_path.exists():
    with open(cfg_path, "r") as file:
        data_raw = json.load(file)  # используем json.load, а не file.read() + json.loads
else:
    # создаём пустой JSON-файл с нулевыми значениями (все null)
    empty_data = {
        "key": None,
        "inv": None,
        "nonce": None,
        "input_file": None,
        "output_file": None,
        "alg": None,
        "mode": None,
    }
    cfg_path.write_text(json.dumps(empty_data, indent=2, ensure_ascii=False))
    data_raw = empty_data

data = DataModel.model_validate(data_raw)

print("Указать параметры заново? Y/(N or Enter or Any)")
use_default_str = input().strip().upper()
while use_default_str not in ("Y", "N", "YES", "NO", ""):
    print("Некорректный ввод выберите  Y или N")
    use_default_str = input().strip().upper()
    if use_default_str == "":
        use_default_str = "N"
renew_params = use_default_str in ("Y", "YES")


alg = data.alg
if(alg == None or renew_params):
    print(f"Доступные алгоритмы: AES, CHACHA20, DES  Текущее значение: {data.alg}")
    algo_str = input("Выберите алгоритм: ").strip().upper()
    while algo_str not in (Algorithm.AES.value, Algorithm.CHACHA.value, Algorithm.DES.value):
        print("Неверный алгоритм. Допустимые значения: AES, CHACHA20, DES")
        algo_str = input("Выберите алгоритм: ").strip().upper()
    alg = Algorithm(algo_str)


# --- MODE (ECB/CBC) ---

print(f"\nДоступные режимы: ECB, CBC  (для ChaCha20 режим игнорируется)" \
f" текущее значение: {data.mode}")
mode_str = input("Введите режим: ").strip().upper()
while mode_str not in (Mode.ECB.value, Mode.CBC.value):
    print("Неверный режим. Допустимые значения: ECB, CBC")
    mode_str = input("Введите режим: ").strip().upper()
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


# --- Выбор шифра и запуск ---

if __name__ == "__main__":
    cipher = get_cipher(alg, mode, key_input, iv_input, nonce_input)

    print(f"Encrypting with {alg} / {mode}...")
    encrypt_file(inp_path, out_path, cipher)
    print("Done.")