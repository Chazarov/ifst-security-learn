from pathlib import Path

from core import Algorithm, Mode, encrypt_file, get_cipher, DataModel
import json

# --- Параметры (настройка под задачу пользователя) ---


cfg_path = Path("data.json")

if cfg_path.exists():
    with open(cfg_path, "r") as file:
        data_raw = json.load(file)
else:
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
    while True:
        algo_str = input("Выберите алгоритм (Или enter чтобы оставить текущее): ").strip().upper()
        if algo_str == "":
            alg = data.alg
        try:
            alg = Algorithm(algo_str)
            break
        except:
            print(f"Некорректное значение. Введите еще раз")

mode = data.mode
if(mode == None or renew_params):
    print(f"\nДоступные режимы: ECB, CBC  (для ChaCha20 режим игнорируется)" \
    f" текущее значение: {data.mode}")
    while True:
        mode_str = input("Введите режим(Или enter чтобы оставить текущее): ").strip().upper()
        if mode_str == "":
            mode = data.mode
        try:
            mode = Mode(mode_str)
            break
        except:
            print(f"Некорректное значение. Введите еще раз")

key = data.key
if (data.key is None or renew_params):
    print(f"\nВведите ключ в виде строки (максимум 32 символа)\n" \
          f"(текущее значение:{data.key}):")
    while True:
        key = input("(Или enter чтобы оставить текущее) KEY: ")
        if key == "":
            if data.key != None:
                key = data.key
            else:
                print("ключ не может быть пустым. Повторите ввод!")
                continue
        ks = key[:32].encode("utf-8")
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
        key = ks.decode("utf-8")
        break


iv = data.iv
if(iv is None or renew_params):
    print(f"\nВведите IV (для AES требуется 16 байт, для DES 8 байт; введите минимум 8 символов) "
          f"\n (текущее значение: {data.iv}):")
    while True:
        iv = input("(Или enter чтобы оставить текущее) IV: ")
        if iv == "":
            if data.iv!= None:
                iv = data.iv
            else:
                print(" IV не может быть пустым! Повторите ввод!")
                continue
        
        s = iv[:16].encode("utf-8")
        if len(s) < 8:
            print("IV слишком короткий, дополняем до 8 байт.")
            s = s.ljust(8, b"0") 
        if alg == Algorithm.AES and len(s) != 16:
            print("Для AES IV должен быть 16 байт.")
            continue
        if alg == Algorithm.DES and len(s) != 8:
            print("Для DES IV должен быть 8 байт.")
            continue
        iv = s.decode("utf-8")
        break

nonce = data.nonce
if(nonce is None or renew_params):
    print("\nВведите nonce (для ChaCha20 требуется 12 байт; введите минимум 12 символов)\n"
          f"текущее значение: {data.nonce}")
    while True:
        nonce = input("(Или enter чтобы оставить текущее) NONCE: ")
        if nonce == "":
            if data.nonce != None:
                nonce = data.nonce
            else:
                print(" nonce не может быть пустым! Повторите ввод!")
                continue
        ns = nonce[:12].encode("utf-8")
        if len(ns) < 12:
            print("Nonce слишком короткий, дополняем до 12 байт.")
            ns = ns.ljust(12, b"0")

        if alg == Algorithm.CHACHA and len(ns) != 12:
            print("Для ChaCha20 nonce должен быть 12 байт.")
            continue
        nonce = ns.decode("utf-8")
        break


# --- INPUT_FILE ---

inp_path = data.input_file
if(inp_path is None or renew_params):
    print("\nВведите путь к входному файлу. "\
          f"\n (текущее значение: {data.input_file}):")
    while True:
        inp_path = input("(enter чтобы оставить текущее) INPUT_FILE:").strip()
        if inp_path == "" :
            inp_path = data.input_file
        if inp_path == None: #type: ignore
            print("Путь к входному файлу не может быть пустым.")
            continue
        break


# --- OUTPUT_FILE ---

out_path = data.output_file
if(out_path is None or renew_params):
    print("\nВведите путь к выходному файлу. "\
          f"\n (текущее значение: {data.output_file}):")
    while True:
        out_path = input("(enter чтобы оставить текущее) INPUT_FILE:").strip()
        if out_path == "" :
            out_path = data.output_file
        if out_path == None: #type: ignore
            print("Путь к входному файлу не может быть пустым.")
            continue
        break


# --- Дополнительная логичная проверка (для будущего использования) ---

if alg == Algorithm.CHACHA:
    # режим ECB/CBC не должен использоваться с ChaCha20 — это просто логическое замечание
    print("Режим ECB/CBC для ChaCha20 игнорируется; используется потоковый режим.")

# --- Конструктор шифра под выбранный алгоритм/режим ---


# --- Выбор шифра и запуск ---
if __name__ == "__main__":
    cipher = get_cipher(alg, mode, key, iv, nonce)

    print(f"Encrypting with {alg} / {mode}...")
    encrypt_file(inp_path, out_path, cipher)
    print("Done.")