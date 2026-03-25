from enum import Enum
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel

# --- Параметры (настройка под задачу пользователя) ---




class Algorithm(Enum, str):
    AES = "AES"
    CHACHA = "CHACHA20"
    DES = "DES"


class Mode(Enum, str):
    CBC = "CBC"
    ECB = "ECB"

class DataModel(BaseModel):
    key:str
    iv:str
    nonce:str
    input_file:str
    output_file:str
    alg:Algorithm
    mode:Mode



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



def decrypt_file(in_path: str, out_path: str, cipher_factory: Cipher[Any]):
    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        decryptor = cipher_factory.decryptor()

        while True:
            chunk = fin.read(4096)
            if not chunk:
                break
            decrypted = decryptor.update(chunk)
            fout.write(decrypted)

        final = decryptor.finalize()
        if final:
            fout.write(final)