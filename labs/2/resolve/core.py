import base64
from dataclasses import dataclass

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ALGORITHMS = ("AES", "DES")
MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")
REPEATED_DEMO_MESSAGE = "AAAAAAAABBBBBBBB" * 2


class SymmetricCipher:
    def __init__(self) -> None:
        self.key: bytes | None = None
        self.iv: bytes | None = None
        self.algorithm: str | None = None
        self.mode: str | None = None

    def generate_key_iv(self, algorithm: str = "AES") -> tuple[bytes, bytes]:
        self.algorithm = algorithm

        if algorithm == "AES":
            key_size = 32
            block_size = 16
        elif algorithm == "DES":
            key_size = 8
            block_size = 8
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")

        self.key = get_random_bytes(key_size)
        self.iv = get_random_bytes(block_size)
        return self.key, self.iv

    def set_key_iv(self, key: bytes, iv: bytes | None) -> None:
        self.key = key
        self.iv = iv

    def encrypt(self, plaintext: str | bytes, algorithm: str, mode: str) -> bytes:
        self.algorithm = algorithm
        self.mode = mode

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        if algorithm == "AES":
            cipher_alg = AES
            block_size = 16
        elif algorithm == "DES":
            cipher_alg = DES
            block_size = 8
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")

        if mode == "ECB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_ECB)
            padded_data = pad(plaintext, block_size)
        elif mode == "CBC":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CBC, self.iv)
            padded_data = pad(plaintext, block_size)
        elif mode == "CFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CFB, self.iv)
            padded_data = plaintext
        elif mode == "OFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_OFB, self.iv)
            padded_data = plaintext
        elif mode == "CTR":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CTR, nonce=self.iv[:8])
            padded_data = plaintext
        else:
            raise ValueError(f"Неизвестный режим: {mode}")

        return cipher.encrypt(padded_data)

    def decrypt(self, ciphertext: bytes, algorithm: str, mode: str) -> bytes:
        self.algorithm = algorithm
        self.mode = mode

        if algorithm == "AES":
            cipher_alg = AES
            block_size = 16
        elif algorithm == "DES":
            cipher_alg = DES
            block_size = 8
        else:
            raise ValueError(f"Неизвестный алгоритм: {algorithm}")

        if mode == "ECB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_ECB)
        elif mode == "CBC":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CBC, self.iv)
        elif mode == "CFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CFB, self.iv)
        elif mode == "OFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_OFB, self.iv)
        elif mode == "CTR":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CTR, nonce=self.iv[:8])
        else:
            raise ValueError(f"Неизвестный режим: {mode}")

        plaintext = cipher.decrypt(ciphertext)

        if mode in ("ECB", "CBC"):
            plaintext = unpad(plaintext, block_size)

        return plaintext


@dataclass
class KeyStore:
    cipher: SymmetricCipher
    aes_key: bytes
    aes_iv: bytes
    des_key: bytes
    des_iv: bytes

    @classmethod
    def create(cls) -> "KeyStore":
        cipher = SymmetricCipher()
        aes_key, aes_iv = cipher.generate_key_iv("AES")
        des_key, des_iv = cipher.generate_key_iv("DES")
        return cls(cipher, aes_key, aes_iv, des_key, des_iv)

    def regenerate(self) -> None:
        self.aes_key, self.aes_iv = self.cipher.generate_key_iv("AES")
        self.des_key, self.des_iv = self.cipher.generate_key_iv("DES")

    def get_key_iv(self, algorithm: str) -> tuple[bytes, bytes]:
        if algorithm == "AES":
            return self.aes_key, self.aes_iv
        if algorithm == "DES":
            return self.des_key, self.des_iv
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text)


def _prepare_cipher(store: KeyStore, algorithm: str, mode: str) -> None:
    key, iv = store.get_key_iv(algorithm)
    store.cipher.set_key_iv(key, None if mode == "ECB" else iv)


def encrypt_message(store: KeyStore, plaintext: str, algorithm: str, mode: str) -> bytes:
    _prepare_cipher(store, algorithm, mode)
    return store.cipher.encrypt(plaintext, algorithm, mode)


def decrypt_message(store: KeyStore, ciphertext: bytes, algorithm: str, mode: str) -> str:
    _prepare_cipher(store, algorithm, mode)
    return store.cipher.decrypt(ciphertext, algorithm, mode).decode("utf-8")


def encrypt_all_modes(store: KeyStore, plaintext: str, algorithm: str) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    for mode in MODES:
        encrypted = encrypt_message(store, plaintext, algorithm, mode)
        results.append((mode, encrypted))
    return results


def all_ciphertexts_different(results: list[tuple[str, bytes]]) -> bool:
    ciphertexts = [item[1] for item in results]
    return len(ciphertexts) == len(set(ciphertexts))


@dataclass
class EcbCbcDemo:
    message: str
    message_len: int
    ecb_blocks: list[str]
    cbc_blocks: list[str]
    ecb_plaintext_blocks_equal: bool
    cbc_plaintext_blocks_equal: bool


def demo_ecb_vs_cbc(store: KeyStore) -> EcbCbcDemo:
    ecb_enc = encrypt_message(store, REPEATED_DEMO_MESSAGE, "AES", "ECB")
    cbc_enc = encrypt_message(store, REPEATED_DEMO_MESSAGE, "AES", "CBC")

    def to_blocks(ciphertext: bytes, block_size: int = 16) -> list[str]:
        return [ciphertext[i : i + block_size].hex() for i in range(0, len(ciphertext), block_size)]

    return EcbCbcDemo(
        message=REPEATED_DEMO_MESSAGE,
        message_len=len(REPEATED_DEMO_MESSAGE),
        ecb_blocks=to_blocks(ecb_enc),
        cbc_blocks=to_blocks(cbc_enc),
        ecb_plaintext_blocks_equal=ecb_enc[0:16] == ecb_enc[16:32],
        cbc_plaintext_blocks_equal=cbc_enc[0:16] == cbc_enc[16:32],
    )
