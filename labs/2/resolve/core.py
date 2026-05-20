import base64
from dataclasses import dataclass

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

ALGORITHMS = ("AES", "DES")
MODES = ("ECB", "CBC", "CFB", "OFB", "CTR")
DEFAULT_DEMO_MESSAGE = "AAAAAAAABBBBBBBB" * 2

ALGORITHM_PARAMS = {
    "AES": {"key_size": 32, "block_size": 16, "nonce_size": 8},
    "DES": {"key_size": 8, "block_size": 8, "nonce_size": 4},
}


class SymmetricCipher:
    def __init__(self) -> None:
        self.key: bytes | None = None
        self.iv: bytes | None = None
        self.algorithm: str | None = None
        self.mode: str | None = None

    def generate_key_iv(self, algorithm: str = "AES") -> tuple[bytes, bytes]:
        self.algorithm = algorithm
        params = ALGORITHM_PARAMS[algorithm]
        self.key = get_random_bytes(params["key_size"])
        self.iv = get_random_bytes(params["block_size"])
        return self.key, self.iv

    def set_key_iv(self, key: bytes, iv: bytes | None) -> None:
        self.key = key
        self.iv = iv

    def encrypt(self, plaintext: str | bytes, algorithm: str, mode: str) -> bytes:
        self.algorithm = algorithm
        self.mode = mode

        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")

        params = ALGORITHM_PARAMS[algorithm]
        cipher_alg = AES if algorithm == "AES" else DES
        block_size = params["block_size"]

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
            cipher = cipher_alg.new(
                self.key,
                cipher_alg.MODE_CTR,
                nonce=self.iv[: params["nonce_size"]],
            )
            padded_data = plaintext
        else:
            raise ValueError(f"Неизвестный режим: {mode}")

        return cipher.encrypt(padded_data)

    def decrypt(self, ciphertext: bytes, algorithm: str, mode: str) -> bytes:
        self.algorithm = algorithm
        self.mode = mode

        params = ALGORITHM_PARAMS[algorithm]
        cipher_alg = AES if algorithm == "AES" else DES
        block_size = params["block_size"]

        if mode == "ECB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_ECB)
        elif mode == "CBC":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CBC, self.iv)
        elif mode == "CFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CFB, self.iv)
        elif mode == "OFB":
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_OFB, self.iv)
        elif mode == "CTR":
            cipher = cipher_alg.new(
                self.key,
                cipher_alg.MODE_CTR,
                nonce=self.iv[: params["nonce_size"]],
            )
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

    def regenerate(self, algorithm: str) -> None:
        key, iv = self.cipher.generate_key_iv(algorithm)
        if algorithm == "AES":
            self.aes_key, self.aes_iv = key, iv
        else:
            self.des_key, self.des_iv = key, iv

    def get_key_iv(self, algorithm: str) -> tuple[bytes, bytes]:
        if algorithm == "AES":
            return self.aes_key, self.aes_iv
        if algorithm == "DES":
            return self.des_key, self.des_iv
        raise ValueError(f"Неизвестный алгоритм: {algorithm}")

    def set_key_iv(self, algorithm: str, key: bytes, iv: bytes) -> None:
        params = ALGORITHM_PARAMS[algorithm]
        if len(key) != params["key_size"]:
            raise ValueError(f"Ключ {algorithm} должен быть {params['key_size']} байт")
        if len(iv) != params["block_size"]:
            raise ValueError(f"IV {algorithm} должен быть {params['block_size']} байт")

        if algorithm == "AES":
            self.aes_key, self.aes_iv = key, iv
        else:
            self.des_key, self.des_iv = key, iv


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64_decode(text: str) -> bytes:
    return base64.b64decode(text.strip())


def get_key_iv_b64(store: KeyStore, algorithm: str) -> tuple[str, str]:
    key, iv = store.get_key_iv(algorithm)
    return b64_encode(key), b64_encode(iv)


def set_key_iv_b64(store: KeyStore, algorithm: str, key_b64: str, iv_b64: str) -> None:
    store.set_key_iv(algorithm, b64_decode(key_b64), b64_decode(iv_b64))


def _prepare_cipher(store: KeyStore, algorithm: str, mode: str) -> None:
    key, iv = store.get_key_iv(algorithm)
    store.cipher.set_key_iv(key, None if mode == "ECB" else iv)


def encrypt_message(store: KeyStore, plaintext: str, algorithm: str, mode: str) -> bytes:
    _prepare_cipher(store, algorithm, mode)
    return store.cipher.encrypt(plaintext, algorithm, mode)


def decrypt_message(store: KeyStore, ciphertext: bytes, algorithm: str, mode: str) -> str:
    _prepare_cipher(store, algorithm, mode)
    return store.cipher.decrypt(ciphertext, algorithm, mode).decode("utf-8")


def decrypt_bytes(store: KeyStore, ciphertext: bytes, algorithm: str, mode: str) -> bytes:
    _prepare_cipher(store, algorithm, mode)
    return store.cipher.decrypt(ciphertext, algorithm, mode)


@dataclass
class BlockComparison:
    block_a: int
    block_b: int
    ecb_equal: bool
    cbc_equal: bool


@dataclass
class EcbCbcDemo:
    message: str
    algorithm: str
    block_size: int
    plaintext_blocks: list[str]
    ecb_blocks: list[str]
    cbc_blocks: list[str]
    comparisons: list[BlockComparison]


def _split_blocks(data: bytes, block_size: int) -> list[bytes]:
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


def _find_repeated_block_pairs(blocks: list[bytes]) -> list[tuple[int, int]]:
    pairs: list[tuple[int, int]] = []
    for left in range(len(blocks)):
        for right in range(left + 1, len(blocks)):
            if blocks[left] == blocks[right]:
                pairs.append((left, right))
    return pairs


def demo_ecb_vs_cbc(store: KeyStore, message: str, algorithm: str = "AES") -> EcbCbcDemo:
    if not message:
        raise ValueError("Введите текст для сравнения")

    block_size = ALGORITHM_PARAMS[algorithm]["block_size"]
    plaintext = message.encode("utf-8")
    padded = pad(plaintext, block_size)
    plaintext_blocks = _split_blocks(padded, block_size)

    ecb_enc = encrypt_message(store, message, algorithm, "ECB")
    cbc_enc = encrypt_message(store, message, algorithm, "CBC")
    ecb_blocks = _split_blocks(ecb_enc, block_size)
    cbc_blocks = _split_blocks(cbc_enc, block_size)

    comparisons = [
        BlockComparison(
            block_a=left + 1,
            block_b=right + 1,
            ecb_equal=ecb_blocks[left] == ecb_blocks[right],
            cbc_equal=cbc_blocks[left] == cbc_blocks[right],
        )
        for left, right in _find_repeated_block_pairs(plaintext_blocks)
    ]

    return EcbCbcDemo(
        message=message,
        algorithm=algorithm,
        block_size=block_size,
        plaintext_blocks=[block.hex() for block in plaintext_blocks],
        ecb_blocks=[block.hex() for block in ecb_blocks],
        cbc_blocks=[block.hex() for block in cbc_blocks],
        comparisons=comparisons,
    )


def format_ecb_cbc_demo(demo: EcbCbcDemo) -> str:
    lines = [
        f"Текст: {demo.message!r}",
        f"Алгоритм: {demo.algorithm}, блок = {demo.block_size} байт",
        "",
        "Открытый текст (блоки):",
    ]

    for index, block in enumerate(demo.plaintext_blocks, start=1):
        lines.append(f"  {index}: {block}")

    lines.extend(["", "ECB:"])
    for index, block in enumerate(demo.ecb_blocks, start=1):
        lines.append(f"  {index}: {block}")

    lines.extend(["", "CBC:"])
    for index, block in enumerate(demo.cbc_blocks, start=1):
        lines.append(f"  {index}: {block}")

    lines.append("")
    if demo.comparisons:
        lines.append("Повторяющиеся блоки открытого текста:")
        for item in demo.comparisons:
            lines.append(
                f"  блок {item.block_a} и {item.block_b}: "
                f"ECB {'=' if item.ecb_equal else '≠'}, "
                f"CBC {'=' if item.cbc_equal else '≠'}"
            )
    else:
        lines.append("Повторяющихся блоков открытого текста нет.")

    return "\n".join(lines)
