from Crypto.Hash import SHA256
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS

DEFAULT_KEY_SIZE = 2048
DSS_MODE = "fips-186-3"


class DSACore:
    def __init__(self) -> None:
        self.private_key = None
        self.public_key = None

    def generate(self, key_size: int = DEFAULT_KEY_SIZE) -> None:
        self.private_key = DSA.generate(key_size)
        self.public_key = self.private_key.publickey()

    def load_private(self, path: str) -> None:
        with open(path, "rb") as file:
            self.private_key = DSA.import_key(file.read())
        self.public_key = self.private_key.publickey()

    def load_public(self, path: str) -> None:
        with open(path, "rb") as file:
            self.public_key = DSA.import_key(file.read())

    def save_private(self, path: str) -> None:
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен")
        with open(path, "wb") as file:
            file.write(self.private_key.export_key())

    def save_public(self, path: str) -> None:
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен")
        with open(path, "wb") as file:
            file.write(self.public_key.export_key())

    def sign_file(self, data_path: str, sig_path: str) -> None:
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен")
        with open(data_path, "rb") as file:
            digest = SHA256.new(file.read())
        signature = DSS.new(self.private_key, DSS_MODE).sign(digest)
        with open(sig_path, "wb") as file:
            file.write(signature)

    def verify_file(self, data_path: str, sig_path: str) -> bool:
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен")
        with open(data_path, "rb") as file:
            digest = SHA256.new(file.read())
        with open(sig_path, "rb") as file:
            signature = file.read()
        try:
            DSS.new(self.public_key, DSS_MODE).verify(digest, signature)
            return True
        except ValueError:
            return False


def create_dsa(key_size: int = DEFAULT_KEY_SIZE) -> DSACore:
    core = DSACore()
    core.generate(key_size)
    return core
