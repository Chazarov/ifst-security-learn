import base64
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

DEFAULT_KEY_SIZE = 2048
OAEP_PADDING_SIZE = 42


@dataclass
class KeyInfo:
    public_loaded: bool
    public_bits: int | None
    public_n: int | None
    public_e: int | None
    private_loaded: bool
    private_bits: int | None
    private_d: int | None


class RSACrypto:
    """Хранит пару RSA-ключей и выполняет операции шифрования."""

    def __init__(self) -> None:
        self.private_key: RSA.RsaKey | None = None
        self.public_key: RSA.RsaKey | None = None

    def generate_keys(self, key_size: int = DEFAULT_KEY_SIZE) -> tuple[RSA.RsaKey, RSA.RsaKey]:
        """Генерирует новую пару RSA-ключей заданного размера в битах."""
        self.private_key = RSA.generate(key_size)
        self.public_key = self.private_key.publickey()
        return self.private_key, self.public_key

    def export_public_key_xml(self, filepath: str) -> str:
        """Сохраняет открытый ключ в XML-файл и возвращает путь к файлу."""
        if not self.public_key:
            raise ValueError("Открытый ключ не сгенерирован")

        root_xml = ET.Element("RSAKeyValue")

        modulus = ET.SubElement(root_xml, "Modulus")
        modulus.text = base64.b64encode(self.public_key.export_key(format="DER")).decode()

        exponent = ET.SubElement(root_xml, "Exponent")
        exponent.text = base64.b64encode(b"65537").decode()

        tree = ET.ElementTree(root_xml)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        return filepath

    def export_private_key_xml(self, filepath: str) -> str:
        """Сохраняет закрытый ключ в XML-файл и возвращает путь к файлу."""
        if not self.private_key:
            raise ValueError("Закрытый ключ не сгенерирован")

        key_data = base64.b64encode(self.private_key.export_key(format="DER")).decode()

        root_xml = ET.Element("RSAKeyValue")
        private_key_element = ET.SubElement(root_xml, "PrivateKey")
        private_key_element.text = key_data

        tree = ET.ElementTree(root_xml)
        tree.write(filepath, encoding="utf-8", xml_declaration=True)
        return filepath

    def import_public_key_xml(self, filepath: str) -> RSA.RsaKey:
        """Загружает открытый ключ из XML-файла и возвращает объект ключа."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        tree = ET.parse(filepath)
        root_xml = tree.getroot()

        modulus_element = root_xml.find("Modulus")
        if modulus_element is None or not modulus_element.text:
            raise ValueError("В XML отсутствует элемент Modulus")

        key_der = base64.b64decode(modulus_element.text)
        self.public_key = RSA.import_key(key_der)
        return self.public_key

    def import_private_key_xml(self, filepath: str) -> RSA.RsaKey:
        """Загружает закрытый ключ из XML-файла и возвращает объект ключа."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Файл не найден: {filepath}")

        tree = ET.parse(filepath)
        root_xml = tree.getroot()

        private_key_element = root_xml.find("PrivateKey")
        if private_key_element is None or not private_key_element.text:
            raise ValueError("В XML отсутствует элемент PrivateKey")

        key_der = base64.b64decode(private_key_element.text)
        self.private_key = RSA.import_key(key_der)
        self.public_key = self.private_key.publickey()
        return self.private_key

    def encrypt_file(self, input_filepath: str, output_filepath: str) -> str:
        """Шифрует файл открытым ключом через PKCS1_OAEP и сохраняет результат."""
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен")

        with open(input_filepath, "rb") as source:
            data = source.read()

        cipher = PKCS1_OAEP.new(self.public_key)
        block_size = self.public_key.size_in_bytes() - OAEP_PADDING_SIZE
        encrypted_blocks: list[bytes] = []

        for index in range(0, len(data), block_size):
            block = data[index : index + block_size]
            encrypted_blocks.append(cipher.encrypt(block))

        with open(output_filepath, "wb") as target:
            for block in encrypted_blocks:
                target.write(len(block).to_bytes(4, "big"))
                target.write(block)

        return output_filepath

    def decrypt_file(self, input_filepath: str, output_filepath: str) -> str:
        """Расшифровывает файл закрытым ключом через PKCS1_OAEP и сохраняет результат."""
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен")

        with open(input_filepath, "rb") as source:
            encrypted_blocks: list[bytes] = []
            while True:
                size_bytes = source.read(4)
                if not size_bytes:
                    break
                size = int.from_bytes(size_bytes, "big")
                encrypted_blocks.append(source.read(size))

        cipher = PKCS1_OAEP.new(self.private_key)
        decrypted_data = b"".join(cipher.decrypt(block) for block in encrypted_blocks)

        with open(output_filepath, "wb") as target:
            target.write(decrypted_data)

        return output_filepath


def create_rsa(key_size: int = DEFAULT_KEY_SIZE) -> RSACrypto:
    """Создаёт объект RSACrypto и сразу генерирует пару ключей."""
    crypto = RSACrypto()
    crypto.generate_keys(key_size)
    return crypto


def get_key_info(crypto: RSACrypto) -> KeyInfo:
    """Возвращает структурированную информацию о загруженных ключах."""
    public_key = crypto.public_key
    private_key = crypto.private_key

    return KeyInfo(
        public_loaded=public_key is not None,
        public_bits=public_key.size_in_bits() if public_key else None,
        public_n=public_key.n if public_key else None,
        public_e=public_key.e if public_key else None,
        private_loaded=private_key is not None,
        private_bits=private_key.size_in_bits() if private_key else None,
        private_d=private_key.d if private_key else None,
    )


def format_key_info(info: KeyInfo) -> str:
    """Формирует текстовое описание ключей для отображения пользователю."""
    lines: list[str] = []

    if info.public_loaded and info.public_bits is not None:
        lines.extend(
            [
                "Открытый ключ:",
                f"  Размер: {info.public_bits} бит",
                f"  n (модуль): {info.public_n}",
                f"  e (экспонента): {info.public_e}",
            ]
        )
    else:
        lines.append("Открытый ключ: не загружен")

    lines.append("")

    if info.private_loaded and info.private_bits is not None:
        lines.extend(
            [
                "Закрытый ключ:",
                f"  Размер: {info.private_bits} бит",
                f"  d (экспонента): {info.private_d}",
                "  Наличие p, q: да",
            ]
        )
    else:
        lines.append("Закрытый ключ: не загружен")

    return "\n".join(lines)
