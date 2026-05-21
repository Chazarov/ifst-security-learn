from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from PIL import Image

MAGIC = b"ST5\x00"
IMAGE_TYPES = [("Изображения", "*.png *.jpg *.jpeg"), ("Все файлы", "*.*")]


class StegoError(Exception):
    pass


def derive_key(password: str) -> bytes:
    return SHA256.new(password.encode("utf-8")).digest()


def encrypt_bytes(data: bytes, password: str) -> bytes:
    cipher = AES.new(derive_key(password), AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))


def decrypt_bytes(data: bytes, password: str) -> bytes:
    cipher = AES.new(derive_key(password), AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)


def _embed_byte(r: int, g: int, b: int, byte: int) -> tuple[int, int, int]:
    return (r & 0xF8) | (byte >> 5), (g & 0xF8) | ((byte >> 2) & 7), (b & 0xFC) | (byte & 3)


def _extract_byte(r: int, g: int, b: int) -> int:
    return ((r & 7) << 5) | ((g & 7) << 2) | (b & 3)


def _output_path(image_path: str) -> str:
    path = Path(image_path)
    return str(path.parent / f"{path.stem}_stego{path.suffix.lower()}")


def _load_rgb_pixels(image_path: str) -> tuple[Image.Image, list[tuple[int, int, int]]]:
    image = Image.open(image_path).convert("RGB")
    return image, list(image.getdata())


def _save_image(image: Image.Image, path: str) -> None:
    suffix = Path(path).suffix.lower()
    if suffix in (".jpg", ".jpeg"):
        image.save(path, format="JPEG", quality=95, subsampling=0)
    else:
        image.save(path, format="PNG")


def hide_message(image_path: str, message: str, password: str) -> str:
    if not message:
        raise StegoError("Введите данные для скрытия")
    if not password:
        raise StegoError("Введите пароль")

    encrypted = encrypt_bytes(message.encode("utf-8"), password)
    payload = MAGIC + len(encrypted).to_bytes(4, "big") + encrypted
    image, pixels = _load_rgb_pixels(image_path)
    if len(pixels) < len(payload):
        raise StegoError("Изображение слишком мало для выбранных данных")

    out = []
    idx = 0
    for r, g, b in pixels:
        if idx < len(payload):
            r, g, b = _embed_byte(r, g, b, payload[idx])
            idx += 1
        out.append((r, g, b))

    output = _output_path(image_path)
    result = Image.new("RGB", image.size)
    result.putdata(out)
    _save_image(result, output)
    return output


def extract_message(image_path: str, password: str) -> str:
    if not password:
        raise StegoError("Введите пароль")

    _, pixels = _load_rgb_pixels(image_path)
    if len(pixels) < len(MAGIC) + 4:
        raise StegoError("Файл не содержит зашифрованной информации")

    raw = bytes(_extract_byte(r, g, b) for r, g, b in pixels)
    if not raw.startswith(MAGIC):
        raise StegoError("Файл не содержит зашифрованной информации")

    size = int.from_bytes(raw[len(MAGIC) : len(MAGIC) + 4], "big")
    end = len(MAGIC) + 4 + size
    if size <= 0 or end > len(raw):
        raise StegoError("Файл не содержит зашифрованной информации")

    try:
        plain = decrypt_bytes(raw[len(MAGIC) + 4 : end], password)
    except ValueError as exc:
        raise StegoError("Неверный пароль или повреждённые данные") from exc

    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StegoError("Файл не содержит зашифрованной информации") from exc
