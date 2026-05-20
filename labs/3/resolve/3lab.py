import os
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import tkinter as tk
from tkinter import filedialog, messagebox
from xml.dom import minidom
import xml.etree.ElementTree as ET

class RSACrypto:
    """Класс для работы с RSA шифрованием"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
    
    def generate_keys(self, key_size=2048):
        """1. Генерация пары ключей RSA"""
        self.private_key = RSA.generate(key_size)
        self.public_key = self.private_key.publickey()
        return self.private_key, self.public_key
    
    def export_public_key_xml(self, filepath=None):
        """2. Экспорт открытого ключа в XML"""
        if not self.public_key:
            raise ValueError("Открытый ключ не сгенерирован!")
        
        if not filepath:
            root = tk.Tk()
            root.withdraw()
            filepath = filedialog.asksaveasfilename(
                title="Сохранить открытый ключ",
                defaultextension=".xml",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )
            root.destroy()
        
        if filepath:
            # Создаём XML
            root_xml = ET.Element("RSAKeyValue")
            
            # Модуль n
            modulus = ET.SubElement(root_xml, "Modulus")
            modulus.text = base64.b64encode(self.public_key.export_key(format='DER')).decode()
            
            # Экспонента e
            exponent = ET.SubElement(root_xml, "Exponent")
            exponent.text = base64.b64encode(b'65537').decode()
            
            tree = ET.ElementTree(root_xml)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            return filepath
        return None
    
    def export_private_key_xml(self, filepath=None):
        """2. Экспорт закрытого ключа в XML"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не сгенерирован!")
        
        if not filepath:
            root = tk.Tk()
            root.withdraw()
            filepath = filedialog.asksaveasfilename(
                title="Сохранить закрытый ключ",
                defaultextension=".xml",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )
            root.destroy()
        
        if filepath:
            # Экспортируем полный ключ в DER и кодируем в base64
            key_data = base64.b64encode(self.private_key.export_key(format='DER')).decode()
            
            root_xml = ET.Element("RSAKeyValue")
            private_key_element = ET.SubElement(root_xml, "PrivateKey")
            private_key_element.text = key_data
            
            tree = ET.ElementTree(root_xml)
            tree.write(filepath, encoding='utf-8', xml_declaration=True)
            
            return filepath
        return None
    
    def import_public_key_xml(self, filepath=None):
        """2. Импорт открытого ключа из XML"""
        if not filepath:
            root = tk.Tk()
            root.withdraw()
            filepath = filedialog.askopenfilename(
                title="Открыть файл с открытым ключом",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )
            root.destroy()
        
        if filepath and os.path.exists(filepath):
            tree = ET.parse(filepath)
            root_xml = tree.getroot()
            
            # Ищем Modulus
            modulus_element = root_xml.find("Modulus")
            if modulus_element is not None and modulus_element.text:
                key_der = base64.b64decode(modulus_element.text)
                self.public_key = RSA.import_key(key_der)
                return self.public_key
        
        return None
    
    def import_private_key_xml(self, filepath=None):
        """2. Импорт закрытого ключа из XML"""
        if not filepath:
            root = tk.Tk()
            root.withdraw()
            filepath = filedialog.askopenfilename(
                title="Открыть файл с закрытым ключом",
                filetypes=[("XML files", "*.xml"), ("All files", "*.*")]
            )
            root.destroy()
        
        if filepath and os.path.exists(filepath):
            tree = ET.parse(filepath)
            root_xml = tree.getroot()
            
            # Ищем PrivateKey
            private_key_element = root_xml.find("PrivateKey")
            if private_key_element is not None and private_key_element.text:
                key_der = base64.b64decode(private_key_element.text)
                self.private_key = RSA.import_key(key_der)
                self.public_key = self.private_key.publickey()
                return self.private_key
        
        return None
    
    def encrypt_file(self, input_filepath, output_filepath=None):
        """3. Шифрование файла открытым ключом"""
        if not self.public_key:
            raise ValueError("Открытый ключ не загружен!")
        
        if not output_filepath:
            root = tk.Tk()
            root.withdraw()
            output_filepath = filedialog.asksaveasfilename(
                title="Сохранить зашифрованный файл",
                defaultextension=".enc",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            root.destroy()
        
        if output_filepath:
            # Читаем файл
            with open(input_filepath, 'rb') as f:
                data = f.read()
            
            # Шифруем данные (гибридное шифрование)
            cipher = PKCS1_OAEP.new(self.public_key)
            
            # Разбиваем на блоки, если файл большой
            block_size = self.public_key.size_in_bytes() - 42  # PKCS1_OAEP padding
            encrypted_blocks = []
            
            for i in range(0, len(data), block_size):
                block = data[i:i+block_size]
                encrypted_block = cipher.encrypt(block)
                encrypted_blocks.append(encrypted_block)
            
            # Сохраняем зашифрованные данные
            with open(output_filepath, 'wb') as f:
                for block in encrypted_blocks:
                    f.write(len(block).to_bytes(4, 'big'))
                    f.write(block)
            
            return output_filepath
        return None
    
    def decrypt_file(self, input_filepath, output_filepath=None):
        """3. Расшифровка файла закрытым ключом"""
        if not self.private_key:
            raise ValueError("Закрытый ключ не загружен!")
        
        if not output_filepath:
            root = tk.Tk()
            root.withdraw()
            output_filepath = filedialog.asksaveasfilename(
                title="Сохранить расшифрованный файл",
                filetypes=[("All files", "*.*")]
            )
            root.destroy()
        
        if output_filepath:
            # Читаем зашифрованный файл
            with open(input_filepath, 'rb') as f:
                encrypted_blocks = []
                while True:
                    size_bytes = f.read(4)
                    if not size_bytes:
                        break
                    size = int.from_bytes(size_bytes, 'big')
                    block = f.read(size)
                    encrypted_blocks.append(block)
            
            # Расшифровываем
            cipher = PKCS1_OAEP.new(self.private_key)
            decrypted_data = b''
            
            for block in encrypted_blocks:
                decrypted_block = cipher.decrypt(block)
                decrypted_data += decrypted_block
            
            # Сохраняем
            with open(output_filepath, 'wb') as f:
                f.write(decrypted_data)
            
            return output_filepath
        return None


def print_separator():
    print("\n" + "=" * 60)


def main():
    rsa = RSACrypto()
    
    print("\n" + "=" * 60)
    print("  RSA — АСИММЕТРИЧНОЕ ШИФРОВАНИЕ")
    print("=" * 60)
    
    # Сразу генерируем ключи
    print("\nГенерация ключей RSA (2048 бит)...")
    try:
        rsa.generate_keys(2048)
        print("✓ Ключи успешно сгенерированы!")
    except Exception as e:
        print(f"✗ Ошибка генерации ключей: {e}")
        return
    
    while True:
        print_separator()
        print("  ГЛАВНОЕ МЕНЮ")
        print("=" * 60)
        print("1. Экспорт открытого ключа в XML")
        print("2. Экспорт закрытого ключа в XML")
        print("3. Импорт открытого ключа из XML")
        print("4. Импорт закрытого ключа из XML")
        print("5. Зашифровать файл")
        print("6. Расшифровать файл")
        print("7. Показать информацию о ключах")
        print("8. Сгенерировать новую пару ключей")
        print("0. Выход")
        print("-" * 60)
        
        choice = input("Ваш выбор: ").strip()
        
        # 1. Экспорт публичного ключа
        if choice == '1':
            print_separator()
            print("  ЭКСПОРТ ОТКРЫТОГО КЛЮЧА")
            print("=" * 60)
            
            try:
                filepath = rsa.export_public_key_xml()
                if filepath:
                    print(f"✓ Открытый ключ сохранён в: {filepath}")
                else:
                    print("✗ Сохранение отменено")
            except Exception as e:
                print(f"✗ Ошибка: {e}")
        
        # 2. Экспорт приватного ключа
        elif choice == '2':
            print_separator()
            print("  ЭКСПОРТ ЗАКРЫТОГО КЛЮЧА")
            print("=" * 60)
            
            try:
                filepath = rsa.export_private_key_xml()
                if filepath:
                    print(f"✓ Закрытый ключ сохранён в: {filepath}")
                    print("⚠ ВНИМАНИЕ: Храните закрытый ключ в безопасности!")
                else:
                    print("✗ Сохранение отменено")
            except Exception as e:
                print(f"✗ Ошибка: {e}")
        
        # 3. Импорт публичного ключа
        elif choice == '3':
            print_separator()
            print("  ИМПОРТ ОТКРЫТОГО КЛЮЧА")
            print("=" * 60)
            
            try:
                key = rsa.import_public_key_xml()
                if key:
                    print(f"✓ Открытый ключ загружен!")
                    print(f"  Размер ключа: {key.size_in_bits()} бит")
                else:
                    print("✗ Загрузка отменена или не удалась")
            except Exception as e:
                print(f"✗ Ошибка импорта: {e}")
        
        # 4. Импорт приватного ключа
        elif choice == '4':
            print_separator()
            print("  ИМПОРТ ЗАКРЫТОГО КЛЮЧА")
            print("=" * 60)
            
            try:
                key = rsa.import_private_key_xml()
                if key:
                    print(f"✓ Закрытый ключ загружен!")
                    print(f"  Размер ключа: {key.size_in_bits()} бит")
                else:
                    print("✗ Загрузка отменена или не удалась")
            except Exception as e:
                print(f"✗ Ошибка импорта: {e}")
        
        # 5. Шифрование файла
        elif choice == '5':
            print_separator()
            print("  ШИФРОВАНИЕ ФАЙЛА")
            print("=" * 60)
            
            if not rsa.public_key:
                print("✗ Сначала загрузите или сгенерируйте открытый ключ!")
                continue
            
            # Выбор файла
            root = tk.Tk()
            root.withdraw()
            input_file = filedialog.askopenfilename(
                title="Выберите файл для шифрования"
            )
            root.destroy()
            
            if not input_file:
                print("✗ Файл не выбран!")
                continue
            
            print(f"\nВыбран файл: {os.path.basename(input_file)}")
            print(f"Размер: {os.path.getsize(input_file)} байт")
            
            try:
                output_file = rsa.encrypt_file(input_file)
                if output_file:
                    print(f"✓ Файл зашифрован и сохранён: {output_file}")
                else:
                    print("✗ Шифрование отменено")
            except Exception as e:
                print(f"✗ Ошибка шифрования: {e}")
        
        # 6. Расшифровка файла
        elif choice == '6':
            print_separator()
            print("  РАСШИФРОВКА ФАЙЛА")
            print("=" * 60)
            
            if not rsa.private_key:
                print("✗ Сначала загрузите или сгенерируйте закрытый ключ!")
                continue
            
            # Выбор файла
            root = tk.Tk()
            root.withdraw()
            input_file = filedialog.askopenfilename(
                title="Выберите зашифрованный файл",
                filetypes=[("Encrypted files", "*.enc"), ("All files", "*.*")]
            )
            root.destroy()
            
            if not input_file:
                print("✗ Файл не выбран!")
                continue
            
            print(f"\nВыбран файл: {os.path.basename(input_file)}")
            
            try:
                output_file = rsa.decrypt_file(input_file)
                if output_file:
                    print(f"✓ Файл расшифрован и сохранён: {output_file}")
                else:
                    print("✗ Расшифровка отменена")
            except Exception as e:
                print(f"✗ Ошибка расшифровки: {e}")
        
        # 7. Информация о ключах
        elif choice == '7':
            print_separator()
            print("  ИНФОРМАЦИЯ О КЛЮЧАХ")
            print("=" * 60)
            
            if rsa.public_key:
                print(f"\nОткрытый ключ:")
                print(f"  Размер: {rsa.public_key.size_in_bits()} бит")
                print(f"  n (модуль): {rsa.public_key.n}")
                print(f"  e (экспонента): {rsa.public_key.e}")
            else:
                print("\nОткрытый ключ: ❌ не загружен")
            
            if rsa.private_key:
                print(f"\nЗакрытый ключ:")
                print(f"  Размер: {rsa.private_key.size_in_bits()} бит")
                print(f"  d (экспонента): {rsa.private_key.d}")
                print(f"  Наличие p, q: ✓")
            else:
                print("\nЗакрытый ключ: ❌ не загружен")
        
        # 8. Генерация новых ключей
        elif choice == '8':
            print_separator()
            print("  ГЕНЕРАЦИЯ НОВЫХ КЛЮЧЕЙ")
            print("=" * 60)
            
            try:
                size = input("Размер ключа (1024/2048/4096) [2048]: ").strip()
                size = int(size) if size else 2048
                rsa.generate_keys(size)
                print(f"✓ Новые ключи сгенерированы! ({size} бит)")
            except Exception as e:
                print(f"✗ Ошибка: {e}")
        
        # 0. Выход
        elif choice == '0':
            print("\nВыход из программы.")
            break
        
        else:
            print("\nНеверный выбор! Попробуйте снова.")


if __name__ == "__main__":
    main()