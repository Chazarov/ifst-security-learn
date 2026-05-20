import os
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

class SymmetricCipher:
    def __init__(self):
        self.key = None
        self.iv = None
        self.algorithm = None
        self.mode = None
    
    def generate_key_iv(self, algorithm='AES'):
        self.algorithm = algorithm
        
        if algorithm == 'AES':
            key_size = 32
            block_size = 16
        elif algorithm == 'DES':
            key_size = 8
            block_size = 8
        
        self.key = get_random_bytes(key_size)
        self.iv = get_random_bytes(block_size)
        
        return self.key, self.iv
    
    def set_key_iv(self, key, iv):
        self.key = key
        self.iv = iv
    
    def encrypt(self, plaintext, algorithm, mode):
        self.algorithm = algorithm
        self.mode = mode
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        if algorithm == 'AES':
            cipher_alg = AES
            block_size = 16
        elif algorithm == 'DES':
            cipher_alg = DES
            block_size = 8
        
        if mode == 'ECB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_ECB)
            padded_data = pad(plaintext, block_size)
        elif mode == 'CBC':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CBC, self.iv)
            padded_data = pad(plaintext, block_size)
        elif mode == 'CFB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CFB, self.iv)
            padded_data = plaintext
        elif mode == 'OFB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_OFB, self.iv)
            padded_data = plaintext
        elif mode == 'CTR':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CTR, nonce=self.iv[:8])
            padded_data = plaintext
        
        ciphertext = cipher.encrypt(padded_data)
        return ciphertext
    
    def decrypt(self, ciphertext, algorithm, mode):
        self.algorithm = algorithm
        self.mode = mode
        
        if algorithm == 'AES':
            cipher_alg = AES
            block_size = 16
        elif algorithm == 'DES':
            cipher_alg = DES
            block_size = 8
        
        if mode == 'ECB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_ECB)
        elif mode == 'CBC':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CBC, self.iv)
        elif mode == 'CFB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CFB, self.iv)
        elif mode == 'OFB':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_OFB, self.iv)
        elif mode == 'CTR':
            cipher = cipher_alg.new(self.key, cipher_alg.MODE_CTR, nonce=self.iv[:8])
        
        plaintext = cipher.decrypt(ciphertext)
        
        if mode in ['ECB', 'CBC']:
            plaintext = unpad(plaintext, block_size)
        
        return plaintext


def print_separator():
    print("\n" + "=" * 70)


def main():
    cipher = SymmetricCipher()
    
    # Генерируем ключи при запуске
    aes_key, aes_iv = cipher.generate_key_iv('AES')
    des_key, des_iv = cipher.generate_key_iv('DES')
    
    print("\n" + "=" * 70)
    print("  ПРОГРАММА СИММЕТРИЧНОГО ШИФРОВАНИЯ")
    print("=" * 70)
    print("\nКлючи сгенерированы автоматически!")
    print(f"AES ключ (base64): {base64.b64encode(aes_key).decode()}")
    print(f"AES IV   (base64): {base64.b64encode(aes_iv).decode()}")
    print(f"DES ключ (base64): {base64.b64encode(des_key).decode()}")
    print(f"DES IV   (base64): {base64.b64encode(des_iv).decode()}")
    
    while True:
        print_separator()
        print("  ГЛАВНОЕ МЕНЮ")
        print("=" * 70)
        print("1. Зашифровать сообщение (выбрать алгоритм и режим)")
        print("2. Зашифровать сообщение во ВСЕХ режимах сразу (сравнение)")
        print("3. Расшифровать сообщение")
        print("4. Демонстрация ECB vs CBC (повторяющиеся блоки)")
        print("5. Сгенерировать новые ключи")
        print("0. Выход")
        print("-" * 70)
        
        choice = input("Ваш выбор: ").strip()
        
        # ========== 1. ЗАШИФРОВАТЬ ==========
        if choice == '1':
            print_separator()
            print("  ШИФРОВАНИЕ СООБЩЕНИЯ")
            print("=" * 70)
            
            text = input("Введите текст для шифрования: ").strip()
            if not text:
                print("Ошибка: пустой текст!")
                continue
            
            print("\nВыберите алгоритм:")
            print("1. AES")
            print("2. DES")
            alg_choice = input("Ваш выбор (1-2): ").strip()
            
            if alg_choice == '1':
                algorithm = 'AES'
                cipher.set_key_iv(aes_key, aes_iv)
            elif alg_choice == '2':
                algorithm = 'DES'
                cipher.set_key_iv(des_key, des_iv)
            else:
                print("Неверный выбор алгоритма!")
                continue
            
            print("\nВыберите режим шифрования:")
            print("1. ECB")
            print("2. CBC")
            print("3. CFB")
            print("4. OFB")
            print("5. CTR")
            mode_choice = input("Ваш выбор (1-5): ").strip()
            
            modes_map = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB', '5': 'CTR'}
            mode = modes_map.get(mode_choice)
            
            if not mode:
                print("Неверный выбор режима!")
                continue
            
            # Для ECB не нужен IV
            if mode == 'ECB':
                cipher.set_key_iv(cipher.key, None)
            
            try:
                encrypted = cipher.encrypt(text, algorithm, mode)
                print("\n" + "-" * 70)
                print(f"  РЕЗУЛЬТАТ ({algorithm}-{mode})")
                print("-" * 70)
                print(f"Алгоритм: {algorithm}")
                print(f"Режим:    {mode}")
                print(f"Исходный текст: {text}")
                print(f"Длина исходного текста: {len(text.encode('utf-8'))} байт")
                print(f"Зашифровано (base64): {base64.b64encode(encrypted).decode()}")
                print(f"Длина шифротекста: {len(encrypted)} байт")
                print("-" * 70)
                
                # Сохраняем для возможной расшифровки
                global last_encrypted, last_algorithm, last_mode
                last_encrypted = encrypted
                last_algorithm = algorithm
                last_mode = mode
                
            except Exception as e:
                print(f"Ошибка шифрования: {e}")
        
        # ========== 2. ВСЕ РЕЖИМЫ СРАЗУ ==========
        elif choice == '2':
            print_separator()
            print("  ШИФРОВАНИЕ ВО ВСЕХ РЕЖИМАХ (СРАВНЕНИЕ)")
            print("=" * 70)
            
            text = input("Введите текст для шифрования: ").strip()
            if not text:
                print("Ошибка: пустой текст!")
                continue
            
            print("\nВыберите алгоритм:")
            print("1. AES")
            print("2. DES")
            alg_choice = input("Ваш выбор (1-2): ").strip()
            
            if alg_choice == '1':
                algorithm = 'AES'
                cipher.set_key_iv(aes_key, aes_iv)
            else:
                algorithm = 'DES'
                cipher.set_key_iv(des_key, des_iv)
            
            modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
            results = []
            
            print(f"\n{'=' * 70}")
            print(f"  РЕЗУЛЬТАТЫ ДЛЯ {algorithm}")
            print(f"{'=' * 70}")
            print(f"Исходный текст: {text}")
            print(f"Длина исходного текста: {len(text.encode('utf-8'))} байт")
            print()
            
            for mode in modes:
                try:
                    if mode == 'ECB':
                        cipher.set_key_iv(cipher.key, None)
                    else:
                        cipher.set_key_iv(cipher.key, cipher.iv)
                    
                    encrypted = cipher.encrypt(text, algorithm, mode)
                    results.append((mode, encrypted))
                    
                    print(f"Режим {mode}:")
                    print(f"  Шифротекст (base64): {base64.b64encode(encrypted).decode()}")
                    print(f"  Длина шифротекста: {len(encrypted)} байт")
                    print()
                    
                except Exception as e:
                    print(f"Режим {mode}: ОШИБКА - {e}")
                    print()
            
            # Сравнение длин
            print("-" * 70)
            print("Сравнение длин шифротекста:")
            for mode, enc in results:
                print(f"  {algorithm}-{mode}: {len(enc)} байт")
            
            # Проверка, что все шифротексты разные
            print()
            if len(results) >= 2:
                all_different = True
                for i in range(len(results)):
                    for j in range(i+1, len(results)):
                        if results[i][1] == results[j][1]:
                            all_different = False
                            print(f"  ⚠ {results[i][0]} и {results[j][0]} дали одинаковый результат!")
                if all_different:
                    print("  ✓ Все режимы дают разный шифротекст!")
        
        # ========== 3. РАСШИФРОВАТЬ ==========
        elif choice == '3':
            print_separator()
            print("  РАСШИФРОВКА СООБЩЕНИЯ")
            print("=" * 70)
            
            # Показываем последнее зашифрованное сообщение
            try:
                if last_encrypted:
                    print(f"\nПоследнее зашифрованное сообщение:")
                    print(f"  Алгоритм: {last_algorithm}")
                    print(f"  Режим: {last_mode}")
                    print(f"  Шифротекст: {base64.b64encode(last_encrypted).decode()}")
                    use_last = input("\nРасшифровать последнее? (y/n): ").strip().lower()
                    
                    if use_last == 'y':
                        try:
                            decrypted = cipher.decrypt(last_encrypted, last_algorithm, last_mode)
                            print(f"\nРасшифрованный текст: {decrypted.decode('utf-8')}")
                            continue
                        except Exception as e:
                            print(f"Ошибка: {e}")
            except:
                pass
            
            # Ручной ввод
            encrypted_b64 = input("\nВведите зашифрованный текст (base64): ").strip()
            if not encrypted_b64:
                print("Пустой ввод!")
                continue
            
            print("\nВыберите алгоритм:")
            print("1. AES")
            print("2. DES")
            alg_choice = input("Ваш выбор (1-2): ").strip()
            algorithm = 'AES' if alg_choice == '1' else 'DES'
            
            print("\nВыберите режим:")
            print("1. ECB")
            print("2. CBC")
            print("3. CFB")
            print("4. OFB")
            print("5. CTR")
            mode_choice = input("Ваш выбор (1-5): ").strip()
            modes_map = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB', '5': 'CTR'}
            mode = modes_map.get(mode_choice)
            
            if not mode:
                print("Неверный режим!")
                continue
            
            if algorithm == 'AES':
                cipher.set_key_iv(aes_key, aes_iv)
            else:
                cipher.set_key_iv(des_key, des_iv)
            
            try:
                encrypted = base64.b64decode(encrypted_b64)
                decrypted = cipher.decrypt(encrypted, algorithm, mode)
                print(f"\n✓ Расшифровано успешно!")
                print(f"Текст: {decrypted.decode('utf-8')}")
            except Exception as e:
                print(f"\n✗ Ошибка расшифровки: {e}")
                print("Проверьте правильность алгоритма, режима и ключа!")
        
        # ========== ECB vs CBC ==========
        elif choice == '4':
            print_separator()
            print("  ДЕМОНСТРАЦИЯ ECB vs CBC (ПОВТОРЯЮЩИЕСЯ БЛОКИ)")
            print("=" * 70)
            
            # Используем сообщение с повторениями
            repeated_msg = "AAAAAAAABBBBBBBB" * 2  # 32 байта
            print(f"\nИсходное сообщение: '{repeated_msg}'")
            print(f"Длина: {len(repeated_msg)} байт = {len(repeated_msg)//16} блока по 16 байт")
            print("\nСтруктура сообщения:")
            print("  Блок 1: 'AAAAAAAA' (8 байт 'A' + 8 байт 'B')")
            print("  Блок 2: 'BBBBBBBB' (8 байт 'A' + 8 байт 'B')")
            print("  Блок 3: 'AAAAAAAA' ← повторяет блок 1!")
            print("  Блок 4: 'BBBBBBBB' ← повторяет блок 2!")
            
            # ECB
            cipher.set_key_iv(aes_key, None)
            ecb_enc = cipher.encrypt(repeated_msg, 'AES', 'ECB')
            
            print(f"\n{'─' * 70}")
            print("  ECB — РЕЖИМ ЭЛЕКТРОННОЙ КОДОВОЙ КНИГИ")
            print(f"{'─' * 70}")
            print("Каждый блок шифруется ОТДЕЛЬНО, без связи с другими.")
            print()
            for i in range(0, len(ecb_enc), 16):
                block = ecb_enc[i:i+16]
                print(f"  Блок {i//16 + 1}: {block.hex()}")
            
            block1 = ecb_enc[0:16]
            block3 = ecb_enc[32:48]
            block2 = ecb_enc[16:32]
            block4 = ecb_enc[48:64]
            
            print(f"\n   Блок 1 == Блок 3: {block1 == block3} ← ОДИНАКОВЫЕ!")
            print(f"   Блок 2 == Блок 4: {block2 == block4} ← ОДИНАКОВЫЕ!")
            print("  Вывод: ECB раскрывает повторяющиеся фрагменты!")
            
            # CBC
            cipher.set_key_iv(aes_key, aes_iv)
            cbc_enc = cipher.encrypt(repeated_msg, 'AES', 'CBC')
            
            print(f"\n{'─' * 70}")
            print("  CBC — РЕЖИМ СЦЕПЛЕНИЯ БЛОКОВ")
            print(f"{'─' * 70}")
            print("Каждый блок XOR'ится с ПРЕДЫДУЩИМ шифротекстом перед шифрованием.")
            print()
            for i in range(0, len(cbc_enc), 16):
                block = cbc_enc[i:i+16]
                print(f"  Блок {i//16 + 1}: {block.hex()}")
            
            block1 = cbc_enc[0:16]
            block3 = cbc_enc[32:48]
            block2 = cbc_enc[16:32]
            block4 = cbc_enc[48:64]
        
            print(f"\n   Блок 1 == Блок 3: {block1 == block3} ← РАЗНЫЕ!")
            print(f"   Блок 2 == Блок 4: {block2 == block4} ← РАЗНЫЕ!")
            print("  Вывод: CBC скрывает повторяющиеся фрагменты!")
            
            print(f"\n{'=' * 70}")
            print("  ИТОГ: ECB НЕБЕЗОПАСЕН для данных с повторениями!")
            print(f"{'=' * 70}")
        
        # ========== 5. НОВЫЕ КЛЮЧИ ==========
        elif choice == '5':
            aes_key, aes_iv = cipher.generate_key_iv('AES')
            des_key, des_iv = cipher.generate_key_iv('DES')
            print_separator()
            print("  НОВЫЕ КЛЮЧИ СГЕНЕРИРОВАНЫ!")
            print("=" * 70)
            print(f"AES ключ (base64): {base64.b64encode(aes_key).decode()}")
            print(f"AES IV   (base64): {base64.b64encode(aes_iv).decode()}")
            print(f"DES ключ (base64): {base64.b64encode(des_key).decode()}")
            print(f"DES IV   (base64): {base64.b64encode(des_iv).decode()}")
        
        # ========== 0. ВЫХОД ==========
        elif choice == '0':
            print("\nВыход из программы. До свидания!")
            break
        
        else:
            print("\nНеверный выбор! Попробуйте снова.")


if __name__ == "__main__":
    last_encrypted = None
    last_algorithm = None
    last_mode = None
    main()