import struct

def rotate_left(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

def sha1(message):
    # Ініціалізування констант
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # Попередня обробка: збереження довжини
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8

    # Додавання одного біта «1» до повідомлення
    message += b'\x80'

    # Додавання «0» бітів, доки довжина повідомлення не стане конгруентною 448 по модулю 512
    # Тобто довжина в байтах % 64 повинна дорівнювати 56
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'

    # Додавання вихідної довжини повідомлення як 64-розрядне ціле число (Big Endian)
    message += struct.pack('>Q', original_bit_len)

    # Обробка повідомлення 512-бітними блоками (64 байти)
    for i in range(0, len(message), 64):
        block = message[i:i + 64]

        # Розбиття блока на 16 слів (кожне по 32 біти = 4 байти)
        words = [struct.unpack('>I', block[j:j + 4])[0] for j in range(0, 64, 4)]

        # Розширення 16 слів до 80 слів
        for j in range(16, 80):
            # XOR операції
            xor_res = words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16]
            words.append(rotate_left(xor_res, 1))

        # Ініціалізування хеш-значення для цього блоку
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Основний цикл
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (rotate_left(a, 5) + f + e + k + words[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = rotate_left(b, 30)
            b = a
            a = temp

        # Оновлення хеш-значення для цього блоку
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Об’єднання хеш-значення
    digest = (struct.pack('>I', h0) +
              struct.pack('>I', h1) +
              struct.pack('>I', h2) +
              struct.pack('>I', h3) +
              struct.pack('>I', h4))

    return digest

# Перевірка
def main():
    test_strings = ["Bordovskyi", "Pavlo", "IШІ-501"]

    for s in test_strings:
        sha1_hash = sha1(s.encode('utf-8'))
        print(f'SHA-1("{s}") = {sha1_hash.hex()}')

if __name__ == "__main__":
    main()