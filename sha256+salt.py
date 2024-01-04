import os
import random
from convert import BinaryConverter
from cutter import ChunkCutter

class SHA256(BinaryConverter, ChunkCutter):
    def __init__(self):
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _rotr(self, x, y):
        return ((x >> y) | (x << (32 - y))) & 0xFFFFFFFF

    def _ch(self, x, y, z):
        return (x & y) ^ (~x & z)

    def _maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def _sigma0(self, x):
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _sigma1(self, x):
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _delta0(self, x):
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ (x >> 3)

    def _delta1(self, x):
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ (x >> 10)
    
    def _pad_message(self, message):
        length = len(message) * 8
        message += b'\x80'
        while (len(message) * 8) % 512 != 448:
            message += b'\x00'
        message += length.to_bytes(8, 'big')
        return message

    def _expand_message(self, W):
        for i in range(16, 64):
            s0 = self._delta0(W[i - 15])
            s1 = self._delta1(W[i - 2])
            W.append((W[i - 16] + s0 + W[i - 7] + s1) & 0xFFFFFFFF)

    def _process_chunk(self, chunk):
        W = chunk[:]

        self._expand_message(W)

        a, b, c, d, e, f, g, h = self.h

        for i in range(64):
            S1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = self._ch(e, f, g)
            T1 = (h + S1 + ch + self.K[i] + W[i]) & 0xFFFFFFFF
            S0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = self._maj(a, b, c)
            T2 = (S0 + maj) & 0xFFFFFFFF

            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF

    def sha256_hash(self, message, salt):
        salt_generator = Salt()
        message_with_salt = salt_generator.combine_with_salt(message, salt)
        message_with_salt = self._pad_message(message_with_salt.encode('utf-8'))

        chunks = self.cut_into_chunks(message_with_salt, 64)

        for chunk in chunks:
            words = self.cut_into_chunks(chunk, 4)
            chunk_data = [int.from_bytes(w, 'big') for w in words]
            self._process_chunk(chunk_data)

        hashed_message = ''.join(format(h, '08x') for h in self.h)
        hashed_message = BinaryConverter.to_hex(bytes.fromhex(hashed_message))

        return hashed_message
        
    def read_message_from_file(self, filename):
        with open(filename, 'r') as file:
            return file.read()

    def read_salt_from_file(self, filename):
        salt_generator = Salt()
        return salt_generator.read_salt_from_file(filename)

class Salt:
    
    def random_salt(self, length=16):
        length = random.randint(1, 16)
        salt = os.urandom(length)
        return BinaryConverter.to_hex(salt)
    
    def read_salt_from_file(self, filename):
        with open(filename, 'r') as file:
            return file.read()

    def combine_with_salt(self, message, salt):
        return message + salt

# Nhập tên file chứa thông điệp
message_file = input("Nhập tên file chứa thông điệp: ")

# Lựa chọn giữa tạo ngẫu nhiên salt hoặc đọc salt từ file
salt_option = input("Lựa chọn salt: (1) Tạo ngẫu nhiên (2) Đọc từ file: ")

sha256 = SHA256()

# Đọc thông điệp từ file
message = sha256.read_message_from_file(message_file)
salt_generator = Salt()

if salt_option == "1":
    # Tạo ngẫu nhiên salt
    salt = salt_generator.random_salt()
else:
    # Nhập tên file chứa giá trị salt
    salt_file = input("Nhập tên file chứa giá trị salt: ")
    # Đọc salt từ file
    salt = sha256.read_salt_from_file(salt_file)

message = sha256.read_message_from_file(message_file)
print("Thông điệp ban đầu:", message)

# Tính toán giá trị hash SHA-256
hashed_message = sha256.sha256_hash(message, salt)

binary_message = BinaryConverter.to_binary(message.encode('utf-8'))
print("Giá trị message sau khi chuyển sang nhị phân:", binary_message)

padded_message = sha256._pad_message(message.encode('utf-8'))
binary_padded_message = BinaryConverter.to_binary(padded_message)
print("Dòng kết quả sau khi thêm bit 1 và các bit 0 cho đủ 512 bit:")
print(binary_padded_message)

binary_hashed_message = BinaryConverter.to_binary(bytes.fromhex(hashed_message))
print("Giá trị hash (trước khi chuyển sang hexa):", binary_hashed_message)

print("Giá trị hash SHA-256: ", hashed_message)