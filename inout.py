import os
import random
from convert import BinaryConverter

class InputOutput:
    @staticmethod
    def get_password():
        password_option = input("Lựa chọn mật khẩu: (1) Nhập từ bàn phím (2) Đọc từ file: ")

        if password_option == "1":
            # Nhập mật khẩu từ bàn phím
            return input("Nhập mật khẩu: ")
        else:
            # Nhập tên file chứa mật khẩu
            password_file = input("Nhập tên file chứa mật khẩu: ")
            # Đọc mật khẩu từ file
            with open(password_file, 'r') as file:
                return file.read()

    @staticmethod
    def get_salt():
        salt_option = input("Lựa chọn salt: (1) Tạo ngẫu nhiên (2) Đọc từ file: ")

        if salt_option == "1":
            # Tạo ngẫu nhiên salt
            length = random.randint(1, 16)
            salt = os.urandom(length)
            return BinaryConverter.to_hex(salt)
        else:
            # Nhập tên file chứa giá trị salt
            salt_file = input("Nhập tên file chứa giá trị salt: ")
            # Đọc salt từ file
            with open(salt_file, 'r') as file:
                return file.read()
            
    @staticmethod
    def print_initial_password(password):
        print("Mật khẩu ban đầu:", password)

    @staticmethod
    def print_salt(salt):
        print("Giá trị salt:", salt)

    @staticmethod
    def print_binary_password(password):
        binary_password = BinaryConverter.to_binary(password.encode('utf-8'))
        print("Giá trị password sau khi chuyển sang nhị phân:", binary_password)

    @staticmethod
    def print_binary_hashed_password(hashed_password):
        binary_hashed_password = BinaryConverter.to_binary(bytes.fromhex(hashed_password))
        print("Giá trị hash (trước khi chuyển sang hexa):", binary_hashed_password)

    @staticmethod
    def print_hashed_password(hashed_password):
        print("Giá trị hash SHA-256:", hashed_password)
    
    @staticmethod
    def print_padded_password(password):
        binary_padded_password = BinaryConverter.to_binary(password)
        print("Kết quả sau khi thêm bit 1 và các bit 0 cho đủ 512 bit:", binary_padded_password)    

 
    