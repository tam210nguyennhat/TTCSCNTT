class BinaryConverter:
    @staticmethod
    def to_binary(data):
        binary_string = ""
        for byte in data:
            # Chuyển đổi giá trị byte thành chuỗi nhị phân
            binary_byte = ""
            for _ in range(8):
                binary_byte = str(byte % 2) + binary_byte
                byte //= 2
            binary_string += binary_byte
        return binary_string
    
    @staticmethod
    def to_hex(data):
        hex_string = ""
        for byte in data:
        # Chuyển đổi giá trị byte thành ký tự hexa
            hex_byte = hex(byte)[2:]
            if len(hex_byte) == 1:
                hex_byte = '0' + hex_byte
            hex_string += hex_byte
        return hex_string