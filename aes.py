import os
import random

def generate_secure_key(length):
    # Đảm bảo độ dài key là hợp lệ
    if length <= 0:
        raise ValueError("Key length should be a positive integer.")
    
    # Tạo danh sách các ký tự ASCII
    all_characters = ''.join(chr(i) for i in range(256))  # Ký tự ASCII từ 0 đến 127

    # Tạo key ngẫu nhiên
    key = ''.join(random.choice(all_characters) for _ in range(length))

    return key


#Xử lý chuyển đổi dữ liệu giữa dạng string và matrix
def bytes2matrix(bytes):
    matrix = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            if i * 4 + j < len(bytes):
                matrix[i][j] = bytes[i * 4 + j]
            else:
                matrix[i][j] = 0
    return matrix

def matrix2bytes(matrix):
    flattened_list = [byte for row in matrix for byte in row]
    byte_string = bytes(flattened_list)
    return byte_string

#Hàm tiện ích

def print_matrix(matrix):
    for rows in matrix:
        print(rows)

def get_file_type(file_path):
    file_signatures = {
        b'\x89PNG\r\n\x1a\n': 'PNG',
        b'\xff\xd8\xff': 'JPG',
        b'GIF8': 'GIF',
        b'%PDF': 'PDF',
        b'PK\x03\x04': 'ZIP',
        b'BM': 'BMP',
        b'\xff\xfb': 'MP3',
        b'ID3': 'MP3',
        b'RIFF': 'WAV',
        b'\x00\x00\x00 ftypisom': 'MP4'
    }
    
    with open(file_path, 'rb') as file:
        file_header = file.read(16)
        print('File header : ', file_header)

        for signature in file_signatures:
            if file_header.startswith(signature):
                return file_signatures[signature]

    return 'DAT'

def show_matrix(matrix):
    for line in matrix:
        print(line, end='\n')
    print(f"Size : {len(matrix)}x{len(matrix[0])}\n")
    
def change_extension(file_path):
    path, filename = os.path.split(file_path)
    name, extension = os.path.splitext(filename)
    file_type = get_file_type(file_path)
    new_path = path + '/' + name + '.' + file_type
    # print(file_path, new_path)
    os.rename(file_path, new_path)


#Một số giá trị cần thiết
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

Rcon = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

class AES:
    #Khởi tạo một lớp AES với khóa
    def __init__(self, key):
        self.key = key
        self.matrix_key = bytes2matrix(key)
        self.create_round_key(bytes2matrix(key))

    #Mã hóa

    #Tạo khóa vòng bằng cách mở rộng khóa có sẵn
    def create_round_key(self, matrix_key):
        self.round_keys = [[] for i in range(4)]
        for i in range(4):
            self.round_keys[i] = self.matrix_key[i]

        for i in range(4, 4 * 11):
            self.round_keys.append([])

            if i % 4 == 0:
                #Chỉ byte đầu XOR với RCon
                byte = Sbox[self.round_keys[i - 1][1]] ^ Rcon[i//4] ^ self.round_keys[i - 4][0]
                self.round_keys[i].append(byte)
            
                for j in range(1, 4):
                    byte = Sbox[self.round_keys[i - 1][(j + 1) % 4]] ^ self.round_keys[i - 4][j]
                    self.round_keys[i].append(byte)

            else:
                for j in range(4):
                    byte = self.round_keys[i - 1][j] ^ self.round_keys[i - 4][j]
                    self.round_keys[i].append(byte)

    def sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = Sbox[s[i][j]]
        return s

    def shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]
        return s

    def mix_single_column(self, a):
        # please see Sec 4.1.2 in The Design of Rijndael
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)
        return a

    def mix_columns(self, s):
        for i in range(4):
            self.mix_single_column(s[i])
        return s

    def add_round_key(self, s: list[list[int]], k: list[list[int]]) -> list[list[int]]: 
        for i in range(4):
            for j in range(4):
                s[i][j] ^= k[i][j]
        return s

    def encrypt(self, s: str) -> str:
        self.text_matrix = bytes2matrix(s)
        self.text_matrix = self.add_round_key(self.text_matrix, self.round_keys[:4])

        for i in range(1, 10):
            self.text_matrix = self.sub_bytes(self.text_matrix)
            self.text_matrix = self.shift_rows(self.text_matrix)
            self.text_matrix = self.mix_columns(self.text_matrix)
            self.text_matrix = self.add_round_key(self.text_matrix, self.round_keys[4 * i: 4 * (i + 1)])
        
        self.text_matrix = self.sub_bytes(self.text_matrix)
        self.text_matrix = self.shift_rows(self.text_matrix)
        self.text_matrix = self.add_round_key(self.text_matrix, self.round_keys[40:])

        return matrix2bytes(self.text_matrix)

    #Giải mã

    def inv_sub_bytes(self, s):
        for i in range(4):
            for j in range(4):
                s[i][j] = InvSbox[s[i][j]]
        return s

    def inv_shift_rows(self, s):
        s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
        s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
        s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]
        return s

    def inv_mix_columns(self, s):
        for i in range(4):
            u = xtime(xtime(s[i][0] ^ s[i][2]))
            v = xtime(xtime(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        return self.mix_columns(s)
    
    def decrypt(self, s: str) -> str:
        self.decrypt_matrix = bytes2matrix(s)
        self.decrypt_matrix = self.add_round_key(self.decrypt_matrix, self.round_keys[40:])
        self.decrypt_matrix = self.inv_shift_rows(self.decrypt_matrix)
        self.decrypt_matrix = self.inv_sub_bytes(self.decrypt_matrix)

        for i in range(9, 0, -1):
            self.decrypt_matrix = self.add_round_key(self.decrypt_matrix, self.round_keys[4 * i: 4 * (i + 1)])
            self.decrypt_matrix = self.inv_mix_columns(self.decrypt_matrix)
            self.decrypt_matrix = self.inv_shift_rows(self.decrypt_matrix)
            self.decrypt_matrix = self.inv_sub_bytes(self.decrypt_matrix)

        self.decrypt_matrix = self.add_round_key(self.decrypt_matrix, self.round_keys[:4])
        return matrix2bytes(self.decrypt_matrix)
    
    #Unicode

    def unicode_encrypt(self, data: str) -> str:
        #Input with unicode string but will return bytes string
        encrypt_data = data.encode(encoding='utf-8')
        encrypt_data = self.encrypt(encrypt_data)
        return encrypt_data

    def unicode_decrypt(self, data: str) -> str:

        #Input with bytes string but will return uncode string
        decrypt_data = self.decrypt(data)
        data = decrypt_data.decode('utf-8')
        return data

    #Larger than 16 bytes

    def unbound_encrypt(self, data: str) -> str:
        encrypt_data = b''
        for i in range(0, len(data), 16):
            encrypt_data += self.encrypt(data[i:i + 16])
        return encrypt_data

    def unbound_decrypt(self, data: str) -> str:
        decrypt_data = b''
        for i in range(0, len(data), 16):
            decrypt_data += self.decrypt(data[i:i + 16])
        return decrypt_data

    #Unicode stirng larger than 16 bytes
    
    def string_encrypt(self, data: str) -> str:
        encrypt_data = b''
        for i in range(0, len(data), 16):
            encrypt_data += self.unicode_encrypt(data[i:i + 16])
        return encrypt_data

    def string_decrypt(self, data: str) -> str:
        decrypt_data = ''
        for i in range(0, len(data), 16):
            decrypt_data += self.unicode_decrypt(data[i:i + 16])
        return decrypt_data

    #File

    def encrypt_file(self, input_path, output_path):
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                data = infile.read(16)
                if not data:
                    break

                text_encrypt = self.encrypt(data)
                outfile.write(text_encrypt)

    def decrypt_file(self, input_path, output_path = 'result.dat'):
        with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
            while True:
                data = infile.read(16)
                
                if not data:
                    break
                
                decrypt_text = self.decrypt(data)
                
                outfile.write(decrypt_text)

    #Process

    def show_func(self, func, data: str, *args) -> str:
        # if args != ():
        #     print(args)
        matrix_data = bytes2matrix(data)
        new_data = func(matrix_data, *args)
        new_string = matrix2bytes(new_data)
        print(new_string.hex())
        return new_string

    #Chi dung data duoi 16 bytes de minh hoa qua trinh  

    def show_process_encrypt(self, data: str) -> str:
        print('Key             : ', self.key)
        print('Data to encrypt : ', data)
        print('Key             : ', self.key.hex())
        print('Data to encrypt : ', data.hex())
        
        print('Round 0: ')
        print('Add Round key: ', end='')
        encrypt_data = self.show_func(self.add_round_key, data, self.round_keys[:4])

        for i in range(1, 10):
            print(f'Round {str(i)}: ')
            print('Sub Bytes    : ', end='')
            encrypt_data = self.show_func(self.sub_bytes, encrypt_data)
            print('Shift rows   : ', end='')
            encrypt_data = self.show_func(self.shift_rows, encrypt_data)
            print('Mix columns  : ', end='')
            encrypt_data = self.show_func(self.mix_columns, encrypt_data)
            print('Add Round key: ', end='')
            encrypt_data = self.show_func(self.add_round_key, encrypt_data, self.round_keys[4 * i: 4 * (i + 1)])
        
        print('Round 10: ')
        print('Sub Bytes    : ', end='')
        encrypt_data = self.show_func(self.sub_bytes, encrypt_data)
        print('Shift rows   : ', end='')
        encrypt_data = self.show_func(self.shift_rows, encrypt_data)
        print('Add Round key: ', end='')
        encrypt_data = self.show_func(self.add_round_key, encrypt_data, self.round_keys[40:])

        print('Encrypt data :', encrypt_data.hex())

        print('Encrypt Done!')
        
        return encrypt_data

    def show_process_decrypt(self, data: str) -> str:
        print('Encrypt data : ', data.hex())
        print('Round 10: ')
        print('Add Round key: ', end='')
        decrypt_data = self.show_func(self.add_round_key, data, self.round_keys[40:])
        print('Inv shift rows   : ', end='')
        decrypt_data = self.show_func(self.inv_shift_rows, decrypt_data)
        print('Inv sub Bytes    : ', end='')
        decrypt_data = self.show_func(self.inv_sub_bytes, decrypt_data)

        for i in range(9, 0, -1):
            print(f'Round {i}: ')
            print('Add Round key    : ', end='')
            decrypt_data = self.show_func(self.add_round_key, decrypt_data, self.round_keys[4 * i: 4 * (i + 1)])
            print('Inv mix columns  : ', end='')
            decrypt_data = self.show_func(self.inv_mix_columns, decrypt_data)
            print('Inv shift rows   : ', end='')
            decrypt_data = self.show_func(self.inv_shift_rows, decrypt_data)
            print('Inv sub Bytes    : ', end='')
            decrypt_data = self.show_func(self.inv_sub_bytes, decrypt_data)
        
        print('Round 0: ')
        print('Add Round key: ', end='')
        decrypt_data = self.show_func(self.add_round_key, decrypt_data, self.round_keys[:4])

        print('Decrypt data :', decrypt_data)

        print('Decrypt Done!')

        return decrypt_data

    def show_matrix_encrypt(self, data: str) -> str:
        print('Data to encrypt')
        encrypt_data = bytes2matrix(data)
        print_matrix(encrypt_data)

        print('Key')
        print_matrix(self.matrix_key)

        print('Round 0')
        print('Add round key')
        encrypt_data = self.add_round_key(encrypt_data, self.round_keys[:4])
        print_matrix(encrypt_data)
        print('__________________')

        for i in range(1, 10):
            print(f'Round {i}')
            print('Sub Bytes')
            encrypt_data = self.sub_bytes(encrypt_data)
            print_matrix(encrypt_data)
            print('Shift Rows')
            encrypt_data = self.shift_rows(encrypt_data)
            print_matrix(encrypt_data)
            print('Mix Columns')
            encrypt_data = self.mix_columns(encrypt_data)
            print_matrix(encrypt_data)
            print('Add round key')
            encrypt_data = self.add_round_key(encrypt_data, self.round_keys[i * 4:(i + 1) * 4])
            print_matrix(encrypt_data)
            print('__________________')

        print('Round 10')
        print('Sub Bytes')
        encrypt_data = self.sub_bytes(encrypt_data)
        print_matrix(encrypt_data)
        print('Shift Rows')
        encrypt_data = self.shift_rows(encrypt_data)
        print_matrix(encrypt_data)
        print('Add round key')
        encrypt_data = self.add_round_key(encrypt_data, self.round_keys[40:])
        print_matrix(encrypt_data)

        return matrix2bytes(encrypt_data)

    def show_matrix_decrypt(self, data: str) -> str:
        print('Data to decrypt')
        decrypt_data = bytes2matrix(data)
        print_matrix(decrypt_data)

        print('Round 10')
        print('Add round key')
        decrypt_data = self.add_round_key(decrypt_data, self.round_keys[40:])
        print_matrix(decrypt_data)
        print('Inv Shift Rows')
        decrypt_data = self.inv_shift_rows(decrypt_data)
        print_matrix(decrypt_data)
        print('Inv Sub Bytes')
        decrypt_data = self.inv_sub_bytes(decrypt_data)
        print_matrix(decrypt_data)
        print('__________________')

        for i in range(9, 0, -1):
            print(f'Round {i}')
            print('Add round key')
            decrypt_data = self.add_round_key(decrypt_data, self.round_keys[i * 4:(i + 1) * 4])
            print_matrix(decrypt_data)
            print('Inv Min Columns')
            decrypt_data = self.inv_mix_columns(decrypt_data)
            print_matrix(decrypt_data)
            print('Inv Shift Rows')
            decrypt_data = self.inv_shift_rows(decrypt_data)
            print_matrix(decrypt_data)
            print('Inv Sub Bytes')
            decrypt_data = self.inv_sub_bytes(decrypt_data)
            print_matrix(decrypt_data)
            print('__________________')

        print('Round 0')
        print('Add round key')
        encrypt_data = self.add_round_key(decrypt_data, self.round_keys[:4])
        print_matrix(decrypt_data)

        data = matrix2bytes(decrypt_data)
        print(data)

        return data






        
        







    
