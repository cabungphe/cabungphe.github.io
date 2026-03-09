def ROL16(x, shift):
    # Dịch xoay trái 16-bit
    x = x & 0xFFFF
    return ((x << shift) | (x >> (16 - shift))) & 0xFFFF

# Dữ liệu trích xuất từ .rodata của IDA
byte_402008 = [0x98, 0x11, 0x77, 0x39, 0x4F, 0x49, 0x33, 0x25, 0x85, 0x43, 0x9C, 0xF3, 0x42, 0x37]
byte_402018 = [0x6A, 0x82, 0x39, 0x6C, 0x3C, 0x29, 0x62, 0x16, 0x1D, 0x94, 0xA1, 0x5A, 0xB6, 0xD3]

state = 4919 # Khởi tạo từ hàm main
passwd = ["_"] * 28 # Chuỗi mật khẩu dài 28 ký tự

for i in range(14):
    low_state = state & 0xFF
    high_state = (state >> 8) & 0xFF
    
    # Tính toán lại ký tự left và right
    left = (byte_402008[i] - i - low_state) & 0xFF
    right = (byte_402018[i] + i + high_state) & 0xFF
    
    # Điền vào mảng passwd
    passwd[i] = chr(left)
    passwd[27 - i] = chr(right)
    
    # Cập nhật state giống hệt hàm của chương trình
    temp = (right + (left ^ state)) & 0xFFFF
    state = ROL16(temp, 3)

# In kết quả
final_password = "".join(passwd)
print(f"[*] Mật khẩu tìm được: {final_password}")

# Kiểm tra chốt hạ
if state == 30740:
    print("[+] Trạng thái cuối (state) khớp với 30740. Chắc chắn đúng!")
else:
    print(f"[-] Trạng thái cuối bị sai: {state}")
