# Mảng 35 bytes trích xuất từ Ghidra
hex_data = "e0ea9fe8c2ffbfe1c2fd96db828df4a88aa6b3145d694d357e694c7b135a1417287136"
data = bytes.fromhex(hex_data)

flag = ""
bVar4 = 0

for byte in data:
    # Lõi giải mã: byte ^ bVar4 ^ 0xa5
    decrypted_char = chr(byte ^ bVar4 ^ 0xa5)
    flag += decrypted_char

    # Ép kiểu giới hạn trong 1 byte (0-255)
    bVar4 = (bVar4 + 7) & 0xFF

print("[+] Flag:", flag)
