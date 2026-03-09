import re

def extract_hex_from_ankh(input_file, output_file):
    # Regex tìm đoạn nằm trong ngoặc vuông sau dấu chấm phẩy
    # Ví dụ: ; [4D 5A 90]
    pattern = re.compile(r";\s*\[([0-9A-Fa-f\s]+)\]")
    
    recovered_bytes = bytearray()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Bỏ qua dòng trống hoặc dòng chỉ có comment thuần túy (không chứa địa chỉ)
            if not line or line.startswith(';'):
                continue
                
            match = pattern.search(line)
            if match:
                hex_string = match.group(1)
                # Tách các chuỗi hex (vd: '4D', '5A', '90') và chuyển thành số nguyên
                byte_list = [int(x, 16) for x in hex_string.split()]
                recovered_bytes.extend(byte_list)
                
    with open(output_file, 'wb') as f_out:
        f_out.write(recovered_bytes)
        
    print(f"[+] Khôi phục thành công {len(recovered_bytes)} bytes!")
    print(f"[+] Đã lưu file tại: {output_file}")

if __name__ == "__main__":
    extract_hex_from_ankh("sacred_scroll.ankh", "recovered_treasure.exe")