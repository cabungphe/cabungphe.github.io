import re

# Từ điển 30 lệnh chính xác theo thứ tự trong file thực thi
MNEMONICS = [
    "MOVE", "GIVE", "TAKE", "JUMP", "CALL", "BACK", "SOUL", "BODY",
    "SPIR", "MIND", "LIFE", "DEATH", "SUN", "MOON", "STARS", "SAND",
    "NILE", "TOMB", "KEY", "LOCK", "DOOR", "PATH", "WALK", "REST",
    "ANKH", "HORUS", "RA", "OSIR", "ISIS", "SET"
]

def find_b0(opcode_str, reg_val):
    """Tìm byte gốc B0 dựa vào thuật toán của Ankh"""
    opcode_idx = MNEMONICS.index(opcode_str)
    possible_b0 = []
    
    for i in range(256):
        if i % 30 == opcode_idx and (i & 7) == reg_val:
            possible_b0.append(i)
            
    if not possible_b0:
        raise ValueError(f"Không thể tìm thấy Byte 0 hợp lệ cho {opcode_str} R{reg_val}")
        
    # Ưu tiên lấy giá trị đầu tiên (thường < 120). 
    # Nếu file exe xuất ra bị lỗi, chúng ta sẽ cần viết một heuristic để sửa PE Header sau.
    return possible_b0[0]

def decode_ankh(input_file, output_file):
    # Biểu thức chính quy (Regex) để bắt cú pháp: OPCODE R<x> [<y>] #<z>
    # Các tham số [y] và #z có thể không xuất hiện ở cuối file (chunk size < 3)
    pattern = re.compile(r"([A-Z]+)\s*R(\d+)(?:\s*\[(\d+)\])?(?:\s*#(\d+))?")
    
    with open(input_file, 'r') as f_in, open(output_file, 'wb') as f_out:
        for line_num, line in enumerate(f_in):
            line = line.strip()
            if not line:
                continue
                
            match = pattern.search(line)
            if not match:
                print(f"[!] Bỏ qua dòng {line_num + 1} không đúng định dạng: {line}")
                continue
                
            opcode = match.group(1)
            reg = int(match.group(2))
            
            # Tính Byte 0
            b0 = find_b0(opcode, reg)
            f_out.write(bytes([b0]))
            
            # Tính Byte 1 (nếu có)
            if match.group(3) is not None:
                b1 = int(match.group(3))
                f_out.write(bytes([b1]))
                
            # Tính Byte 2 (nếu có)
            if match.group(4) is not None:
                b2 = int(match.group(4))
                f_out.write(bytes([b2]))

    print(f"[+] Dịch ngược thành công! Đã lưu file tại: {output_file}")

# Chạy thử thuật toán
if __name__ == "__main__":
    # Thay tên file tùy theo thư mục của bạn
    decode_ankh("sacred_scroll.ankh", "recovered_treasure.exe")