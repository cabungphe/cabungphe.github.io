import os
from PIL import Image

# Đọc dữ liệu file
file_path = "pixel.raw"
with open(file_path, "rb") as f:
    raw_data = f.read()

file_size = len(raw_data)
print(f"Tổng số bytes: {file_size}")

# Tìm các cặp Width x Height có thể có (Giả sử ảnh 1 kênh màu - Grayscale)
print("Các cặp Width x Height tiềm năng:")
factors = []
for i in range(1, int(file_size**0.5) + 1):
    if file_size % i == 0:
        width = file_size // i
        height = i
        factors.append((width, height))
        print(f"- {width} x {height} (hoặc {height} x {width})")

# Bạn có thể thử render nghiệm có tỷ lệ hợp lý nhất (ví dụ: màn hình ngang)
# Giả sử bạn chọn một cặp width, height từ kết quả trên:
# w, h = <điền width>, <điền height>
# img = Image.frombytes('L', (w, h), raw_data)
# img.show()