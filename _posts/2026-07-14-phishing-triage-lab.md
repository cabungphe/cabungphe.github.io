---
title: "Phishing_Email_Triage_&_Alert_Handling"
date: 2026-07-01
categories: [Write up]
tags: [SOC]
image:
  path: /assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/image.png
  alt: Home Lab SOC Banner
  Description:
  
---

## 1. Mục tiêu lab

Giả lập một vụ tấn công Phishing. Đóng vai SOC Tier 1 để phân tích email gốc, trích xuất IOCs và viết Rule trên ELK để bắt hành vi mã độc.

## 2. Set up

Chuẩn bị sẵn 3 máy ảo `Ubuntu Server`(đã cài sẵn ELK), `Windows Server 2022`, `Kali Linux`.

* Attacker: Kali Linux (Chạy GoPhish).

* Nạn nhân: Windows Server 2022 (đã cài Sysmon).

* Logging & SIEM: Sysmon đẩy log về Elastic Stack (ELK).

* Tạo Rule trên SIEM.

### 2.1. Attacker Machine (Kali Linux)

Đây là máy chủ đóng vai trò thiết lập Phishing và phân phối mã độc.
![ip](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/kali/ip.png)

* IP: *192.168.78.135*
* Dockerized GoPhish: Triển khai framework GoPhish dưới dạng Docker container để đảm bảo môi trường độc lập, bám sát kiến trúc microservices.
  ```bash
  sudo docker pull gophish/gophish
  sudo docker run -d -p 3333:3333 -p 80:80 --name gophish_lab gophish/gophish
  ```
  Lần sau mở máy vào lại chỉ cần start docker:
  ```bash
  sudo docker start gophish_lab
  ```

* Lấy mật khẩu để login vào web GoPhish
  ```bash
  sudo docker logs gophish_lab
  ```
Kể từ các bản cập nhật mới, GoPhish tự sinh 1 password Admin ngẫu nhiên trong lần chạy đầu nên cần check log của Docker để lấy password.

* Login vào web qua url `https://192.168.78.135:3333`
![login](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/gophish/login.png)

* Users & Groups:

Add email của nạn nhân vào đây và Save

![group](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/gophish/group.png)

* Sending Profiles:

Điền thông tin gmail mồi, password là khối 16 ký tự do Google cấp để xác thực nhanh qua bên thứ 3. Điền xong ở dưới cùng có thể bấm `Send Test Email` để kiểm tra xem có thể gửi mail tới mục tiêu chưa.

![send](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/gophish/send.png)

* Lending Pages: Có thể tạo 1 cái Page rỗng ở đây.

* Email Templates:

Soạn kịch bản lừa đảo mạo danh nhân viên IT Support, chèn link tải tệp vào, khi nạn nhân click vào link đó, máy sẽ tự động tải xuống file mã độc.
  ```html
  <html>
  <head>
    <title></title>
  </head>
  <body>
  <h2 style="color: #d9534f;">[TH&Ocirc;NG B&Aacute;O KHẨN] Cập nhật bản v&aacute; bảo mật hệ thống</h2>

  <p>K&iacute;nh gửi người d&ugrave;ng,</p>

  <p>Y&ecirc;u cầu bạn lập tức tải xuống c&ocirc;ng cụ v&aacute; lỗi theo đường dẫn bảo mật nội bộ dưới đ&acirc;y v&agrave; chạy tệp tin để hệ thống tự động cập nhật.</p>

  <p>👉 <a href="http://192.168.78.135:8000/Security_Fix.exe" style="color: #0056b3; font-weight: bold; text-decoration: underline;">TẢI C&Ocirc;NG CỤ V&Aacute; LỖI TẠI Đ&Acirc;Y</a></p>

  <p><b>Ph&ograve;ng Quản trị Mạng - IT Support</b></p>
  </body>
  </html>
  ```

![template](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/gophish/template.png)

* Tạo 1 file `payload.c` sau đó biên dịch ra `Security_Fix.exe`:
  ```c
    #include <winsock2.h>
    #include <windows.h>
    #include <stdio.h>

    #pragma comment(lib,"ws2_32.lib")

    int main() {
        WSADATA wsa;
        SOCKET s;
        struct sockaddr_in server;
        char *message;

        // Khởi tạo thư viện mạng của Windows
        WSAStartup(MAKEWORD(2,2), &wsa);

        // Tạo socket
        s = socket(AF_INET, SOCK_STREAM, 0);

        // Cấu hình địa chỉ đích (Máy Kali của bạn)
        server.sin_family = AF_INET;
        server.sin_addr.s_addr = inet_addr("192.168.78.135"); 
        server.sin_port = htons(4444); // Cổng giao tiếp

        // Kết nối về máy Kali
        if (connect(s, (struct sockaddr *)&server, sizeof(server)) < 0) {
            return 1; // Thoát nếu không kết nối được
        }

        // Gửi thông điệp vô hại để tạo log
        message = "\n[!] CANH BAO: PING TU MAY TARGET WIN2K22 CHO LAB SOC!\n";
        send(s, message, strlen(message), 0);

        // Đóng kết nối và thoát êm đẹp
        closesocket(s);
        WSACleanup();

        return 0;
    }
  ```

* Mở Web Server tại nơi chứa file để nạn nhân tải về(ở đây tôi để file exe ở ngoài Desktop).
  ```python
  python3 -m http.server 8000
  ```

* Mở 1 terminal khác để thiết lập trạm lắng nghe tại cổng 4444 bằng Netcat để hứng quyền điều khiển khi nạn nhân click vào file.
  ```bash
  nc -lvnp 4444
  ```

### 2.2. Thiết lập Detection Rule trên SIEM (Elastic Security)

* Create 1 rule mới kiểu `Custom query`.
* Data view chọn `logs-*`.
* Custom query -> Điền câu lệnh KQL vào.
  ```sql
  event.code: 1 AND process.executable: *\\Users\\*\\Downloads\\*.exe
  ```
  `event.code: 1` giúp phát hiện process mới đuợc khởi tạo. Ngoài ra còn có `event.code: 3` phát hiện kết nối mạng, `event.code: 5` là process terminated, `event.code: 11` phát hiện file mới được tạo, và còn nhiều `event.code` khác nữa. Tuy nhiên ở bài lab này tôi mô phỏng lại 1 cuộc Phishing, file mã độc sẽ được tải về máy nạn nhân khi họ click vào link và nằm trong thư mục Downloads mặc định. Trong thực tế, file mã độc tải về thường nằm sâu trong `%AppData%\Roaming` hay `%AppData%\Local\Temp`,... cũng có thể copy file từ `Downloads` sang folder khác rồi xóa bản gốc ở `Downloads` đi,...

  Câu lệnh KQL trên sẽ giúp phát hiện tiến trình được khởi tạo và thực thi từ folder `Downloads`.

* Đặt tên Rule là `[Phishing] Suspicious Executable from Downloads`.
* Severity: `High` -> Khoảng trên 70 điểm.
![about](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/kibana/Rule/about.png)
* Schedule: Ở đây tôi setting Runs every 1 minute để lát nữa thực thi file có thể bắt được Alert luôn.
* Create & enable rule.

## 3. Tấn công

### 3.1. Launch Campaign

Tạo campaign và launch, email phishing sẽ đuợc gửi tới nạn nhân

![campaign](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/gophish/campaign.png)

### 3.2. User nhận mail

![malware](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/email/malware.png)

Khi user click vào link, tệp tin `Security_Fix.exe` được tải về và nằm trong folder `Downloads`. Trên máy chủ Kali ngay lập tức thấy 1 request tải file từ port 8000 đang mở sẵn.

Và khi nạn nhân click thực thi file thì gần như không thấy gì xảy ra cả. Lúc đó file mã độc đã âm thầm chạy, thiết lập kết nối TCP hướng ra ngoài tới trạm lắng nghe Netcat(`port 4444`) trên máy Kali, tín hiệu cảnh báo lập tức hiện lên.

![exec](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/email/execute.png)

## 4. Điều tra

### 4.1. Tiếp nhận Alert trên ELK

![alert](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/kibana/Alert/alert.png)

Tại giao diện Seccurity Alerts, Rule `[Phishing]Suspicious Executable from Downloads` đã được Trigger. Thu thập được các thông tin sơ bộ ban đầu:

* Máy nạn nhân (`host.name`): `win-server22`.
* Tài khoản (`user.name`): `Administrator`.
* Path (`process.executable`): `C:\Users\Administrator\Downloads\Security_Fix.exe`.
* Tiến trình cha (`process.parent.name`): `explorer.exe`.
![ksatsobo](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/kibana/Alert/ksatsobo.png)

Chuyển qua giao diện **Kibana Discover**, thiết lập thời gian và truy vấn KQL để gom toàn bộ raw logs liên quan đến tệp khả nghi(`Security_Fix.exe`) trên máy nạn nhân.

![discover](/assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/kibana/Alert/discover.png)

Kết quả trả về chuỗi 3 event log bám sát vòng đời của mã độc do Sysmon ghi nhận.

* Event ID 1 (Process creation): 
  * Tệp `Security_Fix.exe` được khởi chạy từ đường dẫn `C:\Users\Administrator\Downloads\`. Việc nằm trong thư mục Downloads chứng tỏ đây là một tệp được tải về từ internet, không thuộc hệ điều hành.
  * Tiến trình cha (`process.parent.name`) là `explorer.exe`, khẳng định nạn nhân đã trực tiếp tương tác (nhấp đúp chuột) để thực thi tệp thủ công.
* Event ID 3 (Network Connection):
  * Ngay khi vừa tiến trình vừa được sinh ra, nó lập tức mở một kết nối mạng hướng ra ngoài (Outbound).
  * IP & Port đích: Kết nối trỏ về IP lạ `192.168.78.135` qua cổng `4444`. Trong thực tế, các bản cập nhật phần mềm hợp lệ thường giao tiếp qua cổng `80/443` (HTTP/HTTPS). Việc sử dụng cổng `4444` là dấu hiệu đặc trưng (Indicator of Attack) của các công cụ Reverse Shell hoặc C2 Beacon.
* Event ID 5 (Process Terminated):
  * Ghi nhận khoảnh khắc tiến trình kết thúc, giúp xác định được thời gian tồn tại (Uptime) của mã độc trên hệ thống để đánh giá mức độ ảnh hưởng.  

### 4.2. Truy vết Email trên máy nạn nhân

### 4.3. Trích xuất IOCs & OSINT

## 5. Báo cáo

