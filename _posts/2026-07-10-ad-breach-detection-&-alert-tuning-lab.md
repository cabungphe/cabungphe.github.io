---
title: "AD Breach Detection & Alert Tuning Lab"
date: 2026-07-10
categories: [Write up]
tags: [SOC]
image:
  path: /assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/image.png
  alt: Home Lab SOC Banner
  Description:
  
---


## 1. Mục tiêu lab

**Mục tiêu:**
Giả lập giai đoạn hậu khai thác (Post-Exploitation) trên môi trường Active Directory để bám sát thực tế quy trình SOC. Đóng vai trò SOC Tier 1, mục tiêu là phân tích log, phát hiện hành vi Credential Dumping và Lateral Movement (Pass-the-Hash), đồng thời tinh chỉnh các custom rule để giảm thiểu nhiễu từ các hoạt động quản trị hợp lệ trong mạng.

**Kịch bản tấn công:**
Tiếp nối Giai đoạn 1, nạn nhân đã lỡ click vào đường link trong email Phishing và tải mã độc về máy. Ở Giai đoạn 2 này, kẻ tấn công tiến hành thu thập thông tin xác thực bằng cách dump bộ nhớ của tiến trình `lsass.exe` để lấy NTLM Hash. Sau đó, file dump được gửi bí mật về máy chủ Kali Linux qua giao thức SCP/SSH. Cuối cùng, kẻ tấn công sử dụng công cụ để thực hiện tấn công Pass-the-Hash (PtH) nhằm di chuyển ngang (Lateral Movement) sang các máy tính khác trong Domain.

## 2. Set up

### 2.1. Chuẩn bị Lab

Chuẩn bị 4 máy ảo để mô phỏng một mạng doanh nghiệp cơ bản và trạm kiểm soát của hacker:
*   **Ubuntu Server:** Máy chủ trung tâm cài đặt ELK Stack (triển khai qua Docker Compose) để thu thập log.
*   **Windows Server 2022 (Domain Controller):** Đóng vai trò máy chủ quản lý miền AD.
*   **Windows 10 (Client):** Máy tính của nhân viên (nạn nhân đã bị nhiễm mã độc ở Giai đoạn 1).
*   **Kali Linux (Attacker):** Trạm điều khiển của hacker.

**Thiết lập công cụ trên máy Kali Linux:**
Nếu máy Kali chưa có sẵn `pypykatz` và bộ công cụ `impacket` (để thực hiện di chuyển ngang), hãy mở terminal và chạy các lệnh sau để cài đặt:

```bash
  # Cài đặt pypykatz để đọc file dump ngoại tuyến
  pip3 install pypykatz

  # Cài đặt Impacket (chứa wmiexec, psexec,...)
  sudo apt update
  sudo apt install python3-impacket -y
```

### 2.2. Custom Rules

Do phiên bản ELK miễn phí bị hạn chế tính năng đối với Prebuilt Rules, ta sẽ tự xây dựng các rule tùy chỉnh (Custom Sigma rules / KQL) nhằm bám sát hành vi thay vì signature truyền thống:
*   **[Custom] LSASS Memory Dump (Credential Theft)**:

    Event ID 10 trên lsass.exe vốn cực kỳ ồn — gần như process nào cũng đụng vào lsass ít nhiều — nên nếu bắt tất cả thì rule sẽ ngập noise ngay từ đầu. Vì trong lab này tôi dump thủ công qua Task Manager, nên tôi chốt luôn điều kiện SourceImage là Taskmgr.exe cho gọn, dù biết ngoài thực tế attacker sẽ không hiền như vậy.

![rule_lsass](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/rule/rule_lassas.png)

```sql
  event.code: "10" 
  AND winlog.channel: "Microsoft-Windows-Sysmon/Operational" 
  AND winlog.event_data.TargetImage: *lsass.exe 
  AND (process.name: "taskmgr.exe" OR winlog.event_data.SourceImage: *Taskmgr.exe OR winlog.event_data.SourceImage: *taskmgr.exe)
```

*   **[Custom] Suspicious Command Shell spawned by Network Services**:

    Phát hiện WMI hoặc Services tự động sinh ra command shell.

![rule_suspicious_command](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/rule/rule_suspicious_command.png)

```sql
  event.code: "1" 
  AND winlog.event_data.ParentImage: (*WmiPrvSE.exe* OR *services.exe*) 
  AND winlog.event_data.Image: (*cmd.exe* OR *powershell.exe*)
```

*   **[Custom] Impacket PsExec - Suspicious Service Creation**:

    Phát hiện tạo Windows Service mới (Event ID 7045) trỏ về thư mục hệ thống. Dấu hiệu này có thể là phần mềm hợp lệ hoặc công cụ tấn công (ví dụ: PsExec). Cần đối chiếu với Event 4624 (Logon Type 3, NTLM) cùng thời điểm để loại trừ nhiễu.

![impacet](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/rule/impact.png)

```sql
  event.code: "7045" 
  AND winlog.event_data.ImagePath: (*systemroot* OR *Windows* OR *ADMIN$*)
```

    Ánh xạ MITRE ATT&CK: Rule này bắt trực tiếp kỹ thuật Service Execution (T1569.002) thuộc tactic Execution (TA0002), vì kẻ tấn công lợi dụng cơ chế tạo Windows Service từ xa để thực thi lệnh. Tag Pass the Hash (T1550.002) thuộc tactic Lateral Movement (TA0008) được gắn thêm vì trong kịch bản lab, service này chỉ tạo được nhờ NTLM Hash đánh cắp — bản thân query 7045 không xác nhận được cơ chế xác thực, cần đối chiếu thêm Event 4624 (Logon Type 3, NTLM) để xác nhận đúng là PtH.

Các rule trong bài lab này tôi thiết kế cho 2-3 phút sẽ quét 1 lần.

Các rule ở trên là phiên bản baseline, chưa qua tuning. Ở phần 4 (Điều tra), tôi sẽ đối chiếu alert thật với log nhiễu từ script IT Admin để xây dựng exception/exclusion phù hợp.

### 2.3. Giả lập nhiễu (Benign Noise)

Để môi trường lab có độ chân thực cao và phục vụ cho bước Alert Tuning (tinh chỉnh cảnh báo), cần trộn lẫn các log tấn công (True Positives) với các log hoạt động bình thường (False Positives). Cụ thể, ta sẽ setup một script PowerShell trên máy Windows 10 để mô phỏng các tác vụ quản trị tự động, vô hại qua WinRM. 

```shell
  $ServerIP = "192.168.78.133"

  Write-Host "=== KỊCH BẢN GIẢ LẬP NHIỄU TỪ IT ADMIN ===" -ForegroundColor Cyan
  $cred = Get-Credential -Message "Nhập tài khoản Administrator của máy chủ Windows Server ($ServerIP)"

  while ($true) {
      Write-Host "[*] Bắt đầu đẩy lệnh sang Server lúc $(Get-Date)..." -ForegroundColor Yellow

      # ---------------------------------------------------------
      # TÁC VỤ 1: Kích hoạt Rule 2 (WMI đẻ ra PowerShell)
      # ---------------------------------------------------------
      Write-Host " -> Thực thi Tác vụ 1: Remote PowerShell via WMI (khớp Rule 2)"
      try {
          Invoke-WmiMethod -ComputerName $ServerIP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command `"Get-Service`"" | Out-Null
      } catch {
          Write-Host " [!] Lỗi Tác vụ 1: $($_.Exception.Message)" -ForegroundColor Red
      }

      # ---------------------------------------------------------
      # TÁC VỤ 2: Bổ sung nhiễu tiến trình (WMI đẻ ra CMD/Tiến trình hệ thống, cùng khớp Rule 2)
      # Giả lập IT đẩy lệnh cmd từ xa để kiểm tra thông tin cấu hình
      # ---------------------------------------------------------
      Write-Host " -> Thực thi Tác vụ 2: Remote CMD via WMI (khớp Rule 2)"
      try {
          Invoke-WmiMethod -ComputerName $ServerIP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c systeminfo" | Out-Null
      } catch {
          Write-Host " [!] Lỗi Tác vụ 2: $($_.Exception.Message)" -ForegroundColor Red
      }

      # ---------------------------------------------------------
      # TÁC VỤ 3: Kích hoạt Rule 3 (Tạo Service có chứa file .exe)
      # ---------------------------------------------------------
      Write-Host " -> Thực thi Tác vụ 3: Tạo service IT_NetworkMonitor (khớp Rule 3)"
      try {
          Invoke-WmiMethod -ComputerName $ServerIP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "sc.exe delete IT_NetworkMonitor" | Out-Null
          Start-Sleep -Seconds 2
          Invoke-WmiMethod -ComputerName $ServerIP -Credential $cred -Class Win32_Process -Name Create -ArgumentList "sc.exe create IT_NetworkMonitor binPath= `"C:\Windows\System32\ping.exe 8.8.8.8`" start= demand" | Out-Null
      } catch {
          Write-Host " [!] Lỗi Tác vụ 3: $($_.Exception.Message)" -ForegroundColor Red
      }

      Write-Host "[+] Hoàn tất chu kỳ. Đang ngủ 2 phút chờ Kibana quét log..." -ForegroundColor Green
      Write-Host "-----------------------------------------------------------"
      Start-Sleep -Seconds 120
  }
```

## 3. Tấn công

### 3.1. Dump Hash thủ công

Thông thường, mã độc sẽ sử dụng các kỹ thuật (như gọi `rundll32.exe comsvcs.dll, MiniDump` hay lạm dụng API hệ thống) để tự động trích xuất bộ nhớ tiến trình. Tuy nhiên, vì bài lab này tập trung cốt lõi vào nghiệp vụ SOC, tôi sẽ bỏ qua khâu phát triển tính năng phức tạp đó cho mã độc và tiến hành dump file thủ công:
*   Truy cập trực tiếp vào máy Windows 10 (Nạn nhân).
*   Mở **Task Manager** dưới quyền Administrator.
*   Tại tab **Details**, click chuột phải vào tiến trình `lsass.exe` và chọn **Create dump file**. File `lsass.dmp` sẽ được lưu lại.

![filedump](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/win10/dump.png)

### 3.2. Exfiltration & Lateral Movement (Đánh cắp & Di chuyển ngang)

Chuỗi hành động tiếp theo của kẻ tấn công:
*   **Exfiltration:** Dùng giao thức SCP/SSH đẩy bí mật tệp `lsass.dmp` từ máy nạn nhân về máy Kali Linux.

![dump_scp](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/win10/file_scp.png)

*   **Trích xuất NTLM:** Tại máy Kali, chạy công cụ `pypykatz` đọc file dump ngoại tuyến để bóc tách NTLM Hash của các tài khoản đặc quyền:
    ```bash
    pypykatz lsa minidump "lsass.dmp"
    ```
*   **Lateral Movement:** Tận dụng NTLM Hash vừa thu thập, kẻ tấn công dùng công cụ thuộc bộ Impacket thực hiện Pass-the-Hash (PtH) để thâu tóm máy chủ khác trong mạng, ví dụ như Domain Controller, mà không cần biết mật khẩu gốc.
    ```bash
      impacket-psexec -hashes :cb8a428385459087a76793010d60f5dc CABUNGPHE/Administrator@192.168.78.133
    ```
![attack](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kali/attack.png)

### 3.3 Tạo nhiễu

Chạy script nhiễu vừa đề cập đến ở phần 2.3

![nhieu](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/win10/nhieu.png)

## 4. Điều tra

Sau khi kịch bản tấn công và giả lập nhiễu được thực thi, màn hình Kibana Alerts xuất hiện các cảnh báo ở nhiều mức độ (High, Medium). Đóng vai trò SOC Tier 1, nhiệm vụ của tôi là phân tích log để xâu chuỗi sự kiện, phân biệt tín hiệu tấn công thật (True Positive) và báo động giả (False Positive) dựa trên các bằng chứng kỹ thuật (Artifacts).

![alert](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/alert.png)

### 4.1. Xác nhận Credential Dumping trên máy nạn nhân

Cụm cảnh báo đầu tiên xuất hiện là 4 alert **[Custom] LSASS Memory Dump (Credential Theft)** trên máy `nhanvien_pc`.

Tick chọn 4 alert đó, chuyển `status` từ `open` sang `acknownleged` và chuyển 4 alert đó sang `Timelines` để phân tích.
*   **TargetImage:** `C:\Windows\system32\lsass.exe`
*   **SourceImage:** `C:\Windows\system32\taskmgr.exe`
*   **GrantedAccess:** `0x1FFFFF`

![lsass](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/lsass.png)

Việc tiến trình `taskmgr.exe` (Task Manager) chọc thẳng vào bộ nhớ của `lsass.exe` với mã quyền `0x1FFFFF` (PROCESS_ALL_ACCESS - Quyền truy cập tối đa) là bằng chứng không thể chối cãi của một pha tạo file dump bộ nhớ trực tiếp từ giao diện người dùng. 

**Kết luận:** Đây chắc chắn là **True Positive**. Tôi tiến hành chọn cả 4 cảnh báo này, gắn tag `True Positive`, tạo một Case mới `[T1] Credential Access - LSASS Dump via Taskmgr` để báo cáo sự cố, sau đó đóng (Mark as closed) để giải phóng hàng đợi Dashboard.

![case](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/create_case.png)

```text
  - Tóm tắt: Phát hiện hành vi Credential Dumping (LSASS) qua giao diện vào khoảng 2026/07/19 21:30:08.
  - Mục tiêu: Máy nhanvien_pc | Tài khoản bị ảnh hưởng: nv1
  - Chi tiết kỹ thuật: Tiến trình hệ thống taskmgr.exe được sử dụng để truy cập bộ nhớ lsass.exe:
  SourceImage: C:\Windows\System32\procdump.exe
  TargetImage: C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1FFFFF
  - Hành động đã thực hiện: 
    + Xác nhận True Positive dựa trên Event ID 10.
    + Gộp 4 alerts liên quan vào Case này.
    + Đã đóng (Mark as closed) các alert trên Dashboard để chuyển hướng điều tra bước tiếp theo.
```

### 4.2. Khảo sát Timeline & Tách nhiễu

Tiếp theo là hàng loạt cảnh báo **Suspicious Command Shell** (Medium) và **Impacket PsExec** (High) trên máy `win-server22`. Để không bị nhầm lẫn, tôi đưa toàn bộ các log liên quan vào module **Timelines**, thiết lập khung thời gian sát với thời điểm nổ alert và phân tích lần lượt từ dưới lên (từ cũ nhất đến mới nhất).

**Bước 1: Phân tích hành vi chạy lệnh & Tạo Service**
Lần theo dấu vết trên Timeline (từ `21:27:00`), tôi ghi nhận một chuỗi hành động liên tiếp:
*   Mở powershell để gọi `Get-Service`.
*   Tiến trình `cmd.exe` gọi `systeminfo`.
*   Công cụ `sc.exe` thực hiện hành động `delete` dịch vụ có tên `IT_NetworkMonitor`.
*   Đến `21:28:25`, sau một loạt lệnh `Get-Service`, hệ thống ghi nhận `services.exe` và `C:\Windows\servicing\TrustedInstaller.exe` hoạt động. Ngay sau đó, lệnh create lại `IT_NetworkMonitor` được thực thi cùng với một loạt hành động create/delete tương tự.
*   Kiểm tra thêm chi tiết của các cảnh báo High liên quan đến `ping.exe`, tôi phát hiện đường dẫn gọi lệnh là `C:\Windows\System32\ping.exe 8.8.8.8` xuất phát từ chính tiến trình tạo dịch vụ.

![IT_NetworkMonitor](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/IT.png)

-> *Kết luận:* Chuỗi hành vi gọi `systeminfo`, `Get-Service` và tạo/xóa service chứa lệnh `ping` hoàn toàn khớp với kịch bản giả lập nhiễu tự động của IT Admin. Đây là **False Positive**.

**Bước 2: Phát hiện Lateral Movement (Pass-the-Hash)**
Tiếp tục đối chiếu trên Timeline, một điểm bất thường cực kỳ nghiêm trọng xuất hiện lúc `21:28:35.422`
*   **Source IP:** `192.168.78.135` (Thuộc về máy Kali Linux).
*   **User:** `Administrator`.

![attack](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/attack.png)

Mở rộng chi tiết các Alert High nổ ra ngay sau thời điểm đăng nhập này, tôi kiểm tra trường `Image/ImagePath` và phát hiện đường dẫn: **`%systemroot%\RNrpcJyb.exe`**.
Việc một file thực thi mang tên ngẫu nhiên được sinh ra trong thư mục lõi của Windows (`C:\Windows`) ngay sau khi IP lạ đăng nhập thành công chính là Signature (đặc điểm nhận dạng) kinh điển của công cụ `impacket-psexec`. Kẻ tấn công đã sử dụng NTLM Hash thu được từ pha LSASS Dump trước đó để chiếm quyền Server.

-> *Kết luận:* Hành vi đăng nhập từ Kali và sinh ra file `RNrpcJyb.exe` là **True Positive**.

### 4.3. Phân loại và Đóng Alert (Resolution)

Với các bằng chứng rõ ràng từ Timeline, quy trình Triage được dứt điểm như sau:
1.  **Xử lý Nhiễu (False Positives):** Tick chọn các cảnh báo Medium (gọi `systeminfo`, `Get-Service`) và các cảnh báo High chứa lệnh `ping 8.8.8.8`. Gắn tag `False Positive` và chọn Mark as closed.
2.  **Xử lý Tấn công (True Positives):** Tick chọn các cảnh báo High liên quan đến hành vi tạo service chứa file `%systemroot%\VCtnVeay.exe`. Gắn tag `True Positive`, đưa chúng vào Case sự cố đang mở (để liên kết thành một chuỗi Kill Chain hoàn chỉnh từ khâu Credential Access sang Lateral Movement), sau đó Mark as closed.