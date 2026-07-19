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

![rule_lsass](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/rule_lassas.png)

```sql
  event.code: "10" 
  AND winlog.channel: "Microsoft-Windows-Sysmon/Operational" 
  AND winlog.event_data.TargetImage: *lsass.exe 
  AND (process.name: "taskmgr.exe" OR winlog.event_data.SourceImage: *Taskmgr.exe OR winlog.event_data.SourceImage: *taskmgr.exe)
```

*   **[Custom] Suspicious Command Shell spawned by Network Services**:

    Phát hiện WMI hoặc Services tự động sinh ra command shell.

![rule_suspicious_command](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/rule_suspicious_command.png)

```sql
  event.code: "1" 
  AND winlog.event_data.ParentImage: (*WmiPrvSE.exe* OR *services.exe*) 
  AND winlog.event_data.Image: (*cmd.exe* OR *powershell.exe*)
```

*   **[Custom] Impacket PsExec - Suspicious Service Creation**:

    Phát hiện tạo Windows Service mới (Event ID 7045) trỏ về thư mục hệ thống. Dấu hiệu này có thể là phần mềm hợp lệ hoặc công cụ tấn công (ví dụ: PsExec). Cần đối chiếu với Event 4624 (Logon Type 3, NTLM) cùng thời điểm để loại trừ nhiễu.

![impacet](/assets/Project_SOC_Home_Lab/Active_Directory_Breach_Detection_Lab/kibana/impact.png)

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
