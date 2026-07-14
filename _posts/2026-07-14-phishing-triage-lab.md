---
title: "Phishing_Email_Triage_&_Alert_Handling"
date: 2026-07-01
categories: [Write up]
tags: [SOC]
image:
  path: /assets/Project_SOC_Home_Lab/Phishing_Email_Triage_&_Alert_Handling/image.png
  alt: Home Lab SOC Banner
---

## 1. Mục tiêu lab

Giả lập một vụ tấn công Phishing từ đầu đến cuối. Đóng vai SOC Tier 1 để phân tích email gốc, trích xuất IOCs và viết Rule trên ELK để bắt hành vi mã độc.

## 2. Set up

Chuẩn bị sẵn 3 máy ảo `Ubuntu Server`(đã cài sẵn ELK), `Windows Server 2022`, `Kali Linux`.

**Attacker: ** Kali Linux (Chạy GoPhish).

**Nạn nhân: ** Windows Server 2022 (đã cài Sysmon).

**Logging & SIEM: ** Sysmon đẩy log về Elastic Stack (ELK).

**Tạo Rule trên SIEM: **

## 3. Tấn công

## 4. Điều tra

### 4.1. Tiếp nhận Alert trên ELK

### 4.2. Truy vết Email trên máy nạn nhân

### 4.3. Trích xuất IOCs & OSINT

## 5. Báo cáo

