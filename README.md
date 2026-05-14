# WiFi Security Monitor — Rogue AP & Deauth Detection

Hệ thống giám sát an ninh Wi-Fi: phát hiện Rogue AP, Evil Twin và Deauthentication Attack bằng Python + Scapy, với Web Dashboard và cảnh báo Telegram.

---

## Mục lục

1. [Phân tích đề tài](#1-phân-tích-đề-tài)
2. [Kiến trúc hệ thống](#2-kiến-trúc-hệ-thống)
3. [Thiết bị & môi trường cần chuẩn bị](#3-thiết-bị--môi-trường-cần-chuẩn-bị)
4. [Cài đặt VM1 — Kali Linux (Detector)](#4-cài-đặt-vm1--kali-linux-detector)
5. [Cài đặt VM2 — Ubuntu Server (Attacker/Test)](#5-cài-đặt-vm2--ubuntu-server-attackertest)
6. [Cài đặt project trên VM1](#6-cài-đặt-project-trên-vm1)
7. [Cấu hình whitelist và config](#7-cấu-hình-whitelist-và-config)
8. [Chạy hệ thống](#8-chạy-hệ-thống)
9. [Kiểm thử từng tính năng](#9-kiểm-thử-từng-tính-năng)
10. [Tích hợp Dashboard OpenSearch](#10-tích-hợp-dashboard-opensearch)
11. [Cảnh báo Telegram](#11-cảnh-báo-telegram)
12. [Xử lý lỗi thường gặp](#12-xử-lý-lỗi-thường-gặp)
13. [Kế hoạch 14 ngày](#13-kế-hoạch-14-ngày)
14. [Cảnh báo pháp lý](#14-cảnh-báo-pháp-lý)

---

## 1. Phân tích đề tài

### Các khái niệm chính

**Rogue AP (Unauthorized Access Point)**
Access Point không được phép trong hệ thống. Có thể do nhân viên tự ý cắm router, hoặc attacker cố tình cài để chiếm quyền mạng.

**Evil Twin (Fake AP)**
AP giả mạo có SSID giống hoặc gần giống AP hợp lệ nhưng BSSID (địa chỉ MAC) khác. Client khi kết nối vào Evil Twin sẽ bị nghe lén toàn bộ traffic.

**Deauthentication Attack**
Attacker gửi hàng loạt frame `Deauthentication` (802.11 type 0, subtype 12) giả mạo tới client hoặc AP. Vì frame này không được mã hóa trong chuẩn WPA2, bất kỳ ai cũng có thể giả mạo. Hậu quả: client bị ngắt kết nối liên tục, hoặc bị ép kết nối lại vào Evil Twin.

**Wireless IDS / WIDS**
Hệ thống phát hiện xâm nhập không dây. Hoạt động ở monitor mode — không tham gia mạng, chỉ nghe thụ động tất cả frame trong không khí.

### Phạm vi đề tài

| Tính năng | Có |
|---|---|
| Phát hiện Rogue AP (BSSID lạ cùng SSID) | ✅ |
| Phát hiện Evil Twin (SSID tương tự) | ✅ |
| Phát hiện Deauth Attack (đếm frame theo cửa sổ thời gian) | ✅ |
| Ghi log JSON (JSONL format) | ✅ |
| Web Dashboard realtime | ✅ |
| Tích hợp OpenSearch | ✅ |
| Cảnh báo Telegram | ✅ |
| Định vị chính xác vị trí AP | ❌ |
| Crack password Wi-Fi | ❌ |
| Tấn công ngược lại | ❌ |

---

## 2. Kiến trúc hệ thống

### Sơ đồ tổng thể

```
┌──────────────────────────────────────────────────────────┐
│                     Không gian Wi-Fi                     │
│                                                          │
│  [AP Hợp lệ]               [Rogue AP / Evil Twin]        │
│  SSID: Lab-WiFi            SSID: Lab-WiFi                │
│  BSSID: AA:BB:CC:11:22:33  BSSID: 66:77:88:99:AA:BB ←khác│
│                                                          │
│  [Attacker] ──── Deauth Frames ──►                       │
└──────────────────────┬───────────────────────────────────┘
                       │  Beacon / Deauth Frame (802.11)
                       ▼
          ┌────────────────────────┐
          │   USB Wi-Fi Adapter    │
          │   Monitor Mode         │
          │   (wlan1mon)           │
          └────────────┬───────────┘
                       │
          ┌────────────▼───────────┐
          │   Python / Scapy       │
          │   Detection Engine     │
          │                        │
          │  scanner.py            │  ← Quét ban đầu, liệt kê AP
          │  rogue_detector.py     │  ← So sánh SSID/BSSID vs whitelist
          │  deauth_detector.py    │  ← Đếm frame trong cửa sổ TG
          │  sniffer.py            │  ← Điều phối, ghi log, gửi alert
          └────────────┬───────────┘
                       │
         ┌─────────────┼──────────────┐
         ▼             ▼              ▼
    JSON Log      OpenSearch      Telegram
    (JSONL)       Dashboard        Alert
```

### Luồng xử lý chi tiết

```
Bước 1: SCAN (scanner.py)
  └─ Sniff Beacon 10 giây → build danh sách AP → hiện menu

Bước 2: SNIFF REALTIME (sniffer.py)
  ├─ Nhận Beacon Frame
  │   └─ rogue_detector.check(ap)
  │       ├─ SSID khớp whitelist + BSSID khớp → OK, bỏ qua
  │       └─ SSID khớp whitelist + BSSID KHÁC → 🚨 ROGUE ALERT
  │
  └─ Nhận Deauth Frame
      └─ deauth_detector.process(bssid)
          ├─ Thêm timestamp vào sliding window
          ├─ count < threshold → bình thường
          └─ count ≥ threshold → 🚨 DEAUTH ALERT

Bước 3: HANDLE ALERT
  ├─ In ra terminal (màu đỏ)
  ├─ Ghi logs/wifi_alerts.jsonl
  ├─ Push OpenSearch (nếu bật)
  └─ Gửi Telegram (nếu bật)
```

---

## 3. Thiết bị & môi trường cần chuẩn bị

### Danh sách thiết bị

| # | Thiết bị | Bắt buộc | Ghi chú |
|---|---|---|---|
| 1 | PC/Laptop chạy được VM | ✅ | RAM ≥ 8GB để chạy đồng thời 2 VM |
| 2 | USB Wi-Fi Adapter | ✅ | **Phải** hỗ trợ monitor mode (xem mục bên dưới) |
| 3 | Wi-Fi Router thật | ✅ | AP hợp lệ để điền vào whitelist |
| 4 | Điện thoại Android/iPhone | Tùy chọn | Tạo hotspot giả khi test Rogue AP |

### Chọn USB Wi-Fi Adapter đúng loại

> ⚠️ Card Wi-Fi tích hợp trong laptop **gần như không hỗ trợ monitor mode**. Bắt buộc mua USB rời.

**Chip được khuyến nghị:**

| Chip | Adapter phổ biến | Giá | Ghi chú |
|---|---|---|---|
| Realtek RTL8812AU | Alfa AWUS036ACH | ~700k VNĐ | Hỗ trợ cả 2.4GHz và 5GHz, phổ biến nhất |
| Atheros AR9271 | Alfa AWUS036NHA | ~400k VNĐ | Chỉ 2.4GHz, ổn định, driver có sẵn trong Kali |
| Ralink RT5370 | nhiều thương hiệu | ~150k VNĐ | Rẻ nhất, chỉ 2.4GHz |

**Chip cần tránh:** Intel (không hỗ trợ), Broadcom (driver Linux tệ), MediaTek MT7612U (unstable).

### Cấu hình 2 VM

```
HOST MACHINE (máy thật, RAM ≥ 8GB)
│
├── VM1: Kali Linux 2024.x  ← Máy chính chạy detection
│   ├── RAM: 3GB
│   ├── Disk: 25GB
│   ├── Network 1: Host-only  → 192.168.56.10
│   ├── Network 2: NAT        → cài package internet
│   └── USB Passthrough: USB Wi-Fi Adapter
│
└── VM2: Ubuntu Server 22.04  ← Máy test tấn công
    ├── RAM: 1GB
    ├── Disk: 10GB
    ├── Network 1: Host-only  → 192.168.56.20
    └── Network 2: NAT        → cài package internet
```

---

## 4. Cài đặt VM1 — Kali Linux (Detector)

### 4.1 Tạo VM trong VirtualBox

1. Mở VirtualBox → **New**
2. Name: `Kali-Detector`, Type: Linux, Version: Debian (64-bit)
3. RAM: 3072 MB
4. Create VDI: 25 GB (dynamically allocated)

**Cấu hình Network:**
- Settings → Network → Adapter 1: **NAT**
- Settings → Network → Adapter 2: **Host-only Adapter** → `vboxnet0`

**Cấu hình USB Passthrough:**
- Settings → USB → USB 3.0 Controller ✅
- Nhấn dấu `+` → Add thêm filter → chọn USB Wi-Fi Adapter theo tên

> **Lưu ý VirtualBox:** Trước khi bật VM, cắm USB adapter vào, sau đó vào Devices → USB → chọn adapter để kết nối vào VM.

**Với VMware Workstation:**
- VM Settings → Network Adapter 1: NAT
- VM Settings → Add → Network Adapter 2: Host-only
- Khi VM đang chạy: VM → Removable Devices → USB Adapter → Connect

### 4.2 Cài Kali Linux

Dùng ISO từ https://www.kali.org/get-kali/ (chọn Installer, 64-bit).

Cài đặt thông thường. Khi đến phần **Software selection**, chọn tối thiểu:
- ✅ Kali desktop environment
- ✅ Top10 tools (bao gồm aircrack-ng)

### 4.3 Cập nhật hệ thống sau khi cài

```bash
sudo apt update && sudo apt -y full-upgrade
sudo reboot
```

### 4.4 Cài driver USB Wi-Fi (nếu cần)

Sau khi reboot, kiểm tra adapter đã nhận diện chưa:

```bash
lsusb
# Tìm dòng chứa tên chip Wi-Fi, ví dụ:
# Bus 001 Device 003: ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac
```

**Nếu dùng chip RTL8812AU (Alfa AWUS036ACH):**

```bash
sudo apt -y install dkms linux-headers-$(uname -r) build-essential bc
git clone https://github.com/aircrack-ng/rtl8812au.git
cd rtl8812au
sudo make dkms_install
cd .. && rm -rf rtl8812au
sudo modprobe 88XXau
```

**Nếu dùng chip AR9271 (Atheros):**

```bash
sudo apt -y install firmware-ath9k-htc
# Rút USB ra cắm lại là xong
```

**Xác nhận interface đã nhận:**

```bash
ip link
# Phải thấy: wlan0, wlan1 (tùy máy)
# wlan0 = card tích hợp laptop (nếu có)
# wlan1 = USB adapter mới cắm
```

### 4.5 Kiểm tra và bật monitor mode

```bash
# Kiểm tra adapter có hỗ trợ monitor mode không
sudo iw list | grep -A 10 "Supported interface modes"
# Phải thấy dòng: * monitor
# Nếu không thấy → đổi adapter khác

# Kill các tiến trình tranh giành interface
sudo airmon-ng check kill
# Output: Killing processes that may interfere with wireless...
# NetworkManager, wpa_supplicant sẽ bị kill

# Bật monitor mode (thay wlan1 bằng tên thực tế trên máy bạn)
sudo airmon-ng start wlan1
# Output mẫu:
# (phy1) - Switching to monitor mode for [phy1]wlan1
# (monitor mode enabled on [phy1]wlan1mon)

# Xác nhận
iwconfig
# wlan1mon  IEEE 802.11bgn  Mode:Monitor  Frequency:2.412 GHz  ...
```

**Kiểm tra bắt được packet thật:**

```bash
sudo airodump-ng wlan1mon
# Sau 2-3 giây phải thấy bảng AP như sau:
#
# BSSID              PWR  Beacons  #Data  CH  MB   ENC  CIPHER AUTH ESSID
# AA:BB:CC:11:22:33  -42       15      0   6  130  WPA2 CCMP   PSK  Lab-WiFi
# DD:EE:FF:44:55:66  -71        8      0  11   54  WPA2 CCMP   PSK  Neighbor
#
# Nhấn Ctrl+C để thoát
```

Ghi lại **BSSID** và **channel** của router thật (Lab-WiFi) — cần dùng ở Bước 7.

### 4.6 Cấu hình IP tĩnh cho Host-only

```bash
# Kiểm tra tên interface host-only (thường là eth0 hoặc eth1)
ip link
# eth0: NAT (có IP tự động từ DHCP)
# eth1: Host-only (chưa có IP)

# Set IP tĩnh
sudo nano /etc/network/interfaces
```

Thêm vào cuối file:

```
# Host-only network (giao tiep voi VM2)
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0
```

```bash
sudo systemctl restart networking
# Kiểm tra
ip addr show eth1
# Phải thấy: inet 192.168.56.10/24
```

---

## 5. Cài đặt VM2 — Ubuntu Server (Attacker/Test)

VM2 dùng để giả lập tấn công khi kiểm thử. Không cần USB Wi-Fi Adapter cho VM này (trừ khi muốn test Deauth thật sự với inject frame).

### 5.1 Tạo VM trong VirtualBox

1. New → Name: `Ubuntu-Attacker`, Type: Linux, Version: Ubuntu (64-bit)
2. RAM: 1024 MB, Disk: 10 GB
3. Network Adapter 1: NAT
4. Network Adapter 2: Host-only → `vboxnet0`

### 5.2 Cài Ubuntu Server 22.04

ISO từ https://ubuntu.com/download/server

Cài đặt minimal. Không cần cài desktop.

### 5.3 Cài công cụ tấn công

```bash
sudo apt update
sudo apt -y install aircrack-ng hostapd iw wireless-tools net-tools curl

# Kiểm tra
aireplay-ng --help | head -5
hostapd -h | head -3
```

### 5.4 Cấu hình IP tĩnh

```bash
sudo nano /etc/netplan/00-installer-config.yaml
```

Nội dung:

```yaml
network:
  version: 2
  ethernets:
    enp0s3:           # NAT interface (tên thực tế có thể khác)
      dhcp4: true
    enp0s8:           # Host-only interface
      addresses:
        - 192.168.56.20/24
```

```bash
sudo netplan apply
ip addr show enp0s8
# Phải thấy: inet 192.168.56.20/24
```

### 5.5 Kiểm tra kết nối giữa 2 VM

Từ VM1:
```bash
ping -c 3 192.168.56.20
# Phải thấy: 3 packets transmitted, 3 received
```

Từ VM2:
```bash
ping -c 3 192.168.56.10
# Phải thấy: 3 packets transmitted, 3 received
```

---

## 6. Cài đặt project trên VM1

Tất cả lệnh sau đây chạy trên **VM1 (Kali)**.

### 6.1 Cài các gói hệ thống cần thiết

```bash
sudo apt update
sudo apt -y install python3 python3-pip python3-venv \
    docker.io docker-compose-v2 git curl jq
```

### 6.2 Clone hoặc tạo thư mục project

```bash
mkdir -p ~/wifi-security-monitor
cd ~/wifi-security-monitor
```

Cấu trúc thư mục sau khi tạo đầy đủ:

```
wifi-security-monitor/
├── config/
│   ├── config.yaml           ← Cấu hình chính
│   └── whitelist.json        ← Danh sách AP hợp lệ
├── detector/
│   ├── __init__.py
│   ├── main.py               ← CLI entry point
│   ├── scanner.py            ← Quét AP ban đầu
│   ├── sniffer.py            ← Sniff + điều phối alert
│   ├── rogue_detector.py     ← Phát hiện Rogue AP / Evil Twin
│   └── deauth_detector.py    ← Phát hiện Deauth Attack
├── webapp/
│   ├── app.py                ← FastAPI backend
│   └── templates/
│       └── index.html        ← Dashboard UI
├── logs/
│   └── wifi_alerts.jsonl     ← Log file (tạo tự động)
├── requirements.txt
└── docker-compose.yml
```

### 6.3 Tạo virtual environment và cài thư viện

```bash
cd ~/wifi-security-monitor
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

# Kiểm tra
python -c "import scapy; print('Scapy OK')"
python -c "import fastapi; print('FastAPI OK')"
```

> **Tại sao dùng `.venv/bin/python` thay vì `python`?**
> Khi chạy với `sudo`, shell không kế thừa venv. Phải dùng đường dẫn tuyệt đối: `sudo .venv/bin/python`.

---

## 7. Cấu hình whitelist và config

### 7.1 Tìm thông tin AP thật

Chạy airodump để lấy BSSID và channel của router thật:

```bash
sudo airodump-ng wlan1mon
```

Ghi lại thông tin từ bảng output:

```
BSSID              PWR  CH   ENC  CIPHER  AUTH  ESSID
AA:BB:CC:11:22:33  -42   6  WPA2  CCMP    PSK   Lab-WiFi
```

### 7.2 Cập nhật whitelist.json

Sửa file `config/whitelist.json`:

```json
[
  {
    "ssid": "Lab-WiFi",
    "bssid": "AA:BB:CC:11:22:33",
    "channel": 6,
    "encryption": "WPA2",
    "note": "Router chinh phong lab"
  }
]
```

> Nếu có nhiều AP hợp lệ (nhiều tầng, nhiều phòng), thêm tất cả vào đây. Bất kỳ AP nào không có trong list này mà phát beacon với SSID trùng sẽ bị báo Rogue.

### 7.3 Cập nhật config.yaml

Sửa file `config/config.yaml`, đặc biệt là `interface`:

```yaml
interface: wlan1mon    # Tên interface monitor mode của bạn (kiểm tra bằng iwconfig)
```

Các tham số quan trọng khác:

```yaml
ssid_similarity_threshold: 0.85
# 0.85 = bắt SSID tương đồng >= 85%
# Ví dụ: "Lab-WiFi" vs "Lab_WiFi" → similarity ~0.94 → BẮT ĐƯỢC
# Ví dụ: "Lab-WiFi" vs "Hoang-WiFi" → similarity ~0.6 → bỏ qua

deauth_threshold: 20
# 20 frame deauth trong 10 giây → trigger alert
# Tấn công thật thường gửi 50-100+ frame/giây
# Điều chỉnh thấp hơn nếu muốn nhạy hơn (nhưng dễ false positive)
```

---

## 8. Chạy hệ thống

### 8.1 Mode CLI (Terminal)

```bash
cd ~/wifi-security-monitor
source .venv/bin/activate
sudo .venv/bin/python -m detector.main
```

**Luồng tương tác:**

```
╔══════════════════════════════════════════════════════╗
║         WiFi Security Monitor v1.0                  ║
╚══════════════════════════════════════════════════════╝

[*] Scanning on wlan1mon for 10 seconds...

NO   BSSID                SSID                         CH   ENC     RSSI
---------------------------------------------------------------------------
  1  AA:BB:CC:11:22:33    Lab-WiFi                      6   WPA2    -42 dBm
  2  DD:EE:FF:44:55:66    Neighbor-Net                 11   WPA2    -70 dBm
  3  11:22:33:AA:BB:CC    HomeNet                       1   WPA3    -81 dBm

Nhap so thu tu AP muon giam sat (Enter = giam sat tat ca): 1

[*] Da chon: Lab-WiFi (AA:BB:CC:11:22:33)
[*] Sniffing started on wlan1mon
[*] Dang giam sat... (Nhan Ctrl+C de dung)
```

Khi phát hiện Rogue AP:
```
============================================================
[!!!] ROGUE AP DETECTED  [2026-05-10T12:00:00Z]  Severity: HIGH
  SSID     : Lab-WiFi
  Legit    : AA:BB:CC:11:22:33
  Detected : 66:77:88:99:AA:BB
  Channel  : 6  RSSI: -52 dBm
  Sim      : 1.0
============================================================
```

Khi phát hiện Deauth Attack:
```
============================================================
[!!!] DEAUTH ATTACK DETECTED  [2026-05-10T12:05:00Z]  Severity: HIGH
  Target BSSID : AA:BB:CC:11:22:33
  SSID         : Lab-WiFi
  Source MAC   : 88:99:AA:BB:CC:DD
  Frame count  : 30 in 10s
  Threshold    : 20
============================================================
```

Nhấn `Ctrl+C` để dừng và xem tóm tắt:
```
[*] Dang dung...

[SUMMARY]
  Beacon frames   : 1240
  Deauth frames   : 32
  Total alerts    : 2
  Log file        : logs/wifi_alerts.jsonl
```

### 8.2 Mode Web Dashboard

Mở terminal thứ 2 trên VM1:

```bash
cd ~/wifi-security-monitor
sudo .venv/bin/python -m uvicorn webapp.app:app --host 0.0.0.0 --port 8000
```

Mở trình duyệt trên **máy host** (hoặc VM1 nếu có desktop):

```
http://192.168.56.10:8000
```

Tính năng Dashboard:
- **Scan APs** — quét và liệt kê AP, click để chọn target
- **Start/Stop Monitor** — bật/tắt sniffing
- **Live Alerts** — alert hiện realtime, tự cập nhật mỗi 3 giây
- **Log File** — xem lịch sử, filter theo loại
- **Whitelist** — thêm/xóa AP hợp lệ không cần restart

---

## 9. Kiểm thử từng tính năng

### TC01 — AP hợp lệ không gây alert (Sanity check)

**Mục đích:** Xác nhận không có false positive.

```bash
# Đảm bảo whitelist.json có đúng BSSID router thật
# Chạy tool, để yên 3-5 phút
sudo .venv/bin/python -m detector.main
```

**Kết quả mong đợi:** Không có dòng `[!!!]` nào. Log file trống.

---

### TC02 — Phát hiện Rogue AP / Evil Twin

#### Cách A: Dùng hotspot điện thoại (dễ nhất)

1. Trên điện thoại, vào **Settings → Hotspot/Wi-Fi Sharing**
2. Đặt tên mạng (SSID) **giống hệt** AP trong whitelist: `Lab-WiFi`
3. Bật hotspot
4. Quan sát terminal VM1

**Kết quả mong đợi:**
```
[!!!] ROGUE AP DETECTED
      SSID     : Lab-WiFi
      Legit    : AA:BB:CC:11:22:33
      Detected : [MAC điện thoại]
      Severity : HIGH
```

**Kiểm tra log:**
```bash
tail -f logs/wifi_alerts.jsonl | python3 -m json.tool
```

Output:
```json
{
  "timestamp": "2026-05-10T12:00:00Z",
  "event_type": "rogue_ap_detected",
  "ssid": "Lab-WiFi",
  "legit_bssid": "AA:BB:CC:11:22:33",
  "detected_bssid": "66:77:88:99:AA:BB",
  "channel": 6,
  "rssi": -52,
  "ssid_similarity": 1.0,
  "severity": "high",
  "message": "SSID 'Lab-WiFi' matches legitimate AP but BSSID is unknown..."
}
```

#### Cách B: Dùng hostapd trên VM2 (giống tấn công thật hơn)

Trên **VM2**, mở terminal:

```bash
# Tạo file config hostapd
cat <<'EOF' > /tmp/fakeap.conf
interface=wlan0
ssid=Lab-WiFi
hw_mode=g
channel=6
auth_algs=1
ignore_broadcast_ssid=0
EOF

# Chạy fake AP
sudo hostapd /tmp/fakeap.conf
# Output: wlan0: interface state UNINITIALIZED->ENABLED
# Để terminal này chạy
```

Quan sát terminal VM1 → phải thấy alert tương tự Cách A.

Dừng fake AP: `Ctrl+C` trong terminal VM2.

---

### TC03 — Phát hiện Deauthentication Attack

Trên **VM2**, mở terminal mới (để hostapd terminal chạy song song nếu muốn):

```bash
# Xem tên Wi-Fi interface trên VM2
ip link | grep wlan

# Gửi 30 Deauth frame vào AP thật
# Thay AA:BB:CC:11:22:33 bằng BSSID router thật của bạn
sudo aireplay-ng --deauth 30 -a AA:BB:CC:11:22:33 wlan0
```

> **Lưu ý:** `aireplay-ng` cần interface cũng ở monitor mode. Trên VM2, nếu chỉ có card ảo (không có USB adapter), lệnh này sẽ báo lỗi. Có 2 cách giải quyết:
> - Cắm thêm USB Wi-Fi Adapter thứ 2 vào VM2
> - Hoặc dùng `mdk4` để inject frame qua card ảo (xem lỗi 6 bên dưới)

**Kiểm tra terminal VM1:**
```
[!!!] DEAUTH ATTACK DETECTED
      Target BSSID : AA:BB:CC:11:22:33
      Frame count  : 30 in 10s
      Threshold    : 20
```

**Kiểm tra log:**
```bash
cat logs/wifi_alerts.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    if d['event_type'] == 'deauth_attack_detected':
        print(json.dumps(d, indent=2))
"
```

---

### TC04 — Phát hiện SSID tương tự (Fuzzy matching)

Kiểm tra threshold 0.85 hoạt động đúng. Trên điện thoại, thử các SSID:

| Hotspot SSID | Whitelist SSID | Similarity | Kết quả mong đợi |
|---|---|---|---|
| `Lab-WiFi` | `Lab-WiFi` (BSSID khác) | 1.00 | 🚨 ALERT |
| `Lab_WiFi` | `Lab-WiFi` | ~0.94 | 🚨 ALERT |
| `Lab-Wifi` | `Lab-WiFi` | ~0.94 | 🚨 ALERT |
| `LabWiFi` | `Lab-WiFi` | ~0.87 | 🚨 ALERT |
| `FreeWiFi` | `Lab-WiFi` | ~0.63 | ✅ Bỏ qua |

---

### TC05 — Kiểm tra Web Dashboard

```bash
# Trên VM1, bật webapp
sudo .venv/bin/python -m uvicorn webapp.app:app --host 0.0.0.0 --port 8000
```

Trên máy host, mở: `http://192.168.56.10:8000`

Kiểm tra từng tính năng:
1. Nhấn **SCAN APs** → phải thấy danh sách AP
2. Click chọn AP → nhấn **START MONITOR**
3. Bật hotspot điện thoại (SSID giả) → alert phải hiện trong dashboard sau tối đa 3 giây
4. Tab **LOG FILE** → nhấn **TẢI LOG** → thấy lịch sử
5. **WHITELIST** → thêm AP mới → API gọi reload ngay, không cần restart

---

## 10. Tích hợp Dashboard OpenSearch

### 10.1 Khởi động OpenSearch bằng Docker

```bash
cd ~/wifi-security-monitor

# Bật containers
sudo docker compose up -d

# Kiểm tra đang chạy
sudo docker ps
# Phải thấy: wifi-opensearch, wifi-opensearch-dashboards

# Chờ 60 giây rồi test
curl http://localhost:9200
# Trả về JSON thông tin cluster là OK
```

### 10.2 Bật push log trong config.yaml

```yaml
opensearch:
  enabled: true
  endpoint: http://localhost:9200
  index: wifi-security-logs
  verify_tls: false
```

Chạy lại detector → mỗi alert sẽ tự động được đẩy vào OpenSearch.

### 10.3 Truy cập OpenSearch Dashboards

Mở trình duyệt: `http://192.168.56.10:5601`

**Tạo Index Pattern:**
1. Menu trái → Stack Management → Index Patterns → Create index pattern
2. Index pattern name: `wifi-security-logs*`
3. Time field: `timestamp`
4. Create index pattern

**Tạo visualizations (vào Visualize → Create):**

| Chart | Loại | Aggregation |
|---|---|---|
| Tổng alert | Metric | Count |
| Alert theo loại | Pie | Terms on `event_type.keyword` |
| Timeline | Line | Date histogram on `timestamp` |
| Top Rogue BSSID | Bar | Terms on `detected_bssid.keyword` |
| Severity breakdown | Bar | Terms on `severity.keyword` |

**Tạo Dashboard:**
1. Dashboard → Create dashboard
2. Add all → Save as "WiFi Security Monitor"

---

## 11. Cảnh báo Telegram

### 11.1 Tạo Telegram Bot

1. Mở Telegram → tìm **@BotFather**
2. Gửi `/newbot`
3. Nhập tên hiển thị: `WiFi Security Monitor`
4. Nhập username: `my_wifi_monitor_bot` (kết thúc bằng `_bot`)
5. Copy token được cấp, ví dụ: `1234567890:ABCDefGHijkLMnop`

### 11.2 Lấy Chat ID

```bash
# Thay YOUR_TOKEN bằng token vừa lấy
curl "https://api.telegram.org/botYOUR_TOKEN/getMe"
# Trả về thông tin bot là token hợp lệ

# Mở bot trên Telegram, gửi /start
# Rồi chạy:
curl "https://api.telegram.org/botYOUR_TOKEN/getUpdates"
# Tìm: "chat": { "id": 987654321 }
# Số 987654321 chính là chat_id
```

### 11.3 Test thủ công trước khi tích hợp

```bash
curl -X POST "https://api.telegram.org/botYOUR_TOKEN/sendMessage" \
  -d "chat_id=987654321" \
  -d "text=✅ WiFi Monitor test OK"
# Phải nhận được tin nhắn trên Telegram
```

### 11.4 Cấu hình trong config.yaml

```yaml
telegram:
  enabled: true
  bot_token: "1234567890:ABCDefGHijkLMnop"
  chat_id: "987654321"
```

Khi có alert, bot sẽ gửi:
```
🚨 ROGUE AP DETECTED
SSID: `Lab-WiFi`
Legit: `AA:BB:CC:11:22:33`
Rogue: `66:77:88:99:AA:BB`
CH: 6  RSSI: -52 dBm
Time: 2026-05-10T12:00:00Z
```

---

## 12. Xử lý lỗi thường gặp

### Lỗi 1 — Không vào được monitor mode

**Triệu chứng:**
```
SIOCSIFFLAGS: Operation not possible due to RF-kill
```

**Nguyên nhân:** RF-kill đang block Wi-Fi.

**Giải pháp:**
```bash
sudo rfkill list       # Xem trạng thái
sudo rfkill unblock all
sudo airmon-ng start wlan1
```

---

### Lỗi 2 — airmon-ng thành công nhưng không bắt được packet

**Triệu chứng:** `airodump-ng` chạy nhưng bảng AP trống sau 30 giây.

**Nguyên nhân:** Channel cố định sai, hoặc interface chưa thực sự ở monitor mode.

**Giải pháp:**
```bash
# Kiểm tra mode thực sự
iwconfig wlan1mon
# Phải thấy: Mode:Monitor

# Đặt channel đúng (channel 6 là phổ biến nhất)
sudo iwconfig wlan1mon channel 6

# Xác nhận bắt được bằng tcpdump
sudo tcpdump -i wlan1mon -c 20 type mgt
# Phải thấy frame cuộn nhanh
```

---

### Lỗi 3 — PermissionError khi chạy Python

**Triệu chứng:**
```
PermissionError: [Errno 13] Permission denied: '/dev/rfkill'
```

**Nguyên nhân:** Cần root để bắt raw packet.

**Giải pháp:** Luôn dùng đường dẫn Python trong venv + sudo:
```bash
# ĐÚNG:
sudo .venv/bin/python -m detector.main

# SAI (thiếu sudo):
.venv/bin/python -m detector.main

# SAI (sai Python, dùng system python không có scapy):
sudo python3 -m detector.main
```

---

### Lỗi 4 — Module scapy không tìm thấy

**Triệu chứng:**
```
ModuleNotFoundError: No module named 'scapy'
```

**Nguyên nhân:** Chạy sai Python (không phải Python trong venv).

**Giải pháp:**
```bash
# Kiểm tra Python nào đang dùng
sudo .venv/bin/python -c "import sys; print(sys.executable)"
# Phải trả về: /home/user/wifi-security-monitor/.venv/bin/python

# Cài lại nếu cần
source .venv/bin/activate
pip install -r requirements.txt
```

---

### Lỗi 5 — OpenSearch Container không khởi động

**Triệu chứng:**
```
ERROR: wifi-opensearch exited with code 78
```

**Nguyên nhân:** `vm.max_map_count` quá thấp (OpenSearch yêu cầu ≥ 262144).

**Giải pháp:**
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo docker compose up -d
```

---

### Lỗi 6 — VM2 không inject được Deauth frame (không có USB adapter)

**Triệu chứng:** `aireplay-ng` báo lỗi vì card ảo không hỗ trợ injection.

**Giải pháp thay thế — dùng `mdk4`:**
```bash
sudo apt -y install mdk4

# Tạo file chứa BSSID target
echo "AA:BB:CC:11:22:33" > /tmp/targets.txt

# Gửi deauth frames (mode d = deauth)
sudo mdk4 wlan0 d -b /tmp/targets.txt -c 6
# Chạy vài giây rồi Ctrl+C
```

---

### Lỗi 7 — No beacon captured (sau khi chọn AP)

**Triệu chứng:** Tool chạy nhưng không thấy gì, không alert gì kể cả khi bật hotspot giả.

**Giải pháp:**
```bash
# Kiểm tra AP còn phát không
sudo airodump-ng wlan1mon --channel 6
# Nếu không thấy BSSID mục tiêu → AP đã tắt hoặc đổi channel

# Reset monitor mode
sudo airmon-ng stop wlan1mon
sudo airmon-ng start wlan1
```

---

## 13. Kế hoạch 14 ngày

| Ngày | Việc cần làm | Tiêu chí hoàn thành |
|---|---|---|
| 1 | Tạo 2 VM, cài Kali + Ubuntu, cấu hình network | VM1 và VM2 ping được nhau |
| 2 | Cắm USB adapter, cài driver, bật monitor mode, test airodump | `airodump-ng` thấy AP, ghi lại BSSID router |
| 3 | Setup project, tạo cấu trúc thư mục, cài requirements | `python -c "import scapy"` không lỗi |
| 4 | Hoàn thiện `scanner.py`, test quét AP và hiện menu | Chạy scanner thấy đúng danh sách AP |
| 5 | Điền whitelist.json, viết `rogue_detector.py` | Logic check SSID/BSSID hoạt động đúng |
| 6 | Test TC02 (Cách A — hotspot điện thoại) | Log file có event `rogue_ap_detected` |
| 7 | Test TC02 (Cách B — hostapd VM2), viết `deauth_detector.py` | hostapd tạo được fake AP |
| 8 | Test TC03 (aireplay-ng hoặc mdk4 từ VM2) | Log file có event `deauth_attack_detected` |
| 9 | Hoàn thiện `sniffer.py`, test TC04 (fuzzy SSID) | Tất cả TC01-TC04 pass |
| 10 | Setup Docker, cài OpenSearch, bật push log, tạo index pattern | Dashboard thấy alert realtime |
| 11 | Viết `webapp/app.py` + `index.html`, test TC05 | Dashboard web hoạt động tại port 8000 |
| 12 | Tích hợp Telegram, test gửi alert | Nhận được tin nhắn Telegram khi có alert |
| 13 | Viết report, chụp screenshot, kiểm tra lại toàn bộ | Tất cả TC pass, screenshot đủ |
| 14 | Chuẩn bị slides demo, cleanup code, demo thử | Demo chạy mượt 10 phút không lỗi |

---

## 14. Cảnh báo pháp lý

> ⚠️ **ĐỌC TRƯỚC KHI THỰC HÀNH**

Các kỹ thuật trong đề tài này (monitor mode, deauth frame injection, fake AP) chỉ được phép thực hiện trên:
- Hệ thống mạng do chính bạn sở hữu
- Thiết bị trong phòng lab có sự đồng ý rõ ràng của quản trị viên
- Môi trường kiểm thử cô lập, không kết nối với mạng công cộng

**Tuyệt đối không:**
- Bắt gói tin từ mạng Wi-Fi của người khác (kể cả hàng xóm, quán cà phê)
- Gửi Deauth frame vào AP không thuộc quyền quản lý
- Tạo Evil Twin để lừa người thật kết nối

**Tại Việt Nam**, vi phạm các điều trên có thể bị xử lý theo Điều 80 Luật An ninh mạng 2018 và Nghị định 13/2023/NĐ-CP, với mức phạt từ hành chính đến truy cứu hình sự.

---

## Tham khảo

- Scapy documentation: https://scapy.readthedocs.io/
- aircrack-ng suite: https://www.aircrack-ng.org/
- RTL8812AU driver: https://github.com/aircrack-ng/rtl8812au
- OpenSearch: https://opensearch.org/docs/
- FastAPI: https://fastapi.tiangolo.com/
- hostapd: https://w1.fi/hostapd/
