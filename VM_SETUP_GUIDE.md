# Chuẩn bị VM & Mạng - WiFi Security Monitor

## Tổng quan môi trường lab

Dự án này cần **2 VM hoặc 2 máy thật**:

```
┌─────────────────────────────────────────────────────────┐
│                   HOST MACHINE                          │
│              (máy tính vật lý của bạn)                  │
│                                                         │
│  ┌─────────────────────┐   ┌──────────────────────┐    │
│  │   VM1: Kali Linux   │   │  VM2: Ubuntu Server  │    │
│  │   (DETECTOR)        │   │  (ATTACKER - test)   │    │
│  │                     │   │                      │    │
│  │ + USB Wi-Fi Adapter │   │ + Card mạng ảo       │    │
│  │   (passthrough)     │   │                      │    │
│  │ IP: 192.168.56.10   │   │ IP: 192.168.56.20    │    │
│  └─────────────────────┘   └──────────────────────┘    │
│                                                         │
│           Host-only Network: 192.168.56.0/24            │
└─────────────────────────────────────────────────────────┘
                          │
               USB Wi-Fi Adapter (wlan1mon)
                          │
              ┌───────────▼──────────────┐
              │     KHÔNG KHÍ Wi-Fi      │
              │   (Beacon/Deauth Frames) │
              └───────────────────────┘
                          │
              ┌───────────▼──────────────┐
              │    Wi-Fi Router (thật)   │
              │    SSID: Lab-WiFi        │
              │    IP: 192.168.1.1       │
              └──────────────────────────┘
```

---

## Thiết bị cần chuẩn bị

### Bắt buộc

| STT | Thiết bị | Vai trò | Ghi chú |
|---|---|---|---|
| 1 | PC/Laptop chạy được VM | Chạy 2 VM | RAM ≥ 8GB để chạy 2 VM cùng lúc |
| 2 | USB Wi-Fi Adapter | Bắt gói tin Wi-Fi | **Chip RTL8812AU** (Alfa AWUS036ACH) hoặc AR9271 |
| 3 | Wi-Fi Router | AP hợp lệ (legit) | Router bình thường, không cần config đặc biệt |

### Tùy chọn (để test Evil Twin/Deauth tốt hơn)

| STT | Thiết bị | Mục đích |
|---|---|---|
| 4 | Điện thoại Android/iPhone | Tạo Hotspot giả (test Rogue AP đơn giản) |
| 5 | USB Wi-Fi Adapter thứ 2 | VM2 dùng để inject Deauth frame (nếu muốn) |

---

## VM1 — Kali Linux (Detector)

**Đây là máy chính chạy toàn bộ code detection.**

### Cấu hình VM

| Thông số | Giá trị |
|---|---|
| OS | Kali Linux 2024.x hoặc Ubuntu 22.04 LTS |
| RAM | 2GB (tối thiểu) — 4GB (khuyến nghị) |
| Disk | 20GB |
| CPU | 2 vCPU |
| Network Adapter 1 | **Host-only** — 192.168.56.10/24 (kết nối với VM2) |
| Network Adapter 2 | **NAT** — để cài package từ internet |

### USB Passthrough (quan trọng!)

USB Wi-Fi Adapter phải được pass thẳng vào VM1, không qua host:

**VirtualBox:**
1. VM Settings → USB → USB 3.0 Controller
2. Thêm filter: chọn USB adapter theo tên (ví dụ: Realtek 802.11ac)
3. Khởi động VM1 → USB adapter tự vào VM, không hiện trên host

**VMware:**
1. VM Settings → USB Controller → USB 3.1
2. Kết nối vật lý USB → VMware hỏi "connect to host or VM" → chọn VM1

### Kiểm tra sau khi boot

```bash
# Kiểm tra USB adapter nhận diện
lsusb | grep -i realtek   # hoặc grep -i atheros

# Kiểm tra interface
ip link show
# Phải thấy wlan0 hoặc wlan1

# Kiểm tra monitor mode support
sudo iw list | grep -A5 "Supported interface modes"
# Phải thấy * monitor
```

---

## VM2 — Ubuntu Server (Attacker/Test machine)

**Dùng để giả lập tấn công trong môi trường kiểm thử.**

### Cấu hình VM

| Thông số | Giá trị |
|---|---|
| OS | Ubuntu Server 22.04 LTS |
| RAM | 1GB |
| Disk | 10GB |
| CPU | 1 vCPU |
| Network Adapter 1 | **Host-only** — 192.168.56.20/24 |
| Network Adapter 2 | **NAT** — để cài package |

> VM2 dùng card mạng ảo bình thường, không cần USB Wi-Fi Adapter.
> Nếu muốn test Deauth attack thật sự thì VM2 cũng cần USB Wi-Fi Adapter thứ 2.

### Cài đặt công cụ trên VM2

```bash
sudo apt update
sudo apt -y install aircrack-ng hostapd iw wireless-tools

# Kiểm tra
aireplay-ng --help
hostapd -h
```

---

## Cấu hình IP

### Trên VM1 (Kali - Detector)

```bash
# Xem interface hiện tại
ip addr

# Nếu host-only chưa có IP, set thủ công:
sudo ip addr add 192.168.56.10/24 dev eth0
sudo ip link set eth0 up

# Hoặc chỉnh /etc/network/interfaces
sudo nano /etc/network/interfaces
```

Nội dung `/etc/network/interfaces`:
```
# NAT (internet)
auto eth0
iface eth0 inet dhcp

# Host-only (noi VM2)
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0
```

### Trên VM2 (Ubuntu - Attacker)

```bash
sudo nano /etc/network/interfaces
```

Nội dung:
```
auto eth0
iface eth0 inet dhcp

auto eth1
iface eth1 inet static
    address 192.168.56.20
    netmask 255.255.255.0
```

### Kiểm tra kết nối giữa 2 VM

```bash
# Từ VM1
ping 192.168.56.20   # Phải ping được VM2

# Từ VM2
ping 192.168.56.10   # Phải ping được VM1
```

---

## Sơ đồ mạng đầy đủ

```
Internet
    │
    │ (NAT - cài package)
    │
┌───┴──────────────────────────────────┐
│            HOST (máy thật)           │
│         192.168.56.1 (VB host-only)  │
│                                      │
│  ┌────────────────┐  ┌─────────────┐ │
│  │    VM1: Kali   │  │  VM2: Ubuntu│ │
│  │ .56.10         │◄─►  .56.20     │ │
│  │                │  │             │ │
│  │ [Python App]   │  │ [hostapd]   │ │
│  │ [Dashboard]    │  │ [aireplay]  │ │
│  │ [OpenSearch]   │  │             │ │
│  └────────┬───────┘  └─────────────┘ │
└───────────┼───────────────────────────┘
            │ USB Passthrough
            │
     [USB Wi-Fi Adapter]
            │ Monitor Mode (wlan1mon)
            │
     ════════════════
        Wi-Fi Air
     ════════════════
            │
     [Router: Lab-WiFi]      [Hotspot: Lab-WiFi ← giả]
     BSSID: AA:BB:CC:...     BSSID: XX:XX:XX:... (khác)
```

---

## Luồng test thực tế

### Test 1: Rogue AP (dùng điện thoại)
```
Điện thoại: Bật hotspot tên "Lab-WiFi"
                │
                │ Beacon Frame (SSID: Lab-WiFi, BSSID: phone_mac)
                ▼
VM1: wlan1mon bắt được
        │
        ▼
rogue_detector.check() → SSID khớp, BSSID khác → ALERT
        │
        ▼
Log file + Dashboard + Telegram
```

### Test 2: Deauth Attack (từ VM2)
```
VM2: sudo aireplay-ng --deauth 30 -a AA:BB:CC:11:22:33 wlan0
        │
        │ 30 Deauth Frames
        ▼
VM1: wlan1mon bắt được
        │
        ▼
deauth_detector.process() → 30 frames > threshold 20 → ALERT
```

### Test 3: Dashboard

```
VM1: sudo .venv/bin/python -m uvicorn webapp.app:app --host 0.0.0.0 --port 8000
                                                            │
Từ HOST browser: http://192.168.56.10:8000                  │
                                                            ▼
                                                   Dashboard hiển thị
```

---

## Checklist trước khi bắt đầu code

- [ ] VM1 boot được, kết nối internet (NAT)
- [ ] USB adapter cắm và được passthrough vào VM1
- [ ] `lsusb` trên VM1 thấy adapter
- [ ] `sudo iw list` thấy `* monitor`
- [ ] `sudo airmon-ng start wlan1` thành công → `wlan1mon` xuất hiện
- [ ] `sudo airodump-ng wlan1mon` thấy danh sách AP
- [ ] VM2 boot được
- [ ] VM1 và VM2 ping được nhau qua 192.168.56.x
- [ ] Router thật đang phát Wi-Fi, biết SSID và BSSID
