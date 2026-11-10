# Hướng dẫn dựng môi trường lab — macOS Apple Silicon (M1/M2/M3)

> **Target app đã chọn**: InsecureBankv2  
> **Emulator**: Android Studio AVD (ARM64 — native trên Apple Silicon)  
> **Ngày tạo**: 2026-06-26

---

## Tổng quan kiến trúc

```
macOS Apple Silicon Host
├── Docker Desktop
│   ├── MobSF          (port 8000)
│   └── OWASP ZAP      (port 8090)
├── Burp Suite Community (port 8080) — native app
├── Android Studio AVD  — ARM64 Android 13 (API 33)
│   ├── InsecureBankv2.apk
│   └── frida-server (push qua adb)
└── InsecureBankv2 Backend — Python Flask (port 8888)
```

> ⚠️ **Lưu ý Apple Silicon**: KHÔNG dùng Genymotion (chỉ hỗ trợ x86, không chạy native trên M-chip).  
> Android Studio AVD với image ARM64 chạy native qua Hypervisor.framework — nhanh và ổn định.

---

## Bước 1: Cài Docker Desktop

```bash
# Tải Docker Desktop cho Apple Silicon tại:
# https://docs.docker.com/desktop/install/mac-install/
# Chọn "Mac with Apple silicon"

# Sau khi cài, verify:
docker --version
docker run hello-world
```

---

## Bước 2: Cài Android Studio + tạo AVD

### 2.1 Cài Android Studio
```
Tải tại: https://developer.android.com/studio
Chọn bản "Mac with Apple chip" (.dmg)
```

### 2.2 Tạo AVD (Android Virtual Device)
```
Android Studio → More Actions → Virtual Device Manager → Create Device

Cấu hình khuyến nghị:
- Device: Pixel 6 (hoặc Pixel 4)
- System Image: API 33 (Android 13)  ← QUAN TRỌNG: chọn tab "Arm Images"
- ABI: arm64-v8a  ← bắt buộc để chạy native trên M-chip
- RAM: 2048 MB
- Storage: 2 GB

Sau khi tạo, bật AVD và verify:
$ adb devices
List of devices attached
emulator-5554   device
```

### 2.3 Bật proxy setting trên AVD
```
Vào AVD → Settings → WiFi → Long press "AndroidWifi" → Modify Network
→ Advanced options → Proxy: Manual
→ Proxy hostname: 10.0.2.2   (IP của host từ emulator)
→ Proxy port: 8080            (Burp Suite)
```

---

## Bước 3: Deploy InsecureBankv2

### 3.1 Clone và cài backend
```bash
git clone https://github.com/dineshshetty/Android-InsecureBankv2.git
cd Android-InsecureBankv2/AndroLabServer

# Cài dependencies
pip3 install -r requirements.txt

# Chạy backend server
python3 app.py
# Server chạy tại http://0.0.0.0:8888
```

### 3.2 Cài APK lên AVD
```bash
# Từ thư mục gốc Android-InsecureBankv2
adb install InsecureBankv2.apk

# Nếu không có APK pre-built, build bằng Android Studio:
# Mở thư mục InsecureBankv2/ trong Android Studio → Build APK
```

### 3.3 Cấu hình app kết nối tới backend
```
Mở InsecureBankv2 trên AVD
→ Settings (biểu tượng cài đặt góc trên phải)
→ Server Preferences:
   - Server IP: 10.0.2.2    ← IP host từ emulator
   - Server Port: 8888
→ Save
```

### 3.4 Verify
```
Login với:
- Username: jack
- Password: Jack@123!@#
→ Nếu login thành công = lab hoạt động
```

---

## Bước 4: Cài MobSF

```bash
# Pull image (multi-arch, hỗ trợ ARM64)
docker pull opensecurity/mobile-security-framework-mobsf:latest

# Chạy MobSF
docker run -it --rm \
  -p 8000:8000 \
  -v "$(pwd)/mobsf-data:/home/mobsf/.MobSF" \
  opensecurity/mobile-security-framework-mobsf:latest

# Truy cập: http://localhost:8000
# Default login: mobsf / mobsf
```

### Test MobSF với InsecureBankv2
```
1. Vào http://localhost:8000
2. Upload InsecureBankv2.apk
3. Đợi Static Analysis hoàn tất (~2–5 phút)
4. Xem báo cáo → lưu kết quả vào 03_benchmark/ket-qua-test/mobsf/
```

---

## Bước 5: Cài Burp Suite Community

```bash
# Tải tại: https://portswigger.net/burp/communitydownload
# Chọn bản macOS (ARM64 nếu có, hoặc x86 qua Rosetta)

# Sau khi cài, cấu hình listener:
# Proxy → Proxy settings → Add
# Bind to port: 8080
# Bind to address: All interfaces
```

### Cài Burp CA Certificate vào AVD
```bash
# 1. Mở http://burp trên browser của AVD (qua proxy đã cấu hình)
#    Hoặc download từ: http://10.0.2.2:8080/cert  (từ trình duyệt AVD)
# 2. Download burp.der
# 3. Rename thành burp.cer
# 4. Push vào AVD:
adb push burp.cer /sdcard/

# 5. Trên AVD: Settings → Security → Install from storage → burp.cer
# 6. Name: BurpSuite, Credential use: VPN and apps

# Với Android 7+ (API 24+): cần thêm network_security_config
# Xem phần 5.1 bên dưới
```

### 5.1 Bypass Network Security Config (Android 7+)
InsecureBankv2 đã có `network_security_config.xml` cho phép cleartext, nhưng để trust user-added CA:
```bash
# Decompile APK
apktool d InsecureBankv2.apk -o insecurebank_decompiled

# Edit res/xml/network_security_config.xml
# Thêm:
# <trust-anchors>
#   <certificates src="system"/>
#   <certificates src="user"/>
# </trust-anchors>

# Rebuild và sign
apktool b insecurebank_decompiled -o InsecureBankv2_patched.apk
# Sign APK (cần keytool và apksigner)
```

> **Lưu ý**: InsecureBankv2 có thể không cần bước này vì intentionally insecure. Test thử trước.

---

## Bước 6: Cài OWASP ZAP

```bash
docker pull ghcr.io/zaproxy/zaproxy:stable

# Chạy ZAP ở daemon mode
docker run -u zap \
  -p 8090:8080 \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon \
  -host 0.0.0.0 \
  -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true \
  -config api.key=your-zap-api-key

# Web UI (ZAP Desktop mode — khuyến nghị để làm quen):
# Tải bản Desktop tại: https://www.zaproxy.org/download/
```

---

## Bước 7: Cài Frida + objection

```bash
# Cài frida-tools
pip3 install frida-tools objection

# Verify
frida --version
objection --version

# Download frida-server cho Android ARM64
# Vào: https://github.com/frida/frida/releases
# Tìm: frida-server-<version>-android-arm64.xz

# Giải nén và push vào AVD
xz -d frida-server-*.xz
adb push frida-server /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
```

### Chạy frida-server
```bash
# Terminal 1: chạy server trên AVD
adb shell /data/local/tmp/frida-server &

# Terminal 2: verify kết nối
frida-ps -U   # list processes trên thiết bị

# Bypass SSL pinning với objection (nếu app có pinning)
objection -g com.android.insecurebank explore
> android sslpinning disable
```

---

## Bước 8: Cài JADX + apktool

```bash
# apktool
brew install apktool

# JADX
brew install jadx
# Hoặc tải JADX GUI từ: https://github.com/skylot/jadx/releases

# Verify
apktool --version
jadx --version
```

---

## Checklist xác nhận lab hoạt động

```
□ Docker Desktop chạy OK
□ Android Studio AVD (ARM64 Android 13) khởi động được
□ InsecureBankv2 backend chạy tại http://localhost:8888
□ InsecureBankv2 APK cài trên AVD, login được
□ MobSF tại http://localhost:8000, upload APK được
□ Burp Suite intercept được HTTP traffic từ AVD
□ OWASP ZAP chạy được
□ frida-ps -U list được processes trên AVD
□ jadx và apktool chạy được từ terminal
```

---

## Cấu trúc lưu kết quả benchmark

```
03_benchmark/ket-qua-test/
├── mobsf/
│   ├── static_analysis_report.json   ← export từ MobSF
│   └── dynamic_analysis_report.json
├── burp/
│   ├── captured_requests.xml
│   └── scan_results.html
├── owasp-zap/
│   ├── zap_report.html
│   └── zap_report.json
├── frida/
│   └── ssl_bypass_log.txt
└── jadx-apktool/
    └── static_findings.md
```

---

## Tài liệu tham khảo

- InsecureBankv2: https://github.com/dineshshetty/Android-InsecureBankv2
- MobSF Docs: https://mobsf.github.io/Mobile-Security-Framework-MobSF/
- Burp Suite Docs: https://portswigger.net/burp/documentation
- Frida Docs: https://frida.re/docs/
- OWASP ZAP Docs: https://www.zaproxy.org/docs/
