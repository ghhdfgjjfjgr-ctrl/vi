# Vulnerability Scanner Web App (Demo)

เว็บแอปสแกนช่องโหว่แนวทางโครงงาน (Thai-first dashboard) รองรับ workflow:
- Nmap (Host Discovery / Port & Service / NSE vulners)
- OWASP ZAP (Passive / Spider + Active)
- Arachni (XSS / SQLi checks)
- เก็บผลสแกนใน SQLite + Export JSON และ PDF
- รองรับเป้าหมายแบบ IP, CIDR, Domain, URL (รวมแบบไม่ใส่ scheme เช่น example.com/login)

> ใช้เพื่อการทดสอบความปลอดภัยกับระบบที่ได้รับอนุญาตเท่านั้น

---

## Quick Run (Local)

```bash
python3 app.py
```

เปิด `http://localhost:5000`

> ถ้าเครื่อง local ไม่มี ReportLab/ฟอนต์ไทย ระบบยังสแกนได้ แต่ PDF จะ unavailable

---

## Deploy บน Kali Linux (Raspberry Pi) ด้วย GitHub repo + install script

### 1) เตรียมเครื่อง
- ใช้ Kali Linux บน Raspberry Pi
- เชื่อมต่อเน็ต
- มีสิทธิ์ `sudo`

### 2) รัน install script

```bash
git clone https://github.com/<your-user>/<your-repo>.git
cd <your-repo>
sudo bash scripts/install-kali-rpi.sh https://github.com/<your-user>/<your-repo>.git main
```

สคริปต์จะทำให้อัตโนมัติ:
- ติดตั้งแพ็กเกจที่จำเป็น (`python3`, `venv`, `sqlite3`, `nmap`)
- ติดตั้งแพ็กเกจสร้าง PDF ไทย (`python3-reportlab`, `fonts-thai-tlwg`)
- clone/pull โค้ดไปที่ `/opt/vi-scanner`
- สร้าง virtualenv
- สร้างไฟล์ `.env`
- ติดตั้งและเปิดใช้งาน systemd service: `vi-scanner.service`

### 3) ตรวจสอบสถานะ

```bash
sudo systemctl status vi-scanner.service
```

### 4) เปิดใช้งานจากเครื่องอื่นในวงแลน

```bash
hostname -I
```

จากนั้นเปิด:
- `http://<IP-RaspberryPi>:5000`

### 5) อัปเดตเวอร์ชันจาก GitHub

```bash
sudo bash /opt/vi-scanner/scripts/update-kali-rpi.sh main
```

---

## API Reports
- `GET /api/report/<scan_id>.json` ดาวน์โหลดรายงาน JSON
- `GET /api/report/<scan_id>.pdf` ดาวน์โหลดรายงาน PDF (มีสารบัญ, scan info, host, port/service, findings, risk summary, observations, recommendations)

---

## Environment variables
ค่าเริ่มต้นจะถูกเขียนใน `/opt/vi-scanner/.env`

- `SCANNER_HOST` (default `0.0.0.0`)
- `SCANNER_PORT` (default `5000`)
- `SCANNER_DB_PATH` (default `/opt/vi-scanner/scanner.db`)
- `SCANNER_REPORTS_DIR` (default `/opt/vi-scanner/reports`)


## Health Check

```bash
curl -s http://127.0.0.1:5000/api/health
```

ตัวอย่างผลลัพธ์:
- `status`: ok
- `reportlab`: true/false
- `pdf_font`: ชื่อฟอนต์ที่ระบบเลือกใช้


## แก้ปัญหา Merge Conflict บน GitHub

ถ้าในหน้า Resolve conflicts ขึ้นไฟล์ `app.py`, `templates/index.html`, `README.md` ให้ใช้แนวทางนี้:

- `app.py` ให้เก็บฝั่งที่มี `import socket` และฟังก์ชันสแกนจริง (`_extract_hosts`, `_scan_port`, `simulate_scan(..., target_kind)`)
- `templates/index.html` ให้เก็บบรรทัด input ที่รองรับ `Target IP / Domain / URL`
- `README.md` ให้เก็บบรรทัดที่ระบุว่า รองรับ `IP, CIDR, Domain, URL (รวมแบบไม่ใส่ scheme)`

แนะนำเลือก **Accept both changes** แล้วลบ marker `<<<<<<<`, `=======`, `>>>>>>>` ออกให้หมดก่อน commit.
