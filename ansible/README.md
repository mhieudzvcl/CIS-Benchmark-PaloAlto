# Module Tích Hợp Ansible - Quản Trị Đa Thiết Bị (Multi-Device Management)

## 1. Giới thiệu tổng quan

Thư mục `ansible/` cung cấp khả năng mở rộng quy mô quản trị cho toàn bộ hệ thống đánh giá và khắc phục cấu hình bảo mật tường lửa Palo Alto Networks theo chuẩn **CIS Benchmark v1.2.0**.

Module này giải quyết bài toán:
* **Tự động hóa trên nhiều thiết bị cùng lúc (Multi-Node Concurrency):** Quản trị đồng thời cả hai node tường lửa `PA-CIS-01` (`10.0.10.11`) và `PA-CIS-02` (`10.0.10.12`) trong cụm High Availability.
* **Mô hình kiến trúc Hybrid:**
  * **Python Core:** Đảm nhận vai trò Kiểm toán chuyên sâu (Deep Audit), phân tích cú pháp XPath XML 30 controls và sinh báo cáo trực quan HTML/JSON.
  * **Ansible Orchestrator:** Đảm nhận vai trò Điều phối hàng loạt (Fleet Orchestration), quản lý danh mục thiết bị (Inventory) và khắc phục đồng loạt (Mass Remediation).

---

## 2. Cấu trúc thư mục

```text
ansible/
├── ansible.cfg                    # Cấu hình tối ưu (tắt host key checking, forks = 5)
├── inventory.yaml                 # Khai báo danh mục tường lửa PA-CIS-01 và PA-CIS-02
├── requirements.yaml              # Khai báo các collection phụ trợ
├── playbooks/
│   ├── 01_fleet_hardening.yaml    # Khắc phục đồng loạt baseline CIS an toàn qua PAN-OS XML API
│   ├── 02_fleet_audit.yaml        # Điều phối kịch bản Python quét đánh giá toàn bộ cụm tường lửa
│   └── 03_verify_connectivity.yaml# Kiểm tra kết nối mạng và xác thực API Key trên tất cả các node
└── README.md                      # Hướng dẫn chi tiết
```

---

## 3. Hướng dẫn cài đặt trên máy VM-LINUX-BASTION

Trên máy chủ quản trị `VM-LINUX-BASTION` (`10.0.10.20`), mở terminal và thực hiện:

### Bước 1: Kích hoạt môi trường ảo Python
```bash
cd ~/CIS-Benchmark-PaloAlto
source .venv/bin/activate
```

### Bước 2: Cài đặt Ansible
```bash
pip install ansible
```

### Bước 3: Di chuyển vào thư mục ansible
```bash
cd ansible
```

---

## 4. Các lệnh thực thi Playbook

### Kiểm tra kết nối tới tất cả tường lửa (Playbook 03)
Lệnh này kiểm tra thông mạng port 443, tạo API Key và lấy thông tin phiên bản PAN-OS của từng thiết bị:
```bash
ansible-playbook playbooks/03_verify_connectivity.yaml
```

### Khắc phục cấu hình hàng loạt cho toàn bộ cụm Firewall (Playbook 01)
Lệnh này tự động đẩy đồng thời các cấu hình CIS baseline an toàn (Banner 1.1.2, High DP Load 1.1.3, Disable HTTP/Telnet 1.2.3, Password Complexity 1.3.1, Password Length 1.3.2, Idle Timeout 1.4.1, Lockout 1.4.2 và 1.4.3) xuống cả hai firewall song song:
```bash
ansible-playbook playbooks/01_fleet_hardening.yaml
```

### Quét kiểm toán toàn bộ hệ thống bằng Python Engine (Playbook 02)
Lệnh này điều phối script Python `main.py` chạy qua tất cả các IP trong `inventory.yaml` và xuất báo cáo nghiệm thu:
```bash
ansible-playbook playbooks/02_fleet_audit.yaml
```

---

## 5. Giá trị học thuật đối với môn học NT542

* Chứng minh sự kết hợp hoàn hảo giữa lập trình kịch bản Python nâng cao và công cụ quản trị cấu hình tiêu chuẩn công nghiệp Ansible.
* Đáp ứng trọn vẹn yêu cầu quản trị hạ tầng mạng quy mô lớn (Enterprise Scale), sẵn sàng mở rộng từ 2 thiết bị lab lên hàng trăm thiết bị trong thực tế chỉ bằng việc khai báo thêm IP vào tệp `inventory.yaml`.

