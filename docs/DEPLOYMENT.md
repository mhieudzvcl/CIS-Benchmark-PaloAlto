# Triển khai, vận hành và kiểm thử — CIS Palo Alto Security Auditor

> Tài liệu này dành cho người triển khai và chạy demo. Phần mô tả đề tài, kiến trúc, phạm vi và kết quả nằm tại [README.md](../README.md).

## 1. Yêu cầu

- Linux Bastion có Python 3.10+, kết nối HTTPS tới Management Interface của từng firewall.
- Tài khoản API có quyền **đọc** cho Audit; tài khoản riêng có quyền **ghi và Commit** chỉ dùng cho Remediation được phê duyệt.
- Kiểm thử trước trong lab; sao lưu cấu hình thiết bị và kiểm tra Candidate Configuration trước khi áp dụng thay đổi.
- Không lưu mật khẩu hoặc API key vào source code, command-line argument hay Git repository.

## 2. Cài đặt tại thư mục project

```bash
cd /root/cis-paloalto-group6/CIS-PaloAlto-Auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

**Lưu ý:** Đường dẫn trên là đường dẫn triển khai thực tế trong lab và có thể thay đổi ở hệ thống khác.

## 3. Kiểm thử offline

```bash
python main.py --offline-fixture tests/fixtures/synthetic_running.xml
```

Fixture là dữ liệu giả lập, không được sử dụng làm bằng chứng Audit thực tế.

## 4. Chạy Audit đọc cấu hình

```bash
python main.py --host 10.0.10.11 --lab-insecure
python main.py --hosts 10.0.10.11 10.0.10.12 --lab-insecure
```

`--lab-insecure` bỏ kiểm tra chứng chỉ TLS, **chỉ dùng trong lab cô lập**. Nếu có CA tin cậy:

```bash
python main.py --hosts 10.0.10.11 10.0.10.12 --ca-bundle /path/to/ca.pem
```

Mật khẩu được hỏi tương tác. Báo cáo HTML/JSON được tạo trong `reports/` với timestamp.

## 5. Quy ước đánh giá

| Trạng thái | Ý nghĩa |
|---|---|
| PASS | Thu thập và xác minh đủ căn cứ đáp ứng khuyến nghị |
| FAIL | Thu thập đủ căn cứ, xác định cấu hình không đáp ứng |
| REVIEW | Cần bổ sung chứng cứ, xác minh giá trị mặc định hoặc site policy |
| ERROR | Lỗi thu thập/API/đánh giá, không tương đương FAIL |

`Compliance = PASS / (PASS + FAIL)`; `Coverage = (PASS + FAIL) / Total`.

### NTP (CIS 1.6.2)

Cập nhật `rules/site_policy.yaml` với các NTP server được tổ chức chấp thuận. Trường hợp có hai nguồn nhưng không rõ nguồn được phê duyệt cần `REVIEW`. Trạng thái đồng bộ NTP cần được kiểm chứng riêng.

### HA (CIS 3.1, 3.2)

Đối chiếu API với CLI và GUI:

```text
show high-availability state
show high-availability all
```

Thiếu trạng thái peer, đồng bộ HA hoặc thiếu Link/Path Monitoring phải được xử lý dựa trên cấu hình và trạng thái thực tế. Không tự sửa HA bằng các lệnh remediation của ứng dụng.

## 6. Remediation — xem trước trước khi áp dụng

Chỉ hỗ trợ allowlist `1.2.3`, `1.3.1`, `1.3.2`, `1.4.1`. Không tự động sửa NTP/HA.

**Dry-run (không ghi cấu hình):**

```bash
python main.py --host 10.0.10.11 --remediate 1.3.2 --lab-insecure
```

Nếu control đã PASS, chương trình từ chối remediation do không có gì cần thay đổi.

**Apply chỉ khi đã sao lưu, xác nhận quyền thay đổi và không có Candidate Configuration đang chờ:**

```bash
python main.py --host 10.0.10.11 --username <AUTHORIZED_ADMIN> \
  --remediate 1.3.2 --apply --confirm-host 10.0.10.11 \
  --ack-ha --lab-insecure
```

Xem kế hoạch trước khi xác nhận. Lệnh yêu cầu người vận hành nhập chuỗi xác nhận trực tiếp. Commit xong cần kiểm tra trạng thái job và quét lại.

**Không có rollback tự động.** Khi Commit thất bại phải dừng và kiểm tra trạng thái cấu hình, không chạy lặp lại `--apply`. Không áp dụng đồng thời hai firewall.

## 7. Lưu bằng chứng và báo cáo

- Ảnh/JSON/HTML before-audit → `evidence/before/` (lưu nội bộ).
- Screenshot kế hoạch dry-run → `evidence/remediation/`.
- Commit Job và re-audit → `evidence/after/`.
- So sánh kết quả `PASS`, `FAIL`, `REVIEW` với GUI/CLI; tuyệt đối không giả lập PASS để làm bằng chứng thực nghiệm.

`reports/`, `evidence/`, `.env`, `.venv` và running configuration chứa thông tin nhạy cảm phải được loại khỏi Git.

## 8. Kiểm thử và demo

- Offline: `python -m pytest -q` và kiểm thử XML fixture.
- Thực tế: quét từng firewall rồi quét nhiều firewall; đối chiếu GUI và API.
- Remediation: xác minh FAIL → dry-run → apply có xác nhận → Commit → re-audit PASS.
- HA: xác minh Active/Passive và đồng bộ trên CLI/API trước khi công bố control HA PASS.

Xem thêm [kịch bản demo](DEMO_KICH_BAN.md), [kiến trúc](ARCHITECTURE.md), [test plan](TEST_PLAN.csv) và [manual checklist](MANUAL_CHECKLIST.csv).
