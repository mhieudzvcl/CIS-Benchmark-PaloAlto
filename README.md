# CIS Palo Alto Security Auditor (prototype/teaching project)

**Dự án:** Xây dựng hệ thống tự động đánh giá và khắc phục cấu hình bảo mật tường lửa Palo Alto dựa trên tiêu chuẩn CIS Benchmark.  
**Benchmark:** CIS Palo Alto Firewall 11 Benchmark v1.2.0 (đối chiếu các mục 1.2.3, 1.3.1–1.3.9, 1.4.1, 1.6.2, 3.1, 3.2).  
**Lab:** PAN-OS 11.2.5, PA-CIS-01 `10.0.10.11`, PA-CIS-02 `10.0.10.12`, Linux CIS Bastion `10.0.10.20` (Tailscale VPN).  
**Mức độ hoàn thành:** 14 control chọn lọc, scan multi-device, HTML & JSON, dry-run, remediation giới hạn 4 control, test fixture. **Không khẳng định bao phủ toàn bộ CIS Benchmark, không coi phiên bản này là công cụ production.**

## 1. Tại sao cần chuyển sang thư mục mới?

Project này độc lập, không sửa cấu hình `/root/cis-paloalto` hiện có. Triển khai trong `/root/cis-paloalto-v2` để bạn quay lại bản đang chạy tốt bất cứ lúc nào.

## 2. Cài đặt trên Linux Bastion bằng VS Code Remote-SSH

Sao chép file ZIP từ laptop lên Bastion bằng VS Code Explorer hoặc:

```powershell
scp "C:\Users\<TEN_WINDOWS>\Downloads\CIS-PaloAlto-Auditor.zip" root@100.91.45.26:/root/
```

Trên terminal Bastion:

```bash
cd /root
mkdir -p cis-paloalto-v2
unzip -o CIS-PaloAlto-Auditor.zip -d cis-paloalto-v2
cd /root/cis-paloalto-v2/CIS-PaloAlto-Auditor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Nếu đã có `.venv` cũ tại `/root/cis-paloalto/.venv`, cũng **không copy** nó sang. Mỗi thư mục tự tạo venv riêng.

## 3. Chạy thử OFFLINE (không cần firewall/mật khẩu)

```bash
python main.py --offline-fixture tests/fixtures/synthetic_running.xml
```

Bạn sẽ thấy giao diện Rich và 2 file `reports/<host>_<timestamp>.json/.html`. Mẫu XML là **giả lập**, tuyệt đối không dùng đầu ra này làm bằng chứng firewall thật.

## 4. Chạy audit thật: PA01 và PA02

```bash
python main.py --host 10.0.10.11 --lab-insecure
python main.py --hosts 10.0.10.11 10.0.10.12 --lab-insecure
```

Mỗi thiết bị yêu cầu mật khẩu tài khoản `cis-auditor` (nếu cùng tên). Không dùng command argument chứa mật khẩu. `--lab-insecure` chỉ sử dụng trong lab vì bỏ xác thực chứng chỉ HTTPS.

Nếu có CA bundle tin cậy:

```bash
python main.py --hosts 10.0.10.11 10.0.10.12 --ca-bundle /path/to/ca.pem
```

### Lưu ý về kết quả
- PASS = thu thập dữ liệu và có đủ căn cứ đáp ứng điều kiện.
- FAIL = thu thập dữ liệu và xác định điều kiện không đáp ứng.
- REVIEW = cần xác minh giá trị mặc định, trạng thái thực tế hoặc chính sách site.
- ERROR = lỗi code/thu thập hoặc cấu trúc XML; không được tính là không tuân thủ.
- Compliance = PASS/(PASS+FAIL), với `evaluation coverage = (PASS+FAIL)/total`. Không gọi là tỷ lệ toàn bộ Benchmark.
- Không lưu toàn bộ running config hoặc API key. JSON chứa giá trị được chọn và lý do, HTML hiển thị dữ liệu được escape.

### 1.6.2 NTP
`rules/site_policy.yaml` đặt danh sách `approved_ntp_servers:` gồm đúng nguồn NTP mà nhóm/chủ quản phê duyệt. Nếu để trống, khi có hai nguồn khác nhau sẽ trả `REVIEW` (không biết nguồn có phù hợp). Việc truy cập được NTP và đồng bộ thời gian vẫn phải kiểm chứng riêng.

### 3.1 & 3.2 HA
3.1 yêu cầu trạng thái HA operation, gồm local/peer + state sync; chỉ Running Config là chưa đủ. Nếu API không trả đúng schema hoặc không đủ chứng cứ, sẽ `REVIEW`. Kết quả này cần đối chiếu CLI:

```text
show high-availability state
show high-availability all
```

3.2 dựa trên phần `deviceconfig/high-availability/group/monitoring`, kiểm tra link/path monitoring có nhóm/target. Nếu phiên bản PAN-OS dùng schema khác, cần đối chiếu GUI và cập nhật XPath; công cụ cố tình bảo thủ.

## 5. Remediation an toàn - mặc định KHÔNG thay đổi firewall

**Chỉ** hỗ trợ whitelist:
- `1.2.3`: Disable HTTP/Telnet.
- `1.3.1`: Enable password complexity.
- `1.3.2`: Set length 12, yêu cầu complexity đã bật trước.
- `1.4.1`: Set idle timeout 10.

Ví dụ kiểm tra kế hoạch **DRY RUN** (dùng read-only account):

```bash
python main.py --host 10.0.10.11 --remediate 1.4.1 --lab-insecure
```

Chỉ khi được phép thay đổi cấu hình, biết tác động của HA và có tài khoản có quyền write+commit:

```bash
python main.py --host 10.0.10.11 --username <ADMIN_DUOC_PHEP> \
  --remediate 1.4.1 --apply --confirm-host 10.0.10.11 \
  --ack-ha --lab-insecure
```

Tool sẽ hỏi mật khẩu, trình bày thay đổi, yêu cầu nhập `APPLY 10.0.10.11 1.4.1`, so sánh Candidate và Running để tránh áp dụng khi đã có thay đổi chờ, chỉ gửi các phần tử trong allowlist, gọi `commit partial` theo tài khoản admin, đợi commit job FIN/OK, scan lại và ghi before/after HTML+JSON.

**Quan trọng:**
1. Tài khoản `cis-auditor` chỉ đọc sẽ không có quyền remediation. Cần dùng user riêng có quyền ghi, phân quyền tối thiểu.
2. Không có rollback tự động; nếu Commit fail phải kiểm tra/huỷ thay đổi candidate thủ công dưới sự giám sát của quản trị viên.
3. Không bật HTTP/Telnet để chứng minh lỗi khi đang quản trị qua mạng thật.
4. Trong HA, thay đổi Management có thể cần áp dụng trên từng firewall (nhiều cài đặt Management không sync). Dùng GUI/CLI của cả PA01 và PA02 xác minh.
5. Không chạy áp dụng 2 firewall đồng thời. Không áp dụng khi Candidate đã có thay đổi người khác.
6. `--apply` chỉ thực hiện trong phiên Terminal tương tác và yêu cầu `--ack-ha`.

## 6. Kết quả báo cáo

```
reports/
  10_0_10_11_YYYYMMDD_HHMMSS_microseconds.json
  10_0_10_11_YYYYMMDD_HHMMSS_microseconds.html
```

Mở file HTML bằng VS Code Live Preview hoặc tải về laptop qua VS Code Explorer. File này tự chứa CSS, mở trực tiếp bằng trình duyệt, không cần webserver.

## 7. Cấu trúc source

```
main.py                CLI & Rich dashboard, multi-device
src/panos_client.py    Auth / show / get / op / set / partial commit / job polling
src/cis_scanner.py     14 CIS checks, conservative evidence handling
src/remediation.py     XML-only allowlisted safe plans, Candidate guard
src/reporting.py       JSON & standalone HTML
rules/cis_controls.yaml  Definition metadata & thresholds
rules/site_policy.yaml   Approved NTP site-specific whitelist
templates/report.html     Responsive dark HTML report
docs/                 Architecture, demo runbook, manual matrix, test plan
reports/              Local results (Git-ignored)
docs/MANUAL_CHECKLIST.csv    Manual checks (not automated)
tests/                synthetic XML fixtures and pytest
```

## 8. Đề xuất thực hiện trong đêm (khoảng 3–5 giờ, tùy lab)

| Ưu tiên | Công việc | Điều kiện chốt |
|---|---|---|
| P0 | Chạy unit tests offline | Toàn bộ `pytest` PASS |
| P0 | Quét PA01, PA02 | Có báo cáo HTML/JSON thật từ cả hai IP |
| P0 | Xác minh GUI các CIS 1.2.3, 1.3.1, 1.3.2, 1.4.1 | Giá trị GUI đúng với XML |
| P0 | Test remediation 1.4.1 | DRY RUN -> APPLY -> Commit FIN/OK -> PASS |
| P1 | NTP whitelist / HA kiểm chứng | Manual review các mục chưa đủ evidence |
| P1 | Screenshot + video demo 5 phút | Đủ ảnh trước/sau và hạn chế |
| P2 | Cleanup/secrets/GitHub | Không có API keys/Running XML công khai |

## 9. Giới hạn cần đưa vào báo cáo

Công cụ đã được test tự động trên mẫu XML giả lập, **chưa thể xác thực hoạt động trên firewall thật từ môi trường tạo ZIP**. Người thực hiện phải đối chiếu trên PA-CIS-01/02. Không đồng nhất mô phỏng với kiểm thử sản phẩm thật. 14 kiểm tra là phạm vi chọn lọc so với toàn bộ CIS Benchmark. Một số điều kiện phụ thuộc giá trị mặc định/phiên bản PAN-OS hoặc trạng thái HA vận hành sẽ trả REVIEW. Không có transaction rollback phân tán HA.

## 10. Tài liệu kỹ thuật tham khảo

- CIS Palo Alto Firewall 11 Benchmark v1.2.0 — bản Benchmark hợp pháp có sẵn trong hồ sơ dự án.
- PAN-OS XML API: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions
- PAN-OS Commit: https://docs.paloaltonetworks.com/ngfw/api/pan-os-xml-api-request-types-and-actions/commit
- Palo Alto HA Sync Reference: https://docs.paloaltonetworks.com/ngfw/administration/high-availability/reference-ha-synchronization
