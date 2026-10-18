# Kịch bản demo cuối kỳ – CIS Palo Alto Firewall 11 v1.2.0

## Phần 1 — Giới thiệu (2 phút)
- Nêu lý do: cấu hình quản trị sai dẫn tới lộ mật khẩu, không đồng bộ HA, đồng hồ sai.
- Phạm vi: PAN-OS 11.2.5, PA-CIS-01/02, Linux Bastion, PAN-OS XML API.
- Benchmark gốc v1.2.0, **triển khai 14 control chọn lọc**, không toàn bộ benchmark.

## Phần 2 — Audit tự động (4 phút)
1. Từ VS Code SSH đến 100.91.45.26, mở project.
2. Chạy `python main.py --hosts 10.0.10.11 10.0.10.12 --lab-insecure`.
3. Diễn giải mỗi trạng thái PASS, FAIL, REVIEW, ERROR; nhấn mạnh REVIEW do dữ liệu không đầy đủ.
4. Mở báo cáo HTML, xem summary & evidence paths; lưu ảnh screenshot.

## Phần 3 — Remediation (5 phút)
1. Chọn cấu hình **an toàn để demo**: CIS 1.4.1 Idle Timeout 20 phút (lab-only, có sự đồng ý).
2. Audit, lưu JSON+HTML trạng thái FAIL.
3. Chạy `python main.py --host 10.0.10.11 --username <write-account> --remediate 1.4.1 --lab-insecure` để xem dry-run.
4. Chỉ khi đã có backup và không có thay đổi Candidate đang chờ, chạy `--apply --confirm-host 10.0.10.11 --ack-ha`, nhập chính xác chuỗi xác nhận.
5. Hệ thống kiểm tra Candidate trống (theo so sánh với Running), gọi API set, Partial Commit theo tài khoản, chờ Job FIN/OK và scan lại.
6. Đối chiếu GUI/CLI, kiểm tra PA-CIS-02, ghi hình. Nếu lỗi Commit phải xử lý thủ công; tool KHÔNG tự rollback.

## Phần 4 — Test và đánh giá (3 phút)
- `python -m pytest -q`: bộ synthetic fixture 12 tests (số chính xác theo pytest output).
- So sánh trước/sau và giới hạn công cụ (API, default values, HA/peer operational, NTP approval).
- Đối với HA 3.1, bắt buộc đối chiếu trạng thái thực tế ở cả hai phía: `show high-availability state`.

## Checklist evidence cần chuẩn bị
- [ ] Topology CMC Cloud (VPC, các subnet, HA1/HA2, Bastion)
- [ ] API Success trên cả PA01/PA02
- [ ] CIS 1.4.1 FAIL (CLI/GUI và report)
- [ ] Remediation DRY RUN (không thay đổi firewall)
- [ ] Explicit APPLY, commit job FIN/OK, sau đó PASS
- [ ] Snapshot báo cáo JSON+HTML trước/sau
- [ ] CIS 1.3.1/1.3.2 GUI password complexity
- [ ] CIS 1.2.3 GUI management services
- [ ] CIS 1.6.2 NTP (approved list / verify reachability)
- [ ] CIS 3.1/3.2 HA CLI/GUI
- [ ] Test synthetic 12 passed
- [ ] Ghi rõ hạn chế: 14 control chọn lọc, không chạy toàn bộ Benchmark

## Cảnh báo bảo mật
Không đưa API key, mật khẩu, phash, Running Configuration gốc lên GitHub hay trong báo cáo. HTTPS verify=False chỉ dùng lab; môi trường thật dùng CA bundle.
