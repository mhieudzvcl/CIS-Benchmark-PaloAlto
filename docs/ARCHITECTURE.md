# Kiến trúc và luồng thực thi

## Thành phần

```mermaid
flowchart LR
    DEV[VS Code laptop] -->|SSH over Tailscale| BASTION[Linux CIS Bastion 10.0.10.20]
    BASTION -->|PAN-OS XML API TCP 443| PA1[PA-CIS-01 10.0.10.11]
    BASTION -->|PAN-OS XML API TCP 443| PA2[PA-CIS-02 10.0.10.12]
    BASTION --> ENGINE[Rule Engine: YAML + Python]
    ENGINE --> OUT[Results PASS / FAIL / REVIEW / ERROR]
    OUT --> REPORT[JSON + HTML Report]
    ENGINE -. only after confirmation .-> FIX[Allowlist remediation + Partial Commit]
    FIX -. separate admin .-> PA1
    FIX -. separate admin .-> PA2
```

## Read-only Audit Sequence

```mermaid
sequenceDiagram
    participant CLI as Operator
    participant Scanner as Python Scanner
    participant FW as PAN-OS Firewall
    participant Report as Report
    CLI->>Scanner: --host/--hosts and password prompt
    Scanner->>FW: type=keygen
    FW-->>Scanner: X-PAN-KEY (RAM only)
    Scanner->>FW: config action=show xpath=/config
    FW-->>Scanner: Running XML
    Scanner->>FW: op show high-availability state
    FW-->>Scanner: Operational HA state (if authorized)
    Scanner->>Scanner: Evaluate YAML control definitions
    Scanner->>Report: JSON + HTML, timestamps
    Report-->>CLI: PASS/FAIL/REVIEW/ERROR + score + coverage
```

## Controlled Remediation Sequence

```mermaid
sequenceDiagram
    participant Operator
    participant Tool as Python Remediation
    participant FW as Palo Alto XML API
    Operator->>Tool: --remediate CIS_ID
    Tool-->>Operator: Preview + dry-run (NO write)
    Operator->>Tool: --apply + host guard + ack HA
    Tool-->>Operator: Exact phrase confirmation
    Operator->>Tool: APPLY HOST CIS_ID
    Tool->>FW: config action=get (Candidate)
    FW-->>Tool: Candidate XML
    Tool->>Tool: Compare Candidate vs Running; reject pending changes
    Tool->>FW: config action=set (allowlist only)
    Tool->>FW: commit action=partial (by write admin)
    FW-->>Tool: Commit Job ID
    loop Until FIN/OK or timeout
        Tool->>FW: op show jobs id
    end
    Tool->>FW: config action=show (post-commit)
    Tool->>Tool: Re-evaluate CIS_ID
    Tool-->>Operator: before/after HTML+JSON, verify HA peer separately
```

### Tính năng và giới hạn
- Ưu tiên không thay đổi firewall trong chế độ audit; remediation default dry-run.
- Nội dung `--lab-insecure` chỉ thích hợp với lab cách ly sử dụng certificate tự ký.
- Candidate diff guard + Partial Commit riêng theo user giảm rủi ro commit nhầm nhưng không thay thế quy trình change management.
- Không tự rollback; nếu commit failed/timeout phải kiểm tra thủ công candidate và job. Không sửa HA tự động.
- Quét PA-CIS-01/02 độc lập, không suy ra PASS trên peer từ một firewall.
