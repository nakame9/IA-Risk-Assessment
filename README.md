# IA Risk Assessment

Đây là bài đánh giá rủi ro Information Assurance cho một **cổng hồ sơ sinh viên hư cấu**, làm theo NIST SP 800-30 Rev.1. Bài đánh giá tập trung vào ba việc:

- phân tích mức độ nguy hiểm của mối đe dọa,
- đánh giá tác động đến tài sản thông tin,
- ra quyết định xử lý rủi ro.

**Tài liệu:**

- [PLAN.md](PLAN.md): kế hoạch, phương pháp, các bảng tra G-5/I-2 và kết quả kiểm chứng nguồn.
- [report.md](report.md): **báo cáo nghiên cứu v2.1**, gồm bài toán và RQ, phương pháp, giao thức đánh giá, kết quả, thảo luận và kết luận "việc gì làm trước". Báo cáo v1 nằm ở Phụ lục A (tag `v1`).
- [SPEC.md](SPEC.md): đặc tả đánh giá v2.1, tức bước Prepare. Gồm ánh xạ Task 1-1 → 1-5 của NIST, bộ quy tắc có mã, chính sách KEV, quy trình thu thập bằng chứng và data contract.

**Tiến độ v2.1** (theo [PLAN.md](PLAN.md) §9.10.5): đã xong bước 1 (Prepare), bước 2 (quy tắc và schema, chuyển 13 kịch bản) bước 3 (kiểm tra khớp CVE và import snapshot) bước 4 (báo cáo hành động [out/action_report.md](out/action_report.md)) bước 5 (so sánh giữa hai lần chạy, ví dụ ở [examples/cycle2/](examples/cycle2/)) và bước 6 (thực nghiệm [out/experiments.md](out/experiments.md)). Đã có snapshot KEV thật: phiên bản 2026.11.20, lấy ngày 2026-11-22, giấy phép CC0, nằm ở `data/snapshots/`. Chưa có snapshot EPSS. Có 3 finding CVE minh họa, là giả định [GĐ] nhưng dùng mã CVE thật. Bước 7 (viết lại báo cáo theo khung nghiên cứu) đã xong, nên **cả 7 bước của v2.1 đã hoàn thành**.

**Dữ liệu v2.1** (`data/`):

| Ai sửa | File |
|---|---|
| Người vận hành | `assets.csv`, `inputs.csv` (bằng chứng và phán đoán, mỗi dòng có nguồn), `controls.csv` |
| Người phụ trách mô hình | `templates.csv`, `packages.csv`, `effects.csv` |
| Cả hai | `risk_register.csv` (kịch bản và quyết định) |

Định dạng chi tiết của từng file nằm ở [SPEC.md](SPEC.md) §6.

**Tiến độ:**

| Giai đoạn | Trạng thái |
|---|---|
| 1. Frame | Xong |
| 2. Identify | Xong ([data/assets.csv](data/assets.csv), [data/risk_register.csv](data/risk_register.csv)) |
| 3. Assess | Xong: 1 rủi ro High, 8 Moderate, 4 Low ([report.md §3](report.md)) |
| 4. Treat | Xong: residual dự kiến 0 High, 3 Moderate, 10 Low ([report.md §4](report.md)) |
| 5. Package & review | Xong: `risk.py`, self-check, [out/](out/), phân tích độ nhạy, kết luận ([report.md §5](report.md)) |

**Cách chạy** (cần Python 3, chỉ dùng thư viện chuẩn):

```
python risk.py           # kiểm tra data/, sinh out/action_report.md (báo cáo hành động), register.md, matrix.md, trace.md
python risk.py --check   # self-check: bảng G-5/I-2, ranh giới quy tắc, kiểm tra hợp lệ, khớp CVE, snapshot, kết quả case portal
python risk.py import kev known_exploited_vulnerabilities.json --url <nguồn>   # lưu file feed đã tải về làm snapshot
python risk.py --as-of 2026-11-22   # chạy với ngày đánh giá cố định, để kết quả tái lập được
python risk.py --data examples/cycle2 --as-of 2026-12-05 --baseline out/state.json --out examples/cycle2/out
                                    # chu kỳ cập nhật (mô phỏng): báo cáo mục 2 liệt kê thay đổi và nguyên nhân
python synth.py                     # sinh 200 tài sản tổng hợp (seed cố định), chạy thực nghiệm E1–E6, ghi out/experiments.md
```

`data/*.csv` là dữ liệu nguồn. `out/*.md` do script sinh ra, không sửa tay.

Mọi dữ liệu trong repo đều hư cấu và chỉ dùng cho mục đích học tập.
