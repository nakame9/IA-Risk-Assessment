# IA Risk Assessment

Đây là bài đánh giá rủi ro Information Assurance cho một **cổng hồ sơ sinh viên hư cấu**, làm theo NIST SP 800-30 Rev.1. Bài đánh giá tập trung vào ba việc:

- phân tích mức độ nguy hiểm của mối đe dọa,
- đánh giá tác động đến tài sản thông tin,
- ra quyết định xử lý rủi ro.

**Tài liệu:**

- [PLAN.md](PLAN.md): kế hoạch, phương pháp, các bảng tra G-5/I-2 và kết quả kiểm chứng nguồn.
- [report.md](report.md): báo cáo đánh giá.

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
python risk.py           # tính lại mức rủi ro, sinh out/register.md và out/matrix.md
python risk.py --check   # self-check: đối chiếu bảng G-5/I-2 với PLAN.md, ví dụ tính tay, nhãn không hợp lệ
```

`data/*.csv` là dữ liệu nguồn. `out/*.md` do script sinh ra, không sửa tay.

Mọi dữ liệu trong repo đều hư cấu và chỉ dùng cho mục đích học tập.
