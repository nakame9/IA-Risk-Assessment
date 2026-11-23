# Hướng dẫn cho người IT: đánh giá rủi ro cho doanh nghiệp vừa và nhỏ

> **Phạm vi bản P2a:** 3 dịch vụ.
> 1. Email và tài khoản SaaS.
> 2. Thanh toán cho nhà cung cấp.
> 3. Khôi phục dữ liệu.
>
> **Đây là đánh giá có hỗ trợ, không phải chứng nhận tuân thủ.**

## 1. Chuẩn bị (một lần)

1. **Cài Python:** cài Python 3.11 trở lên từ https://www.python.org/downloads/, và chọn **"Add python.exe to PATH"** khi cài.
2. **Tải công cụ:** tải repo này về máy, ví dụ vào `D:\cong-cu-rui-ro`. Công cụ không cần cài thư viện nào thêm.
3. **Tạo một workspace riêng cho mỗi công ty:**
   - Workspace phải nằm **ngoài** thư mục repo, ở nơi có phân quyền truy cập và được backup.
   - Lệnh tạo:

     ```
     run.bat init "D:\Khach hang\Cong ty A" --company "Công ty A"
     ```

   - Lệnh này tạo `answers.csv` (bảng câu hỏi), `library\` (bản thư viện được ghim, có phiên bản) và `evidence\` (nơi lưu bằng chứng).

## 2. Phỏng vấn và điền `answers.csv`

**Cách mở và lưu file:**
- Mở `answers.csv` bằng Excel.
- Khi lưu, chọn **"CSV UTF-8 (Comma delimited)"**.
- Công cụ đọc được cả file dùng dấu phẩy và file dùng dấu chấm phẩy.

**Ý nghĩa các cột:**

| Cột | Điền gì |
|---|---|
| `answer` | Mã lựa chọn ở cột `options`, ví dụ `all`, `some`, `unknown`. Với câu hỏi `text`, ghi tên người. **Để trống nghĩa là chưa biết** |
| `source` | `observed`: đã tự xem cấu hình hoặc tài liệu. `attested`: người được hỏi khẳng định. `forecast`: ước tính. `unknown`: chưa biết |
| `evidence_ref` | **Bắt buộc khi `source = observed`.** Ghi đã xem gì, ví dụ `evidence\mfa-report-2026-11-20.png` |
| `answered_by`, `answered_on` | Ai trả lời, và ngày theo dạng `YYYY-MM-DD` |

**Ai trả lời câu nào:**
- **Câu hỏi kỹ thuật** (MFA, sao lưu, thử khôi phục): người IT trả lời, và **tự kiểm tra** trong trang quản trị nếu có thể.
- **Câu hỏi về hậu quả và ngưỡng chịu đựng** (EML-07, PAY-04, REC-05, REC-07): **giám đốc** trả lời.

**Lưu ý về bằng chứng:**
- Không lưu mật khẩu hay dữ liệu khách hàng trong workspace.
- Bằng chứng nên được che bớt thông tin nhạy cảm trước khi lưu.

## 3. Chạy và đọc báo cáo

```
run.bat run "D:\Khach hang\Cong ty A"
```

- Nếu `answers.csv` có lỗi (mã lựa chọn sai, `observed` mà thiếu `evidence_ref`, ngày sai định dạng), công cụ liệt kê **tất cả** lỗi một lần.
- Nếu không có lỗi, báo cáo được ghi vào `runs\<ngày>\bao_cao.html`. Mở bằng trình duyệt, không cần mạng.

**Báo cáo gồm:**
- **3 việc nên làm tiếp:** mỗi việc ghi lý do, người phụ trách, hạn đề xuất, công sức, chi phí ("chưa ước tính" nếu chưa có báo giá), và cách chứng minh đã làm xong.
- **Mức rủi ro hiện tại** của 3 tình huống, mức dự kiến nếu làm các biện pháp, và ai cần quyết định.
- **Những điều chưa biết hoặc cần kiểm chứng:** các câu hỏi cần trả lời hoặc kiểm tra lại.

Chi tiết kỹ thuật nằm trong `trace.md` và `action_report.md`, cùng thư mục với báo cáo.

## 4. Lần đánh giá sau

1. Sau khi làm xong một việc, cập nhật câu trả lời tương ứng.
   - Ví dụ: đã thử quy trình đổi tài khoản thì sửa `PAY-02 = both`, `source = observed`, và ghi biên bản vào `evidence_ref`.
2. Chạy lại, so với lần trước:

   ```
   run.bat run "D:\Khach hang\Cong ty A" --baseline "D:\Khach hang\Cong ty A\runs\2026-11-23\state.json"
   ```

3. Báo cáo có thêm mục **"Thay đổi so với lần đánh giá trước"**.

**Nhịp đề xuất:**
- Xem lại các việc cần làm mỗi tháng.
- Đánh giá lại mỗi quý, và sau mỗi sự cố hoặc thay đổi lớn.

## 5. Ví dụ

Thư mục [examples/sme-demo/](examples/sme-demo/) là một công ty **hư cấu**. Có hai lần chạy:
- **Lần 1 (2026-11-23).**
- **Lần 2 (2026-12-05):** sau khi quy trình kiểm tra đổi tài khoản ngân hàng đã được thử và kiểm chứng. Kết quả là rủi ro lừa chuyển tiền giảm từ Cao xuống Trung bình.

`answers.csv` trong ví dụ là trạng thái của lần 2.
