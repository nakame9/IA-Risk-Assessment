# Plan chung: IA Risk Assessment

> Kết quả thảo luận Claude ↔ Codex (mỗi bên 3 lượt), ngày 2026-11-21.
> Đã kiểm chứng lại ngày 2026-11-21 (xem mục 7): Claude tự trích xuất text từ PDF của SP 800-30 Rev.1 và FIPS 199, đồng thời mở trang web của các nguồn còn lại.

## 1. Mục tiêu và phạm vi

- **Trọng tâm:** (a) phân tích mức độ nguy hiểm của mối đe dọa (threat severity), (b) tác động đến tài sản thông tin (impact on information assets), (c) ra quyết định xử lý rủi ro (risk treatment decision).
- **Hệ thống mẫu:** một hệ thống hư cấu có ranh giới rõ, là **cổng hồ sơ sinh viên** (student-records portal), gồm dữ liệu hồ sơ, phân quyền (roles), backup, hosting và phụ thuộc SSO. **Không** gồm thanh toán, nên không xét PCI DSS.
- **Giả định:** dự án học thuật/portfolio, mọi bằng chứng đều hư cấu và **được gắn nhãn rõ**. Các phê duyệt trong dự án đều là mô phỏng (simulated).
- **Sản phẩm:** một báo cáo, risk register dạng CSV và một script Python nhỏ để tính toán nhất quán.

## 2. Phương pháp (đã thống nhất)

| Nguồn | Vai trò |
|---|---|
| [NIST SP 800-30 Rev.1](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf) | Phương pháp chính, gồm cấu trúc đánh giá, các thang đo và bảng tra |
| [ISO/IEC 27005:2022](https://www.iso.org/standard/80585.html) | Hỗ trợ phần bối cảnh, xử lý, truyền thông và rà soát. **Không** tuyên bố tuân thủ |
| [FIPS 199](https://csrc.nist.gov/pubs/fips/199/final) | Hồ sơ CIA của tài sản theo 3 mức Low/Moderate/High |
| [NIST SP 800-60 Vol.I Rev.1](https://csrc.nist.gov/pubs/sp/800/60/v1/r1/final) | Tùy chọn: ví dụ ánh xạ loại thông tin |
| [CVSS v4.0 (FIRST)](https://www.first.org/cvss/v4.0/specification-document) | Chỉ dùng điểm Base (CVSS-B) làm **đầu vào** cho mức nghiêm trọng của lỗ hổng. CVSS đo severity chứ không đo risk |
| [NIST SP 800-53 Rev.5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) | Mã control cho các biện pháp giảm thiểu |
| [MITRE ATT&CK](https://attack.mitre.org/) | Tùy chọn: chỉ ánh xạ những kịch bản tấn công khớp rõ |

**Luồng phân tích theo các phụ lục của SP 800-30:**

1. **Nguồn đe dọa (App. D):** nguồn có chủ đích được chấm theo capability, intent, targeting (D-3 đến D-5). Nguồn không chủ đích được chấm theo range of effects (D-6). Đây là phần "mức độ nguy hiểm". Các đặc tính giữ riêng, **không** gộp thành một hệ số tự chế.
2. **Sự kiện đe dọa (App. E).**
3. **Lỗ hổng và điều kiện tiền đề (App. F):** vulnerability severity (F-2) và mức độ lan rộng của điều kiện (F-5).
4. **Khả năng xảy ra (App. G):** khả năng khởi phát/xảy ra (G-2, G-3) cùng khả năng gây tác động bất lợi (G-4) được tra qua bảng **G-5** để ra overall likelihood.
5. **Tác động (App. H):** thang đo ở bảng H-3 (impact of threat events). Bảng H-2 là các ví dụ về tác động bất lợi.
6. **Rủi ro (App. I):** tra bảng **I-2** từ likelihood × impact. Ý nghĩa từng mức nằm ở I-3.

**Quy tắc chấm điểm:**

- Dùng 5 mức định tính: Very Low, Low, Moderate, High, Very High.
- Kết hợp các mức bằng **bảng tra**, không nhân điểm thứ bậc với nhau.
- Các bảng của NIST chỉ là ví dụ và có thể tùy chỉnh. Dự án ghi rõ là áp dụng nguyên văn.
- Hai bảng tra dưới đây được chép nguyên văn từ SP 800-30 Rev.1 (trang G-2 và I-1). `risk.py` phải khớp từng ô:

  **G-5, Overall Likelihood** (hàng: likelihood of initiation/occurrence; cột: likelihood of adverse impact)

  | | VL | L | M | H | VH |
  |---|---|---|---|---|---|
  | **VH** | L | M | H | VH | VH |
  | **H** | L | M | M | H | VH |
  | **M** | L | L | M | M | H |
  | **L** | VL | L | L | M | M |
  | **VL** | VL | VL | L | L | L |

  **I-2, Level of Risk** (hàng: overall likelihood; cột: level of impact)

  | | VL | L | M | H | VH |
  |---|---|---|---|---|---|
  | **VH** | VL | L | M | H | VH |
  | **H** | VL | L | M | H | VH |
  | **M** | VL | L | M | M | H |
  | **L** | VL | L | L | L | M |
  | **VL** | VL | VL | VL | L | L |

- Hồ sơ CIA 3 mức theo FIPS 199 của tài sản tách riêng khỏi thang impact 5 mức của từng kịch bản. Báo cáo giải thích mối liên hệ giữa hai thang này.
- Giá trị chưa biết ghi là `unknown`, **không bao giờ** coi là 0.

**Chính sách quyết định:**

| Mức rủi ro | Yêu cầu |
|---|---|
| Very Low / Low | Chủ sở hữu rủi ro được chấp nhận, có ghi lại |
| Moderate | Phải xử lý, hoặc được chấp nhận theo ủy quyền |
| High / Very High | Phải xử lý, hoặc cần ngoại lệ của cấp cao |
| Impact = Very High | Luôn escalate, bất kể mức rủi ro |

- Chính sách (appetite) chỉ xác định **có bắt buộc hành động hay không**, chứ không chọn phương án.
- Phương án (mitigate / transfer / avoid / accept) được chọn bằng cách so sánh mức giảm rủi ro, chi phí/công sức, nghĩa vụ pháp lý và phần rủi ro còn lại.
- Rủi ro còn lại (residual risk) được tính lại qua G-5 và I-2, gắn nhãn `projected` cho tới khi được kiểm chứng (`verified`).

## 3. Cấu trúc repo

```text
README.md              # phạm vi, cách chạy, link báo cáo
report.md              # báo cáo duy nhất: scope, method, anchors, threat profiles, evidence, treatment, kết luận
data/assets.csv        # tài sản + hồ sơ CIA (FIPS 199)
data/risk_register.csv # nguồn dữ liệu gốc
risk.py                # stdlib only: tra G-5/I-2, cờ chính sách, sinh out/*.md; `python risk.py --check`
out/register.md        # sinh tự động, không sửa tay
out/matrix.md          # sinh tự động
```

**Các cột của `risk_register.csv`:**

`risk_id, asset_id, threat_profile_id, event, vulnerability_condition, vulnerability_severity, condition_pervasiveness, existing_controls, cvss_b_score, cvss_vector, initiation_likelihood, adverse_impact_likelihood, impact, evidence_ref, confidence, treatment_option, treatment_action, control_ids, risk_owner, due_date, residual_initiation_likelihood, residual_adverse_impact_likelihood, residual_impact, residual_status, decision_ref, status`

- Không lưu các giá trị suy ra (overall likelihood, risk, residual risk, cờ chính sách) trong file đầu vào. Script tự tính chúng.
- `threat_profile_id`, `evidence_ref` và `decision_ref` trỏ tới các mục trong `report.md` để không lặp nội dung.
- Hai cột CVSS hoặc cùng có, hoặc cùng để trống. Phân biệt `n/a` (không áp dụng) với `unknown` (chưa biết). Dòng thiếu một rating bắt buộc sẽ bị bỏ qua và in cảnh báo.
- Trong CSV, các nhãn rating giữ nguyên tiếng Anh.
- Script chỉ **gắn cờ** khi cần hành động hoặc escalate. Script **không bao giờ** tự cấp quyền chấp nhận rủi ro.

**Ngôn ngữ:** báo cáo viết bằng tiếng Việt, thuật ngữ chuẩn tiếng Anh để trong ngoặc ở lần dùng đầu. Code và header CSV dùng tiếng Anh.

## 4. Các giai đoạn

| # | Giai đoạn | Đầu ra |
|---|---|---|
| 1 | **Frame** | Scope và ranh giới hệ thống, giả định hư cấu, horizon 12 tháng, anchors cho từng mức rating, appetite, vai trò phê duyệt |
| 2 | **Identify** | `assets.csv` kèm hồ sơ CIA, threat profiles, lỗ hổng/điều kiện, 10–15 kịch bản |
| 3 | **Assess** | Bằng chứng, các thành phần likelihood, impact, rủi ro hiện tại, mức độ bất định, **2 ví dụ tính tay** |
| 4 | **Treat** | So sánh phương án, control 800-53, owner, hạn, residual `projected`, hồ sơ chấp nhận (mô phỏng) |
| 5 | **Package & review** | `report.md`, CSV, `risk.py` với một self-check, `out/*.md`, phần hạn chế, điều kiện kích hoạt rà soát lại (review triggers) |

`risk.py` **chỉ được viết sau** khi hai ví dụ tính tay ở giai đoạn 3–4 đã chốt quy tắc và các trường dữ liệu. Self-check gồm: vài ô tiêu biểu của bảng G-5 và I-2, một nhãn không hợp lệ, một ca escalate.

## 5. Rủi ro của chính dự án

| Rủi ro | Giảm thiểu |
|---|---|
| Chấm điểm chủ quan làm sai thứ tự ưu tiên | Anchors riêng cho hệ thống mẫu, ghi lại mức bất định, chấm lại các ca sát ngưỡng |
| Bằng chứng hư cấu trông tùy tiện hoặc bị hiểu là thật | Gắn nhãn mọi giả định, tách nguồn tham chiếu ngoài khỏi chi tiết tự đặt, giải thích từng rating |
| Script khiến kết quả sai trông có thẩm quyền | Giữ 2 ví dụ tính tay, có self-check, quyết định cuối luôn do người rà soát |

## 6. Ghi nhận thảo luận

**Đã thay đổi so với đề xuất ban đầu:**

- *Codex:* bỏ ma trận 1–5 dùng `L × I` với các dải tự đặt, chuyển sang bảng tra G-5/I-2 (Claude đề xuất).
- *Codex:* bỏ định dạng spreadsheet, chuyển sang CSV + script stdlib (Claude đề xuất).
- *Codex:* bổ sung bước threat characterization riêng (Claude đề xuất).
- *Claude:* sửa quan niệm "appetite quyết định phương án". Thực tế appetite chỉ quyết định có bắt buộc hành động hay không (Codex sửa).
- *Claude:* bỏ cách chia nhiều file docs, chuyển sang một `report.md` duy nhất (Codex đồng ý và chốt).
- *Claude:* thêm các trường `residual_status`, `decision_ref`, cặp residual likelihood, và quy tắc `n/a` khác `unknown` (Codex đề xuất).

**Hoãn lại:**

- Ước lượng định lượng theo FAIR.
- Ánh xạ ATT&CK đầy đủ.
- SP 800-60 Rev.2 (Claude chưa xác minh trạng thái, nên chưa dùng).
- Mọi UI, database, tài khoản, dashboard, quét tự động.

**Câu hỏi còn mở (cần người dùng trả lời):**

- Có rubric hoặc yêu cầu môn học không?
- Deadline và quy mô nhóm?
- Có muốn dùng một tổ chức hoặc hệ thống thật thay cho hệ thống hư cấu không?

## 7. Kết quả kiểm chứng (2026-11-21)

| Nhận định trong plan | Kết quả | Nguồn đã đọc |
|---|---|---|
| Tên bảng D-3 → D-6, F-2, F-5, G-2 → G-5, H-3, I-2, I-3 | **Đúng**, khớp nguyên văn tên bảng | Text trích từ PDF SP 800-30 Rev.1 (Sep 2012) |
| 5 mức Very Low … Very High; nội dung G-5 và I-2 | **Đúng**, đã chép ở mục 2 | Như trên |
| Các bảng chỉ là ví dụ (exemplary), có thể tùy chỉnh (tailorable) | **Đúng**. App. H ghi rõ có thể dùng làm điểm khởi đầu và tùy chỉnh. Phần 3 ghi rằng không bắt buộc dùng template | Như trên |
| FIPS 199 có 3 mức impact Low / Moderate / High | **Đúng** | Text trích từ PDF FIPS 199 |
| CVSS-B nghĩa là chỉ dùng Base metrics; vector bắt đầu bằng `CVSS:4.0/` | **Đúng** | FIRST CVSS v4.0 Specification |
| "CVSS đo severity, không đo risk" | **Đúng**, nhưng câu này nằm ở **User Guide** (mục "CVSS Base (CVSS-B) Measures Severity, not Risk"), không phải ở Specification | first.org/cvss/v4.0/user-guide |
| SP 800-53 Rev.5 và SP 800-60 Vol.I Rev.1 tồn tại | **Đúng** | csrc.nist.gov |
| ISO/IEC 27005:2022 (ấn bản 4, tháng 10/2022) | **Đúng** theo Wikipedia. Trang iso.org trả về 403 nên chưa đọc được trực tiếp | en.wikipedia.org |
| SP 800-60 Rev.2 | **Chưa xác minh**: URL bản draft trả về 404. Plan vẫn giữ nguyên là chưa dùng | — |
| SP 800-53 có bản phát hành mới hơn (5.2.0) | **Chưa xác minh trực tiếp**. Khi chọn control ở giai đoạn 4, cần lấy bản phát hành hiện hành trên csrc | — |
