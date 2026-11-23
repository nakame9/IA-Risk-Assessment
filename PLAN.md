# Plan chung: IA Risk Assessment

> Kết quả thảo luận Claude ↔ Codex (mỗi bên 3 lượt), ngày 2026-11-21.
> **Trạng thái: v1 đã hoàn thành cả 5 giai đoạn (2026-11-22), xem mục 8. Kế hoạch cải thiện v2 nằm ở mục 9. Mục 9.10 (v2.1) được ưu tiên khi mâu thuẫn với các mục khác. Cả 7 bước của v2.1 đã hoàn thành ngày 2026-11-22 (§9.10.5). Kế hoạch v3 cho doanh nghiệp vừa và nhỏ (chưa triển khai) nằm ở §10.**
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

**Câu hỏi mở (đã đóng):** người dùng không trả lời các câu hỏi này, nên dự án đi tiếp với giả định mặc định.

| Câu hỏi | Cách đã xử lý |
|---|---|
| Có rubric hoặc yêu cầu môn học không? | Không có rubric, nên dự án bám theo đầu ra ở mục 4. Nếu sau này có rubric thì cần đối chiếu lại |
| Deadline và quy mô nhóm? | Không đặt deadline. Các hạn triển khai trong báo cáo là giả định của hệ thống hư cấu, không phải deadline của dự án |
| Dùng tổ chức/hệ thống thật? | Không. Giữ hệ thống hư cấu, mọi bằng chứng đều được gắn nhãn [GĐ]/[ĐG] |

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
| SP 800-53 có bản phát hành mới hơn (5.2.0) | **Chưa xác minh trực tiếp**. Ở giai đoạn 4, mã và tên control đã được đối chiếu với PDF SP 800-53 Rev.5 (bản trên nvlpubs). Chưa so với bản 5.2.0 | — |

## 8. Trạng thái hoàn thành (2026-11-22)

| Giai đoạn | Đầu ra | Nơi lưu |
|---|---|---|
| 1. Frame | Phạm vi, giả định, vai trò, thang đo kèm anchor, appetite, điều kiện rà soát lại | `report.md` §1 |
| 2. Identify | 10 tài sản có hồ sơ CIA, 8 nguồn đe dọa, 11 lỗ hổng, 5 điều kiện tiền đề, 13 kịch bản | `data/assets.csv`, `data/risk_register.csv`, `report.md` §2 |
| 3. Assess | 2 ví dụ tính tay, kết quả 13 kịch bản (1 High, 8 Moderate, 4 Low), ma trận, thứ tự ưu tiên, mức bất định | `report.md` §3 |
| 4. Treat | 13 gói biện pháp gắn control SP 800-53 Rev.5, hồ sơ quyết định mô phỏng, residual `projected` (0 High, 3 Moderate, 10 Low), bằng chứng kiểm chứng | `report.md` §4 |
| 5. Package & review | `risk.py` + `--check`, `out/*.md`, đối soát, phân tích độ nhạy, hạn chế, kết luận | `risk.py`, `out/`, `report.md` §5 |

**Kiểm tra lúc đóng dự án:**
- `python risk.py --check` pass.
- Chạy lại `risk.py` thì `out/` không thay đổi so với bản đã commit.
- 13 dòng của risk register điền đủ các cột bắt buộc.
- Mọi link nội bộ đều hợp lệ.

**Những điểm còn ngoài phạm vi, chủ ý để lại:**
- **Residual chỉ là dự kiến:** mọi residual đều `projected`, vì hệ thống hư cấu không có control thật để kiểm chứng.
- **Không có rà soát độc lập:** plan không yêu cầu bước này.
- **Bản phát hành SP 800-53 mới nhất:** chưa xác minh bản 5.2.0 (mục 7).
- **Các mục đã hoãn ở mục 6:** FAIR, ánh xạ ATT&CK đầy đủ, cộng dồn rủi ro giữa các kịch bản.

## 9. Kế hoạch cải thiện v2: chuyển từ một bài đánh giá sang một mô hình nghiên cứu

> Đây là kết quả thảo luận Claude ↔ Codex (mỗi bên 3 lượt), ngày 2026-11-22. **Chưa triển khai.**

### 9.1 Bài toán và câu hỏi nghiên cứu

**Bài toán:** một tổ chức có hàng trăm tài sản thông tin. Nếu đánh giá theo cảm tính, tổ chức không biết nên xử lý vấn đề nào trước.

**Câu hỏi nghiên cứu (RQ):** làm thế nào để xây dựng một mô hình đánh giá rủi ro **nhất quán**, **giải thích được**, và **hỗ trợ ưu tiên biện pháp** bảo đảm thông tin? Mô hình dựa trên NIST SP 800-30 Rev.1.

Ba thuộc tính của RQ được chuyển thành ba câu hỏi con có thể kiểm chứng:

| Thuộc tính | Câu hỏi con |
|---|---|
| **Nhất quán** | Với cùng một bộ bằng chứng, mô hình có luôn cho cùng một kết quả không? Bao nhiêu phần đầu vào được suy ra từ quy tắc, và bao nhiêu phần còn là phán đoán? |
| **Giải thích được** | Mọi mức rủi ro có lần ngược được qua chuỗi bằng chứng → quy tắc → ô của bảng G-5/I-2 → yêu cầu chính sách hay không? |
| **Hỗ trợ ưu tiên** | Mô hình có xếp hạng được các **biện pháp** (gói control) chứ không chỉ xếp hạng rủi ro, mà không phải làm phép tính giả trên các nhãn thứ bậc hay không? |

### 9.2 Các khoảng trống của bản v1 (từ lượt 1 của Codex, Claude đã đồng ý)

- **Quy mô:**
  - Kịch bản đang được viết tay cho từng dòng.
  - `risk.py` không đọc `assets.csv` và không kiểm tra tham chiếu tài sản.
  - Self-check cố định con số 13 kịch bản.
  - Thang F-5 gắn chặt vào 7 thành phần của portal.
- **Nhất quán:**
  - G-4 chỉ có một ví dụ anchor.
  - Anchor về tính sẵn sàng bỏ sót khoảng 3–7 ngày.
  - **Lỗi điều kiện hóa ở R-09 và R-13:** sự kiện đã ghi "trong kỳ đăng ký", nhưng G-4 lại bị hạ vì lý do "ít khi trùng kỳ đăng ký". Điều kiện thời điểm vì vậy bị tính hai lần.
- **Giải thích được:**
  - Output do script sinh ra không có bằng chứng và quy tắc đứng sau từng rating.
  - Confidence chỉ ghi ở cấp kịch bản, nên không biết đầu vào nào là đầu vào bất định.
- **Ưu tiên biện pháp:**
  - Việc ưu tiên T-01, T-02, T-03 chỉ dựa trên lập luận.
  - Residual được chấm theo cả bộ gói, nên không biết lợi ích riêng hay lợi ích cận biên của từng gói.
  - R-01 và R-11 chồng lấn nhau, dễ bị tính lợi ích hai lần.
- **Prepare/Maintain:**
  - Chưa ánh xạ rõ tới Task 1-1 → 1-5 và 4-1 → 4-2 của SP 800-30. Claude đã tự xác minh số hiệu các task này trong PDF.
  - Chưa có quy trình thu thập bằng chứng, và chưa chạy thử một chu kỳ cập nhật nào.

### 9.3 Mô hình v2 (đã thống nhất)

**Nguyên tắc:**
- Giữ nguyên G-5/I-2 và hồ sơ CIA theo FIPS 199.
- Không cộng, trừ hay chia trên các nhãn thứ bậc.
- Dữ liệu vẫn ở dạng CSV, code chỉ dùng thư viện chuẩn của Python.

**Lớp tài sản và template kịch bản:**
- Mỗi tài sản thuộc một `asset_class`, ví dụ: `pii_database`, `web_service`, `identity_service`, `backup_store`, `admin_endpoint`, `email`, `document_store`.
- **Template kịch bản mang quy tắc, không mang rating.** Template cố định nguồn đe dọa, sự kiện và quy tắc nào được áp dụng. Mỗi tài sản cụ thể chỉ cung cấp thuộc tính bằng chứng.
- Kịch bản cấp tài sản được sinh theo công thức: tài sản × template áp dụng được.
- Kịch bản cấp toàn hệ thống được tạo **một lần**, kèm danh sách tài sản bị ảnh hưởng và một `family_id`. Ví dụ: ransomware, sự cố mất region.

**Quy tắc có mã và phiên bản:**
- Quy tắc là các hàm nhỏ trong `risk.py`. Không xây ngôn ngữ cấu hình quy tắc.
- Mỗi quy tắc khai báo các thuộc tính nó đọc, kiểu dữ liệu, đơn vị và giá trị hợp lệ.
- `--check` từ chối thuộc tính lạ, giá trị sai và bản ghi mâu thuẫn.
- Bằng chứng còn thiếu cho kết quả `unknown`.

| Mã | Quy tắc |
|---|---|
| F2-01 | Control chưa có và chưa lên kế hoạch → VH. Đã lên kế hoạch, có bù trừ tối thiểu → H. Triển khai một phần → M. Triển khai đủ, hiệu quả ở mức "somewhat" → L. Triển khai đủ, đã được đánh giá, hiệu quả → VL. Thiếu bằng chứng về hiệu quả → `unknown`. Đây là **cách diễn giải của dự án** dựa trên F-2. Riêng mức VL đã được đối chiếu nguyên văn ("fully implemented, assessed, and effective") |
| G3-01 | Gọi `f` là tần suất mỗi năm. `0≤f≤0.1` → VL; `0.1<f<1` → L; `1≤f<10` → M; `10≤f≤100` → H; `f>100` → VH. Quy tắc này phá thế trùng ranh giới tại giá trị 10/năm của bảng G-3 |
| C-01 | Thông tin công khai, hoặc không có bản ghi nào bị lộ → VL. Các trường hợp khác xếp theo số bản ghi bị lộ, chia ba khoảng 1–9 / 10–1.000 / >1.000: thông tin không công khai thông thường → L / M / H; thông tin nhạy cảm → M / H / H |
| I-01 | Xét hậu quả **nếu thông tin sai được đem dùng**. Hậu quả negligible / limited / serious / severe → VL / L / M / H. Nếu có cơ chế phát hiện **và sửa trước khi dữ liệu được dùng**, mức tối đa là L. Chỉ phát hiện mà không sửa thì không giảm mức |
| A-01 | Gián đoạn 0 giờ → VL. Ngoài khung thời gian then chốt: `(0,1)` / `[1,24)` / `[24,168]` / `>168` giờ → VL / L / M / H. Trong khung thời gian then chốt: `(0,24)` / `≥24` giờ → M / H |
| IMP-01 | Impact là mức cao nhất trong ba mức C, I, A. Chỉ xếp VH khi bằng chứng ghi nhận **nhiều hậu quả nặng khác nhau**, không chỉ vì nhiều chiều CIA cùng bị ảnh hưởng |
| COND-01 | Sự kiện mất dịch vụ được định nghĩa là xảy ra **vào bất kỳ lúc nào**. Thời điểm trùng khung then chốt chỉ được xét **một lần**, ở G-4. Quy tắc này sửa lỗi của R-09 và R-13 |

Các mức như phân loại độ nhạy, nhóm hậu quả và khung thời gian then chốt vẫn là phán đoán. Chúng phải được định nghĩa ở Prepare và có bằng chứng đi kèm.

**Dữ liệu (tối thiểu):**

| File | Nội dung gốc |
|---|---|
| `data/assets.csv` | Các trường hiện có, thêm `asset_class` và `system_id` |
| `data/templates.csv` | `template_id, asset_classes, scope, threat_profile_id, event, init_rule, adverse_rule, impact_rule` |
| `data/inputs.csv` | `subject_id, attribute, value, mode (evidence/judgment), evidence_ref, rationale, confidence, assessor, observed_on` |
| `data/packages.csv` | `package_id, scope_ids, control_ids, effort_tier, requires, owner, status, verification_ref`. Bundle là một dòng riêng, có effort được đánh giá riêng. **Không cộng effort tier** |
| `data/effects.csv` | `risk_id, package_ids (một tập chính xác), initiation, adverse, impact, basis_ref` |
| `data/risk_register.csv` | Chỉ còn thông tin của từng kịch bản và quyết định, thêm `template_id, family_id, applicable_packages, last_reviewed, next_review`. Các rating suy ra được chuyển sang output sinh tự động |

**Chuỗi giải thích:** với mỗi rủi ro, script sinh ra chuỗi: bằng chứng/phán đoán → quy tắc (mã + phiên bản) → rating đầu vào → ô G-5 → ô I-2 → yêu cầu chính sách → giả định về gói biện pháp.

### 9.4 Xếp hạng biện pháp (không dùng phép tính giả)

**Hiệu ứng thưa (sparse effects):**
- Một ứng viên là một gói đơn hoặc một bundle đã được đánh giá.
- Ứng viên chỉ có hiệu ứng lên một rủi ro khi có đúng tập gói tương ứng trong `effects.csv`.
- **Không ghép** các factor tốt nhất từ nhiều dòng khác nhau.
- Tổ hợp chưa được đánh giá là `unknown`, không phải "không có lợi ích".

**Cách đo lợi ích:** lợi ích được tính bằng **số family** có rủi ro nặng nhất vượt xuống dưới ngưỡng. Hai con số được ghi riêng:
- số family xuống dưới High,
- số family xuống dưới Moderate.

Đếm theo family chứ không theo kịch bản, để R-01 và R-11 không được tính trùng.

**Thứ tự xếp hạng:**
1. Các nghĩa vụ bắt buộc (mandatory) ràng buộc lựa chọn. Escalation đòi hỏi người xem xét, nhưng **không** tự động bắt buộc một gói.
2. Lọc Pareto, so **riêng** từng con số lợi ích với effort.
3. Trong nhóm Pareto, xếp theo thứ tự: số family xuống dưới High (giảm dần), số family xuống dưới Moderate (giảm dần), effort (tăng dần). Giữ nguyên các trường hợp hòa.
4. ~~Chọn tham lam (greedy): sau mỗi lần chọn một ứng viên, tính lại lợi ích cận biên.~~ **Bỏ ở bản v2.1** (xem §9.10). Thay vào đó, xếp hạng các gói đơn và bundle đã được đánh giá so với baseline hiện tại. Sau khi triển khai thì chạy lại.
5. Ứng viên có hiệu ứng `unknown` lên một family có thể vượt ngưỡng được tách khỏi bảng xếp hạng và gắn nhãn **"incomplete"**.

Cách xếp hạng này là **heuristic minh bạch**, không phải danh mục tối ưu.

### 9.5 Đánh giá (chỉ ghi những gì sẽ thực sự chạy)

| # | Phép đo | Cách làm |
|---|---|---|
| E1 | Độ phủ quy tắc | Tỷ lệ các factor cốt lõi được suy ra từ quy tắc, từ phán đoán, hoặc còn `unknown`. Chia theo từng factor và từng template |
| E2 | Tính tất định | Hash SHA-256 của output, với đầu vào, phiên bản quy tắc và ngày đánh giá được cố định. Chạy hai lần phải ra cùng hash. Thời gian chạy được ghi ở ngoài output |
| E3 | Độ nhạy | Nâng hoặc hạ mỗi đầu vào **phán đoán** một mức. Với bằng chứng dạng số, thử giá trị ngay sát ranh giới của quy tắc. Đo tỷ lệ rủi ro bị đổi mức, và độ ổn định của thứ tự gói. ~~Kendall tau-b~~ được thay ở bản v2.1 bằng: số khuyến nghị đứng đầu bị đổi, và số cặp so sánh được bị đảo thứ tự (có xử lý trường hợp hòa và trường hợp bị loại) |
| E4 | Quy mô | Dữ liệu tổng hợp khoảng 200 tài sản do `synth.py` sinh ra, với seed và phiên bản cố định. Gồm nhiều lớp tài sản, có bằng chứng bị thiếu, có dịch vụ dùng chung, có ca sát ranh giới. Ghi lại số tài sản, số kịch bản và thời gian chạy |
| E5 | So với baseline | So mô hình với hai cách chọn đơn giản: chọn theo rủi ro cao nhất trước, và chọn theo effort thấp nhất trước. So ở cùng số hành động effort Low/Medium/High. Báo cáo family nào xuống dưới High hoặc Moderate. Kết quả **chỉ có ý nghĩa trong mô hình tổng hợp** |
| E6 | Truy vết và bảo trì | Tỷ lệ rủi ro có đủ chuỗi giải thích. Chạy thử một chu kỳ Task 4-1 → 4-2 trên case portal, có diff trước/sau. Ví dụ đã sửa: R-02 phụ thuộc cả T-01 **và** T-06, nên phải kiểm chứng cả hai. Mọi bằng chứng kiểm chứng đều ghi rõ là mô phỏng |

**Không thực hiện:**
- **Nghiên cứu hai người chấm thật:** chỉ cung cấp bộ công cụ sẵn sàng chạy (đo phần trăm đồng thuận hoặc Cohen's kappa theo từng đầu vào), ghi rõ là **chưa thực hiện**. Dự án không tuyên bố đã đo được độ tin cậy giữa người chấm.
- **Pilot dùng LLM làm người chấm thứ hai:** bị loại theo lập luận của Codex. Codex đã thấy các rating nên không thể chấm mù, và kết quả cũng không phải là đồng thuận giữa con người.

### 9.6 Thứ tự công việc

1. **Prepare v2:** cố định v1 bằng tag `v1`. Ánh xạ Task 1-1 → 1-5. Viết quy trình thu thập bằng chứng. Sửa lỗi COND-01 và các anchor còn hở.
2. **Schema và quy tắc:** viết đặc tả quy tắc và schema. Chuyển 13 kịch bản sang mô hình mới. Mọi kết quả thay đổi so với v1 đều phải được giải thích.
3. **Code:** mở rộng phần kiểm tra hợp lệ, phần tính điểm, chuỗi giải thích và báo cáo độ phủ trong `risk.py`.
4. **Xếp hạng gói:** thêm `effects.csv` và phần xếp hạng ứng viên theo §9.4, kèm một self-check chạy được.
5. **Thực nghiệm:** viết `synth.py` để chạy E1 → E5. Chạy thử một chu kỳ bảo trì (E6).
6. **Viết lại báo cáo theo khung nghiên cứu:** Bài toán/RQ → Phương pháp và giả định → Giao thức đánh giá → Kết quả → Thảo luận và các mối đe dọa tới tính hợp lệ (threats to validity) → Kết luận. Các bảng đánh giá chi tiết của v1 chuyển xuống phụ lục. Kết quả đã chạy được tách riêng khỏi phần đánh giá với người thật (chỉ là đề xuất).

### 9.7 Những gì đã thay đổi so với đề xuất ban đầu của mỗi bên

- **Claude, xử lý quy mô:** đề xuất ban đầu là sinh kịch bản theo tài sản × template cho mọi kịch bản. Sau sửa: kịch bản toàn hệ thống chỉ tạo một lần, kèm `family_id` (Codex).
- **Claude, đo nhất quán:** đề xuất ban đầu có pilot dùng LLM làm người chấm thứ hai. Sau sửa: bỏ, chỉ giữ bộ công cụ cho người chấm thật mà chưa chạy (Codex).
- **Claude, ví dụ bảo trì:** đề xuất ban đầu là ví dụ "R-02 được kiểm chứng nhờ T-01". Sau sửa: phải kiểm chứng cả T-01 và T-06 (Codex).
- **Claude, quy tắc impact:** đề xuất ban đầu tính C chỉ theo số bản ghi. Sau sửa: xét thêm độ nhạy của thông tin và phạm vi bị lộ. Còn I xét thêm hậu quả và thời điểm phát hiện (Codex).
- **Codex, đo lợi ích:** đề xuất ban đầu đếm theo "decision units". Sau sửa: đếm theo family, có lọc Pareto, chọn tham lam và gắn nhãn incomplete (hai bên thống nhất).
- **Codex, dữ liệu đầu vào:** đề xuất ban đầu dùng `inputs.csv` dạng dài, không ràng buộc. Sau sửa: mỗi quy tắc khai báo thuộc tính, và `--check` từ chối thuộc tính lạ (Claude).

### 9.8 Hoãn lại

- Nghiên cứu hai người chấm thật.
- Ngân sách bằng số (người-ngày) và ROI tính bằng tiền.
- FAIR.
- Mọi UI, database và ML.
- Kết luận về hiệu quả bảo mật thực tế, vì dữ liệu tổng hợp chỉ minh họa hành vi của mô hình.

### 9.9 Rủi ro của bản v2

*(Bản v2.1 bổ sung thêm rủi ro, xem §9.10.6.)*

| Rủi ro | Giảm thiểu |
|---|---|
| **Khách quan giả:** quy tắc chính xác có thể che đi các giả định chủ quan bên dưới | Hiện rõ nguồn gốc của từng bằng chứng, độ phủ của phán đoán và độ nhạy tại các ranh giới |
| **Xếp hạng gói gây hiểu nhầm:** hiệu ứng thưa và effort thứ bậc có thể thiên vị các ứng viên được ghi chép đầy đủ hơn | Hiển thị phần còn thiếu (incomplete), giữ nguyên các trường hợp hòa, chỉ rút kết luận trên các so sánh có dữ liệu hỗ trợ |
| **Vòng lặp tổng hợp:** bộ sinh dữ liệu dễ "thưởng" đúng những giả định mà mô hình đã cài sẵn | Cố định quy tắc trước khi viết `synth.py`. Thêm các phản ví dụ được đặc tả độc lập. Chỉ tuyên bố về hành vi của mô hình, không tuyên bố hiệu quả an ninh thực tế |

### 9.10 Điều chỉnh v2.1: thiết thực, chính xác, hữu dụng (2026-11-22)

> **Bối cảnh:** người dùng cho biết yêu cầu bắt buộc duy nhất là **thiết thực, chính xác và hữu dụng**. Phương pháp và kiến trúc được chọn tự do.
> Mục này là kết quả thảo luận Claude ↔ Codex (mỗi bên 3 lượt). Khi mâu thuẫn với các mục 9.1 đến 9.9, **mục này được ưu tiên**.

#### 9.10.1 Kiến trúc: không làm web stack ở giai đoạn này

**Đã cân nhắc và hoãn lại:** kiến trúc React → FastAPI → engine Python → PostgreSQL → xuất PDF/Excel. Lý do: kiến trúc này không làm kết quả chính xác hơn hay hữu ích hơn. Chỉ làm khi workflow thực tế, nhu cầu phân quyền hoặc nhu cầu audit chứng minh là cần, ví dụ khi nhiều người phải nhập liệu cùng lúc.

Nếu sau này làm, có 4 bài học từ lần xem xét này:
- Engine phải là thư viện **thuần túy**, không truy cập database.
- Không dùng "CIA weight" (cộng có trọng số các mức C, I, A) mà dùng quy tắc mức cao nhất của FIPS 199.
- Thay "likelihood estimator" và "risk scoring" bằng tra bảng G-5 và I-2.
- Phân quyền phải ánh xạ đúng các vai trò ở §1.4 của báo cáo.

**Đầu vào:** ba bảng mà người vận hành chỉnh sửa được, dạng CSV lưu từ Excel. Template, gói biện pháp và effects do người phụ trách mô hình quản lý.

| File | Thay đổi so với §9.3 |
|---|---|
| `data/assets.csv` | Các thành phần kỹ thuật có thêm `vendor, product, version, exposure` |
| `data/inputs.csv` | Giữ nguyên các trường nguồn gốc. **Finding** (liên kết với CVE) là các dòng có `subject_id = F-xxx`. Thuộc tính gồm: `cve_id, component_id, applicability (confirmed/suspected/not_applicable), remediation_state, first_confirmed_on, obligation_triggered_on, obligation_policy_version`. Mỗi cặp thành phần–CVE chỉ có một finding cố định. Applicability được ghi **tách riêng** khỏi exposure |
| `data/controls.csv` *(mới)* | `scope_id, package_id, status, evidence_ref, verified_on`. Tình trạng control vận hành được chuyển về đây |
| `data/snapshots/` + manifest *(mới, sinh tự động)* | Bản lưu cố định của KEV và EPSS. Manifest ghi: URL nguồn, ngày lấy, ngày phát hành, phiên bản, SHA-256 và tham chiếu license |

**Đầu ra:** **một báo cáo hành động dạng Markdown**.
- Phần đầu báo cáo ghi: ngày đánh giá, phạm vi, phiên bản snapshot và phiên bản quy tắc.
- Các mục lần lượt:

| # | Mục | Nội dung |
|---|---|---|
| 1 | **Việc gấp** | Các nghĩa vụ đã quá hạn hoặc sắp tới hạn, các escalation, các quyết định chấp nhận đã hết hạn. Mỗi việc ghi owner, hạn và hành động cần làm |
| 2 | **Thay đổi so với lần trước** | Cái gì đổi, vì sao, và ảnh hưởng tới nghĩa vụ, rating, ưu tiên. Lần chạy đầu ghi "Baseline assessment" |
| 3 | **Gói biện pháp khuyến nghị** | Thứ tự có dữ liệu hỗ trợ, lý do, effort, điều kiện tiên quyết, family bị ảnh hưởng, kết quả dự kiến, tiêu chí kiểm chứng. Liệt kê riêng các ứng viên incomplete |
| 4 | **Backlog vá lỗi** | Finding nằm trong KEV kèm nghĩa vụ tương ứng. Finding không nằm trong KEV được xếp theo EPSS trong cùng nhóm so sánh được. Finding thiếu điểm EPSS ghi rõ là chưa xếp hạng |
| 5 | **Hàng đợi điều tra** | Các việc thu thập bằng chứng, các khả năng hợp lý, và quyết định có thể bị đổi |
| 6 | **Tình trạng bằng chứng và feed** | Bằng chứng thiếu hoặc đã cũ, ngày và phiên bản snapshot, các lần làm mới thất bại, giới hạn về độ phủ |
| 7 | **Rủi ro đã chấp nhận và ngoại lệ** | Người có thẩm quyền, lý do, điều kiện, hạn rà soát |

#### 9.10.2 Dùng dữ liệu khai thác thật mà không làm giả likelihood

**Nguồn dữ liệu** (đã xác minh ngày 2026-11-22):
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog):** danh sách các lỗ hổng đã bị khai thác thực tế. Tải được dạng CSV và JSON. Có trường `knownRansomwareCampaignUse`. Dữ liệu dùng giấy phép **CC0 1.0** ([LICENSE](https://github.com/cisagov/kev-data/blob/develop/LICENSE)). Các liên kết tới bên thứ ba trong dữ liệu theo license riêng của họ.
- **[FIRST EPSS](https://www.first.org/epss/):** xác suất một CVE bị khai thác trong **30 ngày tới**. Cập nhật hằng ngày, tải được dạng CSV hoặc qua API. Theo [FAQ](https://www.first.org/epss/faq):
  - EPSS **không phải** là điểm rủi ro đầy đủ.
  - EPSS không xét bối cảnh của từng hệ thống cụ thể.
  - **Không có ngưỡng áp dụng chung**.
  - FIRST yêu cầu ghi nguồn khi dùng dữ liệu.
  - Phần điều khoản sử dụng do Codex dẫn ([FIRST Services Terms of Use](https://www.first.org/about/policies/FIRST-Services-Terms-of-Use.pdf)) **Claude chưa tự đọc**.
- **BOD 22-01 đã bị thu hồi**, thay bằng BOD 26-04 (trang của CISA ghi ngày 10/06/2026). Vì vậy việc khắc phục lỗ hổng trong KEV là **chính sách dự án tự chọn áp dụng**. Dự án không tuyên bố tuân thủ quy định liên bang.

**Đã bác bỏ:**
- Quy tắc "CVE nằm trong KEV thì G-2 ≥ High".
- Quy tắc "EPSS vượt ngưỡng thì nâng một mức".

Lý do: KEV và EPSS phản ánh hoạt động khai thác **toàn cầu** đối với từng CVE, không phải khả năng một tổ chức cụ thể bị tấn công. Thêm nữa, horizon 30 ngày của EPSS khác horizon 12 tháng của đánh giá, và **không được quy đổi** từ cái này sang cái kia.

**Các quy tắc mới:**

| Mã | Quy tắc |
|---|---|
| CVE-APP-01 | Chỉ liên kết một CVE với một thành phần khi có bằng chứng về sản phẩm, phiên bản, cấu hình và điều kiện tiên quyết. Nếu không chắc chắn, tạo một việc điều tra thay vì mặc định là có lỗ hổng |
| G2-TI-01 | Tư cách thành viên KEV và điểm EPSS (kèm ngày) được gắn vào phần đánh giá G-2 như **bằng chứng ngoài**. Rating G-2 vẫn là phán đoán tại chỗ, có lý do. Feed tự nó không gán rating |
| G4-LOCAL-01 | G-4 được đánh giá theo đường tấn công thực tế, quyền cần có, tình trạng vá và các control đã được kiểm chứng. **Không** dùng lại tín hiệu feed lần nữa cho G-4 hay cho impact |
| TI-ABS-01 | Không có trong KEV không có nghĩa là chưa bị khai thác. Thiếu điểm EPSS không có nghĩa là bằng 0. Kịch bản không có CVE vẫn đi theo đường bằng chứng hoặc phán đoán như cũ |
| TI-RANSOM-01 | `knownRansomwareCampaignUse = Known` thì phải rà soát lại các kịch bản ransomware liên quan. Giá trị `Unknown` nghĩa là chưa xác nhận, không có nghĩa là "No" |
| TI-REV-01 | Có một mục KEV mới áp dụng được, hoặc EPSS vượt ngưỡng rà soát đã khai báo, thì kích hoạt đánh giá lại và rà soát khắc phục khẩn. Ngưỡng này chỉ dùng để **gây chú ý**, không dùng để gán nhãn rủi ro |
| KEV-POL-01 | Khi có đủ ba điều kiện: chính sách đã được áp dụng, applicability đã xác nhận, và finding chưa được khắc phục, thì tạo một **nghĩa vụ khắc phục có hạn**. Hạn là lựa chọn của dự án và phải khai báo. Ngày kích hoạt **giữ nguyên** khi import lại feed. Nghĩa vụ chỉ được đóng khi đã kiểm chứng việc khắc phục, hoặc có ngoại lệ được phê duyệt |
| EPSS-ORDER-01 | Chỉ xếp thứ tự các finding không thuộc KEV **bên trong backlog vá lỗi**, dựa trên một snapshot có ngày. Percentile không phải là xác suất. Không đẩy cả gói vá lỗi lên trên các biện pháp khác chỉ vì gói đó có một CVE có EPSS cao |
| VOI-01 (độ nhạy quyết định) | Tạo việc thu thập bằng chứng khi một thay đổi hợp lý của đầu vào làm đổi thẩm quyền quyết định, đổi escalation, hoặc đổi thứ tự gói. Với đầu vào `unknown` thì xét toàn bộ khoảng giá trị hợp lý. Với phán đoán có confidence thấp thì xét các mức liền kề. Tính lại mọi kịch bản dùng chung bằng chứng đó, và loại trùng theo family. Đây **không phải** giá trị thông tin đo được, vì không có xác suất, chi phí thu thập hay lợi ích kỳ vọng |

**Tính tái lập:**
- Mỗi lần chạy đánh giá đọc **snapshot lưu sẵn** và không lấy dữ liệu trực tiếp từ mạng. Việc import là một bước riêng, chạy bằng tay.
- Nếu feed đã cũ hoặc không lấy được thì phải báo rõ. Phân biệt hai trường hợp "danh mục không đổi" và "làm mới thất bại".

#### 9.10.3 Thay đổi trong cách xếp hạng (§9.4)

1. **Nghĩa vụ và hạn** được xét **trước** mọi so sánh lợi ích và effort. Nghĩa vụ đã quá hạn được hiển thị nổi bật.
2. **Hàng đợi điều tra** là một danh sách riêng. Lợi ích dự kiến còn bất định không được che khuất các nghĩa vụ.
3. **Chia việc xếp thứ tự:** EPSS chỉ xếp thứ tự finding vá lỗi, còn việc so sánh giữa các gói vẫn dùng logic theo family.
4. **Bỏ chọn tham lam.** Chỉ xếp hạng gói đơn và bundle đã được đánh giá so với baseline hiện tại, rồi chạy lại sau khi triển khai.

#### 9.10.4 Thay đổi trong đánh giá (§9.5)

**Thêm các kiểm tra:**
- Chặn liên kết CVE khi applicability chưa được xác nhận.
- Hạn nghĩa vụ giữ nguyên khi import lại feed.
- Đóng nghĩa vụ phải có bằng chứng kiểm chứng.
- Xử lý feed thiếu hoặc feed đã cũ.
- Thứ tự theo EPSS.
- Khoảng giá trị hợp lý của các đầu vào `unknown`.
- Lan truyền thay đổi tới mọi kịch bản dùng chung một bằng chứng.

**Chạy thử một tình huống:** cập nhật chính sách KEV làm **đổi thứ tự hành động** trong khi nhãn rủi ro giữ nguyên.

**Báo cáo độ phủ:** tỷ lệ đầu vào có bằng chứng từ nguồn ngoài được báo cáo **riêng**, không gọi đó là "độ chính xác".

**Giới hạn về độ chính xác:**
- Độ chính xác của mức rủi ro cuối cùng **không kiểm chứng được** trên một hệ thống hư cấu.
- Những gì kiểm chứng được là: phương pháp được áp dụng đúng, độ phủ của bằng chứng, độ nhạy, và các kiểm tra đóng nghĩa vụ.
- Cách tăng độ chính xác nhiều nhất là **khớp đúng danh mục tài sản và có bằng chứng control đã kiểm thử**, chứ không phải thêm công thức tính điểm. Một pilot với workflow thật, khi có điều kiện, sẽ kiểm chứng được tính hữu dụng.

#### 9.10.5 Thứ tự công việc mới (thay cho §9.6)

1. ✅ *(Xong ngày 2026-11-22. Kết quả là [SPEC.md](SPEC.md) và tag `v1`.)* **Prepare v2.1:** cố định v1 bằng tag `v1`. Định nghĩa chính sách KEV, hạn khắc phục và hợp đồng dữ liệu (data contract) cho ba bảng đầu vào cùng snapshot. Sửa COND-01 và các anchor còn hở.
2. ✅ *(Xong ngày 2026-11-22. Xem [SPEC.md](SPEC.md) §7.2.)* **Quy tắc và schema:** chuyển 13 kịch bản sang mô hình mới, và giải thích mọi khác biệt so với v1.
3. ✅ *(Xong ngày 2026-11-22. Phần code và self-check đã chạy trên dữ liệu thử. Snapshot KEV thật (phiên bản 2026.11.20) đã được import. EPSS chưa có.)* **Kiểm tra dữ liệu:** kiểm tra hợp lệ của việc khớp CVE làm bằng tay. Viết bước import snapshot, có manifest và SHA-256.
4. ✅ *(Xong ngày 2026-11-22. Kết quả ở [out/action_report.md](out/action_report.md), xem [SPEC.md](SPEC.md) §7.3.)* **Báo cáo hành động:** sinh nghĩa vụ, chuỗi giải thích, xếp hạng gói, backlog vá lỗi và hàng đợi điều tra.
5. ✅ *(Xong ngày 2026-11-22. Xem [SPEC.md](SPEC.md) §7.4 và [examples/cycle2/](examples/cycle2/). Ví dụ này cũng là phần chạy thử chu kỳ bảo trì của E6.)* **So sánh:** thêm chế độ so sánh giữa hai lần chạy, cho Task 4-1 và 4-2.
6. ✅ *(Xong ngày 2026-11-22. Kết quả ở [out/experiments.md](out/experiments.md), xem [SPEC.md](SPEC.md) §7.5.)* **Thực nghiệm:** chạy E1 đến E6 và các kiểm tra mới ở §9.10.4. Dùng `synth.py` khoảng 200 tài sản.
7. ✅ *(Xong ngày 2026-11-22. Xem [report.md](report.md) mục I–VI. Bản v1 nằm ở Phụ lục A.)* **Viết lại báo cáo:** theo khung nghiên cứu, với kết luận theo hướng "việc gì làm trước".

#### 9.10.6 Bổ sung vào phần hoãn lại và rủi ro

**Hoãn thêm:**
- Web stack (React, FastAPI, PostgreSQL) và xuất PDF/Excel.
- Tự động khớp CPE và phiên bản.
- Lấy feed tự động hoặc phụ thuộc vào feed trực tiếp.
- Ước lượng xác suất likelihood riêng cho từng tổ chức.
- Chọn tham lam.
- Kendall tau-b.
- Nhiều định dạng báo cáo.

**Rủi ro thêm:**

| Rủi ro | Giảm thiểu |
|---|---|
| Khớp CVE sai (false applicability) | Chỉ khớp khi có bằng chứng (CVE-APP-01). Trường hợp không chắc chắn chuyển thành việc điều tra |
| Tạo cảm giác khẩn cấp giả (manufactured urgency) | Chính sách phải có thẩm quyền rõ ràng, và hạn không bị đặt lại khi import lại feed |
| Chỉ nhìn vào lỗ hổng (vulnerability tunnel vision) | Giữ các kịch bản không có CVE và giữ phần so sánh gói biện pháp |

## 10. Kế hoạch v3: bộ công cụ đánh giá có hỗ trợ cho doanh nghiệp vừa và nhỏ (SME)

> Plan chung sau 3 lượt thảo luận Claude ↔ Codex, ngày 2026-11-23. **Chưa triển khai.**
> **Mục tiêu của người dùng:** chạy được cho một doanh nghiệp vừa và nhỏ thật. Yêu cầu bắt buộc vẫn là thiết thực, chính xác, hữu dụng.

### 10.1 Đối tượng và vai trò

**Giả định mặc định [DA]:** SME Việt Nam từ 10 đến 200 nhân sự, không có đội an ninh riêng, chỉ có một người IT bán thời gian hoặc thuê ngoài. Hạ tầng điển hình:
- Microsoft 365 hoặc Google Workspace.
- Một website.
- Phần mềm kế toán, ERP hoặc POS.
- Kho tài liệu dùng chung.
- Laptop và điện thoại.
- Backup.

**Vai trò:**
- **Người IT hoặc nhà cung cấp IT** chạy công cụ.
- **Giám đốc** cung cấp ưu tiên kinh doanh và ra quyết định.

**Ngoài phạm vi ban đầu:** y tế, tài chính, xử lý dữ liệu nhạy cảm quy mô lớn, hệ thống công nghiệp. Các ngành này cần mở rộng phạm vi riêng.

### 10.2 Các khoảng trống phải lấp (rút ra từ lần mô phỏng đầu cuối ngày 2026-11-23)

1. **Effects bị cũ:** effects là các rating tuyệt đối. Khi đầu vào hiện tại thay đổi, script không cảnh báo.
2. **Lỗi bị che:** một finding thiếu trường bắt buộc sẽ che các lỗi khác của nó.
3. **Rơi về dữ liệu demo:** tùy chọn `--data` lặng lẽ lấy dữ liệu của trường đại học khi workspace thiếu file.
4. **Nhập liệu đòi hỏi chuyên môn:** người vận hành phải tự viết phán đoán và effects. Đây là việc của người đánh giá, không phải nhập bảng tính bình thường.
5. **Báo cáo khó dùng cho chủ doanh nghiệp:** báo cáo bằng tiếng Anh, chỉ có mã gói, chỉ đếm family.
6. **Bỏ sót biện pháp nền tảng:** "không vượt ngưỡng" đang bị hiểu ngầm là "không cần làm".

### 10.3 Những gì đã thống nhất

**Độ tin cậy (làm trước mọi thứ khác):**
- **Effects cũ:**
  - Mỗi effect ghi lại nó được đánh giá dựa trên cái gì: các đầu vào liên quan, phạm vi control, phiên bản thư viện và quy tắc.
  - Khi bối cảnh đã đổi, effect chuyển sang **needs review** và bị **loại khỏi lợi ích được tính**, cho tới khi được đánh giá lại.
  - Có một kiểm tra hồi quy cho việc này.
- **Báo lỗi gộp:** báo tất cả lỗi một lần, chỉ bỏ qua các kiểm tra phụ thuộc vào trường đang thiếu.
- **Workspace cô lập:** `python risk.py init <dir>` tạo một workspace đầy đủ cho từng công ty, kèm thư viện có phiên bản được ghim. Lần chạy thật **không bao giờ** rơi về `data/`. Cơ chế overlay chỉ dùng cho ví dụ, và phải bật bằng cờ riêng.
- **Kiểm chứng và ngoại lệ:** kiểm chứng control theo đúng phạm vi. Ngoại lệ phải có người duyệt và ngày hết hạn.

**Thư viện SME** (`library/sme/`, có phiên bản):
- **Khung chính:** **CIS Controls v8.1 IG1**. [TK] Trang [IG1](https://www.cisecurity.org/controls/implementation-groups/ig1) mô tả IG1 gồm 56 safeguard, là "essential cyber hygiene" cho doanh nghiệp "typically small to medium-sized with limited IT and cybersecurity expertise". IG1 không đủ cho mọi SME, nên có thêm các bổ sung kèm lý do.
- **Mapping:** mapping sang SP 800-53 chỉ là tham chiếu tùy chọn. **Mã safeguard của CIS sẽ được đối chiếu với tài liệu CIS khi xây thư viện**, không lấy từ trí nhớ.
- **Effect mặc định** là phán đoán có điều kiện, không phải lời hứa giảm rủi ro. Mỗi effect ghi rõ tác giả, phiên bản, giả định, confidence, môi trường áp dụng và bằng chứng kiểm chứng.

**12 kịch bản mục tiêu:**

| # | Kịch bản | Loại tài sản chính | Nguồn |
|---|---|---|---|
| 1 | Chiếm tài khoản email/SaaS | identity/email | Có chủ đích |
| 2 | Đổi tài khoản ngân hàng của nhà cung cấp để lừa chuyển tiền | finance/ERP | Có chủ đích |
| 3 | Ransomware làm gián đoạn kinh doanh | dịch vụ kinh doanh | Có chủ đích |
| 4 | Mất laptop hoặc điện thoại chưa mã hóa | endpoint/mobile | Không chủ đích |
| 5 | Vô tình chia sẻ công khai tài liệu mật | kho tài liệu | Không chủ đích |
| 6 | Vô tình xóa hoặc hỏng dữ liệu ERP/POS | ứng dụng kinh doanh | Không chủ đích |
| 7 | Backup không dùng được khi cần khôi phục | backup | Không chủ đích |
| 8 | Khai thác website hoặc plugin mở ra internet | web service | Có chủ đích |
| 9 | Nhân viên đã nghỉ vẫn dùng được tài khoản | identity | Có chủ đích |
| 10 | Truy cập từ xa của nhà cung cấp IT bị chiếm hoặc lạm dụng | remote access | Có chủ đích |
| 11 | Dịch vụ SaaS gặp sự cố làm ngưng việc | SaaS | Không chủ đích |
| 12 | Nhân viên xuất trái phép dữ liệu khách hàng | CSDL khách hàng | Có chủ đích |

Thiết bị tương đương được đánh giá theo nhóm. Ransomware và sự cố dịch vụ dùng chung được tạo một lần cho mỗi phạm vi.

**Đầu vào qua phỏng vấn, không qua chấm điểm:**
- **Bảng câu hỏi tiếng Việt** (`answers.csv`). Mỗi câu hỏi có lựa chọn cố định và cụ thể, ví dụ: "Ai được duyệt đổi tài khoản ngân hàng của nhà cung cấp?", "Lần gần nhất thử khôi phục backup là khi nào?", "Bán hàng ngừng tối đa bao lâu thì chịu được?".
- **Quy tắc ANS-xx** chuyển câu trả lời thành đầu vào có kiểu, và phân biệt ba loại:
  - **Quan sát:** cấu hình hoặc kết quả kiểm thử thấy tận mắt, được coi là bằng chứng.
  - **Tự khai** (attestation): vẫn là phán đoán cho tới khi được kiểm tra.
  - **Dự báo:** luôn là phán đoán.
- Câu trả lời gốc, nguồn, ngày và người rà soát đều được giữ trong trace.
- Câu trả lời `unknown` vẫn là `unknown`.
- Người vận hành **không** tự viết residual.

**Hệ quả kinh doanh:**
- Thêm **BUS-01**: hệ quả kinh doanh theo ngưỡng chịu đựng mà chủ doanh nghiệp đồng ý. Ngưỡng tính theo tổn thất và theo khả năng thanh khoản, không chỉ theo tỷ lệ doanh thu.
- **IMP-01 v2** lấy mức cao nhất giữa C/I/A và BUS. Mỗi hệ quả chỉ được tính một lần.
- Các anchor của trường đại học được thay bằng ngưỡng chịu đựng thu thập lúc onboarding: thời gian ngừng tối đa theo từng dịch vụ, khung thời gian then chốt, độ nhạy dữ liệu.

**G-4:**
- Dùng **bảng quyết định nhỏ theo từng kịch bản**: độ phủ, điều kiện tiên quyết, cách vượt qua, các đường tấn công còn lại. Bảng chỉ **gợi ý** một rating, và rating đó được khai báo là phán đoán của mô hình.
- Cho phép ghi đè, kèm lý do. Cho phép `unknown`.
- **Không** dùng cách đếm số rào chắn. Đây là thay đổi so với đề xuất của Claude: Codex chỉ ra rằng kiểm chứng chỉ chứng minh một phép thử cụ thể, và việc liệt kê nhiều gói khác nhau không chứng minh chúng độc lập với nhau.

**Đầu ra cho chủ doanh nghiệp:**
- **Báo cáo HTML tiếng Việt, mở offline.** Gồm **3 việc cần làm tiếp**, mỗi việc ghi lý do kinh doanh, người phụ trách, hạn, effort, cách chứng minh đã làm xong.
- **Khoảng hở nền tảng** vẫn được hiển thị, kể cả khi không vượt ngưỡng nào.
- Trace kỹ thuật nằm sau các tham chiếu.
- **Chi phí:** chỉ ghi khi có ngày, có phạm vi, và tách chi phí một lần với chi phí định kỳ. Báo giá thật của công ty được ưu tiên. Nếu không có căn cứ thì ghi **"chưa ước tính"**.

**Vận hành:**
- Python 3 cùng `run.bat`, đường dẫn có dấu ngoặc kép, thông báo lỗi dễ hiểu. Chưa đóng gói thành file exe.
- **Định dạng CSV:** header máy dùng ASCII, nhãn hiển thị bằng tiếng Việt. Ghi UTF-8 **có BOM** và đọc bằng `utf-8-sig`, để Excel trên Windows hiển thị đúng tiếng Việt. Có tài liệu về dấu phân cách, ngày và số.
- **Nhịp làm việc:** xem lại hành động hằng tháng. Đánh giá lại hằng quý, và sau mỗi sự cố hoặc thay đổi lớn.
- **KEV/EPSS:** không bắt buộc. Làm mới thủ công, không bao giờ gửi danh mục tài sản ra ngoài.
- **Dữ liệu công ty nằm ngoài Git.** Chỉ lưu metadata tối thiểu và tham chiếu bằng chứng đã che thông tin nhạy cảm. Không lưu mật khẩu hay dữ liệu khách hàng. Thư mục có phân quyền truy cập và được backup.

**Pháp lý:**
- [TK] Luật Bảo vệ dữ liệu cá nhân số **91/2025/QH15**, Quốc hội ban hành ngày 26/06/2025, **có hiệu lực từ 01/01/2026** ([chinhphu.vn](https://chinhphu.vn/?docid=214590&pageid=27160)).
- Bảng câu hỏi sẽ có thêm câu hỏi về xử lý dữ liệu cá nhân, nhà cung cấp và chuyển dữ liệu ra nước ngoài.
- **Nghĩa vụ pháp lý cụ thể chưa được mã hóa thành quy tắc.** Trước đó phải xác minh văn bản hướng dẫn, nghĩa vụ theo ngành, các trường hợp miễn trừ và thời hạn.

### 10.4 Các giai đoạn và tiêu chí nghiệm thu

| Giai đoạn | Nội dung | Tiêu chí nghiệm thu (kiểm thử được) |
|---|---|---|
| **P1 Độ tin cậy** | Bốn sửa đổi độ tin cậy ở §10.3 | Kiểm tra hồi quy cho thấy effect cũ không thể đóng góp lợi ích được tính. Finding có nhiều lỗi được báo đủ. Workspace thiếu file không bao giờ mượn dữ liệu demo. Phạm vi control và hạn ngoại lệ được tôn trọng |
| **P2a Bản phát hành nhỏ nhất có ích** | `init`, các vai trò, **3 nhánh câu hỏi**: chiếm email, lừa chuyển tiền, khôi phục thất bại. ANS → đầu vào có kiểu. Báo cáo HTML tiếng Việt có 3 việc cần làm. Lưu baseline. Chạy lại lần hai sau khi hoàn thành một hành động | Một nhà cung cấp IT khởi tạo và chạy được workspace chỉ bằng tài liệu hướng dẫn. Báo cáo nêu rõ hành động, người làm, lý do, hạn, effort, cách kiểm chứng. Phạm vi ghi rõ là 3 dịch vụ. Rating thiếu dữ liệu vẫn là `unknown` |
| **P2b Mở rộng** | Hiệu chỉnh ngưỡng chịu đựng (BUS-01), effect có điều kiện, 9 kịch bản còn lại. Thêm onboarding KEV khi SME có phần mềm tự quản lý | Câu trả lời sinh ra đúng các kịch bản áp dụng được, có thể truy vết. Ngưỡng chịu đựng ảnh hưởng đúng hệ quả cần ảnh hưởng |
| **P3 Pilot và chỉnh sửa** | Một SME đồng ý tham gia. Một lần baseline và một lần theo dõi | Đo được: thời gian onboarding, mức hỗ trợ cần thêm, số lỗi kiểm tra hợp lệ, độ đầy đủ của bằng chứng, mức hiểu báo cáo của chủ doanh nghiệp, các quyết định đã đưa ra, các hành động được kiểm chứng độc lập. Chỉ sửa những vấn đề đã được chứng minh |

**Giao thức pilot:**
- Có văn bản đồng ý của tổ chức.
- Chỉ định một người vận hành và một người ra quyết định.
- Thống nhất phạm vi, quyền truy cập, thời gian lưu trữ và việc xóa dữ liệu, cũng như sự đồng ý công bố.
- Dữ liệu định danh công ty chỉ nằm trên máy cục bộ. Chỉ công bố kết quả đã ẩn danh và đã được duyệt.
- **Không** suy ra rằng xác suất sự cố đã giảm chỉ từ một pilot ngắn.

### 10.5 Rủi ro của kế hoạch

| Rủi ro | Giảm thiểu |
|---|---|
| Tự tin sai vào rating và effect được gợi ý | Hiện rõ các giả định và các đường tấn công còn lại. Bắt buộc rà soát theo bối cảnh. Effect cũ bị loại khỏi lợi ích được tính |
| Đánh giá biến thành giấy tờ định kỳ | Pilot luồng 3 nhánh trước. Đo công sức của người vận hành và mức hiểu của chủ doanh nghiệp. Bỏ các câu hỏi không phục vụ quyết định |
| Lộ thông tin nhạy cảm của công ty qua workspace hoặc báo cáo | Thu thập ở mức tối thiểu. Che thông tin trong bằng chứng. Cô lập từng công ty, giới hạn quyền truy cập, thống nhất việc lưu trữ và xóa |

### 10.6 Không làm hoặc hoãn lại

- Web nhiều người dùng, server, database.
- Tự phát hiện tài sản và tự khớp CPE.
- Chứng nhận tuân thủ.
- Tuyên bố về độ chính xác dự báo.
- Mở rộng sang nhiều ngành.
- Bảng giá VND cho toàn bộ thư viện.
- Bắt buộc thiết lập KEV/EPSS.
- Nhiều định dạng báo cáo.
- Đóng gói thành file exe.

**12 kịch bản là danh mục mục tiêu, không phải điều kiện để phát hành.** `synth.py` được giữ lại làm công cụ kiểm thử hồi quy và quy mô.

### 10.7 Ghi nhận thảo luận

**Thay đổi so với đề xuất của Claude:**
- **G-4:** bỏ cách đếm "số rào chắn đã kiểm chứng", chuyển sang bảng quyết định theo từng kịch bản.
- **Câu trả lời có trích dẫn tài liệu:** không tự động thành bằng chứng, mà vẫn là tự khai.
- **Tổn thất tài chính:** không gộp vào I-01, mà tách thành BUS-01 riêng.
- **Bảng giá:** không đưa giá VND chung vào thư viện.

**Thay đổi so với đề xuất của Codex:** Claude bổ sung các điểm sau và Codex đồng ý:
- Lệnh `init`, cùng nguyên tắc không bao giờ rơi về dữ liệu demo.
- Quy tắc ANS-xx.
- UTF-8 có BOM.
- `run.bat`.
