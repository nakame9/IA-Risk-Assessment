# Đặc tả đánh giá v2.1 (Prepare)

> **Phiên bản đặc tả:** `SPEC-2.1.0`, ngày 2026-11-22.
> Đây là bước 1 của [PLAN.md](PLAN.md) §9.10.5. Bản v1 được cố định bằng tag `v1`.
> **Nhãn dùng trong file:**
> - **[TK]** là nội dung lấy từ nguồn ngoài.
> - **[DA]** là **lựa chọn của dự án**. Có thể đổi, nhưng mỗi lần đổi phải tăng phiên bản đặc tả.

---

## 1. Ánh xạ bước Prepare của NIST SP 800-30 Rev.1

**[TK]** Bước 1 (Prepare) của SP 800-30 Rev.1 gồm Task 1-1 đến 1-5. Số hiệu và tiêu đề task đã được đối chiếu với text trích từ PDF.

| Task | Nội dung theo NIST | Ở dự án này |
|---|---|---|
| 1-1 | Mục đích của đánh giá | Trả lời câu hỏi **"việc gì làm trước"**: xếp hạng các biện pháp bảo đảm thông tin, với lý do lần ngược được về bằng chứng. Phục vụ các quyết định ở §1.6 của [report.md](report.md) (chấp nhận, ủy quyền, ngoại lệ, escalate) |
| 1-2 | Phạm vi: phạm vi áp dụng trong tổ chức, khung thời gian, các cân nhắc về kiến trúc và công nghệ | Mọi tài sản có trong `data/assets.csv`. Horizon 12 tháng [DA]. Case minh họa là cổng hồ sơ sinh viên, ranh giới như §1.2 của report. Thử quy mô bằng dữ liệu tổng hợp khoảng 200 tài sản |
| 1-3 | Giả định và ràng buộc | Các giả định A-01 → A-06 của report vẫn giữ. Bổ sung ở §2 bên dưới |
| 1-4 | Nguồn thông tin về mô tả hệ thống, mối đe dọa, lỗ hổng và tác động | §5: quy trình thu thập bằng chứng và hai nguồn ngoài KEV, EPSS |
| 1-5 | Mô hình rủi ro và cách tiếp cận phân tích | Định tính, dùng bảng G-5 và I-2 nguyên văn. Hướng phân tích theo mối đe dọa. Các quy tắc có mã ở §3 |

## 2. Giả định và ràng buộc bổ sung (Task 1-3)

| Mã | Nội dung |
|---|---|
| A-07 | **[DA]** Không cộng, trừ hay chia trên các nhãn thứ bậc. Mọi phép kết hợp đều dùng bảng tra |
| A-08 | **[DA]** Feed ngoài (KEV, EPSS) chỉ được đọc từ **snapshot lưu sẵn**. Lần chạy đánh giá không truy cập mạng |
| A-09 | **[DA]** Việc khớp CVE với thành phần làm **bằng tay**, có bằng chứng đi kèm. Không tự động khớp CPE |
| A-10 | **[DA]** Dữ liệu tổng hợp chỉ dùng để thử quy mô và độ ổn định. Không dùng làm bằng chứng cho độ chính xác |
| A-11 | **[DA]** Script chỉ gắn cờ những việc mà chính sách yêu cầu. Script không bao giờ tự chấp nhận rủi ro hay đóng nghĩa vụ |

## 3. Bộ quy tắc

Mỗi quy tắc có mã và phiên bản riêng. Cột **thuộc tính đọc** liệt kê đúng những gì quy tắc được phép đọc. Ở bước 2, `--check` phải từ chối mọi thuộc tính không có trong danh sách này.

### 3.1 Quy tắc rating

| Mã | Phiên bản | Thuộc tính đọc | Quy tắc |
|---|---|---|---|
| F2-01 | 1.0 | `control_status` ∈ {absent_unplanned, planned_compensated, partial, implemented, implemented_assessed_effective, unknown} | absent_unplanned → VH; planned_compensated → H; partial → M; implemented → L; implemented_assessed_effective → VL; unknown → `unknown`. Đây là **[DA]** diễn giải bảng F-2. Riêng mức VL đã khớp nguyên văn với định nghĩa của F-2 |
| G3-01 | 1.0 | `annual_frequency` (số thực ≥ 0) | `f ≤ 0.1` → VL; `0.1 < f < 1` → L; `1 ≤ f < 10` → M; `10 ≤ f ≤ 100` → H; `f > 100` → VH. Các dải lấy từ G-3. **[DA]** cách xử lý ranh giới: tại đúng 10/năm thì xếp H, tại đúng 0.1/năm thì xếp VL |
| C-01 | 1.0 | `info_class` ∈ {public, nonpublic, sensitive}; `records_disclosed` (số nguyên ≥ 0) | public hoặc 0 bản ghi → VL. Với nonpublic, các khoảng 1–9 / 10–1.000 / >1.000 → L / M / H. Với sensitive, cùng các khoảng → M / H / H. **[DA]** |
| I-01 | 1.0 | `integrity_consequence` ∈ {negligible, limited, serious, severe}; `corrected_before_use` ∈ {yes, no} | negligible / limited / serious / severe → VL / L / M / H. Nếu `corrected_before_use = yes` thì mức tối đa là L. Chỉ phát hiện mà không sửa thì không giảm mức. **[DA]** |
| A-01 | 1.0 | `outage_hours` (số thực ≥ 0); `in_critical_window` ∈ {yes, no} | 0 → VL. Khi no: `(0,1)` → VL, `[1,24)` → L, `[24,168]` → M, `>168` → H. Khi yes: `(0,24)` → M, `≥24` → H. **[DA]** Quy tắc này lấp khoảng 3–7 ngày còn hở ở anchor của v1 |
| IMP-01 | 1.0 | Kết quả của C-01, I-01, A-01; `multiple_severe_documented` ∈ {yes, no} | Lấy mức cao nhất trong ba kết quả. Chỉ xếp VH khi `multiple_severe_documented = yes` **và** mức cao nhất là H. Có bất kỳ đầu vào nào là `unknown` thì impact là `unknown` |
| COND-01 | 1.0 | Loại sự kiện: không chủ đích | Sự kiện mất dịch vụ được định nghĩa là xảy ra **vào bất kỳ lúc nào**. Thời điểm trùng khung then chốt chỉ xét **một lần**, ở G-4. Với sự kiện có chủ đích, việc kẻ tấn công chọn thời điểm là một phần của sự kiện và được xét ở G-2 |

Các đầu vào còn lại là **phán đoán**, phải có `rationale` và `confidence`:
- G-2: mức khởi phát của nguồn có chủ đích.
- G-4: khả năng gây tác động bất lợi.
- Các đặc tính của nguồn đe dọa (D-3 → D-6).
- `info_class`, `integrity_consequence`, `in_critical_window`.

**Anchor bổ sung cho G-4** [DA]. Mỗi anchor nêu điều kiện **sau khi** đã tính các control hiện có:

| Mức | Anchor |
|---|---|
| VH | Không có rào chắn nào nằm giữa sự kiện và tác động. Ví dụ: backup dùng chung thông tin xác thực với hệ thống chính |
| H | Chỉ có rào chắn mức thấp, đã biết là bị vượt qua thường xuyên. Ví dụ: chỉ có antivirus trước malware đã biết |
| M | Có ít nhất một rào chắn đã triển khai một phần, hoặc chưa được kiểm thử |
| L | Có ít nhất một rào chắn đã triển khai đầy đủ, ví dụ MFA. Hoặc chỉ gây tác động trong một khung thời gian hẹp (COND-01) |
| VL | Có từ hai rào chắn độc lập trở lên, đã triển khai đầy đủ và đã được kiểm thử |

### 3.2 Quy tắc dùng dữ liệu khai thác (threat intelligence)

| Mã | Phiên bản | Quy tắc |
|---|---|---|
| CVE-APP-01 | 1.0 | Chỉ đặt `applicability = confirmed` khi có bằng chứng về sản phẩm, phiên bản, cấu hình và điều kiện tiên quyết. Nếu không chắc thì ghi `suspected`, và finding đó vào hàng đợi điều tra |
| G2-TI-01 | 1.0 | Tư cách thành viên KEV và điểm EPSS (kèm ngày) được hiển thị như **bằng chứng ngoài** cho G-2. Feed tự nó **không** gán rating |
| G4-LOCAL-01 | 1.0 | G-4 đánh giá theo đường tấn công thực tế, quyền cần có, tình trạng vá và control đã kiểm thử. Không dùng lại tín hiệu feed cho G-4 hay impact |
| TI-ABS-01 | 1.0 | Không có trong KEV không có nghĩa là chưa bị khai thác. Thiếu EPSS không có nghĩa là bằng 0 |
| TI-RANSOM-01 | 1.0 | `knownRansomwareCampaignUse = Known` thì đưa các kịch bản ransomware liên quan vào danh sách rà soát lại. Giá trị `Unknown` nghĩa là chưa xác nhận |
| TI-REV-01 | 1.0 | Kích hoạt rà soát lại khi có một mục KEV mới áp dụng được, hoặc khi `epss ≥ EPSS_REVIEW` (§4). Ngưỡng này chỉ dùng để gây chú ý, không gán nhãn rủi ro |
| KEV-POL-01 | 1.0 | Chính sách ở §4 |
| EPSS-ORDER-01 | 1.0 | Chỉ xếp thứ tự các finding không thuộc KEV bên trong backlog vá lỗi: theo `exposure`, sau đó theo EPSS giảm dần. Finding thiếu điểm EPSS ghi là chưa xếp hạng. Percentile chỉ để hiển thị, không phải là xác suất |
| VOI-01 | 1.0 | Độ nhạy quyết định. Với đầu vào `unknown`, xét mọi mức hợp lệ. Với phán đoán có confidence Low, xét các mức liền kề. Với số liệu, xét giá trị sát ranh giới của quy tắc. Nếu thẩm quyền quyết định, escalation hoặc thứ tự gói có thể đổi thì tạo một việc thu thập bằng chứng |

## 4. Chính sách khắc phục KEV (KEV-POL-01)

> **[TK]** BOD 22-01 của CISA đã bị **thu hồi** và được thay bằng BOD 26-04 (trang của CISA ghi ngày 10/06/2026). Chính sách dưới đây là **chính sách tổ chức hư cấu tự chọn áp dụng**, không phải tuân thủ quy định liên bang.
> Các thông số là **[DA]**. Hạn 14 ngày lấy cảm hứng từ mốc mặc định "two weeks" của BOD 22-01 khi còn hiệu lực.

| Tham số | Giá trị | Nguồn |
|---|---|---|
| `policy_version` | `KEV-POL-1.0` | DA |
| Điều kiện kích hoạt | Đủ cả ba: CVE có trong snapshot KEV, `applicability = confirmed`, `remediation_state` ≠ `remediated_verified` | DA |
| Hạn khi `exposure = internet` | 14 ngày kể từ `obligation_triggered_on` | DA |
| Hạn khi `exposure` = `internal` hoặc `isolated` | 30 ngày | DA |
| `obligation_triggered_on` | Ngày sớm nhất mà **cả** CVE thuộc snapshot KEV **và** applicability = confirmed. Ngày này **giữ nguyên** khi import lại feed | DA |
| Đóng nghĩa vụ | `remediation_state = remediated_verified` kèm `evidence_ref`, hoặc có một ngoại lệ được Risk executive phê duyệt (§1.4 của report), có hạn | DA |
| `EPSS_REVIEW` | 0.10, tức xác suất 10% trong 30 ngày, chỉ dùng cho TI-REV-01. **[TK]** FIRST nói rõ **không có ngưỡng áp dụng chung**, nên đây là ngưỡng gây chú ý do dự án tự chọn | DA |

## 5. Quy trình thu thập bằng chứng (Task 1-4)

Mỗi bằng chứng có một `evidence_ref` duy nhất và được ghi kèm: loại, nguồn, người thu thập, ngày quan sát. Bằng chứng quá tuổi tối đa trong bảng dưới được báo là **cũ** (stale) trong báo cáo hành động. Tuổi tối đa là **[DA]**.

| Loại | Ví dụ | Tuổi tối đa |
|---|---|---|
| `inventory` | Bảng kê tài sản, xuất từ CMDB | 180 ngày |
| `config` | Ảnh chụp hoặc file xuất cấu hình IAM, MFA, backup | 90 ngày |
| `test` | Biên bản thử khôi phục, kết quả pentest | 365 ngày |
| `scan` | Kết quả quét lỗ hổng, advisory của nhà cung cấp | 30 ngày |
| `feed` | Snapshot KEV, EPSS | 7 ngày |
| `incident` | Lịch sử sự cố, ticket | 365 ngày |
| `interview` | Phỏng vấn owner, dùng cho phán đoán | 180 ngày |
| `assumption` | Giả định [GĐ] của hệ thống hư cấu | Không hết hạn, nhưng luôn được hiển thị là giả định |

## 6. Data contract

**Quy ước chung cho mọi file:**
- File CSV mã hóa UTF-8, có dòng tiêu đề.
- Ngày tháng theo `YYYY-MM-DD`.
- Danh sách nằm trong một ô thì ngăn cách bằng `;`.
- Giá trị `unknown` được phép ở bất kỳ ô rating hoặc bằng chứng nào. Ô trống chỉ được phép ở các cột ghi "tùy chọn".

### 6.1 `data/assets.csv` (người vận hành sửa)

**Các cột:**
- Giữ các cột hiện có: `asset_id, name, kind, component_ids, owner, confidentiality, integrity, availability, rationale`.
- Thêm:
  - `asset_class` ∈ {pii_database, web_service, identity_service, backup_store, admin_endpoint, email, document_store, cloud_config, log_store}
  - `system_id`
  - `vendor`, `product`, `version` (tùy chọn, dùng cho thành phần kỹ thuật)
  - `exposure` ∈ {internet, internal, isolated}

**Khóa:** `asset_id` là duy nhất.

### 6.2 `data/inputs.csv` (người vận hành sửa; dạng dài)

`subject_id, attribute, value, mode, evidence_ref, rationale, confidence, assessor, observed_on`

| Cột | Ràng buộc |
|---|---|
| `subject_id` | Một trong các mã: R-xx (kịch bản), AS-xx (tài sản), F-xxx (finding) |
| `attribute` | Phải nằm trong danh sách thuộc tính được khai báo ở §3.1 hoặc §6.2.1. Thuộc tính lạ sẽ bị từ chối |
| `mode` | ∈ {evidence, judgment} |
| `confidence` | ∈ {High, Medium, Low} |
| `evidence_ref` | Bắt buộc khi `mode = evidence` |
| `rationale` | Bắt buộc khi `mode = judgment` |

**Khóa:** cặp (`subject_id`, `attribute`) là duy nhất.

#### 6.2.1 Thuộc tính của finding (F-xxx)

| Thuộc tính | Giá trị |
|---|---|
| `cve_id` | Dạng `CVE-YYYY-NNNN+` |
| `component_id` | Một `asset_id` có thật |
| `applicability` | {confirmed, suspected, not_applicable} |
| `remediation_state` | {open, mitigated_unverified, remediated_verified, exception} |
| `first_confirmed_on` | Ngày |
| `obligation_triggered_on` | Ngày. Script sinh ra lần đầu, sau đó **không được ghi đè** |
| `obligation_policy_version` | Ví dụ `KEV-POL-1.0` |

**Khóa:** mỗi cặp (`component_id`, `cve_id`) chỉ có một F-xxx.

### 6.3 `data/controls.csv` (mới; người vận hành sửa)

`scope_id, package_id, status, evidence_ref, verified_on`

| Cột | Ràng buộc |
|---|---|
| `scope_id` | Một `asset_id` hoặc một `system_id` |
| `package_id` | Một mã gói T-xx |
| `status` | Dùng đúng tập giá trị của `control_status` ở F2-01 |
| `verified_on` | Bắt buộc khi `status = implemented_assessed_effective` |

**Khóa:** cặp (`scope_id`, `package_id`) là duy nhất.

### 6.4 Do người phụ trách mô hình quản lý

| File | Vai trò |
|---|---|
| `data/templates.csv` | Template kịch bản. Mỗi template ghi quy tắc được dùng, không ghi rating |
| `data/packages.csv` | Danh sách gói biện pháp |
| `data/effects.csv` | Hiệu ứng của từng tập gói lên từng rủi ro |

Schema của ba file này nằm ở [PLAN.md](PLAN.md) §9.3, và sẽ được cài đặt ở bước 2.

### 6.5 Snapshot và manifest (sinh tự động bởi bước import)

**Thư mục:** `data/snapshots/<source>/<YYYY-MM-DD>/`. Bên trong là file gốc tải về, không sửa gì.

**`data/snapshots/manifest.csv`:**

`source, url, retrieved_on, published_on, version, sha256, license_ref, status`

- `source` ∈ {kev, epss}
- `status` ∈ {ok, refresh_failed}

**Ghi chú về license:**
- **[TK]** KEV dùng giấy phép CC0 1.0 (kho `cisagov/kev-data`).
- **[TK]** FIRST yêu cầu ghi nguồn khi dùng dữ liệu EPSS. Điều khoản sử dụng dịch vụ của FIRST **chưa được đọc**. Cần đọc trước khi phân phối lại snapshot EPSS.

## 7. Thay đổi so với v1

- **COND-01:** sửa sự kiện của R-09 và R-13 thành "vào bất kỳ lúc nào".
  - **Rating giữ nguyên.** G-4 vốn đã được hạ vì xác suất trùng kỳ đăng ký, nay đó là chỗ **duy nhất** điều kiện thời điểm được xét.
  - Đã cập nhật trong `data/risk_register.csv` và report.md §2.5 và §3.3.
- **Anchor tính sẵn sàng:**
  - Bảng ở report §1.5e được chỉnh cho khớp với A-01, lấp khoảng 3–7 ngày còn hở.
  - **Không rating nào của v1 bị đổi**: R-06, R-09, R-13 vẫn là Moderate theo A-01 (gián đoạn vài giờ trong kỳ đăng ký).
- **Các quy tắc C-01, I-01, G-4:** chưa áp dụng lại cho 13 kịch bản. Việc này thuộc bước 2, và ở đó mọi khác biệt so với v1 phải được giải thích.
