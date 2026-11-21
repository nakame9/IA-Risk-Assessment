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

### 3.3 Quy tắc cho hiệu ứng của gói biện pháp (thêm ở bước 4)

| Mã | Phiên bản | Quy tắc |
|---|---|---|
| EFF-01 | 1.0 | Trong residual **dự kiến**, G-4 không được là Very Low. Theo anchor ở §3.1, mức VL chỉ đạt được khi rào chắn **đã được kiểm thử**. Muốn lên VL thì phải có bằng chứng kiểm chứng (report §4.5) |
| EFF-02 | 1.0 | Một tập gói lớn hơn không được cho kết quả tệ hơn bất kỳ tập con nào của nó, xét trên từng thành phần: initiation, adverse, impact |
| Hiệu ứng thưa | 1.1 | Hiệu ứng của ứng viên S lên kịch bản r là dòng trong `effects.csv` có **đúng** tập `S ∩ applicable(r)`. Không có dòng đó thì hiệu ứng là `unknown`. Không bao giờ ghép các factor từ nhiều dòng khác nhau. **Thay đổi ở bản 1.1 (bước 6):** ứng viên chỉ bị gắn nhãn *incomplete* khi family chưa biết hiệu ứng **còn có thể vượt ngưỡng**, tức mức nặng nhất ≥ Moderate. Ứng viên incomplete được xếp ở một danh sách riêng, ghi lợi ích là cận dưới (≥), và ứng viên có ít family chưa biết hơn được xếp trước. Lý do thay đổi: ở quy mô 200 tài sản, bản 1.0 loại hết mọi ứng viên (§7.5) |
| Xếp hạng | 1.0 | Lợi ích = các family có rủi ro nặng nhất vượt xuống dưới High, và các family vượt xuống dưới Moderate. Gói đơn được lọc Pareto theo (hai con số lợi ích) so với effort, rồi xếp theo thứ tự: số family xuống dưới High, số family xuống dưới Moderate, effort. Bundle được liệt kê riêng, với effort ghi là "not assessed", tức **không cộng** các effort tier. Nghĩa vụ KEV đứng trên mọi thứ hạng |
| VOI-01 (thông số) | 1.0 | **[DA]** Với `initiation_likelihood` và `adverse_impact_likelihood` có confidence Low, thử mức liền kề ±1. Với các thuộc tính số có confidence khác High, thử ×0,5 và ×2. Đầu vào sẽ được đưa vào hàng đợi điều tra nếu thay đổi đó làm đổi thẩm quyền quyết định (owner, delegated, senior) hoặc đổi escalation |
| Cửa sổ "sắp tới hạn" | 1.0 | **[DA]** 30 ngày, dùng cho mục 1 của báo cáo hành động |

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

`source, url, retrieved_on, published_on, version, sha256, license_ref, status, path`

- `source` ∈ {kev, epss}
- `status` ∈ {ok, refresh_failed}
- `path` là đường dẫn tương đối tính từ `data/`. Cột này được thêm ở bước 3.

**Lệnh import** (bước 3):
```
python risk.py import kev|epss FILE [--url URL]
```
- File được tải về bằng tay trước. Lệnh import **không** truy cập mạng.
- **Định dạng chấp nhận:**
  - KEV: file JSON. Trong mỗi mục phải có `cveID` và `knownRansomwareCampaignUse`. Phiên bản lấy từ `catalogVersion`, ngày phát hành lấy từ `dateReleased`.
  - EPSS: file CSV hoặc `.csv.gz`, có dòng đầu dạng `#model_version:…,score_date:…` và tiêu đề `cve,epss,percentile`.
  - **KEV đã được đối chiếu với file thật** ngày 2026-11-22. File có `catalogVersion` = 2026.11.20, `dateReleased` = 2026-11-20 và 1.790 mục, khớp với trường `count`. Trong đó 361 mục có `knownRansomwareCampaignUse = Known`, còn 1.429 mục là `Unknown`. Mỗi mục còn có các trường `forensicTriage`, `cwes`, `notes`; dự án chưa dùng các trường này.
  - **Định dạng EPSS chưa được đối chiếu** với file thật. Nếu sai định dạng thì lệnh import báo lỗi rõ ràng.
- **Khi import:**
  - File có SHA-256 trùng một snapshot đã có thì không lưu thêm.
  - File lỗi thì ghi một dòng `refresh_failed`, và giữ nguyên snapshot hợp lệ gần nhất.
- **Khi chạy đánh giá:**
  - Kiểm tra lại SHA-256 của snapshot. Nếu không khớp thì dừng.
  - Snapshot cũ hơn 7 ngày (tính theo `--as-of`) bị cảnh báo là cũ (stale).
- **Snapshot EPSS không được commit** (`.gitignore`), vì điều khoản sử dụng dịch vụ của FIRST chưa được đọc. Manifest vẫn được commit, nên ai tải cùng file đó về đều kiểm chứng lại được bằng SHA-256.

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
- **Các quy tắc C-01, I-01, G-4:** đã áp dụng lại cho 13 kịch bản ở bước 2. Kết quả ở §7.2.

### 7.2 Kết quả chuyển đổi 13 kịch bản (bước 2, ngày 2026-11-22)

**Dữ liệu sau khi chuyển đổi:**
- `data/templates.csv`: 13 template.
- `data/inputs.csv`: 117 dòng đầu vào.
- `data/controls.csv`, `data/packages.csv`: 13 dòng mỗi file.
- `data/effects.csv`: 9 dòng.
- `data/risk_register.csv`: chỉ còn thông tin của từng kịch bản và quyết định.

Các rating suy ra được (overall likelihood, mức rủi ro, residual) giờ do `risk.py` tính, và **không lưu trong CSV**.

**Quy tắc chấm mới cho ra cùng kết quả với v1 ở các chỗ sau:**
- **Impact:** C-01, I-01, A-01 và IMP-01 cho ra **đúng** mức impact của v1 ở cả 13 kịch bản.
- **Initiation của nguồn không chủ đích:** G3-01 cho ra **đúng** mức của v1, với tần suất giả định [GĐ] như sau: R-07 0,5/năm; R-08 0,3/năm; R-09 0,5/năm; R-10 30/năm; R-13 3/năm.
- **Initiation của nguồn có chủ đích (G-2):** vẫn là phán đoán, nên giữ nguyên.

**Khác biệt: 4 rating G-4 được chấm lại theo anchor ở §3.1:**

| Kịch bản | G-4 v1 → v2.1 | Mức rủi ro v1 → v2.1 | Lý do theo anchor |
|---|---|---|---|
| R-07 | High → **Very High** | Moderate → Moderate | Kho dữ liệu đã mở ra Internet thì không còn rào chắn nào giữa sự kiện và tác động. MFA của console không chặn được việc truy cập dữ liệu đã bị lộ |
| R-08 | High → **Moderate** | Moderate → **Low** | Backup có tồn tại nhưng chưa từng được thử, đúng định nghĩa "một rào chắn chưa được kiểm thử" của mức M. v1 chấm H vì cho rằng "chưa thử thì dễ thất bại", tức đã lấy chuyện chưa thử làm lý do nâng mức, trong khi anchor xếp trường hợp này vào M |
| R-11 | Moderate → **High** | Moderate → **High** | Rào chắn chỉ có antivirus và spam filter, đúng ví dụ của mức H. **v1 không nhất quán:** R-01 có cùng rào chắn này nhưng được chấm G-4 = H |
| R-12 | High → **Very High** | Moderate → Moderate | Insider đã có sẵn vai trò được phép xuất dữ liệu, nên việc giới hạn theo vai trò không còn là rào chắn |

**Tổng hợp:**

| | High | Moderate | Low |
|---|---|---|---|
| Rủi ro hiện tại v1 | 1 | 8 | 4 |
| Rủi ro hiện tại v2.1 | 2 | 6 | 5 |
| Residual (dự kiến) sau bước 2, vẫn dùng effects của v1. *Đã được thay bằng §7.3: 0 / 2 / 11* | 0 | 3 | 10 |

**Hệ quả đối với quyết định:**
- **R-11** giờ ở mức High, nên phải xử lý hoặc cần Risk executive cấp ngoại lệ. Quyết định mitigate trong D-R11 vẫn đúng, và residual vẫn là Moderate.
- **R-08** giờ ở mức Low, nên owner được phép chấp nhận. Quyết định mitigate vẫn được giữ, vì gói T-02 vốn cần cho R-01.
- Độ nhạy: R-08 nằm đúng ranh giới. Nếu G-4 quay lại H thì R-08 thành Moderate. Đây là ứng viên cho hàng đợi điều tra (VOI-01): bằng chứng cần thu thập là biên bản thử khôi phục.

### 7.5 Bước 6: thực nghiệm E1–E6 (ngày 2026-11-22)

**Cách chạy:** `python synth.py`.
- Lệnh sinh ra `synthetic/`: 200 tài sản, 210 kịch bản, 5 hệ thống, 11 template. Bộ sinh có phiên bản `SYNTH-1.0`, seed 20261122. Thư mục này không được commit, nhưng có thể sinh lại y hệt.
- Lệnh chạy E1–E6 trên cả case portal lẫn dữ liệu tổng hợp, rồi ghi [out/experiments.md](out/experiments.md).

**Bộ sinh dữ liệu tổng hợp:**
- Các quy tắc trong `risk.py` đã được cố định **trước** khi viết bộ sinh.
- **Phản ví dụ được thêm độc lập:**
  - 3% đầu vào là `unknown`.
  - 5% effect của gói đơn bị bỏ trống.
  - Có giá trị nằm đúng ranh giới của quy tắc: tần suất 0,1 / 1 / 10 / 100; số bản ghi 9 / 10 / 1.000 / 1.001; số giờ gián đoạn 1 / 24 / 168.
- Finding dùng mã CVE thật lấy từ KEV.
- **Giả định của bộ sinh:** hiệu ứng của gói đơn được sinh theo một bảng giả định. Hiệu ứng của bundle là mức tốt nhất của các gói đơn trong nó. Đây là giả định của dữ liệu tổng hợp, **không phải** cách mô hình suy luận.

**Kết quả chính** (số liệu đầy đủ ở [out/experiments.md](out/experiments.md)):

| Phép đo | Case portal | Tổng hợp (200 tài sản) | Đọc kết quả |
|---|---|---|---|
| E2 Tính tất định | Cùng state khi chạy hai lần | Cùng state; sinh lại hai lần ra file giống hệt | Tính toán lặp lại được. Điều này **không** chứng minh bằng chứng là đúng |
| E4 Quy mô | 13 kịch bản, khoảng 0,02 s | 210 kịch bản, khoảng 0,05 s | Thời gian chạy không phải là điểm nghẽn |
| E1 Initiation có nguồn gốc từ quy tắc kèm bằng chứng | 38,5% | 34,8% | **Adverse (G-4) vẫn 100% là phán đoán.** Đây là giới hạn lớn nhất về tính khách quan của mô hình |
| E1 Impact | 100% "quy tắc dùng phán đoán" | 81,9% quy tắc dùng phán đoán, 16,7% unknown | Quy tắc gom phán đoán lại một cách nhất quán, nhưng không thay được bằng chứng |
| E3 Tỷ lệ nhiễu làm đổi mức của ít nhất một rủi ro | 25,4% | 14,3% | Thang 5 mức nhạy ở ranh giới. Đây là lý do có hàng đợi điều tra VOI-01 |
| E3 Khuyến nghị đứng đầu bị đổi | 8,5% | 0,0% | Thứ tự gói khá ổn định |
| E3 Cặp bị đảo thứ tự | 0,9% | 0,1% | Như trên |
| E5 Mô hình so với chọn theo rủi ro / theo effort, cùng effort tier, đếm số family xuống dưới Moderate | 4 so với 0 / 0 | 34 so với 19 / 22 | Mô hình chọn được gói vượt nhiều ngưỡng hơn. Đây chỉ là so sánh **bên trong** dữ liệu, có nguy cơ vòng lặp (§9.9) |
| E6 Có đủ chuỗi giải thích | 13/13 | 167/210 (79,5%) | 43 rủi ro thiếu chuỗi giải thích vì có đầu vào `unknown`. Chúng được đưa vào hàng đợi điều tra |

**Phát hiện dẫn tới thay đổi quy tắc (Hiệu ứng thưa 1.1):**
- Với bản 1.0, ở quy mô 200 tài sản **không còn ứng viên nào** được xếp hạng. Mỗi gói chạm vào rất nhiều kịch bản, nên chỉ cần thiếu một effect là gói bị loại. Quy tắc đúng về nguyên tắc, nhưng không dùng được trong thực tế.
- Bản 1.1 vẫn giữ nguyên tắc không đoán khi thiếu dữ liệu, nhưng có ba thay đổi:
  - Chỉ đánh dấu incomplete khi thiếu dữ liệu thật sự có thể làm đổi kết quả.
  - Xếp các ứng viên incomplete theo lợi ích cận dưới.
  - Hiện rõ các family còn thiếu effect, để người phụ trách mô hình biết cần đánh giá bổ sung chỗ nào.

**Giới hạn của thực nghiệm:**
- Dữ liệu tổng hợp chỉ cho thấy **hành vi của mô hình** (A-10). Nó không chứng minh được độ chính xác hay hiệu quả của control.
- E5 dùng chính dữ liệu effects làm thước đo cho mọi phương pháp, nên kết quả chỉ có giá trị bên trong từng bộ dữ liệu.
- Chưa có nghiên cứu với hai người chấm thật (§9.5).

### 7.4 Bước 5: so sánh giữa hai lần chạy, tức bước Maintain (Task 4-1/4-2) (ngày 2026-11-22)

**Cơ chế:**
- Mỗi lần chạy ghi `state.json`: một bản tóm tắt tất định gồm rating, các đầu vào, control, finding, nghĩa vụ, nhóm Pareto, hàng đợi điều tra, phiên bản quy tắc và phiên bản feed.
- **SHA-256 của state** được in ở đầu báo cáo hành động.
- Khi chạy với `--baseline <state.json cũ>`, mục 2 của báo cáo liệt kê các thay đổi, và **quy mỗi thay đổi của rủi ro về đúng đầu vào đã thay đổi**. Nếu không có đầu vào nào đổi, báo cáo ghi rõ là do quy tắc, effects hoặc control. Nếu phiên bản quy tắc hoặc đặc tả khác nhau, báo cáo cảnh báo trước khi liệt kê.
- **So sánh chỉ chạy khi có `--baseline` truyền vào rõ ràng.** Nhờ vậy cùng đầu vào luôn cho cùng đầu ra. Self-check đã kiểm tra hai lần chạy cho ra state và báo cáo giống hệt nhau (E2).

**Chuyển từ `projected` sang `verified`:**
- Khi **mọi** gói đã chọn cho một rủi ro ở trạng thái `implemented_assessed_effective` trong `controls.csv`, residual được tính bằng rủi ro hiện tại, và trạng thái residual là `verified`.
- Nếu rủi ro hiện tại sau kiểm chứng vẫn tệ hơn residual đã dự kiến, script cảnh báo rằng dự kiến không đạt.

**Tùy chọn mới:**
- `--data DIR`: đọc dữ liệu kiểu overlay. File nào không có trong DIR thì lấy từ `data/`.
- `--out DIR`: thư mục ghi kết quả.

**Ví dụ chu kỳ 2** ([examples/cycle2/](examples/cycle2/), **mô phỏng**, ngày đánh giá 2026-12-05). Thư mục chỉ chứa 3 file đã thay đổi:

| Thay đổi mô phỏng | Kết quả trong [examples/cycle2/out/action_report.md](examples/cycle2/out/action_report.md) |
|---|---|
| T-01 (MFA) và T-06 (alert) được kiểm thử. R-02 G-4 chấm lại thành VL theo anchor "hai rào chắn đã kiểm thử" | R-02: Moderate → **Low**, residual `projected` → `verified`, thẩm quyền chuyển từ delegated sang owner |
| MFA đã kiểm chứng làm G-4 của R-01 và R-11 giảm từ H xuống M | R-11: High → **Moderate**. R-01 không đổi mức (impact Very High), nhưng giờ vào hàng đợi điều tra |
| F-001 được vá và kiểm chứng. F-002 được xác nhận áp dụng | Nghĩa vụ F-001 đóng lại. Nghĩa vụ F-002 mới mở, hạn 2026-12-16 |
| (Không đổi gì về dữ liệu xếp hạng) | **Nhóm Pareto thêm T-02**. Khi R-11 đã xuống Moderate, chỉ còn R-01 giữ family ransomware ở mức High, và riêng T-02 đủ kéo R-01 xuống dưới High |
| Snapshot KEV vẫn là bản lấy ngày 2026-11-22 | Cảnh báo snapshot đã cũ (13 ngày, quá giới hạn 7 ngày) |

Mọi bằng chứng của chu kỳ 2 đều được gắn nhãn `[simulated cycle 2]`.

### 7.3 Bước 4: chấm lại effects và finding minh họa (ngày 2026-11-22)

**Phát hiện thiếu sót của bước 2:** `effects.csv` vẫn mang các rating residual của v1, **chưa được chấm lại theo anchor G-4**. Ở bước 4, toàn bộ effects đã được chấm lại theo EFF-01 và EFF-02. Đồng thời thêm effects cho từng gói đơn, để xếp hạng được gói. Tổng cộng có 35 dòng.

| Kịch bản | Residual v1 → v2.1 | Lý do |
|---|---|---|
| R-01 | Moderate → **Low** | Bundle có MFA và máy trạm quản trị riêng, tức một rào chắn triển khai đủ (G-4 L). Backup khôi phục được nên mất hậu quả phá hủy, impact giảm từ VH xuống H |
| R-02 | Low → **Moderate** | v1 chấm G-4 = VL nhờ MFA. Theo EFF-01, mức VL chỉ đạt được sau khi kiểm thử, nên residual dự kiến chỉ là L |
| R-03 | Moderate → **Low** | Đối soát giúp sửa sai trước khi dữ liệu được dùng, nên I-01 giới hạn impact ở mức L |

**Residual dự kiến của v2.1:** 0 High, 2 Moderate (R-02, R-11), 11 Low.

**Finding minh họa** (**[GĐ]**, giả định cho hệ thống hư cấu, giả sử AS-06 chạy Apache Tomcat). Mã CVE là thật và có trong snapshot KEV 2026.11.20:

| Finding | CVE | Trạng thái giả định | Kết quả |
|---|---|---|---|
| F-001 | CVE-2025-24813 | Đã xác nhận áp dụng, chưa khắc phục | Nghĩa vụ KEV mở, hạn 2026-12-02 (thành phần mở ra internet: 14 ngày) |
| F-002 | CVE-2026-34486 | Nghi ngờ áp dụng | Vào hàng đợi điều tra |
| F-003 | CVE-2017-12617 | Đã khắc phục và kiểm chứng | Nghĩa vụ đã đóng |

Chưa có finding nào nằm ngoài KEV, và chưa có snapshot EPSS. Vì vậy thứ tự theo EPSS (EPSS-ORDER-01) mới chỉ được kiểm tra bằng code, chưa có dữ liệu thật để minh họa.

**Kết quả xếp hạng gói** ([out/action_report.md](out/action_report.md) mục 3):
- **Nhóm Pareto của gói đơn:** T-04 kéo 2 family xuống dưới Moderate, effort Medium. T-09 và T-10 mỗi gói kéo 1 family, effort Low.
- **Family ransomware:** **không gói đơn nào** kéo được family này xuống dưới High. Chỉ bundle đầy đủ của R-01 làm được.
- **Các tổ hợp nhỏ hơn** (T-02 + T-03; T-01 + T-03 + T-08 + T-12) được đánh dấu *incomplete*, vì chưa có effect được đánh giá cho R-01.
- **Việc cần làm:** người phụ trách mô hình phải đánh giá thêm các tổ hợp này nếu muốn biết tổ hợp nhỏ nhất đủ để kéo family ransomware xuống.

**Kiểm chứng:**
- `python risk.py --check` cố định 13 cặp (mức rủi ro hiện tại, residual) theo §7.3.
- Self-check còn kiểm tra:
  - **Hai quy tắc effects:** EFF-01 và EFF-02.
  - **Nghĩa vụ KEV:**
    - ngày kích hoạt và hạn theo exposure,
    - giữ nguyên khi import lại feed,
    - ngày đã ghi nhận được ưu tiên,
    - quá hạn,
    - đóng nghĩa vụ,
    - trường hợp chưa có KEV.
  - **Kết quả của case portal:** nghĩa vụ, nhóm Pareto, bundle của family ransomware, và các mục trong hàng đợi điều tra.
- Phần kiểm tra hợp lệ đã được thử với dữ liệu cố ý làm sai: thuộc tính không khai báo, subject không tồn tại, giá trị âm, thiếu `evidence_ref`, gói biện pháp không áp dụng được. Tất cả đều bị từ chối.
- Một đầu vào `unknown` làm mức rủi ro thành `unknown` và kịch bản được đưa vào hàng đợi điều tra, không bị coi là 0.
