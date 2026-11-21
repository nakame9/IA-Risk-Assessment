# Báo cáo đánh giá rủi ro IA: Cổng hồ sơ sinh viên (hệ thống hư cấu)

> **Trạng thái:** Đã hoàn thành cả 5 giai đoạn. Kết luận cho người ra quyết định nằm ở [§5.4](#54-kết-luận-cho-người-ra-quyết-định).
> **Phương pháp:** NIST SP 800-30 Rev.1 (Sep 2012). Xem [PLAN.md](PLAN.md).
> **Lưu ý:** toàn bộ tổ chức, hệ thống, con số và phê duyệt trong báo cáo đều **hư cấu**, dùng cho mục đích học tập.

**Quy ước nhãn dùng trong báo cáo:**

| Nhãn | Ý nghĩa |
|---|---|
| **[GĐ]** | Giả định do nhóm đặt ra cho hệ thống hư cấu |
| **[TK]** | Nội dung lấy từ tài liệu tham khảo bên ngoài, có ghi nguồn |
| **[ĐG]** | Nhận định chuyên môn của nhóm đánh giá |

---

## 1. Frame (Khung đánh giá)

### 1.1 Mục đích và loại đánh giá

- **Mục đích:** xác định và xếp hạng rủi ro an toàn thông tin của cổng hồ sơ sinh viên, rồi đề xuất quyết định xử lý rủi ro (risk treatment) cho từng rủi ro.
- **Cấp đánh giá:** Tier 3, tức cấp hệ thống thông tin. **[TK]** SP 800-30 Rev.1 mô tả ba tier (organization, mission/business process, information system).
- **Cách tiếp cận:**
  - Định tính (qualitative): dùng 5 mức Very Low … Very High.
  - Hướng mối đe dọa (threat-oriented): đi từ nguồn đe dọa → sự kiện → lỗ hổng → tác động.
  - **[TK]** SP 800-30 liệt kê ba hướng phân tích: threat-oriented, asset/impact-oriented, vulnerability-oriented.
- **Khung thời gian (horizon):** 12 tháng kể từ ngày đánh giá. Mọi đánh giá likelihood đều tính trong khoảng thời gian này.

### 1.2 Ranh giới hệ thống

**[GĐ]** "Trường Đại học Hư Cấu" vận hành một cổng hồ sơ sinh viên với khoảng 12.000 sinh viên đang học.

| Mã | Thành phần | Mô tả | Trong phạm vi |
|---|---|---|---|
| C-01 | Web portal | Giao diện để sinh viên xem điểm, hồ sơ, và đăng ký môn | Có |
| C-02 | Application server | Xử lý nghiệp vụ, phân quyền theo vai trò (sinh viên, giảng viên, phòng Đào tạo, admin) | Có |
| C-03 | Database | Hồ sơ cá nhân, điểm, lịch sử học tập, trạng thái tốt nghiệp | Có |
| C-04 | SSO / IdP | Xác thực tập trung của trường. Portal **phụ thuộc** vào thành phần này | Có, nhưng chỉ xét phần tích hợp và phụ thuộc |
| C-05 | Backup | Bản sao lưu hằng ngày của C-03 | Có |
| C-06 | Hosting (cloud IaaS) | Máy ảo và mạng do nhà cung cấp cloud quản lý | Chỉ xét phần cấu hình thuộc trách nhiệm của trường |
| C-07 | Máy trạm quản trị | Máy của admin và cán bộ phòng Đào tạo dùng để truy cập quản trị | Có |

**Ngoài phạm vi:**
- Thanh toán học phí (nên không xét PCI DSS).
- Hệ thống LMS và email của trường.
- An ninh vật lý của trung tâm dữ liệu cloud (thuộc nhà cung cấp).
- Các hệ thống khác dùng chung SSO.

### 1.3 Giả định

| Mã | Giả định |
|---|---|
| A-01 | **[GĐ]** Portal truy cập được từ Internet. Riêng giao diện quản trị chỉ mở cho dải IP nội bộ |
| A-02 | **[GĐ]** Mỗi năm có 2 kỳ đăng ký môn, mỗi kỳ khoảng 5 ngày. Đây là giai đoạn tính sẵn sàng (availability) quan trọng nhất |
| A-03 | **[GĐ]** Điểm và trạng thái tốt nghiệp trong C-03 là nguồn dữ liệu gốc dùng để cấp bảng điểm và bằng |
| A-04 | **[GĐ]** Đội CNTT có 3 người, không trực 24/7 |
| A-05 | **[GĐ]** Nghĩa vụ pháp lý về bảo vệ dữ liệu cá nhân được coi là ràng buộc bắt buộc. Báo cáo **không** phân tích pháp lý cụ thể vì chưa xác minh văn bản luật áp dụng |
| A-06 | **[GĐ]** Mọi phê duyệt và chấp nhận rủi ro trong báo cáo đều là **mô phỏng** |

### 1.4 Vai trò và thẩm quyền (mô phỏng)

| Vai trò | Người đảm nhận [GĐ] | Thẩm quyền |
|---|---|---|
| Risk executive | Phó Hiệu trưởng phụ trách CNTT | Phê duyệt ngoại lệ cho rủi ro High/Very High, nhận mọi escalation |
| System owner | Trưởng phòng Đào tạo | Chấp nhận rủi ro Moderate theo ủy quyền, phê duyệt kế hoạch xử lý |
| Risk owner | Người phụ trách từng tài sản | Chấp nhận rủi ro Very Low/Low, có ghi lại |
| ISSO / Phòng CNTT | Trưởng nhóm CNTT | Triển khai control, báo cáo hiệu quả |
| Assessor | Nhóm dự án | Phân tích và đề xuất. **Không** có quyền chấp nhận rủi ro |

### 1.5 Thang đo (assessment scales) và anchor riêng cho hệ thống

**[TK]** SP 800-30 Rev.1 coi các thang ở Appendix D–I là ví dụ (exemplary), có thể dùng làm điểm khởi đầu và tùy chỉnh (tailor) theo tổ chức. Dự án giữ nguyên định nghĩa gốc và **chỉ bổ sung ví dụ anchor** cho hệ thống này. Mọi anchor đều là **[ĐG]**/**[GĐ]**.

#### a) Đặc tính nguồn đe dọa có chủ đích: capability (D-3), intent (D-4), targeting (D-5)

| Mức | Capability (D-3, rút gọn) | Ví dụ anchor cho hệ thống |
|---|---|---|
| Very High | Chuyên môn rất cao, nguồn lực lớn, tấn công liên tục và phối hợp | Hiếm gặp với hệ thống này |
| High | Chuyên môn cao, nguồn lực đáng kể | Nhóm ransomware chuyên nghiệp |
| Moderate | Nguồn lực, chuyên môn và cơ hội ở mức vừa phải | Nhóm tội phạm dùng công cụ khai thác có sẵn |
| Low | Nguồn lực, chuyên môn và cơ hội hạn chế | Sinh viên muốn sửa điểm, dùng tool công khai |
| Very Low | Rất hạn chế | Người dùng tò mò thử URL |

- **Intent (D-4)** và **targeting (D-5)** dùng nguyên định nghĩa gốc.
  - Intent đi từ "thu thập hoặc sửa thông tin cụ thể" (Moderate) tới "phá hủy chức năng cốt lõi" (Very High).
  - Targeting đi từ "không nhắm cụ thể" (Very Low) tới "nhắm dai dẳng dựa trên trinh sát" (Very High).
- Ba đặc tính được **ghi riêng** trong threat profile, không gộp thành một con số.

#### b) Nguồn không chủ đích: range of effects (D-6)

Áp dụng cho các thành phần C-01 → C-07 của hệ thống:

| Mức | Phạm vi ảnh hưởng |
|---|---|
| Very High | Gần như toàn bộ |
| High | Phần lớn, gồm nhiều thành phần then chốt |
| Moderate | Một phần đáng kể |
| Low | Một số, không có thành phần then chốt nào |
| Very Low | Tối thiểu, không có thành phần then chốt nào |

Ví dụ: admin xóa nhầm một bảng trong C-03 là **Low**. Cấu hình sai IAM của cloud làm sập cả C-01 → C-05 là **High**.

#### c) Lỗ hổng: vulnerability severity (F-2) và điều kiện tiền đề: pervasiveness (F-5)

**F-2** gắn mức nghiêm trọng với tình trạng triển khai control:

| Mức | Tình trạng (theo F-2) |
|---|---|
| Very High | Lỗ hổng bị lộ và khai thác được, control chưa có và cũng chưa lên kế hoạch |
| High | Control đã lên kế hoạch nhưng chưa triển khai, có control bù trừ tối thiểu |
| Moderate | Control mới triển khai một phần |
| Low | Control đã triển khai đầy đủ nhưng hiệu quả còn cải thiện được |
| Very Low | Theo định nghĩa gốc |

- Nếu có điểm CVSS-B thì dùng nó làm **đầu vào tham khảo** cho F-2, không thay thế F-2. **[TK]** FIRST CVSS v4.0 User Guide nêu rằng điểm Base đo độ nghiêm trọng (severity) và không nên dùng một mình để đánh giá rủi ro.
- **F-5 (tùy chỉnh cho Tier 3, một hệ thống):** đo bằng tỷ lệ thành phần C-01 → C-07 chịu ảnh hưởng của điều kiện đó.

  | Mức | Số thành phần chịu ảnh hưởng |
  |---|---|
  | Very Low | 1 |
  | Low | 2 |
  | Moderate | 3–4 |
  | High | 5–6 |
  | Very High | Cả 7 |

  Ví dụ: "dùng chung một tài khoản admin cho mọi máy chủ" ảnh hưởng C-02, C-03, C-05, C-06, C-07, tức là **High**.

#### d) Likelihood (G-2, G-3, G-4) → G-5

**G-3 (không chủ đích)** dùng nguyên tần suất của SP 800-30:

| Mức | Tần suất |
|---|---|
| Very High | Hơn 100 lần/năm |
| High | 10–100 lần/năm |
| Moderate | 1–10 lần/năm |
| Low | Dưới 1 lần/năm nhưng hơn 1 lần/10 năm |
| Very Low | Dưới 1 lần/10 năm |

**G-2 (có chủ đích)** chỉ có mô tả định tính, từ "gần như chắc chắn khởi phát" tới "rất khó khởi phát". Anchor riêng cho hệ thống [ĐG]:

| Mức | Anchor |
|---|---|
| Very High | Kiểu tấn công đang được quét hoặc khai thác tự động trên diện rộng nhắm vào dịch vụ công khai như C-01 |
| High | Có động cơ rõ ràng và lặp lại, ví dụ sửa điểm vào cuối mỗi kỳ |
| Moderate | Có động cơ nhưng cần điều kiện đặc biệt |
| Low | Động cơ yếu, hoặc cần quyền truy cập nội bộ hiếm có |
| Very Low | Không có động cơ hợp lý nào |

**G-4 (khả năng gây tác động bất lợi):**
- Đánh giá **sau khi** đã tính tới các control hiện có.
- Ví dụ [ĐG]: có MFA và cảnh báo đăng nhập bất thường thì một lần đăng nhập bằng mật khẩu bị lộ chỉ ở mức **Low** về khả năng gây tác động.

Overall likelihood được tra theo bảng **G-5**, chép nguyên văn ở [PLAN.md](PLAN.md).

#### e) Impact (H-3)

**[TK]** Theo định nghĩa của H-3 và FIPS 199, một số mức cùng dùng một cách diễn đạt:
- H-3 Moderate và FIPS 199 MODERATE đều là "serious adverse effect".
- H-3 High và FIPS 199 HIGH đều là "severe or catastrophic adverse effect".
- H-3 Very High là "**multiple** severe or catastrophic adverse effects".
- FIPS 199 LOW là "limited adverse effect".

Anchor riêng cho hệ thống. Các ngưỡng số đều là **[GĐ]**. Cột A đã được chỉnh ngày 2026-11-22 cho khớp với quy tắc A-01 trong [SPEC.md](SPEC.md), để lấp khoảng 3–7 ngày còn hở. Không rating nào thay đổi.

| Mức | Bảo mật (C) | Toàn vẹn (I) | Sẵn sàng (A) |
|---|---|---|---|
| Very Low | Lộ thông tin vốn đã công khai, ví dụ danh bạ khoa | Sai lệch hiển thị, dữ liệu gốc không bị ảnh hưởng | Gián đoạn dưới 1 giờ, ngoài kỳ đăng ký |
| Low | Lộ dữ liệu cá nhân không nhạy cảm của dưới 10 sinh viên | Sai lệch nhỏ, phát hiện và sửa được từ log trong ngày | Gián đoạn từ 1 giờ đến dưới 24 giờ, ngoài kỳ đăng ký |
| Moderate | Lộ hồ sơ hoặc điểm của 10–1.000 sinh viên | Sửa điểm trái phép nhưng phát hiện được trước khi cấp bảng điểm | Gián đoạn 24 giờ – 7 ngày ngoài kỳ đăng ký, hoặc dưới 24 giờ trong kỳ đăng ký |
| High | Lộ phần lớn hoặc toàn bộ CSDL (trên 1.000 sinh viên) | Dữ liệu điểm hoặc tốt nghiệp bị sửa mà không phát hiện được, và đã được dùng để cấp văn bằng | Gián đoạn hơn 7 ngày, hoặc từ 24 giờ trở lên trong kỳ đăng ký |
| Very High | Nhiều tác động High xảy ra cùng lúc. Ví dụ: ransomware vừa làm lộ dữ liệu, vừa mã hóa C-03, vừa phá hỏng C-05 nên không khôi phục được | | |

#### f) Level of risk (I-2, I-3)

- Mức rủi ro được tra theo bảng **I-2** (xem [PLAN.md](PLAN.md)).
- Ý nghĩa của từng mức theo I-3:
  - Very Low: tác động không đáng kể (negligible).
  - Low: tác động hạn chế (limited).
  - Moderate: tác động nghiêm trọng (serious).
  - High: tác động nặng nề hoặc thảm khốc (severe/catastrophic).
  - Very High: nhiều tác động nặng nề hoặc thảm khốc (multiple severe/catastrophic).

#### g) Độ tin cậy (confidence)

**[ĐG]** Đây là lựa chọn của dự án, không lấy từ SP 800-30. Mỗi rating được gắn một mức tin cậy:

| Mức | Ý nghĩa |
|---|---|
| High | Có bằng chứng trực tiếp |
| Medium | Suy luận từ bằng chứng gián tiếp |
| Low | Chủ yếu là giả định |

- Rating có confidence Low mà nằm sát ngưỡng thì phải chấm lại ở giai đoạn 5.
- Giá trị chưa biết ghi `unknown`, không bao giờ ghi 0.

### 1.6 Khẩu vị rủi ro (risk appetite) và quy tắc quyết định

| Mức rủi ro | Yêu cầu | Người quyết định |
|---|---|---|
| Very Low / Low | Được chấp nhận, có ghi lại | Risk owner |
| Moderate | Phải xử lý, hoặc được chấp nhận theo ủy quyền, kèm lý do | System owner |
| High / Very High | Phải xử lý, hoặc cần ngoại lệ có thời hạn | Risk executive |
| Impact = Very High (bất kể mức rủi ro) | Escalate | Risk executive |

**Quy tắc:**
- Appetite chỉ quyết định **có bắt buộc hành động hay không**.
- Phương án (mitigate / transfer / avoid / accept) được chọn bằng cách so sánh mức giảm rủi ro, chi phí/công sức, nghĩa vụ bắt buộc (A-05) và phần rủi ro còn lại.
- Nghĩa vụ bắt buộc luôn đứng trên ngưỡng chấp nhận.
- Mọi quyết định chấp nhận đều có hạn rà soát lại, tối đa 12 tháng.

### 1.7 Điều kiện kích hoạt rà soát lại (review triggers)

Đánh giá phải được làm lại khi xảy ra một trong các trường hợp sau:
- Thay đổi kiến trúc hoặc nhà cung cấp của C-01 → C-06.
- Xảy ra sự cố an ninh liên quan tới hệ thống.
- Công bố lỗ hổng nghiêm trọng ảnh hưởng thành phần đang dùng.
- Thay đổi nghĩa vụ pháp lý.
- Hết hạn của một quyết định chấp nhận rủi ro.
- Định kỳ 12 tháng.

---

## 2. Identify (Nhận diện)

Giai đoạn này tương ứng với Task 2-1 đến 2-3 của SP 800-30 Rev.1:
- **Task 2-1:** nhận diện nguồn đe dọa và đặc tính của chúng.
- **Task 2-2:** nhận diện sự kiện đe dọa.
- **Task 2-3:** nhận diện lỗ hổng và điều kiện tiền đề.

Likelihood, impact và mức rủi ro (Task 2-4 đến 2-6) thuộc giai đoạn 3, nên các cột đó trong CSV đang để trống.

### 2.1 Tài sản và hồ sơ CIA (FIPS 199)

- Danh sách đầy đủ, kèm lý do chấm từng mức, nằm trong [data/assets.csv](data/assets.csv). Có 10 tài sản, từ AS-01 đến AS-10.
- Hồ sơ CIA dùng 3 mức Low/Moderate/High theo định nghĩa của FIPS 199:
  - Low: tác động hạn chế (limited).
  - Moderate: tác động nghiêm trọng (serious).
  - High: tác động nặng nề hoặc thảm khốc (severe/catastrophic).
- Mọi mức chấm đều là **[ĐG]**.

**Hồ sơ của toàn hệ thống:**
- **[TK]** FIPS 199 quy định hồ sơ của một hệ thống lấy mức **cao nhất** (high water mark) trên từng mục tiêu C, I, A, xét qua các loại thông tin nằm trong hệ thống.
- Chỉ tính các tài sản có `kind` là `information` hoặc `system_information`:
  - AS-01, AS-02, AS-03: dữ liệu sinh viên.
  - AS-04: tài khoản, thông tin xác thực và phân quyền.
  - AS-10: log kiểm toán.
- Không tính các tài sản sau:
  - AS-05 (backup), vì đây là bản sao của cùng dữ liệu nên kế thừa hồ sơ của dữ liệu gốc.
  - Các tài sản là dịch vụ hoặc thành phần.

> **SC cổng hồ sơ sinh viên = {(confidentiality, HIGH), (integrity, HIGH), (availability, MODERATE)}**
>
> - Mức C = HIGH đến từ AS-04: lộ thông tin xác thực admin sẽ dẫn tới lộ toàn bộ C-03.
> - Mức I = HIGH đến từ AS-02, AS-03, AS-04.

### 2.2 Nguồn đe dọa (threat profiles), Task 2-1

- Loại nguồn đe dọa lấy theo taxonomy ở bảng D-2.
- Nguồn có chủ đích được chấm 3 đặc tính: capability (D-3), intent (D-4), targeting (D-5).
- Nguồn không chủ đích được chấm range of effects (D-6).
- Mọi rating đều là **[ĐG]**.

| ID | Loại (D-2) | Mô tả [GĐ] | Capability | Intent | Targeting | Range of effects |
|---|---|---|---|---|---|---|
| TS-01 | Adversarial – Group (established) | Nhóm tội phạm mạng có động cơ tài chính, dùng ransomware và DDoS thuê | High | Moderate | Low | — |
| TS-02 | Adversarial – Individual (outsider) | Kẻ tấn công cơ hội, dùng scanner và danh sách mật khẩu bị lộ | Low | Low | Very Low | — |
| TS-03 | Adversarial – Individual (insider) | Sinh viên muốn sửa điểm của chính mình | Low | Moderate | Moderate | — |
| TS-04 | Adversarial – Individual (privileged insider) | Cán bộ hoặc admin bất mãn, hoặc bị mua chuộc | Moderate | Moderate | High | — |
| TS-05 | Accidental – Privileged user/administrator | Admin của đội CNTT 3 người (A-04) | — | — | — | Moderate |
| TS-06 | Accidental – User | Giảng viên nhập điểm | — | — | — | Low |
| TS-07 | Environmental – Infrastructure failure/outage | Sự cố ở region của nhà cung cấp cloud | — | — | — | High |
| TS-08 | Structural – Software | Lỗi phần mềm SSO/IdP (C-04) | — | — | — | Moderate |

**Lý do chấm:**

- **TS-01:**
  - Intent = Moderate. D-4 Moderate mô tả kẻ tấn công muốn chiếm quyền hoặc làm gián đoạn tài nguyên bằng cách tạo chỗ đứng trong hệ thống, đồng thời tránh bị phát hiện. Mô tả này khớp với ransomware.
  - Targeting = Low. D-5 Low mô tả việc nhắm vào một *nhóm* tổ chức và tìm mục tiêu cơ hội trong nhóm đó. Trường đại học là một nhóm mục tiêu, nhưng không bị nhắm riêng.
- **TS-02:** Intent = Low. D-4 Low mô tả kẻ tấn công tìm thông tin nhạy cảm mà không quan tâm tới việc bị phát hiện.
- **TS-03:** Intent = Moderate, vì sinh viên muốn sửa một thông tin cụ thể. Targeting = Moderate, vì sinh viên nhắm dai dẳng vào một thông tin cụ thể dựa trên hiểu biết có sẵn về hệ thống.
- **TS-04:** Targeting = High, vì người bên trong biết chính xác dữ liệu nào giá trị và nằm ở đâu.
- **TS-05:** Range = Moderate. Một thao tác sai ở C-06 hoặc C-03 có thể chạm vào một phần đáng kể của hệ thống, kể cả thành phần then chốt.
- **TS-07:** Range = High. Sự cố mất cả region sẽ làm mất C-01 đến C-03, và C-05 cũng nằm cùng region.

### 2.3 Lỗ hổng (vulnerabilities), Task 2-3: F-2

Tình trạng control ở đây là **[GĐ]**. Mức F-2 được chấm theo đúng tiêu chí "tình trạng triển khai control" của bảng F-2.

| ID | Lỗ hổng | Tình trạng control [GĐ] | F-2 |
|---|---|---|---|
| V-01 | Tài khoản cán bộ và admin trên SSO chưa có MFA | Đã lên kế hoạch nhưng chưa triển khai. Có khóa tài khoản khi đăng nhập sai nhiều lần (bù trừ tối thiểu) | High |
| V-02 | Backup nằm cùng tài khoản cloud, dùng cùng thông tin xác thực admin, không có bản offline hoặc immutable | Chưa có và chưa lên kế hoạch | Very High |
| V-03 | API sửa điểm chỉ kiểm tra vai trò trên UI, thiếu kiểm tra quyền theo từng đối tượng (object-level authorization) | Triển khai một phần | Moderate |
| V-04 | Vá framework và thư viện của portal thủ công, mỗi tháng một lần | Triển khai một phần | Moderate |
| V-05 | Sửa điểm hoặc trạng thái tốt nghiệp không cần người thứ hai duyệt, không có đối soát định kỳ | Đã lên kế hoạch nhưng chưa triển khai | High |
| V-06 | Máy trạm quản trị vẫn dùng để đọc email, duyệt web, và có quyền local admin | Triển khai một phần (chỉ có antivirus) | Moderate |
| V-07 | Chưa từng thử khôi phục từ backup, chưa có kế hoạch DR hoặc RTO | Đã lên kế hoạch cho năm sau | High |
| V-08 | Không có baseline hoặc rà soát cấu hình IAM và security group của cloud | Triển khai một phần (có MFA cho console) | Moderate |
| V-09 | Log được thu tập trung nhưng không ai xem, không có cảnh báo | Triển khai một phần | Moderate |
| V-10 | Chức năng xuất hàng loạt hồ sơ không giới hạn số lượng và không cảnh báo | Triển khai một phần (giới hạn theo vai trò) | Moderate |
| V-11 | Không có rate limiting hoặc WAF. Chỉ có bảo vệ DDoS mặc định của nhà cung cấp | Triển khai một phần | Moderate |

**Về CVSS:**
- V-03 và V-04 là lỗ hổng kỹ thuật, nhưng hệ thống hư cấu không có CVE cụ thể. Vì vậy cột CVSS của các kịch bản liên quan ghi `unknown`.
- Các lỗ hổng mang tính tổ chức hoặc quy trình ghi `n/a`, vì CVSS không áp dụng cho chúng.

### 2.4 Điều kiện tiền đề (predisposing conditions), Task 2-3: F-4 và F-5

Loại điều kiện lấy theo taxonomy F-4. Mức F-5 được chấm theo thang đã tùy chỉnh ở §1.5c, tức đếm số thành phần C-xx chịu ảnh hưởng.

| ID | Điều kiện | Loại (F-4) | Thành phần chịu ảnh hưởng | F-5 |
|---|---|---|---|---|
| PC-01 | Mọi đăng nhập vào portal và máy quản trị đều phụ thuộc vào một SSO duy nhất | Technical – Architectural | C-01, C-02, C-07 | Moderate |
| PC-02 | Một tài khoản admin dùng chung cho các máy chủ | Technical – Architectural | C-02, C-03, C-05, C-06, C-07 | High |
| PC-03 | Portal mở ra Internet (A-01) | Technical – Functional (networked multiuser) | C-01, C-02 | Low |
| PC-04 | Đội CNTT nhỏ, không trực 24/7 (A-04) | Operational/Environmental | Cả 7 thành phần | Very High |
| PC-05 | Tải đỉnh và yêu cầu sẵn sàng cao trong kỳ đăng ký (A-02) | Operational/Environmental | C-01, C-02, C-03, C-04 | Moderate |

### 2.5 Kịch bản rủi ro, Task 2-2

- Có 13 kịch bản, nằm trong [data/risk_register.csv](data/risk_register.csv).
- Tên sự kiện lấy từ bảng E-2 hoặc E-3 khi khớp. Khi không khớp, sự kiện được ghi là "organization-defined event". **[TK]** SP 800-30 coi E-2 và E-3 là các ví dụ tiêu biểu (representative examples).

**Cách ghi hai cột rating ở cấp kịch bản [ĐG]:**
- `vulnerability_severity` lấy mức F-2 **cao nhất** trong số các V-xx liên quan.
- `condition_pervasiveness` lấy mức F-5 **cao nhất** trong số các PC-xx liên quan.
- Đây chỉ là đầu vào để đánh giá likelihood ở giai đoạn 3. Các mức này không được dùng để tính toán trực tiếp.

#### R-01
Ransomware nhiều bước, nhắm vào AS-01, AS-02, AS-05.
- **Chuỗi tấn công:**
  1. Phishing một admin (V-01, V-06).
  2. Dùng tài khoản admin dùng chung (PC-02) để chạm tới cả C-03 lẫn C-05.
  3. Xóa backup (V-02).
  4. Không khôi phục được (V-07).
  5. Phát hiện chậm (PC-04).
- **Ghi chú cho giai đoạn 3:** đây là ứng viên cho mức impact **Very High** theo §1.5e, nên phải escalate.

#### R-02
Dò mật khẩu hoặc dùng mật khẩu bị lộ (credential stuffing) vào tài khoản cán bộ.
- Thiếu MFA (V-01) và không ai xem log (V-09).
- Lockout chỉ làm chậm kiểu dò từ một nguồn.

#### R-03
Sinh viên lợi dụng lỗ hổng object-level authorization (V-03) để sửa điểm của mình.
- Không có người thứ hai duyệt hay đối soát (V-05), nên thay đổi khó bị phát hiện.

#### R-04
Insider có quyền sửa trạng thái tốt nghiệp và xóa dấu vết trong log (AS-10).
- PC-02 khiến khó quy được trách nhiệm cho một người cụ thể.

#### R-05
Khai thác lỗ hổng mới công bố trước khi kịp vá. Chu kỳ vá hằng tháng (V-04) để lộ ra một cửa sổ khai thác.

#### R-06
DDoS đúng vào kỳ đăng ký môn (PC-05).
- Bảo vệ mặc định có thể không đủ (V-11). Mức đủ hay không là **[ĐG]**, chưa có số liệu.

#### R-07
Admin cấu hình sai quyền của storage hoặc security group, làm lộ C-03 hoặc C-05 ra Internet (V-08).

#### R-08
Admin xóa nhầm bảng điểm, rồi phát hiện bản backup không khôi phục được (V-07).
- PC-04 làm thời gian phát hiện và xử lý kéo dài.

#### R-09
Mất region cloud **vào bất kỳ lúc nào**.
- Backup nằm cùng region, và chưa có DR (V-07).
- Thiệt hại lớn nhất nếu sự cố rơi vào kỳ đăng ký. Điều kiện thời điểm này **chỉ được xét ở G-4** (COND-01, sửa ngày 2026-11-22). Bản trước định nghĩa sự kiện là "trong kỳ đăng ký" rồi lại hạ G-4 vì cùng lý do đó, nên điều kiện thời điểm bị tính hai lần.

#### R-10
Giảng viên nhập sai điểm, và điểm sai được dùng để cấp bảng điểm trước khi ai đó phát hiện (V-05).

#### R-11
Malware qua email trên máy trạm quản trị (V-06), dẫn tới bị đánh cắp phiên hoặc thông tin xác thực admin (AS-04).
- Đây thường là bước đầu của R-01, nhưng được tách riêng vì tác động riêng lên AS-04 và AS-09.

#### R-12
Cán bộ phòng Đào tạo xuất hàng loạt hồ sơ rồi làm lộ ra ngoài.
- Chức năng xuất không giới hạn (V-10) và không có cảnh báo (V-09).

#### R-13
SSO/IdP gặp sự cố **vào bất kỳ lúc nào** (PC-01, PC-05).
- Việc trùng kỳ đăng ký chỉ được xét ở G-4 (COND-01, sửa ngày 2026-11-22).
- Kịch bản này chỉ có điều kiện tiền đề, không có V-xx, nên cột `vulnerability_severity` ghi `n/a`.

---

## 3. Assess (Phân tích)

Giai đoạn này tương ứng với Task 2-4 đến 2-6 của SP 800-30 Rev.1:
- **Task 2-4:** đánh giá likelihood, gồm hai thành phần:
  - Khả năng sự kiện được khởi phát hoặc xảy ra: G-2 cho nguồn có chủ đích, G-3 cho nguồn không chủ đích.
  - Khả năng sự kiện gây tác động bất lợi: G-4.
- **Task 2-5:** đánh giá impact theo H-3.
- **Task 2-6:** xác định mức rủi ro theo I-2.

Overall likelihood được tra theo bảng G-5. Mức rủi ro hiện tại (current risk) được đánh giá với các control **hiện có** ghi trong cột `existing_controls`.

**Lưu ý về dữ liệu:**
- Ba cột đầu vào `initiation_likelihood`, `adverse_impact_likelihood`, `impact` và cột `confidence` đã được ghi vào [data/risk_register.csv](data/risk_register.csv).
- Overall likelihood và mức rủi ro là **giá trị suy ra** nên không lưu trong CSV. Chúng được tra tay theo G-5 và I-2 rồi trình bày ở §3.3. Đến giai đoạn 5, `risk.py` sẽ tính lại và phải ra cùng kết quả.

### 3.1 Ví dụ tính tay 1: R-01 (nguồn có chủ đích)

| Bước | Rating | Căn cứ |
|---|---|---|
| Khởi phát (G-2) | **Moderate** | **[ĐG]** TS-01 nhắm vào một *nhóm* mục tiêu (targeting Low) chứ không nhắm riêng trường. Nhưng trường đại học thuộc nhóm thường bị ransomware nhắm tới, và kẻ tấn công có năng lực High. Không có dấu hiệu kiểu tấn công này đang được khai thác tự động trên diện rộng, nên chưa tới mức VH theo anchor ở §1.5d. Mức hợp lý nhất là "somewhat likely" trong 12 tháng. |
| Gây tác động bất lợi (G-4) | **High** | Nếu chuỗi tấn công bắt đầu, phần lớn rào chắn đều yếu: không có MFA (V-01), backup cùng thông tin xác thực và không immutable (V-02, Very High), chưa thử khôi phục (V-07), tài khoản admin dùng chung (PC-02), không trực 24/7 (PC-04). Chỉ có antivirus và spam filter có thể chặn ở bước đầu, nên chưa tới VH. |
| Overall likelihood (G-5) | **Moderate** | Tra G-5: hàng Moderate, cột High → Moderate |
| Impact (H-3, anchor §1.5e) | **Very High** | Cùng lúc xảy ra lộ dữ liệu (C), mã hóa C-03 (I/A) và mất C-05 nên không khôi phục được. Đây đúng là trường hợp "multiple severe" |
| Mức rủi ro (I-2) | **High** | Tra I-2: hàng Moderate, cột Very High → High |
| Cờ chính sách (§1.6) | **Phải xử lý hoặc cần ngoại lệ; escalate** | Mức rủi ro là High. Ngoài ra Impact là Very High nên phải escalate lên Risk executive |
| Confidence | **Low** | Mức khởi phát hoàn toàn dựa vào giả định, vì hệ thống hư cấu không có dữ liệu threat intelligence thật |

### 3.2 Ví dụ tính tay 2: R-10 (nguồn không chủ đích)

| Bước | Rating | Căn cứ |
|---|---|---|
| Xảy ra (G-3) | **High** | **[GĐ]** Khoảng 12.000 sinh viên và hàng trăm học phần mỗi kỳ. Lỗi nhập điểm ước tính xảy ra 10–100 lần/năm, ứng với mức High của G-3 |
| Gây tác động bất lợi (G-4) | **Low** | Phần lớn lỗi được sinh viên phát hiện trong thời gian phúc khảo, và giảng viên sửa được trong thời hạn nhập điểm. Chỉ một số ít lỗi lọt tới lúc cấp bảng điểm (V-05) |
| Overall likelihood (G-5) | **Moderate** | Tra G-5: hàng High, cột Low → Moderate |
| Impact | **Low** | Sai lệch thường chỉ ở vài sinh viên và sửa được. Ứng với mức "sai lệch nhỏ, sửa được" ở anchor I mức Low |
| Mức rủi ro (I-2) | **Low** | Tra I-2: hàng Moderate, cột Low → Low |
| Cờ chính sách | **Được chấp nhận, có ghi lại** | Risk owner (Trưởng phòng Đào tạo) được chấp nhận |
| Confidence | **Medium** | Tần suất là suy luận từ quy mô đào tạo |

**Nhận xét:** hai ví dụ này cho thấy một sự kiện **xảy ra thường xuyên** chưa chắc là rủi ro cao (R-10), còn một sự kiện **chỉ ở mức "có thể"** vẫn có thể là rủi ro cao nhất (R-01). Lý do là bảng G-5 và I-2 kết hợp nhiều yếu tố: mức khởi phát, khả năng gây tác động và mức tác động. Đây là lý do dự án dùng bảng tra thay cho việc nhân điểm.

### 3.3 Kết quả của toàn bộ kịch bản

**Ký hiệu:**
- Khởi phát/Xảy ra là G-2 nếu nguồn có chủ đích (ký hiệu "adv") và G-3 nếu nguồn không chủ đích (ký hiệu "non").
- Các rating đầu vào đều là **[ĐG]**.

| Risk | Nguồn | Khởi phát/Xảy ra | Gây tác động (G-4) | Overall likelihood (G-5) | Impact (H-3) | **Mức rủi ro (I-2)** | Confidence | Cờ |
|---|---|---|---|---|---|---|---|---|
| R-01 | TS-01 adv | Moderate | High | Moderate | Very High | **High** | Low | Phải xử lý/ngoại lệ; **escalate** |
| R-02 | TS-02 adv | Very High | Moderate | High | Moderate | **Moderate** | Medium | Xử lý hoặc chấp nhận theo ủy quyền |
| R-03 | TS-03 adv | High | Moderate | Moderate | High | **Moderate** | Low | Xử lý hoặc chấp nhận theo ủy quyền |
| R-04 | TS-04 adv | Low | High | Moderate | High | **Moderate** | Low | Xử lý hoặc chấp nhận theo ủy quyền |
| R-05 | TS-02 adv | Moderate | Moderate | Moderate | High | **Moderate** | Low | Xử lý hoặc chấp nhận theo ủy quyền |
| R-06 | TS-01 adv | Low | Moderate | Low | Moderate | **Low** | Low | Được chấp nhận, có ghi lại |
| R-07 | TS-05 non | Low | High | Moderate | High | **Moderate** | Medium | Xử lý hoặc chấp nhận theo ủy quyền |
| R-08 | TS-05 non | Low | High | Moderate | High | **Moderate** | Medium | Xử lý hoặc chấp nhận theo ủy quyền |
| R-09 | TS-07 non | Low | Low | Low | Moderate | **Low** | Medium | Được chấp nhận, có ghi lại |
| R-10 | TS-06 non | High | Low | Moderate | Low | **Low** | Medium | Được chấp nhận, có ghi lại |
| R-11 | TS-01 adv | High | Moderate | Moderate | High | **Moderate** | Medium | Xử lý hoặc chấp nhận theo ủy quyền |
| R-12 | TS-04 adv | Low | High | Moderate | High | **Moderate** | Low | Xử lý hoặc chấp nhận theo ủy quyền |
| R-13 | TS-08 non | Moderate | Low | Low | Moderate | **Low** | Medium | Được chấp nhận, có ghi lại |

**Lý do chấm ngắn cho các kịch bản còn lại:**

- **R-02:**
  - Khởi phát = Very High: dò mật khẩu tự động vào trang đăng nhập công khai khớp với anchor VH (A-01).
  - Gây tác động = Moderate: lockout chặn được một phần, nhưng thiếu MFA (V-01).
  - Impact = Moderate: tài khoản cán bộ chỉ đọc được hồ sơ trong phạm vi được phân quyền.
- **R-03:**
  - Khởi phát = High: sinh viên có động cơ rõ ràng và lặp lại mỗi kỳ.
  - Impact = High: lấy hậu quả **nặng nhất mà vẫn hợp lý**. Vì không có đối soát (V-05), điểm bị sửa có thể được dùng để cấp văn bằng.
- **R-04, R-12:**
  - Khởi phát = Low: số người bên trong vừa có quyền vừa có động cơ là rất ít.
  - Gây tác động = High: không có người thứ hai duyệt, không ai xem log, không có giới hạn xuất dữ liệu.
- **R-05:**
  - Khởi phát = Moderate: còn tùy việc trong 12 tháng tới có lỗ hổng mới nào ảnh hưởng đúng framework đang dùng hay không. Chưa có CVE cụ thể nên CVSS ghi `unknown`.
  - Impact = High: kẻ tấn công có thể lấy được toàn bộ CSDL.
- **R-06:**
  - Khởi phát = Low: chưa thấy động cơ rõ ràng để DDoS cổng sinh viên.
  - Impact = Moderate: portal gián đoạn vài giờ trong kỳ đăng ký.
- **R-07, R-08:**
  - Xảy ra = Low: dưới 1 lần/năm.
  - Gây tác động = High: một kho dữ liệu bị mở ra Internet sẽ bị scanner tìm thấy rất nhanh (R-07); backup chưa từng thử khôi phục nên dễ khôi phục thất bại (R-08).
- **R-09:**
  - Gây tác động = Low: chỉ gây hại đáng kể khi sự cố rơi đúng vào khoảng 10 ngày đăng ký mỗi năm (A-02). Theo COND-01, đây là chỗ **duy nhất** điều kiện thời điểm được xét.
  - Impact = Moderate: **[GĐ]** sự cố region thường kéo dài vài giờ, tức dưới 24 giờ trong kỳ đăng ký, ứng với mức Moderate của A-01. Nếu sự cố kéo dài từ 24 giờ trở lên thì impact thành High. Đây là một ranh giới mà việc thu thập bằng chứng ở v2.1 phải xác định (VOI-01).
- **R-11:**
  - Khởi phát = High: email chứa malware gửi tới cán bộ là chuyện thường xuyên.
  - Impact = High: kẻ tấn công lấy được thông tin xác thực admin (AS-04, C = High).
- **R-13:**
  - Xảy ra = Moderate: SSO lỗi 1–10 lần/năm.
  - Gây tác động = Low: chỉ đáng kể khi rơi vào kỳ đăng ký. Theo COND-01, đây là chỗ duy nhất điều kiện thời điểm được xét.

### 3.4 Ma trận rủi ro (số kịch bản)

Hàng là overall likelihood. Cột là impact. Ô có nền đậm là mức rủi ro theo I-2.

| Likelihood \ Impact | Very Low | Low | Moderate | High | Very High |
|---|---|---|---|---|---|
| **Very High** | | | | | |
| **High** | | | 1 (R-02) | | |
| **Moderate** | | 1 (R-10) | | **7** (R-03, R-04, R-05, R-07, R-08, R-11, R-12) | 1 (R-01) |
| **Low** | | | 3 (R-06, R-09, R-13) | | |
| **Very Low** | | | | | |

**Tổng hợp:** 1 rủi ro High, 8 rủi ro Moderate, 4 rủi ro Low. Không có rủi ro nào ở mức Very High hoặc Very Low.

### 3.5 Thứ tự ưu tiên

**[ĐG]** Thứ tự ưu tiên được sắp theo các tiêu chí lần lượt: mức rủi ro → impact → overall likelihood → confidence thấp hơn được ưu tiên trước. Riêng tiêu chí confidence là để kịch bản bất định nhiều được xem lại sớm.

1. **R-01**: High, escalate.
2. **R-03, R-04, R-05, R-12** (Moderate, impact High, confidence Low). Tiếp theo là **R-07, R-08, R-11** (Moderate, impact High, confidence Medium).
3. **R-02**: Moderate, impact Moderate.
4. **R-06, R-09, R-13** (impact Moderate), tiếp theo là **R-10** (impact Low): Low, được chấp nhận và ghi lại. Mỗi kịch bản vẫn cần risk owner ký xác nhận ở giai đoạn 4.

**Lỗ hổng chung của nhiều kịch bản:**

| Lỗ hổng/điều kiện | Có mặt trong |
|---|---|
| V-05 (không có người thứ hai duyệt hay đối soát) | R-03, R-04, R-10 |
| V-07 (chưa thử khôi phục) | R-01, R-08, R-09 |
| V-01 (không có MFA) | R-01, R-02, R-11 |
| PC-02 (tài khoản admin dùng chung) | R-01, R-04, R-08, R-11 |

Đây là đầu vào quan trọng cho giai đoạn 4: một control có thể giảm nhiều rủi ro cùng lúc.

### 3.6 Bất định và giới hạn

**Các rating sát ngưỡng có confidence Low.** Những rating này phải chấm lại ở giai đoạn 5 (§1.5g):

| Kịch bản | Rating sát ngưỡng | Nếu chấm khác thì sao |
|---|---|---|
| R-03 | Impact High/Moderate | Nếu Impact là Moderate thì mức rủi ro vẫn là Moderate (tra I-2: Moderate × Moderate). Kết luận **không đổi** |
| R-05 | Khởi phát Moderate/High | Nếu khởi phát là High thì overall likelihood vẫn là Moderate (tra G-5: High × Moderate). Kết luận **không đổi** |
| R-01 | Khởi phát Moderate/Low | Nếu khởi phát là Low thì overall likelihood là Moderate (tra G-5: Low × High), nên mức rủi ro vẫn là High. Kết luận **không đổi**, và vẫn phải escalate vì Impact là Very High |

**Các giới hạn khác:**
- **Kịch bản có liên hệ với nhau:** R-11 thường là bước mở đầu của R-01. Báo cáo đánh giá riêng từng kịch bản và **không** cộng dồn (aggregate) rủi ro. Phần này để ngỏ.
- **Toàn bộ là định tính:** các mức là phán đoán theo thang thứ bậc, không phải xác suất đã hiệu chỉnh. Mọi tần suất ghi trong báo cáo là **[GĐ]**.

---

## 4. Treat (Xử lý rủi ro)

**Nguyên tắc chung (§1.6):**
- Chính sách (appetite) chỉ quyết định rủi ro **có bắt buộc phải xử lý** hay không.
- Phương án được chọn bằng cách so sánh: mức giảm rủi ro, công sức/chi phí, nghĩa vụ bắt buộc (A-05) và phần rủi ro còn lại.

**Quy ước trong báo cáo:**
- Mã control lấy theo **[TK]** NIST SP 800-53 Rev.5. Tên control được đối chiếu với catalog trong bản PDF chính thức.
- Mọi phê duyệt đều là **mô phỏng** (A-06).
- Rủi ro còn lại (residual risk) được tính lại qua bảng G-5 và I-2 và gắn nhãn `projected`. Nhãn này chỉ chuyển thành `verified` sau khi control đã được triển khai và kiểm chứng hiệu quả (§4.5).

### 4.1 Gói biện pháp (treatment packages)

**Lý do gom thành gói:** nhiều kịch bản dùng chung một lỗ hổng (§3.5). Một gói biện pháp vì vậy có thể giảm nhiều rủi ro cùng lúc.

**Cách đọc bảng:**
- Cột "Công sức" là **[ĐG]**, chỉ mang tính tương đối (Thấp/Vừa/Cao), không có số liệu chi phí.
- Người triển khai của mọi gói là IT Lead (ISSO), trừ T-04 và T-10, do IT Lead và phòng Đào tạo cùng triển khai.

| Gói | Biện pháp | Control SP 800-53 Rev.5 | Giảm | Dùng cho | Công sức | Hạn |
|---|---|---|---|---|---|---|
| T-01 | Bật MFA trên SSO cho mọi tài khoản cán bộ và admin | IA-2(1) Multi-factor authentication to privileged accounts; IA-2(2) … to non-privileged accounts | V-01 | R-01, R-02, R-11 | Thấp | 2027-01-31 |
| T-02 | Đưa backup sang tài khoản cloud và thông tin xác thực riêng, ở region khác, có bản immutable; việc xóa backup cần hai người duyệt; thử khôi phục mỗi quý; lập kế hoạch khôi phục | CP-9 System backup; CP-9(1) Testing for reliability and integrity; CP-9(3) Separate storage for critical information; CP-9(7) Dual authorization for deletion or destruction; CP-4 Contingency plan testing; CP-10 System recovery and reconstitution | V-02, V-07 | R-01, R-08 (R-09 được lợi gián tiếp) | Vừa | 2027-02-28 |
| T-03 | Bỏ tài khoản admin dùng chung, cấp tài khoản admin riêng cho từng người, chỉ cấp quyền tối thiểu, ghi log mọi thao tác đặc quyền | AC-2 Account management; AC-6(5) Privileged accounts; AC-6(9) Log use of privileged functions | PC-02 | R-01, R-04, R-08, R-11 | Thấp | 2027-01-31 |
| T-04 | Sửa điểm hoặc trạng thái tốt nghiệp sau khi đã khóa sổ phải có người thứ hai duyệt; đối soát điểm trước khi cấp bảng điểm hoặc văn bằng | AC-3(2) Dual authorization; AC-5 Separation of duties | V-05 | R-03, R-04 (R-10 được lợi gián tiếp) | Vừa | 2027-02-28 |
| T-05 | Bổ sung kiểm tra object-level authorization phía server cho API sửa điểm; kiểm thử bảo mật trước khi phát hành; pentest hằng năm | AC-3 Access enforcement; SA-11 Developer testing and evaluation; CA-8 Penetration testing | V-03 | R-03 | Vừa | 2027-02-28 |
| T-06 | Xem log hằng tuần, có cảnh báo tự động khi tài khoản hoạt động bất thường; chỉ một nhóm nhỏ được quyền sửa hoặc xóa log | AU-6 Audit record review, analysis, and reporting; AU-6(1) Automated process integration; AU-9(4) Access by subset of privileged users; AC-2(12) Account monitoring for atypical usage | V-09 | R-02, R-04, R-12 | Vừa | 2027-02-28 |
| T-07 | Vá theo mức nghiêm trọng (lỗ hổng nghiêm trọng vá trong 7 ngày [GĐ]), quét lỗ hổng định kỳ, đặt WAF trước C-01 | SI-2 Flaw remediation; RA-5 Vulnerability monitoring and scanning; SC-7 Boundary protection | V-04 | R-05 | Vừa | 2027-02-28 |
| T-08 | Dùng máy trạm riêng cho quản trị, không đọc email và không duyệt web trên máy này; admin dùng tài khoản thường cho công việc thường; bỏ quyền local admin | AC-6(2) Non-privileged access for nonsecurity functions; CM-7 Least functionality; SI-3 Malicious code protection | V-06 | R-01, R-11 | Vừa | 2027-03-31 |
| T-09 | Lập baseline cấu hình IAM và security group, mọi thay đổi phải qua kiểm soát; mặc định chặn, chỉ mở khi cần | CM-2 Baseline configuration; CM-3 Configuration change control; CM-6 Configuration settings; SC-7(5) Deny by default — allow by exception | V-08 | R-07 | Thấp | 2027-02-28 |
| T-10 | Giới hạn số hồ sơ được xuất mỗi ngày, cảnh báo khi có lượt xuất lớn | AC-6 Least privilege; SI-4(18) Analyze traffic and covert exfiltration | V-10 | R-12 | Thấp | 2027-03-31 |
| T-11 | *(Hoãn)* Rate limiting và kế hoạch ứng phó DDoS | SC-5 Denial-of-service protection | V-11 | R-06 | Vừa | — |
| T-12 | Đào tạo nhận biết phishing có bài tập thực hành | AT-2(1) Practical exercises; AT-2(3) Social engineering and mining | V-01, V-06 (gián tiếp) | R-01, R-11 | Thấp | 2027-03-31 |
| T-13 | Lập quy trình xử lý sự cố ransomware | IR-4 Incident handling | PC-04 (gián tiếp) | R-01 | Thấp | 2027-03-31 |

**Gói ưu tiên:** T-01, T-02 và T-03 có công sức thấp hoặc vừa, nhưng giảm được 4–5 kịch bản cùng lúc. Vì vậy ba gói này được xếp hạn sớm nhất.

### 4.2 Quyết định xử lý và rủi ro còn lại

Cách tính residual như sau:
- Các control trong bảng **chủ yếu làm giảm G-4**, tức khả năng sự kiện gây tác động bất lợi.
- Mức khởi phát (G-2/G-3) thường **không đổi**, vì nguồn đe dọa vẫn còn đó. Riêng R-07 có giảm mức khởi phát, vì T-09 làm giảm chính tần suất cấu hình sai.
- Với các rủi ro chọn "accept", residual được giữ bằng rủi ro hiện tại.

| Risk | Hiện tại | Phương án | Gói | Residual: khởi phát / gây tác động → G-5 / impact | **Residual (I-2)** | Risk owner | Hạn |
|---|---|---|---|---|---|---|---|
| R-01 | **High** | Mitigate | T-01, T-02, T-03, T-08, T-12, T-13 | Moderate / Moderate → Moderate / High | **Moderate** | Head of Academic Affairs | 2027-03-31 |
| R-02 | Moderate | Mitigate | T-01, T-06 | Very High / Very Low → Low / Moderate | **Low** | Head of Academic Affairs | 2027-02-28 |
| R-03 | Moderate | Mitigate | T-05, T-04 | High / Low → Moderate / Moderate | **Moderate** | Head of Academic Affairs | 2027-02-28 |
| R-04 | Moderate | Mitigate | T-04, T-03, T-06 | Low / Low → Low / High | **Low** | Head of Academic Affairs | 2027-02-28 |
| R-05 | Moderate | Mitigate | T-07 | Moderate / Low → Low / High | **Low** | Head of Academic Affairs | 2027-02-28 |
| R-06 | Low | Accept | — | không đổi | **Low** | Head of Academic Affairs | Rà soát 2027-11-22 |
| R-07 | Moderate | Mitigate | T-09 | Very Low / High → Low / High | **Low** | Head of Academic Affairs | 2027-02-28 |
| R-08 | Moderate | Mitigate | T-02, T-03 | Low / Low → Low / Moderate | **Low** | Head of Academic Affairs | 2027-02-28 |
| R-09 | Low | Accept | — | không đổi | **Low** | Head of Academic Affairs | Rà soát 2027-11-22 |
| R-10 | Low | Accept | — | không đổi | **Low** | Head of Academic Affairs | Rà soát 2027-11-22 |
| R-11 | Moderate | Mitigate | T-08, T-01, T-03, T-12 | High / Low → Moderate / High | **Moderate** | IT Lead | 2027-03-31 |
| R-12 | Moderate | Mitigate | T-10, T-06 | Low / Moderate → Low / Moderate | **Low** | Head of Academic Affairs | 2027-03-31 |
| R-13 | Low | Accept | — | không đổi | **Low** | IT Lead | Rà soát 2027-11-22 |

**Tổng hợp (projected):**
- Trước xử lý: 1 High, 8 Moderate, 4 Low.
- Sau xử lý: 0 High, 3 Moderate (R-01, R-03, R-11), 10 Low.
- Ba rủi ro còn ở mức Moderate cần **System owner chấp nhận theo ủy quyền** (§1.6).

### 4.3 Hồ sơ quyết định (mô phỏng)

Mỗi hồ sơ ghi lại: các phương án đã cân nhắc, lý do chọn, người quyết định và điều kiện để quyết định còn hiệu lực.

Có hai phương án được cân nhắc chung cho mọi rủi ro:
- **Avoid:** tức ngừng chức năng. Phương án này bị loại cho mọi rủi ro liên quan tới portal, vì portal phục vụ chức năng đào tạo cốt lõi (A-03).
- **Transfer:** bảo hiểm an ninh mạng chỉ bù đắp thiệt hại tài chính. Nó không khôi phục được dữ liệu và không chuyển được trách nhiệm bảo vệ dữ liệu cá nhân (A-05). Vì vậy transfer chỉ được xem là **bổ sung**, không thay thế mitigate.

#### D-R01
- **Escalation:** rủi ro bị escalate lên Risk executive, vì Impact là Very High.
- **Quyết định:** mitigate bằng T-01, T-02, T-03, T-08, T-12, T-13.
- **Lý do:**
  - Không được phép accept vì rủi ro ở mức High.
  - T-02 là gói then chốt, vì nó cắt bước "xóa backup". Nhờ vậy impact giảm từ Very High xuống High: dữ liệu vẫn có thể bị lộ, nhưng khôi phục được.
  - Bảo hiểm an ninh mạng được ghi nhận là phương án bổ sung, cần Risk executive cân nhắc riêng. Phần này nằm ngoài phạm vi báo cáo.
- **Phần còn lại:** residual Moderate được System owner chấp nhận theo ủy quyền, với điều kiện T-02 đạt thử khôi phục lần đầu.
- **Hạn rà soát:** 2027-11-22.

#### D-R02
- **Quyết định:** mitigate bằng T-01 và T-06.
- **Lý do:** MFA vô hiệu hóa gần như toàn bộ tấn công credential stuffing, với công sức thấp.

#### D-R03
- **Quyết định:** mitigate bằng T-05 và T-04.
- **Lý do:**
  - T-05 sửa trực tiếp lỗ hổng V-03.
  - T-04 bảo đảm điểm bị sửa sẽ bị phát hiện trước khi được dùng để cấp văn bằng. Nhờ vậy impact giảm từ High xuống Moderate.
- **Phần còn lại:** residual Moderate vì động cơ sửa điểm của sinh viên không đổi. System owner chấp nhận theo ủy quyền.

#### D-R04
- **Quyết định:** mitigate bằng T-04, T-03, T-06.
- **Lý do:**
  - Cần người thứ hai duyệt, tài khoản admin riêng, và log được bảo vệ.
  - Một insider muốn sửa dữ liệu khi đó phải thông đồng với người khác và để lại dấu vết.

#### D-R05
- **Quyết định:** mitigate bằng T-07.
- **Lý do:** rút ngắn cửa sổ vá và có WAF chặn trước.
- **Phần còn lại:** impact vẫn High vì kẻ tấn công vẫn có thể lấy được CSDL nếu khai thác thành công.

#### D-R06
- **Quyết định:** accept. Risk owner xác nhận.
- **Lý do:**
  - Rủi ro ở mức Low.
  - T-11 cần công sức vừa, nhưng chỉ giảm một rủi ro Low.
- **Điều kiện xem lại:** khi có dấu hiệu bị DDoS, hoặc khi bị đe dọa tống tiền bằng DDoS (ransom DDoS).

#### D-R07
- **Quyết định:** mitigate bằng T-09.
- **Lý do:** có baseline và mặc định chặn thì tần suất cấu hình sai giảm, nên mức khởi phát giảm từ Low xuống Very Low.

#### D-R08
- **Quyết định:** mitigate bằng T-02 và T-03.
- **Lý do:** backup đã được thử khôi phục thì impact giảm từ High xuống Moderate. Tối đa chỉ mất dữ liệu của 24 giờ gần nhất, tương ứng chu kỳ backup hằng ngày.

#### D-R09
- **Quyết định:** accept. Risk owner xác nhận.
- **Lý do:**
  - Bản backup ở region khác của T-02 có giúp, nhưng chưa được tính vào residual để giữ ước lượng thận trọng.
  - Phương án dựng site xử lý dự phòng (CP-7 Alternate processing site) bị hoãn vì chi phí cao so với một rủi ro Low.

#### D-R10
- **Quyết định:** accept. Risk owner xác nhận.
- **Lý do:** việc đối soát của T-04 sẽ giúp gián tiếp, nhưng chưa được tính vào residual.

#### D-R11
- **Quyết định:** mitigate bằng T-08, T-01, T-03, T-12.
- **Phần còn lại:** residual Moderate vì email chứa malware vẫn tới thường xuyên. System owner chấp nhận theo ủy quyền.

#### D-R12
- **Quyết định:** mitigate bằng T-10 và T-06.
- **Lý do:** giới hạn số hồ sơ xuất mỗi ngày làm số bản ghi có thể bị lộ giảm xuống dưới 1.000, nên impact giảm từ High xuống Moderate.
- **Phần còn lại:** khả năng gây tác động vẫn ở mức Moderate, vì insider vẫn có thể sao chép từng phần nhỏ.

#### D-R13
- **Quyết định:** accept. Risk owner xác nhận.
- **Hành động kèm theo:**
  - Thỏa thuận SLA với đơn vị CNTT trung tâm đang vận hành SSO (SA-9 External system services).
  - Hành động này không làm đổi rating.

### 4.4 Hạn chế của phần xử lý

- **Residual là dự kiến:** mọi residual mới là `projected`. Mức giảm của từng control là **[ĐG]**, chưa có số liệu hiệu quả thực tế.
- **Ước lượng công sức:** mức công sức chỉ là tương đối. Báo cáo không ước lượng chi phí bằng tiền và không dùng FAIR (đã hoãn).
- **Hạn triển khai:** các hạn là **[GĐ]**. Hạn của T-01 và T-03 sớm nhất, vì hai gói này cần công sức thấp nhất mà lại giảm được nhiều kịch bản nhất.

### 4.5 Kiểm chứng hiệu quả (để chuyển `projected` → `verified`)

| Gói | Bằng chứng cần có |
|---|---|
| T-01 | 100% tài khoản cán bộ và admin đã bật MFA, theo báo cáo từ IdP |
| T-02 | Biên bản thử khôi phục đạt yêu cầu. Thử xóa backup bằng một tài khoản đơn lẻ thì bị từ chối |
| T-03 | Đã xóa tài khoản dùng chung. Log ghi được thao tác đặc quyền theo từng người |
| T-04 | Thử sửa một điểm đã khóa sổ thì thay đổi bị giữ lại chờ người thứ hai duyệt |
| T-05 | Kết quả kiểm thử và pentest không còn lỗ hổng object-level authorization trên API sửa điểm |
| T-06 | Có biên bản xem log hằng tuần. Cảnh báo kích hoạt đúng khi thử nghiệm |
| T-07 | Báo cáo quét lỗ hổng. Thời gian vá lỗ hổng nghiêm trọng đúng mục tiêu |
| T-08 | Danh sách máy trạm quản trị, không có quyền local admin và không dùng email trên máy |
| T-09 | Rà soát cấu hình so với baseline không còn chênh lệch |
| T-10 | Cảnh báo kích hoạt khi thử xuất vượt giới hạn |
| T-12 | Tỷ lệ hoàn thành bài tập phishing thực hành |
| T-13 | Quy trình đã được phê duyệt và đã diễn tập mô phỏng (tabletop) |

---

## 5. Package & review (Đóng gói và rà soát)

### 5.1 Tính toán tự động và đối soát

**[risk.py](risk.py):**
- Chỉ dùng thư viện chuẩn của Python.
- Đọc [data/risk_register.csv](data/risk_register.csv).
- Tra bảng G-5 và I-2 để tính overall likelihood, mức rủi ro hiện tại và mức rủi ro còn lại.
- Gắn cờ theo chính sách ở §1.6.
- Sinh ra hai file [out/register.md](out/register.md) và [out/matrix.md](out/matrix.md).
- Script **chỉ gắn cờ** những việc mà chính sách yêu cầu. Nó không bao giờ tự chấp nhận rủi ro.

```
python risk.py           # sinh out/register.md và out/matrix.md
python risk.py --check   # chạy self-check
```

**Self-check (`--check`) kiểm tra 5 điều:**
1. Bảng G-5 và I-2 trong code khớp **từng ô** với bản chép nguyên văn trong [PLAN.md](PLAN.md).
2. Hai ví dụ tính tay ở §3.1 và §3.2 cho đúng kết quả.
3. Kịch bản có impact Very High luôn bị gắn cờ escalate.
4. Nhãn rating không hợp lệ (ví dụ `Medium`) làm script **báo lỗi**. Giá trị `unknown` làm dòng đó bị bỏ qua kèm cảnh báo, không bao giờ bị coi là 0.
5. Register thật được tính đủ 13 dòng mà không có cảnh báo nào.

Ngoài ra, khi cố ý sửa sai một ô của G-5 hoặc đưa một nhãn sai vào CSV, self-check đều báo lỗi đúng chỗ.

**Đối soát kết quả:** kết quả do script sinh ra khớp với phần tính tay ở 4 chỗ:
- Bảng §3.3, đủ 13 dòng.
- Ma trận ở §3.4.
- Thứ tự ưu tiên ở §3.5.
- Số lượng rủi ro còn lại ở §4.2: 0 High, 3 Moderate, 10 Low.

Lần đối soát duy nhất phát hiện sai khác là thứ tự trong nhóm rủi ro Low ở §3.5. Đã sửa: R-10 xếp sau cùng vì impact của nó thấp hơn.

### 5.2 Độ nhạy và chấm lại các rating sát ngưỡng

**Cách làm:** lần lượt nâng hoặc hạ **từng** rating đầu vào một mức, rồi xem mức rủi ro hiện tại có thay đổi không. Kết quả là **hầu hết các kịch bản đều nằm cạnh một ngưỡng**. Đây là đặc điểm thường gặp của thang định tính 5 mức. Bảng dưới chỉ liệt kê những thay đổi có thể **làm đổi quyết định xử lý**:

| Kịch bản | Confidence | Thay đổi một mức | Hệ quả đối với quyết định |
|---|---|---|---|
| R-06 (đang accept) | Low | Khởi phát hoặc G-4 tăng một mức thì mức rủi ro thành **Moderate** | Risk owner không còn được tự chấp nhận. Phải xử lý (T-11) hoặc cần System owner chấp nhận |
| R-13 (đang accept) | Medium | Khởi phát hoặc G-4 tăng một mức thì mức rủi ro thành **Moderate** | Như trên |
| R-03, R-11 (residual Moderate) | Low / Medium | Khởi phát, G-4 hoặc impact tăng một mức thì mức rủi ro hiện tại thành **High** | Cần Risk executive cấp ngoại lệ. Quyết định mitigate vẫn giữ nguyên |
| R-01 | Low | Impact giảm một mức thì mức rủi ro thành Moderate và **không còn phải escalate**. Khởi phát hoặc G-4 tăng một mức thì mức rủi ro thành Very High | Quyết định mitigate vẫn giữ nguyên trong cả hai hướng |

**Chấm lại các rating có confidence Low** (R-01, R-03, R-04, R-05, R-06, R-12):
- Hệ thống là hư cấu nên **không có bằng chứng mới** nào để dựa vào. Vì vậy mọi rating được **giữ nguyên**.
- Tuy vậy, kết quả độ nhạy dẫn tới hai thay đổi trong hồ sơ quyết định:
  - **R-06:** quyết định accept chỉ còn hiệu lực khi chưa có dấu hiệu bị DDoS hoặc bị tống tiền bằng DDoS. Nếu có, phải chấm lại ngay. Điều kiện này đã có trong D-R06, nay được nâng thành điều kiện bắt buộc.
  - **R-03:** thêm vào danh sách theo dõi ưu tiên của T-06. Mọi lần sửa điểm sau khi đã khóa sổ đều phải được xem lại.

### 5.3 Hạn chế tổng thể

1. **Hư cấu:** tổ chức, hệ thống, tình trạng control, tần suất và phê duyệt đều là **[GĐ]**. Kết quả chỉ minh họa phương pháp, không áp dụng được cho một hệ thống thật nếu chưa thu thập bằng chứng thật.
2. **Định tính:** các mức là phán đoán theo thang thứ bậc, không phải xác suất. Kết quả độ nhạy ở §5.2 cho thấy một thay đổi một mức thường đủ để đổi mức rủi ro.
3. **Không cộng dồn:** các kịch bản liên quan nhau được đánh giá riêng, ví dụ R-11 thường là bước đầu của R-01.
4. **Residual chưa kiểm chứng:** mọi residual đều là `projected`. Mức giảm của từng control là **[ĐG]**.
5. **Không có chi phí bằng tiền và không dùng FAIR:** công sức chỉ được ước lượng tương đối.
6. **Pháp lý:** nghĩa vụ bảo vệ dữ liệu cá nhân được coi là ràng buộc (A-05), nhưng chưa xác minh văn bản luật cụ thể.
7. **Nguồn:** các bảng của SP 800-30 Rev.1 (2012) được dùng nguyên văn. Có thể đã có bản phát hành mới hơn của SP 800-53, nhưng chưa xác minh (xem [PLAN.md](PLAN.md) §7).

### 5.4 Kết luận cho người ra quyết định

- **Rủi ro lớn nhất** là ransomware nhiều bước (R-01), ở mức **High** và đã được escalate.
  - Nguyên nhân gốc là ba điểm yếu đi cùng nhau: backup nằm cùng chỗ và dùng chung thông tin xác thực (V-02), chưa có MFA (V-01), tài khoản admin dùng chung (PC-02).
- **Ba gói nên làm trước** là T-01 (MFA), T-03 (tài khoản admin riêng) và T-02 (backup tách biệt, có thử khôi phục).
  - T-01 và T-03 cần công sức thấp, T-02 cần công sức vừa.
  - Ba gói giảm trực tiếp 5 trên 13 kịch bản: R-01, R-02, R-04, R-08, R-11. R-09 chỉ được lợi gián tiếp.
- **Sau khi triển khai đủ 12 gói** (T-11 được hoãn), mức rủi ro dự kiến còn 0 High, 3 Moderate, 10 Low.
  - Ba rủi ro Moderate còn lại (R-01, R-03, R-11) cần System owner chấp nhận theo ủy quyền.
  - Các mức này chỉ được coi là đạt khi có bằng chứng như liệt kê ở §4.5.
- **Đánh giá lại** khi gặp một trong các điều kiện ở §1.7, và chậm nhất vào 2027-11-22.
