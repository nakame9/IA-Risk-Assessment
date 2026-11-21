# Báo cáo đánh giá rủi ro IA: Cổng hồ sơ sinh viên (hệ thống hư cấu)

> **Trạng thái:** Giai đoạn 1 (Frame) đã xong. Các giai đoạn 2–5 chưa thực hiện.
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

Anchor riêng cho hệ thống. Các ngưỡng số đều là **[GĐ]**:

| Mức | Bảo mật (C) | Toàn vẹn (I) | Sẵn sàng (A) |
|---|---|---|---|
| Very Low | Lộ thông tin vốn đã công khai, ví dụ danh bạ khoa | Sai lệch hiển thị, dữ liệu gốc không bị ảnh hưởng | Gián đoạn dưới 1 giờ, ngoài kỳ đăng ký |
| Low | Lộ dữ liệu cá nhân không nhạy cảm của dưới 10 sinh viên | Sai lệch nhỏ, phát hiện và sửa được từ log trong ngày | Gián đoạn dưới 1 ngày, ngoài kỳ đăng ký |
| Moderate | Lộ hồ sơ hoặc điểm của 10–1.000 sinh viên | Sửa điểm trái phép nhưng phát hiện được trước khi cấp bảng điểm | Gián đoạn 1–3 ngày, hoặc vài giờ trong kỳ đăng ký |
| High | Lộ phần lớn hoặc toàn bộ CSDL (trên 1.000 sinh viên) | Dữ liệu điểm hoặc tốt nghiệp bị sửa mà không phát hiện được, và đã được dùng để cấp văn bằng | Không cấp được bảng điểm hoặc bằng trong hơn 1 tuần, hoặc mất trọn một kỳ đăng ký |
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

## 2–5. Identify / Assess / Treat / Package

*Chưa thực hiện. Xem kế hoạch trong [PLAN.md](PLAN.md).*
