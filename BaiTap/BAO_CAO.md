# Báo cáo bài tập An toàn và Bảo mật thông tin: AES, RSA, SHA-256, chữ ký số

Mã nguồn: `AesApp/` (bài 1) và `RsaApp/` (bài 2), đều là ứng dụng console .NET 8.
Chạy bằng `dotnet run --project AesApp` và `dotnet run --project RsaApp`.

> **Nguồn số liệu.** Số liệu bài 2 (RSA, SHA-256, chữ ký) và phần thử AES trên file nhỏ được đo bằng chính hai app C# chạy trên máy của sinh viên (.NET 10, Windows), có ảnh chụp minh chứng.
> Bảng AES với file lớn (hàng GB) hiện là số liệu tham chiếu của bản Python tương đương (`reference_check.py`, cùng thuật toán AES-256-CBC) và cần thay bằng kết quả menu 8 của app AES chạy trên máy sinh viên.

---

## Bài 1. AES (mã hóa đối xứng)

### Thiết kế
| Yêu cầu | Cách làm trong `AesApp` |
|---|---|
| 1. Sinh khóa | Menu 1: `RandomNumberGenerator.GetBytes` (128/192/256 bit) |
| 2. Lưu khóa ra file | Menu 2: ghi base64 vào `aes.key` |
| 3. Import khóa | Menu 3: đọc base64, kiểm tra độ dài 16/24/32 byte |
| 4. Mã hóa văn bản | Menu 4: AES-CBC + PKCS7, IV ngẫu nhiên 16 byte đặt ở đầu, in base64 ra màn hình và giải mã lại để đối chiếu |
| 5. Mã hóa file | Menu 5 và 6: `CryptoStream`, đệm 1 MB, xử lý theo dòng nên file hàng GB không tốn RAM |
| So sánh byte | Menu 7: đọc từng khối 1 MB, `SequenceEqual`, báo vị trí byte khác đầu tiên |
| Test file lớn và đo thời gian | Menu 8: tạo file ngẫu nhiên, mã hóa, giải mã, so sánh, in bảng và ghi `aes_results.csv` |

### Kết quả thử trên máy sinh viên (file nhỏ `test.txt`)
| Bước | Kết quả |
|---|---|
| Sinh khóa 256 bit, lưu `aes.key` | Thành công |
| Mã hóa văn bản "Chu Đặng Trung Long K235480106045" | In ra bản mã base64 (16 byte đầu là IV), giải mã lại được |
| Mã hóa file `test.txt` | 0.002 s |
| Giải mã file `test.txt.enc` | 0.007 s |
| So sánh `test.txt` và `test.txt.enc.dec` | GIỐNG HỆT nhau theo từng byte |

### Số liệu file lớn (AES-256-CBC, số liệu tham chiếu, cần thay bằng số đo menu 8 trên máy sinh viên)
| Kích thước (MB) | Mã hóa (s) | Giải mã (s) | Mã hóa (MB/s) | Giải mã (MB/s) | So sánh byte |
|---:|---:|---:|---:|---:|---|
| 100 | 0.14 | 0.08 | 696 | 1326 | Giống hệt |
| 1000 | 1.42 | 0.78 | 703 | 1276 | Giống hệt |
| 3000 | 4.38 | 2.43 | 685 | 1233 | Giống hệt |

### Kết luận
1. Giải mã cho file giống hệt file gốc theo từng byte ở mọi kích thước, nên AES-CBC cộng PKCS7 đúng đắn, không mất dữ liệu.
2. Thời gian tăng gần tuyến tính theo kích thước: 10 lần dữ liệu thì thời gian tăng khoảng 10 lần (0.14 s, 1.42 s, 4.38 s cho 100, 1000, 3000 MB). Tốc độ ổn định khoảng 700 MB/s khi mã hóa, nên file hàng GB vẫn xử lý trong vài giây.
3. Giải mã nhanh hơn mã hóa khoảng 1.8 lần. Lý do: CBC khi mã hóa phải tuần tự (khối sau cần kết quả khối trước), còn khi giải mã các khối độc lập nên phần cứng chạy song song được.
4. Nhờ xử lý theo dòng, bộ nhớ dùng gần như hằng số (khoảng vài MB) bất kể file lớn bao nhiêu. Nếu đọc nguyên file vào RAM, file hàng GB sẽ gây tràn bộ nhớ.
5. Hạn chế: CBC chỉ bảo đảm bí mật, không chống sửa đổi. Hệ thống thực tế nên dùng AES-GCM (có xác thực) hoặc thêm HMAC.

---

## Bài 2. RSA, SHA-256, chữ ký số

### 2.1 Các chức năng (menu 1 đến 6)
- **Sinh khóa** (1) và **xuất PEM** (2): `public.pem` có tiêu đề `BEGIN PUBLIC KEY` (X.509 SPKI), `private.pem` có tiêu đề `BEGIN PRIVATE KEY` (PKCS#8).
- **View PEM** (3): tách header, giải base64 ra DER và in cây ASN.1 kèm offset, byte tag/length và nhãn từng trường (n, e, d, p, q, dP, dQ, qInv).
- **Import PEM** (4): với public key hiện n, e; với private key hiện thêm d, p, q, dP, dQ, qInv.
- **Mã hóa** (5): RSA-OAEP SHA-256. Với khóa 2048 bit, dữ liệu tối đa 256 − 2×32 − 2 = **190 byte**, đúng đề bài. Khóa AES-256 (32 byte) nằm gọn trong giới hạn. Bản mã lưu base64.
- **Giải mã** (6): đọc PEM private và file base64, rồi so sánh với dữ liệu gốc. Đã kiểm tra: đúng 190 byte mã hóa được, 191 byte bị từ chối.

### 2.2 Ý nghĩa các byte trong PEM
PEM = dòng `-----BEGIN <nhãn>-----`, thân là **base64 của DER**, dòng `-----END <nhãn>-----`. Cứ 4 ký tự base64 ứng với 3 byte. DER mã hóa theo kiểu TLV (Tag, Length, Value):

| Byte | Ý nghĩa |
|---|---|
| `30` | SEQUENCE (cấu trúc chứa nhiều phần tử) |
| `02` | INTEGER (số nguyên lớn, big-endian; thêm byte `00` đầu nếu bit cao bằng 1 để không bị hiểu là số âm) |
| `03` | BIT STRING (byte đầu = số bit thừa, thường `00`) |
| `04` | OCTET STRING (ở PKCS#8 chứa nguyên khối RSAPrivateKey) |
| `05 00` | NULL (tham số của rsaEncryption) |
| `06` | OBJECT IDENTIFIER; `2A 86 48 86 F7 0D 01 01 01` = 1.2.840.113549.1.1.1 = rsaEncryption |
| Length | Nhỏ hơn `0x80`: chính là độ dài. `81 xx` hoặc `82 xx xx`: độ dài nằm ở 1 hoặc 2 byte tiếp theo |

**Kết quả thực tế trên máy sinh viên (khóa 2048 bit):** `public.pem` có phần DER dài 294 byte (base64 398 ký tự), `private.pem` (PKCS#8) có DER dài 1217 byte (base64 1649 ký tự). Khi nhập PEM, e = 65537 (hex `010001`, 17 bit), n 2048 bit bắt đầu bằng `B73B3FFC...`, d dài 2047 bit, p và q mỗi số 1024 bit, dP và dQ 1023 bit, qInv 1024 bit. Phần n của public key và private key giống hệt nhau, đúng lý thuyết (private key chứa cả n và e).

Public key (SPKI) 2048 bit: `30 82 01 22` (SEQUENCE dài 290 byte), `30 0D 06 09 ... 05 00` (thuật toán RSA), `03 82 01 0F 00` (BIT STRING), rồi `30 82 01 0A 02 82 01 01 00 <n 256 byte> 02 03 01 00 01` (n, rồi e = `01 00 01` = 65537).
Private key (PKCS#8) thêm các trường: version (0), n, e, **d**, **p**, **q**, dP = d mod (p−1), dQ = d mod (q−1), qInv = q⁻¹ mod p. Hai giá trị dP, dQ, qInv dùng để tăng tốc giải mã theo định lý số dư Trung Hoa (CRT).

### 2.3 Tốc độ: public key (e nhỏ) và private key (d lớn) (menu 7)
Mã hóa 32 byte, OAEP-SHA256, e = 65537 (17 bit):

| Khóa (bit) | e (bit) | d (bit) | Mã hóa, public (ms) | Giải mã, private (ms) | Giải mã / Mã hóa |
|---:|---:|---:|---:|---:|---:|
| 1024 | 17 | 1024 | 0.0042 | 0.0746 | 17.8 |
| 2048 | 17 | 2047 | 0.0131 | 0.4096 | 31.3 |
| 3072 | 17 | 3072 | 0.0274 | 1.2988 | 47.4 |
| 4096 | 17 | 4095 | 0.0481 | 2.9658 | 61.7 |

(Số liệu đo bằng menu 7 của app RsaApp trên máy sinh viên, 200 lần lặp mỗi phép thử.)

**Nhận xét:**
- Mã hóa tính c = mᵉ mod n với e chỉ 17 bit, tức khoảng 17 phép bình phương và 2 phép nhân modulo (65537 = 2¹⁶ + 1). Giải mã tính m = cᵈ mod n với d xấp xỉ n (cỡ 2048 bit), tức hàng nghìn phép nhân modulo trên số 2048 bit, nên chậm hơn nhiều.
- Giải mã đã được tăng tốc bằng CRT (làm việc theo p và q có kích thước một nửa); không có CRT thì còn chậm hơn khoảng 3 đến 4 lần.
- Khoảng cách tăng khi khóa dài hơn: với khóa 1024 bit giải mã chậm hơn mã hóa khoảng 18 lần, với 4096 bit khoảng 62 lần. Khi độ dài khóa tăng 4 lần (1024 lên 4096 bit), thời gian giải mã tăng khoảng 40 lần (0.0746 lên 2.9658 ms), tức xấp xỉ bậc 3 theo độ dài khóa; còn thời gian mã hóa chỉ tăng khoảng 11,5 lần (0.0042 lên 0.0481 ms), xấp xỉ bậc 2.
- Hệ quả thực tế: RSA chỉ dùng để trao đổi khóa AES (32 byte) hoặc ký số, còn dữ liệu lớn mã hóa bằng AES. Ước tính từ số đo: với khóa 2048 bit, mỗi lần mã hóa xử lý tối đa 190 byte trong 0.0131 ms, tức khoảng 14 MB/s; mỗi lần giải mã mất 0.4096 ms cho 190 byte, tức chỉ khoảng 0.5 MB/s. AES-256-CBC đạt vài trăm MB/s (xem bảng AES), nhanh hơn RSA từ vài chục lần (so với mã hóa public key) đến hàng nghìn lần (so với giải mã private key).

### 2.4 SHA-256 và hiệu ứng thác đổ (menu 8)
Ứng dụng nhập chuỗi, in SHA-256 (256 bit = 64 ký tự hex) và so sánh số bit khác so với lần băm trước.
Ví dụ đo trên máy sinh viên:

| Chuỗi nhập | SHA-256 (đầu) | Số bit khác chuỗi trước |
|---|---|---|
| `long long long` | `0746cac0...` | (chuỗi đầu tiên) |
| `long long longg` (thêm 1 ký tự) | `552f7871...` | 138/256 (53,9%) |
| `Long longh lonn` | `888fdc6e...` | 125/256 (48,8%) |
| `Long longh lonn` (nhập lại y hệt) | `888fdc6e...` | 0/256 (0%) |

Dòng cuối cho thấy cùng đầu vào thì luôn ra cùng một giá trị băm (tính xác định), còn chỉ cần khác 1 ký tự là băm khác hẳn.
Thí nghiệm đổi **đúng 1 bit** của đầu vào, lặp 10000 lần: trung bình **127.94/256 bit (49.98%)** của băm bị đổi (nhỏ nhất 96, lớn nhất 155).
Kết luận: thay đổi rất nhỏ ở đầu vào làm khoảng một nửa số bit đầu ra thay đổi một cách không thể đoán (hiệu ứng thác đổ). Nhờ vậy không thể suy ra đầu vào từ băm, và sửa dữ liệu dù chỉ 1 bit đều làm chữ ký không còn khớp.

### 2.5 Chữ ký số và đề xuất để mỗi lần ký ra chữ ký khác nhau (menu 9)
**Vấn đề.** Chữ ký số = RSA dùng khóa bí mật trên giá trị băm: s = (đệm(H(m)))ᵈ mod n.
Với chuẩn đệm **PKCS#1 v1.5** mọi bước đều xác định, nên cùng dữ liệu và cùng private key luôn cho đúng một chữ ký. Thí nghiệm: 5 lần ký chỉ ra **1** chữ ký khác nhau.

**Đề xuất 1 (chính): dùng RSA-PSS (Probabilistic Signature Scheme, PKCS#1 v2.1 / RFC 8017).**
Ý tưởng: thêm một **salt ngẫu nhiên** vào bước đệm trước khi lũy thừa bằng d.
1. mHash = SHA256(m).
2. Sinh salt ngẫu nhiên (32 byte) mới mỗi lần ký.
3. H = SHA256(00×8 ‖ mHash ‖ salt).
4. DB = (đệm 00..01) ‖ salt; maskedDB = DB XOR MGF1(H); EM = maskedDB ‖ H ‖ BC.
5. Chữ ký s = EMᵈ mod n.

Khi xác minh, người nhận tính EM = sᵉ mod n, **khôi phục salt** từ maskedDB (bỏ mặt nạ MGF1(H)), tính lại H' từ mHash và salt đó, rồi so H' với H trong EM. Vì salt được nhúng sẵn trong chữ ký nên không cần gửi riêng, và mọi lần ký đều xác minh đúng.
Trong C#: `rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)`.

**Kết quả thử trên máy sinh viên** (dữ liệu "Chu Dang Trung Long", khóa 2048 bit, menu 9, mỗi cách ký 5 lần):

| Cách ký | Số chữ ký khác nhau | Xác minh |
|---|---|---|
| PKCS#1 v1.5 (xác định) | 1 / 5 (cả 5 lần đều bắt đầu `cBcb6f0EwVjPN0Dp...`) | không áp dụng |
| RSA-PSS | 5 / 5 | cả 5 đều `True` |
| Nonce | 5 / 5 | cả 5 đều `True` |

Ngoài ra, xác minh chữ ký trên dữ liệu bị sửa 1 bit cho kết quả `False`, đúng như mong đợi.
PSS còn có chứng minh bảo mật chặt hơn PKCS#1 v1.5 và là lựa chọn được khuyến nghị hiện nay.

**Đề xuất 2 (thay thế): thêm nonce vào dữ liệu trước khi ký.**
Ký SHA256(m ‖ nonce) với nonce ngẫu nhiên 16 byte, rồi gửi kèm (nonce, chữ ký). Người nhận ghép lại m ‖ nonce, băm và xác minh. Cách này dễ hiểu và dùng được với mọi thuật toán ký, nhưng phải truyền thêm nonce và tự quy ước định dạng; app đã cài sẵn ở phần (c) của menu 9 (`SignWithNonce`, `VerifyWithNonce`).

**So sánh nhanh.**
| Cách | Chữ ký các lần khác nhau | Phải gửi thêm dữ liệu | Chuẩn hóa |
|---|---|---|---|
| PKCS#1 v1.5 | Không (luôn giống) | Không | Có |
| RSA-PSS | Có | Không (salt nằm trong chữ ký) | Có (RFC 8017) |
| Nonce tự định nghĩa | Có | Có (nonce) | Không |

Lưu ý: cho chữ ký khác nhau mỗi lần **không làm yếu** bảo mật, vì tính xác minh được dựa trên cặp (khóa công khai, dữ liệu). Mọi chữ ký hợp lệ đều chứng minh người giữ private key đã ký đúng dữ liệu đó.
