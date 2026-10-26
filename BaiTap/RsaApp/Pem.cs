using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaApp;

/// <summary>Đọc PEM, giải mã DER (ASN.1) và in ra ý nghĩa từng phần.</summary>
internal static class Pem
{
    public static void View(string path)
    {
        string text = File.ReadAllText(path);
        var f = PemEncoding.Find(text);
        string label = text[f.Label];
        string b64 = text[f.Base64Data];
        byte[] der = Convert.FromBase64String(b64);

        Console.WriteLine($"Header : -----BEGIN {label}-----");
        Console.WriteLine($"Footer : -----END {label}-----");
        Console.WriteLine($"Phần thân là BASE64 của khối DER, dài {der.Length} byte (base64 dài {b64.Length} ký tự, mỗi 4 ký tự = 3 byte).");
        Console.WriteLine();
        Console.WriteLine(label switch
        {
            "PUBLIC KEY" => "Định dạng: X.509 SubjectPublicKeyInfo (SPKI) -> SEQUENCE { AlgorithmIdentifier, BIT STRING{ RSAPublicKey{ n, e } } }",
            "RSA PUBLIC KEY" => "Định dạng: PKCS#1 RSAPublicKey -> SEQUENCE { n, e }",
            "PRIVATE KEY" => "Định dạng: PKCS#8 PrivateKeyInfo -> SEQUENCE { version, AlgorithmIdentifier, OCTET STRING{ RSAPrivateKey } }",
            "RSA PRIVATE KEY" => "Định dạng: PKCS#1 RSAPrivateKey -> SEQUENCE { version, n, e, d, p, q, dP, dQ, qInv }",
            "ENCRYPTED PRIVATE KEY" => "Định dạng: PKCS#8 đã mã hóa bằng mật khẩu (không phân tích được nội dung nếu chưa giải mã).",
            _ => "Định dạng khác."
        });
        Console.WriteLine();
        Console.WriteLine("--- Hex của 48 byte DER đầu tiên ---");
        Console.WriteLine(BitConverter.ToString(der, 0, Math.Min(48, der.Length)).Replace('-', ' '));
        Console.WriteLine();
        Console.WriteLine("--- Cấu trúc ASN.1/DER (offset | byte tag+length | ý nghĩa) ---");
        if (label != "ENCRYPTED PRIVATE KEY") Dump(der, 0, der.Length, 0);
        Console.WriteLine();
        Console.WriteLine(Legend);
    }

    private const string Legend =
@"Cách đọc các byte DER (TLV = Tag - Length - Value):
  30        : tag SEQUENCE (0x30 = kiểu cấu trúc, chứa nhiều phần tử con)
  02        : tag INTEGER  (số nguyên lớn, big-endian; nếu bit cao = 1 thì thêm byte 00 phía trước để không thành số âm)
  03        : tag BIT STRING (byte đầu của giá trị là số bit thừa, thường 00)
  04        : tag OCTET STRING (chuỗi byte, ở PKCS#8 chứa nguyên khối RSAPrivateKey)
  06        : tag OBJECT IDENTIFIER (OID thuật toán, 2A 86 48 86 F7 0D 01 01 01 = 1.2.840.113549.1.1.1 = rsaEncryption)
  05 00     : tag NULL, độ dài 0 (tham số của rsaEncryption)
  Length    : nếu < 0x80 thì chính là độ dài; nếu 0x81/0x82 thì 1/2 byte tiếp theo chứa độ dài (vd 82 01 0A = 266 byte)";

    private static void Dump(byte[] d, int start, int end, int depth)
    {
        // Xác định nhãn nếu khối này là RSAPublicKey (2 INTEGER) hoặc RSAPrivateKey (9 INTEGER)
        string[]? labels = GuessLabels(d, start, end);
        int idx = 0;
        int p = start;
        string pad = new string(' ', depth * 2);
        while (p < end)
        {
            int tagPos = p;
            byte tag = d[p++];
            int len = d[p++];
            int lenBytes = 1;
            if ((len & 0x80) != 0)
            {
                int n = len & 0x7F;
                len = 0;
                for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
                lenBytes = 1 + n;
            }
            int vs = p, ve = p + len;
            string head = BitConverter.ToString(d, tagPos, 1 + lenBytes).Replace('-', ' ');
            string name = TagName(tag);
            string extra = "";

            if (tag == 0x02)
            {
                var v = new BigInteger(d.AsSpan(vs, len), isUnsigned: true, isBigEndian: true);
                string lab = labels != null && idx < labels.Length ? labels[idx] + " = " : "";
                string hex = Convert.ToHexString(d, vs, Math.Min(len, 12));
                extra = $"{lab}{(v.IsZero ? 0 : (int)v.GetBitLength())} bit, hex bắt đầu: {hex}{(len > 12 ? "..." : "")}";
                if (len <= 4) extra += $" (= {v})";
                idx++;
            }
            else if (tag == 0x06)
            {
                extra = DecodeOid(d, vs, len);
            }

            Console.WriteLine($"{pad}{tagPos,5} | {head,-14} | {name} ({len} byte) {extra}");

            bool constructed = (tag & 0x20) != 0;
            if (constructed)
            {
                Dump(d, vs, ve, depth + 1);
            }
            else if (tag == 0x03 && len > 1 && d[vs] == 0x00 && d[vs + 1] == 0x30)
            {
                Console.WriteLine($"{pad}      |   (byte 00 = 0 bit thừa; phần còn lại là DER lồng bên trong)");
                Dump(d, vs + 1, ve, depth + 1);
            }
            else if (tag == 0x04 && len > 0 && d[vs] == 0x30)
            {
                Dump(d, vs, ve, depth + 1);
            }
            p = ve;
        }
    }

    private static string[]? GuessLabels(byte[] d, int start, int end)
    {
        int p = start, count = 0;
        bool allInt = true;
        try
        {
            while (p < end)
            {
                byte tag = d[p++];
                int len = d[p++];
                if ((len & 0x80) != 0)
                {
                    int n = len & 0x7F; len = 0;
                    for (int i = 0; i < n; i++) len = (len << 8) | d[p++];
                }
                if (tag != 0x02) allInt = false;
                count++;
                p += len;
            }
        }
        catch { return null; }
        if (!allInt) return null;
        if (count == 2) return new[] { "n (modulus)", "e (public exponent)" };
        if (count == 9) return new[] { "version", "n (modulus)", "e (public exponent)", "d (private exponent)", "p (prime 1)", "q (prime 2)", "dP = d mod (p-1)", "dQ = d mod (q-1)", "qInv = q^-1 mod p" };
        return null;
    }

    private static string TagName(byte t) => t switch
    {
        0x30 => "SEQUENCE",
        0x31 => "SET",
        0x02 => "INTEGER",
        0x03 => "BIT STRING",
        0x04 => "OCTET STRING",
        0x05 => "NULL",
        0x06 => "OBJECT IDENTIFIER",
        0xA0 => "[0] context-specific",
        _ => $"tag 0x{t:X2}"
    };

    private static string DecodeOid(byte[] d, int s, int len)
    {
        var sb = new StringBuilder();
        long v = 0;
        bool first = true;
        for (int i = 0; i < len; i++)
        {
            v = (v << 7) | (uint)(d[s + i] & 0x7F);
            if ((d[s + i] & 0x80) == 0)
            {
                if (first)
                {
                    long a = v < 40 ? 0 : v < 80 ? 1 : 2;
                    sb.Append(a).Append('.').Append(v - a * 40);
                    first = false;
                }
                else sb.Append('.').Append(v);
                v = 0;
            }
        }
        string oid = sb.ToString();
        return oid == "1.2.840.113549.1.1.1" ? oid + " (rsaEncryption)" : oid;
    }

    // ---------------------------------------------------------------- import
    /// <summary>Nhập PEM; trả về đối tượng RSA và in n, e (và d, p, q... nếu là private key).</summary>
    public static RSA Import(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(path));
        RSAParameters pub = rsa.ExportParameters(false);
        Console.WriteLine($"Độ dài khóa: {rsa.KeySize} bit");
        Console.WriteLine("e (public exponent) = " + ToBig(pub.Exponent!) + $"  [hex {Convert.ToHexString(pub.Exponent!)}]");
        Console.WriteLine("n (modulus), hex:");
        Console.WriteLine(Convert.ToHexString(pub.Modulus!));
        try
        {
            RSAParameters pr = rsa.ExportParameters(true);
            Console.WriteLine();
            Console.WriteLine(">>> Đây là PRIVATE KEY (chứa cả thành phần công khai n, e)");
            Console.WriteLine($"d ({pr.D!.Length * 8} bit), hex: {Convert.ToHexString(pr.D)}");
            Console.WriteLine("p = " + Convert.ToHexString(pr.P!));
            Console.WriteLine("q = " + Convert.ToHexString(pr.Q!));
            Console.WriteLine("dP = " + Convert.ToHexString(pr.DP!));
            Console.WriteLine("dQ = " + Convert.ToHexString(pr.DQ!));
            Console.WriteLine("qInv = " + Convert.ToHexString(pr.InverseQ!));
        }
        catch (CryptographicException)
        {
            Console.WriteLine(">>> Đây là PUBLIC KEY (chỉ có n, e).");
        }
        return rsa;
    }

    private static BigInteger ToBig(byte[] b) => new BigInteger(b, isUnsigned: true, isBigEndian: true);
}
