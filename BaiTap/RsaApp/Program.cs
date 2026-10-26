using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace RsaApp;

/// <summary>
/// Bài 2 - RSA, SHA-256, chữ ký số (console, .NET 8).
/// Mã hóa dùng RSA-OAEP(SHA-256): với khóa 2048 bit, dữ liệu tối đa = 256 - 2*32 - 2 = 190 byte.
/// </summary>
internal static class Program
{
    private static RSA? _rsa;           // cặp khóa vừa sinh / vừa nhập (dùng cho ký)

    private static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8; // để nhập được tiếng Việt có dấu (Đ, ặ, ...)
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("========== RSA / SHA-256 / Chữ ký số ==========");
            Console.WriteLine($"Khóa trong bộ nhớ: {(_rsa == null ? "(chưa có)" : _rsa.KeySize + " bit")}");
            Console.WriteLine("1. Sinh cặp khóa RSA");
            Console.WriteLine("2. Xuất cặp khóa ra file PEM (public.pem + private.pem)");
            Console.WriteLine("3. Xem 1 file PEM (giải thích các byte)");
            Console.WriteLine("4. Nhập file PEM -> hiện n, e (và d, p, q... nếu là private key)");
            Console.WriteLine("5. Mã hóa (dữ liệu <= 190 byte) bằng PUBLIC key -> file base64");
            Console.WriteLine("6. Giải mã bằng PRIVATE key (file PEM + file base64) rồi so sánh với nguồn");
            Console.WriteLine("7. Đánh giá tốc độ mã hóa / giải mã (public e nhỏ vs private d lớn)");
            Console.WriteLine("8. Băm SHA-256 + hiệu ứng thác đổ (avalanche)");
            Console.WriteLine("9. Chữ ký số: xác định (PKCS#1 v1.5) vs ngẫu nhiên hóa (RSA-PSS / nonce)");
            Console.WriteLine("0. Thoát");
            Console.Write("Chọn: ");
            string? c = Console.ReadLine()?.Trim();
            try
            {
                switch (c)
                {
                    case "1": GenKey(); break;
                    case "2": ExportPem(); break;
                    case "3": Pem.View(Ask("File PEM", null)); break;
                    case "4": _rsa = Pem.Import(Ask("File PEM", null)); break;
                    case "5": Encrypt(); break;
                    case "6": Decrypt(); break;
                    case "7": Benchmark(); break;
                    case "8": HashMenu(); break;
                    case "9": SignMenu(); break;
                    case "0": return;
                    default: Console.WriteLine("Lựa chọn không hợp lệ."); break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("LỖI: " + ex.Message);
            }
        }
    }

    // ================================================================ 1, 2: khóa
    private static void GenKey()
    {
        string s = Ask("Độ dài khóa 1024/2048/3072/4096 [2048]", "2048");
        _rsa?.Dispose();
        _rsa = RSA.Create(int.Parse(s));
        var p = _rsa.ExportParameters(false);
        Console.WriteLine($"Đã sinh khóa {_rsa.KeySize} bit. e = {new BigInteger(p.Exponent!, true, true)}");
    }

    private static void ExportPem()
    {
        if (_rsa == null) throw new InvalidOperationException("Chưa có khóa (chọn 1 hoặc 4).");
        string pub = Ask("File public [public.pem]", "public.pem");
        string pri = Ask("File private [private.pem]", "private.pem");
        File.WriteAllText(pub, _rsa.ExportSubjectPublicKeyInfoPem());   // -----BEGIN PUBLIC KEY-----
        File.WriteAllText(pri, _rsa.ExportPkcs8PrivateKeyPem());        // -----BEGIN PRIVATE KEY-----
        Console.WriteLine($"Đã ghi {Path.GetFullPath(pub)} và {Path.GetFullPath(pri)}");
        Console.WriteLine("Lưu ý: private.pem phải giữ bí mật, không gửi cho người khác.");
    }

    // ================================================================ 5, 6: mã hóa
    private static void Encrypt()
    {
        string pem = Ask("File PEM chứa public key (hoặc private key)", "public.pem");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(pem));
        int max = rsa.KeySize / 8 - 2 * 32 - 2;
        Console.WriteLine($"Khóa {rsa.KeySize} bit -> dữ liệu tối đa {max} byte (OAEP-SHA256).");
        Console.WriteLine("Chọn dữ liệu: 1 = sinh ngẫu nhiên khóa AES-256 (32 byte); 2 = nhập văn bản");
        byte[] data;
        if (Ask("Chọn [1]", "1") == "1")
        {
            data = RandomNumberGenerator.GetBytes(32);
            Console.WriteLine("Khóa AES-256 (base64): " + Convert.ToBase64String(data));
        }
        else
        {
            Console.Write("Nhập văn bản: ");
            data = Encoding.UTF8.GetBytes(Console.ReadLine() ?? "");
        }
        if (data.Length > max) throw new ArgumentException($"Dữ liệu {data.Length} byte > {max} byte.");

        byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
        string outFile = Ask("File lưu bản mã [cipher.b64]", "cipher.b64");
        File.WriteAllText(outFile, Convert.ToBase64String(cipher));
        string plainFile = Ask("File lưu dữ liệu gốc (base64) để so sánh sau [plain.b64]", "plain.b64");
        File.WriteAllText(plainFile, Convert.ToBase64String(data));
        Console.WriteLine($"Bản mã {cipher.Length} byte đã lưu (base64) vào {Path.GetFullPath(outFile)}");
        Console.WriteLine("Hai lần mã hóa cùng dữ liệu cho bản mã khác nhau vì OAEP có seed ngẫu nhiên.");
    }

    private static void Decrypt()
    {
        string pem = Ask("File PEM private key [private.pem]", "private.pem");
        string cf = Ask("File bản mã base64 [cipher.b64]", "cipher.b64");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(pem));
        byte[] plain = rsa.Decrypt(Convert.FromBase64String(File.ReadAllText(cf).Trim()), RSAEncryptionPadding.OaepSHA256);
        Console.WriteLine($"Giải mã được {plain.Length} byte. Base64: {Convert.ToBase64String(plain)}");

        string pf = Ask("File dữ liệu gốc base64 để so sánh [plain.b64] (Enter để bỏ qua)", "");
        if (pf != "")
        {
            byte[] orig = Convert.FromBase64String(File.ReadAllText(pf).Trim());
            Console.WriteLine(orig.AsSpan().SequenceEqual(plain) ? "SO SÁNH: GIỐNG HỆT dữ liệu gốc." : "SO SÁNH: KHÁC dữ liệu gốc!");
        }
    }

    // ================================================================ 7: tốc độ
    private static void Benchmark()
    {
        int iters = int.Parse(Ask("Số lần lặp mỗi phép thử [200]", "200"));
        byte[] data = RandomNumberGenerator.GetBytes(32);
        Console.WriteLine();
        Console.WriteLine($"{"KeySize",8} {"e(bit)",7} {"d(bit)",7} {"Enc/ms (public)",17} {"Dec/ms (private)",18} {"Dec/Enc",8}");
        foreach (int bits in new[] { 1024, 2048, 3072, 4096 })
        {
            using var rsa = RSA.Create(bits);
            var pr = rsa.ExportParameters(true);
            int eBits = (int)new BigInteger(pr.Exponent!, true, true).GetBitLength();
            int dBits = (int)new BigInteger(pr.D!, true, true).GetBitLength();
            byte[] cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256); // khởi động (warm-up)
            rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < iters; i++) cipher = rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            double enc = sw.Elapsed.TotalMilliseconds / iters;
            sw.Restart();
            for (int i = 0; i < iters; i++) rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            double dec = sw.Elapsed.TotalMilliseconds / iters;
            Console.WriteLine($"{bits,8} {eBits,7} {dBits,7} {enc,17:F4} {dec,18:F4} {dec / enc,8:F1}");
        }
        Console.WriteLine();
        Console.WriteLine("Ghi chú: public key có e = 65537 (17 bit) nên lũy thừa modulo chỉ ~17 phép bình phương;");
        Console.WriteLine("private key có d xấp xỉ bằng n (cỡ 2048 bit) nên chậm hơn nhiều lần (dù .NET đã dùng CRT với p, q).");
    }

    // ================================================================ 8: SHA-256
    private static void HashMenu()
    {
        Console.WriteLine("Nhập chuỗi để băm; dòng trống để dừng. Chương trình so sánh với lần băm trước.");
        byte[]? prev = null;
        while (true)
        {
            Console.Write("> ");
            string s = Console.ReadLine() ?? "";
            if (s == "") break;
            byte[] h = SHA256.HashData(Encoding.UTF8.GetBytes(s));
            Console.WriteLine("SHA-256 = " + Convert.ToHexString(h).ToLowerInvariant());
            if (prev != null)
            {
                int diff = BitDiff(prev, h);
                Console.WriteLine($"Khác lần trước: {diff}/256 bit ({diff / 2.56:F1}%) - kỳ vọng ~128 bit (50%)");
            }
            prev = h;
        }

        Console.WriteLine();
        Console.WriteLine("--- Thí nghiệm: đổi đúng 1 bit của đầu vào, lặp 10000 lần ---");
        var rnd = new Random(1);
        long total = 0; int min = 256, max = 0;
        const int N = 10000;
        for (int i = 0; i < N; i++)
        {
            byte[] m = new byte[64];
            rnd.NextBytes(m);
            byte[] h1 = SHA256.HashData(m);
            int bit = rnd.Next(m.Length * 8);
            m[bit / 8] ^= (byte)(1 << (bit % 8));
            byte[] h2 = SHA256.HashData(m);
            int d = BitDiff(h1, h2);
            total += d; min = Math.Min(min, d); max = Math.Max(max, d);
        }
        Console.WriteLine($"Số bit băm thay đổi trung bình: {total / (double)N:F2}/256 ({total / (double)N / 2.56:F2}%), nhỏ nhất {min}, lớn nhất {max}");
        Console.WriteLine("=> Chỉ đổi 1 bit đầu vào, khoảng một nửa số bit đầu ra bị đổi (hiệu ứng thác đổ).");
    }

    private static int BitDiff(byte[] a, byte[] b)
    {
        int n = 0;
        for (int i = 0; i < a.Length; i++) n += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return n;
    }

    // ================================================================ 9: chữ ký số
    private static void SignMenu()
    {
        if (_rsa == null) { _rsa = RSA.Create(2048); Console.WriteLine("(Chưa có khóa nên đã sinh tạm khóa 2048 bit)"); }
        Console.Write("Nhập dữ liệu cần ký: ");
        byte[] data = Encoding.UTF8.GetBytes(Console.ReadLine() ?? "");
        const int K = 5;

        // (a) PKCS#1 v1.5: xác định -> luôn cùng chữ ký
        Console.WriteLine("\n(a) RSA PKCS#1 v1.5 (xác định), ký " + K + " lần cùng dữ liệu, cùng private key:");
        var setA = new HashSet<string>();
        for (int i = 0; i < K; i++)
        {
            byte[] sig = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            string b = Convert.ToBase64String(sig);
            setA.Add(b);
            Console.WriteLine($"  lần {i + 1}: {b[..40]}...");
        }
        Console.WriteLine($"  => {setA.Count} chữ ký khác nhau / {K} lần");

        // (b) RSA-PSS: salt ngẫu nhiên -> mỗi lần khác nhau, vẫn xác minh đúng
        Console.WriteLine("\n(b) RSA-PSS (đề xuất): salt ngẫu nhiên 32 byte trong mỗi lần ký:");
        var setB = new HashSet<string>();
        bool allOk = true;
        for (int i = 0; i < K; i++)
        {
            byte[] sig = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            bool ok = _rsa.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            allOk &= ok;
            string b = Convert.ToBase64String(sig);
            setB.Add(b);
            Console.WriteLine($"  lần {i + 1}: {b[..40]}...  verify={ok}");
        }
        Console.WriteLine($"  => {setB.Count} chữ ký khác nhau / {K} lần, tất cả xác minh đúng = {allOk}");
        byte[] tampered = (byte[])data.Clone();
        if (tampered.Length > 0) tampered[0] ^= 1; else tampered = new byte[] { 1 };
        byte[] s0 = _rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        Console.WriteLine("  Xác minh chữ ký trên dữ liệu bị sửa 1 bit: " +
            _rsa.VerifyData(tampered, s0, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) + " (phải là False)");

        // (c) nonce: ký H(data || nonce), gửi kèm nonce
        Console.WriteLine("\n(c) Phương pháp nonce: ký SHA256(data || nonce), gửi (nonce, chữ ký):");
        var setC = new HashSet<string>();
        for (int i = 0; i < K; i++)
        {
            var (nonce, sig) = SignWithNonce(_rsa, data);
            bool ok = VerifyWithNonce(_rsa, data, nonce, sig);
            string b = Convert.ToBase64String(sig);
            setC.Add(b);
            Console.WriteLine($"  lần {i + 1}: nonce={Convert.ToHexString(nonce)[..16]}... sig={b[..30]}... verify={ok}");
        }
        Console.WriteLine($"  => {setC.Count} chữ ký khác nhau / {K} lần");
    }

    public static (byte[] nonce, byte[] sig) SignWithNonce(RSA rsa, byte[] data)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(16);
        byte[] h = SHA256.HashData(Concat(data, nonce));
        return (nonce, rsa.SignHash(h, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    public static bool VerifyWithNonce(RSA rsa, byte[] data, byte[] nonce, byte[] sig)
    {
        byte[] h = SHA256.HashData(Concat(data, nonce));
        return rsa.VerifyHash(h, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        byte[] r = new byte[a.Length + b.Length];
        a.CopyTo(r, 0);
        b.CopyTo(r, a.Length);
        return r;
    }

    // ================================================================ tiện ích
    private static string Ask(string prompt, string? def)
    {
        Console.Write(prompt + ": ");
        string s = Console.ReadLine()?.Trim().Trim('"') ?? "";
        if (s == "")
        {
            if (def == null) throw new ArgumentException("Bạn chưa nhập giá trị.");
            return def;
        }
        return s;
    }
}
