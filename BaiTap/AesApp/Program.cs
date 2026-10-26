using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace AesApp;

/// <summary>
/// Bài 1 - Mã hóa đối xứng AES (console).
/// Chế độ: AES-CBC + PKCS7, IV ngẫu nhiên 16 byte được ghi ở đầu dữ liệu mã hóa.
/// File lớn được xử lý theo dòng (stream) nên chạy được với file hàng GB mà không tốn RAM.
/// </summary>
internal static class Program
{
    private const int BufSize = 1 << 20; // 1 MB

    private static byte[]? _key;

    private static void Main()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8; // để nhập được tiếng Việt có dấu (Đ, ặ, ...)
        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("========== AES (đối xứng) ==========");
            Console.WriteLine($"Khóa hiện tại: {(_key == null ? "(chưa có)" : _key.Length * 8 + " bit")}");
            Console.WriteLine("1. Sinh khóa AES");
            Console.WriteLine("2. Lưu khóa ra file");
            Console.WriteLine("3. Nhập (import) khóa từ file");
            Console.WriteLine("4. Mã hóa / giải mã 1 đoạn văn bản");
            Console.WriteLine("5. Mã hóa 1 file");
            Console.WriteLine("6. Giải mã 1 file");
            Console.WriteLine("7. So sánh 2 file theo byte");
            Console.WriteLine("8. TEST TỰ ĐỘNG: tạo file lớn -> mã hóa -> giải mã -> so sánh -> bảng số liệu");
            Console.WriteLine("0. Thoát");
            Console.Write("Chọn: ");
            string? c = Console.ReadLine()?.Trim();
            try
            {
                switch (c)
                {
                    case "1": GenKey(); break;
                    case "2": SaveKey(); break;
                    case "3": ImportKey(); break;
                    case "4": TextDemo(); break;
                    case "5": FileEncryptMenu(); break;
                    case "6": FileDecryptMenu(); break;
                    case "7": CompareMenu(); break;
                    case "8": AutoTest(); break;
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

    // ---------------------------------------------------------------- khóa
    private static void GenKey()
    {
        Console.Write("Độ dài khóa (128/192/256) [256]: ");
        string s = Console.ReadLine()?.Trim() ?? "";
        int bits = s == "" ? 256 : int.Parse(s);
        if (bits != 128 && bits != 192 && bits != 256) throw new ArgumentException("Chỉ hỗ trợ 128, 192, 256.");
        _key = RandomNumberGenerator.GetBytes(bits / 8);
        Console.WriteLine($"Đã sinh khóa {bits} bit (base64): {Convert.ToBase64String(_key)}");
    }

    private static void SaveKey()
    {
        RequireKey();
        string path = Ask("Đường dẫn file lưu khóa [aes.key]", "aes.key");
        File.WriteAllText(path, Convert.ToBase64String(_key!));
        Console.WriteLine("Đã lưu khóa (dạng base64) vào " + Path.GetFullPath(path));
    }

    private static void ImportKey()
    {
        string path = Ask("Đường dẫn file khóa [aes.key]", "aes.key");
        byte[] k = Convert.FromBase64String(File.ReadAllText(path).Trim());
        if (k.Length != 16 && k.Length != 24 && k.Length != 32)
            throw new CryptographicException($"Khóa không hợp lệ: {k.Length} byte (cần 16/24/32).");
        _key = k;
        Console.WriteLine($"Đã nhập khóa {k.Length * 8} bit.");
    }

    private static void RequireKey()
    {
        if (_key == null) throw new InvalidOperationException("Chưa có khóa. Hãy sinh khóa (1) hoặc nhập khóa (3) trước.");
    }

    // ---------------------------------------------------------------- văn bản
    private static void TextDemo()
    {
        RequireKey();
        Console.Write("Nhập đoạn văn bản cần mã hóa: ");
        string text = Console.ReadLine() ?? "";
        string b64 = EncryptText(text, _key!);
        Console.WriteLine("Kết quả mã hóa (base64, 16 byte đầu là IV):");
        Console.WriteLine(b64);
        Console.WriteLine("Giải mã lại: " + DecryptText(b64, _key!));
    }

    public static string EncryptText(string text, byte[] key)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] iv = RandomNumberGenerator.GetBytes(16);
        byte[] cipher = aes.EncryptCbc(Encoding.UTF8.GetBytes(text), iv, PaddingMode.PKCS7);
        byte[] all = new byte[16 + cipher.Length];
        iv.CopyTo(all, 0);
        cipher.CopyTo(all, 16);
        return Convert.ToBase64String(all);
    }

    public static string DecryptText(string b64, byte[] key)
    {
        byte[] all = Convert.FromBase64String(b64);
        using var aes = Aes.Create();
        aes.Key = key;
        byte[] plain = aes.DecryptCbc(all.AsSpan(16), all.AsSpan(0, 16), PaddingMode.PKCS7);
        return Encoding.UTF8.GetString(plain);
    }

    // ---------------------------------------------------------------- file
    private static void FileEncryptMenu()
    {
        RequireKey();
        string src = Ask("File nguồn", null);
        string dst = Ask("File mã hóa [" + src + ".enc]", src + ".enc");
        TimeSpan t = EncryptFile(src, dst, _key!);
        Console.WriteLine($"Xong. Thời gian mã hóa: {t.TotalSeconds:F3} s");
    }

    private static void FileDecryptMenu()
    {
        RequireKey();
        string src = Ask("File đã mã hóa", null);
        string dst = Ask("File giải mã [" + src + ".dec]", src + ".dec");
        TimeSpan t = DecryptFile(src, dst, _key!);
        Console.WriteLine($"Xong. Thời gian giải mã: {t.TotalSeconds:F3} s");
    }

    public static TimeSpan EncryptFile(string src, string dst, byte[] key)
    {
        var sw = Stopwatch.StartNew();
        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        fout.Write(aes.IV, 0, 16);
        using (var cs = new CryptoStream(fout, aes.CreateEncryptor(), CryptoStreamMode.Write, leaveOpen: true))
        {
            fin.CopyTo(cs, BufSize);
            cs.FlushFinalBlock();
        }
        fout.Flush();
        sw.Stop();
        return sw.Elapsed;
    }

    public static TimeSpan DecryptFile(string src, string dst, byte[] key)
    {
        var sw = Stopwatch.StartNew();
        using var fin = new FileStream(src, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        byte[] iv = new byte[16];
        fin.ReadExactly(iv, 0, 16);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using var fout = new FileStream(dst, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        using (var cs = new CryptoStream(fin, aes.CreateDecryptor(), CryptoStreamMode.Read, leaveOpen: true))
        {
            cs.CopyTo(fout, BufSize);
        }
        fout.Flush();
        sw.Stop();
        return sw.Elapsed;
    }

    // ---------------------------------------------------------------- so sánh theo byte
    private static void CompareMenu()
    {
        string a = Ask("File 1", null);
        string b = Ask("File 2", null);
        long diff = CompareFiles(a, b);
        Console.WriteLine(diff < 0 ? "GIỐNG HỆT nhau theo từng byte." : $"KHÁC nhau, byte khác đầu tiên ở vị trí {diff}.");
    }

    /// <returns>-1 nếu hai file giống hệt; ngược lại là vị trí byte khác đầu tiên.</returns>
    public static long CompareFiles(string a, string b)
    {
        using var fa = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        using var fb = new FileStream(b, FileMode.Open, FileAccess.Read, FileShare.Read, BufSize, FileOptions.SequentialScan);
        if (fa.Length != fb.Length) return Math.Min(fa.Length, fb.Length);
        byte[] ba = new byte[BufSize];
        byte[] bb = new byte[BufSize];
        long pos = 0;
        while (true)
        {
            int na = fa.Read(ba, 0, BufSize);
            if (na == 0) return -1;
            fb.ReadExactly(bb, 0, na);
            var sa = ba.AsSpan(0, na);
            var sb = bb.AsSpan(0, na);
            if (!sa.SequenceEqual(sb))
            {
                int i = sa.CommonPrefixLength(sb);
                return pos + i;
            }
            pos += na;
        }
    }

    // ---------------------------------------------------------------- test tự động
    private static void AutoTest()
    {
        RequireKey();
        Console.Write("Các kích thước test, đơn vị MB, cách nhau bằng dấu phẩy [10,100,1000,4000]: ");
        string s = Console.ReadLine()?.Trim() ?? "";
        if (s == "") s = "10,100,1000,4000";
        long[] sizesMb = s.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(long.Parse).ToArray();
        string dir = Ask("Thư mục chứa file tạm [./aes_test]", "./aes_test");
        Directory.CreateDirectory(dir);

        var csv = new StringBuilder("size_mb,encrypt_s,decrypt_s,enc_MBps,dec_MBps,identical\n");
        Console.WriteLine();
        Console.WriteLine($"{"Size(MB)",10} {"Enc(s)",10} {"Dec(s)",10} {"Enc MB/s",10} {"Dec MB/s",10} {"Giống?",8}");
        foreach (long mb in sizesMb)
        {
            string src = Path.Combine(dir, $"src_{mb}MB.bin");
            string enc = src + ".enc";
            string dec = src + ".dec";
            CreateRandomFile(src, mb);
            double te = EncryptFile(src, enc, _key!).TotalSeconds;
            double td = DecryptFile(enc, dec, _key!).TotalSeconds;
            bool same = CompareFiles(src, dec) < 0;
            Console.WriteLine($"{mb,10} {te,10:F2} {td,10:F2} {mb / te,10:F1} {mb / td,10:F1} {(same ? "ĐÚNG" : "SAI"),8}");
            csv.AppendLine(FormattableString.Invariant($"{mb},{te:F3},{td:F3},{mb / te:F1},{mb / td:F1},{same}"));
            File.Delete(src); File.Delete(enc); File.Delete(dec); // tránh đầy ổ đĩa
        }
        string csvPath = Path.Combine(dir, "aes_results.csv");
        File.WriteAllText(csvPath, csv.ToString());
        Console.WriteLine("Đã ghi số liệu: " + Path.GetFullPath(csvPath));
    }

    private static void CreateRandomFile(string path, long mb)
    {
        var rnd = new Random(12345);
        byte[] buf = new byte[BufSize];
        using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, BufSize);
        for (long i = 0; i < mb; i++)
        {
            rnd.NextBytes(buf);
            fs.Write(buf, 0, buf.Length);
        }
    }

    // ---------------------------------------------------------------- tiện ích
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
