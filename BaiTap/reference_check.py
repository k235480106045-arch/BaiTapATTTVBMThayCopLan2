"""Bản tham chiếu bằng Python: cùng thuật toán với 2 app C#, dùng để kiểm chứng logic và lấy số liệu minh họa."""
import os, time, random, hashlib, base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad

BUF = 1 << 20
DIR = "/tmp/claude-0/aes_ref"
os.makedirs(DIR, exist_ok=True)

def make_file(path, mb):
    rnd = random.Random(12345)
    with open(path, "wb") as f:
        for _ in range(mb):
            f.write(rnd.randbytes(BUF))

def enc_file(src, dst, key):
    iv = os.urandom(16)
    c = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    p = padding.PKCS7(128).padder()
    t = time.perf_counter()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        fo.write(iv)
        while chunk := fi.read(BUF):
            fo.write(c.update(p.update(chunk)))
        fo.write(c.update(p.finalize()) + c.finalize())
    return time.perf_counter() - t

def dec_file(src, dst, key):
    t = time.perf_counter()
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        iv = fi.read(16)
        c = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        u = padding.PKCS7(128).unpadder()
        while chunk := fi.read(BUF):
            fo.write(u.update(c.update(chunk)))
        fo.write(u.update(c.finalize()) + u.finalize())
    return time.perf_counter() - t

def same(a, b):
    with open(a, "rb") as fa, open(b, "rb") as fb:
        while True:
            x, y = fa.read(BUF), fb.read(BUF)
            if x != y: return False
            if not x: return True

print("=== AES-256-CBC, file lớn ===")
key = os.urandom(32)
print(f"{'MB':>6} {'enc s':>8} {'dec s':>8} {'enc MB/s':>9} {'dec MB/s':>9} identical")
for mb in (100, 1000, 3000):
    s = f"{DIR}/s.bin"; e = s + ".enc"; d = s + ".dec"
    make_file(s, mb)
    te = enc_file(s, e, key); td = dec_file(e, d, key)
    ok = same(s, d)
    print(f"{mb:>6} {te:>8.2f} {td:>8.2f} {mb/te:>9.0f} {mb/td:>9.0f} {ok}")
    for x in (s, e, d): os.remove(x)

print("\n=== RSA-OAEP-SHA256, mã hóa 32 byte ===")
print(f"{'bits':>5} {'e bit':>6} {'d bit':>6} {'enc ms':>9} {'dec ms':>9} {'dec/enc':>8}")
data = os.urandom(32)
oaep = apad.OAEP(mgf=apad.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
for bits in (1024, 2048, 3072, 4096):
    k = rsa.generate_private_key(65537, bits)
    n = 200 if bits < 4096 else 100
    ct = k.public_key().encrypt(data, oaep)
    t = time.perf_counter()
    for _ in range(n): ct = k.public_key().encrypt(data, oaep)
    enc = (time.perf_counter() - t) / n * 1000
    t = time.perf_counter()
    for _ in range(n): k.decrypt(ct, oaep)
    dec = (time.perf_counter() - t) / n * 1000
    dbits = k.private_numbers().d.bit_length()
    print(f"{bits:>5} {17:>6} {dbits:>6} {enc:>9.4f} {dec:>9.4f} {dec/enc:>8.1f}")
k = rsa.generate_private_key(65537, 2048)
mx = 256 - 2*32 - 2
print(f"Giới hạn OAEP-SHA256 với 2048 bit: {mx} byte; thử {mx} byte:", end=" ")
k.public_key().encrypt(os.urandom(mx), oaep); print("OK", end="; ")
try:
    k.public_key().encrypt(os.urandom(mx + 1), oaep); print("191 byte: OK (bất thường)")
except ValueError:
    print("191 byte: bị từ chối")

print("\n=== SHA-256 avalanche (đổi 1 bit, 10000 lần) ===")
rnd = random.Random(1); tot = 0; mn, mxx = 256, 0
for _ in range(10000):
    m = bytearray(rnd.randbytes(64))
    h1 = hashlib.sha256(m).digest()
    b = rnd.randrange(512); m[b // 8] ^= 1 << (b % 8)
    h2 = hashlib.sha256(m).digest()
    d = bin(int.from_bytes(h1, "big") ^ int.from_bytes(h2, "big")).count("1")
    tot += d; mn = min(mn, d); mxx = max(mxx, d)
print(f"trung bình {tot/10000:.2f}/256 bit ({tot/10000/2.56:.2f}%), min {mn}, max {mxx}")
a = hashlib.sha256(b"Hello").hexdigest(); b = hashlib.sha256(b"Hellp").hexdigest()
print("Hello:", a); print("Hellp:", b)

print("\n=== Chữ ký: PKCS#1 v1.5 vs PSS, cùng dữ liệu, cùng khóa, 5 lần ===")
msg = b"Hop dong so 01"
v15 = {k.sign(msg, apad.PKCS1v15(), hashes.SHA256()) for _ in range(5)}
pss = apad.PSS(mgf=apad.MGF1(hashes.SHA256()), salt_length=32)
sigs = [k.sign(msg, pss, hashes.SHA256()) for _ in range(5)]
print("PKCS#1 v1.5: số chữ ký khác nhau =", len(v15), "/ 5")
print("PSS        : số chữ ký khác nhau =", len(set(sigs)), "/ 5")
ok = True
for s in sigs:
    try: k.public_key().verify(s, msg, pss, hashes.SHA256())
    except Exception: ok = False
print("PSS: cả 5 chữ ký xác minh đúng =", ok)
try:
    k.public_key().verify(sigs[0], b"Hop dong so 02", pss, hashes.SHA256()); print("sửa dữ liệu: vẫn đúng (SAI)")
except Exception:
    print("sửa dữ liệu: xác minh thất bại (đúng như mong đợi)")
