from Crypto.PublicKey import RSA

key = RSA.generate(2048)
with open("RSA.txt", "wb") as f:
    f.write(key.export_key())
with open("gongyao.txt", "wb") as f:
    f.write(key.publickey().export_key())
print("✅ 已生成：RSA.txt(私钥) / gongyao.txt(公钥)")