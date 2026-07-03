from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
cipher = AES.new(key, AES.MODE_ECB)
with open('image5.jpeg', 'rb') as f:
    data = f.read()
encrypted = cipher.encrypt(pad(data, 16))
with open('encrypted_image5.jpg', 'wb') as f:
    f.write(encrypted)