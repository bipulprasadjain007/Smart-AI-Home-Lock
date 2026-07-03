from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

key = bytes.fromhex('dbebba31873175ba0513ff7b40304508')  # Same AES_KEY as in .env
pin = '040206'
cipher = AES.new(key, AES.MODE_ECB)
encrypted_pin = cipher.encrypt(pad(pin.encode('utf-8'), 16))

with open('encrypted_pin.bin', 'wb') as f:
    f.write(encrypted_pin)
