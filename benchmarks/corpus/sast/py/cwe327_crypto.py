from Crypto.Cipher import DES
def enc(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)
