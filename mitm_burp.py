import datetime
import uuid
import execjs
from gmssl import sm4

# 从f参数中提取date, Client为c参数
def extract_date(f, Client):
    f_ = f[-15:] + f[:-15]
    date_e = f_[1::2][:14 + len(Client) + 1]
    date_reverse = ""
    e_positions = list(range(1, 2 * (len(Client) + 1), 2))
    for i in range(len(date_e)):
        if i not in e_positions:
            date_reverse += date_e[i]
    date = date_reverse[::-1]
    return date

# 获取新的f
def genFlowNumber(Client):
    def g(n, g):
        result = []
        n = list(n)
        g = list(g)
        while n and g:
            result.append(n.pop(0))
            result.append(g.pop(0))
        result.extend(n + g)
        return ''.join(result)

    e = Client + '@'
    date = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    uuid_str = str(uuid.uuid4()).replace("-", "")
    a = g(uuid_str, g(date[::-1], e))
    return a[15:] + a[:15]

# 从f中获取key，auth/exchangeKey接口
def genKeyFromFlowNumber(n):
    numbers = [0, 1, 3, 4, 5, 6, 8, 9, 11, 13, 15, 16, 17, 19, 20, 21]
    result = ''.join(map(lambda g: n[g], numbers))
    return result

# 计算解密b参数的key
def genKeyFromPublicKey(PublicKey, date):
    date_reverse = date[::-1]
    result = ""
    i = 0
    for char in date_reverse:
        i += int(char) + 1
        result += PublicKey[i]
    return result + PublicKey[-2:]

# 签名，计算参数s
def sm2_doSignature(msg, appPrivateKey):
    js_code = '''
        const sm2 = require('./sm-crypto/node_modules/sm-crypto').sm2
        function doSignature(msg, privateKey){
            let sigValueHex = sm2.doSignature(msg, privateKey, {der: true,hash: true})
            return sigValueHex
        }
    '''
    ctx = execjs.compile(js_code)
    signature = ctx.call('doSignature', msg, appPrivateKey)
    return signature

# sm4加密
def encryptSM4(encrypt_key , value):
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(encrypt_key.encode() , sm4.SM4_ENCRYPT)
    date_str = str(value)
    encrypt_value = crypt_sm4.crypt_ecb(date_str.encode())
    return encrypt_value.hex()

# sm4解密
def decryptSM4(decrypt_key , encrypt_value):
    crypt_sm4 = sm4.CryptSM4()
    crypt_sm4.set_key(decrypt_key.encode() , sm4.SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(bytes.fromhex(encrypt_value))
    return decrypt_value.decode()