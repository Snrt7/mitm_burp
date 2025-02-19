import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import execjs
import time
import hashlib

KEY = b"5828c2d384e1938a"
IV = b"eaaa78bbfe1cfd44"

# 修改js固定randomKey
# main.js
# return _0xb4a446[0xe]='4',_0xb4a446[0x13]=_0x19c28f['s'+'u'+'b'+'s'+'t'+'r'](0x3&_0xb4a446[0x13]|0x8,0x1),_0xb4a446['j'+'o'+'i'+'n']('');
# return 'eaaa78bbfe1cfd445828c2d384e1938a';


# AES加密函数
def aes_cbc_encrypt(data: str) -> str:
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(ct_bytes).decode('utf-8')


# AES解密函数
def aes_cbc_decrypt(data: str) -> str:
    data = base64.b64decode(data)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    pt = unpad(cipher.decrypt(data), AES.block_size)
    return pt.decode('utf-8')


# sm2 doEncrypt
def sm2_doEncrypt(msg):
    js_code = '''
        const sm2 = require('./sm-crypto/node_modules/sm-crypto').sm2
        function doEncrypt(msg){
            let publicKey = '04AD65C11DF12C73EBA21E95B6094612F660C806EE203F0F223535239A912488907B3A373BD343E8EF328C3B990FF8A901BFC8D2EDF06643247D6A381BFF923968'
            let result = sm2.doEncrypt(msg, publicKey, 1)
            // let result = sm2.doDecrypt(msg, privateKey, 1)
            return result
        }
    '''
    ctx = execjs.compile(js_code)
    result = ctx.call('doEncrypt', msg)
    return result


def get_Auth(_0x1a5726, request_body):
    timestamp = int(time.time() * 1000)
    randomKey = 'eaaa78bbfe1cfd445828c2d384e1938a'
    md5_body = hashlib.md5(request_body.encode()).hexdigest()
    _0x2f3b68 = _0x1a5726['userId'] + '|WEB|deviceId|' + _0x1a5726['token'] + '|' + str(timestamp) + '|appVer|' + _0x1a5726['orgCode'] + '|1|' + '0|' + md5_body + '|2|' + randomKey
    return _0x2f3b68