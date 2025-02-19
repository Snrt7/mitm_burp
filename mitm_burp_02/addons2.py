from mitmproxy import http
from mitm_burp import aes_cbc_encrypt, aes_cbc_decrypt, sm2_doEncrypt, get_Auth
import json

url = "https://xx.xx.xx.xx:xx/xx/"

def request(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        request_body = flow.request.get_text()
        if len(request_body) > 0:
            print("=" * 15 + " 请求包明文如下 " + "=" * 15)
            print(request_body)
            original_body = request_body
            try:
                request_body = aes_cbc_encrypt(request_body)
                # 更新Authorization-Web
                if flow.request.url.startswith('https://xx.xx.xx.xx:xx/xx/login'):
                    # 登录前
                    _0x1a5726 = {"token": "","userId": "0","orgCode": "xxx"}
                else:
                    # 登录后
                    _0x1a5726 = {"token": "xxxxxxxxxxx","userId": "xx","orgCode": "xxxx"}
                flow.request.headers['Authorization-Web'] = '04' + sm2_doEncrypt(get_Auth(_0x1a5726, request_body))
            except Exception as e:
                request_body = original_body
                print("加密错误，请检查")
                raise e
            result = request_body
            print("=" * 15 + " 请求包加密后的密文数据包如下 " + "=" * 15)
            print(request_body)
            print(flow.request.headers)
            flow.request.set_text(result)
    else:
        pass


def response(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        response_body = flow.response.get_text()
        print("=" * 15 + " 响应包密文如下 " + "=" * 15)
        print(response_body)
        response_body = aes_cbc_decrypt(response_body)
        result = response_body
        print("=" * 15 + " 响应包解密后的明文数据包如下 " + "=" * 15)
        print(result)
        flow.response.set_text(result)