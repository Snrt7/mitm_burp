from mitmproxy import http
from mitm_burp import aes_cbc_encrypt, aes_cbc_decrypt
import json

url = "https://xx.xx.xx.xx:xx/xx/"

def request(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        request_body = flow.request.get_text()
        if len(request_body) > 0:
            print("=" * 15 + " 请求包密文如下 " + "=" * 15)
            print(request_body)
            original_body = request_body
            try:
                request_body = aes_cbc_decrypt(request_body)
            except Exception as e:
                request_body = original_body
                print("解密错误，请检查")
                raise e
            result = request_body
            print("=" * 15 + " 请求包解密后的明文数据包如下 " + "=" * 15)
            print(result)
            flow.request.set_text(result)
    else:
        pass

def response(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        response_body = flow.response.get_text()
        print("=" * 15 + " 响应包明文如下 " + "=" * 15)
        print(response_body)
        response_body = aes_cbc_encrypt(response_body)
        result = response_body
        print("=" * 15 + " 响应包加密后的密文数据包如下 " + "=" * 15)
        print(result)
        flow.response.set_text(result)