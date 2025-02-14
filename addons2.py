from mitmproxy import http
from mitm_burp import extract_date, genFlowNumber, genKeyFromFlowNumber, genKeyFromPublicKey, sm2_doSignature, encryptSM4, decryptSM4
import json

url = "https://xxx.xxx.com/app/"
appPrivateKey = '1a498da4a4f5ded3409a8bd437acd498d89c86f1d308507d6da1c63e2562cf4e'
appPublicKey = '0408477c828f1691700998b884c957f66d815d8c96c3f3b94215b7f8c8fa2a36e1a4a1ea8dd5623ce1f2b997d5bc94085da4902142dec8de28020286ab6d006e6f'
gatewayPublicKey = '04fb26b91ac34969c4e17fe746d7e3de951db46d7e245055bc305f960a09f5a119f032f481ea79d8f8f117677f0936c3404db9217b93aba4cd7a3e1323ced2532b'

def request(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        request_body = flow.request.json()
        print("=" * 15 + " 请求包明文如下 " + "=" * 15)
        print(request_body)
        Client = request_body['c']
        request_body['f'] = genFlowNumber(Client)
        request_body['b'] = str(request_body['b']).replace("'", '"')
        request_body['s'] = sm2_doSignature(request_body['b'], appPrivateKey)
        global date
        date = extract_date(request_body['f'], Client)
        sm4_key = genKeyFromPublicKey(gatewayPublicKey, date)
        print("请求包加密密钥为： " + sm4_key)
        original_b = request_body['b']
        try:
            request_body['b'] = encryptSM4(sm4_key, request_body['b'])
        except Exception as e:
            request_body['b'] = original_b
            print("加密错误，请检查gatewayPublicKey")
            raise e
        result = json.dumps(request_body)
        print("=" * 15 + " 请求包加密后的密文数据包如下 " + "=" * 15)
        print(request_body)
        flow.request.set_text(result)
    else:
        pass


def response(flow: http.HTTPFlow) -> None:
    if flow.request.url.startswith(url):
        response_body = flow.response.json()
        print("=" * 15 + " 响应包密文如下 " + "=" * 15)
        print(response_body)
        print(date)
        sm4_key = genKeyFromPublicKey(appPublicKey, date)
        print("响应包解密密钥为： " + sm4_key)
        response_body['b'] = decryptSM4(sm4_key, response_body['b'])
        response_body['b'] = json.loads(response_body['b'])
        result = json.dumps(response_body, ensure_ascii=False)
        print("=" * 15 + " 响应包解密后的明文数据包如下 " + "=" * 15)
        print(response_body)
        flow.response.set_text(result)