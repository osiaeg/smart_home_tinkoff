from http.client import HTTPConnection
import base64

conn = HTTPConnection('localhost:9998')
conn.request('POST', "/")
response = conn.getresponse()
# print(response.read())
print(base64.b64decode(response.read()))
