#!/usr/bin/python

import sys
import requests
import json
import base64
import csv
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

waf_url = str(sys.argv[1])
waf_login_username = str(sys.argv[2])
waf_login_password = str(sys.argv[3])
service_name = str(sys.argv[4])
cert_name = str(sys.argv[5])
csv_filename = str(sys.argv[6])
with open(csv_filename, newline='') as csvfile:
    r = csv.reader(csvfile)
    for row in r:
        print(row)

waf_rest_url=waf_url + "/restapi/v3.2/"
hhh = { 'Content-Type': 'application/json'}
post_data = json.dumps({ 'username': waf_login_username, 'password': waf_login_password })
print("POST " + waf_rest_url + 'login')
r = requests.post(waf_rest_url + 'login', headers=hhh, data=post_data, verify=False )
token = json.loads(r.text)['token']
token = token.encode('ascii')
b64token = base64.b64encode(token)
b64token = b64token.decode('ascii')
hhh={"Content-Type": "application/json", "Authorization": "Basic " + b64token}
# Working curl example: 
# curl -K token.txt -X PUT -k https://waf.cudathon.com:8443/restapi/v3.2/services/juiceshop/ssl-security -H Content-Type:application/json -d '{"certificate":"qqqq"}'
# {"id":"juiceshop","token":"eyJ1c2VyIjoiYWRtaW4iLCJldCI6IjE2MzU3NTgxMDYiLCJwYXNzd29yZCI6IjU2YWRiNWM3MTMw\nNjcxYTgzZDE4M2U2NmE2YjQ5NGM4In0=\n","msg":"Configuration updated"}
print("--------------------------------")
r = requests.get(waf_rest_url + "services/" + service_name + "/ssl-security", headers=hhh, verify=False)
j = r.json()
print("SSL Certificate for Service " + service_name + " is: " + j['data'][service_name]['SSL Security']['certificate'])
print("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-")
r = requests.put(waf_rest_url + "services/" + service_name + "/ssl-security", headers=hhh, data='{"certificate":"' + cert_name + '"}', verify=False)
t = r.text
print(json.loads(t)['msg'])
print("--------------------------------")
r = requests.get(waf_rest_url + "services/" + service_name + "/ssl-security", headers=hhh, verify=False)
j = r.json()
print("SSL Certificate for Service " + service_name + " is: " + j['data'][service_name]['SSL Security']['certificate'])
