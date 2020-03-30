# bwaf_server_maintenance

# Barracuda Networks
# Legal Notice 3/30/2020
# ----------------------
# Attention: this is unsupported code. use at your own risk.
#
# Any code/script/template/other in the "experimental" folder is unsupported code, use at your own risk, and do your own testing.
# This will not be supported by Barracuda Networks, and is not for production or environments where downtime would cause an issue.
# This is not meant for production environments, it is meant for use in dev/test and pre-production only.
#
# Content that is promoted out of the experimental folder will be considered supported.
#
# Content within the experimental folder is unsupported.
#
# (c) 2020 Barracuda Networks

This is a python script used to take servers in and out of maitenance, or set their status in general.
Status should match what you see in the GUI.

Tested for 10.1 with python 2.7
Should work for 2.7and 3.X
Tested on WSL ubuntu, with 2.7
```
root@MSI:/mnt/d/src#
python bwaf_server_maintenance.py http://bwaf99.eastus.cloudapp.azure.com:8000 admin PASSWORDREDACTED! 10.5.2.8 80 "Out of Service Maintenance"
POST http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/login
GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services?parameters=name
=================START SERVICE wordpress_service==========================
wordpress_service
GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/wordpress_service/servers?parameters=name,ip-address,port,status
-> Server1
  -> status : In Service
  -> port : 2001
  -> ip-address : 10.5.2.5
  -> name : Server1
-> ubu97
  -> status : Out of Service Maintenance
  -> name : ubu97
  -> ip-address : 10.5.2.8
  -> port : 80
        GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/wordpress_service/content-rules?parameters=name
--- (no rules) ---
=================END SERVICE wordpress_service==========================
=================START SERVICE web==========================
web
GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/web/servers?parameters=name,ip-address,port,status
-> ubu96
  -> status : Out of Service Maintenance
  -> name : ubu96
  -> ip-address : 10.5.2.7
  -> port : 80
        GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/web/content-rules?parameters=name
-----------------------------------start rule yyyy-------------------------------------
       server name: rule_server1 ip: 2.2.2.3 port: 80 status: In Service
       server name: rule_server2 ip: 2.2.2.2 port: 80 status: In Service
       server name: ubu96 ip: 10.5.2.7 port: 80 status: Out of Service Maintenance
       server name: ubu97 ip: 10.5.2.8 port: 80 status: Out of Service Maintenance
-----------------------------------end rule yyyy-------------------------------------
-----------------------------------start rule r1-------------------------------------
       server name: ubu97 ip: 10.5.2.8 port: 80 status: Out of Service Maintenance
-----------------------------------end rule r1-------------------------------------
=================END SERVICE web==========================
=================START SERVICE webgoat==========================
webgoat
GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/webgoat/servers?parameters=name,ip-address,port,status
-> Server_10.5.2.5_8080
  -> status : In Service
  -> name : Server_10.5.2.5_8080
  -> ip-address : 10.5.2.5
  -> port : 8080
-> idontexist
  -> status : In Service
  -> port : 80
  -> ip-address : 10.5.2.99
  -> name : idontexist
        GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/webgoat/content-rules?parameters=name
-----------------------------------start rule qqqq-------------------------------------
       server name: ubu96 ip: 10.5.2.7 port: 80 status: Out of Service Maintenance
-----------------------------------end rule qqqq-------------------------------------
=================END SERVICE webgoat==========================
=================START SERVICE dvwa==========================
dvwa
GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/dvwa/servers?parameters=name,ip-address,port,status
-> ubu96
  -> status : Out of Service Maintenance
  -> name : ubu96
  -> ip-address : 10.5.2.7
  -> port : 80
-> ubu97
  -> status : Out of Service Maintenance
  -> port : 80
  -> ip-address : 10.5.2.8
  -> name : ubu97
        GET http://bwaf99.eastus.cloudapp.azure.com:8000/restapi/v3.1/services/dvwa/content-rules?parameters=name
-----------------------------------start rule r1-------------------------------------
       server name: rule_server2 ip: 2.2.2.2 port: 80 status: In Service
       server name: ubu97 ip: 10.5.2.8 port: 80 status: Out of Service Maintenance
-----------------------------------end rule r1-------------------------------------
-----------------------------------start rule r2-------------------------------------
       server name: rule_server2 ip: 2.2.2.2 port: 80 status: In Service
-----------------------------------end rule r2-------------------------------------
=================END SERVICE dvwa==========================
root@MSI:/mnt/d/src#
```
