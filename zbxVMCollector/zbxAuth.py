#!/usr/bin/python

from zbxApi import ZabbixAPI

zbx_user     = "zabbix_api"
zbx_password = "S3cur3P@ss0rd"
zbx_server   = "http://zabbix.example.com"

zapi = ZabbixAPI(zbx_server)
zapi.login(zbx_user, zbx_password)
