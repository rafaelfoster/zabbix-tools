#!/usr/bin/env python

import yaml
import atexit
import random

import tools.cli as cli
from pyVim import connect
from pyVmomi import vmodl
from zbxAuth import zapi

import requests
requests.packages.urllib3.disable_warnings()

configFile = "/admin/scripts/zbxVMCollector/config-vcenter.yaml"

def zbxGetProxy():
	zbxProxy = zbx_proxy
	proxy = zapi.proxy.get({
		"output": "proxyid",
		"filter": {
			"host": zbxProxy
		}
	})

	return proxy[0]['proxyid']


def zbxGetGroupHosts():
	zbxHostGroup = zbx_group
	group = zapi.hostgroup.get({
		"output": "groupid",
		"filter": {
			"name": zbxHostGroup
		}
	})

	return group[0]['groupid']

def zbxGetTemplates(TemplateType):
	if TemplateType == "VM":
		zbxTemplate = zbx_TemplateVMS
	else:
		zbxTemplate = zbx_TemplateHosts

	template = zapi.template.get({
		"output": "templateid",
		"filter": {
			"host": zbxTemplate
		}
	})

	return template[0]['templateid']


def zbxCreateHost(VMHost, groupID, templateid, proxy_id):
	hostList = zapi.host.get({
		"output": ["host", "hostid", "name"],
		"groupids": groupID
	})

	hostExist = False
	for host in hostList:
		if VMHost['vmName'] == host['host'] or VMHost['vmName'] == host['name']:
			return 1

	if hostExist == False:
		if VMHost['vmGuestName'] != "localhost":
			vmName = VMHost['vmGuestName']
		else:
			vmName = VMHost['vmName']

		zbcHost = zapi.host.create({
			"host": VMHost['vmName'],
			"name": vmName,
			"proxy_hostid": proxy_id,
			"interfaces": [
				{
					"type": 1,
					"main": 1,
					"useip": 1,
					"ip": VMHost['vmIPAddress'],
					"dns": "",
					"port": "10050"
				}
			],
			"groups": [
				{
					"groupid": groupID
				}
			],
			"templates": [
				{
					"templateid": templateid
				}
			]
		})


def getHostVMInformation( virtual_machine, groupID, templateid, proxyID, depth=1 ):
	maxdepth = 10
	vmType = "VM"
	VMHost = {}

	# if this is a group it will have children. if it does, recurse into them
	# and then return
	if hasattr(virtual_machine, 'childEntity'):
		if depth > maxdepth:
			return
		vmList = virtual_machine.childEntity
		for c in vmList:
			getHostVMInformation(c, groupID, templateid, proxyID, depth + 1)
		return

	summary = virtual_machine.summary
	
	if summary.config.template == True:
		return 1

	VMHost['vmName'] = summary.config.name
	VMHost['vmPath'] = summary.config.vmPathName
	VMHost['vmOS'] = summary.config.guestFullName
	VMHost['vmUUID'] = summary.config.instanceUuid
	VMHost['vmAnnotation'] = summary.config.annotation
	if summary.guest is not None:
		vmToolsVersion = summary.guest.toolsStatus
		if vmToolsVersion != "toolsNotInstalled":
			VMHost['vmIPAddress'] = summary.guest.ipAddress
			VMHost['vmGuestName'] = summary.guest.hostName
		else:
			# creating a randon IP cause this machine has no VMware Tools to we get its IP Address
			VMHost['vmIPAddress'] = genRandomIP()
			VMHost['vmGuestName'] = VMHost['vmName']

	zbxCreateHost(VMHost, groupID, templateid,  proxyID)
	
def genRandomIP():
	ip = ".".join(map(str, (random.randint(0, 255) 
							for _ in range(4))))
	return ip

def main():
	stream = open(configFile, 'r')
	yml_config = yaml.load(stream)
	
	for section_key, section_value in yml_config.items():
		globals()[section_key] = section_value

	# print zbxGetGroupHosts("FW-01")

	# exit()
	
	try:
		service_instance = connect.SmartConnect(host=hostname,
												user=username,
												pwd=password,
												port=int(port))

		atexit.register(connect.Disconnect, service_instance)

		content = service_instance.RetrieveContent()
		children = content.rootFolder.childEntity
		for child in children:
			if hasattr(child, 'vmFolder'):
				datacenter = child
			else:
				# some other non-datacenter type object
				continue

			vm_folder = datacenter.vmFolder
			vm_list = vm_folder.childEntity
			groupID = zbxGetGroupHosts()
			templateid = zbxGetTemplates("VM")
			proxy_id = zbxGetProxy()
			for virtual_machine in vm_list:
				getHostVMInformation(virtual_machine,  groupID, templateid, proxy_id,  10)

	except vmodl.MethodFault as error:
		print "Caught vmodl fault : " + error.msg
		return -1

	return 0

# Start program
if __name__ == "__main__":
	main()
