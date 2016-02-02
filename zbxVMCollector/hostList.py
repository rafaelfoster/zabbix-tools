#!/usr/bin/env python

import yaml
import atexit
import random

import tools.cli as cli
from pyVim import connect
from pyVmomi import vim
from pyVmomi import vmodl
from zbxAuth import zapi

import requests
requests.packages.urllib3.disable_warnings()

configFile = "/admin/scripts/zbxVMCollector/config-vcenter.yaml"

def main():
	stream = open(configFile, 'r')
	yml_config = yaml.load(stream)
	
	for section_key, section_value in yml_config.items():
		globals()[section_key] = section_value

	try:
		service_instance = connect.SmartConnect(host=hostname,
											user=username,
											pwd=password,
											port=int(port))
		content = service_instance.RetrieveContent()
		children = content.rootFolder.childEntity
		for child in children:
			if hasattr(child, 'hostFolder'):
				datacenter = child
			else:
				# some other non-datacenter type object
				continue

		#print datacenter

	#	host_folder = datacenter.hostFolder
	#	compresourcelist = host_folder.childEntity
	#	for compres in compresourcelist[0].Summary:
	#		print compres

		# for cluster_name in clusters:
			# cluster_obj = self.get_obj(content, [vim.ClusterComputeResource], cluster_name)
			# hosts = cluster_obj.host

	        obj_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                           [vim.HostSystem],
                                                           True)
	        host_cluster_list = obj_view.view
        	obj_view.Destroy()

	        for host_cluster in host_cluster_list:
				print host_cluster.summary.config.name
				print host_cluster.summary.hardware.uuid
				print host_cluster.summary.quickStats.uptime
				print host_cluster.runtime.bootTime
				product = host_cluster.summary.config.product
				print product.name + product.version
				print host_cluster.summary.managementServerIp


	except vmodl.MethodFault as error:
		print "Caught vmodl fault : " + error.msg
		return -1
	return 0

# Start program
if __name__ == "__main__":
	main()

