#!/usr/bin/env python
# VMware vSphere Python SDK
# Copyright (c) 2008-2014 VMware, Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import print_function

import yaml
import json
import atexit
import getpass
import argparse
from time import clock

from pyVim import connect
from PerformanceManager import PerformanceMonitor

import requests
requests.packages.urllib3.disable_warnings()

si = "None"
configFile = "/admin/scripts/zbxVMCollector/config-vcenter.yaml"

# ------------- [HOST]-----------------
# "hostname"         => host.name,
# "product"          => host.summary.config.product.fullName,
# "hardwaremodel"    => host.summary.hardware.model,
# "cpumodel"         => host.summary.hardware.cpuModel,
# "cpumhz"           => host.summary.hardware.cpuMhz.to_i*1000000,
# "cpucore"          => host.summary.hardware.numCpuCores,
# "cpuusage"         => host.summary.quickStats.overallCpuUsage.to_i*1000000,
# "cpuusagepercent"  => host.summary.quickStats.overallCpuUsage.to_i.percent_of(host.summary.hardware.cpuMhz.to_i*host.summary.hardware.numCpuCores.to_i),
# "totalcpusize"     => host.summary.hardware.numCpuCores*host.summary.hardware.cpuMhz.to_i*1000000,
# "totalmemorysize"  => host.summary.hardware.memorySize,
# "memoryusage"      => host.summary.quickStats.overallMemoryUsage.to_i*1024*1024,
# "memoryusagepercent" => (host.summary.quickStats.overallMemoryUsage.to_i*1024*1024).percent_of(host.summary.hardware.memorySize.to_i),
# "powerstate"       => host.summary.runtime.powerState,
# "maintenancemode"  => host.summary.runtime.inMaintenanceMode,
# "uptime"           => host.summary.quickStats.uptime,
# "overallstatus"    => host.summary.overallStatus,
# "pathstateactive"  => pathStateActive,
# "pathstatedead"    => pathStateDead,
# "pathstatedisabled" => pathStateDisabled,
# "pathstatestandby" => pathStateStandby,
# "pathstateunknown" => pathStateUnknown


# ------------- [VM]-----------------
# "name"                  => vm.name,
# "runninghost"           => vm.runtime.host.name,
# "powerstate"            => vm.summary.runtime.powerState,
# "toolsinstallermounted" => vm.summary.runtime.toolsInstallerMounted,
# "consolidationeeded"    => vm.summary.runtime.consolidationNeeded,
# "cleanpoweroff"         => vm.summary.runtime.cleanPowerOff,
# "boottime"              => vm.summary.runtime.bootTime,
# "guestfullname"         => vm.summary.guest.guestFullName,
# "hostname"              => vm.summary.guest.hostName,
# "ipaddress"             => vm.summary.guest.ipAddress,
# "vmwaretools"           => vm.summary.guest.toolsVersionStatus2,
# "maxcpuusage"           => maxcpuusage,
# "overallcpuusage"       => vm.summary.quickStats.overallCpuUsage.to_i*1000000,
# "percentcpuusage"       => vm.summary.quickStats.overallCpuUsage.to_i.percent_of(vm.summary.runtime.maxCpuUsage.to_i),
# "numcpu"                => vm.summary.config.numCpu,
# "memorysize"            => vm.summary.config.memorySizeMB.to_i*1024*1024,
# "hostmemoryusage"       => vm.summary.quickStats.hostMemoryUsage.to_i*1024*1024,
# "guestmemoryusage"      => vm.summary.quickStats.guestMemoryUsage.to_i*1024*1024,
# "balloonedmemory"       => vm.summary.quickStats.balloonedMemory.to_i*1024*1024,
# "percentmemoryusage"    => vm.summary.quickStats.hostMemoryUsage.to_i.percent_of(vm.summary.config.memorySizeMB.to_i),
# "uncommittedstorage"    => vm.summary.storage.uncommitted,
# "usedstorage"           => vm.summary.storage.committed,
# "provisionedstorage"    => vm.summary.storage.uncommitted + vm.summary.storage.committed,
# "percentusedstorage"    => vm.summary.storage.committed.to_i.percent_of(vm.summary.storage.uncommitted.to_i + vm.summary.storage.committed.to_i),
# "unsharedstorage"       => vm.summary.storage.unshared,
# "storagelocation"       => vm.summary.config.vmPathName,
# "uptime"                => vm.summary.quickStats.uptimeSeconds,
# "overallstatus"         => vm.summary.overallStatus

# ------------- [Datastore]-----------------
# "name"                  => datastore.name,
# "capacity"              => datastore.summary.capacity,
# "capacityfree"          => datastore.summary.freeSpace,
# "capacityused"          => datastore.summary.capacity - datastore.summary.freeSpace,
# "capacityusedpercent"   => 1 - (datastore.summary.freeSpace.to_i.percent_of(datastore.summary.capacity.to_i)),
# "accessible"            => datastore.summary.accessible,
# "maintenancemode"       => datastore.summary.maintenanceMode,
# "type"                  => datastore.summary.type,
# "vmcount"               => ((vmlist.join(', ')).split(",")).count,
# "vmlist"                => vmlist.join(', ')


def get_args():
    parser = argparse.ArgumentParser()

    # parser.add_argument('-s', '--host',
                        # required=True,
                        # action='store',
                        # help='Remote host to connect to')

    # parser.add_argument('-P', '--port',
                        # required=False,
                        # action='store',
                        # help="port to use, default 443", default=443)

    # parser.add_argument('-u', '--user',
                        # required=True,
                        # action='store',
                        # help='User name to use when connecting to host')

    # parser.add_argument('-p', '--password',
                        # required=False,
                        # action='store',
                        # help='Password to use when connecting to host')

    # parser.add_argument('-d', '--uuid',
                        # required=False,
                        # action='store',
                        # help='Instance UUID (not BIOS id) of a VM to find.')

    parser.add_argument('-i', '--ip',
                        required=False,
                        action='store',
                        help='IP address of the VM to search for')

    parser.add_argument('-d', '--disk',
                        required=False,
                        action='store',
                        help='Disk ID')

    parser.add_argument('-n', '--network',
                        required=False,
                        action='store',
                        help='Network Interface Monitor')

    parser.add_argument('-c', '--cpu',
                        required=False,
                        action='store',
                        help='Disk ID')

    parser.add_argument('-m', '--memory',
                        required=False,
                        action='store',
                        help='Memory')

    parser.add_argument('-I', '--information',
                        required=False,
                        action='store',
                        help='Informations are')

    parser.add_argument('-o', '--option',
                        required=False,
                        action='store',
                        help='Options ')

    args = parser.parse_args()

    # password = None
    # if args.password is None:
        # password = getpass.getpass(
            # prompt='Enter password for host %s and user %s: ' %
                   # (args.host, args.user))

    args = parser.parse_args()

    if password:
        args.password = password

    return args

def cpu(vm, option):
# "maxcpuusage"           => maxcpuusage,
# "overallcpuusage"       => vm.summary.quickStats.overallCpuUsage.to_i*1000000,
# "percentcpuusage"       => vm.summary.quickStats.overallCpuUsage.to_i.percent_of(vm.summary.runtime.maxCpuUsage.to_i),
# "numcpu"                => vm.summary.config.numCpu,
	if option == "NUMCPUS":
		print(vm.summary.config.numCpu)
	elif option == "CPUUSAGE":
		cpuUsage = vm.summary.quickStats.overallCpuUsage
		# cpuUsage = PerformanceMonitor(si, vm, "cpu.capacity.usage.average")
		print(cpuUsage)
	elif option == "PERCENTCPUUSAGE":
		totalCpu = (( 100 * vm.summary.quickStats.overallCpuUsage) / vm.summary.runtime.maxCpuUsage )
		print(totalCpu)
	elif option == "MAXCPUUSAGE":
		print(vm.summary.runtime.maxCpuUsage)
		exit()
		# cpu.capacity.provisioned.average --- 15

def disk(vm, diskPath, option):
	disk_spec  = vm.guest.disk
	if diskPath == "AUTODISCOVER":
		diskArray = []
		for VMDisk in disk_spec:
			diskOutput = {}
			diskOutput["{#FSNAME}"] = VMDisk.diskPath.replace('\\','')
			diskArray.append(diskOutput)
		print(json.dumps({'data': diskArray}, indent=4, separators=(',',':')))
	else:
		VMdiskPath = '%s\\' % (diskPath)
		for VMDisk in disk_spec:
			if VMdiskPath == VMDisk.diskPath:
				if option ==  "CAPACITY"      : print(VMDisk.capacity / 1024 / 1024 / 1024 )
				elif option ==  "FREESPACE"   : print(VMDisk.freeSpace / 1024 / 1024 )
				elif option ==  "USEDSPACE"   : print( (VMDisk.capacity - VMDisk.freeSpace) /1024 / 1024)
				elif option ==  "PERCENTUSED" : 
					diskPercentUsage = ((100 * VMDisk.freeSpace) / VMDisk.capacity )
					print("{0:.2f}".format(diskPercentUsage))

def VMinformation(vm, option):
	if   option ==  "VMNAME"                : print( vm.summary.config.name)
	elif option ==  "UUID"                  : print( vm.summary.config.uuid)
	elif option ==  "OS"                    : print( vm.summary.config.guestFullName)
	elif option ==  "LASTBOOTEDTIMESTAMP"   : print( vm.runtime.bootTime)
	elif option ==  "RUNNINGHOST"           : print( vm.runtime.host.name)
	elif option ==  "POWERSTATE"            : print( vm.summary.runtime.powerState)
	elif option ==  "BOOTTIME"              : print( vm.summary.runtime.bootTime)
	elif option ==  "HOSTNAME"              : print( vm.summary.guest.hostName)
	elif option ==  "IPADDRESS"             : print( vm.summary.guest.ipAddress)
	elif option ==  "VMWARETOOLS"           : print( vm.summary.guest.toolsVersionStatus2)
	elif option ==  "UPTIME"                : print( vm.summary.quickStats.uptimeSeconds)
	elif option ==  "OVERALLSTATUS"         : print( vm.summary.overallStatus)
	exit()

def memory(vm, option):
	if option   == "MEMORYSIZE" :
		vmMemorySizeMB = vm.summary.config.memorySizeMB
		if vmMemorySizeMB > 1024:
			print(vmMemorySizeMB /1024)
	elif option == "PERCENTMEMORYUSAGE": 
		vmMemoryPercent = vm.summary.quickStats.hostMemoryUsage
		print( ( 100 *  vmMemoryPercent ) / vm.summary.config.memorySizeMB )
	elif option == "HOSTMEMORYUSAGE"  : print( vm.summary.quickStats.hostMemoryUsage)
	elif option == "GUESTMEMORYUSAGE" : print(vm.summary.quickStats.guestMemoryUsage)

def network(vm, vmnic, option):
	statInt = 20 * 3
	if vmnic == "AUTODISCOVER":
		print(vm.guest.NicInfo)
		exit()
	netMetricName = ""
	if option ==  "INBOUND" :
		statNetworkTx = PerformanceMonitor(si, vm, "net.bytesTx.average")
		networkTx = (sum(statNetworkTx[0].value[0].value))
		print(networkTx)
	elif option ==  "OUTBOUND":
		statNetworkRx = PerformanceMonitor(si, vm, "net.bytesRx.average")
		networkRx = (sum(statNetworkRx[0].value[0].value) )
		print(networkRx)

# ------------- [DataStore Information]-----------------
def DatastoreInformation(datastore, datastoreName, option):
	# if datastoreName == "AUTODISCOVER":
		# exit()

	# if   option ==  "NAME"            : print(datastore.name)
	# elif option ==  "CAPACITY"        : print(datastore.summary.capacity)
	# elif option ==  "capacityfree"    : print(datastore.summary.freeSpace)
	# elif option ==  "capacityused"    : print(datastore.summary.capacity - datastore.summary.freeSpace)
	# elif option ==  "PERCENTUSED"     : print( ( 100 * datastore.summary.freeSpace ) / datastore.summary.capacity )
	# elif option ==  "accessible"      : print(datastore.summary.accessible)
	# elif option ==  "maintenancemode" : print(datastore.summary.maintenanceMode)
	# elif option ==  "type"            : print(datastore.summary.type)
	# elif option ==  "vmcount"         : print(((vmlist.join(') ')).split(")")).count)
	# elif option ==  "vmlist"          : print(vmlist.join(') ')

	exit()

def HostInformation(host, option):
	# ------------- [HOST Information]-----------------
	# if option ==  "hostname"          
	# if option ==  "product"           : print( host.summary.config.product.fullName)
	# if option ==  "hardwaremodel"     : print( host.summary.hardware.model)
	# if option ==  "cpumodel"          : print( host.summary.hardware.cpuModel)
	# if option ==  "cpumhz"            : print( host.summary.hardware.cpuMhz.to_i*1000000)
	# if option ==  "cpucore"           : print( host.summary.hardware.numCpuCores)
	# if option ==  "cpuusage"          : print( host.summary.quickStats.overallCpuUsage.to_i*1000000)
	# if option ==  "cpuusagepercent"   : print( host.summary.quickStats.overallCpuUsage.to_i.percent_of(host.summary.hardware.cpuMhz.to_i*host.summary.hardware.numCpuCores.to_i))
	# if option ==  "totalcpusize"      : print( host.summary.hardware.numCpuCores*host.summary.hardware.cpuMhz.to_i*1000000)
	# if option ==  "totalmemorysize"   : print( host.summary.hardware.memorySize)
	# if option ==  "memoryusage"       : print( host.summary.quickStats.overallMemoryUsage.to_i*1024*1024)
	# if option ==  "memoryusagepercent"  : print( (host.summary.quickStats.overallMemoryUsage.to_i*1024*1024).percent_of(host.summary.hardware.memorySize.to_i))
	# if option ==  "powerstate"        : print( host.summary.runtime.powerState)
	# if option ==  "maintenancemode"   : print( host.summary.runtime.inMaintenanceMode)
	# if option ==  "uptime"            : print( host.summary.quickStats.uptime)
	# if option ==  "overallstatus"     : print( host.summary.overallStatus)
	# if option ==  "pathstateactive"   : print( pathStateActive)
	# if option ==  "pathstatedead"     : print( pathStateDead)
	# if option ==  "pathstatedisabled"  : print( pathStateDisabled)
	# if option ==  "pathstatestandby"  : print( pathStateStandby)

	# if option == "HOSTNAME" : print( host.name) 
	# if option == "PRODUCT" :           
	# if option == "HARDWAREMODEL" :     
	# if option == "CPUMODEL" :          
	# if option == "CPUMHZ" :            
	# if option == "CPUCORE" :           
	# if option == "CPUUSAGE" :          
	# if option == "CPUUSAGEPERCENT" :   
	# if option == "TOTALCPUSIZE" :      
	# if option == "TOTALMEMORYSIZE" :   
	# if option == "MEMORYUSAGE" :       
	# if option == "MEMORYUSAGEPERCENT" :  
	# if option == "POWERSTATE" :        
	# if option == "MAINTENANCEMODE" :   
	# if option == "UPTIME" :            
	# if option == "OVERALLSTATUS" :     
	# if option == "PATHSTATEACTIVE" :   
	# if option == "PATHSTATEDEAD" :     
	# if option == "PATHSTATEDISABLED" :  
	# if option == "PATHSTATESTANDBY" :  
	# if option == "PATHSTATEUNKNOWN" :  print( pathStateUnknown)

	exit()

def main():
	global si
	strError = list()
	stream = open(configFile, 'r')
	yml_config = yaml.load(stream)

	for section_key, section_value in yml_config.items():
		globals()[section_key] = section_value

	args = get_args()
	# form a connection...
	si = connect.SmartConnect(host=hostname, user=username, pwd=password, port=port)

	# Note: from daemons use a shutdown hook to do this, not the atexit
	atexit.register(connect.Disconnect, si)

	# http://pubs.vmware.com/vsphere-55/topic/com.vmware.wssdk.apiref.doc/vim.SearchIndex.html
	search_index = si.content.searchIndex
	
	vm = None

	if args.ip:
		vm = search_index.FindByIp(None, args.ip, True)
	else:
		print("You should specific some VM IP Address.")
		exit(1)

	if not vm:
		print("ERROR: Could not find virtual machine with this IP Address.")
		exit(1)

	# Defining Option
	if not args.option         :	option = None

        if vm.summary.runtime.powerState != "poweredOn": 
		print(0)
		return 0
	

	if args.disk               : 	disk(vm, args.disk, args.option)
	elif args.cpu              :	cpu(vm, args.cpu)
	elif args.information      :	VMinformation(vm, args.information)
	elif args.memory           : 	memory(vm, args.memory)
	elif args.network          : 	network(vm, args.network, args.option)

	exit()

if __name__ == "__main__":
	main()
