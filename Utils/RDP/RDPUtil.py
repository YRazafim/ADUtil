#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = Wrapper for xfreerdp

# Others
import subprocess, sys, traceback, time, random, threading

########################################################
#                     Connection                       #
########################################################

def connect_rdp(ip, port, username, password, domain, ntHash, keyboard, mountDrive, fullScreen, noNLA):
	print_yellow("[*] Connecting to RDP server")
	print_yellow("---")
	print()

	try:
		command = f"xfreerdp /v:{ip} /port:{port} /u:{username} /d:{domain} /cert-ignore +clipboard /kbd:{keyboard}"

		if mountDrive != None:
			command += f" /drive:{mountDrive}"

		if fullScreen:
			command += " /f"

		if ntHash != "":
			command += f" /pth:{ntHash}"
		else:
			command += f" /p:{password}"
		
		if noNLA:
			command += " -sec-nla"

		print(f"[+] Running: {command}")
		process = subprocess.Popen(command, shell = True)
		process.wait()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##########################################################################
#                     Network Level Authentication                       #
##########################################################################

def runCommand(resultDict, process):
	stdout, stderr = process.communicate()
	resultDict['stdout'] = stdout
	resultDict['stderr'] = stderr

def checkNLA(ip, port):
	print_yellow("[*] Checking NLA")
	print_yellow("---")
	print()

	try:
		command = f"timeout 3 xvfb-run -a xfreerdp /v:{ip} /port:{port} /cert-ignore -sec-nla" # Dumb method BUT no real RDP client in Python for that
		resultDict = {}
		process = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, text = True, shell = True)
		thread = threading.Thread(target = runCommand, args = (resultDict, process))
		thread.start()
		thread.join()

		stderr = resultDict.get('stderr')

		if stderr.find("HYBRID_REQUIRED_BY_SERVER") != -1:
			print(f"[{ip}:{port}] NLA required")
		elif stderr.find("ERRCONNECT_DNS_NAME_NOT_FOUND") != -1:
			print(f"[{ip}:{port}] DNS resolution failed")
		elif stderr.find("explicit kill or server shutdown") != -1:
			print(f"[{ip}:{port}] NLA not required")
		else:
			print(f"[{ip}:{port}] Connection error")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#############################################################
#                     RDP User Access                       #
#############################################################

def runCommand(resultDict, process):
	stdout, stderr = process.communicate()
	resultDict['stdout'] = stdout
	resultDict['stderr'] = stderr

def userCanRDP(ip, port, username, password, domain, ntHash):
	print_yellow("[*] Checking user RDP access")
	print_yellow("---")
	print()

	try:
		command = f"timeout 3 xvfb-run -a xfreerdp /v:{ip} /port:{port} /u:{username} /d:{domain} /cert-ignore"
		if ntHash != "":
			command += f" /pth:{ntHash}"
		else:
			command += f" /p:{password}"
		resultDict = {}
		process = subprocess.Popen(command, stdout = subprocess.PIPE, stderr = subprocess.PIPE, text = True, shell = True)
		thread = threading.Thread(target = runCommand, args = (resultDict, process))
		thread.start()
		thread.join()

		stdout = resultDict.get('stdout')
		stderr = resultDict.get('stderr')

		if stderr.find("ERRCONNECT_DNS_NAME_NOT_FOUND") != -1:
			print(f"[{ip}:{port}] DNS resolution failed")
		elif stderr.find("explicit kill or server shutdown") != -1:
			print(f"[{ip}:{port}] User '{username}' can connect")
		elif stderr.find("STATUS_LOGON_FAILURE") != -1:
			print(f"[{ip}:{port}] Logon failure")
		elif stderr.find("BIO_read returned a system error 0") != -1:
			print(f"[{ip}:{port}] User '{username}' can't connect")
		else:
			print(f"[{ip}:{port}] Connection error")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

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
	conn_group = parser.add_argument_group('[[ Connection ]]')
	conn_group.add_argument("--port", help = "Target(s) port. Default = 3389", type = int, default = 3389)
	conn_group.add_argument("--keyboard", help = "Keyboard to use on RDP server. Default = French", default = "French")
	conn_group.add_argument("--mountDrive", help = "Mount local folder on RDP server in the form of <RemoteMountDriveLetter>,<LocalFolderPath>")
	conn_group.add_argument("--fullScreen", help = "Start xfreerdp in full screen", action = "store_true")
	conn_group.add_argument("--noNLA", help = "Disable NLA. Default = False", action = "store_true")

	client_group = parser.add_argument_group('[[ Client ]]')
	client_group.add_argument("--client", help = "Start RDP client", action = "store_true")

	nla_group = parser.add_argument_group('[[ Network Level Authentication (NLA) ]]')
	nla_group.add_argument("--checkNLA", help = "Check if target server allow connection without NLA", action = "store_true")

	userAccess_group = parser.add_argument_group('[[ RDP User Access ]]')
	userAccess_group.add_argument("--canRDP", help = "Check if provided user can RDP to remote target(s)", action = "store_true")
  
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

		# Client
		if args.client:
			connect_rdp(target, args.port, args.username, args.password, args.domain, args.ntHash, args.keyboard, args.mountDrive, args.fullScreen, args.noNLA)
			maybeSleep(inAction = True)

		# Network Level Authentication (NLA)
		if args.checkNLA:
			checkNLA(target, args.port)
			maybeSleep(inAction = True)

		# RDP User Access
		if args.canRDP:
			userCanRDP(target, args.port, args.username, args.password, args.domain, args.ntHash)
			maybeSleep(inAction = True)

##################################################
#                     TODO                       #
##################################################

# - Try to use https://github.com/skelsec/aardwolf/https://github.com/skelsec/aardwolfgui