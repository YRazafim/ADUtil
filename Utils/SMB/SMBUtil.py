#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = SMB
from impacket import smb, smb3
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_READ_DATA, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_SHARE_READ, \
						FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_WRITE_DATA, FILE_DIRECTORY_FILE, FILE_LIST_DIRECTORY, \
						FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_DELETE_ON_CLOSE, DELETE, SYNCHRONIZE, FILE_OPEN_REPARSE_POINT, \
						SMB2_FILE_DISPOSITION_INFO, SMB2_SET_INFO, SMB2_0_INFO_FILE, SMB2SetInfo, SMB3Packet, GENERIC_ALL, FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATE, \
						SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311

# ADDITIONAL PROTOCOLS = RPC
from Utils.RPC import RPCUtil

# Others
import time, ntpath, sys, random, string, re, traceback, os, chardet
import xml.etree.ElementTree as ET, xml.dom.minidom
from io import StringIO

########################################################
#                     Connection                       #
########################################################

def connect_smb(target, username, password, domain, ntHash, aesKey, ccache, preferredDialect = '2.0.2'):
	print_yellow("[*] Connecting to SMB server")
	print_yellow("---")
	print()

	try:
		print("[+] Using SMB Dialect {}".format(preferredDialect))

		# SMB Signing
		# 	Negotiated during Negotiate Protocol Request/Negotiate Protocol Response
		# 	Dialect == NT LM 0.12 (SMBv1)
		#		SMB Signing can be disabled/enabled/required (Default = Enabled)
		# 	Dialect != NT LM 0.12 (SMBv2/SMBv3)
		#		SMB Signing can be enabled/required (Default = Enabled)
		# Channel Binding
		# 	Not supported by SMB protocol

		if preferredDialect == 'NT LM 0.12': # SMBv1
			dialect = preferredDialect
		else: # SMBv2/SMBv3
			if preferredDialect == '2.0.2':
				dialect = SMB2_DIALECT_002
			elif preferredDialect == '2.1':
				dialect = SMB2_DIALECT_21
			elif preferredDialect == '3.0':
				dialect = SMB2_DIALECT_30
			elif preferredDialect == '3.0.2':
				dialect = SMB2_DIALECT_302
			else: # 3.1.1
				dialect = SMB2_DIALECT_311

		smb = SMBConnection(target, target, preferredDialect = dialect)

		if aesKey != None or ccache != None:
			if ccache != None:
				import os
				os.environ["KRB5CCNAME"] = ccache
			_ = smb.kerberosLogin(username, password, domain = domain, aesKey = aesKey, useCache = True)
		else:
			_ = smb.login(username, password, domain, nthash = ntHash)
		
		print("[+] Connected to SMB server")
		return smb
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

##############################################
#               Brute Force                  #
##############################################

def doBF(target, usernames, passwords, nthashes, domain, passLogin):
	print_yellow("[*] Brute Force SMB server")
	print_yellow("---")
	print()
 
	try:
		usernamesA = []
		if usernames != '':
			try:
				with open(usernames, "r") as f:
					usernamesA = [username[:-1] for username in f.readlines()]
			except:
				usernamesA = [usernames]
		
		passwordsA = []
		if passwords != '':
			try:
				with open(passwords, "r") as f:
					passwordsA = [password[:-1] for password in f.readlines()]
			except:
				passwordsA = [passwords]
		
		nthashesA = []
		if nthashes != '':
			try:
				with open(nthashes, "r") as f:
					nthashesA = [nthash[:-1] for nthash in f.readlines()]
			except:
				nthashesA = [nthashes]

		for username in usernamesA:

			if passLogin:
				try:
					smb = SMBConnection(target, target)
					logged = smb.login(username, username, domain)

					if (logged):
						print(f"[+] Valid account found {username}:{username}")
					else:
						print(f"[-] Invalid account {username}:{username}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('STATUS_LOGON_FAILURE') != -1:
						print(f"[-] Invalid account {username}:{username}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_LOCKED_OUT') != -1:
						print(f"[-] Account locked out {username}:{username}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_DISABLED') != -1:
						print(f"[+] Valid disabled account found {username}:{username}")
					else:
						print(f"[-] Got error for {username}:{username}: {str(e)}", file = sys.stderr)
						print('---------------------------------', file = sys.stderr)
						traceback.print_exc()
						print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for password in passwordsA:
				try:
					smb = SMBConnection(target, target)
					logged = smb.login(username, password, domain)

					if (logged):
						print(f"[+] Valid account found {username}:{password}")
					else:
						print(f"[-] Invalid account {username}:{password}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('STATUS_LOGON_FAILURE') != -1:
						print(f"[-] Invalid account {username}:{password}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_LOCKED_OUT') != -1:
						print(f"[-] Account locked out {username}:{password}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_DISABLED') != -1:
						print(f"[+] Valid disabled account found {username}:{password}")
					else:
						print(f"[-] Got error for {username}:{password}: {str(e)}", file = sys.stderr)
						print('---------------------------------', file = sys.stderr)
						traceback.print_exc()
						print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for nthash in nthashesA:
				try:
					smb = SMBConnection(target, target)
					logged = smb.login(username, '', domain, nthash = nthash)

					if (logged):
						print(f"[+] Valid account found {username}:{nthash}")
					else:
						print(f"[-] Invalid account {username}:{nthash}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('STATUS_LOGON_FAILURE') != -1:
						print(f"[-] Invalid account {username}:{nthash}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_LOCKED_OUT') != -1:
						print(f"[-] Account locked out {username}:{nthash}", file = sys.stderr)
					elif str(e).find('STATUS_ACCOUNT_DISABLED') != -1:
						print(f"[+] Valid disabled account found {username}:{nthash}")
					else:
						print(f"[-] Got error for {username}:{nthash}: {str(e)}", file = sys.stderr)
						print('---------------------------------', file = sys.stderr)
						traceback.print_exc()
						print('---------------------------------', file = sys.stderr)
				maybeSleep()

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#########################################################
#                     Enumeration                       #
#########################################################

def getInfo(target):
	print_yellow("[*] Enumerating target info")
	print_yellow("---")
	print()
	
	try:
		conn = SMBConnection(target, target) # Use NTLM authentication because Kerberos authentication does not provide any info
		try:
			conn.login('', '')
		except:
			# NTLM authentication failed as expected, but we should have gather info
			pass

		print(f"[+] {'Target':<25} {'Hostname':<25} {'Domain':<25} {'Signing Required':<25} {'SMBv1 Supported':<25} {'OS':<25}")
		ip = conn.getRemoteHost()
		hostname = conn.getServerName()
		domain = conn.getServerDNSDomainName()
		os = conn.getServerOS()
		signing = 'True' if conn.isSigningRequired() == 1 else 'False'
		smbv1 = 'False'
		try:
			_ = SMBConnection(ip, ip, None, preferredDialect = 'NT LM 0.12') # Dialect for SMBv1
			smbv1 = 'True'
		except:
			pass
		print(f"[+] {ip:<25} {hostname:<25} {domain:<25} {signing:<25} {smbv1:<25} {os:<25}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getSMBv1(target):
	print_yellow("[*] Enumerating SMBv1")
	print_yellow("---")
	print()
	
	try:
		conn = SMBConnection(target, target) # Use NTLM authentication because Kerberos authentication does not provide any info
		try:
			conn.login('', '')
		except:
			# NTLM authentication failed as expected, but we should have gather info
			pass

		ip = conn.getRemoteHost()
		hostname = conn.getServerName()
		smbv1 = 'False'
		try:
			_ = SMBConnection(ip, ip, None, preferredDialect = 'NT LM 0.12') # Dialect for SMBv1
			smbv1 = 'True'
		except:
			pass
		if smbv1:
			print(f"[{ip}:{hostname}] SMBv1 supported")
		else:
			print(f"[{ip}:{hostname}] SMBv1 not supported")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getOS(target):
	print_yellow("[*] Enumerating OS")
	print_yellow("---")
	print()
	
	try:
		conn = SMBConnection(target, target) # Use NTLM authentication because Kerberos authentication does not provide any info
		try:
			conn.login('', '')
		except:
			# NTLM authentication failed as expected, but we should have gather info
			pass

		ip = conn.getRemoteHost()
		hostname = conn.getServerName()
		os = conn.getServerOS()
		print(f"[{ip}:{hostname}] {os}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getSigning(target):
	print_yellow("[*] Enumerating SMB Signing")
	print_yellow("---")
	print()
	
	try:
		conn = SMBConnection(target, target) # Use NTLM authentication because Kerberos authentication does not provide any info
		try:
			conn.login('', '')
		except:
			# NTLM authentication failed as expected, but we should have gather info
			pass

		ip = conn.getRemoteHost()
		hostname = conn.getServerName()
		os = conn.getServerOS()
		if conn.isSigningRequired() == 1:
			print(f"[{ip}:{hostname}] SMB Signing required")
		else:
			print(f"[{ip}:{hostname}] SMB Signing not required")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def enumShares(conn, ip, user, pwd, domain, nthash, aesKey, ccache):
	print_yellow("[*] Enumerating shares")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		originalSTDOUT = sys.stdout
		sys.stdout = StringIO()
		sharesInfo = RPCUtil.listShares(ip, user, pwd, domain, nthash, aesKey, ccache)
		sys.stdout = originalSTDOUT

		if sharesInfo != None:
			shares = []
			print(f"[+] {'Share':<25} {'Description':<60} {'Access':<25}")

			for shareInfo in sharesInfo:
				shareName = shareInfo['shi1_netname'][:-1]
				access = []

				# Can read ?
				try:
					paths = conn.listPath(shareName, "/*")
					access += ['READ']
				except Exception as e:
					pass

				# Can write ?
				tempDir = "/" + ''.join(random.choices(string.ascii_letters, k = 20))
				try:
					conn.createDirectory(shareName, tempDir)
					access += ['WRITE']
					conn.deleteDirectory(shareName, tempDir)
				except Exception as e:
					pass
		
				# No access ?
				if access == []:
					access = ['NO ACCESS']
		
				access = ','.join(access)
				desc = shareInfo['shi1_remark'][:-1] if shareInfo['shi1_remark'] != '\x00' else '<No Description>'

				share = f"[+] {shareName:<25} {desc:<60} {access:<25}"
				shares += [share]
				print(share)
		
		return shares
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

########################################################
#                     Read/Write                       #
########################################################

def readFile(conn, shareName, path, decode, treeId = None):
	smbConn = conn._SMBConnection

	createContexts = None
	data = b''
	offset = 0

	if smbConn.isSnapshotRequest(path):
		createContexts = []
		path, ctx = smbConn.timestampForSnapshot(path)
		createContexts.append(ctx)

	# TODO: Handle situations where share is password protected
	path = path.replace('/', '\\')
	path = ntpath.normpath(path)
	if len(path) > 0 and path[0] == '\\':
		path = path[1:]

	haveTreeId = True
	if treeId == None:
		haveTreeId = False
		treeId = smbConn.connectTree(shareName)
	fileId = smbConn.create(treeId, path, FILE_READ_DATA, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE, FILE_OPEN, 0, createContexts = createContexts)
	res = smbConn.queryInfo(treeId, fileId)
	fileInfo = smb.SMBQueryFileStandardInfo(res)
	fileSize = fileInfo['EndOfFile']
	if (fileSize-offset) < smbConn._Connection['MaxReadSize']:
		# Skip reading 0 bytes files
		if (fileSize-offset) > 0:
			data = smbConn.read(treeId, fileId, offset, fileSize-offset)
	else:
		written = 0
		toBeRead = fileSize-offset
		while written < toBeRead:
			data += smbConn.read(treeId, fileId, offset, smbConn._Connection['MaxReadSize'])
			written += len(data)
			offset  += len(data)
	if fileId is not None:
		smbConn.close(treeId, fileId)
	if not haveTreeId:
		smbConn.disconnectTree(treeId)

	if decode:
		try:
			encoding = chardet.detect(data)['encoding']
			data = data.decode(encoding)
		except:
			pass

	return data

def downloadFile(conn, path, treeId = None):
	print_yellow("[*] Downloading file")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		shareName = path.split("/")[0]
		path = '/'.join(path.split("/")[1:])
		name = path.split("/")[-1]

		contentFile = readFile(conn, shareName, path, False, treeId)
		with open(name, "wb+") as outF:
			outF.write(contentFile)
		print(f"[+] '{name}' saved")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
	
def writeFile(conn, data, shareName, path, treeId = None):
	smbConn = conn._SMBConnection
	
	# TODO: Handle situations where share is password protected
	path = path.replace('/', '\\')
	path = ntpath.normpath(path)
	if len(path) > 0 and path[0] == '\\':
		path = path[1:]

	haveTreeId = True
	if treeId == None:
		haveTreeId = False
		treeId = smbConn.connectTree(shareName)
	fileId = None
	try:
		fileId = smbConn.create(treeId, path, FILE_WRITE_DATA, FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE, FILE_OVERWRITE_IF, 0)
		writeOffset = 0
		while True:
			data = data[writeOffset:]
			if len(data) == 0:
				break
			written = smbConn.write(treeId, fileId, data, writeOffset, len(data))
			writeOffset += written
	finally:
		if fileId is not None:
			smbConn.close(treeId, fileId)
		if not haveTreeId:
			smbConn.disconnectTree(treeId)

def uploadFile(conn, inPath, outPath, treeId = None):
	print_yellow("[*] Uploading file")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		fullDst = outPath
		shareName = outPath.split("/")[0]
		outPath = '/'.join(outPath.split("/")[1:])
		inFile = inPath.split("/")[-1]

		data = open(inPath, "rb").read()
		writeFile(conn, data, shareName, outPath, treeId)
		print(f"[+] '{inFile}' uploaded into '{fullDst}'")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def dirExist(conn, dir, treeId):
	try:
		fid = conn.openFile(treeId, dir, FILE_DIRECTORY_FILE, FILE_READ_DATA | FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE)
		conn.closeFile(treeId, fid)
	except:
		return False
	return True

def removeFile(conn, shareName, path, treeId = None):
	smbConn = conn._SMBConnection
	
	# TODO: Handle situations where share is password protected
	path = path.replace('/', '\\')
	path = ntpath.normpath(path)
	if len(path) > 0 and path[0] == '\\':
		path = path[1:]

	haveTreeId = True
	if treeId == None:
		haveTreeId = False
		treeId = smbConn.connectTree(shareName)
	
	fileId = None
	try:
		fileId = smbConn.create(treeId, path, DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, FILE_OPEN, 0)
	finally:
		if fileId is not None:
			smbConn.close(treeId, fileId)
		if not haveTreeId:
			smbConn.disconnectTree(treeId)

def removeDir(conn, shareName, path, treeId = None):
	smbConn = conn._SMBConnection
	
	# TODO: Handle situations where share is password protected
	path = path.replace('/', '\\')
	path = ntpath.normpath(path)
	if len(path) > 0 and path[0] == '\\':
		path = path[1:]

	haveTreeId = True
	if treeId == None:
		haveTreeId = False
		treeId = smbConn.connectTree(shareName)
	
	fileId = None
	try:
		fileId = smbConn.create(treeId, path, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
								FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT, FILE_OPEN, 0)
		
		delete_req = smb.SMBSetFileDispositionInfo()
		delete_req['DeletePending'] = True
		
		packet = SMB3Packet()
		packet['Command'] = SMB2_SET_INFO
		packet['TreeID']  = treeId

		setInfo = SMB2SetInfo()
		setInfo['InfoType']              = SMB2_0_INFO_FILE
		setInfo['FileInfoClass']         = SMB2_FILE_DISPOSITION_INFO
		setInfo['BufferLength']          = len(delete_req)
		setInfo['AdditionalInformation'] = 0
		setInfo['FileID']                = fileId
		setInfo['Buffer']                = delete_req

		packet['Data'] = setInfo
		packetID = smbConn.sendSMB(packet)
		ans = smbConn.recvSMB(packetID)
		return ans.isValidAnswer(0)
	finally:
		if fileId is not None:
			smbConn.close(treeId, fileId)
		if not haveTreeId:
			smbConn.disconnectTree(treeId)

def removePath(conn, path, treeId = None):
	print_yellow("[*] Removing remote path")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		shareName = path.split("/")[0]
		haveTreeId = True
		if treeId == None:
			haveTreeId = False
			treeId = conn._SMBConnection.connectTree(shareName)
		
		try:
			path = '/'.join(path.split("/")[1:])
			if dirExist(conn, path, treeId):
				removeDir(conn, shareName, path, treeId)
			else:
				removeFile(conn, shareName, path, treeId)
		finally:
			if not haveTreeId:
				conn._SMBConnection.disconnectTree(treeId)

		print(f"[+] '{path}' removed")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
			print(f"[-] '{path}' not found", file = sys.stderr)
		elif str(e).find('STATUS_DIRECTORY_NOT_EMPTY') != -1:
			print(f"[-] Directory '{path}' not empty", file = sys.stderr)
		else:
			print(f"[-] Got error: {str(e)}", file = sys.stderr)
			print('---------------------------------', file = sys.stderr)
			traceback.print_exc()
			print('---------------------------------', file = sys.stderr)

def makeDir(conn, shareName, path, treeId = None):
	smbConn = conn._SMBConnection
	
	# TODO: Handle situations where share is password protected
	path = path.replace('/', '\\')
	path = ntpath.normpath(path)
	if len(path) > 0 and path[0] == '\\':
		path = path[1:]

	haveTreeId = True
	if treeId == None:
		haveTreeId = False
		treeId = smbConn.connectTree(shareName)
	
	fileId = None
	try:
		fileId = smbConn.create(treeId, path, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                 FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, FILE_CREATE, 0)
	finally:
		if fileId is not None:
			smbConn.close(treeId, fileId)
		if not haveTreeId:
			smbConn.disconnectTree(treeId)

def createDir(conn, path, treeId = None):
	print_yellow("[*] Creating directory")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		shareName = path.split("/")[0]
		path = '/'.join(path.split("/")[1:])
		makeDir(conn, shareName, path, treeId)

		print(f"[+] Directory '{path}' created")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		if str(e).find('STATUS_OBJECT_NAME_COLLISION') != -1:
			print(f"[-] '{path}' already exist", file = sys.stderr)
		else:
			print(f"[-] Got error: {str(e)}", file = sys.stderr)
			print('---------------------------------', file = sys.stderr)
			traceback.print_exc()
			print('---------------------------------', file = sys.stderr)

#######################################################
#                     Searching                       #
#######################################################

MATCHED = False
GREP = False

def grepFile(conn, shareName, f, path, name, exts, contents, names, downloadDir, treeId = None, downloadAll = True):
	matchExt = False
	matchContent = False
	matchName = False
	global MATCHED
	if exts != [] and not f.is_directory() > 0:
		nameExt = name.split(".")[-1]
		for ext in exts:
			if ext[1:].lower() == nameExt.lower():
				MATCHED = True
				matchExt = True
				break
	if names != []:
		for key in names:
			if key in name:
				MATCHED = True
				matchName = True
				break
	contentFile = ''
	if contents != [] and not f.is_directory() > 0:
		contentFile = readFile(conn, shareName, path + name, True, treeId)
		for key in contents:
			if isinstance(contentFile, bytes):
				key = key.encode()
			if key.lower() in contentFile.lower():
				MATCHED = True
				matchContent = True
				break
	if ((matchExt or exts == []) and
		(matchContent or contents == []) and
		(matchName or names == [])):
		if downloadDir != None or downloadAll:
			if not matchContent:
				contentFile = readFile(conn, shareName, path + name, False, treeId)
				maybeSleep()
			if downloadDir == None:
				downloadDir = ''
			else:
				if not downloadDir.endswith("/"):
					downloadDir += "/"
			localPath = downloadDir + path + name
			directory = os.path.dirname(localPath)
			os.makedirs(directory, exist_ok = True)
			if isinstance(contentFile, bytes):
				mode = 'wb+'
			else:
				mode = 'w+'
			with open(localPath, mode) as outF:
				outF.write(contentFile)
			print("[+] %s\t%db %s [SAVED]" % (path + name, f.get_filesize(), time.ctime(float(f.get_mtime_epoch()))))
		else:
			print("[+] %s\t%db %s" % (path + name, f.get_filesize(), time.ctime(float(f.get_mtime_epoch()))))

def listShareRec(conn, shareName, path, res, knownDirs, indent, exts, contents, names, downloadDir, allInfo, recursive = True, treeId = None, downloadAll = False):
	try:
		paths = conn.listPath(shareName, path)
		maybeSleep()
	except Exception as e:
		print("    " * indent + "[-] Exception: {}".format(str(e)), file = sys.stderr)
		paths = []
	if path.endswith('*'):
		path = path[:-1]
	for f in paths:
		name = f.get_longname()
		isDir = f.is_directory() > 0
		if isDir:
			displayInfo = "    " * indent + "[+] %s\t%db %s Dir" % (path + name, f.get_filesize(), time.ctime(float(f.get_mtime_epoch())))
		else:
			displayInfo = "    " * indent + "[+] %s\t%db %s File" % (path + name, f.get_filesize(), time.ctime(float(f.get_mtime_epoch())))
		allInfo += [displayInfo]
		if (name != '.' and name != '..'):
			if (exts == [] and contents == [] and names == [] and downloadAll == False): # Just display the file/dir
				print(displayInfo)
			else:
				global GREP
				GREP = True
				if not isDir: # Match file with exts, names and contents and/or download
					try:
						grepFile(conn, shareName, f, path, name, exts, contents, names, downloadDir, treeId, downloadAll)
					except Exception as e:
						print(f"[-] Failed to grep '{path + name}'", file = sys.stderr)
			if isDir and recursive:
				if path+name not in knownDirs:
					listShareRec(conn, shareName, path + name + "/*", res, knownDirs, indent + 1, exts, contents, names, downloadDir, allInfo, recursive, treeId, downloadAll)
				else:
					knownDirs += [path+name]
			else:
				res += [path + name]

	return (res, allInfo)

def listFiles(conn, shareName, path, exts, contents, names, downloadDir, recursive = True, treeId = None, downloadAll = False):
	print_yellow("[*] Listing files on share")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		if exts != []:
			exts = exts.split(",")

		if contents != []:
			contents = contents.split(",")

		if names != []:
			names = names.split(",")

		if treeId == None:
			treeId = conn._SMBConnection.connectTree(shareName)

		if (path != '' and dirExist(conn, path, treeId)) or path == '':
			if path == '':
				path = '*'

			if path.endswith("/"):
				path += '*'
			else:
				if not path.endswith('*'):
					path += "/*"

			res, allInfo = listShareRec(conn, shareName, path, [], [], 0, exts, contents, names, downloadDir, [], recursive, treeId, downloadAll)
			global MATCHED, GREP
			if GREP == True and downloadAll == False:
				if MATCHED == False:
					print("[-] No files matched", file = sys.stderr)
			else:
				if res == [] and downloadAll == False:
					print("[+] Empty")
			MATCHED = False
			GREP = False
			
			return (res, allInfo)
		else:
			print("[-] Invalid directory", file = sys.stderr)
			return ([], [])
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

############################################################################
#                     Group Policy Preferences (GPP)                       #
############################################################################

def getAutologon(xmlString):
	domain = '<None>'
	user = '<None>'
	pwd = '<None>'
	root = ET.fromstring(xmlString)
	registries = root.findall(f".//Registry")
	for registry in registries:
		properties = list(registry) # Properties
		for property in properties:
			if property.attrib['name'] == 'DefaultDomainName':
				domain = property.attrib['value']
			elif property.attrib['name'] == 'DefaultUserName':
				user = property.attrib['value']
			elif property.attrib['name'] == 'DefaultPassword':
				pwd = property.attrib['value']
	if domain != '<None>' or user != '<None>' or pwd != '<None>':
		return (True, f"{domain}\{user}:{pwd}")
	else:
		return (False, "")

def getCPassword(xmlString):
	# TODO
	return (False, '')

def displayGP(xmlString, path):
	print(f"\t[+] Printing raw GP '{path}'")
	print("\t-------------------------")
	try:
		prettyXML = xml.dom.minidom.parseString(xmlString).toprettyxml()
	except:
		prettyXML = xmlString
	lines = prettyXML.split("\n")
	for line in lines:
		print("\t" + line)
	print("\t-------------------------")

def searchGPPs(conn):
	print_yellow("[*] Searching GPP")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		originalSTDOUT = sys.stdout
		originalSTDERR = sys.stderr
		sys.stdout = StringIO()
		sys.stderr = StringIO()
		paths, _ = listFiles(conn, 'SYSVOL', '', [], [], [], None, True)
		sys.stdout = originalSTDOUT
		sys.stderr = originalSTDERR

		haveGPP = False
		gppMachine = r'([^/]+)/Policies/{([^}]+)}/Machine/Preferences/(.+)\.xml'
		gppUser = r'([^/]+)/Policies/{([^}]+)}/User/Preferences/(.+)\.xml'
		for path in paths:
			if not (re.match(gppMachine, path) or re.match(gppUser, path)):
				pass
			else:
				maybeSleep()
				haveGPP = True
				print(f"[+] Found GPP '{path}'")
				content = readFile(conn, 'SYSVOL', path, True)
				haveAutologon, creds = getAutologon(content)
				if haveAutologon:
					print(f"\t[+] Found GPP Autologon = {creds}")
				haveCPassword, pwd = getCPassword(content)
				if haveCPassword:
					print(f"\t[+] Found GPP CPassword = {pwd}")
				if not haveAutologon and not haveCPassword:
					displayGP(content, path)
				# To complete

		if not haveGPP:
			print("[-] No GPP file found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

########################################################
#                     SMB Client                       #
########################################################

def extractKeys(cmd):
	# Regular expression to match words within single quotes, double quotes, and words without quotes
	pattern = r"'[^']*'|\"[^\"]*\"|\S+"
	# Find all matches using the pattern
	words = re.findall(pattern, cmd)
	# Remove surrounding quotes from extracted words
	words = [word.strip("'\"") for word in words]

	return words

def smbClient(conn, ip, user, pwd, domain, nthash, aesKey, ccache):
	print_yellow("[*] Starting SMB client")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		currentDir = ''
		currentShare = ''
		currentTreeId = ''

		while True:
			if currentShare == '':
				cmd = input(f"[{domain}/{user}@{ip}]$> ")
			else:
				if currentDir == '':
					cmd = input(f"[{domain}/{user}@{ip}][{currentShare}]> ")
				else:
					cmd = input(f"[{domain}/{user}@{ip}][{currentShare}/{currentDir}]> ")

			if cmd == "exit": # Exit
				break
			
			elif cmd.startswith("help"): # Help
				print(f"{'shares':<50}- List shares with access rights")
				print(f"{'use <share>':<50}- Connect to <share>")
				print(f"{'ls [<dir>] [-r]':<50}- List <dir> directory or current directory. Recursively or not")
				print(f"{'cd <dir>':<50}- Change working directory")
				print(f"{'upload <localFile> <remotePath>':<50}- Upload <localFile> to <remotePath>")
				print(f"{'download <remotePath> [localOutputDir] [-r]':<50}- Download file into current directory or <localOutputDir>. Directory structure will be created for recursion")
				print(f"{'cat <remoteFile>':<50}- Cat <remoteFile>")
				print(f"{'rm <file>/<dir>':<50}- Remove file/directory")
				print(f"{'mkdir <dir>':<50}- Make directory")
				print()
			
			elif cmd.startswith("shares"): # List shares
				originalSTDOUT = sys.stdout
				sys.stdout = StringIO()
				shares = enumShares(conn, ip, user, pwd, domain, nthash, aesKey, ccache)
				sys.stdout = originalSTDOUT
				for share in shares:
					print(share)
				print()

			elif cmd.startswith("use"): # Connect to a share
				keys = extractKeys(cmd)
				if len(keys) == 2:
					try:
						currentTreeId = conn._SMBConnection.connectTree(keys[1])
						currentShare = keys[1]
					except Exception as e:
						if str(e).find('STATUS_BAD_NETWORK_NAME') != -1:
							print("[-] Invalid share", file = sys.stderr)
						else:
							print(f"[-] Got error: {str(e)}", file = sys.stderr)
							print('---------------------------------', file = sys.stderr)
							traceback.print_exc()
							print('---------------------------------', file = sys.stderr)
					print()
				else:
					print("[-] Invalid 'use' command", file = sys.stderr)
					print()
			
			else:
				if cmd.startswith("ls"): # List files
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						dir = ''
						rec = False
						goodCmd = False
						if len(keys) != 1 and len(keys) != 2 and len(keys) != 3:
							print("[-] Invalid 'ls' command", file = sys.stderr)
						else:
							if len(keys) == 1:
								goodCmd = True
							elif len(keys) == 2:
								if keys[1] == '-r':
									rec = True
								else:
									dir = keys[1]
								goodCmd = True
							elif len(keys) == 3:
								if keys[1] == '-r':
									rec = True
									dir = keys[2]
									goodCmd = True
								else:
									if keys[2] == '-r':
										rec = True
										dir = keys[1]
										goodCmd = True
									else:
										print("[-] Invalid 'ls' command", file = sys.stderr)

						if goodCmd:
							if dir != '' and dir != '.':
								path = ntpath.normpath(currentDir + '/' + dir)
								path = path.replace("\\", "/")
								if path.endswith('/'):
									path = path[:-1]
								if path.startswith('/'):
									path = path[1:]
								if path == '.':
									path = ''
							else:
								path = currentDir

							originalSTDOUT = sys.stdout
							sys.stdout = StringIO()
							_, allInfo = listFiles(conn, currentShare, path, [], [], [], None, rec, currentTreeId, False)
							sys.stdout = originalSTDOUT
							for f in allInfo:
								if path != '.' or path != '':
									pattern = f"{path}/"
									f = re.sub(pattern, '', f, count = 1)
								print(f)
						print()
				
				elif cmd.startswith("cd"): # Change directory
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						if len(keys) != 2:
							print("[-] Invalid 'cd' command", file = sys.stderr)
						else:
							dst = keys[1]
							if dst != '.':
								dst = ntpath.normpath(currentDir + "/" + dst)
								dst = dst.replace("\\", "/")
								if dst.endswith('/'):
									dst = dst[:-1]
								if dst.startswith('/'):
									dst = dst[1:]
								if dst == '.':
									currentDir = ''
								else:
									if dirExist(conn, dst, currentTreeId):
										currentDir = dst
									else:
										print("[-] Directory not found", file = sys.stderr)
							else:
								pass
						print()

				elif cmd.startswith("upload"): # List files
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						if len(keys) != 3:
							print("[-] Invalid 'upload' command", file = sys.stderr)
						else:
							localFile = keys[1]
							remoteFile = keys[2]

							opened = False
							try:
								data = open(localFile, "rb+").read()
								opened = True
							except Exception as e:
								print("[-] Failed to open local file", file = sys.stderr)

							if opened:
								if currentDir != '':
									remoteFile = currentDir + '/' + remoteFile
								
								remoteFile = remoteFile.replace('\\', '/')
								originalSTDOUT = sys.stdout
								sys.stdout = StringIO()
								try:
									writeFile(conn, data, currentShare, remoteFile, currentTreeId)
									sys.stdout = originalSTDOUT
									print(f"[+] '{localFile}' uploaded into '{remoteFile}'")
								except Exception as e:
									sys.stdout = originalSTDOUT
									if str(e).find('STATUS_OBJECT_PATH_NOT_FOUND') != -1:
										print(f"[-] Invalid remote path '{remoteFile}'", file = sys.stderr)
									else:
										print(f"[-] Got error: {str(e)}", file = sys.stderr)
										print('---------------------------------', file = sys.stderr)
										traceback.print_exc()
										print('---------------------------------', file = sys.stderr)
						print()

				elif cmd.startswith("download"): # Download
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						remotePath = ''
						localDir = None
						rec = False
						goodCmd = False
						if len(keys) == 2:
							remotePath = keys[1]
							goodCmd = True
						elif len(keys) == 3:
							goodCmd = True
							remotePath = keys[1]
							if keys[2] == '-r':
								rec = True
							else:
								localDir = keys[2]
						elif len(keys) == 4:
							remotePath = keys[1]
							if keys[2] == '-r':
								goodCmd = True
								rec = True
								localDir = keys[3]
							elif keys[3] == '-r':
								goodCmd = True
								rec = True
								localDir = keys[2]
							else:
								print("[-] Invalid 'download' command", file = sys.stderr)
						else:
							print("[-] Invalid 'download' command", file = sys.stderr)

						if goodCmd:
							if remotePath != '.':
								remotePath = ntpath.normpath(currentDir + '/' + remotePath)
								remotePath = remotePath.replace("\\", "/")
								if remotePath.endswith('/'):
									remotePath = remotePath[:-1]
								if remotePath.startswith('/'):
									remotePath = remotePath[1:]
								if remotePath == '.':
									remotePath = ''
							else:
								remotePath = currentDir

							if dirExist(conn, remotePath, currentTreeId):
								if rec:
									if remotePath == '':
										remotePath = '*'

									if remotePath.endswith("/"):
										remotePath += '*'
									else:
										if not path.endswith('*'):
											path += "/*"

									try:
										_, _ = listShareRec(conn, currentShare, remotePath, [], [], 0, [], [], [], localDir, [], True, currentTreeId, True)
									except Exception as e:
										print(f"[-] Got error: {str(e)}", file = sys.stderr)
										print('---------------------------------', file = sys.stderr)
										traceback.print_exc()
										print('---------------------------------', file = sys.stderr)
								else:
									print(f"[-] '{remotePath}' is a directory and '-r' argument not provided. Skipped", file = sys.stderr)
							else:
								try:
									data = readFile(conn, currentShare, remotePath, False, currentTreeId)
									if localDir != None:
										outF = localDir + '/' + remotePath.split("/")[-1]
									else:
										outF = remotePath.split("/")[-1]
									with open(outF, "wb+") as f:
										f.write(data)
									print(f"[+] '{outF}' saved")
								except Exception as e:
									if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
										print(f"[-] File '{remotePath}' not found", file = sys.stderr)
									else:
										print(f"[-] Got error: {str(e)}", file = sys.stderr)
										print('---------------------------------', file = sys.stderr)
										traceback.print_exc()
										print('---------------------------------', file = sys.stderr)
						print()

				elif cmd.startswith("cat"): # Cat a file
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						if len(keys) != 2:
							print("[-] Invalid 'cat' command", file = sys.stderr)
						else:
							remotePath = keys[1]
							if currentDir != '':
								remotePath = ntpath.normpath(currentDir + "/" + remotePath)
							remotePath = remotePath.replace("\\", "/")
							
							if dirExist(conn, remotePath, currentTreeId):
								print("[-] Remote path is a directory", file = sys.stderr)
							else:
								try:
									data = readFile(conn, currentShare, remotePath, True, currentTreeId)
									print(data)
								except Exception as e:
									if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
										print(f"[-] File '{remotePath}' not found", file = sys.stderr)
									else:
										print(f"[-] Got error: {str(e)}", file = sys.stderr)
										print('---------------------------------', file = sys.stderr)
										traceback.print_exc()
										print('---------------------------------', file = sys.stderr)
						print()

				elif cmd.startswith('rm'): # Remove a file/directory
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						if len(keys) != 2:
							print("[-] Invalid 'rm' command", file = sys.stderr)
						else:
							remotePath = keys[1]
							if remotePath != '.':
								remotePath = ntpath.normpath(currentDir + '/' + remotePath)
								remotePath = remotePath.replace("\\", "/")
								if remotePath.endswith('/'):
									remotePath = remotePath[:-1]
								if remotePath.startswith('/'):
									remotePath = remotePath[1:]
							else:
								remotePath = currentDir
							
							try:
								if dirExist(conn, remotePath, currentTreeId):
									removeDir(conn, currentShare, remotePath, currentTreeId)
								else:
									removeFile(conn, currentShare, remotePath, currentTreeId)
								print(f"[+] '{remotePath}' removed")
							except Exception as e:
								if str(e).find('STATUS_OBJECT_NAME_NOT_FOUND') != -1:
									print(f"[-] '{remotePath}' not found", file = sys.stderr)
								elif str(e).find('STATUS_DIRECTORY_NOT_EMPTY') != -1:
									print(f"[-] Directory '{remotePath}' not empty", file = sys.stderr)
								else:
									print(f"[-] Got error: {str(e)}", file = sys.stderr)
									print('---------------------------------', file = sys.stderr)
									traceback.print_exc()
									print('---------------------------------', file = sys.stderr)
						print()

				elif cmd.startswith('mkdir'): # Create a directory
					if currentShare == '':
						print("[-] Use a share first", file = sys.stderr)
						print()
					else:
						keys = extractKeys(cmd)
						if len(keys) != 2:
							print("[-] Invalid 'mkdir' command", file = sys.stderr)
						else:
							remotePath = keys[1]
							remotePath = ntpath.normpath(currentDir + '/' + remotePath)
							remotePath = remotePath.replace("\\", "/")
							if remotePath.endswith('/'):
								remotePath = remotePath[:-1]
							if remotePath.startswith('/'):
								remotePath = remotePath[1:]

							try:
								makeDir(conn, currentShare, remotePath, currentTreeId)
								print(f"[+] Directory '{remotePath}' created")
							except Exception as e:
								if str(e).find('STATUS_OBJECT_NAME_COLLISION') != -1:
									print(f"[-] '{remotePath}' already exist", file = sys.stderr)
								else:
									print(f"[-] Got error: {str(e)}", file = sys.stderr)
									print('---------------------------------', file = sys.stderr)
									traceback.print_exc()
									print('---------------------------------', file = sys.stderr)
						print()

				else:
					print("[-] Invalid command", file = sys.stderr)
					print()

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
	auth_group = parser.add_argument_group('[[ Authentication ]]')
	auth_group.add_argument("--preferredDialect", help = "SMB Dialect to request. Default = 2.0.2", choices = ["NT LM 0.12", "2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"], default = '2.0.2')

	enum_group = parser.add_argument_group('[[ Enumerate ]]')
	enum_group.add_argument("--getInfo", help = "Get target(s) info (No credential required)", action = "store_true")
	enum_group.add_argument("--getSMBv1", help = "Get target(s) SMBv1 information", action = "store_true")
	enum_group.add_argument("--getOS", help = "Get target(s) OS information", action = "store_true")
	enum_group.add_argument("--getSigning", help = "Get target(s) SMB Signing information", action = "store_true")
	enum_group.add_argument("--shares", help = "Enumerate shares with access rights", action = "store_true")

	bf_group = parser.add_argument_group('[[ Brute Force ]]')
	bf_group.add_argument("--doBF", help = "Perform Brute Force with provided credentials (Usernames/Pwds/NT hashes files or single values)", action = "store_true")
	bf_group.add_argument("--passLogin", help = "Try Password = Login", action = "store_true")

	search_group = parser.add_argument_group('[[ Search ]]')
	search_group.add_argument("--listFiles", help = "List files on the provided share")
	search_group.add_argument("--rec", help = "List files recursively", action = "store_true")
	search_group.add_argument("--directory", help = "Optional directory path to list files", default = '')
	search_group.add_argument("--extensions", help = "Optional extension list to filter. Commas separated list", default = [])
	search_group.add_argument("--contents", help = "Optional keyword list to match with file content (Raw text only). Commas separated list", default = [])
	search_group.add_argument("--names", help = "Optional keyword list to match with file name. Commas separated list", default = [])
	search_group.add_argument("--downloadMatched", help = "Download matched file into the provided directory. Directory structure will be created")

	rw_group = parser.add_argument_group('[[ Read/Write ]]')
	rw_group.add_argument("--downloadFile", help = "File to download from <ShareName>/<Path>")
	rw_group.add_argument("--uploadFile", help = "Upload file with <InputFilePath>:<ShareName>/<OutputFilePath>")
	rw_group.add_argument("--removePath", help = "Directory/file to remove from <ShareName>/<Path>")
	rw_group.add_argument("--makeDir", help = "Create directory <ShareName>/<Path>")

	gpp_group = parser.add_argument_group('[[ GPP ]]')
	gpp_group.add_argument("--GPP", help = "Search GPP files with CPassword and Autologon", action = "store_true")

	client_group = parser.add_argument_group('[[ Client ]]')
	client_group.add_argument("--client", help = "Start an SMB client with basic features", action = "store_true")

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
		
		conn = None

		# Enumerate
		if args.getInfo:
			getInfo(target)
			maybeSleep(inAction = True)
		if args.getSMBv1:
			getSMBv1(target)
			maybeSleep(inAction = True)
		if args.getOS:
			getOS(target)
			maybeSleep(inAction = True)
		if args.getSigning:
			getSigning(target)
			maybeSleep(inAction = True)
		if args.shares:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			_ = enumShares(conn, target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache)
			maybeSleep(inAction = True)

		# Brute Force
		if args.doBF:
			doBF(target, args.username, args.password, args.ntHash, args.domain, args.passLogin)
			maybeSleep(inAction = True)
		
		# Search
		if args.listFiles != None:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			_ = listFiles(conn, args.listFiles, args.directory, args.extensions, args.contents, args.names, args.downloadMatched, args.rec)
			maybeSleep(inAction = True)
		
		# Read/Write
		if args.downloadFile != None:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			downloadFile(conn, args.downloadFile)
			maybeSleep(inAction = True)
		if args.uploadFile != None:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			uploadFile(conn, *args.uploadFile.split(":"))
			maybeSleep(inAction = True)
		if args.removePath != None:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			removePath(conn, args.removePath)
			maybeSleep(inAction = True)
		if args.makeDir != None:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			createDir(conn, args.makeDir)
			maybeSleep(inAction = True)
		
		# GPP
		if args.GPP:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			searchGPPs(conn)
			maybeSleep(inAction = True)
		
		# Client
		if args.client:
			if conn == None:
				conn = connect_smb(target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.preferredDialect)
				maybeSleep(inAction = True)
			smbClient(conn, target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache)
			maybeSleep(inAction = True)

##################################################
#                     TODO                       #
##################################################

# - Control GPP feature + Implement CPassword feature
# - Implement others file format support (PDF, XLSX, etc.) for content search