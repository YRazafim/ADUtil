#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# Others
import binascii, hashlib, textwrap, math, sys, hashlib, hmac, ctypes, traceback
from struct import pack
from Crypto.Cipher import DES, ARC4, AES
from Crypto.Hash import CMAC
try: # In case OpenSSL have MD4 disabled
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")
except:
	pass

#################################################
#                    Annexes                    #
#################################################

# Bit parity adjustment
def bit_parity_adjustment(input):
	keys = []
	digests = textwrap.wrap (input, 14)
	for digest in digests:
		bits = ''
		key = ''
		for hex_val in textwrap.wrap (digest, 2):
			bits += format(int (hex_val, 16), "b").zfill(8)
		for bits7 in textwrap.wrap (bits, 7):
			if ((bits7.count("1") % 2) == 1):
				tmp = hex (int (bits7 + "0", 2))[2:]
			else:
				tmp = hex (int (bits7 + "1", 2))[2:]
			if (len (tmp) == 1):
				tmp = "0" + tmp
			key += tmp
		keys += [key]
	return keys

#########################################################
#                     LM / NT hashes                    #
#########################################################

def pwdToLM(pwd):
	# Password is truncated or null padded to 14 bytes and uppered
	if (len (pwd) > 14):
		pwd = pwd[0:14]
	pwd = pwd.upper()
	pwd = (binascii.hexlify (pwd.encode())).decode() + "00" * (14 - len (pwd))
	
	keys = bit_parity_adjustment (pwd)
	C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
	C1 = binascii.hexlify (C1_Cipher.encrypt (b"KGS!@#$%")).decode()
	C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
	C2 = binascii.hexlify (C2_Cipher.encrypt (b"KGS!@#$%")).decode()

	# LM_Hash = DES-CBC (bit_parity_adjustment (pwd)[0], "KGS!@#$%") | DES-CBC (bit_parity_adjustment (pwd)[1], "KGS!@#$%")
	LM_HASH = C1 + C2
	
	return LM_HASH

def pwdToNT(pwd, hexPwd = None):
	# NT Hash = MD4 (UTF-16LE (<Pwd>))
	if hexPwd != None:
		NT_HASH = hashlib.new ("md4", hexPwd).hexdigest()
	else:
		NT_HASH = hashlib.new ("md4", pwd.encode("utf-16-le")).hexdigest()

	return NT_HASH

def encodePwd(pwd):
	print_yellow("[*] Hex UTF-16LE encode password")
	print_yellow("---")
	print()

	try:
		print ("[+] Hex UTF-16LE encoded password = {}".format(binascii.hexlify(pwd.encode("utf-16le")).decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def computeHash(hexPwd):
	print_yellow("[*] Compute LM/NT Hashes")
	print_yellow("---")
	print()

	try:
		unicodeDecodeError = False
		try:
			pwd = binascii.unhexlify(hexPwd).decode('utf-16-le')
		except UnicodeDecodeError:
			# Unicode characters probably for Machine Account
			# Cannot compute LM Hash as it uses only ASCII printable characters from password -> Return empty LM Hash
			unicodeDecodeError = True

		if unicodeDecodeError:
			print("[+] Password contains unicode characters. Returning empty LM Hash")
			LM_HASH = 'aad3b435b51404eeaad3b435b51404ee'
		else:
			LM_HASH = pwdToLM(pwd)
		print ("[+] LM hash = {}".format (LM_HASH))
		
		NT_HASH = pwdToNT('', binascii.unhexlify(hexPwd))
		print ("[+] NT hash = {}".format (NT_HASH))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

############################################################
#                     NTLM Responses                       #
############################################################

############################
### LMv1/NTLMv1 response ###
############################

# Compute LMv1 response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)
def LMv1_Response(pwd, hexServerChallenge):
	print_yellow("[*] Compute LMv1 Response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None:
			print("[-] Clear-text password and hex Server Challenge required", file = sys.stderr)
			return

		LM_Hash = pwdToLM(pwd)
		
		keys = bit_parity_adjustment (LM_Hash + "00" * (21 - len (binascii.unhexlify (LM_Hash))))
		C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
		C1 = binascii.hexlify (C1_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
		C2 = binascii.hexlify (C2_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C3_Cipher = DES.new (binascii.unhexlify (keys[2]), DES.MODE_ECB)
		C3 = binascii.hexlify (C3_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))

		# LMv1_Response = DES-CBC (bit_parity_adjustment (LM_Hash null padded)[0], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash null padded)[1], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash null padded)[2], hexServerChallenge)
		LMv1_Response = C1 + C2 + C3

		print ("[+] Pwd = {}".format (pwd))
		print ("[+] Server Challenge = {}".format (hexServerChallenge))
		print ("[+] LMv1 Response = {}".format (LMv1_Response.decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv1 response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)
def NTLMv1_Response(pwd, hexServerChallenge):
	print_yellow("[*] Compute NTLMv1 Response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None:
			print("[-] Clear-text password and hex Server Challenge required", file = sys.stderr)
			return

		NT_Hash = pwdToNT(pwd)

		# NT_Hash is null padded to 21 bytes
		NT_Hash += "0000000000"

		keys = bit_parity_adjustment (NT_Hash)
		C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
		C1 = binascii.hexlify (C1_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
		C2 = binascii.hexlify (C2_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C3_Cipher = DES.new (binascii.unhexlify (keys[2]), DES.MODE_ECB)
		C3 = binascii.hexlify (C3_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))

		# NTLMv1_Response = DES-CBC (bit_parity_adjustment (LM_Hash)[0], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash)[1], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash)[2], hexServerChallenge)
		NTLMv1_Response = C1 + C2 + C3

		print ("[+] Pwd = {}".format (pwd))
		print ("[+] Server Challenge = {}".format (hexServerChallenge))
		print ("[+] NTLMv1 Response = {}".format (NTLMv1_Response.decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

############################
### LMv2/NTLMv2 response ###
############################

# Compute LMv2 response for NTLMv2 authentication protocol
def LMv2_Response(pwd, hexServerChallenge, username, domain, hexClientChallenge):
	print_yellow("[*] Compute LMv2 Response for NTLMv2 authentication protocol")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or username == '' or domain == '' or hexClientChallenge == None:
			print("[-] Clear-text password, username, domain and hex Server Challenge, Client Challenge required", file = sys.stderr)
			return

		NT_Hash = pwdToNT(pwd)
		
		# NTLMv2_Hash = HMAC-MD5 (NT_HASH, UTF-16LE (UPPER (<Username>) | <Domain>))
		NTLMv2_Hash = hmac.new (binascii.unhexlify (NT_Hash), (username.upper() + domain).encode("utf-16le"), "md5").hexdigest()

		# NTPROOFSTR = HMAC-MD5 (NTLMv2_Hash, hexServerChallengeE|hexClientChallenge)
		NTPROOFSTR = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (hexServerChallenge + hexClientChallenge), "md5").hexdigest()

		# LMv2 response = NTPROOFSTR | hexClientChallenge
		LMv2_Response = NTPROOFSTR + hexClientChallenge

		print ("[+] Pwd = {}".format (pwd))
		print ("[+] Server Challenge = {}".format (hexServerChallenge))
		print ("[+] Username = {}".format (username))
		print ("[+] Domain = {}".format (domain))
		print ("[+] Client Challenge = {}".format (hexClientChallenge))
		print ("[+] NTProofStr = {}".format (NTPROOFSTR))
		print ("[+] LMv2 Response = {}".format (LMv2_Response))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv2 response for NTLMv2 authentication protocol
def NTLMv2_Response(pwd, hexServerChallenge, username, domain, hexTargetInfo, hexTimestamp, hexClientChallenge):
	print_yellow("[*] Compute NTLMv2 Response for NTLMv2 authentication protocol")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or username == '' or domain == '' or hexTargetInfo == None or hexTimestamp == None or hexClientChallenge == None:
			print("[-] Clear-text password, username, domain and hex Server Challenge, Client Challenge, Target Info, Timestamp required", file = sys.stderr)
			return

		BLOBSIGNATURE = "01010000"
		RESERVED = "00000000"

		NT_HASH = pwdToNT(pwd)

		# NTLMv2_Hash = HMAC-MD5 (NT_HASH, UTF-16LE (UPPER (<username>) | <domain>))
		NTLMv2_Hash = hmac.new (binascii.unhexlify (NT_HASH), (username.upper() + domain).encode("utf-16le"), "md5").hexdigest()

		# BLOB
		# TIMESTAMP = LE-64Bits (Windows timestamp from January 1, 1601 in microseconds)
		# TARGS = DATE.split ("/")
		# TIMESTAMP = binascii.hexlify (struct.pack ("<Q", int ((datetime (int (TARGS[0]), int (TARGS[1]), int (TARGS[2]), int (TARGS[3]), int (TARGS[4]), int (TARGS[5]), int (TARGS[6])) - datetime (1601, 1, 1)).total_seconds() * 10000000))).decode ("utf-8")
		BLOB = BLOBSIGNATURE + RESERVED + hexTimestamp + hexClientChallenge + RESERVED + hexTargetInfo + RESERVED

		# NTPROOFSTR = HMAC-MD5 (NTLMv2_Hash, hexServerChallenge|BLOB)
		NTPROOFSTR = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (hexServerChallenge + BLOB), "md5").hexdigest()

		# NTLMv2 response = NTPROOFSTR | BLOB
		NTLMv2_Response = NTPROOFSTR + BLOB

		print ("[+] Pwd = {}".format (pwd))
		print ("[+] Server Challenge = {}".format (hexServerChallenge))
		print ("[+] Username = {}".format (username))
		print ("[+] Domain = {}".format (domain))
		print ("[+] Target Info = {}".format (hexTargetInfo))
		print ("[+] Timestamp = {}".format (hexTimestamp))
		print ("[+] Client Challenge = {}".format (hexClientChallenge))
		print ("[+] Blob = {}".format (BLOB))
		print ("[+] NTProofStr = {}".format (NTPROOFSTR))
		print ("[+] NTLMv2 Response = {}".format (NTLMv2_Response))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###############################
### NTLMv2 Session Response ###
###############################

# Compute NTLMv2 Session response for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security)
def NTLMv2Session_Response(pwd, hexServerChallenge, hexClientChallenge):
	print_yellow("[*] Compute NTLMv2 Session Response for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or hexClientChallenge == None:
			print("[-] Clear-text password and hex Server Challenge, Client Challenge required", file = sys.stderr)
			return

		# LM_Response = hexClientChallenge null padded to 24 bytes
		LM_Response = hexClientChallenge + "00" * (24 - len (binascii.unhexlify (hexClientChallenge)))

		# NTLMv2_SessionHash = HMAC-MD5 (SNONCE)[0:16]
		SNONCE = hexServerChallenge + hexClientChallenge
		NTLMv2_SessionHash = hashlib.new ("md5", binascii.unhexlify (SNONCE)).hexdigest()[0:16]

		NT_Hash = pwdToNT(pwd)

		keys = bit_parity_adjustment (NT_Hash + "00" * (21 - len (binascii.unhexlify (NT_Hash))))
		C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
		C1 = binascii.hexlify (C1_Cipher.encrypt (binascii.unhexlify (NTLMv2_SessionHash)))
		C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
		C2 = binascii.hexlify (C2_Cipher.encrypt (binascii.unhexlify (NTLMv2_SessionHash)))
		C3_Cipher = DES.new (binascii.unhexlify (keys[2]), DES.MODE_ECB)
		C3 = binascii.hexlify (C3_Cipher.encrypt (binascii.unhexlify (NTLMv2_SessionHash)))

		# NTLMv2_Session_Response = C1|C2|C3
		NTLMv2_Session_Response = C1 + C2 + C3

		print ("[+] Pwd = {}".format (pwd))
		print ("[+] Server Challenge = {}".format (hexServerChallenge))
		print ("[+] Client Challenge = {}".format (hexClientChallenge))
		print ("[+] LM Response = {}".format (LM_Response))
		print ("[+] NTLMv2 Session Response = {}".format (NTLMv2_Session_Response.decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###############################
### NTLM Anonymous response ###
###############################

# Compute Anonymous response for NTLM authentication protocol with anonymous context
def NTLMAnonymous_Response():
	print_yellow("[*] Compute Anonymous Response for NTLM authentication protocol with anonymous context")
	print_yellow("---")
	print()

	try:
		print ("[+] LM Response = 0x0")
		print ("[+] NTLM Response = <Empty>")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########
### MIC ###
###########

# Compute MIC for NTLM authentication protocol
def computeMIC(hexMasterKey2, hexNegotiateChallengeAuthMessage):
	print_yellow("[*] Compute MIC for NTLMv2 authentication protocol")
	print_yellow("---")
	print()

	try:
		if hexMasterKey2 == None:
			print("[-] Hex MasterKey2 required", file = sys.stderr)
			return

		K = binascii.unhexlify (hexMasterKey2)
		M = binascii.unhexlify (''.join(hexNegotiateChallengeAuthMessage.split(':')))

		MIC = hmac.new (K, M, "md5").hexdigest()

		print ("[+] MIC = {}".format (MIC))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#############################################################
#                     Signing/Sealing                       #
#############################################################

########################
### User Session Key ###
########################

# Compute Lan Manager User Session Key for NTLMv1 authentication protocol with "Negotiate Lan Manager Key" flag negotiated
def LanManager_UserSessionKey(pwd, hexServerChallenge):
	print_yellow('[*] Compute Lan Manager User Session Key for NTLMv1 authentication protocol with "Negotiate Lan Manager Key" flag negotiated')
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None:
			print("[-] Clear-text password and hex Server Challenge required", file = sys.stderr)
			return

		LM_Hash = pwdToLM(pwd)
		
		keys = bit_parity_adjustment (LM_Hash + "00" * (21 - len (binascii.unhexlify (LM_Hash))))
		C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
		C1 = binascii.hexlify (C1_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
		C2 = binascii.hexlify (C2_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))
		C3_Cipher = DES.new (binascii.unhexlify (keys[2]), DES.MODE_ECB)
		C3 = binascii.hexlify (C3_Cipher.encrypt (binascii.unhexlify (hexServerChallenge)))

		# LMv1_Response = DES-CBC (bit_parity_adjustment (LM_Hash null padded)[0], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash null padded)[1], hexServerChallenge) | DES-CBC (bit_parity_adjustment (LM_Hash null padded)[2], hexServerChallenge)
		LMv1_Response = C1 + C2 + C3

		keys = bit_parity_adjustment (LM_Hash[0:16] + "bdbdbdbdbdbd")

		C1_Cipher = DES.new (binascii.unhexlify (keys[0]), DES.MODE_ECB)
		C1 = binascii.hexlify (C1_Cipher.encrypt (binascii.unhexlify (LMv1_Response[0:16])))
		C2_Cipher = DES.new (binascii.unhexlify (keys[1]), DES.MODE_ECB)
		C2 = binascii.hexlify (C2_Cipher.encrypt (binascii.unhexlify (LMv1_Response[0:16])))

		LanManager_SessionKey = C1 + C2

		print ("LanManager User Session Key = {}".format (LanManager_SessionKey.decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute LMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)
def LMv1_UserSessionKey(pwd):
	print_yellow("[*] Compute LMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None:
			print("[-] Clear-text password required", file = sys.stderr)
			return

		LM_Hash = pwdToLM(pwd)
		
		LMv1_SessionKey = LM_Hash[0:16] + "00" * 8

		print ("[+] LMv1 User Session Key = {}".format (LMv1_SessionKey))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)
def NTLMv1_UserSessionKey(pwd):
	print_yellow("[*] Compute NTLMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None:
			print("[-] Clear-text password required", file = sys.stderr)
			return

		NT_Hash = pwdToNT(pwd)
		
		NTLMv1_SessionKey = hashlib.new ("md4", binascii.unhexlify (NT_Hash)).hexdigest()

		print ("[+] NTLMv1 User Session Key = {}".format (NTLMv1_SessionKey))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute LMv2 User Session Key for NTLMv2 authentication protocol
def LMv2_UserSessionKey(pwd, hexServerChallenge, username, domain, hexClientChallenge):
	print_yellow("[*] Compute LMv2 User Session Key for NTLMv2 authentication protocol")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or username == '' or domain == '' or hexClientChallenge == None:
			print("[-] Clear-text password required, username, domain and hex Server Challenge, Client Challenge required", file = sys.stderr)
			return

		NT_Hash = pwdToNT(pwd)

		# NTLMv2_Hash = HMAC-MD5 (NT_Hash, UTF-16LE (UPPER (<username>) | <domain>))
		NTLMv2_Hash = hmac.new (binascii.unhexlify (NT_Hash), (username.upper() + domain).encode("utf-16le"), "md5").hexdigest()

		# NTPROOFSTR = HMAC-MD5 (NTLMv2_Hash, hexServerChallenge|hexClientChallenge)
		NTPROOFSTR = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (hexServerChallenge + hexClientChallenge), "md5").hexdigest()

		# LMv2_SessionKey = HMAC-MD5 (NTLMv2_Hash, NTPROOFSTR)
		LMv2_SessionKey = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (NTPROOFSTR), "md5").hexdigest()

		print ("[+] LMv2 User Session Key = {}".format (LMv2_SessionKey))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv2 User Session Key for NTLMv2 authentication protocol
def NTLMv2_UserSessionKey(pwd, hexServerChallenge, username, domain, hexTargetInfo, hexTimestamp, hexClientChallenge):
	print_yellow("[*] Compute NTLMv2 User Session Key for NTLMv2 authentication protocol")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or username == '' or domain == '' or \
			hexTargetInfo == None or hexTimestamp == None or hexClientChallenge == None:
			print("[-] Clear-text password, username, domain and hex Server Challenge, Client Challenge, Target Info, Timestamp required", file = sys.stderr)
			return

		BLOBSIGNATURE = "01010000"
		RESERVED = "00000000"
		
		NT_Hash = pwdToNT(pwd)
		
		# NTLMv2_Hash = HMAC-MD5 (NT_HASH, UTF-16LE (UPPER (<username>) | <domain>))
		NTLMv2_Hash = hmac.new (binascii.unhexlify (NT_Hash), (username.upper() + domain).encode("utf-16le"), "md5").hexdigest()

		# BLOB
		# TIMESTAMP = LE-64Bits (Windows timestamp from January 1, 1601 in microseconds)
		# TARGS = DATE.split ("/")
		# TIMESTAMP = binascii.hexlify (struct.pack ("<Q", int ((datetime (int (TARGS[0]), int (TARGS[1]), int (TARGS[2]), int (TARGS[3]), int (TARGS[4]), int (TARGS[5])) - datetime (1601, 1, 1)).total_seconds()) * 10000000)).decode ("utf-8")
		BLOB = BLOBSIGNATURE + RESERVED + hexTimestamp + hexClientChallenge + RESERVED + hexTargetInfo + RESERVED

		# NTPROOFSTR = HMAC-MD5 (NTLMv2_Hash, hexServerChallenge|BLOB)
		NTPROOFSTR = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (hexServerChallenge + BLOB), "md5").hexdigest()

		NTLMv2_SessionKey = hmac.new (binascii.unhexlify (NTLMv2_Hash), binascii.unhexlify (NTPROOFSTR), "md5").hexdigest()

		print ("[+] NTLMv2 User Session Key = {}".format (NTLMv2_SessionKey))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv2Session User Session Key for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security)
def NTLMv2Session_UserSessionKey(pwd, hexServerChallenge, hexClientChallenge):
	print_yellow("[*] Compute NTLMv2Session User Session Key for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security)")
	print_yellow("---")
	print()

	try:
		if pwd == None or hexServerChallenge == None or hexClientChallenge == None:
			print("[-] Clear-text password and hex Server Challenge, Client Challenge required", file = sys.stderr)
			return

		NT_Hash = pwdToNT(pwd)
		
		NTLMv1_SessionKey = hashlib.new ("md4", binascii.unhexlify (NT_Hash)).hexdigest()

		NTLMv2Session_SessionKey = hmac.new (binascii.unhexlify (NTLMv1_SessionKey), binascii.unhexlify (hexServerChallenge + hexClientChallenge), "md5").hexdigest()

		print ("[+] NTLMv2Session User Session Key = {}".format (NTLMv2Session_SessionKey))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute Null User Session Key for NTLM authentication protocol with anonymous context
def Null_UserSessionKey():
	print_yellow("[*] Compute Null User Session Key for NTLM authentication protocol with anonymous context")
	print_yellow("---")
	print()

	try:
		print ("[+] Null Session Key = 0x00000000000000000000000000000000")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#####################
### Secondary Key ###
#####################

# Decrypt Secondary Key encrypted used when "Negotiate Key Exchange" flag set
def decryptSecondaryKeyEnc(hexMasterKey1, hexSecondaryKeyEnc):
	print_yellow('[*] Decrypt Secondary Key encrypted used when "Negotiate Key Exchange" flag negotiated')
	print_yellow("---")
	print()

	try:
		if hexMasterKey1 == None:
			print("[-] Hex MasterKey1 required", file = sys.stderr)
			return

		SecondaryKey = ARC4.new (binascii.unhexlify(hexMasterKey1)).decrypt (binascii.unhexlify(hexSecondaryKeyEnc))

		print("[+] Secondary Key = {}".format (binascii.hexlify(SecondaryKey).decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

####################
### Final Key(s) ###
####################

# Compute Final Key(s) for Signing&Sealing with NTLMv1/v2 Session Security
def finalKeys(hexMasterKey2):
	print_yellow("[*] Compute Final Key(s) for Signing&Sealing with NTLMv1/v2 Session Security")
	print_yellow("---")
	print()

	try:
		if hexMasterKey2 == None:
			print("[-] Hex MasterKey2 required", file = sys.stderr)
			return

		# Used for NTLMv1 authentication when the "Negotiate NTLM Key" flag not negotiated
		print ("[+] NTLMv1 Session Security")
		print ('\t[+] If "Negotiate Lan Manager Key" and "Negotiate 56" flags negotiated\n\t\t[+] Final Key = {}'.format (hexMasterKey2[0:14] + "a0"))
		print ('\t[+] Elif "Negotiate Lan Manager Key" negotiated and "Negotiate 56" not negotiated\n\t\t[+] Final Key = {}'.format (hexMasterKey2[0:10] + "e538b0"))
		print ("\t[+] Else\n\t\t[+] Final Key = {}".format (hexMasterKey2))

		# Used for NTLMv1 authentication when "Negotiate NTLM Key flag" negotiated or NTLMv2 authentication
		print ("\n[+] NTLMv2 Session Security")
		CSigningKey = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2) + b"session key to client-to-server signing key magic constant\x00").hexdigest()
		SSigningKey = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2) + b"session key to server-to-client signing key magic constant\x00").hexdigest()
		print ("\t[+] Client Signing Key = {}".format (CSigningKey))
		print ("\t[+] Server Signing Key = {}".format (SSigningKey))
		CSealingKey56 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2[0:14]) + b"session key to client-to-server sealing key magic constant\x00").hexdigest()
		SSealingKey56 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2[0:14]) + b"session key to server-to-client sealing key magic constant\x00").hexdigest()
		CSealingKey128 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2) + b"session key to client-to-server sealing key magic constant\x00").hexdigest()
		SSealingKey128 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2) + b"session key to server-to-client sealing key magic constant\x00").hexdigest()
		CSealingKey40 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2[0:10]) + b"session key to client-to-server sealing key magic constant\x00").hexdigest()
		SSealingKey40 = hashlib.new ("md5", binascii.unhexlify (hexMasterKey2[0:10]) + b"session key to server-to-client sealing key magic constant\x00").hexdigest()
		print ('\t[+] If "Negotiate 56" flag negotiated\n\t\t[+] Client Sealing Key = {}\n\t\t[+] Server Sealing Key = {}'.format (CSealingKey56, SSealingKey56))
		print ('\t[+] Elif "Negotiate 128" flag negotiated\n\t\t[+] Client Sealing Key = {}\n\t\t[+] Server Sealing Key = {}'.format (CSealingKey128, SSealingKey128))
		print ("\t[+] Else\n\t\t[+] Client Sealing Key = {}\n\t\t[+] Server Sealing Key = {}".format (CSealingKey40, SSealingKey40))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#######################
### Signing/Sealing ###
#######################

# Compute NTLMv1 Signing and Sealing of a message
def signSeal_NTLMv1SessionSecurity(hexMessage, hexFinalKey):
	print_yellow("[*] NTLMv1 Signing and Sealing of a message")
	print_yellow("---")
	print()

	try:
		if hexFinalKey == None:
			print("[-] Hex Final Key required", file = sys.stderr)
			return

		M = binascii.unhexlify (hexMessage)
		K = binascii.unhexlify (hexFinalKey)

		def MakeSignature (Cipher, M, SN):
			CRC32 = binascii.hexlify (pack ("<I", binascii.crc32 (M))).decode ("utf-8")
			C = binascii.hexlify (Cipher.encrypt (binascii.unhexlify ("00" * 4 + CRC32 + SN))).decode ("utf-8")
			return "01000000" + "<CounterRandom>" + C[8:]

		def EncryptMessage (Cipher, M, SN):
			Seal = binascii.hexlify (Cipher.encrypt (M)).decode ("utf-8")
			return (Seal, MakeSignature (Cipher, M, SN))

		Cipher = ARC4.new (K)
		print ("[+] Signature = {}".format (MakeSignature (Cipher, M, "00000000")))

		Seal1, C1 = EncryptMessage (Cipher, M, "01000000")
		print ("[+] Seal1 = {}".format (Seal1))
		Seal2, C2 = EncryptMessage (Cipher, M, "02000000")
		print ("[+] Seal2 = {}".format (Seal2))

		print ("[+] Trailer buffer signature =\n{}\n{}".format (C1, C2))

		print ("[+] Encrypted message =\n{}\n{}".format (Seal1 + C1, Seal2 + C2))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

# Compute NTLMv2 Signing and Sealing of a message
def signSeal_NTLMv2SessionSecurity(hexMessage, hexSigningKey, hexSealingKey, negKeyExchangeFlag):
	print_yellow("[*] NTLMv2 Signing and Sealing of a message")
	print_yellow("---")
	print()

	try:
		if hexSigningKey == None or hexSealingKey == None:
			print("[-] Hex Signing Key and Sealing Key required", file = sys.stderr)
			return

		M = binascii.unhexlify (hexMessage)
		KSign = binascii.unhexlify (hexSigningKey)
		KSeal = binascii.unhexlify (hexSealingKey)

		def MakeSignature (Cipher, M, KSign, SN, negKeyExchangeFlag):
			X = hmac.new (KSign, binascii.unhexlify (SN + binascii.hexlify (M).decode ("utf-8")), "md5").hexdigest()
			if (negKeyExchangeFlag):
				C = binascii.hexlify (Cipher.encrypt (binascii.unhexlify (X[0:16]))).decode ("utf-8")
				return "01000000" + C + SN
			else:
				return "01000000" + X[0:16] + SN

		def EncryptMessage (Cipher, M, KSign, SN, negKeyExchangeFlag):
			Seal = binascii.hexlify (Cipher.encrypt (M)).decode ("utf-8")
			return (Seal, MakeSignature (Cipher, M, KSign, SN, negKeyExchangeFlag))

		Cipher = ARC4.new (KSeal)
		print ("[+] Signature = {}".format (MakeSignature (Cipher, M, KSign, "00000000", negKeyExchangeFlag)))

		Seal1, C1 = EncryptMessage (Cipher, M, KSign, "01000000", negKeyExchangeFlag)
		print ("[+] Seal1 = {}".format (Seal1))
		Seal2, C2 = EncryptMessage (Cipher, M, KSign, "02000000", negKeyExchangeFlag)
		print ("[+] Seal2 = {}".format (Seal2))

		print ("[+] Trailer buffer signature =\n{}\n{}".format (C1, C2))

		print ("[+] Encrypted message =\n{}\n{}".format (Seal1 + C1, Seal2 + C2))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#################################################
#                     SMB                       #
#################################################

def deriveKeySMB(hexMasterKey2, dialectSMB, hexPrevSMBPackets = "", indent = 0):
	if indent == 0:
		print_yellow("[*] Compute SMB Signing Key")
		print_yellow("---")
		print()

	try:
		if dialectSMB == None:
			print("\t" * indent + "[-] SMB Dialect required", file = sys.stderr)
			return ''

		def ComputePreAuthIntegrityHash (messages):
			preAuthIntegrityHash = "00" * 64
			for message in messages:
				toHash = preAuthIntegrityHash + message
				preAuthIntegrityHash = hashlib.sha512 (binascii.unhexlify (toHash)).hexdigest()
			return preAuthIntegrityHash

		def SMB3KDF (sessionKey, Label, Context):
			r = 32
			L = 128
			n = math.ceil (L / 256)
			if (n > ((2**r) - 1)):
				return ""
			res = ""
			for i in range (1, n+1):
				fixedInputData = binascii.unhexlify ("0" * ((r // 4) - len (hex (i)[2:])) + hex (i)[2:]) + Label + b"\x00" + Context + binascii.unhexlify ("0" * ((r // 4) - len (hex (L)[2:])) + hex (L)[2:])
				K = hmac.new (sessionKey, fixedInputData, "sha256").hexdigest()
				res += K
			return res[:r]

		if (dialectSMB == "2.0.2" or dialectSMB == "2.1"):
			KSign = hexMasterKey2
			KApp = hexMasterKey2
			print ("\t" * indent + "[+] Signing Key = {}".format (KSign))
			print ("\t" * indent + "[+] Application Key = {}".format (KApp))
			return KSign
		elif (dialectSMB == "3.0" or dialectSMB == "3.0.2"):
			KSign = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMB2AESCMAC\x00", b"SmbSign\x00")
			KApp = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMB2APP\x00", b"SmbRpc\x00")
			CliKEnc = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMB2AESCCM\x00", b"ServerIn\x00")
			ServerKDec = CliKEnc
			CliKDec = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMB2AESCCM\x00", b"ServerOut\x00")
			ServerKEnc = CliKDec
			print ("\t" * indent + "[+] Signing Key = {}".format (KSign))
			print ("\t" * indent + "[+] Application Key = {}".format (KApp))
			print ("\t" * indent + "[+] Client Encryption Key = Server Decryption Key = {}".format (CliKEnc, ServerKDec))
			print ("\t" * indent + "[+] Client Decryption Key = Server Encryption Key = {}".format (CliKDec, ServerKEnc))
			return KSign
		elif (dialectSMB == "3.1.1"):
			if (hexPrevSMBPackets != ""):
				PrevMessages = hexPrevSMBPackets.split(":")
				preAuthIntegrityHash = ComputePreAuthIntegrityHash (PrevMessages)
				KSign = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMBSigningKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				KApp = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMBAppKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				CliKEnc = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMBC2SCipherKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				ServerKDec = CliKEnc
				CliKDec = SMB3KDF (binascii.unhexlify (hexMasterKey2), b"SMBS2CCipherKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				ServerKEnc = CliKDec
				print ("\t" * indent + "[+] Signing Key = {}".format (KSign))
				print ("\t" * indent + "[+] Application Key = {}".format (KApp))
				print ("\t" * indent + "[+] Client Encryption Key = Server Decryption Key = {}".format (CliKEnc, ServerKDec))
				print ("\t" * indent + "[+] Client Decryption Key = Server Encryption Key = {}".format (CliKDec, ServerKEnc))
				return KSign
			else:
				print ("\t" * indent + "[-] Previous SMB messages required for SMB Dialect 3.1.1 in the form <SMBHeader+NegotiateProtocolRequest>:<SMBHeader+NegotiateProtocolResponse>:<SMBHeader+SessionSetupRequest>:<SMBHeader+SessionSetupResponse>:<SMBHeader+SessionSetupRequest>", file = sys.stderr)
				return ''
		else:
			print ("\t" * indent + "[-] Unsupported SMB Dialect", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def signPacketSMB(hexMasterKey2, dialectSMB, hexSMBPacket, hexPrevSMBPackets = ""):
	print_yellow("[*] Compute SMB Signature of the message")
	print_yellow("---")
	print()

	try:
		if dialectSMB == None or hexMasterKey2 == None:
			print("[-] SMB Dialect and hex MasterKey2 required", file = sys.stderr)
			return

		print("[+] Derive MasterKey2")
		hexSigningKey = deriveKeySMB(hexMasterKey2, dialectSMB, hexPrevSMBPackets, indent = 1)
		if hexSigningKey == '':
			return

		print("[+] Computing signature")
		if (dialectSMB == "2.0.2" or dialectSMB == "2.1"):
			Signature = hmac.new (binascii.unhexlify (hexSigningKey), binascii.unhexlify (hexSMBPacket), "sha256").hexdigest()[:32]
		elif (dialectSMB == "3.0" or dialectSMB == "3.0.2" or dialectSMB == "3.1.1"):
			Signature = CMAC.new (binascii.unhexlify (hexSigningKey), binascii.unhexlify (hexSMBPacket), ciphermod = AES).hexdigest()
		else:
			print("\t[-] Unsupported SMB Dialect", file = sys.stderr)
			return
		print ("\t[+] Signature = {}".format (Signature))
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

def add_arguments(parser):
	general_group = parser.add_argument_group('[[ General ]]')
	general_group.add_argument("--hexServerChallenge", help = "Hex Server Challenge")
	general_group.add_argument("--hexClientChallenge", help = "Hex Client Challenge")
	general_group.add_argument("--hexTargetInfo", help = "Hex Target Info")
	general_group.add_argument("--hexTimestamp", help = "Hex Timestamp")
	general_group.add_argument("--hexUserSessionKey", help = "Hex User Session Key (Lan Manager/LMv1/LMv2/NTLMv1/NTLMv2/NTLMv2Session/Null User Session Key)")
	general_group.add_argument("--hexSecondaryKeyEnc", help = "Hex Secondary Key encrypted")
	general_group.add_argument("--hexMasterKey1", help = "Hex MasterKey1")
	general_group.add_argument("--hexMasterKey2", help = "Hex MasterKey2")
	general_group.add_argument("--hexFinalKey", help = "Hex Final Key")
	general_group.add_argument("--hexSigningKey", help = "Hex Signing Key")
	general_group.add_argument("--hexSealingKey", help = "Hex Sealing Key")
	general_group.add_argument("--negKeyExchangeFlag", help = 'Set "Negotiate Key Exchange" flag for Signing and Sealing', action = "store_true")
	general_group.add_argument("--dialectSMB", help = "SMB Dialect for SMB Signing", choices = ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"])
	general_group.add_argument("--hexPrevSMBPackets", help = "Previous SMB messages for SMB Dialect 3.1.1 in the form <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>")
	
	hash_group = parser.add_argument_group('[[ LM/NT Hashes ]]')
	hash_group.add_argument("--encodePwd", help = "Hex UTF-16LE encode provided password")
	hash_group.add_argument("--computeHash", help = "Compute LM/NT Hashes from <HexUTF16LEPwd>. Hex UTF-16LE encoded password useful for machine account's pwds")
	
	ntlmresponses_group = parser.add_argument_group('[[ NTLM Responses ]]')
	ntlmresponses_group.add_argument("--NTLMv1Response", help = "Compute LMv1/NTLMv1 Response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)", action = "store_true")
	ntlmresponses_group.add_argument("--NTLMv2Response", help = "Compute LMv2/NTLMv2 Response for NTLMv2 authentication protocol", action = "store_true")
	ntlmresponses_group.add_argument("--NTLMv2SessionResponse", help = "Compute NTLMv2 Session Response for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security)", action = "store_true")
	ntlmresponses_group.add_argument("--anonymousResponse", help = "Compute Anonymous Response for NTLM authentication protocol with anonymous context", action = "store_true")
	ntlmresponses_group.add_argument("--MIC", help = "Compute MIC of message <HexNTLMSSP_NEGOTIATE>:<HexNTLMSSP_CHALLENGE>:<HexNTLMSSP_AUTH> for NTLMv2 authentication protocol. MIC field of NTLMSSP_AUTH must be replaced with '0'*32")
	
	signseal_group = parser.add_argument_group('[[ Signing/Sealing ]]')
	signseal_group.add_argument("--LanManagerUserSessionKey", help = 'Compute Lan Manager User Session Key for NTLMv1 authentication protocol with "Negotiate Lan Manager Key" flag negotiated', action = "store_true")
	signseal_group.add_argument("--LMv1UserSessionKey", help = "Compute LMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)", action = "store_true")
	signseal_group.add_argument("--NTLMv1UserSessionKey", help = "Compute NTLMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security)", action = "store_true")
	signseal_group.add_argument("--LMv2UserSessionKey", help = "Compute LMv2 User Session Key for NTLMv2 authentication protocol", action = "store_true")
	signseal_group.add_argument("--NTLMv2UserSessionKey", help = "Compute NTLMv2 User Session Key for NTLMv2 authentication protocol", action = "store_true")
	signseal_group.add_argument("--NTLMv2SessionUserSessionKey", help = "Compute NTLMv2Session User Session Key for NTLMv1 authentication with NTLMv2 Session Security (Extended Session Security)", action = "store_true")
	signseal_group.add_argument("--nullUserSessionKey", help = "Compute Null User Session Key for NTLM authentication protocol with anonymous context", action = "store_true")
	signseal_group.add_argument("--secondaryKeyEnc", help = 'Secondary Key encrypted to decrypt when "Negotiate Key Exchange" flag negotiated')
	signseal_group.add_argument("--finalKeys", help = "Compute Final Key(s) for Signing and Sealing with NTLMv1/v2 Session Security", action = "store_true")
	signseal_group.add_argument("--signSealNTLMv1", help = "Compute NTLMv1 Signing and Sealing from hex message")
	signseal_group.add_argument("--signSealNTLMv2", help = "Compute NTLMv2 Signing and Sealing from hex message")
	
	smb_group = parser.add_argument_group('[[ SMB Signing ]]')
	smb_group.add_argument("--deriveKeySMB", help = "Hex MasterKey2 to derive")
	smb_group.add_argument("--signPacketSMB", help = "SMB packet <HexSMBHeader+SMBMessage> to sign. Signature field must be replaced with '0'*32")
	
def handle_arguments(args):
	targets = ['LOCAL']

	for target in targets:
		print_red("|---------------------------")
		print_red(f"| {target}")
		print_red("|---------------------------")
		print()

		# LM/NT Hashes
		if args.encodePwd != None:
			encodePwd(args.encodePwd)
			print()
		if args.computeHash != None:
			computeHash(args.computeHash)
			print()
		
		# NTLM Responses
		if args.NTLMv1Response:
			LMv1_Response(args.password, args.hexServerChallenge)
			print()
			NTLMv1_Response(args.password, args.hexServerChallenge)
			print()
		if args.NTLMv2Response:
			LMv2_Response(args.password, args.hexServerChallenge, args.username, args.domain, args.hexClientChallenge)
			print()
			NTLMv2_Response(args.password, args.hexServerChallenge, args.username, args.domain, args.hexTargetInfo, args.hexTimestamp, args.hexClientChallenge)
			print()
		if args.NTLMv2SessionResponse:
			NTLMv2Session_Response(args.password, args.hexServerChallenge, args.hexClientChallenge)
			print()
		if args.anonymousResponse:
			NTLMAnonymous_Response()
			print()
		if args.MIC != None:
			computeMIC(args.hexMasterKey2, args.MIC)
			print()
		
		# Signing/Sealing
		if args.LanManagerUserSessionKey:
			LanManager_UserSessionKey(args.password, args.hexServerChallenge)
			print()
		if args.LMv1UserSessionKey:
			LMv1_UserSessionKey(args.password)
			print()
		if args.NTLMv1UserSessionKey:
			NTLMv1_UserSessionKey(args.password)
			print()
		if args.LMv2UserSessionKey:
			LMv2_UserSessionKey(args.password, args.hexServerChallenge, args.username, args.domain, args.hexClientChallenge)
			print()
		if args.NTLMv2UserSessionKey:
			NTLMv2_UserSessionKey(args.password, args.hexServerChallenge, args.username, args.domain, args.hexTargetInfo, args.hexTimestamp, args.hexClientChallenge)
			print()
		if args.NTLMv2SessionUserSessionKey:
			NTLMv2Session_UserSessionKey(args.password, args.hexServerChallenge, args.hexClientChallenge)
			print()
		if args.nullUserSessionKey:
			Null_UserSessionKey()
			print()
		if args.secondaryKeyEnc != None:
			decryptSecondaryKeyEnc(args.hexMasterKey1, args.secondaryKeyEnc)
			print()
		if args.finalKeys:
			finalKeys(args.hexMasterKey2)
			print()
		if args.signSealNTLMv1 != None:
			signSeal_NTLMv1SessionSecurity(args.signSealNTLMv1, args.hexFinalKey)
			print()
		if args.signSealNTLMv2 != None:
			signSeal_NTLMv2SessionSecurity(args.signSealNTLMv2, args.hexSigningKey, args.hexSealingKey, args.negKeyExchangeFlag)
			print()
		
		# SMB Signing
		if args.deriveKeySMB != None:
			deriveKeySMB(args.deriveKeySMB, args.dialectSMB, args.hexPrevSMBPackets)
			print()
		if args.signPacketSMB != None:
			signPacketSMB(args.hexMasterKey2, args.dialectSMB, args.signPacketSMB, args.hexPrevSMBPackets)
			print()
		
##################################################
#                     TODO                       #
##################################################

# - Implement NTLM Relay