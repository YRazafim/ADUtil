#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = SPNEGO/Kerberos/NTLM/LDAP/RPC/MSSQL/RDP/SMB/HTTP
from Utils.SPNEGO import SPNEGOUtil
from Utils.KERBEROS import KerberosUtil
from Utils.NTLM import NTLMUtil
from Utils.Errors import ErrorsUtil
from Utils.LDAP import LDAPUtil
from Utils.RPC import RPCUtil
from Utils.MSSQL import MSSQLUtil
from Utils.RDP import RDPUtil
from Utils.SMB import SMBUtil
from Utils.HTTP import HTTPUtil

# Others
import argparse

##################################################
#                     MAIN                       #
##################################################

def print_yellow(text):
	print("\033[93m" + text + "\033[0m")

def main():
	parser = argparse.ArgumentParser(description = "AD Util: Helper for KERBEROS/NTLM/LDAP/RPC/MSSQL/RDP/SMB/HTTP protocols", formatter_class = argparse.RawTextHelpFormatter)

	auth_group = parser.add_argument_group('[[ Authentication ]]')
	auth_group.add_argument("-t", "--target", help = "Target IP/Hostname/URL (for HTTP module) file or commas separated list. FQDN required for Kerberos authentication")
	auth_group.add_argument("-u", "--username", help = "Username for authentication or file", default = "")
	auth_group.add_argument("-p", "--password", help = "Password for authentication or file", default = "")
	auth_group.add_argument("-d", "--domain", help = "Domain for authentication (Target hostname or '.' for local account)", default = "")
	auth_group.add_argument("-nt", "--ntHash", help = "NT Hash for NTLM authentication or file", default = "")
	auth_group.add_argument("-k", "--aesKey", help = "AES 128/256 key for Kerberos authentication or file")
	auth_group.add_argument("-cc", "--ccache", help = "TGT/ST for Kerberos authentication")
	auth_group.add_argument("-c", "--cert", help = "PFX/PEM certificate for LDAP+SChannel or KDC+PKINIT authentication")
	auth_group.add_argument("-cp", "--certPwd", help = "PFX password for PFX certificate")
	auth_group.add_argument("-cpk", "--certPrivKey", help = "PEM private key for PEM certificate")
	auth_group.add_argument("-fT", "--fakeTime", help = 'Fake UTC time for Kerberos authentication ("<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM")')

	detection_group = parser.add_argument_group('[[ Detections ]]')
	detection_group.add_argument("-throttle", help = "Seconds to wait between each targets. Default = None", type = int)
	detection_group.add_argument("-throttleDeep", help = "Seconds to wait between actions and pre-defined requests (mostly recursive functions). Default = None", type = int)
	detection_group.add_argument("-shuffle", help = "Shuffle targets. Default = False", action = "store_true")

	subparsers = parser.add_subparsers(dest = "protocol", required = True, help = "Protocol to target")
	kerberos_parser = subparsers.add_parser('KERBEROS', help = "Manage tickets, compute Kerberos keys and debug communications", formatter_class = argparse.RawTextHelpFormatter)
	KerberosUtil.add_arguments(kerberos_parser)
	ntlm_parser = subparsers.add_parser('NTLM', help = "Compute NTLM hashes/responses and debug communications", formatter_class = argparse.RawTextHelpFormatter)
	NTLMUtil.add_arguments(ntlm_parser)
	ldap_parser = subparsers.add_parser('LDAP', help = "Parse/build/search/edit LDAP attributes", formatter_class = argparse.RawTextHelpFormatter)
	LDAPUtil.add_arguments(ldap_parser)
	rpc_parser = subparsers.add_parser('RPC', help = "Call many procedures through RPC interfaces", formatter_class = argparse.RawTextHelpFormatter)
	RPCUtil.add_arguments(rpc_parser)
	mssql_parser = subparsers.add_parser('MSSQL', help = "Pre-defined/raw queries for MSSQL", formatter_class = argparse.RawTextHelpFormatter)
	MSSQLUtil.add_arguments(mssql_parser)
	rdp_parser = subparsers.add_parser('RDP', help = "RDP client with xfreerdp", formatter_class = argparse.RawTextHelpFormatter)
	RDPUtil.add_arguments(rdp_parser)
	smb_parser = subparsers.add_parser('SMB', help = "Search files and enumerate target info through SMB", formatter_class = argparse.RawTextHelpFormatter)
	SMBUtil.add_arguments(smb_parser)
	http_parser = subparsers.add_parser('HTTP', help = "Request HTTP servers with NTLM/Kerberos", formatter_class = argparse.RawTextHelpFormatter)
	HTTPUtil.add_arguments(http_parser)
	
	args = parser.parse_args()

	if args.fakeTime != None:
		print_yellow("[*] Patching client UTC Time")
		print_yellow("---")
		print()

		try:
			''' Simple method but some library will use different functions to retrieve time (GSSAPI for example) and It will not work
			from unittest.mock import patch
			import datetime
			fixedUTCDate = datetime.datetime.strptime(args.fakeTime, "%d/%m/%Y %H:%M:%S %p").replace(tzinfo = datetime.timezone.utc)
			obj = patch.object(datetime, 'datetime', wraps = datetime.datetime).start()
			obj.utcnow = staticmethod(lambda: fixedUTCDate)
			obj.now = staticmethod(lambda: fixedUTCDate)
			print("[+] Fake client UTC Time = {}\n".format(fixedUTCDate.strftime("%d/%m/%Y %H:%M:%S %p")))
			'''

			import sys, datetime, subprocess, os, traceback
			newCMD = []
			for idx, a in enumerate(sys.argv):
				if a.startswith("-fT") or a.startswith("--fakeTime"):
					requestedTime = sys.argv[idx+1].strip(" AM").strip(" PM")
					requestedTime = requestedTime.split("/")[1] + "/" + requestedTime.split("/")[0] + "/" + requestedTime.split("/")[2]
					newCMD = ["faketime"] + [requestedTime] + sys.argv[:idx] + sys.argv[idx+2:]
					break
			fixedUTCDate = datetime.datetime.strptime(args.fakeTime, "%d/%m/%Y %H:%M:%S %p").replace(tzinfo = datetime.timezone.utc)
			print("[+] Fake client UTC Time = {}\n".format(fixedUTCDate.strftime("%d/%m/%Y %H:%M:%S %p")))
			env = os.environ.copy()
			env['TZ'] = 'UTC'
			subprocess.run(newCMD, env = env)
			exit()
		except KeyboardInterrupt:
			exit()
		except Exception as e:
			print(f"[-] Got error: {str(e)}", file = sys.stderr)
			print('---------------------------------', file = sys.stderr)
			traceback.print_exc()
			print('---------------------------------', file = sys.stderr)
			return ''

	if args.protocol == 'KERBEROS':
		KerberosUtil.handle_arguments(args)
	elif args.protocol == 'NTLM':
		NTLMUtil.handle_arguments(args)
	elif args.protocol == 'LDAP':
		LDAPUtil.handle_arguments(args)
	elif args.protocol == 'RPC':
		RPCUtil.handle_arguments(args)
	elif args.protocol == 'MSSQL':
		MSSQLUtil.handle_arguments(args)
	elif args.protocol == 'RDP':
		RDPUtil.handle_arguments(args)
	elif args.protocol == 'SMB':
		SMBUtil.handle_arguments(args)
	elif args.protocol == 'HTTP':
		HTTPUtil.handle_arguments(args)

if __name__ == "__main__":
	main()

##################################################
#                     TODO                       #
##################################################

# - Implement WinRM protocol
# - Start Powershell variant
#	- Implement protocol communications and inject ST/NT Hash during authentication
#	- OR PTH/PTT and use native Win API (see Mimikatz sekurlsa::pth and kerberos:ptt)
# - Remove unrequired dependencies from installers: libkrb5-dev, krb5-user ?