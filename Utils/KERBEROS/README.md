# Debugging

## PA_ENC_TIMESTAMP

Decrypt hex-encoded PA_ENC_TIMESTAMP cipher value from PADATA of KRB_AS_REQ (`Kerberos->as-req->padata->pA-ENC-TIMESTAMP->padata-type->padata-value->cipher`).
- Requirement
    - User Secret Key (for the requested Encryption Type)
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --PA_ENC_TIMESTAMP <HexPAENCTIMESTAMP> --encryptionType <EncType> --hexUserSecretKey <HexUserSecretKey>
```

## TGTEncPart

Decrypt hex-encoded TGT encrypted part of KRB_AS_REP (`Kerberos->as-rep->ticket->enc-part->cipher`).
- Requirement
    - Krbtgt Secret Key (for the requested Encryption Type)
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --TGTEncPart <HexTGTEncPart> --encryptionType <EncType> --hexKrbtgtSecretKey <HexKrbtgtSecretKey>
```

## ASRepEncPart

Decrypt hex-encoded AS-Rep encrypted part of KRB_AS_REP (`Kerberos->as-rep->enc-part->cipher`).
- Requirement
    - User Secret Key (for the requested Encryption Type) or AS-Rep Encryption Key for PKINIT authentication
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --ASRepEncPart <HexASRepEncPart> --encryptionType <EncType> --hexUserSecretKey <HexKrbtgtSecretKey>
ADUtil KERBEROS --ASRepEncPart <HexASRepEncPart> --encryptionType <EncType> --hexASRepEncKey <HexASRepEncKey>
```

## PA_PK_AS_REP

Decode hex-encoded PA_PK_AS_REP value from PADATA of KRB_AS_REP (`Kerberos->as-rep->padata->pA-PK-AS-REP->padata-type->padata-value`) for PKINIT authentication.
- Requirement
    - Diffie-Hellman Private Key (Displayed when requesting TGT with ADUtil and PKINIT)
    - Diffie-Hellman Nonce (Displayed when requesting TGT with ADUtil and PKINIT)
- Note
    - Using hardcoded public Diffie-Hellman parameters `p = int('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16)` and `g = 2`

```
ADUtil KERBEROS --PA_PK_AS_REP <HexDHPrivKey>:<HexDHNonce>:<HexPaPKASRepValue>
```

## PA_TGS_REQ_Authenticator

Decrypt hex-encoded PA_TGS_REQ Authenticator cipher value from PADATA of KRB_TGS_REQ (`Kerberos->tgs-req->padata->pA-TGS-REQ->padata-type->padata-value->ap-req->authenticator->cipher`).
- Requirement
    - Client-to-TGS Session Key
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --PA_TGS_REQ_Authenticator <HexPATGSREQAuthenticator> --encryptionType <EncType> --hexClientTGSSessionKey <HexClientTGSSessionKey>
```

## PA-FOR-USER

Build PA-FOR-USER from PADATA of KRB_TGS_REQ (`Kerberos->tgs-req->padata->pA-FOR-USER->padata-type->padata-value`) for S4U2Self.
- Requirement
    - Client-to-TGS Session Key

```
ADUtil KERBEROS --PA_FOR_USER <Domain>:<CnameToImpersonate> --hexClientTGSSessionKey <HexClientTGSSessionKey>
```

## PA_PAC_OPTIONS

Build PA-PAC-OPTIONS from PADATA of KRB_TGS_REQ (`Kerberos->tgs-req->padata->pA-PAC-OPTIONS->padata-type->padata-value`) for S4U2Proxy with RBCD bit flag set (offset = 3).

```
ADUtil KERBEROS --PA_PAC_OPTIONS
```

## STEncPart

Decrypt hex-encoded Service Ticket encrypted part of KRB_TGS_REP (`Kerberos->tgs-rep->ticket->enc-part->cipher`).
- Requirement
    - Service Secret Key (for the requested Encryption Type) or Client-to-TGS Session Key for S4U2Self+U2U
    - Encryption Type (23, 17, 18)
- Optional
    - AS-Rep Encryption Key to decrypt PAC_CREDENTIALS_INFO NTLM package for PKINIT authentication

```
ADUtil KERBEROS --STEncPart <HexSTEncPart> --encryptionType <EncType> --hexServiceSecretKey <HexServiceSecretKey> [--hexASRepEncKey <HexASRepEncKey>]
ADUtil KERBEROS --STEncPart <HexSTEncPart> --encryptionType <EncType> --hexClientTGSSessionKey <HexClientTGSSessionKey> [--hexASRepEncKey <HexASRepEncKey>]
```

## TGSRepEncPart

Decrypt hex-encoded TGS-Rep encrypted part of KRB_TGS_REP (`Kerberos->tgs-rep->enc-part->cipher`).
- Requirement
    - Client-to-TGS Session Key
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --TGSRepEncPart <HexTGSRepEncPart> --encryptionType <EncType> --hexClientTGSSessionKey <HexClientTGSSessionKey>
```

## AP_REQ_Authenticator

Decrypt hex-encoded AP_REQ Authenticator cipher value from KRB_AP_REQ wrapped into the targeted communication protocol (`<Protocol>->Kerberos->ap-req->authenticator->cipher`)
- Requirement
    - Client-to-Service Session Key
    - Encryption Type (23, 17, 18)

```
ADUtil KERBEROS --AP_REQ_Authenticator <HexAPREQAuthenticator> --encryptionType <EncType> --hexClientServiceSessionKey <HexClientServiceSessionKey>
```

## SMB Key Derivation

Derive hex-encoded Client-to-Service Session Key (as MasterKey2) for SMB Signing
- Requirement
    - SMB Dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1)
    - Previous SMB messages in the form of &lt;HexSMBHeader+NegotiateProtocolRequest&gt;:&lt;HexSMBHeader+NegotiateProtocolResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt;:&lt;HexSMBHeader+SessionSetupResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt; for SMB Dialect = 3.1.1

```
ADUtil KERBEROS --deriveKeySMB <HexClientServiceSessionKey> --dialectSMB <SMBDialect> [--hexPrevSMBPackets <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>]
```

## SMB Signing

Sign an hex-encoded SMB packet &lt;HexSMBHeader+SMBMessage&gt;.
- Requirement
    - Client-to-Service Session Key
    - SMB Dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1)
    - Previous SMB messages in the form of &lt;HexSMBHeader+NegotiateProtocolRequest&gt;:&lt;HexSMBHeader+NegotiateProtocolResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt;:&lt;HexSMBHeader+SessionSetupResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt; for SMB Dialect = 3.1.1
- Note
    - Signature field must be replaced with '0'*32 from &lt;HexSMBHeader+SMBMessage&gt;

```
ADUtil KERBEROS --signPacketSMB <HexSMBHeader+SMBMessage> --hexClientServiceSessionKey <HexClientServiceSessionKey> --dialectSMB <SMBDialect> [--hexPrevSMBPackets <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>]
```

## Exporting Keys for Wireshark

Export provided Kerberos Key(s) into file for Wireshark decryption.
- Requirement
    - Output file name and hex-encoded Kerberos Key(s) along with their Encryption Type (23, 17, 18) in the form of &lt;OutFile>:(&lt;EncType1&gt;,&lt;HexKerberosKey1&gt;):[...]:(&lt;EncTypeN&gt;,&lt;HexKerberosKeyN&gt;)
- Note
    - Add the output file into Wireshark Edit -> Preferences -> KRB5 and select 'Try to decrypt Kerberos blobs'

```
ADUtil KERBEROS --keysToWireshark <OutFile>:(<EncType1>,<HexKerberosKey1>):[...]:(<EncTypeN>,<HexKerberosKeyN>)
```

# Kerberos Key

## Encode password

Hex UTF-16LE encode provided password.
- Requirement
    - Password

```
ADUtil KERBEROS --encodePwd <Password>
```

## Kerberos Key

Compute Kerberos Key for encryption type 18, 17 and 23 from account name, domain FQDN and hex UTF-16LE encoded password.
- Requirement
    - Account name
    - Domain FQDN
    - Hex UTF-16LE encoded password or empty string
- Note
    - Using hex UTF-16LE encoded password as argument is useful for machine accounts' pwds. This is the encoding format for $MACHINE.ACC from LSA secrets

```
ADUtil KERBEROS --computeKerberosKey <AccountName>:<DomainFQDN>:<HexUTF16LEPwd>
ADUtil KERBEROS --computeKerberosKey <AccountName>:<DomainFQDN>: # Empty password
```

# Managing Ticket

## Parsing Credential File

Parse a Credential File (CCACHE/Kirbi) and display its values.
- Requirement
    - Credential File (CCACHE/Kirbi)
- Optional
    - Kerberos keys to decrypt ticket encrypted part (hexCredFileKeys1)
        - TGT
            - Krbtgt Secret Key
        - ST
            - Service Secret Key
            - Client-to-TGS Session Key
    - AS-Rep Encryption Keys to decrypt PAC_CREDENTIALS_INFO NTLM package for PKINIT authentication (hexCredFileKeys2)
- Note
    - Multiple keys can be provided if more than one credential inside Credential File

```
ADUtil KERBEROS --credFile <CredFile> [--hexCredFileKeys1 <Key1>,<Key2>,...,<KeyN>] [--hexCredFileKeys2 <Key1>,<Key2>,...,<KeyN>]
```

## Converting Credential File

Convert a Credential File (CCACHE <-> Kirbi).
- Requirement
    - Input Credential File (CCACHE/Kirbi) and output Credential File (CCACHE/Kirbi) in the form of &lt;InputCredFile&gt;:&lt;OutputCredFile&gt;

```
ADUtil KERBEROS --convertFile <InputCredFile>:<OutputCredFile>
```

## Extracting credentials from Credential File

Extract a credential &lt;UserName&gt;@&lt;ServiceClass&gt;/&lt;ServerFQDN&gt;@&lt;DomainFQDN&gt; from input Credential File (CCACHE/Kirbi) to output Credential File (CCACHE/Kirbi).
- Requirement
    - Credential to extract, input Credential File (CCACHE/Kirbi) and output Credential File (CCACHE) in the form of &lt;UserName&gt;@&lt;ServiceClass&gt;/&lt;ServerFQDN&gt;@&lt;DomainFQDN&gt;:&lt;InputCredFile&gt;:&lt;OutputCredFile&gt;
- Note
    - Output Credential File is created as CCACHE if it does not exist otherwise the extracted credential is added

```
ADUtil KERBEROS --extractCred <UserName>@<ServiceClass>/<ServerFQDN>@<DomainFQDN>:<InputCredFile>:<OutputCredFile>
```

## Editing Credential File

Edit unencrypted fields of a Credential File (CCACHE/Kirbi).
- Requirement
    - Input Credential File (CCACHE/Kirbi) and output Credential File (CCACHE/Kirbi) in the form of &lt;InputCredFile&gt;:&lt;OutputCredFile&gt;
- Note
    - While most of these fields could be edited, the user identity, ticket lifetime and flags will not be used and verified by the target (unlike ones from encrypted PACs and the unencrypted Service Principal)
    - Of course, if you know the Kerberos keys, you can forge an arbitrary Golden/Silver ticket (see Forging ticket options).
- Optional
    - User Principal in the form of &lt;User&gt;@&lt;Domain&gt;
    - Credential User Principal in the form of &lt;User&gt;@&lt;Domain&gt;
    - Credential Service Principal in the form of &lt;ServiceClass&gt;/&lt;ServerFQDN&gt;@&lt;Domain&gt;
    - Credential Start Time UTC string in the form of "&lt;Day&gt;/&lt;Month&gt;/&lt;Year&gt; &lt;Hours&gt;:&lt;Minutes&gt;:&lt;Seconds&gt; AM/PM"
    - Credential End Time UTC string in the form of "&lt;Day&gt;/&lt;Month&gt;/&lt;Year&gt; &lt;Hours&gt;:&lt;Minutes&gt;:&lt;Seconds&gt; AM/PM"
    - Credential End Renew Time UTC string in the form of "&lt;Day&gt;/&lt;Month&gt;/&lt;Year&gt; &lt;Hours&gt;:&lt;Minutes&gt;:&lt;Seconds&gt; AM/PM"
    - Commas separated list of Credential Ticket Flags from [reserved, forwardable, forwarded, proxiable, proxy, may_postdate, postdated, invalid, renewable, initial, pre_authent, hw_authent, transited_policy_checked, ok_as_delegate, enc_pa_rep, anonymous]
    - Ticket Service Principal in the form of &lt;ServiceClass&gt;/&lt;ServerFQDN&gt;@&lt;Domain&gt;

```
ADUtil KERBEROS --editFile <InputCredFile>:<OutputCredFile> [--userPrincipal <User>@<Domain>] [--credUserPrincipal <User>@<Domain>] [--credServicePrincipal <ServiceClass>/<ServerFQDN>@<Domain>] [--credStartTime "<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM"] [--credEndTime "<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM"] [--credRenewTill "<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM"] [--credFlags <Flag1>,<Flag2>,...,<FlagN>] [--ticketServicePrincipal <ServiceClass>/<ServerFQDN>@<Domain>]
```

# Forging Ticket

Forge a CCACHE ticket manually (TGT or Service Ticket).
- Requirement
    - Kerberos key to encrypt
        - TGT
            - Krbtgt Secret Key
        - Service Ticket
            - Service Secret Key
            - Client-to-TGS Session Key (for S4U2Self + U2U)
    - Username
    - Domain FQDN
    - Domain SID
- Optional
    - Service Principal Name in the form of &lt;ServiceClass&gt;/&lt;ServerFQDN&gt;@&lt;DomainFQDN&gt;. For TGT, it is not required as it will use automatically krbtgt/&lt;DomainFQDN&gt;
    - Commas separated list of groups RID user will belong to from PAC_LOGON_INFO. Default = [513, 512, 520, 518, 519]
    - User RID to forge in PAC_LOGON_INFO. Default = 500
    - Commas separated list of ExtraSids to be included inside PAC_LOGON_INFO. Default = None
    - Populate ticket with extra PAC_UPN_DNS_INFO. Default = False
    - Use the old PAC structure to create ticket (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR). Default = False
    - Ticket duration in hours. Default = 10 hours
    - Ticket renewal duration in hours. Default = 23 hours

```
ADUtil -u <Username> -d <DomainFQDN> KERBEROS --forgeTicket --hexKrbtgtSecretKey <hexKrbtgtSecretKey> --domainSID <DomainSID> [--groupsRID <GroupRID1>,<GroupRID2>,...,<GroupRIDN>] [--userRID <UserRID>] [--extraSID <ExtraSID1>,<ExtraSID2>,...,<ExtraSIDN>] [--extraPAC] [--oldPAC] [--duration <DurationHours>] [--renewDuration <RenewDurationHours>] # TGT
ADUtil -u <Username> -d <DomainFQDN> KERBEROS --forgeTicket --hexServiceSecretKey <hexServiceSecretKey>/--hexClientTGSSessionKey <hexClientTGSSessionKey> --domainSID <DomainSID> --SPN <ServiceClass>/<ServerFQDN> [--groupsRID <GroupRID1>,<GroupRID2>,...,<GroupRIDN>] [--userRID <UserRID>] [--extraSID <ExtraSID1>,<ExtraSID2>,...,<ExtraSIDN>] [--extraPAC] [--oldPAC] [--duration <DurationHours>] [--renewDuration <RenewDurationHours>] # Service Ticket
```

# Authentication Service

Request a TGT from KDC and save it as CCACHE.
- Requirement
    - KDC FQDN
    - Username
    - Domain FQDN
    - Password or NT Hash (as Kerberos Key with Encryption Type 23) or AES Key (as Kerberos Key with Encryption Type 18/17) or Certificate File (PFX/PEM) for PKINIT authentication. It can be omitted if &lt;Username&gt; does not require Kerberos Pre-Authentication: hashes will be displayed to Hashcat/John format for cracking but no CCACHE will be saved because the AS-Rep encrypted part will be impossible to decrypt in order to retrieve Client-to-TGS Session Key
- Optional
    - PFX Password for PFX Certificate File
    - PEM Private Key for PEM Certificate File
    - Add TGT to existing CCACHE

```
ADUtil -t <KDCFQDN> -u <Username> -d <DomainFQDN> [-p <Password>] [-nt <NTHash>] [-k <AESKey>] [-c <CertFile> -cp <PFXPwd> -cpk <PEMPrivKey>] KERBEROS --requestTGT [--addTGTToCCACHE <CCacheFile>]
```

# Brute force

Perform Brute Force/Pwd Spraying with provided credentials.
- Requirement
    - KDC FQDN
    - Username or file with usernames
    - Domain FQDN
- Optional
    - Password or file with passwords
    - NT Hash or file with NT Hashes
    - AES Key or file with AES Keys
    - Try Login = Password
    - Do not authenticate with PA-ENC-TIMESTAMP. Allows user enumeration only without locking accounts

```
ADUtil -t <KDCFQDN> -u <Username>/<UsernameFile> -d <DomainFQDN> [-p <Password>/<PasswordFile>] [-nt <NTHash>/<NTHashFile>] [-k <AESKey>/<AESKeyFile>] KERBEROS --doBF [--passLogin] [--noAuthenticate]
```

# Ticket Granting Service

Request a Service Ticket from KDC and save it as CCACHE.
- Requirement
    - KDC FQDN
    - Username
    - Domain FQDN
    - Password or NT Hash (as Kerberos Key with Encryption Type 23) or AES Key (as Kerberos Key with Encryption Type 18/17) or Certificate File (PFX/PEM) for PKINIT authentication or Credential File (CCACHE/Kirbi). It can be omitted if &lt;Username&gt; does not require Kerberos Pre-Authentication: hashes will be displayed to Hashcat/John format for cracking but no KRB_TGS_REQ will be send because the AS-Rep encrypted part will be impossible to decrypt in order to retrieve Client-to-TGS Session Key
    - Service Principal Name in the form of &lt;ServiceClass&gt;/&lt;ServerFQDN&gt;
- Optional
    - Add ST to existing CCACHE
    - Account to impersonate through S4U
    - Do S4U2Self (no S4U2Proxy) through S4U
    - Do User-to-User through S4U
    - Do not include PA-FOR-USER through S4U. ST will be populate with PAC_CREDENTIALS_INFO (LM/NT Hashes) if used PKINIT authentication
    - Additional ST for S4U2Proxy
    - Account to print hashes for ST (ie. Account that hold SPN)

```
ADUtil -t <KDCFQDN> -u <Username> -d <DomainFQDN> [-p <Password>] [-nt <NTHash>] [-k <AESKey>] [-c <CertFile> -cp <PFXPwd> -cpk <PEMPrivKey>] [-cc <CredFile>] KERBEROS --requestST <ServiceClass>/<ServerFQDN> [--addSTToCCACHE <CCacheFile>] [--impersonate <AccountName>] [--self] [--u2u] [--noPAForUser] [--additionalTicket <ServiceTicketFile>] [--kerberoast <AccountName>]
```