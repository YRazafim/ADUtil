# LM/NT Hashes

## Encode password

Hex UTF-16LE encode provided password.

```
ADUtil NTLM --encodePwd <Password>
```

## LM/NT Hashes

Compute LM/NT Hashes from hex UTF-16LE encoded password.

```
ADUtil NTLM --computeHash <HexUTF16LEPwd>
ADUtil NTLM --computeHash '' # Empty password
```

# NTLM Responses

## NTLMv1 Response

Compute LMv1/NTLMv1 Response for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security).
- Requirement
    - Clear-text password
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)

```
ADUtil -p <Password> NTLM --NTLMv1Response --hexServerChallenge <HexServerChallenge>
```

## NTLMv2 Response

Compute LMv2/NTLMv2 Response for NTLMv2 authentication protocol.
- Requirement
    - Clear-text password
    - Username (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->User name`)
    - Domain FQDN (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->Domain name`)
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)
    - Hex-encoded Client Challenge (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->NTLMv2 Client Challenge`)
    - Hex-encoded Target Info (from `Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Attribute: NetBIOS domain name` to `Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Attribute: End of list`)
    - Hex-encoded Timestamp (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Time`)

```
ADUtil -p <Password> -u <Username> -d <DomainFQD> NTLM --NTLMv2Response --hexServerChallenge <HexServerChallenge> --hexClientChallenge <HexClientChallenge> --hexTargetInfo <HexTargetInfo> --hexTimestamp <HexTimestamp>
```

## NTLMv2 Session Response

Compute NTLMv2 Session Response for NTLMv1 authentication protocol with NTLMv2 Session Security (Extended Session Security).
- Requirement
    - Clear-text password
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)
    - Hex-encoded Client Challenge (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->Lan Manager Reponse->LMv2 Client Challenge`)

```
ADUtil -p <Password> NTLM --NTLMv2SessionResponse --hexServerChallenge <HexServerChallenge> --hexClientChallenge <HexClientChallenge>
```

## Anonymous Response

Compute Anonymous Response for NTLM authentication protocol with anonymous context (No account associated, different than `guest` user).

```
ADUtil NTLM --anonymousResponse
```

## MIC

Compute MIC of message &lt;HexNTLMSSP_NEGOTIATE&gt;:&lt;HexNTLMSSP_CHALLENGE&gt;:&lt;HexNTLMSSP_AUTH&gt; for NTLMv2 authentication protocol.
- Requirement
    - Hex-encoded Master Key 2
- Note
    - MIC field of NTLMSSP_AUTH must be replaced with '0'*32

```
ADUtil NTLM --MIC <MIC> --hexMasterKey2 <HexMasterKey2>
```

# Signing and Sealing

## User Session Key

Derived from account's password and used to retrieve Master Key 1 and Master Key 2.

## Lan Manager User Session Key

Compute Lan Manager User Session Key for NTLMv1 authentication protocol with `Negotiate Lan Manager Key` flag negotiated.
- Requirement
    - Clear-text password
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)

```
ADUtil -p <Password> NTLM --LanManagerUserSessionKey --hexServerChallenge <HexServerChallenge>
```

## LMv1 User Session Key

Compute LMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security).
- Requirement
    - Clear-text password

```
ADUtil -p <Password> NTLM --LMv1UserSessionKey
```

## NTLMv1 User Session Key

Compute NTLMv1 User Session Key for NTLMv1 authentication protocol without NTLMv2 Session Security (Extended Session Security).
- Requirement
    - Clear-text password

```
ADUtil -p <Password> NTLM --NTLMv1UserSessionKey
```

## LMv2 User Session Key

Compute LMv2 User Session Key for NTLMv2 authentication protocol.
- Requirement
    - Clear-text password
    - Username (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->User name`)
    - Domain FQDN (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->Domain name`)
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)
    - Hex-encoded Client Challenge (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->NTLMv2 Client Challenge`)

```
ADUtil -p <Password> -u <Username> -d <DomainFQDN> NTLM --LMv2UserSessionKey --hexServerChallenge <HexServerChallenge> --hexClientChallenge <HexClientChallenge>
```

## NTLMv2 User Session Key

Compute NTLMv2 User Session Key for NTLMv2 authentication protocol.
- Requirement
    - Clear-text password
    - Username (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->User name`)
    - Domain FQDN (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->Domain name`)
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)
    - Hex-encoded Client Challenge (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->NTLMv2 Client Challenge`)
    - Hex-encoded Target Info (from `Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Attribute: NetBIOS domain name` to `Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Attribute: End of list`)
    - Hex-encoded Timestamp (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Response->NTLMv2 Response->Time`)

```
ADUtil -p <Password> -u <Username> -d <DomainFQDN> NTLM --NTLMv2UserSessionKey --hexServerChallenge <HexServerChallenge> --hexClientChallenge <HexClientChallenge> --hexTargetInfo <HexTargetInfo> --hexTimestamp <HexTimestamp>
```

## NTLMv2 Session User Session Key

Compute NTLMv2Session User Session Key for NTLMv1 authentication with NTLMv2 Session Security (Extended Session Security).
- Requirement
    - Clear-text password
    - Hex-encoded Server Challenge (`Session Setup Response:NTLMSSP_CHALLENGE->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->NTLM Server Challenge`)
    - Hex-encoded Client Challenge (`Session Setup Request:NTLMSSP_AUTH->Security Blob->GSS-API->Simple Protected Negotiation->negTokenTarg->NTLM Secure Service Provider->Lan Manager Reponse->LMv2 Client Challenge`)

```
ADUtil -p <Password> NTLM --NTLMv2SessionUserSessionKey --hexServerChallenge <HexServerChallenge> --hexClientChallenge <HexClientChallenge>
```

## Null User Session Key

Compute Null User Session Key for NTLM authentication protocol with anonymous context (No account associated, different than `guest` user).

```
ADUtil NTLM --nullUserSessionKey
```

## Secondary Key

Secondary Key (Session Key) encrypted to decrypt when `Negotiate Key Exchange` flag negotiated.
- Requirement
    - Hex-encoded Master Key 1 (User Session Key or Lan Manager User Session Key if `Negotiate Lan Manager Key` negotiated for NTLMv1 authentication)

```
ADUtil NTLM --secondaryKeyEnc <HexSecondaryKeyEnc> --hexMasterKey1 <HexMasterKey1>
```

## Final Key

Compute Final Key(s) for Signing and Sealing with NTLMv1/v2 Session Security.
- Requirement
    - Hex-encoded Master Key 2 (Master Key 1 or Secondary Key if `Negotiate Key Exchange` flag negotiated)

```
ADUtil NTLM --finalKeys --hexMasterKey2 <HexMasterKey2>
```

## Signing and Sealing

## NTLMv1

Compute NTLMv1 Signing and Sealing from hex-encoded message.
- Requirement
    - Hex-encoded Final Key

```
ADUtil NTLM --signSealNTLMv1 <HexMessage> --hexFinalKey <HexFinalKey>
```

## NTLMv2

Compute NTLMv1 Signing and Sealing from hex-encoded message.
- Requirement
    - Hex-encoded Signing Key
    - Hex-encoded Sealing Key
- Optional
    - Set `Negotiate Key Exchange` flag for Signing and Sealing

```
ADUtil NTLM --signSealNTLMv2 <HexMessage> --hexSigningKey <HexSigningKey> --hexSealingKey <HexSealingKey> [--negKeyExchangeFlag]
```

# SMB Signing

## SMB Key Derivation

Derive hex-encoded Client-to-Service Session Key (as MasterKey2) for SMB Signing
- Requirement
    - SMB Dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1)
    - Previous SMB messages in the form of &lt;HexSMBHeader+NegotiateProtocolRequest&gt;:&lt;HexSMBHeader+NegotiateProtocolResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt;:&lt;HexSMBHeader+SessionSetupResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt; for SMB Dialect = 3.1.1

```
ADUtil NTLM --deriveKeySMB <HexMasterKey2> --dialectSMB <SMBDialect> [--hexPrevSMBPackets <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>]
```

## SMB Signing

Sign an hex-encoded SMB packet &lt;HexSMBHeader+SMBMessage&gt;.
- Requirement
    - Hex-encoded Master Key 2 (Master Key 1 or Secondary Key if `Negotiate Key Exchange` flag negotiated)
    - SMB Dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1)
    - Previous SMB messages in the form of &lt;HexSMBHeader+NegotiateProtocolRequest&gt;:&lt;HexSMBHeader+NegotiateProtocolResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt;:&lt;HexSMBHeader+SessionSetupResponse&gt;:&lt;HexSMBHeader+SessionSetupRequest&gt; for SMB Dialect = 3.1.1
- Note
    - Signature field must be replaced with '0'*32 from &lt;HexSMBHeader+SMBMessage&gt;

```
ADUtil NTLM --signPacketSMB <HexSMBHeader+SMBMessage> --hexMasterKey2 <HexMasterKey2> --dialectSMB <SMBDialect> [--hexPrevSMBPackets <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>]
```