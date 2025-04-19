from setuptools import setup, find_packages

def parse_requirements(filename):
    with open(filename, 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name = 'ADUtil',
    version = '0.1',
    py_modules = ['ADUtil', 'Utils.Errors.ErrorsUtil', 'Utils.SPNEGO.SPNEGOUtil', 'Utils.KERBEROS.KerberosUtil', 'Utils.NTLM.NTLMUtil', 'Utils.LDAP.LDAPUtil', 'Utils.MSSQL.MSSQLUtil', 'Utils.RDP.RDPUtil', 'Utils.RPC.RPCUtil', 'Utils.SMB.SMBUtil', 'Utils.HTTP.HTTPUtil'],
    install_requires = parse_requirements('requirements.txt'),
    entry_points = {
        'console_scripts': [
            'ADUtil = ADUtil:main',
        ],
    },
)
