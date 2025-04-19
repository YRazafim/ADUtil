# Disclaimer

This tool has been developped
- To understand Active Directory exploitation techniques at low-level
- To provide core features with limited dependencies
- To organize each exploitation technique independently without following tons of cross-references
- Because I was not satisfy with the existing toolings
    - Multitude of tools
    - Does not works always well together

Implemented techniques are well-known. I tried to include references to the original projects and authors in the code and to explain each technique as much as possible.

# Table of contents

- [Installation](#installation)
- [Usage](#usage)
    - [KERBEROS](Utils/KERBEROS)
    - [NTLM](Utils/NTLM)
    - [LDAP](Utils/LDAP)
    - [RPC](Utils/RPC)
    - [SMB](Utils/SMB)
    - [MSSQL](Utils/MSSQL)
    - [HTTP](Utils/HTTP)
    - [RDP](Utils/RDP)

# Installation

```
./install.sh
```

# Usage

```
ADUtil -h
ADUtil KERBEROS -h
ADUtil NTLM -h
ADUtil LDAP -h
ADUtil RPC -h
ADUtil SMB -h
ADUtil MSSQL -h
ADUtil HTTP -h
ADUtil RDP -h
```
