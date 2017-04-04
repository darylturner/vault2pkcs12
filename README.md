# vault2pkcs12
Parse JSON output from Hashicorp Vault PKI backend and export to PKCS12 for import to Windows.

```
.\getvaultcert.exe -token 39a1b46e-485e-79b2-35ae-c611def2c73c |`
    .\vault2pkcs12.exe -password secretsquirrel -out c:\users\daryl\desktop\certs.pfx
```
