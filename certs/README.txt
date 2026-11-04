SAMAUDIT – folder for your own certificates
===========================================

TIP: The easiest way is to upload the certificate in the web interface:
"Connection" -> "Upload your own certificate". It becomes active immediately, without a
restart, and takes precedence over this folder.

Alternatively (without the web interface) put the file(s) into this folder and restart:

    docker compose restart

SAMAUDIT detects automatically:

  A) PFX/PKCS#12 file (e.g. exported from a Windows certification authority)
       web.pfx                      -> in .env:  TLS_PFX_PASSWORD=YourPassword

  B) certificate + private key (PEM or DER)
       samaudit.crt  (or .cer / .pem)
       samaudit.key                 -> encrypted? in .env: TLS_KEY_PASSWORD=...

If the folder holds several certificates, the one matching a key is used.
With several PFX files, name the right one in .env: TLS_PFX=web.pfx
(or TLS_CERT=file.crt and TLS_KEY=file.key).

The result is shown under "Connection" in the web interface (issuer, expiry date,
warnings) and in the log:  docker logs samaudit 2>&1 | grep -iE 'certificate|zertifikat'
If your certificate cannot be used (wrong password, key does not match), SAMAUDIT keeps
running with the self-signed certificate and shows the reason there.

Important:
  - The certificate must contain the name used to open SAMAUDIT
    (e.g. samaudit.firma.local) – set PUBLIC_HOSTNAME in .env to the same name.
  - After a renewal, replace the files and run "docker compose restart".
  - A certificate uploaded via the web interface takes precedence; it can also be
    removed there.
  - The files do not need to be readable by others on the host (chmod 600 is enough);
    SAMAUDIT reads them once with root rights at start-up and works with an in-memory copy.

CA certificate for LDAP_CERT_MODE=verify (optional):
    put ca.pem here and set in .env:  LDAP_CERT_MODE=verify  and  LDAP_CA_FILE=ca.pem

These files are excluded from the repository by .gitignore.
