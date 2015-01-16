# powershell-credential-tools

### credentialEncryptor.ps1

**Simple script for encrypting a set of credentials**

* Prompts for a username/password to encrypt and formats the input into a JSON structure as follows:

    ```{ "username" : "value", "password": "value" }```

* Prompts for a local directory to write the output files to

* Generates a 256bit secret key via a secure random byte generator, and encrypts the JSON structure with this key via ConvertFrom-SecureString (which uses AES)

* The resulting encrypted bytes are stored in the output directory as in a file named: **encrypted.credentials**

* The secret key's bytes are Base64 encoded and stored in the output directory in a file named: **secret.key**

* Both of the above files have their permissions changed to R/W by the local *Administrators* group only.

* As a test, both of the files are read back in and used to decrypt the credentials to verify that the decryption works 

* The resulting files can then be used by other Powershell scripts which need to load up stored credentials locally and make use of them for various purposes. The onus is on the **you** to properly secure the **secret.key**!

