# powershell-credential-encryption-tools

### credentialEncryptor.ps1 and decryptUtil.ps1

**Simple script for AES encrypting a set of portable credentials**

**USAGE:**  
```./credentialEncryptor.ps1 -k [pathToKeyFile] -o [pathToCredFile] [-validate $true | $false]```


* Prompts for a username/password to encrypt

* If the keyFile specified via "-k" does NOT pre-exist, a new one will be generated 256bit using a secure random byte generator. If it does pre-exist it will be used. This key is usded to encrypt (AES) the credentials and builds a JSON structure as follows

    ```{ "username" : "AESEncryptedValue", "password": "AESEncryptedValue" }```

* The resulting JSON is stored in local dir named: **encrypted.credentials** (unless -o is specified explicitly)

* If the key is newly generated; the secret key's bytes are Base64 encoded and stored in the local directory in a file named: **secret.key** (unless -k is specified explicity)

* Both of the above files have their permissions changed to R/W by the Administrators group only. If the key pre-exists this will not occur

* Optionally if -validate $true/$false is passed, as a test, both of the files are read back in and used to decrypt the credentials to verify that the decryption works and the inputs match what was decrypted. Note this potentially exposes the credentials in the clear in memory.

* The resulting files can then be used by other Powershell scripts which need to load up stored credentials locally and make use of them for various purposes. It is important to note that the resulting files are **portable** and nothing about the encryption/decryption routines is bound to the security context of the local user running these commands. That noted; **the responsibility is on the you to properly secure the secret.key!**

* Also see **decryptUtil.ps1** for some useful and supporting functions, including an example of loading the JSON file of credentials into a PSCredential
