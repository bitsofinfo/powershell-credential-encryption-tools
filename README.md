# powershell-credential-encryption-tools

### credentialEncryptor.ps1 and decryptUtil.ps1

**Simple script for AES encrypting a set of portable credentials**

**USAGE:** ```./credentialEncryptor.ps1 [-validate $true | $false]```

* Prompts for a username/password to encrypt and the directory to write to

* Generates a 256bit secret key via a secure random byte generator, and encrypts (AES) the credentials into a JSON structure as follows

    ```{ "username" : "AESEncryptedValue", "password": "AESEncryptedValue" }```

* The resulting JSON is stored in output dir named: **encrypted.credentials**

* The secret key's bytes are Base64 encoded and stored in the output directory in a file named: **secret.key**

* Both of the above files have their permissions changed to "Full Control" by the Administrators group only.

* Optionally if -validate $true/$false is passed; as a test, both of the files are read back in and used to decrypt the credentials to verify that the decryption works and the inputs match what was decrypted. Note this potentially exposes the credentials in the clear in memory. 

* The resulting files can then be used by other Powershell scripts which need to load up stored credentials locally and make use of them for various purposes. It is important to note that the resulting files are **portable** and nothing about the encryption/decryption routines is bound to the security context of the local user running these commands. That noted; **the responsibility is on the you to properly secure the secret.key!**

* Also see **decryptUtil.ps1** for some useful and supporting functions, including an example of loading the JSON file of credentials into a PSCredential
