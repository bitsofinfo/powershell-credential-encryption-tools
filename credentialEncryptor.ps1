#############################################
# credentialEncryptor.ps1
# - Tool for encrypting a set of credentials
# 
# a) Prompts for a username/password to encrypt
#    and formats the input into a JSON structure
#    as follows:
#
#    { "username" : "value", "password": "value" }
#
# b) Prompts for a directory to write the output to
#
# c) Generates a 256bit secret key via a secure 
#    random byte generator, and encrypts the JSON
#    structure with this key via ConvertFrom-SecureString
#    which does so via AES
#
# d) The resulting encrypted bytes are stored 
#    in the output directory as in a file 
#    named: encrypted.credentials
#
# e) The secret key's bytes are Base64 encoded
#    and stored in the output
#    directory in a file named: secret.key
#
# f) Both of the above files have their permissions
#    changed to R/W by the Administrators group 
#    only.
#
# g) As a test, both of the files are read back 
#    in and used to decrypt the credentials
#    to verify that the decryption works 
#
#############################################

# Collect inputs
$username = Read-Host "username to encrypt"
$password = Read-Host "password to encrypt"
$outputPath = Read-Host "Enter full path for output files"

$credentialsFile = "encrypted.credentials"
$keyFile = "secret.key"

# Convert to a credentials structure, -> JSON -> JSON as SecureString
$credentialsObj = [PSCustomObject]@{username = $username;password = $password}
$jsonCredentials = ConvertTo-JSON $credentialsObj
$jsonCredsAsSecureString = ConvertTo-SecureString -String $jsonCredentials -AsPlainText -Force

# clear out the temp variables
Remove-Variable username
Remove-Variable password

# Generate a 32byte key, we will use this key to encrypt the JSON
$secureRandom = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rawKeyBytes = New-Object byte[](32)
$secureRandom.GetBytes($rawKeyBytes)

# Convert the key bytes to a unicode string -> SecureString
$keyBytesUnicode = [System.Text.Encoding]::Unicode.GetString($rawKeyBytes)
$keyAsSecureString = ConvertTo-SecureString -String $keyBytesUnicode -AsPlainText -Force

# Now convert the jsonCredsAsSecureString -> AES encrypted version using the key generated above
$encryptedJSONCredentials = ConvertFrom-SecureString -SecureString $jsonCredsAsSecureString -SecureKey $keyAsSecureString

# Write the encrypted JSON credentials to disk
$encryptedJSONCredentials | Out-File -Encoding UTF8 -FilePath $outputPath\$credentialsFile

# Write the key out to disk
[Convert]::ToBase64String($rawKeyBytes) | Out-File -Encoding UTF8 -FilePath $outputPath\$keyFile


Remove-Variable jsonCredsAsSecureString
Remove-Variable rawKeyBytes
Remove-Variable keyBytesUnicode
Remove-Variable keyAsSecureString
Remove-Variable encryptedJSONCredentials


##################################################
# Files written to disk
# lets now alter the permissions on these
# files so only administrators can access them
# as a precaution
##################################################
$credentialsACL = Get-Acl $outputPath\$credentialsFile
$keyACL = Get-Acl $outputPath\$keyFile

$credentialsACL.SetAccessRuleProtection($true,$false)
$keyACL.SetAccessRuleProtection($true,$false)

$aclPermissions = [System.Security.AccessControl.FileSystemRights]"Read","Write"
$aclInheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
$aclPropogationFlags = [System.Security.AccessControl.PropagationFlags]::None
$aclType = [System.Security.AccessControl.AccessControlType]::Allow
$aclUser = New-Object System.Security.Principal.NTAccount("Administrators")

$aclObject = New-Object System.Security.AccessControl.FileSystemAccessRule `
  ($aclUser, $aclPermissions, $aclInheritanceFlags, $aclPropogationFlags, $aclType)


$credentialsACL.Access | ?{ $_.IdentityReference -Like "*" } |%{
  $credentialsACL.RemoveAccessRuleSpecific($_)
}

$keyACL.Access | ?{ $_.IdentityReference -Like "*" } |%{
  $keyACL.RemoveAccessRuleSpecific($_)
}

$credentialsACL.AddAccessRule($aclObject)
$keyACL.AddAccessRule($aclObject)

Set-Acl -Path $outputPath\$credentialsFile -AclObject $credentialsACL
Set-Acl -Path $outputPath\$keyFile -AclObject $keyACL

##################################
# part 2... VALIDATE,
# load up key + encrypted
##################################
$keyAsB64 = get-content $outputPath\$keyFile
$encryptedJSONCredentials2 = get-content $outputPath\$credentialsFile

# convert key from b64 to bytes -> unicode -> secure string
$rawKeyBytes2 = [Convert]::FromBase64String($keyAsB64)
$keyBytesUnicode2 = [System.Text.Encoding]::Unicode.GetString($rawKeyBytes2)
$keyAsSecureString2 = ConvertTo-SecureString -String $keyBytesUnicode2 -AsPlainText -Force

# decrypt to a SecureString
$jsonCredsAsSecureString = ConvertTo-SecureString -String $encryptedJSONCredentials2 -SecureKey $keyAsSecureString2

# convert from SecureString to plain-text... for compare
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($jsonCredsAsSecureString)
$jsonCredentials2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) # zero memory


# compare decrypted to what we wrote... ok?
if ($jsonCredentials -eq $jsonCredentials2) {
    Write-Output ""
    Write-Output ""
    Write-Output "******************************************"
    Write-Output "Validated OK!"
    Write-Output "Output files written to: $outputPath"
    Write-Output ""
    Write-Output "Encrypted credentials file: $outputPath\$credentialsFile"
    Write-Output "Key file: $outputPath\$keyFile"
    Write-Output ""
    Write-Output "IMPORTANT: KEY FILE MUST BE SECURED!"
    Write-Output "(Permissions auto-set to Administrators only)"
    Write-Output "******************************************"
    Write-Output ""
    Write-Output ""

} else {
    Write-Output ""
    Write-Error "Validation Failure"
    Write-Output ""
}

Remove-Variable * -ErrorAction SilentlyContinue
