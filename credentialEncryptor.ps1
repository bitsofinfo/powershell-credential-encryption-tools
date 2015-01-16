#############################################
# credentialEncryptor.ps1 [-validate $true|$false]
# - Tool for encrypting a set of credentials
# 
# a) Prompts for a username/password to encrypt
#    and the directory to write to
#
# b) Generates a 256bit secret key via a secure 
#    random byte generator, and encrypts (AES) 
#    the credentials and builds a JSON structure as follows
#
#    { "username" : "AESEncryptedValue", "password": "AESEncryptedValue" }
#
# c) The resulting JSON is stored in output dir
#    named: encrypted.credentials
#
# d) The secret key's bytes are Base64 encoded
#    and stored in the output directory 
#    in a file named: secret.key
#
# f) Both of the above files have their permissions
#    changed to R/W by the Administrators group 
#    only.
#
# g) Optionally if -validate $true/$false is passed
#    As a test, both of the files are read back 
#    in and used to decrypt the credentials
#    to verify that the decryption works and the
#    inputs match what was decrypted. Note this
#    potentially exposes the credentials in the
#    clear in memory. 
#
#############################################

# If -validate $true, the encryption will be validated
# by reading back in the encrypted values and generated
# key and decrypting the data to cleartext and ensuring
# it matches what the user entered to validate the routine
param([bool]$validate=$false)

# include
. "./decryptUtil.ps1"

# Collect inputs
$usernameSecureString = Read-Host "username to encrypt" -AsSecureString
$passwordSecureString = Read-Host "password to encrypt" -AsSecureString
$outputPath = Read-Host "Enter full path for output files"

$credentialsFile = "encrypted.credentials"
$keyFile = "secret.key"

# Generate a 32byte key, we will use this key to encrypt the uname/password within
# the JSON file
$secureRandom = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
$rawKeyBytes = New-Object byte[](32)
$secureRandom.GetBytes($rawKeyBytes)

# Convert the key bytes to a unicode string -> SecureString
$keyBytesUnicode = [System.Text.Encoding]::Unicode.GetString($rawKeyBytes)
$keyAsSecureString = ConvertTo-SecureString -String $keyBytesUnicode -AsPlainText -Force

# Now convert the username/pw SecureStrings -> AES encrypted versions using the key generated above
$encryptedUsername = ConvertFrom-SecureString -SecureString $usernameSecureString -SecureKey $keyAsSecureString
$encryptedPassword = ConvertFrom-SecureString -SecureString $passwordSecureString -SecureKey $keyAsSecureString

# Convert to a credentials structure, -> JSON -> JSON as SecureString
$credentialsObj = [PSCustomObject]@{username = $encryptedUsername;password = $encryptedPassword}
$jsonCredentials = ConvertTo-JSON $credentialsObj

# Write the encrypted JSON credentials to disk
$jsonCredentials | Out-File -Encoding UTF8 -FilePath $outputPath\$credentialsFile

# Write the key out to disk
[Convert]::ToBase64String($rawKeyBytes) | Out-File -Encoding UTF8 -FilePath $outputPath\$keyFile



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

$aclPermissions = [System.Security.AccessControl.FileSystemRights]"FullControl"
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


if ($validate) {
    ##################################
    # Validate
    ##################################
    $usernameSecureString2 = decrypt2SecureString $outputPath\$credentialsFile $outputPath\$keyFile 'username'
    $passwordSecureString2 = decrypt2SecureString $outputPath\$credentialsFile $outputPath\$keyFile 'password'

    # what was entered via the prompt
    $usernameClear = secureString2Cleartext $usernameSecureString
    $passwordClear = secureString2Cleartext $passwordSecureString

    # what was decrypted...
    $usernameClear2 = secureString2Cleartext $usernameSecureString2
    $passwordClear2 = secureString2Cleartext $passwordSecureString2


    # compare decrypted to what we wrote... ok?
    if ($usernameClear -eq $usernameClear2 -and $passwordClear -eq $passwordClear2) {
        Write-Output ""
        Write-Output ""
        Write-Output "******************************************"
        Write-Output "Validated OK! (you should term this session)"
        Write-Output "******************************************"
        Write-Output ""
        Write-Output ""

    } else {
        Write-Output ""
        Write-Error "Validation Failure"
        Write-Output ""
    }

}

Write-Output ""
Write-Output ""
Write-Output "******************************************"
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


Remove-Variable * -ErrorAction SilentlyContinue
