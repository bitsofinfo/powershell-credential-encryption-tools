#############################################
# USAGE:
# credentialEncryptor.ps1 -k [pathToKeyFile] -o [pathToCredFile] [-validate $true|$false]
#
# a) Prompts for a username/password to encrypt
#
# b) If the keyFile specified via "-k" does NOT
#    pre-exist, a new one will be generated 256bit
#    using a secure random byte generator. If it does
#    pre-exist it will be used. This key is usded to encrypt (AES)
#    the credentials and builds a JSON structure as follows
#
#    { "username" : "AESEncryptedValue", "password": "AESEncryptedValue" }
#
# c) The resulting JSON is stored in local dir
#    named: ./encrypted.credentials (unless -o is specified)
#
# d) If the key is newly generated; the secret key's
#    bytes are Base64 encoded and stored in the local directory
#    in a file named: ./secret.key (unless -k is specified)
#
# f) Both of the above files have their permissions
#    changed to R/W by the Administrators group
#    only. If the key pre-exists this will not occur
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
param([string]$k='secret.key',
      [string]$o='encrypted.credentials',
      [bool]$validate=$false)

$keyFile = $k
$credentialsFile = $o

# include
. "./decryptUtil.ps1"

# Collect inputs
$usernameSecureString = Read-Host "username to encrypt" -AsSecureString
$passwordSecureString = Read-Host "password to encrypt" -AsSecureString

$keyAsSecureString = $null
$keyFileGenerated = $false

# if the keyFile pre-exists, lets just use that
if (Test-Path $keyFile) {

  $keyAsSecureString = loadKeyFile2SecureString $keyFile

# No preexisting key exists, generate one....
} else {

    # Generate a 32byte key, we will use this key to encrypt the uname/password within
    # the JSON file
    $secureRandom = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $rawKeyBytes = New-Object byte[](32)
    $secureRandom.GetBytes($rawKeyBytes)

    # Write the key out to disk
    [Convert]::ToBase64String($rawKeyBytes) | Out-File -Encoding UTF8 -FilePath $keyFile

    Write-Output "No keyfile pre-exists, generated one at: $keyFile"

    # Convert the key bytes to a unicode string -> SecureString
    $keyBytesUnicode = [System.Text.Encoding]::Unicode.GetString($rawKeyBytes)
    $keyAsSecureString = ConvertTo-SecureString -String $keyBytesUnicode -AsPlainText -Force

    $keyFileGenerated = $true
}

# Now convert the username/pw SecureStrings -> AES encrypted versions using the key generated above
$encryptedUsername = ConvertFrom-SecureString -SecureString $usernameSecureString -SecureKey $keyAsSecureString
$encryptedPassword = ConvertFrom-SecureString -SecureString $passwordSecureString -SecureKey $keyAsSecureString

# Convert to a credentials structure, -> JSON -> JSON as SecureString
$credentialsObj = [PSCustomObject]@{username = $encryptedUsername;password = $encryptedPassword}
$jsonCredentials = ConvertTo-JSON $credentialsObj

# Write the encrypted JSON credentials to disk
$jsonCredentials | Out-File -Encoding UTF8 -FilePath $credentialsFile




##################################################
# Files written to disk
# lets now alter the permissions on these
# files so only administrators can access them
# as a precaution (only change keyFile if we generated it)
##################################################
$credentialsACL = Get-Acl $credentialsFile
$keyACL = Get-Acl $keyFile

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
$credentialsACL.AddAccessRule($aclObject)
Set-Acl -Path $credentialsFile -AclObject $credentialsACL

if ($keyFileGenerated) {
    $keyACL.Access | ?{ $_.IdentityReference -Like "*" } |%{
      $keyACL.RemoveAccessRuleSpecific($_)
    }
    $keyACL.AddAccessRule($aclObject)

    Set-Acl -Path $keyFile -AclObject $keyACL
}



if ($validate) {
    ##################################
    # Validate
    ##################################
    $usernameSecureString2 = decrypt2SecureString $credentialsFile $keyFile 'username'
    $passwordSecureString2 = decrypt2SecureString $credentialsFile $keyFile 'password'

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
Write-Output "Output files written:"

if ($keyFileGenerated) {
    Write-Output "New key was file generated..."
}

Write-Output ""
Write-Output "Encrypted credentials file: $credentialsFile"
Write-Output "Key file: $keyFile"
Write-Output ""
Write-Output "IMPORTANT: KEY FILE MUST BE SECURED!"
Write-Output "(Permissions auto-set to Administrators only)"
Write-Output "******************************************"
Write-Output ""
Write-Output ""


Remove-Variable * -ErrorAction SilentlyContinue
