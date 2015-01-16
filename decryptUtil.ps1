# convert from SecureStrings to plain-text... for compare
function secureString2Cleartext($secureString) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $clear = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) # zero memory

    Remove-Variable bstr

    return $clear
}

# Decrypt the named property from the jsonCredentialFile using b64KeyFile
# all file variables are expected to be legit paths to the respective files
function decrypt2SecureString($jsonCredentialFile, $b64KeyFile, $property) {

    $keyAsB64 = get-content $b64KeyFile
    $jsonCredentials = get-content $jsonCredentialFile | Out-String

    $credentialObj = ConvertFrom-JSON -InputObject $jsonCredentials

    $propertyEncrypted = $credentialObj."$property"

    # convert key from b64 to bytes -> unicode -> secure string
    $rawKeyBytes = [Convert]::FromBase64String($keyAsB64)
    $keyBytesUnicode = [System.Text.Encoding]::Unicode.GetString($rawKeyBytes)
    $keyAsSecureString = ConvertTo-SecureString -String $keyBytesUnicode -AsPlainText -Force

    # decrypt to a SecureStrings
    $secureString = ConvertTo-SecureString -String $propertyEncrypted -SecureKey $keyAsSecureString


    Remove-Variable keyAsB64
    Remove-Variable jsonCredentials
    Remove-Variable credentialObj
    Remove-Variable propertyEncrypted
    Remove-Variable rawKeyBytes
    Remove-Variable keyBytesUnicode
    Remove-Variable keyAsSecureString

    return $secureString

}

# Decrypt the credentials from the jsonCredentialFile using b64KeyFile
# all file variables are expected to be legit paths to the respective files
# This *assumes* that 2 properties exist in the JSON file that are encrypted
# that of 'username' and 'password'. This will return a usable PSCredential
# object that can be used
function decrypt2PSCredential($jsonCredentialFile, $b64KeyFile) {

    $passwordSecureString = decrypt2SecureString $jsonCredentialFile $b64KeyFile 'password'
    $usernameSecureString = decrypt2SecureString $jsonCredentialFile $b64KeyFile 'username'
    $usernameClearText = secureString2Cleartext $usernameSecureString
    $psCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $usernameClearText,$passwordSecureString

    Remove-Variable passwordSecureString
    Remove-Variable usernameSecureString
    Remove-Variable usernameClearText

    return $psCredential
}



# For testing...
#$asSecureString = decrypt2SecureString 'encrypted.credentials' 'secret.key' 'password'
#$asCleartext = secureString2ClearText $asSecureString
#Write-Output $asCleartext
#Write-Output (decrypt2PSCredential 'encrypted.credentials' 'secret.key')
