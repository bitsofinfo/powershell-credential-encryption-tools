# convert from SecureStrings to plain-text... for compare
function secureString2Cleartext($secureString) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    $clear = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) # zero memory
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
    return ConvertTo-SecureString -String $propertyEncrypted -SecureKey $keyAsSecureString

}

# For testing...
#$asSecureString = decrypt2SecureString 'encrypted.credentials' 'secret.key' 'password'
#$asCleartext = secureString2ClearText $asSecureString
#Write-Output $asCleartext
