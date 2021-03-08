
# NOTE The below enumeration is on loan from:
# http://www.digipine.com/index.php?mid=windowsmfc&document_srl=208
# Modified a little bit to match:
# https://docs.microsoft.com/en-US/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties

# Usage, for example:
# [AdsUserFlags]530
# returns:
# AccountDisabled, AccountLockedOut, NormalAccount
[Flags()]
Enum AdsUserFlags
{
    Script = 1 # 0x1
    AccountDisabled = 2 # 0x2
    HomeDirectoryRequired = 8 # 0x8
    AccountLockedOut = 16 # 0x10
    PasswordNotRequired = 32 # 0x20
    PasswordCannotChange = 64 # 0x40
    EncryptedTextPasswordAllowed = 128 # 0x80
    TempDuplicateAccount = 256 # 0x100
    NormalAccount = 512 # 0x200
    InterDomainTrustAccount = 2048 # 0x800
    WorkstationTrustAccount = 4096 # 0x1000
    ServerTrustAccount = 8192 # 0x2000
    PasswordDoesNotExpire = 65536 # 0x10000
    MnsLogonAccount = 131072 # 0x20000
    SmartCardRequired = 262144 # 0x40000
    TrustedForDelegation = 524288 # 0x80000
    AccountNotDelegated = 1048576 # 0x100000
    UseDesKeyOnly = 2097152 # 0x200000
    DontRequirePreauth = 4194304 # 0x400000
    PasswordExpired = 8388608 # 0x800000
    TrustedToAuthenticateForDelegation = 16777216 # 0x1000000
    PartialSecretsAccount = 67108864 # 0x04000000
}

$adsUserFlagsMap = @{
    Script = 1
    AccountDisabled = 2
    HomeDirectoryRequired = 8
    AccountLockedOut = 16
    PasswordNotRequired = 32
    PasswordCannotChange = 64
    EncryptedTextPasswordAllowed = 128
    TempDuplicateAccount = 256
    NormalAccount = 512
    InterDomainTrustAccount = 2048
    WorkstationTrustAccount = 4096
    ServerTrustAccount = 8192
    PasswordDoesNotExpire = 65536
    MnsLogonAccount = 131072
    SmartCardRequired = 262144
    TrustedForDelegation = 524288
    AccountNotDelegated = 1048576
    UseDesKeyOnly = 2097152
    DontRequirePreauth = 4194304
    PasswordExpired = 8388608
    TrustedToAuthenticateForDelegation = 16777216
    NoAuthDataRequired = 33554432
}

function Get-RandomString
{
    Param(
        [Parameter(Mandatory=$false)][Int]$Length = 16
    )
    # Basic idea largely stolen from:
    # https://devblogs.microsoft.com/scripting/generate-random-letters-with-powershell/
    $letterRange = (65..90) + (97..122)
    $specialCharacters = '!@#$%^&*()_+=-<>/\' -split '' | Where-Object { $_ }
    $charArray = 1..$Length | ForEach-Object {
        switch (Get-Random -Maximum 3) {
            0 {
                [char]($letterRange | Get-Random)
            }
            1 {
                $specialCharacters | Get-Random
            }
            2 {
                Get-Random -Maximum 9
            }
        }
    }
    $charArray -join ''
}

function ConvertTo-CanonicalName
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$DistinguishedName
    )
    foreach ($dn in $DistinguishedName) {
        $tmp = $dn -split ','
        $cnList = ($tmp | Where-Object { $_ -match '^cn=' }) -replace '^cn='
        $ouList = ($tmp | Where-Object { $_ -match '^ou=' }) -replace '^ou='
        $dcList = ($tmp | Where-Object { $_ -match '^dc=' }) -replace '^dc='
        $CanonicalName = "$($dcList -join '.')/"
        if ($ouList -is [String]) {
            $CanonicalName += $ouList
        } else {
            $CanonicalName += $ouList[($ouList.Count + 1)..0] -join '/'
        }
        if ($cnList.Count -eq 1) {
            $CanonicalName += "/$($cnList)"
        } elseif ($cnList.Count -gt 1) {
            $CanonicalName += $cnList[($cnList.Count + 1)..0] -join '/'
        }
        if ($CanonicalName -match '/$') {
            $CanonicalName = $CanonicalName -replace '/$'
        }
        $CanonicalName
    }
}

function ConvertTo-DistinguishedName
{
    param(
        [parameter(mandatory=$false)][String[]]$CanonicalName,
        [parameter(mandatory=$false)]
        [validateset('OU', 'CN', 'None')]
        [String]$LeafAttribute = 'CN'
    )
    foreach ($cn in $CanonicalName) {
        $domain, $path = $cn -split '/'
        $domain = $domain -split '\.'
        $domain = ",DC=$($domain -join ',DC=')"
        [Array]::Reverse($path)
        if ($LeafAttribute -eq 'None') {
            $path = $path -join ',OU='
        } else {
            $path = "$LeafAttribute=$($path -join ',OU=')"
        }
        "$path$domain"
    }
}

function ConvertFrom-UserAccountControlInteger
{
    Param(
        [Parameter(Mandatory=$true)][Int]$UserAccountControlInteger
    )
    return ([AdsUserFlags] $UserAccountControlInteger) -split ', '
}

function ConvertTo-UserAccountControlInteger
{
    Param(
        [Parameter(Mandatory=$true)][String[]]$UserAccountControlFlag
    )
    $userAccountControlInteger = 0
    foreach ($uACFlag in $UserAccountControlFlag) {
        $userAccountControlInteger += $adsUserFlagsMap[$uACFlag]
    }
    return $userAccountControlInteger
}
