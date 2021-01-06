
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

$configFile = "$PSScriptRoot\PortableADTools.xml"
$config = Import-Clixml -Path $configFile

$dsServerName = $config.dsServerName
$dsPort = $config.dsPort
$userDomain = $config.userDomain
$userName = $config.userName
$userPassword = $config.userPassword
$authType = $config.authType
$searchbase = $config.searchbase

function Invoke-LDAPQuery
{
    Param(
        [Parameter(Mandatory=$false)][String]$Filter = '(&(cn=Administrators))'
    )

    if ($authType -eq 'Basic') {
        $credential = New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList "$userDomain\$userName", $userPassword
    }

    if ($authType -eq 'Negotiate') {
        if ($PSVersionTable.OS -match 'Linux') {
            # Seems to work on Linux, not Windows:
            $credential = New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $userDomain\$userName, $userPassword
        } else {
            # Seems to work on Windows, not Linux:
            $credential = New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $userName, $userPassword, $userDomain
        }
    }

    $dsServer = New-Object `
        -TypeName System.DirectoryServices.Protocols.LdapConnection `
        -ArgumentList "$($dsServerName):$dsPort", $credential, $authType

    $dsServer.SessionOptions.ProtocolVersion = 3
     
    $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $attributeList = @('*')

    $searchRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.SearchRequest `
        -ArgumentList $searchbase, $Filter, $scope, $attributeList

    $dsServer.SendRequest($searchRequest)
}

# TODO Access results this way:
# $searchResults.Entries[0].attributes['sAMAccountName'].GetValues('string')

