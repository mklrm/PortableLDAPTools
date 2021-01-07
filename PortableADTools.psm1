
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

# TODO Add logging to text file, default location to profile or home directory 
# depending on OS, allow to be configured.

$configFile = "$PSScriptRoot\PortableADTools.xml"
$config = Import-Clixml -Path $configFile

$ldapServerName = $config.ldapServerName
$ldapPort = $config.ldapPort
$userDomain = $config.userDomain
$userName = $config.userName
$userPassword = $config.userPassword
$authType = $config.authType
$searchbase = $config.searchbase

if ($authType -eq 'Basic') {
    $credential = New-Object `
        -TypeName System.Net.NetworkCredential `
        -ArgumentList "$userDomain\$userName", $userPassword
}

if ($authType -eq 'Negotiate') {
    if ($PSVersionTable.OS -match 'Linux') {
        $credential = New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList $userDomain\$userName, $userPassword
    } else {
        $credential = New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList $userName, $userPassword, $userDomain
    }
}

$ldapServer = New-Object `
    -TypeName System.DirectoryServices.Protocols.LdapConnection `
    -ArgumentList "$($ldapServerName):$ldapPort", $credential, $authType

$ldapServer.SessionOptions.ProtocolVersion = 3

function Invoke-LDAPQuery
{
    Param(
        [Parameter(Mandatory=$false)][String]$Filter = '(&(cn=Administrators))'
    )

    $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $attributeList = @('*')

    $searchRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.SearchRequest `
        -ArgumentList $searchbase, $Filter, $scope, $attributeList

    $ldapServer.SendRequest($searchRequest)
}

# TODO Access results this way:
# $searchResults.Entries[0].attributes['sAMAccountName'].GetValues('string')

function Set-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)][String]$DistinguishedName,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Add', 'Delete', 'Replace')][String]$Operation,
        [Parameter(Mandatory=$true)][String]$AttributeName,
        [Parameter(Mandatory=$true)][String]$Values
    )
    $modifyRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.ModifyRequest `
        -ArgumentList $DistinguishedName, $Operation, $AttributeName, $Values

    $ldapServer.SendRequest($modifyRequest)
}

# NOTE ALL OF THE BELOW FUNCTIONS ARE MEANT TO BE USED INTERACTIVELY, NOT IN A SCRIPT.
# They make fuzzy searches so objects found and selected for modification might not 
# be what you'd expect.
# TODO Add a warning to the command help texts too
# TODO Show what's about to be modified and let user confirm before taking action

function Get-LDAPObject
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADGet SearchTerm(s)"
        Write-Host "Usage: PADGet SearchTerm(s) ReturnAttribute(s)"
        Write-Host "     SearchTerm: Term to find objects by"
        Write-Host "ReturnAttribute: Which attributes to return per object"
    }
}

function Get-LDAPObjectByAttribute
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADGet SearchTerm(s) SearchAttribute(s)"
        Write-Host "Usage: PADGet SearchTerm(s) SearchAttribute(s) ReturnAttribute(s)"
        Write-Host "     SearchTerm: Term to find objects by"
        Write-Host "SearchAttribute: Attribute in which to look for SearchTerm"
        Write-Host "ReturnAttribute: Which attributes to return per object"
    }
}

function Set-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADSet SearchTerm(s) Attribute(s) Value"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to modify"
        Write-Host "     Value: Value to set to the attribute"
    }
}

function Add-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADAdd SearchTerm(s) Attribute(s) Value"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to modify"
        Write-Host "     Value: Value to add to the attribute"
    }
}

function Remove-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$Attribute,
        [Parameter(Mandatory=$false)][String[]]$Value
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADRem SearchTerm(s) Attribute(s)"
        Write-Host "Usage: PADRem SearchTerm(s) Attribute(s) Value(s)"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to remove all value(s) from"
        Write-Host "     Value: Which values to remove from attribute, default (not passed) is all"
    }
}

function Add-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADAddMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
    }
}

function Remove-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: PADRemMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
    }
}

Set-Alias -Name PADGet -Value Get-LDAPObject
Set-Alias -Name PADGetByAttribute -Value Get-LDAPObjectByAttribute
Set-Alias -Name PADSet -Value Set-LDAPObjectAttribute
Set-Alias -Name PADAdd -Value Add-LDAPObjectAttribute
Set-Alias -Name PADRem -Value Remove-LDAPObjectAttribute
Set-Alias -Name PADAddMember -Value Add-LDAPGroupMember
Set-Alias -Name PADRemMember -Value Remove-LDAPGroupMember

