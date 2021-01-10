
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

# TODO Add logging to text file, default location to profile or home directory 
# depending on OS, allow to be configured.

$configFile = "$PSScriptRoot\PortableLDAPTools.xml"
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

function Convert-SearchResultAttributeCollectionToPSCustomObject
{
    Param(
        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.Protocols.SearchResultAttributeCollection[]]
        $SearchResultAttributeCollection
    )
    # TODO SecurityIdentifier is not supported on Linux: 
    # "Windows Principal functionality is not supported on this platform."
    # Try to at least make sure it's returned in a format that can be 
    # converted to a SID on Windows.
    foreach ($srac in $SearchResultAttributeCollection) {
        $attributeObject = [PSCustomObject]@{}
        foreach ($attributeName in ($srac.Keys | Sort-Object)) {
            if ($attributeName -eq 'objectsid') {
                $values = $srac[$attributeName][0]
                if ($values -is [string]) { # NOTE Apparently some objects return 
                                            # the sid differently, such as the 
                                            # Active Directory Administrators group
                    $values = $srac[$attributeName].GetValues('Byte[]')[0]
                }
                $values = New-Object -TypeName System.Security.Principal.SecurityIdentifier `
                    -ArgumentList $values, 0
            } elseif ($attributeName -eq 'objectguid') {
                $values = $srac[$attributeName][0]
                $values = New-Object -TypeName System.Guid -ArgumentList @(,$values)
            } else {
                $values = $srac[$attributeName].GetValues('string')
                $values = foreach ($value in $values) {
                    if ($value -match '\.0Z$') {
                        $value = [DateTime]::ParseExact($value, 'yyyyMMddHHmmss.fK', $null)
                    } elseif ($attributeName -eq 'pwdlastset') {
                        $value = [DateTime]::FromFileTime($value)
                    }
                    $value
                }
            }
            $attributeObject | Add-Member -MemberType NoteProperty `
                -Name $attributeName -Value $values
        }
        $attributeObject
    }
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

    if (-not $SearchTerm) {
        Write-Host "Usage: LDAPGet SearchTerm(s)"
        Write-Host "Usage: LDAPGet SearchTerm(s) ReturnAttribute(s)"
        Write-Host "     SearchTerm: Term to find objects by"
        Write-Host "ReturnAttribute: Which attributes to return per object"
        return
    }

    foreach ($sTerm in $SearchTerm) {
        $filter = "(|(cn=$sTerm)(Name=$sTerm)(sAMAccountName=$sTerm)"
        if ($sTerm -match '\s') {
            $sTermSplit = $sTerm -split '\s'
            if ($sTermSplit.Count -eq 2) {
                $sTerm1, $sTerm2 = $sTermSplit[0..1]
                $filter += "(&(Givenname=$sTerm1)(SurName=$sTerm2))(&(Givenname=$sTerm2)(Surname=$sterm1))"
            }
            # TODO Add more queries
        }
        $filter += ')'
        (Invoke-LDAPQuery -Filter $filter).Entries | ForEach-Object {
            Convert-SearchResultAttributeCollectionToPSCustomObject -SearchResultAttributeCollection $_.Attributes
            #$_
        }
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
        Write-Host "Usage: LDAPGet SearchTerm(s) SearchAttribute(s)"
        Write-Host "Usage: LDAPGet SearchTerm(s) SearchAttribute(s) ReturnAttribute(s)"
        Write-Host "     SearchTerm: Term to find objects by"
        Write-Host "SearchAttribute: Attribute in which to look for SearchTerm"
        Write-Host "ReturnAttribute: Which attributes to return per object"
        return
    }
}

function Set-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        Write-Host "Usage: LDAPSet SearchTerm(s) Attribute(s) Value"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to modify"
        Write-Host "     Value: Value to set to the attribute"
        return
    }

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -gt 0) {
        Write-Host "About to set '$Attribute' to '$Value' on the following objects:" `
            -ForegroundColor Yellow
        foreach ($ldapObject in $ldapObjectList) {
            Write-Host $ldapObject.distinguishedname -ForegroundColor Green
        }
        Write-Host '[A]ll, [S]elect objects, [D]eselect objects , Ctrl+C to cancel' `
            -ForegroundColor Yellow
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
        Write-Host "Usage: LDAPAdd SearchTerm(s) Attribute(s) Value"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to modify"
        Write-Host "     Value: Value to add to the attribute"
        return
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
        Write-Host "Usage: LDAPRem SearchTerm(s) Attribute(s)"
        Write-Host "Usage: LDAPRem SearchTerm(s) Attribute(s) Value(s)"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to remove all value(s) from"
        Write-Host "     Value: Which values to remove from attribute, default (not passed) is all"
        return
    }
}

function Add-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: LDAPAddMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
        return
    }
}

function Remove-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $Filter -and -not $Attribute) {
        Write-Host "Usage: LDAPRemMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
        return
    }
}

Set-Alias -Name LDAPGet -Value Get-LDAPObject
Set-Alias -Name LDAPGetByAttribute -Value Get-LDAPObjectByAttribute
Set-Alias -Name LDAPSet -Value Set-LDAPObjectAttributeValue
Set-Alias -Name LDAPAdd -Value Add-LDAPObjectAttribute
Set-Alias -Name LDAPRem -Value Remove-LDAPObjectAttribute
Set-Alias -Name LDAPAddMember -Value Add-LDAPGroupMember
Set-Alias -Name LDAPRemMember -Value Remove-LDAPGroupMember

