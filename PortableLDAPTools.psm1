
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
$authType = $config.authType
$searchbase = $config.searchbase

Write-Host "Enter password for user $userDomain\$($userName):"
$userPassword = Read-Host -MaskInput

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

function ConvertTo-CanonicalName
{
    Param(
        [Parameter(Mandatory=$true)][String[]]$DistinguishedName
        
    )
    foreach ($dn in $DistinguishedName) {
        $tmp = $dn -split ','
        $cnList = ($tmp | Where-Object { $_ -match '^cn=' }) -replace '^cn='
        $ouList = ($tmp | Where-Object { $_ -match '^ou=' }) -replace '^ou='
        $dcList = ($tmp | Where-Object { $_ -match '^dc=' }) -replace '^dc='
        $CanonicalName = "$($dcList -join '.')/"
        $CanonicalName += $ouList[($ouList.Count + 1)..0] -join '/'
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

function Convert-SearchResultAttributeCollectionToPSCustomObject
{
    Param(
        [Parameter(Mandatory=$false)]
        [System.DirectoryServices.Protocols.SearchResultAttributeCollection[]]
        $SearchResultAttributeCollection
    )
    foreach ($srac in $SearchResultAttributeCollection) {
        $attributeObject = [PSCustomObject]@{}
        $attributeNameList = ($srac.Keys + 'canonicalname' | Sort-Object)
        foreach ($attributeName in $attributeNameList) {
            if ($attributename -eq 'canonicalname') {
                $values = ConvertTo-CanonicalName `
                    -DistinguishedName $srac['distinguishedname'].GetValues('string') | 
                        Select-Object -First 1
            } elseif ($attributeName -eq 'objectsid') {
                $values = $srac[$attributeName][0]
                # NOTE Only Windows is familiar with its SecurityIdentifiers
                if ($PSVersionTable.OS -match 'Windows') {
                    if ($values -is [string]) { # NOTE Apparently some objects return 
                                                # the sid differently, such as the 
                                                # Active Directory Administrators group
                        $values = $srac[$attributeName].GetValues('Byte[]')[0]
                    }
                    $values = New-Object -TypeName System.Security.Principal.SecurityIdentifier `
                        -ArgumentList $values, 0
                }
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

function Get-LDAPFuzzyQueryFilter
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$ObjectClass
    )

    $filters = @()
    foreach ($sTerm in $SearchTerm) {
        $filter = ''
        if ($ObjectClass) {
            $filter += "(&(objectclass=$ObjectClass)"
        }
        $filter += "(|(cn=$sTerm)(name=$sTerm)(samaccountName=$sTerm)(distinguishedname=$sTerm)"
        if ($sTerm -match '\s') {
            $sTermSplit = $sTerm -split '\s'
            if ($sTermSplit.Count -eq 2) {
                $sTerm1, $sTerm2 = $sTermSplit[0..1]
                $filter += "(&(givenname=$sTerm1)(sn=$sTerm2))(&(givenname=$sTerm2)(sn=$sterm1))"
            }
        }
        $filter += ')'
        if ($ObjectClass) {
            $filter += ')'
        }
        $filters += $filter
    }
    return $filters
}

function Get-Confirmation # TODO Rename
{
    Param(
        [Parameter(Mandatory=$false)]$ObjectList,
        [Parameter(Mandatory=$false)][String]$DisplayProperty = 'canonicalname'
    )
    $bail = $false
    while ($bail -eq $false) {
        $hideKeysStrokes = $true
        $key = ([Console]::ReadKey($hideKeysStrokes)).Key
        switch ($key) {
            A {
                return $ObjectList
            }
            S {
                return New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                    -Mode Multiselect -Title 'Use space to select, arrow keys and pgup/pgdn to move.', 
                    'Enter confirms.'
            }
            D {
                $deselectList = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                    -Mode Multiselect -Title 'Use space to deselect, arrow keys and pgup/pgdn to move.', 
                    'Enter confirms.'

                $selectList = Compare-Object -ReferenceObject $ObjectList.Name `
                    -DifferenceObject $deselectList.Name -IncludeEqual | 
                    Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject
                $selected = foreach ($select in $selectList) {
                    $ObjectList | Where-Object { $_.Name -eq $select }
                }
                return $selected
            }
            Escape {
                $bail = $true
            }
            Default {
                # Do nothing I guess?
            }
        }
    }
    Write-Host 'Bye bye!' -ForegroundColor Yellow
}

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

    foreach ($filter in (Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm)) {
        (Invoke-LDAPQuery -Filter $filter).Entries | ForEach-Object {
            Convert-SearchResultAttributeCollectionToPSCustomObject `
                -SearchResultAttributeCollection $_.Attributes
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
            Write-Host $ldapObject.canonicalname -ForegroundColor Green
        }
        Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
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

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        Write-Host "Usage: LDAPAdd SearchTerm(s) Attribute(s) Value"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to modify"
        Write-Host "     Value: Value to add to the attribute"
        return
    }

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -gt 0) {
        Write-Host "About to add '$Value' to '$Attribute' on the following objects:" `
            -ForegroundColor Yellow
        foreach ($ldapObject in $ldapObjectList) {
            Write-Host $ldapObject.canonicalname -ForegroundColor Green
        }
        Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
            -ForegroundColor Yellow
    }
}

function Remove-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$Attribute,
        [Parameter(Mandatory=$false)][String[]]$Value
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        Write-Host "Usage: LDAPRem SearchTerm(s) Attribute(s)"
        Write-Host "Usage: LDAPRem SearchTerm(s) Attribute(s) Value(s)"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to remove all value(s) from"
        Write-Host "     Value: Which values to remove from attribute, default (not passed) is all"
        return
    }

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -gt 0) {
        Write-Host "About to remove '$Value' from '$Attribute' on the following objects:" `
            -ForegroundColor Yellow
        foreach ($ldapObject in $ldapObjectList) {
            Write-Host $ldapObject.distinguishedname -ForegroundColor Green
        }
        Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
            -ForegroundColor Yellow
    }
}

function Add-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        Write-Host "Usage: LDAPAddMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
        return
    }

    $ldapGroupFilters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTermGroup -ObjectClass Group
    $ldapGroupList = foreach ($filter in $ldapGroupFilters) {
        (Invoke-LDAPQuery -Filter $filter).Entries | ForEach-Object {
            Convert-SearchResultAttributeCollectionToPSCustomObject `
                -SearchResultAttributeCollection $_.Attributes
        }
    }

    $ldapMemberList = Get-LDAPObject -SearchTerm $SearchTermMember

    if ($ldapGroupList.Count -gt 0 -and $ldapMemberList.Count -gt 0) {
        $addToMap = @()
        Write-Host "About to add group members:" `
            -ForegroundColor Yellow
        foreach ($ldapGroup in $ldapGroupList) {
            foreach ($ldapMember in $ldapMemberList) {
                Write-Host "    $($ldapGroup.canonicalname) -> $($ldapMember.canonicalname)" `
                    -ForegroundColor Green
                $addToMap += [PSCustomObject]@{
                    Group = $ldapGroup
                    Member = $ldapMember
                    Name = "$($ldapGroup.canonicalname) -> $($ldapMember.canonicalname)"
                }
            }
        }
        Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
            -ForegroundColor Yellow
        # TODO Make this loop
        $addToMap = Get-Confirmation -ObjectList $addToMap -DisplayProperty Name
        foreach ($addtoEntry in $addToMap) {
            # TODO Write a separate function that adds an object to a group
            # TODO Only write this if succesfully added member (whatever that looks like using this component):
            Write-Host "Group $($addtoEntry.Group.canonicalname) member added: $($addToEntry.Member.canonicalname)"
        }
    } else {
        if ($ldapGroupList.Count -gt 0) {
            Write-Host "Found no members to add."
        } else {
            Write-Host "Found no groups to add members to."
        }
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

function New-LDAPObject
{
    Param(
        [Parameter(Mandatory=$false)][String]$ObjectClass
    )
}

function Remove-LDAPObject
{
}

function Reset-ADObjectPassword
{
}

Set-Alias -Name LDAPGet -Value Get-LDAPObject
Set-Alias -Name LDAPGetByAttribute -Value Get-LDAPObjectByAttribute
Set-Alias -Name LDAPSet -Value Set-LDAPObjectAttributeValue
Set-Alias -Name LDAPAdd -Value Add-LDAPObjectAttribute
Set-Alias -Name LDAPRem -Value Remove-LDAPObjectAttribute
Set-Alias -Name LDAPAddMember -Value Add-LDAPGroupMember
Set-Alias -Name LDAPRemMember -Value Remove-LDAPGroupMember

