
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
    if ($Operation -eq 'Replace') {
    $modifyRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.ModifyRequest `
        -ArgumentList $DistinguishedName, $Operation, $AttributeName, $Values
    } elseif ($Operation -eq 'Add') {
        $addModification = New-Object `
            -TypeName System.DirectoryServices.Protocols.DirectoryAttributeModification
        $addModification.Name = $AttributeName
        $addModification.Add($Values) | Out-Null
        $addModification.Operation = 'Add'
        $modifyRequest = New-Object `
            -TypeName System.DirectoryServices.Protocols.ModifyRequest `
            -ArgumentList $DistinguishedName, $addModification
    } elseif ($Operation -eq 'Delete') {
        $addModification = New-Object `
            -TypeName System.DirectoryServices.Protocols.DirectoryAttributeModification
        $addModification.Name = $AttributeName
        $addModification.Add($Values) | Out-Null
        $addModification.Operation = 'Delete'
        $modifyRequest = New-Object `
            -TypeName System.DirectoryServices.Protocols.ModifyRequest `
            -ArgumentList $DistinguishedName, $addModification
    }


    $ldapServer.SendRequest($modifyRequest) | out-null
    # TODO The above returns something like:
    # RequestId    :
    # MatchedDN    :
    # Controls     : {}
    # ResultCode   : Success
    # ErrorMessage :
    # Referral     : {}
    # Which Out-Null hides. But this also throws a proper error at least when you target a non-existing object.
    # Look into it.
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

function Select-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)]$ObjectList,
        [Parameter(Mandatory=$false)][String]$DisplayProperty = 'canonicalname'
    )
    while ($true) {
        $hideKeysStrokes = $true
        $key = ([Console]::ReadKey($hideKeysStrokes)).Key
        switch ($key) {
            A {
                return 'Apply'
            }
            S {
                if ($PSVersionTable.OS -match 'Windows') {
                    $selected = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to select, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms.'
                    return $selected
                }
            }
            D {
                if ($PSVersionTable.OS -match 'Windows') {
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
            }
            Escape {
                return @()
            }
        }
    }
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

    $result = @()
    foreach ($filter in (Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm)) {
        (Invoke-LDAPQuery -Filter $filter).Entries | ForEach-Object {
            $result += Convert-SearchResultAttributeCollectionToPSCustomObject `
                -SearchResultAttributeCollection $_.Attributes
        }
    }
    $result | Sort-Object -Property canonicalname
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

function Get-LDAPObjectByAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String]$AttributeValue
    )

    if (-not $SearchTerm -and -not $SearchAttribute -and -not $AttributeValue) {
        Write-Host "Usage: LDAPGetObjectByAttributeValue SearchAttribute(s) AttributeValue(s)"
        Write-Host "SearchAttribute: Attribute(s) in which to look for AttributeValue(s)"
        Write-Host " AttributeValue: Which values to look for int SearchAttribute(s)"
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
        $apply = $false
        while ($apply -eq $false) {
            Write-Host "About to set attribute '$Attribute' value to '$Value' on the following objects:" `
                -ForegroundColor Yellow
            foreach ($ldapObject in $ldapObjectList) {
                Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
            }
            Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
                -ForegroundColor Yellow

            $answer = Select-LDAPObject -ObjectList $ldapObjectList
            if ($answer -eq 'Apply') {
                $apply = $true
            } else {
                $ldapObjectList = $answer
            }
            if ($ldapObjectList.Count -eq 0) {
                $apply = $true
            }
        }
        foreach ($ldapObject in $ldapObjectList) {
            $objName = $ldapObject.CanonicalName
            $oldValue = $ldapObject.$Attribute -join ', '
            try {
                $msg = "'$objName' '$Attribute' is '$oldValue'"
                Write-Host $msg
                Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                    -AttributeName $Attribute -Values $Value -ErrorAction Stop
                $msg = "'$objName' '$Attribute' set to '$Value'"
                Write-Host $msg
            } catch {
                $err = $_.ToString()
                $msg = "Error setting '$objName' '$Attribute' to '$Value': $err"
                Write-Host $msg
            }
        }
    } else {
        Write-Host "Could not find objects to modify."
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
        $apply = $false
        while ($apply -eq $false) {
            Write-Host "About to add attribute '$Attribute' value '$Value' to the following objects:" `
                -ForegroundColor Yellow
            foreach ($ldapObject in $ldapObjectList) {
                Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
            }
            Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
                -ForegroundColor Yellow

            $answer = Select-LDAPObject -ObjectList $ldapObjectList
            if ($answer -eq 'Apply') {
                $apply = $true
            } else {
                $ldapObjectList = $answer
            }
            if ($ldapObjectList.Count -eq 0) {
                $apply = $true
            }
        }
        foreach ($ldapObject in $ldapObjectList) {
            $objName = $ldapObject.canonicalname
            $valName = $Value -join ', '
            $oldValue = $ldapObject.$Attribute -join ', '
            try {
                $msg = "'$objName' '$Attribute' is '$oldValue'"
                Write-Host $msg
                Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Add `
                    -AttributeName $Attribute -Values $Value -ErrorAction Stop
                $msg = "'$objName' '$Attribute' value '$valName' added"
                Write-Host $msg
            } catch {
                $err = $_.ToString()
                $msg = "Error adding '$objName' '$Attribute' value '$valName': $err"
                Write-Host $msg
            }
        }
    } else {
        Write-Host "Could not find objects to modify."
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
        Write-Host " Attribute: Which attribute to remove value(s) from"
        Write-Host "     Value: Which values to remove from attribute, default (not passed) is all"
        return
    }

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -gt 0) {
        $apply = $false
        while ($apply -eq $false) {
            Write-Host "About to remove attribute '$Attribute' value '$Value' from the following objects:" `
                -ForegroundColor Yellow
            foreach ($ldapObject in $ldapObjectList) {
                Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
            }
            Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
                -ForegroundColor Yellow

            $answer = Select-LDAPObject -ObjectList $ldapObjectList
            if ($answer -eq 'Apply') {
                $apply = $true
            } else {
                $ldapObjectList = $answer
            }
            if ($ldapObjectList.Count -eq 0) {
                $apply = $true
            }
        }
        foreach ($ldapObject in $ldapObjectList) {
            $objName = $ldapObject.CanonicalName
            $oldValue = $ldapObject.$Attribute -join ', '
            try {
                $msg = "'$objName' '$Attribute' is '$oldValue'"
                Write-Host $msg
                Set-LDAPObject -DistinguishedName $ldapObject.distinguishedname -Operation Delete `
                    -AttributeName $Attribute -Values $Value
                $msg = "'$objName' '$Attribute' '$Value' removed"
                Write-Host $msg
            } catch {
                $err = $_.ToString()
                $msg = "Error removing '$objName' '$Attribute' '$Value': $err"
                Write-Host $msg
            }
        }
    } else {
        Write-Host "Could not find objects to modify."
    }
}

function Clear-LDAPObjectAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute
    )

    if (-not $SearchTerm -or -not $Attribute) {
        Write-Host "Usage: LDAPRem SearchTerm(s) Attribute(s)"
        Write-Host "SearchTerm: Term to find objects by"
        Write-Host " Attribute: Which attribute to remove all value(s) from"
        return
    }

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -gt 0) {
        $apply = $false
        while ($apply -eq $false) {
            Write-Host "About to remove all values from attribute '$Attribute' from the following objects:" `
                -ForegroundColor Yellow
            foreach ($ldapObject in $ldapObjectList) {
                Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
            }
            Write-Host '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel' `
                -ForegroundColor Yellow

            $answer = Select-LDAPObject -ObjectList $ldapObjectList
            if ($answer -eq 'Apply') {
                $apply = $true
            } else {
                $ldapObjectList = $answer
            }
            if ($ldapObjectList.Count -eq 0) {
                $apply = $true
            }
        }
        foreach ($ldapObject in $ldapObjectList) {
            $objName = $ldapObject.CanonicalName
            $oldValue = $ldapObject.$Attribute -join ', '
            try {
                $msg = "'$objName' '$Attribute' is '$oldValue'"
                Write-Host $msg
                Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Delete `
                    -AttributeName $Attribute -Values $ldapObject.$Attribute -ErrorAction Stop
                $msg = "'$objName' '$Attribute' cleared"
                Write-Host $msg
            } catch {
                $err = $_.ToString()
                $msg = "Error clearing '$objName' '$Attribute': $err"
                Write-Host $msg
            }
        }
    } else {
        Write-Host "Could not find objects to modify."
    }
}

function Select-LDAPGroupMemberModificationTarget
{
    param(
        [parameter(mandatory=$false)]$LDAPGroupList,
        [parameter(mandatory=$false)]$LDAPMemberList,
        [parameter(mandatory=$false)]$OperationDescription,
        [parameter(mandatory=$false)]$Instructions
    )

    $membershipMap = @()
    foreach ($ldapGroup in $LDAPGroupList) {
        foreach ($ldapMember in $LDAPMemberList) {
            $membershipMap += [PSCustomObject]@{
                Group = $ldapGroup
                Member = $ldapMember
                Name = "$($ldapGroup.canonicalname) -> $($ldapMember.canonicalname)"
            }
        }
    }
    $apply = $false
    while ($apply -eq $false) {
        Write-Host $OperationDescription -ForegroundColor Yellow
        foreach ($entry in $membershipMap) {
            Write-Host "    $($entry.Group.canonicalname) -> $($entry.Member.canonicalname)" `
                -ForegroundColor Green
        }
        Write-Host $Instructions -ForegroundColor Yellow
        $answer = Select-LDAPObject -ObjectList $membershipMap -DisplayProperty Name
        if ($answer -eq 'Apply') {
            $apply = $true
        } else {
            $membershipMap = $answer
        }
        if ($membershipMap.Count -eq 0) {
            $apply = $true
        }
    }
    return $membershipMap
}

function Add-LDAPGroupMember
{
    param(
        [parameter(mandatory=$false)][string[]]$searchtermgroup,
        [parameter(mandatory=$false)][string[]]$searchtermmember
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        Write-Host "Usage: LDAPAddMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
        return
    }

    $operationDescription = "About to add group members:"

    $instructions = '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel'
    if ($PSVersionTable.OS -notmatch 'Windows') {
        $instructions = '[A]pply, Esc to cancel'
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
        $addToMap = Select-LDAPGroupMemberModificationTarget `
            -LDAPGroupList $ldapGroupList -LDAPMemberList $ldapMemberList `
            -OperationDescription $operationDescription -Instructions $instructions
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            try {
                if ($addtoEntry.Group.member -contains $addtoEntry.Member.distinguishedname) {
                    $msg = "'$groupCanName' already contains '$groupMemName'"
                    Write-Host $msg
                } else {
                    Set-LDAPObject -DistinguishedName $groupDN -Operation 'Add' -AttributeName member `
                        -Values $memberDN -ErrorAction Stop
                    $msg = "'$groupCanName' member '$groupMemName' added"
                    Write-Host $msg
                }
            } catch {
                $err = $_.ToString()
                $msg = "Error adding '$groupCanName' member '$groupMemName': $err"
                Write-Host $msg
            }                
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

    if (-not $SearchTermGroup -and -not $SearchTermMember) {
        Write-Host "Usage: LDAPRemMember SearchTermGroup(s) SearchTermMember(s)"
        Write-Host " SearchTermGroup: Term to find groups by"
        Write-Host "SearchTermMember: Term to find member object(s) to remove from group by"
        return
    }

    $operationDescription = "About to remove group members:"

    $instructions = '[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel'
    if ($PSVersionTable.OS -notmatch 'Windows') {
        $instructions = '[A]pply, Esc to cancel'
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
        $addToMap = Select-LDAPGroupMemberModificationTarget `
            -LDAPGroupList $ldapGroupList -LDAPMemberList $ldapMemberList `
            -OperationDescription $operationDescription -Instructions $instructions
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            try {
                if ($addtoEntry.Group.member -notcontains $addtoEntry.Member.distinguishedname) {
                    $msg = "'$groupCanName' does not contain '$groupMemName'"
                    Write-Host $msg
                } else {
                    Set-LDAPObject -DistinguishedName $groupDN -Operation 'Delete' -AttributeName member `
                        -Values $memberDN -ErrorAction Stop
                    $msg = "'$groupCanName' member '$groupMemName' removed"
                    Write-Host $msg
                }
            } catch {
                $err = $_.ToString()
                $msg = "Error removing '$groupCanName' member '$groupMemName': $err"
                Write-Host $msg
            }                
        }
    } else {
        if ($ldapGroupList.Count -gt 0) {
            Write-Host "Found no members to remove."
        } else {
            Write-Host "Found no groups to remove members from."
        }
    }
}

function Add-LDAPObject
{
    Param(
        [Parameter(Mandatory=$false)][String]$ObjectClass
    )
}

function Remove-LDAPObject
{
    # TODO Probably better to do New-LDAPUser, New-LDAPGroup
}

function Reset-ADObjectPassword
{
}

Set-Alias -Name LDAPGet -Value Get-LDAPObject
Set-Alias -Name LDAPGetByAttribute -Value Get-LDAPObjectByAttribute
Set-Alias -Name LDAPGetByAttributeValue -Value Get-LDAPObjectByAttribute
Set-Alias -Name LDAPSetVal -Value Set-LDAPObjectAttributeValue
Set-Alias -Name LDAPAddVal -Value Add-LDAPObjectAttributeValue
Set-Alias -Name LDAPRemVal -Value Remove-LDAPObjectAttributeValue
Set-Alias -Name LDAPClrVal -Value Clear-LDAPObjectAttributeValue
Set-Alias -Name LDAPAddMember -Value Add-LDAPGroupMember
Set-Alias -Name LDAPRemMember -Value Remove-LDAPGroupMember
Set-Alias -Name LDAPAddObj -Value Add-LDAPObject
Set-Alias -Name LDAPRemObj -Value Remove-LDAPObject
Set-Alias -Name LDAPSetPass -Value Reset-ADObjectPassword

