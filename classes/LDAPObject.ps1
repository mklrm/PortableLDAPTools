
using namespace System.Security.Principal
using namespace System.DirectoryServices.Protocols

if ($psVersionMajor -le 5) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal") | Out-Null
}

# NOTE Excellent article about Powershell classes:
# https://xainey.github.io/2016/powershell-classes-and-concepts/#inheritance

Class LDAPObject
{
    [String] $CanonicalName
    [String] $cn
    [String] $DistinguishedName
    [DateTime[]] $DsCorePropagationData
    [Int] $instancetype
    [String] $Name
    [String] $objectcategory
    [String[]] $objectclass
    [Guid] $objectguid
    [Int] $usnchanged
    [Int] $usncreated
    [DateTime] $WhenChanged
    [DateTime] $WhenCreated
    [PSCustomObject] $UnhandledAttributes 

    LDAPObject([PSCustomObject[]] $AttributeObject)
    {
        $unhandledAttributeList = @()
        $attributeList = ($AttributeObject | Get-Member -MemberType NoteProperty).Name
        
        $skipAutomaticConversionList = 'dscorepropagationdata', 'whenchanged', 'whencreated', 'memberof', 
            'member'

        foreach ($attributeName in $attributeList) {
            if ($skipAutomaticConversionList -contains $attributeName) {
                continue
            }
            try {
                $this.$attributeName = $AttributeObject.$attributeName
            } catch {
                if ($_.ToString() -match "The property '.*?' cannot be found on this object.") {
                    $unhandledAttributeList += $attributeName
                } else {
                    throw $_
                }
            }
        }

        if ($AttributeObject.dscorepropagationdata) {
            $values = $AttributeObject.dscorepropagationdata
            foreach ($value in $values) {
                $this.DsCorePropagationData += [DateTime]::ParseExact($value, 'yyyyMMddHHmmss.fK', $null)
            }
            $unhandledAttributeList = $unhandledAttributeList | Where-Object { $_ -ne 'dscorepropagationdata' }
        }

        if ($AttributeObject.whenchanged) {
            $value = $AttributeObject.whenchanged
            $this.WhenChanged = [DateTime]::ParseExact($value, 'yyyyMMddHHmmss.fK', $null)
            $unhandledAttributeList = $unhandledAttributeList | Where-Object { $_ -ne 'whenchanged' }
        }
        
        if ($AttributeObject.whencreated) {
            $value = $AttributeObject.whencreated
            $this.WhenCreated = [DateTime]::ParseExact($value, 'yyyyMMddHHmmss.fK', $null)
            $unhandledAttributeList = $unhandledAttributeList | Where-Object { $_ -ne 'whencreated' }
        }
        
        if ($unhandledAttributeList.count -gt 0) {
            $this.UnhandledAttributes = ($AttributeObject | Select-Object -Property $unhandledAttributeList | `
                Get-Member -MemberType NoteProperty).Name
            foreach ($attributeName in $this.UnhandledAttributes) {
                $this | Add-Member -MemberType NoteProperty -Name $attributeName -Value $AttributeObject.$attributeName
            }
        }

        if ($this.useraccountcontrol) {
            $userAccountControlFlagList = ConvertFrom-UserAccountControlInteger `
                -UserAccountControlInteger $this.useraccountcontrol
            foreach ($userAccountControlFlag in $userAccountControlFlagList) {
                $this | Add-Member -MemberType NoteProperty `
                    -Name $userAccountControlFlag -Value $true -Force
            }
        }
    }

    [String] ToString()
    {
        return $this.canonicalname
    }
}

Class LDAPMemberList
{
    [String[]] $DistinguishedName
    [LDAPObject[]] $MemberList

    LDAPMemberList()
    {
    }

    [Void] AddDistinguishedName([String] $DistinguishedName)
    {
        $this.DistinguishedName += $DistinguishedName
    }

    [Void] UpdateLDAPObjectList()
    {
        foreach ($dn in $this.DistinguishedName) {
            $splitDN = $dn -split ','
            $leaf = $splitDN[0]
            $filter = "(&($leaf))"
            $searchBase = $splitDN[1..($splitDN.Count + 1)] -join ','
            $this.MemberList += Invoke-LDAPQuery -Filter $filter -SearchBase $searchBase 
        }
    }

    [String] ToString()
    {
        if ($this.MemberList.Count -lt 1) {
            return $this.DistinguishedName
        }
        #if ($this.MemberList.Count -ne $this.DistinguishedName.Count) {
        #    $this.UpdateLDAPObjectList()
        #}
        return $this.MemberList.CanonicalName
    }
}

Class LDAPGroup : LDAPObject
{
    [Int] $grouptype
    [SecurityIdentifier] $objectsid
    [String] $samaccountname
    [Int] $samaccounttype
    [String] $Description
    [LDAPMemberList[]] $Members
    [LDAPMemberList[]] $MemberOf
    [Int] $admincount
    [Boolean] $iscriticalsystemobject
    [Int] $systemflags

    LDAPGroup([PSCustomObject[]] $AttributeObject) : base ($AttributeObject)
    {
        $this.Members = New-Object -TypeName LDAPMemberList
        foreach ($dn in $AttributeObject.Member) {
            $this.Members.AddDistinguishedName($dn)
        }

        $this.MemberOf = New-Object -TypeName LDAPMemberList
        foreach ($dn in $AttributeObject.MemberOf) {
            $this.MemberOf.AddDistinguishedName($dn)
        }
    }
}

Class LDAPAuthenticatedObject : LDAPObject
{
    [String] $sAMAccountName
    [Boolean] $AccountDisabled
    [String] $Description
    [Boolean] $AccountLockedOut
    [Boolean] $PasswordNotRequired
    [Boolean] $PasswordCannotChange
    [Boolean] $PasswordDoesNotExpire
    [Boolean] $PasswordExpired
    [Int64] $AccountExpires # TODO Change to a date
    [DateTime] $LastLogonDate
    [DateTime] $LastLogonTimestampDate
    [DateTime] $PasswordLastSet
    [Int64] $BadPasswordTime # TODO Change to a date
    [Int] $BadPasswordCount
    [Int] $LogonCount
    [SecurityIdentifier] $ObjectSid
    [Int] $PrimaryGroupId
    [Int] $sAMCccountType
    [Int] $UserAccountControl
    [Int] $Codepage
    [Int] $CountryCode

    LDAPAuthenticatedObject([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
        if ($AttributeObject.useraccountcontrol) {
            $userAccountControlFlagList = ConvertFrom-UserAccountControlInteger `
                -UserAccountControlInteger $AttributeObject.useraccountcontrol
            foreach ($userAccountControlFlag in $userAccountControlFlagList) {
                try {
                    $this.$UserAccountControlFlag = $true
                } catch {
                    # Quiet
                }
            }
        }
        if ($AttributeObject.lastlogon) {
            $this.LastLogonDate = [DateTime]::FromFileTime($AttributeObject.lastlogon)
        }
        if ($AttributeObject.lastlogontimestamp) {
            $this.LastLogonTimestampDate = [DateTime]::FromFileTime($AttributeObject.lastlogontimestamp)
        }
        if ($AttributeObject.pwdlastset) {
            $this.PasswordLastSet = [DateTime]::FromFileTime($AttributeObject.pwdlastset)
        }
        if ($AttributeObject.badpwdcount) {
            $this.BadPasswordCount = $AttributeObject.badpwdcount
        }
    }
}

Class LDAPUser : LDAPAuthenticatedObject
{
    [String] $DisplayName
    [String] $GivenName
    [String] $SurName
    [String] $UserPrincipalName
    [LDAPMemberList[]] $MemberOf
    [String] $Mail
    [String] $Mobile
    [String] $Title
    [String] $Company
    [String] $Department
    [String] $Manager
    [String] $HomeDirectory
    [String] $HomeDrive
    [String] $StreetAddress

    LDAPUser([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
        if ($AttributeObject.sn) {
            $this.SurName = $AttributeObject.sn
        }

        $this.MemberOf = New-Object -TypeName LDAPMemberList
        foreach ($dn in $AttributeObject.MemberOf) {
            $this.MemberOf.AddDistinguishedName($dn)
        }
    }
}

Class LDAPComputer : LDAPAuthenticatedObject
{
    [String] $displayname
    [String] $dnshostname
    [Int] $localpolicyflags
    #[String[]] $msdfsr-computerreferencebl # TODO Figure out what to...
    #[Byte[]] $msds-generationid # ...do...
    #[Int] $msds-supportedencryptiontypes # ...with the dashes
    [String] $operatingsystem
    [String] $operatingsystemversion
    [String[]] $ridsetreferences
    [String[]] $serverreferencebl
    [String[]] $serviceprincipalname

    LDAPComputer([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
    }
}

