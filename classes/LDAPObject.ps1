
using namespace System.Security.Principal

if ($psVersionMajor -le 5) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal") | Out-Null
}

# NOTE Excellent article about Powershell classes:
# https://xainey.github.io/2016/powershell-classes-and-concepts/#inheritance

Class LDAPObject
{
    [String] $CanonicalName
    [String] $cn
    [String] $distinguishedname
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
    [PSCustomObject[]] $attributes

    LDAPObject([PSCustomObject[]] $AttributeObject)
    {
        $unhandledAttributeList = @()
        $attributeList = ($AttributeObject | Get-Member -MemberType NoteProperty).Name

        $skipAutomaticConversionList = 'dscorepropagationdata', 'whenchanged', 'whencreated'

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
            $this.attributes = $AttributeObject | Select-Object -Property $unhandledAttributeList
        }
    }

    [String] ToString()
    {
        return $this.canonicalname
    }
}

Class LDAPGroup : LDAPObject
{
    [Int] $grouptype
    [SecurityIdentifier] $objectsid
    [String] $samaccountname
    [Int] $samaccounttype
    [String] $Description
    [String[]] $Member
    [String[]] $MemberOf
    [Int] $admincount
    [Boolean] $iscriticalsystemobject
    [Int] $systemflags

    LDAPGroup([PSCustomObject[]] $AttributeObject) : base ($AttributeObject)
    {
    }
}

Class LDAPAuthenticatedObject : LDAPObject
{
    [String] $sAMAccountName
    [String] $Description
    [String[]] $MemberOf
    [Int64] $accountexpires # TODO Change to a date
    [Boolean] $iscriticalsystemobject
    [DateTime] $LastLogonDate
    [DateTime] $LastLogonTimestampDate
    [DateTime] $PasswordLastSet
    [Int64] $BadPasswordTime # TODO Change to a date
    [Int] $BadPasswordCount
    [Int] $LogonCount
    [SecurityIdentifier] $ObjectSid
    [Int] $primarygroupid
    [Int] $samaccounttype
    [Int] $useraccountcontrol
    [Int] $codepage
    [Int] $countrycode

    LDAPAuthenticatedObject([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
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
    [String] $Mail
    [String] $Mobile
    [String] $Title
    [String] $Company
    [String] $Department
    [String] $HomeDirectory
    [String] $HomeDrive
    [String] $StreetAddress

    LDAPUser([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
        if ($AttributeObject.sn) {
            $this.SurName = $AttributeObject.sn
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

