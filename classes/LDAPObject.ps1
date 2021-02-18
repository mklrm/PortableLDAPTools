
using namespace System.Security.Principal

if ($psVersionMajor -le 5) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal") | Out-Null
}

# NOTE Excellent article about Powershell classes:
# https://xainey.github.io/2016/powershell-classes-and-concepts/#inheritance

Class LDAPObject
{
    [String] $canonicalname
    [String] $cn
    [String] $distinguishedname
    [DateTime[]] $dscorepropagationdata
    [Int] $instancetype
    [String] $name
    [String] $objectcategory
    [String[]] $objectclass
    [Guid] $objectguid
    [Int] $usnchanged
    [Int] $usncreated
    [DateTime] $whenchanged
    [DateTime] $whencreated
    [PSCustomObject[]] $attributes

    LDAPObject([PSCustomObject[]] $AttributeObject)
    {
        $unhandledAttributeList = @()
        $attributeList = ($AttributeObject | Get-Member -MemberType NoteProperty).Name

        foreach ($attributeName in $attributeList) {
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
    [String] $description
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
    [Int64] $accountexpires
    [Int64] $badpasswordtime
    [Int] $badpwdcount
    [Int] $codepage
    [Int] $countrycode
    [Boolean] $iscriticalsystemobject
    [DateTime] $LastLogonDate
    [DateTime] $LastLogonTimestampDate
    [Int] $logoncount
    [String[]] $MemberOf
    [SecurityIdentifier] $objectsid
    [Int] $primarygroupid
    [DateTime] $PwdLastSetDate
    [String] $samaccountname
    [Int] $samaccounttype
    [Int] $useraccountcontrol

    LDAPAuthenticatedObject([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
        if ($AttributeObject.lastlogon) {
            $this.LastLogonDate = [DateTime]::FromFileTime($AttributeObject.lastlogon)
        }
        if ($AttributeObject.lastlogontimestamp) {
            $this.LastLogonTimestampDate = [DateTime]::FromFileTime($AttributeObject.lastlogontimestamp)
        }
        if ($AttributeObject.pwdlastset) {
            $this.PwdLastSetDate = [DateTime]::FromFileTime($AttributeObject.pwdlastset)
        }
    }
}

Class LDAPUser : LDAPAuthenticatedObject
{
    [Int] $admincount
    [String] $description

    LDAPUser([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
    }
}

Class LDAPComputer : LDAPAuthenticatedObject
{
    [String] $description
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

