
using namespace System.Security.Principal

# NOTE Excellent article about Powershell classes:
# https://xainey.github.io/2016/powershell-classes-and-concepts/#inheritance
#
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
    [PSCustomObject[]] $additionalattributes

    LDAPObject([PSCustomObject[]] $AttributeObject)
    {
        $additionalAttributeList = @()
        $attributeList = ($AttributeObject | Get-Member -MemberType NoteProperty).Name

        foreach ($attributeName in $attributeList) {
            try {
                $this.$attributeName = $AttributeObject.$attributeName
            } catch {
                if ($_.ToString() -match "The property '.*?' cannot be found on this object.") {
                    $additionalAttributeList += $attributeName
                } else {
                    throw $_
                }
            }
        }
        
        if ($additionalAttributeList.count -gt 0) {
            $this.additionalattributes = $AttributeObject | Select-Object -Property $additionalAttributeList
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
    [String[]] $member
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
    [Int64] $lastlogoff # TODO [DateTime]
    [Int64] $lastlogon # TODO [DateTime]
    [Int64] $lastlogontimestamp # TODO [DateTime]
    [Int] $logoncount
    [String[]] $memberof
    [SecurityIdentifier] $objectsid
    [Int] $primarygroupid
    [DateTime] $pwdlastset
    [String] $samaccountname
    [Int] $samaccounttype
    [Int] $useraccountcontrol

    LDAPAuthenticatedObject([PSCustomObject[]] $AttributeObject) : base($AttributeObject)
    {
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

