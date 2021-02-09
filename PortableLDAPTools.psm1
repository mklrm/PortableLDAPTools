
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

# TODO Recursive group membership handleification

# TODO Add a summary of what the function does at the top of each help text

# TODO Ask for connection values, give ready choices to pick from for things that can (like default ports)

# TODO Writing out every single result (or preview of what's going to be happening either really) 
#      isn't very readable if you're adding say hundreds or thousands of members to a group 
#      or whatever else. Could:
#      1. Only display some arbitrary number of entries in the preview and let the user know 
#         that there's more on the list and the list can be accessed via a New-Menu shortcut
#      2. Only echo unsuccessful results and give stats of how many actions were successful 
#         and how many failed. Tell user to run 'LDAPSomeCommand' to show all results or 
#         something. 

using namespace System.DirectoryServices.Protocols
using namespace System.Collections.Specialized
using namespace System.Security.Principal

$scriptFileName = ($PSCommandPath | Split-Path -Leaf) -replace '\..*$'
$pathMyDocuments = [environment]::GetFolderPath('MyDocuments')

$configFile = "$pathMyDocuments\$scriptFileName.xml"
$config = Import-Clixml -Path $configFile

$ldapServerName = $config.ldapServerName
$ldapPort = $config.ldapPort
$userDomain = $config.userDomain
$userName = $config.userName
$authType = $config.authType
$searchbase = $config.searchbase
$pageSize = $config.pageSize

if (-not $pageSize) {
    $pageSize = 5000
}

$Script:credential = $null
$Script:ldapServer = $null

$confirmMessageColor = $Host.PrivateData.FormatAccentColor # NOTE Just pretty much used this for now because 
                                                           #      the default is green.
$cancelMessageColor = $Host.PrivateData.WarningForegroundColor

if (-not $confirmMessageColor) {
    $confirmMessageColor = 'Green'
}

$logFileEncoding = 'utf8'
$logFileName = "$scriptFileName-$(Get-Date -Format 'yyyy.MM.dd').log"
$logFileNameFilter = "$scriptFileName-*.log"

$logFileFullName = "$pathMyDocuments\$logFileName"
$logFileNameFullNameFilter = "$pathMyDocuments\$logFileNameFilter"

if ($config.logFileFullName) {
    $logFileFullName = $config.logFileFullName
}

function Get-LDAPCredential
{
    Write-Host "Enter password for user $userDomain\$($userName):"
    $userPassword = Read-Host -MaskInput

    if ($authType -eq 'Basic') {
        return New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList "$userDomain\$userName", $userPassword
    }

    if ($authType -eq 'Negotiate') {
        if ($PSVersionTable.OS -match 'Linux') {
            return New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $userDomain\$userName, $userPassword
        } else {
            return  New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $userName, $userPassword, $userDomain
        }
    }
}

function Connect-LDAPServer
{
    if ($null -eq $credential) {
        $Script:credential = Get-LDAPCredential
    }
    $ldapServer = New-Object `
        -TypeName LdapConnection -ArgumentList "$($ldapServerName):$ldapPort", $credential, $authType

    $ldapServer.SessionOptions.SecureSocketLayer = $true
    $ldapServer.SessionOptions.ProtocolVersion = 3
    return $ldapServer
}

function Write-Log
{
    Param(
        [Parameter(Mandatory=$true)][String]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Informational', 'Error')]
        [String]$Level = 'Informational',
        [Parameter(Mandatory=$false)][Switch]$NoEcho
    )
    $logFileName = "$scriptFileName-$(Get-Date -Format 'yyyy.MM.dd').log"
    $logFileFullName = "$pathMyDocuments\$logFileName"
    $logMessage = "[$(Get-Date -Format 'yyyy.MM.dd HH\:mm\:ss')] $Message"
    switch ($Level) {
        'Informational' {
            $foregroundColor = $HOST.UI.RawUI.ForegroundColor
            $backgroundColor = $HOST.UI.RawUI.BackgroundColor
        }
        'Error' {
            $foregroundColor = $Host.PrivateData.ErrorForegroundColor
            $backgroundColor = $HOST.PrivateData.ErrorBackgroundColor
        }
    }
    if (-not $NoEcho.IsPresent) {
        Write-Host -Object $Message `
            -ForegroundColor $foregroundColor `
            -BackgroundColor $backgroundColor
    }
    $logMessage | Out-File -FilePath $logFileFullName `
        -Encoding $logFileEncoding -Append -Force
}

try {
    $msg = "$PSCommandPath loading"
    Write-Log -Message $msg -ErrorAction Stop
    Write-Log -Message "Logging to $logFileFullName"
} catch {
    $err = $_.ToString()
    throw "Error writing to log file $($logFileFullName): $err"
}

function Get-LDAPLogFileList
{
    Param(
        [Parameter(Mandatory=$false)][Int]$First,
        [Parameter(Mandatory=$false)][Int]$Last
    )
    $logPathList = Get-ChildItem $logFileNameFullNameFilter | Select-Object -ExpandProperty FullName | `
        Sort-Object
    if ($First) {
        $logPathList | Select-Object -First $First
    }
    if ($Last) {
        $logPathList | Select-Object -Last $Last
    }
    if (-not $First -and -not $Last) {
        $logPathList
    }
}

function Write-Help
{
    Param(
        [Parameter(Mandatory=$true)][String[]]$Usage,
        [Parameter(Mandatory=$true)]$Parameter
    )
    $colorUsgTitle = 'Green'
    $colorUsgMessage = $Host.UI.RawUI.ForegroundColor
    $colorMsgTitle = 'Yellow'
    $colorMsgMessage = $Host.UI.RawUI.ForegroundColor
    Write-Host
    foreach ($msg in $Usage) {
        Write-Host "Usage: " -ForegroundColor $colorUsgTitle -NoNewline
        Write-Host $msg -ForegroundColor $colorUsgMessage
    }
    Write-Host
    $topLength = ($Parameter.Keys | Measure-Object -Maximum -Property Length).Maximum
    foreach ($param in $Parameter.Keys) {
        Write-Host "$($param): ".PadLeft($topLength + 2) `
            -ForegroundColor $colorMsgTitle -NoNewline
        Write-Host $Parameter.$param -ForegroundColor $colorMsgMessage
    }
    Write-Host
}

function Send-LDAP
{
    Param(
        [Parameter(Mandatory=$true)][DirectoryRequest]$Request
    )

    if ($null -eq $Script:ldapServer) {
        $Script:ldapServer = Connect-LDAPServer
    }
    try {
        $Script:ldapServer.SendRequest($Request) | ForEach-Object {
            if ($_ -is [AddResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -is [DeleteResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -isnot [ModifyResponse]) {
                # NOTE It's likely returning an object from an ldap directory...
                $_
            } else {
                #return $_
                # ...otherwise something we do not care about...
            }
         }
    } catch {
        if ($_.Exception.Message -match '"The supplied credential is invalid."') {
            Write-Host "The supplied credential is invalid."
            $Script:credential = $null
            $script:ldapServer = Connect-LDAPServer
            Send-LDAP -Request $Request
        } else {
            throw $_
        }
    }
    # NOTE ...such as this here.
    # RequestId    :
    # MatchedDN    :
    # Controls     : {}
    # ResultCode   : Success
    # ErrorMessage :
    # Referral     : {}
    # Which Out-Null hides. But this also throws a proper error at least when you target a non-existing object.
    # Look into it.
}

function Invoke-LDAPQuery
{
    Param(
        [Parameter(Mandatory=$false)][String]$Filter = '(&(cn=Administrators))',
        [Parameter(Mandatory=$false)][String[]]$AttributeList
    )

    if (-not $AttributeList) {
        $AttributeList = '*'
    } elseif ($AttributeList -contains 'canonicalname' -and  $AttributeList -notcontains 'distinguishedname') {
        # Canonicalname is constructed from distinguishedname so going to be needing that
        $AttributeList += 'distinguishedname'
    }

    # NOTE Search paging explained here:
    # https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb332056(v=msdn.10)?redirectedfrom=MSDN#search-operations

    $scope = [SearchScope]::Subtree

    $searchRequest = New-Object -TypeName SearchRequest `
        -ArgumentList $searchbase, $Filter, $scope, $AttributeList

    $pageRequest = New-Object -TypeName PageResultRequestControl -ArgumentList $pageSize
    $searchRequest.Controls.Add($pageRequest)
    
    $searchResponse = Send-LDAP -Request $searchRequest
    if ($searchResponse.Controls.Length -ne 1 -or
        $searchResponse.Controls[0] -isnot [PageResultResponseControl]) {
        throw "The server cannot page the result set"
        return
    }
    while ($true) {
        $pageResponse = [PageResultResponseControl]$searchResponse.Controls[0]
        $pageRequest.Cookie = $pageResponse.Cookie
        $searchResponse = Send-LDAP -Request $searchRequest
        $searchResponse
        if ($pageResponse.Cookie.Length -eq 0) {
            return
        }
    }
}

function Add-LDAPObject
{
    Param(
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )][String]$Name,
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )][String]$OrganizationalUnit,
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )][String]$ObjectClass,
        [Parameter(
            Mandatory=$true,
            ValueFromPipelineByPropertyName=$true
        )][Hashtable]$AdditionalAttributes
    )

    if ($null -eq $Script:ldapServer) {
        $Script:ldapServer = Connect-LDAPServer
    }

    if ($OrganizationalUnit -notmatch ',DC=') { # TODO More robust test
        # Assume this is a CanonicalName
        $OrganizationalUnit = ConvertTo-DistinguishedName -CanonicalName $OrganizationalUnit
    }
    
    $DistinguishedName = "CN=$Name,$OrganizationalUnit"

    $addRequest = New-Object `
        -TypeName AddRequest -ArgumentList $DistinguishedName, $ObjectClass
    foreach ($attribute in $AdditionalAttributes.Keys) {
        $newAttribute = New-Object -TypeName DirectoryAttribute `
            -ArgumentList $attribute, $AdditionalAttributes[$attribute]
        $addRequest.Attributes.Add($newAttribute) | Out-Null
    }

    Send-LDAP -Request $addRequest
}

function Set-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)][String]$DistinguishedName,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Add', 'Delete', 'Replace')][String]$Operation,
        [Parameter(Mandatory=$true)][String]$AttributeName,
        [Parameter(Mandatory=$true)]$Values
    )
    if ($Operation -eq 'Replace') {
        $modifyRequest = New-Object -TypeName ModifyRequest `
            -ArgumentList $DistinguishedName, $Operation, $AttributeName, $Values
    } else {
        $modification = New-Object -TypeName DirectoryAttributeModification
        $modification.Name = $AttributeName
        $modification.Add($Values) | Out-Null
        $modification.Operation = $Operation
        $modifyRequest = New-Object -TypeName ModifyRequest -ArgumentList $DistinguishedName, $modification
    }

    Send-LDAP -Request $modifyRequest
}

function Remove-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)][String]$DistinguishedName
    )
    $deleteRequest = New-Object `
        -TypeName DeleteRequest -ArgumentList $DistinguishedName

    Send-LDAP -Request $deleteRequest
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

function ConvertTo-DistinguishedName
{
    param(
        [parameter(mandatory=$false)][String[]]$CanonicalName,
        [parameter(mandatory=$false)]
        [validateset('OU', 'CN')]
        [String]$LeafNamingAttribute = 'OU'
    )
    # cn=test user 3,ou=users,ou=org,dc=satan,dc=local
    # satan.local/org/users/test user 3
    foreach ($cn in $CanonicalName) {
        $domain, $path = $cn -split '/'
        $domain = $domain -split '\.'
        [Array]::Reverse($domain)
        $domain = ",DC=$($domain -join ',DC=')"
        [Array]::Reverse($path)
        $path = "$LeafNamingAttribute=$($path -join ',OU=')"
        "$path$domain"
    }
}

function Convert-SearchResultAttributeCollectionToPSCustomObject
{
    Param(
        [Parameter(Mandatory=$false)]
        [SearchResultAttributeCollection[]]$SearchResultAttributeCollection
    )
    foreach ($srac in $SearchResultAttributeCollection) {
        $attributeObject = [PSCustomObject]@{}
        $attributeNameList = $srac.Keys
        if ($srac.Keys -contains 'distinguishedname' -and $attributeNameList -notcontains 'canonicalname') {
            $attributeNameList += 'canonicalname'
        } 
        $attributeNameList = $attributeNameList | Sort-Object
        foreach ($attributeName in $attributeNameList) {
            if ($attributeName -eq 'member;range=0-1499') {
                $attributeName = 'member'
                $values = ''
            } elseif ($attributeName -eq 'member' -and $attributeNameList -contains ('member;range=0-1499')) {
                continue
            } elseif ($attributeName -eq 'member' -and 
                        $attributeNameList -notcontains ('member;range=0-1499')) {
                $values = ''
            } elseif ($attributename -eq 'canonicalname') {
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
        if (($attributeObject | Get-Member -MemberType NoteProperty).Name -contains 'member') {
            $filter = "(&(memberof=$($attributeObject.DistinguishedName)))"
            $attributeObject.member = (Invoke-LDAPQuery -Filter $filter `
                    -AttributeList 'distinguishedname').Entries | Foreach-Object {
                $_.Attributes['distinguishedname'].GetValues('string')
            }
        }
        $objectClassUser = 'organizationalPerson,person,top,user'
        $objectClassComputer = 'computer,organizationalPerson,person,top,user'
        $objectClassGroup = 'group,top'
        if ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassUser) {
            New-Object -TypeName LDAPUser -ArgumentList $attributeObject
        } elseif ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassComputer) {
            New-Object -TypeName LDAPComputer -ArgumentList $attributeObject
        } elseif ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassGroup) {
            New-Object -TypeName LDAPGroup -ArgumentList $attributeObject
        } else {
            $attributeObject | Select-Object -Property * -ExcludeProperty 'member;range=0-1499'
        }
    }
}

# NOTE ALL OF THE BELOW FUNCTIONS ARE MEANT TO BE USED INTERACTIVELY, NOT IN A SCRIPT.
# They make fuzzy searches so objects found and selected for modification might not 
# be what you'd expect.

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
        $filter += "(|(cn=$sTerm)(name=$sTerm)(samaccountname=$sTerm)(distinguishedname=$sTerm)"
        $filter += "(givenname=$sTerm)(sn=$sTerm)"
        if ($sTerm -match '@') {
            $filter += "(userprincipalname=$sTerm)(mail=$sTerm)"
        }
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

function Get-LDAPAttributeValueQueryFilter
{
    Param(
        [Parameter(Mandatory=$true)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String[]]$AttributeValue = "*",
        [Parameter(Mandatory=$false)][String]$ObjectClass
    )
    
    $filter = ''
    if ($ObjectClass) {
        $filter += "(&(objectclass=$ObjectClass)"
    }
    $filter += "(|"
    foreach ($sAttr in $SearchAttribute) {
        foreach ($vAttr in $AttributeValue) {
            $filter += "($sAttr=$vAttr)"
        }
    }
    $filter += ')'
    if ($ObjectClass) {
        $filter += ')'
    }
    return $filter
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
        $confirmMessage = 'You picked '
        switch ($key) {
            A {
                $confirmMessage += '[A]pply, working...'
                Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                return 'Apply'
            }
            S {
                $confirmMessage += '[S]elect objects, working...'
                Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                if ($PSVersionTable.OS -match 'Windows') {
                    $selected = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to select, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms.'
                    return $selected
                }
            }
            D {
                $confirmMessage += '[D]eselect, working...'
                Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
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
                $confirmMessage += 'cancel.'
                Write-Host $confirmMessage -ForegroundColor $cancelMessageColor
                return @()
            }
        }
    }
}

function Search-LDAP
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )

    # TODO There's probably a way to only write out specific default attributes
    # as cmdlets, or rather objects are tend to do. I seem to recall that requires 
    # defining a new class for the object which might not be possible on older 
    # versions of powershell.

    if (-not $SearchTerm) {
        $usage = "LDAPGet SearchTerm(s)", "LDAPGet SearchTerm(s) ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = 'Term to find objects by'
        $parameters['ReturnAttribute'] = "Which attributes to return per object '*' which is the default, means any value other than null."
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    foreach ($filter in (Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm)) {
        (Invoke-LDAPQuery -Filter $filter -AttributeList $ReturnAttribute).Entries | ForEach-Object {
            $result += Convert-SearchResultAttributeCollectionToPSCustomObject `
                -SearchResultAttributeCollection $_.Attributes
        }
    }
    if (-not $ReturnAttribute) {
        $result | Sort-Object -Property canonicalname
    } else {
        $selectSplat = @{}
        if ($ReturnAttribute.Count -eq 1) {
            $selectSplat.ExpandProperty = $ReturnAttribute[0]
        } elseif ($ReturnAttribute.Count -gt 1) {
            $selectSplat.Property = $ReturnAttribute
        }
        foreach ($entry in $result) {
            if ($ReturnAttribute.Count -eq 1 -and (-not $entry.$ReturnAttribute)) {
                continue
            }
            $entry | Select-Object @selectSplat
        }
    }
}

function Search-LDAPByAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String[]]$AttributeValue = "*",
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute = '*'
    )

    if (-not $SearchAttribute) {
        $usage = "LDAPGetBy SearchAttribute(s) AttributeValue(s) ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchAttribute'] = "Attributes in which to look for value"
        $parameters['AttributeValue'] = "Which values to look for in attributes. '*' which is the default, means any value other than null."
        $parameters['ReturnAttribute'] = "Which attributes to return per object. '*' is again the default."
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    $filters = Get-LDAPAttributeValueQueryFilter `
        -SearchAttribute $SearchAttribute -AttributeValue $AttributeValue
    foreach ($filter in $filters) {
        (Invoke-LDAPQuery -Filter $filter).Entries | ForEach-Object {
            $result += Convert-SearchResultAttributeCollectionToPSCustomObject `
                -SearchResultAttributeCollection $_.Attributes | `
                    Select-Object -Property $ReturnAttribute
        }
    }
    if (-not $ReturnAttribute) {
        $result | Sort-Object -Property canonicalname
    } else {
        $result | Select-Object $ReturnAttribute
    }
}

function Select-LDAPTargetObject
{
    Param(
        [Parameter(Mandatory=$true)]$LDAPObjectList,
        [Parameter(Mandatory=$true)][String]$Title
    )
    $apply = $false
    while ($apply -eq $false) {
        Write-Host $Title -ForegroundColor Yellow
        foreach ($ldapObject in $LDAPObjectList) {
            Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
        }
        if ($PSVersionTable.OS -match 'Windows') {
            $footer ='[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel'
        } else {
            $footer ='[A]pply, Esc to cancel'
        }
        Write-Host $footer -ForegroundColor Yellow
        $answer = Select-LDAPObject -ObjectList $LDAPObjectList
        if ($answer -eq 'Apply') {
            $apply = $true
        } else {
            $ldapObjectList = $answer
        }
        if ($ldapObjectList.Count -eq 0) {
            $apply = $true
        }
    }
    return $LDAPObjectList
}

function Search-LDAPAndSetAttributeValue
{
    param(
        [parameter(Mandatory=$false)][string[]]$searchterm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        $usage = "LDAPSet SearchTerm(s) Attribute Value", 
            "LDAPSet SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to modify"
        $parameters['Value'] = "Value to set to the attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to set attribute '$Attribute' to '$Value' on the following object(s):"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute -join ', '
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName $Attribute -Values $Value -ErrorAction Stop
            $msg = "'$objName' '$Attribute' set to '$Value'"
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error setting '$objName' '$Attribute' to '$Value': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Search-LDAPAndAddAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        $usage = "LDAPAdd SearchTerm(s) Attribute Value", 
            "LDAPAdd SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to modify"
        $parameters['Value'] = "Value to add to the attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to add attribute '$Attribute' to '$Value' on the following objects:"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.canonicalname
        $valName = $Value -join ', '
        $oldValue = $ldapObject.$Attribute -join ', '
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Add `
                -AttributeName $Attribute -Values $Value -ErrorAction Stop
            $msg = "'$objName' '$Attribute' value '$valName' added"
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error adding '$objName' '$Attribute' value '$valName': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Search-LDAPAndRemoveAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        $usage = "LDAPRem SearchTerm(s) Attribute Value", 
            "LDAPRem SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to remove value from"
        $parameters['Value'] = "Which value to remove from attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove attribute '$Attribute' from '$Value' the following objects:"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute -join ', '
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg
            Set-LDAPObject -DistinguishedName $ldapObject.distinguishedname -Operation Delete `
                -AttributeName $Attribute -Values $Value
            $msg = "'$objName' '$Attribute' '$Value' removed"
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName' '$Attribute' '$Value': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Search-LDAPAndClearAttribute
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute) {
        $usage = "LDAPClr SearchTerm(s) Attribute"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects by"
        $parameters['Attribute'] = "Which attribute to remove values from"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if (-not $ldapObjectList) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove all values from attribute '$Attribute' from the following objects:"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute -join ', '
        try {
            if ($oldValue) {
                $msg = "'$objname' '$attribute' is '$oldvalue'"
                write-log -message $msg
                foreach ($value in $ldapObject.$Attribute) {
                    Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Delete `
                        -AttributeName $Attribute -Values $value -ErrorAction Stop
                }
                $msg = "'$objName' '$Attribute' cleared"
                Write-Log -Message $msg
            } else {
                $msg = "'$objname' '$attribute' is already not set"
                write-log -message $msg
            }
        } catch {
            $err = $_.ToString()
            $msg = "Error clearing '$objName' '$Attribute': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Get-MembershipMap
{
    param(
        [parameter(mandatory=$false)]$LDAPGroupList,
        [parameter(mandatory=$false)]$LDAPMemberList
    )
    $membershipMap = @()
    foreach ($ldapGroup in $LDAPGroupList) {
        $LDAPMemberModifyList = $LDAPMemberList
        if ($LDAPMemberList -eq '*') {
            $filter = "(&(memberof=$($ldapGroup.DistinguishedName)))"
            $LDAPMemberModifyList = (Invoke-LDAPQuery -Filter $filter).Entries | Foreach-Object {
                Convert-SearchResultAttributeCollectionToPSCustomObject `
                    -SearchResultAttributeCollection $_.Attributes
            }
        }
        foreach ($ldapMember in $LDAPMemberModifyList) {
            $membershipMap += [PSCustomObject]@{
                Group = $ldapGroup
                Member = $ldapMember
                Name = "$($ldapGroup.canonicalname) - $($ldapMember.canonicalname)"
            }
        }
    }
    $membershipMap
}

function Select-LDAPGroupMemberModificationTarget
{
    param(
        [parameter(mandatory=$false)]$LDAPGroupList,
        [parameter(mandatory=$false)]$LDAPMemberList,
        [parameter(mandatory=$True)]
        [ValidateSet('Add','Remove')]$Operation,
        [parameter(mandatory=$false)]$Instructions
    )

    if ($Operation -eq 'Add') {
        $operationDescription = "About to add group members:"
        $direction = 'to'
    } elseif ($Operation -eq 'Remove') {
        $operationDescription = "About to remove group members:"
        $direction = 'from'
    }

    $membershipMap = Get-MembershipMap -LDAPGroupList $LDAPGroupList -LDAPMemberList $LDAPMemberList
    if ($Operation -eq 'Remove' -and -not $membershipMap) {
        Write-Host "There's no members in the passed groups to remove."
        return
    }
    $topLength = ($ldapMemberList.canonicalname | Measure-Object -Maximum -Property Length).Maximum
    $apply = $false
    while ($apply -eq $false) {
        Write-Host $OperationDescription -ForegroundColor Yellow
        foreach ($entry in $membershipMap) {
            $member = "'$($entry.Member.canonicalname)'"
            $member = $member.PadRight($topLength + 2) # The 2 is the ' surrounding $member
            $group = "'$($entry.Group.canonicalname)'"
            Write-Host "    $member $direction $group" -ForegroundColor Green
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

function Search-LDAPAndModifyGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation,
        [Parameter(Mandatory=$true)]
        [ValidateSet('Add', 'Remove')]
        [String]$Operation
    )

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

    if ($Operation -eq 'Remove' -and $SearchTermMember -eq '*') {
        $ldapMemberList = '*'
    } else {
        $ldapMemberList = Search-LDAP -SearchTerm $SearchTermMember
    }

    if ($ldapGroupList.Count -gt 0 -and $ldapMemberList.Count -gt 0) {
        if (-not $NoConfirmation.IsPresent) {
            $addToMap = Select-LDAPGroupMemberModificationTarget `
                -LDAPGroupList $ldapGroupList `
                -LDAPMemberList $ldapMemberList `
                -Operation $Operation `
                -Instructions $instructions
        } else {
            $addToMap = Get-MembershipMap `
                -LDAPGroupList $LDAPGroupList `
                -LDAPMemberList $LDAPMemberList
        }
        # NOTE Since group member lists are cached there's always a 
        #      possibility something else modifies it while this 
        #      function is doing the same
        $memberCache = @{}
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            if (-not ($memberCache.Keys -contains $groupDN)) {
                $memberFilter = "(&(memberof=$groupDN))"
                $memberCache.Add($groupDN, (Invoke-LDAPQuery -Filter $memberFilter).Entries.distinguishedname)
            }
            try {
                # TODO Work out the 'only 1500 members being returned with a group' issue, see 
                #      if returning to something like this is quicker
                # TODO Doing individual queries for members might well be faster than getting 
                #      all group members
                if ($Operation -eq 'Add') {
                    if ($memberCache[$groupDN] -contains $addtoEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' already contains '$groupMemName'"
                        Write-Log -Message $msg
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Add' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' added"
                        Write-Log -Message $msg
                    }
                }
                if ($Operation -eq 'Remove') {
                    if ($memberCache[$groupDN] -notcontains $addtoEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' does not contain '$groupMemName'"
                        Write-Log -Message $msg
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Delete' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' removed"
                        Write-Log -Message $msg
                    }
                }
            } catch {
                $err = $_.ToString()
                if ($Operation -eq 'Add') {
                    $msg = "Error adding '$groupCanName' member '$groupMemName': $err"
                } elseif ($Operation -eq 'Remove') {
                    $msg = "Error removing '$groupCanName' member '$groupMemName': $err"
                }
                Write-Log -Message $msg -Level Error
            }                
        }
    } else {
        if ($Operation -eq 'Add') {
            if ($ldapGroupList.Count -gt 0) {
                Write-Host "Found no members to add."
            } else {
                Write-Host "Found no groups to add members to."
            }
        } elseif ($Operation -eq 'Remove') {
            if ($ldapGroupList.Count -gt 0) {
                Write-Host "Found no members to remove."
            } else {
                Write-Host "Found no groups to remove members from."
            }
        }
    }
}

function Search-LDAPAndAddGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        $usage = "LDAPAddMember SearchTermGroup(s) SearchTermMember(s)", 
            "LDAPAddMember SearchTermGroup(s) SearchTermMember(s) -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['SearchTermMember'] = "Terms to find objects to add to groups"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }
    if (-not $NoConfirmation.IsPresent) {
        Search-LDAPAndModifyGroupMember `
            -SearchTermGroup $SearchTermGroup `
            -SearchTermMember $SearchTermMember `
            -Operation 'Add'
    } else {
        Search-LDAPAndModifyGroupMember `
            -SearchTermGroup $SearchTermGroup `
            -SearchTermMember $SearchTermMember `
            -Operation Add `
            -NoConfirmation
    }
}

function Search-LDAPAndRemoveGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        $usage = "LDAPAddMember SearchTermGroup(s) SearchTermMember(s)", 
            "LDAPAddMember SearchTermGroup(s) SearchTermMember(s) -NoConfirmation"
        $sTMInfo = "Terms to find objects to add to groups, use * to remove all members"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['SearchTermMember'] = $sTMInfo
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }
    if (-not $NoConfirmation.IsPresent) {
        Search-LDAPAndModifyGroupMember `
            -SearchTermGroup $SearchTermGroup `
            -SearchTermMember $SearchTermMember `
            -Operation Remove
    } else {
        Search-LDAPAndModifyGroupMember `
            -SearchTermGroup $SearchTermGroup `
            -SearchTermMember $SearchTermMember `
            -Operation Remove `
            -NoConfirmation
    }
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

function Search-LDAPAndResetPassword
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][SecureString]$NewPassword
    )
    
    # TODO Maybe let user to input one password and have 
    # randomly generated ones be protected by that. Save 
    # them in a zip file with a password on it or something. 
    # AND then don't echo the password...
    # AND when you do, maybe do this instead of 'objname pass set to <password>':
    # Account: Domain\Account
    # Password: <password>
    
    if (-not $SearchTerm) {
        $usage = "LDAPSetPass SearchTerm(s)", "LDAPSetPass SearchTerm(s) NewPassword"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects"
        $parameters['NewPassword'] = "Automatically generated if not provided"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

    # Code to convert password to correct format copied from the answer by Michael Frommhold MSFT:
    # https://social.technet.microsoft.com/Forums/en-US/7af21e17-18dc-4eea-8439-ffd9a2d5bcaf/reset-password-with-history-resulting-in-the-server-does-not-support-the-control-the-control-is?forum=winserverDS

    function ConvertTo-LDAPPassword
    {
        Param(
            [Parameter(Mandatory=$true)][SecureString]$Password
        )
        [string]$Password = ConvertFrom-SecureString -SecureString $Password -AsPlainText
        [byte[]]$ret = $null
        [string]$formattedpwd = [char]34 + $Password + [char]34
        $ret = [System.Text.Encoding]::Unicode.GetBytes($formattedpwd)
        return $ret
    }

    if ($NewPassword) {
        [byte[]]$NewPassword = ConvertTo-LDAPPassword $NewPassword
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to set password on the following objects:"
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            if ($NewPassword) {
                $newPass = $NewPassword
            } else {
                $newRandomPassword = Get-RandomString
                [byte[]]$newPass = ConvertTo-LDAPPassword `
                    -Password ($newRandomPassword | ConvertTo-SecureString -AsPlainText)
            }
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName 'unicodePwd' -Values $newPass -ErrorAction Stop
            $msg = "'$objName' password set"
            if (-not $NewPassword) {
                $msg = "$msg to $newRandomPassword"
            }
            Write-Host $msg
            $msg = "'$objName' password set"
            Write-Log -Message $msg -NoEcho
        } catch {
            $err = $_.ToString()
            $msg = "Error setting '$objName' password: $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Search-LDAPAndRemove
{
    param(
        [Parameter(Mandatory=$false)][string[]]$SearchTerm
    )
    if (-not $SearchTerm) {
        $usage = "LDAPRemObj SearchTerm(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects to remove"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }
    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove the following object(s):"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            Remove-LDAPObject -DistinguishedName $ldapObject.DistinguishedName `
                -ErrorAction Stop
            $msg = "'$objName' removed"
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

Set-Alias -Name LDAPGet -Value Search-LDAP
Set-Alias -Name LDAPGetBy -Value Search-LDAPByAttributeValue
Set-Alias -Name LDAPSet -Value Search-LDAPAndSetAttributeValue
Set-Alias -Name LDAPAdd -Value Search-LDAPAndAddAttributeValue
Set-Alias -Name LDAPRem -Value Search-LDAPAndRemoveAttributeValue
Set-Alias -Name LDAPClr -Value Search-LDAPAndClearAttribute
Set-Alias -Name LDAPAddMember -Value Search-LDAPAndAddGroupMember
Set-Alias -Name LDAPRemMember -Value Search-LDAPAndRemoveGroupMember
Set-Alias -Name LDAPAddObj -Value Add-LDAPObject
Set-Alias -Name LDAPRemObj -Value Search-LDAPAndRemove
Set-Alias -Name LDAPSetPass -Value Search-LDAPAndResetPassword
Set-Alias -Name LDAPGetLogList -Value Get-LDAPLogFileList

Export-ModuleMember -Function Search-LDAP, 
        Search-LDAPByAttributeValue, 
        Search-LDAPAndSetAttributeValue, 
        Search-LDAPAndAddAttributeValue, 
        Search-LDAPAndRemoveAttributeValue,
        Search-LDAPAndClearAttribute,
        Search-LDAPAndAddGroupMember,
        Search-LDAPAndRemoveGroupMember,
        Add-LDAPObject,
        Search-LDAPAndRemove,
        Search-LDAPAndResetPassword,
        Get-LDAPLogFileList `
    -Alias LDAPGet,
        LDAPGetBy,
        LDAPSet,
        LDAPAdd,
        LDAPRem,
        LDAPClr,
        LDAPAddMember,
        LDAPRemMember,
        LDAPAddObj,
        LDAPRemObj,
        LDAPSetPass,
        LDAPGetLogList

