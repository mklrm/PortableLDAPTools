
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

# TODO Add a function that returns a list of log files

# TODO Regenerate the log file name when running a query, inform if it changes (day changes)

# TODO Readable group membership (Not a list of distinguishednames)
#      Maybe return the members as objects and make canonicalname the string representation

# TODO Recursive group membership handleification

# TODO Could move to some sort of Search-LDAPObjectAndSomethingSomething-format with function names
#      _SHOULD_ do so with the functions made for human consumption
#      ...and Select- where that's applicable. There may be other options.

# TODO Add a summary of what the function does at the top of each help text

# TODO Add -NoConfirmation to the add and remove group member functions, 
#      probably might as well add it to some others too.

# TODO Ask for connection values, give ready choices to pick from for things that can (like default ports)

# TODO Still got issues with large groups (this is from a search result already converted to PSCustomObject):
# member                :
# member;range=0-1499   : {CN=test user Y 3493,OU=users,OU=org,DC=satan,DC=local, ...}

using namespace System.DirectoryServices.Protocols
using namespace System.Collections.Specialized

$scriptFileName = ($PSCommandPath | Split-Path -Leaf) -replace '\..*$'

$configFile = "$PSScriptRoot\$scriptFileName.xml"
$config = Import-Clixml -Path $configFile

$ldapServerName = $config.ldapServerName
$ldapPort = $config.ldapPort
$userDomain = $config.userDomain
$userName = $config.userName
$authType = $config.authType
$searchbase = $config.searchbase

$pageSize = 5000 # TODO Probably should read from config if available

$Script:credential = $null
$Script:ldapServer = $null

$logFileEncoding = 'utf8'
$logFileName = "$scriptFileName-$(Get-Date -Format 'yyyy.MM.dd').log"
$logFileNameFilter = "$scriptFileName-*.log"

$pathMyDocuments = [environment]::GetFolderPath('MyDocuments')
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
        -TypeName System.DirectoryServices.Protocols.LdapConnection `
        -ArgumentList "$($ldapServerName):$ldapPort", $credential, $authType

    $ldapServer.SessionOptions.SecureSocketLayer = $true
    #$ldapServer.SessionOptions.Sealing = $true
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
    $logMessage = "[$(Get-Date -Format 'yyyy.MM.dd HH\:mm\:ss')] $Message"
    switch ($Level) {
        'Informational' {
            $foregroundColor = $HOST.UI.RawUI.ForegroundColor
            $backgroundColor = $HOST.UI.RawUI.BackgroundColor
        }
        'Error' {
            # TODO Maybe there's a way to determine the color 
            # that's being used for error messages, for now 
            # doing this should be a safe bet
            $foregroundColor = $HOST.UI.RawUI.BackgroundColor
            $backgroundColor = $HOST.UI.RawUI.ForegroundColor
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

function Get-LDAPLog {
    Get-ChildItem $logFileNameFullNameFilter | Select-Object -ExpandProperty FullName | Sort-Object
}

try {
    $msg = "$PSCommandPath loading"
    Write-Log -Message $msg -ErrorAction Stop
} catch {
    $err = $_.ToString()
    throw "Error writing to log file $($logFileFullName): $err"
}

Write-Log -Message "Logging to $logFileFullName"

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

function Send-LDAPRequest
{
    Param(
        [Parameter(Mandatory=$true)]$Request # TODO Rename and add type...
    )

    if ($null -eq $Script:ldapServer) {
        $Script:ldapServer = Connect-LDAPServer
    }
    try {
        $Script:ldapServer.SendRequest($Request) | ForEach-Object {
            if ($_ -is [System.DirectoryServices.Protocols.AddResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -is [System.DirectoryServices.Protocols.DeleteResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -isnot [System.DirectoryServices.Protocols.ModifyResponse]) {
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
            Send-LDAPRequest -Request $Request
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
        [Parameter(Mandatory=$false)][String]$Filter = '(&(cn=Administrators))'
    )

    # NOTE Search paging explained here:
    # https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb332056(v=msdn.10)?redirectedfrom=MSDN#search-operations

    $scope = [System.DirectoryServices.Protocols.SearchScope]::Subtree
    $attributeList = @('*') # TODO Add a parameter for this and don't default to everything...

    $searchRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.SearchRequest `
        -ArgumentList $searchbase, $Filter, $scope, $attributeList

    $pageRequest = New-Object -TypeName PageResultRequestControl -ArgumentList $pageSize
    $searchRequest.Controls.Add($pageRequest)
    
    $searchResponse = Send-LDAPRequest -Request $searchRequest
    if ($searchResponse.Controls.Length -ne 1 -or
        $searchResponse.Controls[0] -isnot [PageResultResponseControl]) {
        throw "The server cannot page the result set"
        return
    }
    while ($true) {
        $pageResponse = [PageResultResponseControl]$searchResponse.Controls[0]
        $pageRequest.Cookie = $pageResponse.Cookie
        $searchResponse = Send-LDAPRequest -Request $searchRequest
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
        -TypeName System.DirectoryServices.Protocols.AddRequest `
        -ArgumentList $DistinguishedName, $ObjectClass
    foreach ($attribute in $AdditionalAttributes.Keys) {
        $newAttribute = New-Object `
            -TypeName System.DirectoryServices.Protocols.DirectoryAttribute `
            -ArgumentList $attribute, $AdditionalAttributes[$attribute]
        $addRequest.Attributes.Add($newAttribute) | Out-Null
    }

    Send-LDAPRequest -Request $addRequest
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
        $modifyRequest = New-Object `
            -TypeName System.DirectoryServices.Protocols.ModifyRequest `
            -ArgumentList $DistinguishedName, $Operation, $AttributeName, $Values
    } else {
        $modification = New-Object `
            -TypeName System.DirectoryServices.Protocols.DirectoryAttributeModification
        $modification.Name = $AttributeName
        $modification.Add($Values) | Out-Null
        $modification.Operation = $Operation
        $modifyRequest = New-Object `
            -TypeName System.DirectoryServices.Protocols.ModifyRequest `
            -ArgumentList $DistinguishedName, $modification
    }

    Send-LDAPRequest -Request $modifyRequest
}

function Remove-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)][String]$DistinguishedName
    )
    $deleteRequest = New-Object `
        -TypeName System.DirectoryServices.Protocols.DeleteRequest `
        -ArgumentList $DistinguishedName

    Send-LDAPRequest -Request $deleteRequest
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
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute = '*'
    )

    # TODO There's probably a way to only write out specific default attributes
    # as cmdlets, or rather objetcs are tend to do. I seem to recall that requires 
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

function Get-LDAPObjectByAttributeValue
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
    if ($NoConfirmation.IsPresent) {
        $apply = $true
    }
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

function Set-LDAPObjectAttributeValue
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

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
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

function Add-LDAPObjectAttributeValue
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

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
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
            $msg = "'$objName' '$Attribute' value '$valName' added" # TODO Maybe report the whole new value set
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error adding '$objName' '$Attribute' value '$valName': $err"
            Write-Log -Message $msg -Level Error
        }
    }
}

function Remove-LDAPObjectAttributeValue
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

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
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

function Clear-LDAPObjectAttribute
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

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove all values from attribute '$Attribute' from the following objects:"
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute -join ', '
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Delete `
                -AttributeName $Attribute -Values $ldapObject.$Attribute -ErrorAction Stop
            $msg = "'$objName' '$Attribute' cleared"
            Write-Log -Message $msg
        } catch {
            $err = $_.ToString()
            $msg = "Error clearing '$objName' '$Attribute': $err"
            Write-Log -Message $msg -Level Error
        }
    }
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

    $membershipMap = @()
    foreach ($ldapGroup in $LDAPGroupList) {
        foreach ($ldapMember in $LDAPMemberList) {
            $membershipMap += [PSCustomObject]@{
                Group = $ldapGroup
                Member = $ldapMember
                Name = "$($ldapGroup.canonicalname) - $($ldapMember.canonicalname)"
            }
        }
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

function Add-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        $usage = "LDAPAddMember SearchTermGroup(s) SearchTermMember(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['SearchTermMember'] = "Terms to find objects to add to groups"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

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
            -Operation 'Add' -Instructions $instructions
        # NOTE Since group member lists are cached there's always a 
        #      possibility something else modifies it while this 
        #      function is doing the same
        $memberCache = @{}
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            if (-not $memberCache[$groupDN]) {
                $memberFilter = "(&(memberof=$groupDN))"
                $memberCache.Add($groupDN, (Invoke-LDAPQuery -Filter $memberFilter).Entries.distinguishedname)
            }
            try {
                # TODO Work out the 'only 1500 members being returned with a group' issue, see 
                #      if returning to something like this is quicker
                # TODO Doing individual queries for members might well be faster than getting 
                #      all group members
                #if ($addtoEntry.Group.member -contains $addtoEntry.Member.distinguishedname) {
                if ($memberCache[$groupDN] -contains $addtoEntry.Member.distinguishedname) {
                    $msg = "'$groupCanName' already contains '$groupMemName'"
                    Write-Log -Message $msg
                } else {
                    Set-LDAPObject -DistinguishedName $groupDN -Operation 'Add' -AttributeName member `
                        -Values $memberDN -ErrorAction Stop
                    $msg = "'$groupCanName' member '$groupMemName' added"
                    Write-Log -Message $msg
                }
            } catch {
                $err = $_.ToString()
                $msg = "Error adding '$groupCanName' member '$groupMemName': $err"
                Write-Log -Message $msg -Level Error
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
        $usage = "LDAPRemMember SearchTermGroup(s) SearchTermMember(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Term to find groups"
        $parameters['SearchTermMember'] = "Term to find objects to remove from groups"
        Write-Help -Usage $usage -Parameter $parameters
        return
    }

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
            -Operation 'Remove' -Instructions $instructions
        # NOTE Since group member lists are cached there's always a 
        #      possibility something else modifies it while this 
        #      function is doing the same
        $memberCache = @{}
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            if (-not $memberCache[$groupDN]) {
                $memberFilter = "(&(memberof=$groupDN))"
                $memberCache.Add($groupDN, (Invoke-LDAPQuery -Filter $memberFilter).Entries.distinguishedname)
            }
            try {
                # TODO Work out the 'only 1500 members being returned with a group' issue, see 
                #      if returning to something like this is quicker
                # TODO Doing individual queries for members might well be faster than getting 
                #      all group members
                #if ($addtoEntry.Group.member -notcontains $addtoEntry.Member.distinguishedname) {
                if ($memberCache[$groupDN] -notcontains $addtoEntry.Member.distinguishedname) {
                    $msg = "'$groupCanName' does not contain '$groupMemName'"
                    Write-Log -Message $msg
                } else {
                    Set-LDAPObject -DistinguishedName $groupDN -Operation 'Delete' -AttributeName member `
                        -Values $memberDN -ErrorAction Stop
                    $msg = "'$groupCanName' member '$groupMemName' removed"
                    Write-Log -Message $msg
                }
            } catch {
                $err = $_.ToString()
                $msg = "Error removing '$groupCanName' member '$groupMemName': $err"
                Write-Log -Message $msg -Level Error
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

function Reset-LDAPObjectPassword
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

    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
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

function Search-LDAPObjectAndRemove
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
    $ldapObjectList = Get-LDAPObject -SearchTerm $SearchTerm
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

Set-Alias -Name LDAPGet -Value Get-LDAPObject
Set-Alias -Name LDAPGetBy -Value Get-LDAPObjectByAttributeValue
Set-Alias -Name LDAPSet -Value Set-LDAPObjectAttributeValue
Set-Alias -Name LDAPAdd -Value Add-LDAPObjectAttributeValue
Set-Alias -Name LDAPRem -Value Remove-LDAPObjectAttributeValue
Set-Alias -Name LDAPClr -Value Clear-LDAPObjectAttribute
Set-Alias -Name LDAPAddMember -Value Add-LDAPGroupMember
Set-Alias -Name LDAPRemMember -Value Remove-LDAPGroupMember
Set-Alias -Name LDAPAddObj -Value Add-LDAPObject
Set-Alias -Name LDAPRemObj -Value Search-LDAPObjectAndRemove
Set-Alias -Name LDAPSetPass -Value Reset-LDAPObjectPassword

