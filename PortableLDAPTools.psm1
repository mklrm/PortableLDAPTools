
# NOTE System.DirectoryServices.Protocol seems to only be included in fairly recent 
# version of .Net Core so you'll be needing a recent version of powershell on Linux.

# TODO Writing out every single result (or preview of what's going to be happening either really) 
#      isn't very readable if you're adding say hundreds or thousands of members to a group 
#      or whatever else. Could:
#      Only display some arbitrary number of entries in the preview and let the user know 
#      that there's more on the list and the list can be accessed via a New-Menu shortcut...
#      the problem with doing that being New-Menu doesn't necessarily work under Linux. Should 
#      maybe start testing that.

# TODO There's a lot of repetition again particularly between the functions that modify objects, 
#      might want to try and centralize all of that as much as possible

using namespace System.DirectoryServices.Protocols
using namespace System.Collections.Specialized
using namespace System.Security.Principal

$objectClassUser = 'organizationalPerson,person,top,user'
$objectClassComputer = 'computer,organizationalPerson,person,top,user'
$objectClassGroup = 'group,top'

$psVersionMajor = $PSVersionTable.PSVersion.Major

if ($psVersionMajor -le 5) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Collections.Specialized")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
}

$scriptFileName = ($PSCommandPath | Split-Path -Leaf) -replace '\..*$'
$pathMyDocuments = [environment]::GetFolderPath('MyDocuments')

$configFile = "$pathMyDocuments\$scriptFileName.xml"
$config = Import-Clixml -Path $configFile

$activeConfig = $config.ConfigurationList | Where-Object { $_.Name -eq $config.ActiveConfigurationName }

$Script:ldapServerName = $activeConfig.ldapServerName
$Script:ldapPort = $activeConfig.ldapPort
$Script:userDomain = $activeConfig.userDomain
$Script:userName = $activeConfig.userName
$Script:userPassword = $activeConfig.userPassword
$Script:authType = $activeConfig.authType
$Script:searchbase = $activeConfig.searchbase
$Script:pageSize = $activeConfig.pageSize

# TODO Add to config file
# TODO Also I doubt this actually needs to be Global
$Global:searchLDAPReturnAttributes = 'sAMAccountName,UserPrincipalName,CanonicalName,DistinguishedName'
$Global:searchLDAPReturnAttributes = $Global:searchLDAPReturnAttributes -split ','

if (-not $Script:pageSize) {
    $Script:pageSize = 5000
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
    Param(
        [Parameter(Mandatory=$true)][SecureString]$Password
    )
    if (-not $Password) {
        Write-Host "Enter password for user $($Script:userDomain)\$($Script:userName):"
        $Password = Read-Host -AsSecureString
    }

    if ($Script:authType -eq 'Basic') {
        return New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList "$($Script:userDomain)\$($Script:userName)", $Password
    }

    if ($Script:authType -eq 'Negotiate') {
        if ($PSVersionTable.OS -match 'Linux') {
            return New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $($Script:userDomain)\$($Script:userName), $Password
        } else {
            return  New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $Script:userName, $Password, $Script:userDomain
        }
    }
}

function Connect-LDAPServer
{
    Param(
        [Parameter(Mandatory=$false)][SecureString]$Password
    )
    if ($null -eq $Script:credential) {
        if ($Password) {
            $Script:credential = Get-LDAPCredential -Password $Password
        } else {
            $Script:credential = Get-LDAPCredential
        }
    }
    $ldapServer = New-Object `
        -TypeName LdapConnection -ArgumentList "$($Script:ldapServerName):$($Script:ldapPort)", 
            $Script:credential, $Script:authType

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

function New-LDAPConnectionConfiguration
{
    Write-Host "Please enter..." -ForegroundColor Green
    Write-Host "Configuration name is used to pick between different configurations on the same computer."
    $configName = Read-Host -Prompt "Configuration name"
    Write-Host "`nLDAP server name could also be an IP address"
    $configServer = Read-Host -Prompt "LDAP server name"
    Write-Host "`nActive Directory listens to LDAP in 389 and LDAPS in 636 on default settings"
    $configPort = Read-Host -Prompt "LDAP server port"
    $msg = "`nDistinguishedName of the path where you want searches to start. Generally domain root " 
    $msg += "would be a good one for the purposes of this script."
    Write-Host $msg
    $configSearchBase = Read-Host -Prompt "SearchBase"
    Write-Host "`nDomain of the user you're using to connect to the LDAP server"
    $configUserDomain = Read-Host -Prompt "User domain"
    Write-Host "`nName of the user you're using to connect to the LDAP server"
    $configUserName = Read-Host -Prompt "User name"
    $msg = "`nPassword of the user you're using to connect to the LDAP server, enter nothing for " 
    $msg += "none and be required to enter a password once after importing the module and running a query. " 
    $msg += "Thereafter you will not be required to enter the password again for the duration of the "
    $msg += "powershell session or until you import the module again."
    Write-Host $msg
    $configUserPassword = Read-Host -Prompt "User password" -AsSecureString
    $msg = "`nNegotiation is a pretty good default for Active Directory unless you want to go for "
    $msg += "the Kerberos or nothing route."
    Write-Host $msg
    $configAuthentication = Read-Host -Prompt "Authentication (Negotiation is a good default for AD)"
    $msg =  "`nPage size determines how many results the LDAP server is asked to return at a "
    $msg +=  "time which has performance implications of the LDAP server. This script uses 5000 as the "
    $msg += "default if you enter none. This shouldn't choke pretty much any server and they tend to "
    $msg += "have protection anyway." 
    Write-Host $msg
    $configPageSize = Read-Host -Prompt "Page size"

    $newConfig = [PSCustomObject]@{
        configName = $configName
        ldapServerName = $configServer
        ldapPort = $configPort
        searchbase = $configSearchBase
        userDomain = $configUserDomain
        userName = $configUserName
        userPassword = $configUserPassword
        authType = $configAuthentication
        pageSize = $configPageSize
    }

    Write-Host "`nPlease review and edit any values you're not happy with." -ForegroundColor Yellow
    $newConfig = Edit-LDAPConnectionConfiguration -Configuration $newConfig

    if ($newConfig) {
        $config.ConfigurationList += $newConfig
        $hideKeysStrokes = $true
        Write-Host "Load the configuration [Y/N]?" -ForegroundColor Yellow
        $key = ([Console]::ReadKey($hideKeysStrokes)).Key
        switch ($key) {
            Y {
                $Script:ldapServerName = $newConfig.ldapServerName
                $Script:ldapPort = $newConfig.ldapPort
                $Script:userDomain = $newConfig.userDomain
                $Script:userName = $newConfig.userName
                $Script:userPassword = $newConfig.userPassword
                $Script:authType = $newConfig.authType
                $Script:searchbase = $newConfig.searchbase
                $Script:pageSize = $newConfig.pageSize
                Write-Host "Configuration loaded."
            }
            N {
                Write-Host "You picked [N]o."
            }
            Default {
                Write-Host "I'll take that as a [N]o."
            }
        }
        Write-Host "Set the configuration as active (meaning it's loaded when the module is imported) [Y/N]?" `
            -Foregroundcolor Yellow
        $key = ([Console]::ReadKey($hideKeysStrokes)).Key
        switch ($key) {
            Y {
                $config.ActiveConfigurationName = $newConfig.Name
                Write-Host "Configuration set as active."
            }
            N {
                Write-Host "You picked [N]o."
            }
            Default {
                Write-Host "I'll take that as a [N]o."
            }
        }
        $config | Export-Clixml -Path $configFile
    }
}

function Edit-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$true)][PSCustomObject]$Configuration
    )
    while ($true) {
        $msg = "1..Configuration name : $($Configuration.configName)`n" + `
               "2....LDAP server name : $($Configuration.ldapServerName)`n" + `
               "3....LDAP server port : $($Configuration.ldapPort)`n" + `
               "4..........SearchBase : $($Configuration.searchbase)`n" + `
               "5.........User domain : $($Configuration.userDomain)`n" + `
               "6...........User name : $($Configuration.userName)`n" + `
               "7.......User password : $($Configuration.userPassword)`n" + `
               "8......Authentication : $($Configuration.authType)`n" + `
               "9...........Page size : $($Configuration.pageSize)`n"
        Write-Host $msg 
        Write-Host "`nPick a number to modify a setting`n"
        Write-Host "[A]pply, Esc to cancel`n"
        $hideKeysStrokes = $true
        $key = ([Console]::ReadKey($hideKeysStrokes)).Key
        switch ($key) {
            D1 {
                Write-Host "Enter new value for configuration name"
                $Configuration.configName = Read-Host -Prompt "New value"
            }
            D2 {
                Write-Host "Enter new value for LDAP server name"
                $Configuration.ldapServerName = Read-Host -Prompt "New value"
            }
            D3 {
                Write-Host "Enter new value for LDAP server port"
                $Configuration.ldapPort = Read-Host -Prompt "New value"
            }
            D4 {
                Write-Host "Enter new value for search base"
                $Configuration.searchbase = Read-Host -Prompt "New value"
            }
            D5 {
                Write-Host "Enter new value for user domain"
                $Configuration.userDomain = Read-Host -Prompt "New value"
            }
            D6 {
                Write-Host "Enter new value for user name"
                $Configuration.userName = Read-Host -Prompt "New value"
            }
            D7 {
                Write-Host "Enter new value for user password"
                $Configuration.userPassword = Read-Host -Prompt "New value" -AsSecureString
            }
            D8 {
                Write-Host "Enter new value for authentication type"
                $Configuration.authType = Read-Host -Prompt "New value"
            }
            D9 {
                Write-Host "Enter new value for page size"
                $Configuration.pageSize = Read-Host -Prompt "New value"
            }
            A {
                Write-Host "[A]pplying settings"
                return $Configuration
            }
            Escape {
                Write-Host "Discarding"
                return $null
            }
        }
    }
}

function Remove-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$true)][String[]]$Name
    )
    # TODO Implement
}

function Write-Help
{
    Param(
        [Parameter(Mandatory=$true)][String]$Description,
        [Parameter(Mandatory=$true)][String[]]$Usage,
        [Parameter(Mandatory=$true)]$Parameter
    )
    $descriptionColor = 'Yellow'
    $colorUsgTitle = 'Green'
    $colorUsgMessage = $Host.UI.RawUI.ForegroundColor
    $colorMsgTitle = 'Yellow'
    $colorMsgMessage = $Host.UI.RawUI.ForegroundColor
    Write-Host
    Write-Host $Description -ForegroundColor $descriptionColor
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
        if ($Script:userPassword) {
            $Script:ldapServer = Connect-LDAPServer -Password $Script:userPassword
        } else {
            $Script:ldapServer = Connect-LDAPServer
        }
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

    $singleAttribute = $false
    if ($AttributeList.Count -eq 1) {
        $singleAttribute = $AttributeList[0]
    }

    if (-not $AttributeList) {
        $AttributeList = '*'
    } else {
        # Not having objectclass in objects will break parts of this script
        if ($AttributeList -notcontains 'objectclass') {
            $AttributeList += 'objectclass'
        }
        # Let's at least have something to display
        if ($AttributeList -notcontains 'cn') {
            $AttributeList += 'cn'
        }
        # Canonicalname is constructed from distinguishedname so going to be needing that
        if ($AttributeList -contains 'canonicalname' -and  $AttributeList -notcontains 'distinguishedname') {
            $AttributeList += 'distinguishedname'
        }
    }

    # NOTE Search paging explained here:
    # https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb332056(v=msdn.10)?redirectedfrom=MSDN#search-operations

    $scope = [System.DirectoryServices.SearchScope]::Subtree

    $searchRequest = New-Object -TypeName SearchRequest `
        -ArgumentList $Script:searchbase, $Filter, $scope, $AttributeList

    $pageRequest = New-Object -TypeName PageResultRequestControl -ArgumentList $Script:pageSize
    $searchRequest.Controls.Add($pageRequest) | Out-Null
    
    # TODO Send-LDAP throws an error when $Script:ldapServer.SendRequest($Request) is called and 
    #      'member' was passed on AttributeList, fix
    # TODO Also this first $searchResponse not being returned anywhere still doesn't seem right 
    #      although this all seems to be working, look into it
    $searchResponse = Send-LDAP -Request $searchRequest
    if ($searchResponse.Controls.Length -ne 1 -or
        $searchResponse.Controls[0] -isnot [PageResultResponseControl]) {
        throw "The server cannot page the result set"
    }
    while ($true) {
        $pageResponse = [PageResultResponseControl]$searchResponse.Controls[0]
        $pageRequest.Cookie = $pageResponse.Cookie
        $searchResponse = Send-LDAP -Request $searchRequest
        if ($singleAttribute) {
            # Convert the single attribute
            $searchResponse.Entries | ForEach-Object {
                # TODO This absolutely will not produce the right result for all attributes, 
                #      I'll have to modify Convert-InputObject to accept 
                #      and only convert single attributes or something. Maybe I should move 
                #      some of the logic outside of it or something as it is a pretty awful read
                if ($_.Attributes.Keys -contains $singleAttribute) {
                    $_.Attributes[$singleAttribute].GetValues('string')
                }
            }
        } else {
            $searchResponse.Entries | ForEach-Object {
                Convert-SearchResultAttributeCollection -InputObject $_.Attributes
            }
        }
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

function Convert-SearchResultAttributeCollection
{
    Param(
        [Parameter(Mandatory=$false)][SearchResultAttributeCollection[]]$InputObject
    )
    foreach ($attributeList in $InputObject) {
        $attributeObject = [PSCustomObject]@{}
        $attributeNameList = $attributeList.Keys
        if ($attributeList.Keys -contains 'distinguishedname' -and $attributeNameList -notcontains 'canonicalname') {
            $attributeNameList += 'canonicalname'
        } 

        if ($attributeNameList -contains 'member;range=0-1499') {
            # 'member;range=0-1499' being present means 'member' which will also be present 
            # and empty will be replaced
            $attributeNameList = $attributeNameList | Where-Object { $_ -ne 'member' }
        }
        $attributeNameList = $attributeNameList | Sort-Object

        foreach ($attributeName in $attributeNameList) {
            if ($attributeName -eq 'member;range=0-1499') {
                # This is a group with more than 1500 members which the rest of were not returned. There 
                # probably is some other way to get the rest but this works for now.
                $attributeName = 'member'
                $filter = "(&(memberof=$($attributeObject.DistinguishedName)))"
                $values = Invoke-LDAPQuery -Filter $filter -AttributeList 'distinguishedname'
            } elseif ($attributename -eq 'canonicalname') {
                $stringValues = $attributeList['distinguishedname'].GetValues('string')
                $values = ConvertTo-CanonicalName -DistinguishedName $stringValues | Select-Object -First 1
            } elseif ($attributeName -eq 'objectsid') {
                $values = $attributeList[$attributeName][0]
                # NOTE Only Windows is familiar with its SecurityIdentifiers
                if ($PSVersionTable.OS -match 'Windows' -or $psVersionMajor -le 5) {
                    if ($values -is [string]) { # NOTE Apparently some objects return 
                                                # the sid differently, such as the 
                                                # Active Directory Administrators group
                        $values = $attributeList[$attributeName].GetValues('Byte[]')[0]
                    }
                    $values = New-Object -TypeName SecurityIdentifier -ArgumentList $values, 0
                }
            } elseif ($attributeName -eq 'objectguid') {
                $values = $attributeList[$attributeName][0]
                $values = New-Object -TypeName System.Guid -ArgumentList @(,$values)
            } else {
                $values = $attributeList[$attributeName].GetValues('string')
                $values = foreach ($value in $values) {
                    if ($value -match '\.0Z$') {
                        $value = [DateTime]::ParseExact($value, 'yyyyMMddHHmmss.fK', $null)
                    }
                    $value
                }
            }
            $attributeObject | Add-Member -MemberType NoteProperty `
                -Name $attributeName -Value $values
        }

        if ($psVersionMajor -ge 5) {
            if ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassUser) {
                New-Object -TypeName LDAPUser -ArgumentList $attributeObject
            } elseif ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassComputer) {
                New-Object -TypeName LDAPComputer -ArgumentList $attributeObject
            } elseif ((($attributeObject.objectclass | Sort-Object) -join ',') -eq $objectClassGroup) {
                New-Object -TypeName LDAPGroup -ArgumentList $attributeObject
            }
        } else {
            $attributeObject
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
                if ($PSVersionTable.OS -match 'Windows' -or $psVersionMajor -le 5) {
                    $selected = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to select, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms.'
                    return $selected
                }
            }
            D {
                $confirmMessage += '[D]eselect, working...'
                Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                if ($PSVersionTable.OS -match 'Windows' -or $psVersionMajor -le 5) {
                    $deselectList = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to deselect, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms.'
                    if ($deselectList) {
                    $selectList = Compare-Object -ReferenceObject $ObjectList.Name `
                        -DifferenceObject $deselectList.Name -IncludeEqual | 
                        Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject
                    } else {
                        return $ObjectList
                    }
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
        [ArgumentCompleter({
            return $Global:searchLDAPReturnAttributes | ForEach-Object { $_ }
        })]
        [String[]]$ReturnAttribute
    )

    if (-not $SearchTerm) {
        $description = "Looks for objects by search terms and returns either all or requested return attributes. Search is fuzzy, you pass keywords that can include '*' as wildcards and the script attempts to find objects that have those values in attributes that generally identify an object such as Name, sAMAccountName, UserPrincipalName and so forth. So keep in mind that you are not making exact searches which is why these commands first let you know what is about to be done and you then have to choose to apply the changes."
        $usage = "LDAPGet SearchTerm(s)", "LDAPGet SearchTerm(s) ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = 'Term to find objects by'
        $parameters['ReturnAttribute'] = "Which attributes to return per object '*' which is the default, means any value other than null."
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    foreach ($filter in (Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm)) {
        $result += Invoke-LDAPQuery -Filter $filter -AttributeList $ReturnAttribute
    }
    $result
}

function Search-LDAPByAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String[]]$AttributeValue = "*",
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute = '*'
    )

    if (-not $SearchAttribute) {
        $description = "Looks for objects that have matching values in attributes."
        $usage = "LDAPGetBy SearchAttribute(s) AttributeValue(s) ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchAttribute'] = "Attributes in which to look for value"
        $parameters['AttributeValue'] = "Which values to look for in attributes. '*' which is the default, means any value other than null."
        $parameters['ReturnAttribute'] = "Which attributes to return per object. '*' is again the default."
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    $filters = Get-LDAPAttributeValueQueryFilter `
        -SearchAttribute $SearchAttribute -AttributeValue $AttributeValue
    foreach ($filter in $filters) {
        $result += Invoke-LDAPQuery -Filter $filter
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
        $i = 0 
        foreach ($ldapObject in $LDAPObjectList) {
            Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
        }
        if ($PSVersionTable.OS -match 'Windows' -or $psVersionMajor -le 5) {
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
        [parameter(Mandatory=$false)][string[]]$Searchterm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][String]$Value,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute -or -not $Value) {
        $description = "Finds objects by passed search terms and then attempts to set the value of an Attribute to Value."
        $usage = "LDAPSet SearchTerm(s) Attribute Value", 
            "LDAPSet SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to modify"
        $parameters['Value'] = "Value to set to the attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to set attribute '$Attribute' to '$Value' on the following object(s):"
    Write-Host "Working" -NoNewline -ForegroundColor Green # TODO Define color somewhere
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $valName = $Value -join ', '
        $oldValue = $ldapObject.$Attribute -join ', '
        if (-not $oldValue) {
            $oldValue = $ldapObject.attributes.$Attribute -join ', '
        }
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg -NoEcho
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName $Attribute -Values $Value -ErrorAction Stop
            $msg = "'$objName' '$Attribute' set to '$valName'"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
        } catch {
            $err = $_.ToString()
            $msg = "Error setting '$objName' '$Attribute' to '$valName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Red # TODO Define color somewhere
            $failures++
        }
    }
    $color = 'Green' # TODO Define color somewhere
    if ($failure -gt 0) {
        $color = 'Red' # TODO Define color somewhere
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
        -ForegroundColor $color
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
        $description = "Looks for objects by search terms and sets the Attribute to Value."
        $usage = "LDAPAdd SearchTerm(s) Attribute Value", 
            "LDAPAdd SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to modify"
        $parameters['Value'] = "Value to add to the attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to add attribute '$Attribute' to '$Value' on the following objects:"
    Write-Host "Working" -NoNewline -ForegroundColor Green # TODO Define color somewhere
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.canonicalname
        $valName = $Value -join ', '
        $oldValue = $ldapObject.$Attribute -join ', '
        if (-not $oldValue) {
            $oldValue = $ldapObject.Attributes.$Attribute -join ', '
        }
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg -NoEcho
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Add `
                -AttributeName $Attribute -Values $Value -ErrorAction Stop
            $msg = "'$objName' '$Attribute' value '$valName' added"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
        } catch {
            $err = $_.ToString()
            $msg = "Error adding '$objName' '$Attribute' value '$valName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Red # TODO Define color somewhere
            $failures++
        }
    }
    $color = 'Green' # TODO Define color somewhere
    if ($failure -gt 0) {
        $color = 'Red' # TODO Define color somewhere
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
        -ForegroundColor $color
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
        $description = "Finds objects by search terms and removes Value from Attribute."
        $usage = "LDAPRem SearchTerm(s) Attribute Value", 
            "LDAPRem SearchTerm(s) Attribute Value -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects by"
        $parameters['Attribute'] = "Which attribute to remove value from"
        $parameters['Value'] = "Which value to remove from attribute"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove value '$Value' attribute '$Attribute' the following objects:"
    Write-Host "Working" -NoNewLine -ForegroundColor Green # TODO Define color somewhere
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute
        if (-not $oldValue) {
            $oldValue = $ldapObject.Attributes.$Attribute
        }
        try {
            $msg = "'$objName' '$Attribute' is '$($oldValue -join ', ')'"
            Write-Log -Message $msg -NoEcho
            Set-LDAPObject -DistinguishedName $ldapObject.distinguishedname -Operation Delete `
                -AttributeName $Attribute -Values $Value
            $msg = "'$objName' '$Attribute' '$Value' removed"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName' '$Attribute' '$Value': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Red # TODO Define color somewhere
            $failures++
        }
    }
    $color = 'Green' # TODO Define color somewhere
    if ($failure -gt 0) {
        $color = 'Red' # TODO Define color somewhere
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
        -ForegroundColor $color
}

function Search-LDAPAndClearAttribute
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$Attribute,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTerm -or -not $Attribute) {
        $description = "Looks for objects by search terms and removes all values from Attribute."
        $usage = "LDAPClr SearchTerm(s) Attribute"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects by"
        $parameters['Attribute'] = "Which attribute to remove values from"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if (-not $ldapObjectList) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove all values from attribute '$Attribute' from the following objects:"
    Write-Host "Working" -NoNewline -ForegroundColor Green # TODO Define color somewhere
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $oldValue = $ldapObject.$Attribute
        if (-not $oldValue) {
            $oldValue = $ldapObject.Attributes.$Attribute
        }
        try {
            if ($oldValue) {
                $msg = "'$objname' '$attribute' is '$($oldValue -join ',')'"
                write-log -message $msg -NoEcho
                foreach ($value in $oldValue) {
                    Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Delete `
                        -AttributeName $Attribute -Values $value -ErrorAction Stop
                }
                $msg = "'$objName' '$Attribute' cleared"
                Write-Log -Message $msg -NoEcho
            } else {
                $msg = "'$objname' '$attribute' is already not set"
                write-log -message $msg -NoEcho
            }
            Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
        } catch {
            $err = $_.ToString()
            $msg = "Error clearing '$objName' '$Attribute': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            $failures++
        }
    }
    $color = 'Green' # TODO Define color somewhere
    if ($failure -gt 0) {
        $color = 'Red' # TODO Define color somewhere
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
        -ForegroundColor $color
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
            $LDAPMemberModifyList = Invoke-LDAPQuery -Filter $filter
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
    if ($PSVersionTable.OS -and  $PSVersionTable.OS -notmatch 'Windows') {
        $instructions = '[A]pply, Esc to cancel'
    }

    $ldapGroupFilters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTermGroup -ObjectClass Group
    $ldapGroupList = foreach ($filter in $ldapGroupFilters) {
        Invoke-LDAPQuery -Filter $filter
    }

    if ($Operation -eq 'Remove' -and $SearchTermMember -eq '*') {
        $ldapMemberList = '*'
    } else {
        $ldapMemberList = Search-LDAP -SearchTerm $SearchTermMember
    }

    if ($ldapGroupList.Count -gt 0 -and $ldapMemberList.Count -gt 0) {
        if (-not $NoConfirmation.IsPresent) {
            # TODO Rename $addToMap and similar var names in this function as they 
            #      now pertain to the removal action too
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
        Write-Host "Working" -NoNewline -ForegroundColor Green # TODO Define color somewhere
        $failures = 0
        foreach ($addtoEntry in $addToMap) {
            $groupDN = $addtoEntry.Group.DistinguishedName
            $memberDN = $addtoEntry.Member.DistinguishedName
            $groupCanName = $addtoEntry.Group.canonicalname
            $groupMemName = $addToEntry.Member.canonicalname
            if (-not ($memberCache.Keys -contains $groupDN)) {
                $memberFilter = "(&(memberof=$groupDN))"
                $memberCache.Add($groupDN, (Invoke-LDAPQuery -Filter $memberFilter `
                    -AttributeList 'distinguishedname'))
            }
            try {
                if ($Operation -eq 'Add') {
                    if ($memberCache[$groupDN] -contains $addtoEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' already contains '$groupMemName'"
                        Write-Log -Message $msg -NoEcho
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Add' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' added"
                        Write-Log -Message $msg -NoEcho
                    }
                }
                if ($Operation -eq 'Remove') {
                    if ($memberCache[$groupDN] -notcontains $addtoEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' does not contain '$groupMemName'"
                        Write-Log -Message $msg -NoEcho
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Delete' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' removed"
                        Write-Log -Message $msg -NoEcho
                    }
                }
                Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
            } catch {
                $err = $_.ToString()
                if ($Operation -eq 'Add') {
                    $msg = "Error adding '$groupCanName' member '$groupMemName': $err"
                } elseif ($Operation -eq 'Remove') {
                    $msg = "Error removing '$groupCanName' member '$groupMemName': $err"
                }
                Write-Log -Message $msg -Level Error -NoEcho
                Write-Host '.' -NoNewline -ForegroundColor Red # TODO Define color somewhere
                $failures++
            }                
        }
        $color = 'Green' # TODO Define color somewhere
        if ($failure -gt 0) {
            $color = 'Red' # TODO Define color somewhere
        }
        Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
            -ForegroundColor $color
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
        $description = "Finds groups and objects to add as members to said groups. Allows user to pick which objects to add to which groups via an interactive menu."
        $usage = "LDAPAddMember SearchTermGroup(s) SearchTermMember(s)", 
            "LDAPAddMember SearchTermGroup(s) SearchTermMember(s) -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['SearchTermMember'] = "Terms to find objects to add to groups"
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help $description -Usage $usage -Parameter $parameters
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
        $description = "Finds groups and objects to attempt to remove from said groups. Passing '*' as SearchTermMember offers to remove all current members of a group. Allows user to pick which objects to add to which groups via an interactive menu."
        $usage = "LDAPAddMember SearchTermGroup(s) SearchTermMember(s)", 
            "LDAPAddMember SearchTermGroup(s) SearchTermMember(s) -NoConfirmation"
        $sTMInfo = "Terms to find objects to add to groups, use * to remove all members"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['SearchTermMember'] = $sTMInfo
        $parameters['NoConfirmation'] = "Command will not ask you for confirmation"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
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

function Get-LDAPGroupMemberRecursive
{
    Param(
        [Parameter(Mandatory=$true)][LDAPGroup]$LDAPGroup,
        [Parameter(Mandatory=$false)][String]$DisplayPropertyName = 'cn',
        [Parameter(Mandatory=$false)][LDAPGroup[]]$ProcessedLDAPGroupList
    )

    if ($psVersionMajor -lt 5) {
        $msg  = "This function uses classes which were inroduced in version "
        $msg += "5.0 of powershell which itself is ancient, please upgrade."
        return
    }

    # Return if the group has already been processed, otherwise we'll likely end up in an endless loop
    if ($ProcessedLDAPGroupList.distinguishedname -contains $LDAPGroup.distinguishedname) {
        return
    }

    if (-not $ProcessedLDAPGroupList) {
        $ProcessedLDAPGroupList = @()
    }

    $ProcessedLDAPGroupList += $LDAPGroup

    $attributeList = 'distinguishedname', $DisplayPropertyName
    $filter = "(&(memberof=$($LDAPGroup.distinguishedname)))"
    $memberList = Invoke-LDAPQuery -Filter $filter -AttributeList $attributeList

    $recursiveMemberOfPath = ''
    foreach ($processedLDAPGroup in $ProcessedLDAPGroupList) {
        $recursiveMemberOfPath += "$($processedLDAPGroup.$DisplayPropertyName) > "
    }

    foreach ($member in $memberList) {
        "$recursiveMemberofPath$($member.$DisplayPropertyName)"

        if ((($member.objectclass | Sort-Object) -join ',') -eq $objectClassGroup) {
            Get-LDAPGroupMemberRecursive -LDAPGroup $member `
                -DisplayProperty $DisplayPropertyName `
                -ProcessedLDAPGroupList $ProcessedLDAPGroupList
        }
    }
}

function Search-LDAPGroupAndGetMembersRecursive
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$DisplayPropertyName = 'cn'
    )

    if (-not $SearchTerm) {
        $description = "Finds groups by search terms and attempts to represent "
        $description += "members recursively in an easily readable form."
        $usage = "LDAPGetMemberRecursive SearchTerm(s)", 
            "LDAPGetMemberRecursive SearchTermMember(s) DisplayPropertyName"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermGroup'] = "Terms to find groups"
        $parameters['DisplayPropertyName'] = "Which attribute to use for object representation"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    if ($psVersionMajor -lt 5) {
        $msg  = "This function uses classes which were inroduced in version "
        $msg += "5.0 of powershell which itself is ancient, please upgrade."
        return
    }

    $attributeList = 'distinguishedname', $DisplayPropertyName
    $groupList = @()
    foreach ($filter in (Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm -ObjectClass group)) {
        $groupList += Invoke-LDAPQuery -Filter $filter -AttributeList $attributeList
    }
    
    foreach ($group in $groupList) {
        Get-LDAPGroupMemberRecursive -LDAPGroup $group -DisplayPropertyname $DisplayPropertyName
    }
}

function Get-LDAPGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm
    )
    $ldapGroupFilters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm -ObjectClass Group
    $ldapGroupList = foreach ($filter in $ldapGroupFilters) {
        Invoke-LDAPQuery -Filter $filter
    }
    foreach ($ldapGroup in $ldapGroupList) {
        foreach ($memberDN in $ldapGroup.member) {
            Invoke-LDAPQuery -Filter "(&(distinguishedname=$memberDN))"
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
        $description = "Looks for objects by search terms and changes their passwords."
        $usage = "LDAPSetPass SearchTerm(s)", "LDAPSetPass SearchTerm(s) NewPassword"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Term to find objects"
        $parameters['NewPassword'] = "Automatically generated if not provided"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
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
        $description = "Looks for objects by search terms and removes them."
        $usage = "LDAPRemObj SearchTerm(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects to remove"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }
    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to remove the following object(s):"
    Write-Host "Working" -NoNewline -ForegroundColor Green # TODO Define color somewhere
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            Remove-LDAPObject -DistinguishedName $ldapObject.DistinguishedName `
                -ErrorAction Stop
            $msg = "'$objName' removed"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Green # TODO Define color somewhere
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor Red # TODO Define color somewhere
            $failures++
        }
    }
    $color = 'Green' # TODO Define color somewhere
    if ($failure -gt 0) {
        $color = 'Red' # TODO Define color somewhere
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $logFileFullName for details." `
        -ForegroundColor $color
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
Set-Alias -Name LDAPGetMemberRecursive -Value Search-LDAPGroupAndGetMembersRecursive

Export-ModuleMember -Function `
        Invoke-LDAPQuery,        
        Search-LDAP, 
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
        Get-LDAPLogFileList,
        New-LDAPConnectionConfiguration,
        Edit-LDAPConnectionConfiguration,
        Remove-LDAPConnectionConfiguration,
        Get-LDAPGroupMember,
        Search-LDAPGroupAndgetMembersRecursive `
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
        LDAPGetLogList,
        LDAPGetMemberRecursive
