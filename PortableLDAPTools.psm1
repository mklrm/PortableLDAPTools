
# PortableLDAPTools.psm1 / Lauri Mikkola 2021

using namespace System.DirectoryServices.Protocols
using namespace System.Collections.Specialized
using namespace System.Security.Principal

$objectClassUser = 'organizationalPerson,person,top,user'
$objectClassComputer = 'computer,organizationalPerson,person,top,user'
$objectClassGroup = 'group,top'
$objectClassOrganizationalUnit = 'organizationalUnit,top'
$objectClassContainer = 'container,top'

$canonicalNamePattern = '^([\w]{1,}\.{1}[\w]{1,}){1,}/'
$distinguishedNamePattern = ',DC=.*?$'

$psVersionMajor = $PSVersionTable.PSVersion.Major

if ($psVersionMajor -le 5) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Collections.Specialized")
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal")
}

$dateTimeStringFormat = 'yyyy\.MM\.dd-HH\.mm\.ss'

$scriptFileName = ($PSCommandPath | Split-Path -Leaf) -replace '\..*$'
$pathMyDocuments = [environment]::GetFolderPath('MyDocuments')
$pathScriptFiles = "$pathMyDocuments\$scriptFileName"
$configFile = "$pathScriptFiles\$scriptFileName.xml"

$logFileEncoding = 'utf8'
$logFileName = "$scriptFileName-$(Get-Date -Format 'yyyy.MM.dd').log"
$logFileNameFilter = "$scriptFileName-*.log"
$Script:logFileFullName = "$pathScriptFiles\$logFileName"
$logFileNameFullNameFilter = "$pathScriptFiles\$logFileNameFilter"

$csvFileEncoding = 'utf8'
$csvFileDelimiter = ';'

$Script:credential = $null
$Script:ldapServer = $null
$Script:ServerSupportsPaging = $null
$newMenuLoaded = $false
if (Get-Module -Name New-Menu) {
    $newMenuLoaded = $true
}

if ($config.logFileFullName) {
    $Script:logFileFullName = $config.logFileFullName
}

$confirmMessageColor = $Host.PrivateData.FormatAccentColor # NOTE Used this for now because the default is green
if (-not $confirmMessageColor) {
    $confirmMessageColor = 'Green'
}
$cancelMessageColor = $Host.PrivateData.WarningForegroundColor
$happyMessageColor = 'Green'
$warningMessageColor = 'Yellow'
$attentionMessageColor = 'White'
$rageMessageColor = 'Red'
$disappointedMessageColor = 'DarkMagenta'

$attributeMap = @{
    'SurName' = 'sn'
}

# INTERNAL FUNCTIONS

function Write-Log
{
    Param(
        [Parameter(Mandatory=$true)][String]$Message,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Informational', 'Error')]
        [String]$Level = 'Informational',
        [Parameter(Mandatory=$false)][Switch]$NoEcho
    )
    if (-not (Test-Path -Path $pathScriptFiles)) {
        try {
            New-Item -Path $pathScriptFiles -ErrorAction Stop | Out-Null
        } catch {
            throw "Error creating directory $pathScriptFilesfor for log files: $($_.TroString())"
        }
    }
    $logFileName = "$scriptFileName-$(Get-Date -Format 'yyyy.MM.dd').log"
    $Script:logFileFullName = "$pathScriptFiles\$logFileName"
    $logMessage = "[$(Get-Date -Format 'yyyy.MM.dd HH\:mm\:ss')] $Message"
    switch ($Level) {
        'Informational' {
            $foregroundColor = $HOST.UI.RawUI.ForegroundColor
            $backgroundColor = $HOST.UI.RawUI.BackgroundColor
        }
        'Error' {
            $foregroundColor = $HOST.PrivateData.ErrorForegroundColor
            $backgroundColor = $HOST.PrivateData.ErrorBackgroundColor
        }
    }
    if (-not $NoEcho.IsPresent) {
        Write-Host -Object $Message `
            -ForegroundColor $foregroundColor `
            -BackgroundColor $backgroundColor
    }
    $logMessage | Out-File -FilePath $Script:logFileFullName `
        -Encoding $logFileEncoding -Append -Force
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

function Convert-SearchResultAttributeCollection
{
    Param(
        [Parameter(Mandatory=$false)][SearchResultAttributeCollection[]]$InputObject,
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )
    foreach ($attributeList in $InputObject) {

        $attributeObject = [PSCustomObject]@{}
        
        if ($ReturnAttribute.Count -eq 1) {
            if ($attributeList.Keys -contains $ReturnAttribute) {
                if ($ReturnAttribute[0] -eq 'member' -and $AttributeList.Keys -contains 'member;range=0-1499') {
                    # Since 'member;range=0-1499' is on the attribute list 'member' will be empty. 
                    # Pick 'member;range=0-1499' as the single attribute instead of 'member' and it 
                    # will be used as a signal later to build 'member' with all members included. 
                    # DistinguishedName is required for getting the group members.
                    $attributeNameList = 'DistinguishedName', 'member;range=0-1499'
                } else {
                    $attributeNameList = $ReturnAttribute
                }
            } else {
                # The requested return attribute is not on the attribute list
                return
            }
        } else {
            # If a list of specific attributes to return were passed only process 
            # attributes on that list and drop the rest
            if ($ReturnAttribute) {
                $attributeNameList = foreach ($attributeName in $attributeList.Keys) {
                    if ($ReturnAttribute -contains $attributeName) {
                        $attributeName
                    }
                }
            }
            $attributeNameList = $attributeList.Keys
            if ($attributeList.Keys -contains 'distinguishedname' -and 
                $attributeNameList -notcontains 'canonicalname') {
                
                $attributeNameList += 'canonicalname'
            }

            if ($attributeNameList -contains 'member;range=0-1499') {
                # 'member;range=0-1499' being present means 'member' will also be present 
                # but empty despite there being at least 1500 members. 'member is dropped 
                # here and then added back later with all members.
                $attributeNameList = $attributeNameList | Where-Object { $_ -ne 'member' }
            }
            $attributeNameList = $attributeNameList | Sort-Object
        }

        if ($attributeNameList.Count -eq 0) {
            return
        }

        foreach ($attributeName in $attributeNameList) {
            if ($attributeName -eq 'member;range=0-1499') {
                # This is a group with more than 1500 members which the rest of were not returned. There 
                # probably is some other way to get the rest but this works for now.
                $attributeName = 'member'
                $filter = "(&(memberof=$($attributeObject.DistinguishedName)))"
                $values = Invoke-LDAPQuery -Filter $filter -AttributeList 'distinguishedname'
                $values = $values | Select-Object -ExpandProperty DistinguishedName
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
            }
            $attributeObject | Add-Member -MemberType NoteProperty -Name $attributeName -Value $values
        }

        # Change arrays containing only a single item to just that single value
        $attributeObject | Get-Member -MemberType NoteProperty | 
            Select-Object -ExpandProperty Name | ForEach-Object {
                if ($attributeObject.$_ -is [Array] -and $attributeObject.$_.Count -lt 2) {
                    $attributeObject.$_ = $attributeObject.$_[0]
                }
            }

        if ($psVersionMajor -ge 5) {
            $objectClass = ($attributeObject.objectclass | Sort-Object) -join ','
            if ($objectClass -eq $objectClassUser) {
                New-Object -TypeName LDAPUser -ArgumentList $attributeObject
            } elseif ($objectClass -eq $objectClassComputer) {
                New-Object -TypeName LDAPComputer -ArgumentList $attributeObject
            } elseif ($objectClass -eq $objectClassGroup) {
                New-Object -TypeName LDAPGroup -ArgumentList $attributeObject
            } elseif ($objectClass -eq $objectClassOrganizationalUnit) {
                New-Object -TypeName LDAPObject -ArgumentList $attributeObject
            } elseif ($objectClass -eq $objectClassContainer) {
                New-Object -TypeName LDAPObject -ArgumentList $attributeObject
            } else {
                $attributeObject
            }
        } else {
            $attributeObject
        }
    }
}

function Invoke-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$false)][String]$ConfigurationName,
        [Parameter(Mandatory=$false)][PSCustomObject]$Configuration
    )

    if (-not $Configuration -and -not $ConfigurationName) {
        Write-Host "Pass either a Configuration or a ConfigurationName" -ForegroundColor $rageMessageColor
        return
    }

    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    }
    
    if ($ConfigurationName) {
        $Configuration = $config.ConfigurationList | Where-Object { $_.configName -eq $ConfigurationName }
        if (-not $Configuration) {
            Write-Host "Could not find an existing configuration named $ConfigurationName" `
                -ForegroundColor $rageMessageColor
            return
        }
    }

    $hideKeyStrokes = $true
    Write-Host "Load the configuration [Y/N]?" -ForegroundColor Yellow
    $key = ([Console]::ReadKey($hideKeyStrokes)).Key
    switch ($key) {
        Y {
            $Script:ldapServerName = $Configuration.ldapServerName
            $Script:ldapPort = $Configuration.ldapPort
            $Script:userDomain = $Configuration.userDomain
            $Script:userName = $Configuration.userName
            $Script:userPassword = $Configuration.userPassword
            $Script:authType = $Configuration.authType
            $Script:searchbase = $Configuration.searchbase
            $Script:pageSize = $Configuration.pageSize
            Write-Host "Configuration loaded."
        }
        N {
            Write-Host "You picked [N]o."
        }
        Default {
            Write-Host "I'll take that as a [N]o."
        }
    }
}

function Export-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$true)][PSCustomObject]$NewConfiguration
    )

    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    } else {
        $config = [PSCustomObject]@{
            ActiveConfigurationName = $null
            ConfigurationList = @()
        }
    }

    if ($config.ConfigurationList.configName -contains $NewConfiguration.configName) {
        $config.ConfigurationList = $config.ConfigurationList | `
            Where-Object { $_.configName -ne $NewConfiguration.configName }
    }

    if ($config.ConfigurationList -ne [Array]) {
        $tmp = $config.ConfigurationList
        $config.ConfigurationList = @()
        $config.ConfigurationList += $tmp
    }
    $config.ConfigurationList += $NewConfiguration

    Invoke-LDAPConnectionConfiguration -Configuration $newConfig

    Write-Host "Set the configuration as active (meaning it's loaded when the module is imported) [Y/N]?" `
        -Foregroundcolor Yellow
    $key = ([Console]::ReadKey($hideKeyStrokes)).Key
    switch ($key) {
        Y {
            $config.ActiveConfigurationName = $newConfig.configName
            Write-Host "Configuration set as active."
        }
        N {
            Write-Host "You picked [N]o."
        }
        Default {
            Write-Host "I'll take that as a [N]o."
        }
    }
    $config | Export-Clixml -Path $configFile -Force
}

function Initialize-Configuration
{
    if (-not (Test-Path -Path $configFile)) {
        Write-Host "No configuration file found at $configFile, let's create one." -ForegroundColor Yellow
        $config = [PSCustomObject]@{
            ActiveConfigurationName = $null
            ConfigurationList = @()
        }
        New-LDAPConnectionConfiguration
    }

    $config = Import-Clixml -Path $configFile

    $activeConfig = $config.ConfigurationList | `
        Where-Object { $_.configName -eq $config.ActiveConfigurationName }
    
    if ($activeConfig.Count -gt 1) {
        $configName = $activeConfig[0].configName
        throw "Configuration file $configFile contains more than one configuration named '$configName'"
    }

    $Script:ldapServerName = $activeConfig.ldapServerName
    $Script:ldapPort = $activeConfig.ldapPort
    $Script:userDomain = $activeConfig.userDomain
    $Script:userName = $activeConfig.userName
    $Script:userPassword = $activeConfig.userPassword
    $Script:authType = $activeConfig.authType
    $Script:searchbase = $activeConfig.searchbase
    $Script:pageSize = $activeConfig.pageSize
}

function Get-LDAPCredential
{
    if (-not $Script:userPassword) {
        Write-Host "Enter password for user $($Script:userDomain)\$($Script:userName):"
        $Script:userPassword = Read-Host -AsSecureString
    }

    if ($Script:authType -eq 'Basic') {
        $Script:credential = New-Object `
            -TypeName System.Net.NetworkCredential `
            -ArgumentList "$($Script:userDomain)\$($Script:userName)", $Script:userPassword
        return
    }

    if ($Script:authType -eq 'Negotiate') {
        if ($PSVersionTable.OS -match 'Linux') {
            $Script:credential = New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $($Script:userDomain)\$($Script:userName), $Script:userPassword
            return
        } else {
            $Script:credential = New-Object `
                -TypeName System.Net.NetworkCredential `
                -ArgumentList $Script:userName, $Script:userPassword, $Script:userDomain
            return
        }
    }

    throw "Unsupported authentication authentication type $Script:authType, use Basic or Negotiate"
}

function Connect-LDAPServer
{
    if (-not $Script:ldapServerName) {
        Initialize-Configuration
    }

    if ($null -eq $Script:credential) {
        Get-LDAPCredential
    }
    try {
        $Script:ldapServer = New-Object -TypeName LdapConnection `
            -ArgumentList "$($Script:ldapServerName):$($Script:ldapPort)", $Script:credential, $Script:authType
    } catch {
        throw "Error connecting to LDAP server: $($_.ToString())"
    }

    $Script:ldapServer.SessionOptions.SecureSocketLayer = $true
    $Script:ldapServer.SessionOptions.ProtocolVersion = 3
}

function Send-LDAP
{
    Param(
        [Parameter(Mandatory=$true)][DirectoryRequest]$Request
    )

    if ($null -eq $Script:ldapServer) {
        Connect-LDAPServer
    }
    if ($Request -is [SearchRequest] -and -not $Request.DistinguishedName) {
        $Request.DistinguishedName = $Script:searchbase
    }
    try {
        $Script:ldapServer.SendRequest($Request) | ForEach-Object {
            if ($_ -is [AddResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -is [DeleteResponse]) {
                # NOTE Be silent for now
            } elseif ($_ -is [ModifyDNResponse]) {
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
        [Parameter(Mandatory=$false)][String[]]$AttributeList,
        [Parameter(Mandatory=$false)][String]$SearchBase,
        [Parameter(Mandatory=$false)][SearchScope]$Scope = [SearchScope]::Subtree,
        [Parameter(Mandatory=$false)][Int]$PageSize,
        [Parameter(Mandatory=$false)][Int]$SizeLimit
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
        if ($AttributeList -contains 'canonicalname' -and $AttributeList -notcontains 'distinguishedname') {
            $AttributeList += 'distinguishedname'
        }
        # If there's more than 1500 members in a group DistinguishedName will be required 
        # to get all members
        if ($AttributeList -contains 'member' -and $AttributeList -notcontains 'distinguishedname') {
            $AttributeList += 'distinguishedname'
        }
    }
    # NOTE Search paging explained here:
    # https://docs.microsoft.com/en-us/previous-versions/dotnet/articles/bb332056(v=msdn.10)?redirectedfrom=MSDN#search-operations

    $searchRequest = New-Object -TypeName SearchRequest -ArgumentList $null, $Filter, $Scope, $AttributeList
    if ($null -ne $SearchBase) {
        $searchRequest.DistinguishedName = $SearchBase
    }

    if ($SizeLimit) {
        $searchRequest.SizeLimit = $SizeLimit
    }

    if (-not $PageSize) {
        if (-not $Script:PageSize) {
            Initialize-Configuration # NOTE I still don't particularly enjoy having this be called here in 
                                     #      addition to it being in Connect-LDAPServer
        }
        $PageSize = $Script:PageSize
    }

    function Invoke-AttributeConversion
    {
        Param(
            [Parameter(Mandatory=$false)]$SearchResponse
        )
        if ($singleAttribute) {
            # Convert the single attribute
            $SearchResponse.Entries | ForEach-Object {
                if ($_.Attributes.Keys -contains $singleAttribute) {
                    Convert-SearchResultAttributeCollection -InputObject $_.Attributes `
                        -ReturnAttribute $singleAttribute
                } else {
                    return
                }
            }
        } else {
            $SearchResponse.Entries | ForEach-Object {
                Convert-SearchResultAttributeCollection -InputObject $_.Attributes
            }
        }
    }

    $pageRequest = New-Object -TypeName PageResultRequestControl -ArgumentList $PageSize
    $searchRequest.Controls.Add($pageRequest) | Out-Null
    
    $note = "Note that the server does not support paging. Some objects may have not been returned."
    if ($null -eq $Script:ServerSupportsPaging) {
        # See if the server supports paging
        $searchResponse = Send-LDAP -Request $searchRequest
        if ($searchResponse.Controls.Length -ne 1 -or
            $searchResponse.Controls[0] -isnot [PageResultResponseControl]) {
            $Script:ServerSupportsPaging = $false
            Invoke-AttributeConversion -SearchResponse
            Write-Host $note -ForegroundColor $rageMessageColor
            return
        } else {
            $Script:ServerSupportsPaging = $true
        }
    } elseif ($Script:ServerSupportsPaging -eq $false) {
        $searchResponse = Send-LDAP -Request $searchRequest
        Invoke-AttributeConversion -SearchResponse $searchResponse
        Write-Host $note -ForegroundColor $rageMessageColor
        return
    } else {
        $searchResponse = Send-LDAP -Request $searchRequest
    }

    while ($true) {
        $pageResponse = [PageResultResponseControl] $searchResponse.Controls[0]
        $pageRequest.Cookie = $pageResponse.Cookie
        $searchResponse = Send-LDAP -Request $searchRequest
        Invoke-AttributeConversion -SearchResponse $searchResponse
        if ($pageResponse.Cookie.Length -eq 0) {
            return
        }
    }
}

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

        $filters += [PSCustomObject]@{
            Filter = $filter
            SearchBase = $null
        }
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

    if ($SearchAttribute.Count -eq 1 -and $SearchAttribute -eq 'CanonicalName' -and
        $AttributeValue.Count -eq 1) {
        
        # This is a contoso.com/path/to/something/* search
        $SearchAttribute = 'DistinguishedName'
        $AttributeValue = ConvertTo-DistinguishedName -CanonicalName $AttributeValue -LeafAttribute None
    }

    if ($SearchAttribute.Count -eq 1 -and $SearchAttribute -eq 'DistinguishedName' -and
        $AttributeValue.Count -eq 1 -and $AttributeValue -match '\*') {
        
        # This is a *,OU=something,OU=to,OU=path,DC=contoso,DC=com type search
        
        $leaf = $AttributeValue -split ',' | Select-Object -First 1
        if ($leaf -notmatch '=') {
            $search = "(CN=$leaf)(OU=$leaf)"
        } else {
            $search = $leaf
        }

        $searchBase = $AttributeValue[0] -replace ("^$leaf," -replace '\*','\*')
        # All parent nodes in canonical name path such as contoso.com/computers/* when converted to 
        # distinguished name default to OU=computers. Computers for example is a container which in 
        # a distinguished name path is represented by common name, CN=computers. First test if an 
        # OU exists and if not try CN instead.
        try {
            # NOTE There's probably a better way than this to test if the searchbase exists but 
            #      at least this shouldn't be too bad performance wise.
            Invoke-LDAPQuery -Filter "(&(name=*))" -AttributeList cn `
                -SearchBase $searchBase -SizeLimit 1 -ErrorAction Stop | Out-Null
        } catch {
            if ($_.Tostring() -match 'The object does not exist') {
                $searchBase = $searchBase -replace '^OU','CN'
                try {
                    Invoke-LDAPQuery -Filter "(&(name=*))" -AttributeList cn `
                        -SearchBase $searchBase -SizeLimit 1 -ErrorAction Stop | Out-Null
                } catch {
                    if ($_.Tostring() -match 'The object does not exist') {
                        Write-Host "Could not find organizational unit or container" `
                            -ForegroundColor $rageMessageColor
                        return
                    } elseif ($_.ToString() -notmatch 'The size limit was exceeded') {
                        # 'The size limit was exceeded' is acceptable as  
                        # objects were returned. This is not so throw it.
                        throw $_
                    }
                }
            } elseif ($_.ToString() -notmatch 'The size limit was exceeded') {
                # 'The size limit was exceeded' is acceptable as  
                # objects were returned. This is not so throw it.
                throw $_
            }
        }

        $filter += "(|($search)"
    } else {
        $filter += "(|"
        foreach ($sAttr in $SearchAttribute) {
            foreach ($vAttr in $AttributeValue) {
                $filter += "($sAttr=$vAttr)"
            }
        }
    }

    $filter += ')'
    if ($ObjectClass) {
        $filter += ')'
    }

    if (-not $searchBase) {
        $searchBase = $null
    }

    return [PSCustomObject]@{
        Filter = $filter
        SearchBase = $searchBase
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

    if ($OrganizationalUnit -notmatch ',DC=') {
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

function Move-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)][String]$DistinguishedName,
        [Parameter(Mandatory=$true)][String]$TargetDistinguishedName
    )
    $modifyDNRequest = New-Object -TypeName ModifyDNRequest
    $modifyDNRequest.DeleteOldRdn = $true
    $modifyDNRequest.DistinguishedName = $DistinguishedName
    $newName = $DistinguishedName -split ',' | Select-Object -First 1
    $modifyDNRequest.NewName = $newName
    $modifyDNRequest.NewParentDistinguishedName = $TargetDistinguishedName
    Send-LDAP -Request $modifyDNRequest
}

function Select-LDAPObject
{
    Param(
        [Parameter(Mandatory=$true)]$ObjectList,
        [Parameter(Mandatory=$false)][String]$DisplayProperty = 'canonicalname'
    )
    while ($true) {
        $hideKeyStrokes = $true
        $key = ([Console]::ReadKey($hideKeyStrokes)).Key
        $confirmMessage = 'You picked '
        switch ($key) {
            A {
                $confirmMessage += '[A]pply, working...'
                Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                return 'Apply'
            }
            S {
                if ($newMenuLoaded) {
                    $confirmMessage += '[S]elect objects, working...'
                    Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                    $selected = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to select, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms. Use slash (/) to search.'
                    return $selected
                }
            }
            D {
                if ($newMenuLoaded) {
                    $confirmMessage += '[D]eselect, working...'
                    Write-Host $confirmMessage -ForegroundColor $confirmMessageColor
                    $deselectList = New-Menu -InputObject $ObjectList -DisplayProperty $DisplayProperty `
                        -Mode Multiselect -Title 'Use space to deselect, arrow keys and pgup/pgdn to move.', 
                        'Enter confirms. Use slash (/) to search.'
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

function Select-LDAPTargetObject
{
    Param(
        [Parameter(Mandatory=$true)]$LDAPObjectList,
        [Parameter(Mandatory=$true)][String]$Title
    )
    $apply = $false
    while ($apply -eq $false) {
        Write-Host "$Title`n" -ForegroundColor Yellow
        foreach ($ldapObject in $LDAPObjectList) {
            Write-Host "`t$($ldapObject.canonicalname)" -ForegroundColor Green
        }
        if ($newMenuLoaded) {
            $footer ='[A]pply, [S]elect objects, [D]eselect objects, Esc to cancel'
        } else {
            $footer ='[A]pply, Esc to cancel'
        }
        Write-Host "`n$footer" -ForegroundColor Yellow
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
        Write-Host "$OperationDescription`n" -ForegroundColor Yellow
        foreach ($entry in $membershipMap) {
            $member = "'$($entry.Member.canonicalname)'"
            $member = $member.PadRight($topLength + 2) # The 2 is the ' surrounding $member
            $group = "'$($entry.Group.canonicalname)'"
            Write-Host "    $member $direction $group" -ForegroundColor Green
        }
        Write-Host "`n$Instructions" -ForegroundColor Yellow
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
    if (-not $newMenuLoaded) {
        $instructions = '[A]pply, Esc to cancel'
    }

    $ldapGroupFilters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTermGroup -ObjectClass Group
    $ldapGroupList = foreach ($filter in $ldapGroupFilters) {
        Invoke-LDAPQuery -Filter $filter.Filter -SearchBase $filter.SearchBase
    }

    if ($Operation -eq 'Remove' -and $SearchTermMember -eq '*') {
        $ldapMemberList = '*'
    } else {
        $ldapMemberList = Search-LDAP -SearchTerm $SearchTermMember
    }

    if ($ldapGroupList.Count -gt 0 -and $ldapMemberList.Count -gt 0) {
        if (-not $NoConfirmation.IsPresent) {
            $modifyMap = Select-LDAPGroupMemberModificationTarget `
                -LDAPGroupList $ldapGroupList `
                -LDAPMemberList $ldapMemberList `
                -Operation $Operation `
                -Instructions $instructions
        } else {
            $modifyMap = Get-MembershipMap `
                -LDAPGroupList $LDAPGroupList `
                -LDAPMemberList $LDAPMemberList
        }
        # NOTE Since group member lists are cached there's always a 
        #      possibility something else modifies it while this 
        #      function is doing the same
        $memberCache = @{}
        Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
        $failures = 0
        $warnings = 0
        foreach ($modifyEntry in $modifyMap) {
            $groupDN = $modifyEntry.Group.DistinguishedName
            $memberDN = $modifyEntry.Member.DistinguishedName
            $groupCanName = $modifyEntry.Group.canonicalname
            $groupMemName = $modifyEntry.Member.canonicalname
            if (-not ($memberCache.Keys -contains $groupDN)) {
                $memberFilter = "(&(memberof=$groupDN))"
                $memberCache.Add($groupDN, ((Invoke-LDAPQuery -Filter $memberFilter `
                    -AttributeList 'DistinguishedName').DistinguishedName))
            }
            try {
                if ($Operation -eq 'Add') {
                    if ($memberCache[$groupDN] -contains $modifyEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' already contains '$groupMemName' (warning)"
                        Write-Log -Message $msg -NoEcho
                        $warnings++
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Add' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' added"
                        Write-Log -Message $msg -NoEcho
                    }
                }
                if ($Operation -eq 'Remove') {
                    if ($memberCache[$groupDN] -notcontains $modifyEntry.Member.distinguishedname) {
                        $msg = "'$groupCanName' does not contain '$groupMemName' (warning)"
                        Write-Log -Message $msg -NoEcho
                        $warnings++
                    } else {
                        Set-LDAPObject -DistinguishedName $groupDN -Operation 'Delete' -AttributeName member `
                            -Values $memberDN -ErrorAction Stop
                        $msg = "'$groupCanName' member '$groupMemName' removed"
                        Write-Log -Message $msg -NoEcho
                    }
                }
                Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
            } catch {
                $err = $_.ToString()
                if ($Operation -eq 'Add') {
                    $msg = "Error adding '$groupCanName' member '$groupMemName': $err"
                } elseif ($Operation -eq 'Remove') {
                    $msg = "Error removing '$groupCanName' member '$groupMemName': $err"
                }
                Write-Log -Message $msg -Level Error -NoEcho
                Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
                $failures++
            }                
        }
        $color = $happyMessageColor
        if ($failure -gt 0) {
            $color = $rageMessageColor
        } elseif ($warnings -gt 0) {
            $color = $warningMessageColor
        }
        Write-Host "`nDone with $failures/$($modifyMap.Count) failures and $warnings/$($modifyMap.Count) warnings. See $($Script:logFileFullName) for details." `
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

# //INTERNAL FUNCTIONS

# EXPORTED FUNCTIONS

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

function Get-LDAPLogContent
{
    foreach ($logFileFullName in Get-LDAPLogFileList -Last 1) {
        Get-Content -Path $logFileFullName
    }
}

function Get-LDAPConnectionConfiguration
{
    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    } else {
        Write-Host "Configuration file $configFile does not exist." -ForegroundColor $warningMessageColor
        return
    }

    Write-Host "Active configuration: $($config.ActiveConfigurationName)" -ForegroundColor $happyMessageColor
    
    foreach ($conf in $config.ConfigurationList) {
        $conf | Format-List
    }
}

function New-LDAPConnectionConfiguration
{
    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    } else {
        $config = [PSCustomObject]@{
            ActiveConfigurationName = $null
            ConfigurationList = @()
        }
        if (-not (Test-Path -Path $pathScriptFiles)) {
            try {
                New-Item -Path $pathScriptFiles -ErrorAction Stop | Out-Null
            } catch {
                throw "Error creating directory $pathScriptFiles for configuration file: $($_.TroString())"
            }
        }
    }
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
    $msg = "`nNegotiate is a pretty good default for Active Directory unless you want to go for "
    $msg += "the Kerberos or nothing route."
    Write-Host $msg
    $configAuthentication = Read-Host -Prompt "Authentication (Negotiate is a good default for AD)"
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
    Edit-LDAPConnectionConfiguration -Configuration $newConfig
}

function Edit-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$false)][String]$ConfigurationName,
        [Parameter(Mandatory=$false)][PSCustomObject]$Configuration
    )

    if (-not $Configuration -and -not $ConfigurationName) {
        Write-Host "Pass either a Configuration or a ConfigurationName" -ForegroundColor $rageMessageColor
        return
    }

    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    }
    
    if ($ConfigurationName) {
        $Configuration = $config.ConfigurationList | Where-Object { $_.configName -eq $ConfigurationName }
        if (-not $Configuration) {
            Write-Host "Could not find an existing configuration named $ConfigurationName" `
                -ForegroundColor $rageMessageColor
            return
        }
    }

    $originalConfigName = $Configuration.configName

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
        $hideKeyStrokes = $true
        $key = ([Console]::ReadKey($hideKeyStrokes)).Key
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
                $configName = $Configuration.configName
                if ($config.ConfigurationList.configName -contains $configName) {
                    Write-Host "About to replace and existing configuration, overwrite [Y/N]?" `
                        -ForegroundColor $attentionMessageColor
                    $key = ([Console]::ReadKey($hideKeyStrokes)).Key
                    switch ($key) {
                        Y {
                            Write-Host "Overwriting previous configuration." -ForegroundColor $happyMessageColor
                        }
                        N {
                            Write-Host "Discarding new configuration." -ForegroundColor $cancelMessageColor
                            return $null
                        }
                        Default {
                            Write-Host "Discarding new configuration." -ForegroundColor $cancelMessageColor
                            return $null
                        }
                    }
                }
                Write-Host "[A]pplying settings"
                if ($configName -ne $originalConfigName) {
                    Write-Host "Configuration name was changed from $originalConfigName to $configName." `
                        -ForegroundColor $warningMessageColor
                    Write-Host "Removing old configuration and adding new one with different name." `
                        -ForegroundColor $warningMessageColor
                    Remove-LDAPConnectionConfiguration -ConfigurationName $originalConfigName
                }
                Export-LDAPConnectionConfiguration -NewConfiguration $Configuration
                return
            }
            Escape {
                Write-Host "Discarding new configuration."
                return $null
            }
        }
    }
}

function Set-LDAPConnectionConfigurationActive
{
    Param(
        [Parameter(Mandatory=$true)][PSCustomObject]$ConfigurationName
    )

    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    }
    
    $Configuration = $config.ConfigurationList | Where-Object { $_.configName -eq $ConfigurationName }
    if (-not $Configuration) {
        Write-Host "Could not find an existing configuration named $ConfigurationName" `
            -ForegroundColor $rageMessageColor
        return
    } else {
        try {
            $config.ActiveConfigurationName = $ConfigurationName
            $config | Export-Clixml -Path $configFile -Force
            Write-Host "Active configuration set to $ConfigurationName" -ForegroundColor $happyMessageColor
            Invoke-LDAPConnectionConfiguration -ConfigurationName $ConfigurationName
        } catch {
            $msg = "Error setting active configuration to $ConfigurationName "
            $msg += "in $($configFile): $($_.ToString())"
            Write-Host $msg -ForegroundColor $rageMessageColor
        }
    }
}

function Remove-LDAPConnectionConfiguration
{
    Param(
        [Parameter(Mandatory=$true)][PSCustomObject]$ConfigurationName
    )

    if (Test-Path -Path $configFile) {
        $config = Import-Clixml -Path $configFile
    }
    
    $Configuration = $config.ConfigurationList | Where-Object { $_.configName -eq $ConfigurationName }
    if (-not $Configuration) {
        Write-Host "Could not find an existing configuration named $ConfigurationName" `
            -ForegroundColor $rageMessageColor
        return
    } else {
        try {
            $config.ConfigurationList = $config.ConfigurationList | `
                Where-Object { $_.configName -ne $ConfigurationName }
            $config | Export-Clixml -Path $configFile -Force
            Write-Host "Configuration $ConfigurationName removed from $configFile" `
                -ForegroundColor $happyMessageColor
        } catch {
            Write-Host "Error removing configuration $ConfigurationName from $($configFile): $($_.ToString())" `
                -ForegroundColor $rageMessageColor
        }
    }
}

function Search-LDAP
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute,
        [Parameter(Mandatory=$false)]
        [ValidateSet('User', 'Computer', 'Group', 'OrganizationalUnit', 'Container')]
        [String]$ObjectClass
    )

    if (-not $SearchTerm) {
        $description = "Looks for objects by search terms and returns either all or requested return attributes. Search is fuzzy, you pass keywords that can include '*' as wildcards and the script attempts to find objects that have those values in attributes that generally identify an object such as Name, sAMAccountName, UserPrincipalName and so forth. So keep in mind that you are not making exact searches which is why these commands first let you know what is about to be done and you then have to choose to apply the changes."
        $usage = "LDAPGet SearchTerm(s)", "LDAPGet SearchTerm(s) ReturnAttribute(s)", 
            "LDAPGet SearchTerm(s) ReturnAttribute(s) ObjectClass"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = 'Term to find objects by'
        $parameters['ReturnAttribute'] = "Which attributes to return per object '*' which is the default, means any value other than null."
        $parameters['ObjectClass'] = "Class of object to return."
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    if ($SearchTerm.Count -eq 1) {
        if ($SearchTerm -match $canonicalNamePattern -and $SearchTerm -match '\*') {
            if (-not $ObjectClass) {
                $filters = Get-LDAPAttributeValueQueryFilter -SearchAttribute CanonicalName `
                    -AttributeValue $SearchTerm
            } else {
                $filters = Get-LDAPAttributeValueQueryFilter -SearchAttribute CanonicalName `
                    -AttributeValue $SearchTerm -ObjectClass $ObjectClass
            }
        }
        if ($SearchTerm -match $distinguishedNamePattern -and $SearchTerm -match '\*') {
            if (-not $ObjectClass) {
                $filters = Get-LDAPAttributeValueQueryFilter -SearchAttribute DistinguishedName `
                    -AttributeValue $SearchTerm
            } else {
                $filters = Get-LDAPAttributeValueQueryFilter -SearchAttribute DistinguishedName `
                    -AttributeValue $SearchTerm -ObjectClass $ObjectClass
            }
        }
    }

    if (-not $filters) {
        if (-not $ObjectClass) {
            $filters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm
        } else {
            $filters = Get-LDAPFuzzyQueryFilter -SearchTerm $SearchTerm -ObjectClass $ObjectClass
        }
    }

    foreach ($filter in $filters) {
        $result += Invoke-LDAPQuery -Filter $filter.Filter -SearchBase $filter.SearchBase `
            -AttributeList $ReturnAttribute
    }
    if (-not $ReturnAttribute) {
        $result | Sort-Object -Property CanonicalName
    } elseif ($ReturnAttribute.Count -eq 1) {
        $result | Select-Object -ExpandProperty $ReturnAttribute[0]
    } else {
        $result | Select-Object $ReturnAttribute
    }
}

function Search-LDAPByAttributeValue
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchAttribute,
        [Parameter(Mandatory=$false)][String[]]$AttributeValue = "*",
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )

    if (-not $SearchAttribute) {
        $description = "Looks for objects that have matching values in attributes."
        $usage = "LDAPGetBy SearchAttribute(s) AttributeValue(s) ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchAttribute'] = "Attributes in which to look for a value"
        $parameters['AttributeValue'] = "Which value(s) to look for in attributes. '*' which is the default, means any value other than null."
        $parameters['ReturnAttribute'] = "Which attributes to return per object. '*' expands all."
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $result = @()
    $filters = Get-LDAPAttributeValueQueryFilter `
        -SearchAttribute $SearchAttribute -AttributeValue $AttributeValue
    foreach ($filter in $filters) {
        $result += Invoke-LDAPQuery -Filter $filter.Filter -SearchBase $filter.SearchBase
    }
    if (-not $ReturnAttribute) {
        $result | Sort-Object -Property CanonicalName
    } elseif ($ReturnAttribute.Count -eq 1) {
        $result | Select-Object -ExpandProperty $ReturnAttribute[0]
    } else {
        $result | Select-Object $ReturnAttribute
    }
}

function Search-LDAPByObjectClass
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)]
        [ValidateSet('User', 'Computer', 'Group', 'OrganizationalUnit', 'Container')]
        [String]$ObjectClass = "User",
        [Parameter(Mandatory=$false)][String[]]$ReturnAttribute
    )

    if (-not $SearchTerm -or -not $ObjectClass) {
        $description = "Looks for objects that are of a matching class."
        $usage = "LDAPGetClass SearchAttribute(s) ObjectClass ReturnAttribute(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchAttribute'] = "Attributes in which to look for a value"
        $parameters['ObjectClass'] = "Which class of object to find."
        $parameters['ReturnAttribute'] = "Which attributes to return per object. '*' expands all."
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    Search-LDAP -SearchTerm $SearchTerm -ObjectClass $ObjectClass -ReturnAttribute $ReturnAttribute
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

    if ($attributeMap[$Attribute]) {
        Write-Host "You specified $Attribute as attribute, will modify $($attributeMap[$Attribute])" `
            -ForegroundColor $warningMessageColor
        $Attribute = $attributeMap[$Attribute]
    }

    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to set attribute '$Attribute' to '$Value' on the following object(s):"
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
    $failures = 0
    $warnings = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $valName = $Value -join ', '
        $oldValue = $ldapObject.$Attribute -join ', '
        if (-not $oldValue) {
            $oldValue = $ldapObject.attributes.$Attribute -join ', '
        }
        if ($oldValue -eq $valName) {
            $msg = "'$objName' '$Attribute' already set to '$oldValue'"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $warningMessageColor
            $warnings++
            continue
        }
        try {
            $msg = "'$objName' '$Attribute' is '$oldValue'"
            Write-Log -Message $msg -NoEcho
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName $Attribute -Values $Value -ErrorAction Stop
            $msg = "'$objName' '$Attribute' set to '$valName'"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            throw $_
            $err = $_.ToString()
            $msg = "Error setting '$objName' '$Attribute' to '$valName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    } elseif ($warnings -gt 0) {
        $color = $warningMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures and $warnings/$($ldapObjectList.Count) warnings. See $($Script:logFileFullName) for details." `
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
        -Title "About to add value '$Value' to attribute '$Attribute' on the following objects:"
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
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
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error adding '$objName' '$Attribute' value '$valName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $($Script:logFileFullName) for details." `
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
        -Title "About to remove value '$Value' from attribute '$Attribute' on the following objects:"
    Write-Host "Working" -NoNewLine -ForegroundColor $happyMessageColor
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
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName' '$Attribute' '$Value': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $($Script:logFileFullName) for details." `
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
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
    $failures = 0
    $warnings = 0
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
                $msg = "'$objname' '$attribute' is already not set (warnings)"
                write-log -message $msg -NoEcho
                $warnings++
            }
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error clearing '$objName' '$Attribute': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    } elseif ($warnings -gt 0) {
        $color = $warningMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures and $warnings/$($ldapObjectList.Count) warnings. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
}

function Search-LDAPAndAddGroupMember
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember,
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        $description = "Finds groups and objects to add as members to said groups. Allows user to pick which objects to add to which groups via an interactive menu."
        $usage = "LDAPAddMember SearchTermMember(s) SearchTermGroup(s)", 
            "LDAPAddMember SearchTermMember(s) SearchTermGroup(s) -NoConfirmation"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermMember'] = "Terms to find objects to add to groups"
        $parameters['SearchTermGroup'] = "Terms to find groups"
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
        [Parameter(Mandatory=$false)][String[]]$SearchTermMember,
        [Parameter(Mandatory=$false)][String[]]$SearchTermGroup,
        [Parameter(Mandatory=$false)][Switch]$NoConfirmation
    )

    if (-not $SearchTermGroup -or -not $SearchTermMember) {
        $description = "Finds groups and objects to attempt to remove from said groups. Passing '*' as SearchTermMember offers to remove all current members of a group. Allows user to pick which objects to add to which groups via an interactive menu."
        $usage = "LDAPAddMember SearchTermMember(s) SearchTermGroup(s)", 
            "LDAPAddMember SearchTermMember(s) SearchTermGroup(s) -NoConfirmation"
        $sTMInfo = "Terms to find objects to add to groups, use * to remove all members"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTermMember'] = $sTMInfo
        $parameters['SearchTermGroup'] = "Terms to find groups"
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
        $groupList += Invoke-LDAPQuery -Filter $filter.Filter -SearchBase $filter.SearchBase `
            -AttributeList $attributeList
    }
    
    foreach ($group in $groupList) {
        Get-LDAPGroupMemberRecursive -LDAPGroup $group -DisplayPropertyname $DisplayPropertyName
    }
}

function Search-LDAPAndResetPassword
{
    Param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][SecureString]$NewPassword
    )
    
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
        $newClearPass = $NewPassword
        [byte[]]$NewPassword = ConvertTo-LDAPPassword $NewPassword
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to set password on the following objects:"
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to modify."
        return
    }

    $attributeList = 'mail,sAMAccountName,Password' -split ','
    $failures = 0
    $resultList = @()
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            if ($NewPassword) {
                $newPass = $NewPassword
            } else {
                $newClearPass = Get-RandomString
                [byte[]]$newPass = ConvertTo-LDAPPassword `
                    -Password ($newClearPass | ConvertTo-SecureString -AsPlainText)
            }
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName 'unicodePwd' -Values $newPass -ErrorAction Stop
            $resultList += $ldapObject | Add-Member -MemberType NoteProperty Password $newClearPass -PassThru | `
                Select-Object $attributeList
            Write-Host '.' -NoNewLine -ForegroundColor $happyMessageColor
            $msg = "'$objName' password set"
            Write-Log -Message $msg -NoEcho
        } catch {
            Write-Host '.' -NoNewLine -ForegroundColor $rageMessageColor
            $err = $_.ToString()
            $msg = "Error setting '$objName' password: $err"
            Write-Log -Message $msg  -NoEcho-Level Error
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
    
    $resultFile = ".\NewPasswordList-$(Get-Date -Format $dateTimeStringFormat).csv"
    $msg = "`nWould you like to [W]rite the new passwords to $resultFile or [P]rint them to command line?`n"
    Write-Host $msg -ForegroundColor $attentionMessageColor
    $hideKeyStrokes = $true
    while ($true) {
        $key = ([Console]::ReadKey($hideKeyStrokes)).Key
        switch ($key) {
            W {
                try {
                    $resultList | Export-Csv -Path $resultFile -Delimiter $csvFileDelimiter `
                        -Encoding $csvFileEncoding -NoTypeInformation -ErrorAction Stop
                    Write-Host "File $resultFile written." -ForegroundColor $happyMessageColor
                } catch {
                    Write-Host "Error writing $($resultFile): $($_.ToString())" `
                        -ForegroundColor $rageMessageColor
                }
                return
            }
            P {
                foreach ($result in $resultList) {
                    Write-Host "Email: $($result.mail)"
                    Write-Host "Account: $($result.sAMAccountName)"
                    Write-Host "Password: $($result.Password)`n"
                }
                return
            }
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
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
    $failures = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            Remove-LDAPObject -DistinguishedName $ldapObject.DistinguishedName `
                -ErrorAction Stop
            $msg = "'$objName' removed"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error removing '$objName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
}

function Search-LDAPAndMove
{
    param(
        [Parameter(Mandatory=$false)][String[]]$SearchTerm,
        [Parameter(Mandatory=$false)][String]$TargetPath
    )

    if (-not $SearchTerm) {
        $description = "Looks for objects by search terms and moves them to a selected organizational unit."
        $description += "TargetPath is not mandatory, the command gives a list to pick a target OU from."
        $usage = "LDAPMove SearchTerm(s)"
        $usage += "LDAPMove SearchTerm(s) TargetPath"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects to move"
        $parameters['TargetPath'] = "Canonical or Distinguished Name of and organizational unit or container"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }

    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to move."
        return
    }

    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to move the following object(s):"
    
    if (-not $TargetPath) {
        if ($newMenuLoaded) {
            $ouList = Invoke-LDAPQuery -Filter '(&(objectclass=organizationalunit))'
            $title = 'Use enter to select an organizational unit to move objects ',
                     'to it, arrow keys and pgup/pgdn to move. Use slash (/) to search.'
            [LDAPObject] $TargetPath = New-Menu -InputObject $ouList -DisplayProperty CanonicalName `
                                        -Title $title
            if (-not $TargetPath) {
                Write-Host "You didn't pick an organizational unit to move selected objects to." `
                    -ForegroundColor $disappointedMessageColor
                return
            }
        } else {
            $msg = "The New-Menu module is not imported. You need the module to interactively pick "
            $msg += "from a list which target path to move object(s) to or pass the target path via "
            $msg += "the TargetPath parameter.`n"
            $msg += "The module is available at: https://github.com/mklrm/New-Menu"
            Write-Host $msg -ForegroundColor $warningMessageColor
            return
        }
    } else {
        if ($TargetPath -match $canonicalNamePattern) {
            [PSCustomObject] $TargetPath = [PSCustomObject]@{
                CanonicalName = $TargetPath
                DistinguishedName = ConvertTo-DistinguishedName -CanonicalName $TargetPath -LeafAttribute 'OU'
            }
        } elseif ($TargetPath -match $distinguishedNamePattern) {
            [PSCustomObject] $TargetPath = [PSCustomObject]@{
                CanonicalName = ConvertTo-CanonicalName -DistinguishedName $TargetPath
                DistinguishedName = $TargetPath
            }
        }
    }

    Write-Host "`n`tMoving selected objects to $($TargetPath.CanonicalName)`n" `
        -ForegroundColor $warningMessageColor
    Write-Host "[A]pply or [C]ancel?" -ForegroundColor $happyMessageColor

    $hideKeyStrokes = $true
    $key = ([Console]::ReadKey($hideKeyStrokes)).Key
    switch ($key) {
        A {
            Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
        }
        C {
            Write-Host "Exiting." -ForegroundColor $warningMessageColor
            return
        }
        Default {
            Write-Host "I'll take that as a [C]ancel." -ForegroundColor $warningMessageColor
            return
        }
    }

    $failures = 0
    
    $targetPathName = $TargetPath.CanonicalName

    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        try {
            Move-LDAPObject -DistinguishedName $ldapObject.DistinguishedName `
                -TargetDistinguishedName $TargetPath.DistinguishedName -ErrorAction Stop
            $msg = "'$objName' moved to '$targetPathName'"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error moving '$objName' to '$targetPathName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
}

function Search-LDAPAndDisable
{
    param(
        [Parameter(Mandatory=$false)][string[]]$SearchTerm
    )
    if (-not $SearchTerm) {
        $description = "Looks for objects by search terms and disables them."
        $usage = "LDAPDisable SearchTerm(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects to disable"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }
    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to disable."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to disable the following object(s):"
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
    $failures = 0
    $warnings = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $userAccountControlFlags = ConvertFrom-UserAccountControlInteger `
            -UserAccountControlInteger $ldapObject.UserAccountControl
        $disabled = $userAccountControlFlags -contains 'AccountDisabled'
        if ($disabled) {
            $msg = "'$objName' is already disabled (warning)"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $attentionMessageColor
            $warnings++
            continue
        } else {
            $userAccountControlNewValue = $ldapObject.UserAccountControl + $adsUserFlagsMap['AccountDisabled']
        }
        try {
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName 'UserAccountControl' -Values "$userAccountControlNewValue"
            $msg = "'$objName' disabled"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error disabling '$objName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failures -gt 0) {
        $color = $rageMessageColor
    } elseif ($warnings -gt 0) {
        $color = $warningMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures and $warnings/$($ldapObjectList.Count) warnings. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
}

function Search-LDAPAndEnable
{
    param(
        [Parameter(Mandatory=$false)][string[]]$SearchTerm
    )
    if (-not $SearchTerm) {
        $description = "Looks for objects by search terms and enables them."
        $usage = "LDAPEnable SearchTerm(s)"
        [OrderedDictionary]$parameters = @{}
        $parameters['SearchTerm'] = "Terms to find objects to enable"
        Write-Help -Description $description -Usage $usage -Parameter $parameters
        return
    }
    $ldapObjectList = Search-LDAP -SearchTerm $SearchTerm
    if ($ldapObjectList.Count -lt 1) {
        Write-Host "Could not find objects to enable."
        return
    }
    $ldapObjectList = Select-LDAPTargetObject -LDAPObjectList $ldapObjectList `
        -Title "About to enable the following object(s):"
    Write-Host "Working" -NoNewline -ForegroundColor $happyMessageColor
    $failures = 0
    $warnings = 0
    foreach ($ldapObject in $ldapObjectList) {
        $objName = $ldapObject.CanonicalName
        $userAccountControlFlags = ConvertFrom-UserAccountControlInteger `
            -UserAccountControlInteger $ldapObject.UserAccountControl
        $disabled = $userAccountControlFlags -contains 'AccountDisabled'
        if (-not $disabled) {
            $msg = "'$objName' is already enabled (warning)"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $attentionMessageColor
            $warnings++
            continue
        } else {
            $userAccountControlNewValue = $ldapObject.UserAccountControl - $adsUserFlagsMap['AccountDisabled']
        }
        try {
            Set-LDAPObject -DistinguishedName $ldapObject.DistinguishedName -Operation Replace `
                -AttributeName 'UserAccountControl' -Values "$userAccountControlNewValue"
            $msg = "'$objName' enabled"
            Write-Log -Message $msg -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $happyMessageColor
        } catch {
            $err = $_.ToString()
            $msg = "Error enabled '$objName': $err"
            Write-Log -Message $msg -Level Error -NoEcho
            Write-Host '.' -NoNewline -ForegroundColor $rageMessageColor
            $failures++
        }
    }
    $color = $happyMessageColor
    if ($failure -gt 0) {
        $color = $rageMessageColor
    } elseif ($warnings -gt 0) {
        $color = $warningMessageColor
    }
    Write-Host "`nDone with $failures/$($ldapObjectList.Count) failures and $warnings/$($ldapObjectList.Count) warnings. See $($Script:logFileFullName) for details." `
        -ForegroundColor $color
}

# //EXPORTED FUNCTIONS

. $PSScriptRoot\classes\LDAPObject.ps1

Set-Alias -Name LDAPGetLogList -Value Get-LDAPLogFileList
Set-Alias -Name LDAPLog -Value Get-LDAPLogContent
Set-Alias -Name LDAPGet -Value Search-LDAP
Set-Alias -Name LDAPGetBy -Value Search-LDAPByAttributeValue
Set-Alias -Name LDAPGetClass -Value Search-LDAPByObjectClass
Set-Alias -Name LDAPSet -Value Search-LDAPAndSetAttributeValue
Set-Alias -Name LDAPAdd -Value Search-LDAPAndAddAttributeValue
Set-Alias -Name LDAPRem -Value Search-LDAPAndRemoveAttributeValue
Set-Alias -Name LDAPClr -Value Search-LDAPAndClearAttribute
Set-Alias -Name LDAPAddMember -Value Search-LDAPAndAddGroupMember
Set-Alias -Name LDAPRemMember -Value Search-LDAPAndRemoveGroupMember
Set-Alias -Name LDAPGetMemberRecursive -Value Search-LDAPGroupAndGetMembersRecursive
Set-Alias -Name LDAPSetPass -Value Search-LDAPAndResetPassword
Set-Alias -Name LDAPRemObj -Value Search-LDAPAndRemove
Set-Alias -Name LDAPMove -Value Search-LDAPAndMove
Set-Alias -Name LDAPDisable -Value Search-LDAPAndDisable
Set-Alias -Name LDAPEnable -Value Search-LDAPAndEnable
