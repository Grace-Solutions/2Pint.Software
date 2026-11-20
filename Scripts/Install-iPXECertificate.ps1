<#
.SYNOPSIS
    Gets this machine an HTTPS certificate the 2Pint signed iPXE builds trust, from the 2Pint Service, and installs it with its root.

.DESCRIPTION
    Idempotent: run it as often as you like (a daily scheduled task is fine). It does only what is missing:

    1. The root. Fetches the 2Pint iPXE Root CA from the service (GET <ServiceUrl>/ca) and adds it to LocalMachine\Root when it is not
       there yet.
    2. The names. Collects this machine's DNS names, each once: the fully qualified name on its primary DNS suffix, on its Active Directory
       domain, as DNS knows it (forward, and reverse lookups that resolve back to this machine), on each network adapter's own DNS suffix,
       then the bare host name, then -AdditionalNames. DNS names only (no addresses, no wildcards), at most 16; the first is the subject.
    3. The certificate. Keeps a certificate already in LocalMachine\My when it was issued under that root, holds its private key, covers
       every name and has more than -RenewDays left. Otherwise it makes a new RSA 2048 key in the machine's key store (it never leaves this
       machine), builds the signing request, sends it with the names (POST <ServiceUrl>/ca, X-API-Key: Base64 of the SHA-512 of the license
       key), checks the answer and installs the certificate with its key in LocalMachine\My.

    The signing request, the certificate and the root are also written as PEM to -OutputDirectory. A request that fails leaves what was
    installed as it was, and a key made for it is deleted. Busy or failing answers are retried a few times, never without end.

    4. Key access. The services that match -ServicePattern (every 2Pint service and IIS by default) may read the private key: each one's
       logon account and service SID, and IIS_IUSRS for IIS, whose app pools run as identities of their own; then -KeyAccess. Checked on
       every run, a kept certificate's too, and added only where missing. SYSTEM and Administrators have it already.

    5. The 2Pint products, with -UpdateProductSettings. Points them at the certificate by thumbprint, where they are installed: 2PXE (HostCertificateThumbprint),
       DeployR (CertificateThumbprint, when it locates its certificate by thumbprint) and StifleR (WSCertificateThumbprint,
       SignalRCertificateThumbprint) under HKLM\SOFTWARE\2Pint Software, as DeployR Community's installer does; any other *Thumbprint
       value there that names an earlier 2Pint iPXE certificate; and every http.sys HTTPS binding that uses one (the iPXE Anywhere Web
       Service, IIS and other self-hosted services). A known setting is changed when it is empty, names an earlier 2Pint iPXE certificate
       or names one no longer installed; one that names another certificate is left as it is. With -RestartServices, running services
       whose settings changed are restarted. Whatever cannot be changed is left as it was, with a warning, and the rest carries on.

    It returns an object with the action taken (Kept, Issued or Renewed), the thumbprint, the names and what it changed.

.PARAMETER LicenseKey
    The 2Pint product (license) key the service issues against.

.PARAMETER AdditionalNames
    More DNS names for the certificate (an alias or a load-balanced name), after the automatic ones.

.PARAMETER ServiceUrl
    The service's base URL; the trailing slash is optional.

.PARAMETER RenewDays
    Renews once the certificate has this many days left or fewer (the service issues for 90 days).

.PARAMETER KeyStorage
    Cng (default): a key in the Microsoft Software Key Storage Provider. Csp: a key in the legacy Microsoft Enhanced RSA and AES provider,
    for software that can only use CryptoAPI keys.

.PARAMETER OutputDirectory
    Where the PEM copies of the request, the certificate and the root are written.

.PARAMETER KeyAccess
    More accounts that may read the certificate's private key (DOMAIN\user, DOMAIN\gmsa$, NT SERVICE\name, or a SID), besides the
    accounts of the services -ServicePattern matches.

.PARAMETER ServicePattern
    Regular expressions (case-insensitive) matched against each installed service's name and display name; every service that matches
    may read the private key through its logon account and its service SID (NT SERVICE\<name>), and IIS (W3SVC) through IIS_IUSRS.
    Defaults to every 2Pint service (2PXE, the 2PXE Responder, DeployR, iPXE Anywhere Web Service, StifleR) and IIS. Pass an empty
    list for none.

.PARAMETER FriendlyName
    The certificate's friendly name in the certificate store.

.PARAMETER UpdateProductSettings
    Points the 2Pint products' settings and the http.sys HTTPS bindings at the certificate (step 5). Without it they are left as they are.

.PARAMETER RestartServices
    With -UpdateProductSettings, restarts the running services whose settings changed. Without it they take the certificate when they
    next start.

.PARAMETER Force
    Requests a new certificate even when the one installed is still good.

.PARAMETER RemoveReplaced
    With -UpdateProductSettings: after a new certificate is installed and the products point at it, removes the earlier 2Pint iPXE certificates for the same name,
    with their keys.

.EXAMPLE
    .\Install-IpxeCertificate.ps1 -LicenseKey 'XXXX-XXXX-XXXX-XXXX'

.EXAMPLE
    .\Install-IpxeCertificate.ps1 -LicenseKey $key -AdditionalNames 'pxe.contoso.com', 'deploy.contoso.com' -UpdateProductSettings -RestartServices -RemoveReplaced

.EXAMPLE
    .\Install-IpxeCertificate.ps1 -LicenseKey $key -ServicePattern '2Pint', 'Contoso Deploy' -KeyAccess 'CONTOSO\svc-deploy'

.EXAMPLE
    .\Install-IpxeCertificate.ps1 -LicenseKey $key -WhatIf
    Shows the names and the signing request without sending it or changing anything.
#>
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $False)] [ValidateNotNullOrEmpty()] [System.String] $LicenseKey = '',
    [System.String[]] $AdditionalNames = @(''),
    [ValidateNotNullOrEmpty()] [System.String] $ServiceUrl = 'https://api.service.2pintsoftware.com/',
    [ValidateRange(1, 89)] [System.Int32] $RenewDays = 30,
    [ValidateNotNullOrEmpty()] [System.String] $FriendlyName = 'iPXE HTTPS Boot Certificate',
    [ValidateSet('Cng', 'Csp')] [System.String] $KeyStorage = 'Cng',
    [System.String] $OutputDirectory = (Join-Path $env:ProgramData '2Pint\iPXE Certificate'),
    [System.String[]] $KeyAccess,
    [AllowEmptyCollection()] [System.String[]] $ServicePattern = ('2Pint', '2PXE', '^W3SVC$'),
    [switch] $UpdateProductSettings,
    [switch] $RestartServices,
    [switch] $Force,
    [switch] $RemoveReplaced
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

# Removing or restarting is only safe once the products have moved to the new certificate.
foreach ($needs in 'RestartServices', 'RemoveReplaced') {
    if ($PSBoundParameters[$needs] -and -not $UpdateProductSettings) { throw "-$needs needs -UpdateProductSettings." }
}

$MaxNames = 16
$MaxAttempts = 3
$ServerAuth = '1.3.6.1.5.5.7.3.1'

if ($PSVersionTable.PSEdition -eq 'Desktop') {
    # Windows PowerShell offers TLS 1.0 by default; the service needs 1.2.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
}
if (-not ('System.Security.Cryptography.X509Certificates.CertificateRequest' -as [System.Type])) {
    throw 'Building the signing request needs .NET Framework 4.7.2 or later under Windows PowerShell, or PowerShell 7.'
}

$base = $ServiceUrl.Trim().TrimEnd('/')
$caUrl = "$base/ca"

function Write-Info([System.String] $Text) { Write-Host "INFO $Text" }

# --- Key access ---------------------------------------------------------------------------------------------------------------

# SYSTEM and Administrators can use every machine key already: never added.
$builtIn = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
	[void] $builtIn.Add('S-1-5-18')
	[void] $builtIn.Add('S-1-5-32-544')
$keyReaders = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'
$readerSids = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)

function Resolve-AccountSid([System.String] $Account) {
    $text = $Account.Trim()
    if ($text -match '^S-1-\d') { return New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList $text }
    if ($text -eq 'LocalSystem') { $text = 'NT AUTHORITY\SYSTEM' }
    if ($text.StartsWith('.\')) { $text = "$env:COMPUTERNAME\$($text.Substring(2))" }
    $named = New-Object -TypeName 'System.Security.Principal.NTAccount' -ArgumentList $text
    $named.Translate([System.Security.Principal.SecurityIdentifier])
}

# An account that may read the key, each once; one that does not resolve is left out with a warning and the rest carry on.
function Add-KeyReader([System.String] $Account, [System.String] $Why) {
    try { $sid = Resolve-AccountSid $Account }
    catch { Write-Warning "$Why '$Account', which this machine cannot resolve; left out of key access."; return }
    if ($builtIn.Contains($sid.Value) -or -not $readerSids.Add($sid.Value)) { return }
    $shown = $Account
    try { $shown = $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { }
    $keyReaders.Add([pscustomobject]@{ Account = $shown; Sid = $sid })
}

# The services whose accounts may read the key: every installed service whose name or display name matches -ServicePattern.
$patterns = New-Object -TypeName 'System.Collections.Generic.List[System.Text.RegularExpressions.Regex]'
foreach ($pattern in $ServicePattern) {
    if (-not $pattern) { continue }
    try { $patterns.Add((New-Object -TypeName 'System.Text.RegularExpressions.Regex' -ArgumentList $pattern, ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase))) }
    catch { throw "-ServicePattern '$pattern' is not a regular expression." }
}
if ($patterns.Count -gt 0) {
    # Loaded with -WhatIf off: under -WhatIf, Windows PowerShell's module autoload reports every alias it sets.
    $whatIf = $WhatIfPreference
    $WhatIfPreference = $false
    Import-Module -Name CimCmdlets
    $services = Get-CimInstance -ClassName Win32_Service
    $WhatIfPreference = $whatIf
    foreach ($service in ($services | Sort-Object -Property Name)) {
        $display = "$($service.DisplayName)"
        if (-not ($patterns | Where-Object { $_.IsMatch($service.Name) -or $_.IsMatch($display) })) { continue }
        $logon = if ($service.StartName) { "$($service.StartName)" } else { 'LocalSystem' }
        Write-Info "Service $($service.Name) ($display) runs as $logon."
        Add-KeyReader $logon "Service $($service.Name) runs as"
        Add-KeyReader "NT SERVICE\$($service.Name)" "Service $($service.Name) has the SID"
        # IIS serves through its app pools, each under an identity of its own (IIS APPPOOL\<pool>); every one of them is in IIS_IUSRS.
        if ($service.Name -eq 'W3SVC') { Add-KeyReader 'S-1-5-32-568' 'IIS app pools are in' }
    }
}
foreach ($account in $KeyAccess) {
    if ($account) { Add-KeyReader $account 'Key access names' }
}
if ($keyReaders.Count -gt 0) { Write-Info "Key access: $(($keyReaders | ForEach-Object { $_.Account }) -join ', ')" }

# The file that holds a certificate's private key, in the machine's CNG or CryptoAPI key folder.
function Get-KeyFile([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $key = $null
    try { $key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate) } catch { }
    $unique = if ($key -is [System.Security.Cryptography.RSACng]) { $key.Key.UniqueName }
    elseif ($key -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $key.CspKeyContainerInfo.UniqueKeyContainerName }
    else { $null }
    if (-not $unique) { return $null }
    foreach ($folder in 'Microsoft\Crypto\Keys', 'Microsoft\Crypto\RSA\MachineKeys') {
        $path = Join-Path (Join-Path $env:ProgramData $folder) $unique
        if (Test-Path -LiteralPath $path) { return $path }
    }
    $null
}

# Read on the key file for each reader that lacks it. Only the file's DACL is written: its owner and the other entries stay as they are.
function Grant-KeyAccess {
    [CmdletBinding(SupportsShouldProcess)]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
    $readers = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
    if ($keyReaders.Count -eq 0) { return , $readers }
    $file = Get-KeyFile $Certificate
    if (-not $file) {
        Write-Warning "The private key of $($Certificate.Thumbprint) is not in the machine's key folders; its access is left as it is."
        return , $readers
    }
    $info = New-Object -TypeName 'System.IO.FileInfo' -ArgumentList $file
    $sections = [System.Security.AccessControl.AccessControlSections]::Access
    $acl = if ($PSVersionTable.PSEdition -eq 'Desktop') { $info.GetAccessControl($sections) } else { [System.IO.FileSystemAclExtensions]::GetAccessControl($info, $sections) }
    $read = [System.Security.AccessControl.FileSystemRights]::Read
    $adding = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
    foreach ($reader in $keyReaders) {
        $has = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
            $_.IdentityReference.Value -eq $reader.Sid.Value -and $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and ($_.FileSystemRights -band $read) -eq $read
        }
        if ($has) { $readers.Add($reader.Account); continue }
        $rule = New-Object -TypeName 'System.Security.AccessControl.FileSystemAccessRule' -ArgumentList $reader.Sid, $read, ([System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        $adding.Add($reader.Account)
    }
    if ($adding.Count -gt 0 -and $PSCmdlet.ShouldProcess("the private key of $($Certificate.Thumbprint)", "Allow $($adding -join ', ') to read it")) {
        if ($PSVersionTable.PSEdition -eq 'Desktop') { $info.SetAccessControl($acl) } else { [System.IO.FileSystemAclExtensions]::SetAccessControl($info, $acl) }
        Write-Info "Key access added for $($adding -join ', ')."
        foreach ($account in $adding) { $readers.Add($account) }
    }
    , $readers
}

# --- Names ------------------------------------------------------------------------------------------------------------------

$dnsLabel = New-Object -TypeName 'System.Text.RegularExpressions.Regex' -ArgumentList '^(?!-)[a-z0-9-]{1,63}(?<!-)$'

function Get-CleanName([System.String] $Value) {
    if ($null -eq $Value) { return $null }
    $clean = $Value.Trim().Trim('.').ToLowerInvariant()
    if ($clean.Length -eq 0) { return $null }
    $clean
}

function Test-DnsName([System.String] $Name) {
    if ($Name.Length -lt 1 -or $Name.Length -gt 253) { return $false }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($Name.Trim('[', ']'), [ref] $address)) { return $false }
    foreach ($label in $Name.Split('.')) {
        if (-not $dnsLabel.IsMatch($label)) { return $false }
    }
    $true
}

# Bounded DNS lookups: a resolver that does not answer costs at most this long per lookup.
function Resolve-Bounded([System.String] $Query) {
    try {
        $lookup = [System.Net.Dns]::GetHostEntryAsync($Query)
        if ($lookup.Wait(3000)) { return $lookup.Result }
    }
    catch { }
    $null
}

$hostProperties = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
$bare = (Get-CleanName $hostProperties.HostName)
if (-not $bare) { $bare = Get-CleanName $env:COMPUTERNAME }
$bare = $bare.Split('.')[0]
$primarySuffix = Get-CleanName $hostProperties.DomainName
# Loaded with -WhatIf off: under -WhatIf, Windows PowerShell's module autoload reports every alias it sets.
$whatIf = $WhatIfPreference
$WhatIfPreference = $false
Import-Module -Name CimCmdlets
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$WhatIfPreference = $whatIf
$directoryDomain = if ($computer.PartOfDomain) { Get-CleanName $computer.Domain } else { $null }

# This machine's own addresses, to accept only reverse-lookup names that resolve back to it.
$ownAddresses = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
$adapterSuffixes = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($adapter.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }
    if ($adapter.NetworkInterfaceType -in [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback, [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel) { continue }
    $properties = $adapter.GetIPProperties()
    if (Get-CleanName $properties.DnsSuffix) { $adapterSuffixes.Add((Get-CleanName $properties.DnsSuffix)) }
    foreach ($unicast in $properties.UnicastAddresses) {
        $address = $unicast.Address
        if ($address.IsIPv6LinkLocal -or [System.Net.IPAddress]::IsLoopback($address)) { continue }
        $bytes = $address.GetAddressBytes()
        if ($address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $bytes[0] -eq 169 -and $bytes[1] -eq 254) { continue }
        [void] $ownAddresses.Add($address.ToString())
    }
}

# Candidates in priority order, as 2PXE asks for its own certificates: fully qualified names first, the bare host name last.
$candidates = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
if ($primarySuffix) { $candidates.Add("$bare.$primarySuffix") }
if ($directoryDomain) { $candidates.Add("$bare.$directoryDomain") }
foreach ($query in $candidates.ToArray()) {
    $entry = Resolve-Bounded $query
    if ($entry) { $candidates.Add((Get-CleanName $entry.HostName)) }
}
foreach ($suffix in $adapterSuffixes) { $candidates.Add("$bare.$suffix") }
foreach ($address in $ownAddresses) {
    $entry = Resolve-Bounded $address
    if (-not $entry -or -not (Get-CleanName $entry.HostName)) { continue }
    $name = Get-CleanName $entry.HostName
    # A reverse name counts only when it resolves back to one of this machine's addresses (stale PTR records are common).
    $forward = Resolve-Bounded $name
    if ($forward -and ($forward.AddressList | Where-Object { $ownAddresses.Contains($_.ToString()) })) { $candidates.Add($name) }
}
$candidates.Add($bare)

$seen = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
$qualified = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
$short = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
foreach ($candidate in $candidates) {
    $name = Get-CleanName $candidate
    if (-not $name -or -not (Test-DnsName $name) -or -not $seen.Add($name)) { continue }
    if ($name.Contains('.')) { $qualified.Add($name) } else { $short.Add($name) }
}

$added = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
foreach ($raw in $AdditionalNames) {
    $name = Get-CleanName $raw
    if (-not $name) { continue }
    if ($name.Contains('*')) { throw "No wildcards: give '$raw' in full." }
    $address = $null
    if ([System.Net.IPAddress]::TryParse($name.Trim('[', ']'), [ref] $address)) { throw "'$raw' is an address; the certificate names DNS names only." }
    if (-not (Test-DnsName $name)) { throw "'$raw' is not a DNS name: letters, digits and hyphens between dots." }
    if ($seen.Add($name)) { $added.Add($name) }
}

$names = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
foreach ($name in $qualified) { $names.Add($name) }
foreach ($name in $short) { $names.Add($name) }
foreach ($name in $added) { $names.Add($name) }
if ($names.Count -eq 0) { throw 'This machine has no usable DNS name.' }
if ($names.Count -gt $MaxNames) {
    Write-Warning "The service takes at most $MaxNames names; left out: $(($names.GetRange($MaxNames, $names.Count - $MaxNames)) -join ', ')"
    $names.RemoveRange($MaxNames, $names.Count - $MaxNames)
}
$primary = $names[0]
Write-Info "Names: $($names -join ', ')"

# --- PEM and certificate helpers -----------------------------------------------------------------------------------------------

function ConvertTo-Pem([System.String] $Label, [byte[]] $Der) {
    $text = [System.Convert]::ToBase64String($Der)
    $builder = New-Object -TypeName 'System.Text.StringBuilder'
    [void] $builder.Append("-----BEGIN $Label-----`n")
    for ($at = 0; $at -lt $text.Length; $at = $at + 64) { [void] $builder.Append($text.Substring($at, [System.Math]::Min(64, $text.Length - $at))).Append("`n") }
    [void] $builder.Append("-----END $Label-----`n")
    $builder.ToString()
}

function ConvertFrom-PemCertificates([System.String] $Text) {
    $found = New-Object -TypeName 'System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]'
    $pattern = New-Object -TypeName 'System.Text.RegularExpressions.Regex' -ArgumentList '-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----'
    foreach ($match in $pattern.Matches($Text)) {
        $der = [System.Convert]::FromBase64String(($match.Groups[1].Value -replace '\s', ''))
        $found.Add((New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Certificate2' -ArgumentList (, $der)))
    }
    , $found
}

# The certificate's DNS names, read from its subject alternative name extension (DER), not its localised text.
function Get-DnsNames([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $result = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
    $extension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
    if (-not $extension) { return , $result }
    $data = $extension.RawData
    if ($data.Length -lt 2 -or $data[0] -ne 0x30) { return , $result }
    $outer = Read-DerHeader $data 0
    $at = $outer.Header
    $end = $outer.Header + $outer.Length
    while ($at -lt $end) {
        $tag = $data[$at]
        $inner = Read-DerHeader $data $at
        if ($tag -eq 0x82) { $result.Add([System.Text.Encoding]::ASCII.GetString($data, $at + $inner.Header, $inner.Length).ToLowerInvariant()) }
        $at = $at + $inner.Header + $inner.Length
    }
    , $result
}

# A DER element's header at At: how many bytes the tag and length take, and the length of its content.
function Read-DerHeader([byte[]] $Data, [System.Int32] $At) {
    $length = [System.Int32] $Data[$At + 1]
    $header = 2
    if ($length -band 0x80) {
        $count = $length -band 0x7F
        $length = 0
        for ($i = 0; $i -lt $count; $i++) { $length = ($length -shl 8) -bor $Data[$At + 2 + $i] }
        $header = 2 + $count
    }
    [pscustomobject]@{ Header = $header; Length = $length }
}

function Test-ServerCertificate([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate) {
    $constraints = $Certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] }
    if ($constraints | Where-Object { $_.CertificateAuthority }) { return $false }
    $usages = $Certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] }
    if ($usages -and -not ($usages | Where-Object { $_.EnhancedKeyUsages | Where-Object { $_.Value -eq $ServerAuth } })) { return $false }
    $true
}

# The root the chain ends at, when it is one of the service's.
function Get-ChainRoot([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate, $Roots) {
    $chain = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Chain' -ArgumentList $true
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        foreach ($root in $Roots) { [void] $chain.ChainPolicy.ExtraStore.Add($root) }
        [void] $chain.Build($Certificate)
        if ($chain.ChainElements.Count -lt 2) { return $null }
        $top = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        $Roots | Where-Object { $_.Thumbprint -eq $top.Thumbprint } | Select-Object -First 1
    }
    finally { $chain.Reset() }
}

function Open-Store([System.String] $Name, [System.Security.Cryptography.X509Certificates.OpenFlags] $Flags) {
    $store = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X509Store' -ArgumentList $Name, ([System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $store.Open($Flags)
    $store
}

function Get-HttpStatus($ErrorRecord) {
    $response = $ErrorRecord.Exception.PSObject.Properties['Response']
    if ($response -and $response.Value) { return [System.Int32] $response.Value.StatusCode }
    $null
}

function Get-RetryAfterSeconds($ErrorRecord) {
    $response = $ErrorRecord.Exception.PSObject.Properties['Response']
    if (-not $response -or -not $response.Value) { return $null }
    $headers = $response.Value.Headers
    try {
        if ($headers.PSObject.Properties['RetryAfter'] -and $headers.RetryAfter -and $headers.RetryAfter.Delta) { return [System.Int32] $headers.RetryAfter.Delta.TotalSeconds }
        $value = $headers['Retry-After']
        $seconds = 0
        if ($value -and [System.Int32]::TryParse("$value", [ref] $seconds)) { return $seconds }
    }
    catch { }
    $null
}

# --- The 2Pint products -----------------------------------------------------------------------------------------------------------

$ProductRoot = 'SOFTWARE\2Pint Software'
# The settings DeployR Community's installer points at its certificate, and the services (by display name) that read them when they start.
$KnownSettings = New-Object -TypeName 'System.Collections.Generic.List[System.Object]'
	$KnownSettings.Add([pscustomobject]@{ Key = '2PXE\GeneralSettings'; Value = 'HostCertificateThumbprint'; Service = '^2Pint Software 2PXE$' })
	$KnownSettings.Add([pscustomobject]@{ Key = 'DeployR\GeneralSettings'; Value = 'CertificateThumbprint'; Service = '^2Pint Software DeployR' })
	$KnownSettings.Add([pscustomobject]@{ Key = 'StifleR\Server\GeneralSettings'; Value = 'WSCertificateThumbprint'; Service = '^2Pint Software StifleR Server' })
	$KnownSettings.Add([pscustomobject]@{ Key = 'StifleR\Server\GeneralSettings'; Value = 'SignalRCertificateThumbprint'; Service = '^2Pint Software StifleR Server' })

function Get-CleanThumbprint($Value) { ("$Value" -replace '[^0-9A-Fa-f]', '').ToUpperInvariant() }

# Points the products' settings at the certificate. Each value on its own: one that cannot be changed is warned about and the rest go on.
function Update-ProductSettings {
    [CmdletBinding(SupportsShouldProcess)]
    param([System.String] $Thumbprint, $Older, $InStore, $Changes, $Restart)
    try {
        $hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $top = $hive.OpenSubKey($ProductRoot)
    }
    catch { Write-Warning "Could not read HKLM\${ProductRoot}: $($_.Exception.Message)"; return }
    if (-not $top) { Write-Info 'No 2Pint product settings on this machine.'; return }
    $top.Close()

    $handled = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($known in $KnownSettings) {
        $path = "$ProductRoot\$($known.Key)"
        [void] $handled.Add("$path|$($known.Value)")
        try {
            $key = $hive.OpenSubKey($path, $true)
            if (-not $key) { continue }
            try {
                if ($known.Key -like 'DeployR\*') {
                    $locate = "$($key.GetValue('CertificateLocateBy'))"
                    if ($locate -and $locate -ne 'CertificateThumbprint') { Write-Info "DeployR finds its certificate by $locate; left as it is."; continue }
                }
                if ($key.GetValueNames() -notcontains $known.Value) { continue }
                $current = Get-CleanThumbprint $key.GetValue($known.Value)
                if ($current -eq $Thumbprint) { continue }
                if ($current -and -not $Older.Contains($current) -and $InStore.Contains($current)) {
                    Write-Info "HKLM\$path\$($known.Value) names another certificate ($current); left as it is."
                    continue
                }
                if ($PSCmdlet.ShouldProcess("HKLM\$path\$($known.Value)", "Set to $Thumbprint")) {
                    $key.SetValue($known.Value, $Thumbprint, [Microsoft.Win32.RegistryValueKind]::String)
                    $Changes.Add("HKLM\$path\$($known.Value)")
                    [void] $Restart.Add($known.Service)
                    Write-Info "Set HKLM\$path\$($known.Value) = $Thumbprint"
                }
            }
            finally { $key.Close() }
        }
        catch { Write-Warning "Could not update HKLM\$path\$($known.Value): $($_.Exception.Message)" }
    }

    # Any other *Thumbprint value that names an earlier 2Pint iPXE certificate (the installer's own record among them), at most 500 keys deep.
    $pending = New-Object -TypeName 'System.Collections.Generic.Queue[System.String]'
	$pending.Enqueue($ProductRoot)
    $visited = 0
    while ($pending.Count -gt 0 -and $visited -lt 500) {
        $path = $pending.Dequeue()
        $visited = $visited + 1
        try {
            $key = $hive.OpenSubKey($path, $true)
            if (-not $key) { continue }
            try {
                foreach ($child in $key.GetSubKeyNames()) { $pending.Enqueue("$path\$child") }
                foreach ($name in $key.GetValueNames()) {
                    if ($name -notmatch 'thumbprint' -or $handled.Contains("$path|$name")) { continue }
                    if ($key.GetValueKind($name) -ne [Microsoft.Win32.RegistryValueKind]::String) { continue }
                    $current = Get-CleanThumbprint $key.GetValue($name)
                    if ($current.Length -ne 40 -or $current -eq $Thumbprint -or -not $Older.Contains($current)) { continue }
                    if (-not $PSCmdlet.ShouldProcess("HKLM\$path\$name", "Set to $Thumbprint")) { continue }
                    $key.SetValue($name, $Thumbprint, [Microsoft.Win32.RegistryValueKind]::String)
                    $Changes.Add("HKLM\$path\$name")
                    $product = $path.Substring($ProductRoot.Length).Trim('\').Split('\')[0]
                    if ($product) { [void] $Restart.Add('^2Pint Software ' + [System.Text.RegularExpressions.Regex]::Escape($product)) }
                    Write-Info "Set HKLM\$path\$name = $Thumbprint"
                }
            }
            finally { $key.Close() }
        }
        catch { Write-Warning "Could not update the values under HKLM\${path}: $($_.Exception.Message)" }
    }
    $hive.Close()
}

# http.sys's HTTPS bindings (IP:port and host name:port), read and changed through the Windows HTTP Server API.
if (-not ('TwoPintIpxe.HttpSsl' -as [System.Type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace TwoPintIpxe
{
    public sealed class SslBinding
    {
        public string Kind { get; set; }
        public string Endpoint { get; set; }
        public string Thumbprint { get; set; }
        public Guid AppId { get; set; }
    }

    public static class HttpSsl
    {
        const int SslCertInfo = 1, SslSniCertInfo = 5, QueryNext = 1;
        const uint NoError = 0, InsufficientBuffer = 122, MoreData = 234, NoMoreItems = 259;

        [StructLayout(LayoutKind.Sequential)] struct HttpApiVersion { public ushort Major; public ushort Minor; }

        [StructLayout(LayoutKind.Sequential)]
        struct SslParam
        {
            public int SslHashLength; public IntPtr SslHash; public Guid AppId; public IntPtr SslCertStoreName;
            public uint DefaultCertCheckMode; public uint DefaultRevocationFreshnessTime; public uint DefaultRevocationUrlRetrievalTimeout;
            public IntPtr DefaultSslCtlIdentifier; public IntPtr DefaultSslCtlStoreName; public uint DefaultFlags;
        }

        [StructLayout(LayoutKind.Sequential)] struct SslSet { public IntPtr IpPort; public SslParam Param; }
        [StructLayout(LayoutKind.Sequential)] struct SslQuery { public int QueryDesc; public IntPtr IpPort; public uint Token; }
        [StructLayout(LayoutKind.Sequential)] struct SniKey { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)] public byte[] IpPort; public IntPtr Host; }
        [StructLayout(LayoutKind.Sequential)] struct SniSet { public SniKey Key; public SslParam Param; }
        [StructLayout(LayoutKind.Sequential)] struct SniQuery { public int QueryDesc; public SniKey Key; public uint Token; }

        [DllImport("httpapi.dll")] static extern uint HttpInitialize(HttpApiVersion version, uint flags, IntPtr reserved);
        [DllImport("httpapi.dll")] static extern uint HttpTerminate(uint flags, IntPtr reserved);
        [DllImport("httpapi.dll")] static extern uint HttpQueryServiceConfiguration(IntPtr handle, int id, IntPtr input, int inputLength, IntPtr output, int outputLength, out int returned, IntPtr overlapped);
        [DllImport("httpapi.dll")] static extern uint HttpSetServiceConfiguration(IntPtr handle, int id, IntPtr config, int length, IntPtr overlapped);
        [DllImport("httpapi.dll")] static extern uint HttpDeleteServiceConfiguration(IntPtr handle, int id, IntPtr config, int length, IntPtr overlapped);

        const uint InitializeConfig = 2;

        static void Initialize()
        {
            uint result = HttpInitialize(new HttpApiVersion { Major = 1, Minor = 0 }, InitializeConfig, IntPtr.Zero);
            if (result != NoError) throw new Win32Exception((int)result);
        }

        static string Address(byte[] raw)
        {
            int family = BitConverter.ToUInt16(raw, 0);
            int port = (raw[2] << 8) | raw[3];
            if (family == 2) return new System.Net.IPAddress(new byte[] { raw[4], raw[5], raw[6], raw[7] }) + ":" + port;
            if (family == 23) { var six = new byte[16]; Array.Copy(raw, 8, six, 0, 16); return "[" + new System.Net.IPAddress(six) + "]:" + port; }
            return "family " + family + ":" + port;
        }

        static string Hex(IntPtr hash, int length)
        {
            var bytes = new byte[length];
            Marshal.Copy(hash, bytes, 0, length);
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        // Each binding of one kind, with its raw configuration, to the action given; stops once it says so.
        static void Walk(int id, Func<IntPtr, int, bool> visit)
        {
            for (uint token = 0; token < 10000; token++)
            {
                int inputLength;
                IntPtr input;
                if (id == SslCertInfo)
                {
                    var query = new SslQuery { QueryDesc = QueryNext, Token = token };
                    inputLength = Marshal.SizeOf(typeof(SslQuery));
                    input = Marshal.AllocHGlobal(inputLength);
                    Marshal.StructureToPtr(query, input, false);
                }
                else
                {
                    var query = new SniQuery { QueryDesc = QueryNext, Key = new SniKey { IpPort = new byte[128] }, Token = token };
                    inputLength = Marshal.SizeOf(typeof(SniQuery));
                    input = Marshal.AllocHGlobal(inputLength);
                    Marshal.StructureToPtr(query, input, false);
                }
                try
                {
                    int size;
                    uint result = HttpQueryServiceConfiguration(IntPtr.Zero, id, input, inputLength, IntPtr.Zero, 0, out size, IntPtr.Zero);
                    if (result == NoMoreItems) return;
                    if (result != InsufficientBuffer && result != MoreData) throw new Win32Exception((int)result);
                    IntPtr output = Marshal.AllocHGlobal(size);
                    try
                    {
                        result = HttpQueryServiceConfiguration(IntPtr.Zero, id, input, inputLength, output, size, out size, IntPtr.Zero);
                        if (result != NoError) throw new Win32Exception((int)result);
                        if (!visit(output, size)) return;
                    }
                    finally { Marshal.FreeHGlobal(output); }
                }
                finally { Marshal.FreeHGlobal(input); }
            }
        }

        static SslBinding Read(int id, IntPtr output)
        {
            if (id == SslCertInfo)
            {
                var set = (SslSet)Marshal.PtrToStructure(output, typeof(SslSet));
                var raw = new byte[28];
                Marshal.Copy(set.IpPort, raw, 0, BitConverter.ToUInt16(new[] { Marshal.ReadByte(set.IpPort), Marshal.ReadByte(set.IpPort, 1) }, 0) == 23 ? 28 : 16);
                return new SslBinding { Kind = "ipport", Endpoint = Address(raw), Thumbprint = Hex(set.Param.SslHash, set.Param.SslHashLength), AppId = set.Param.AppId };
            }
            var sni = (SniSet)Marshal.PtrToStructure(output, typeof(SniSet));
            int port = (sni.Key.IpPort[2] << 8) | sni.Key.IpPort[3];
            return new SslBinding { Kind = "hostnameport", Endpoint = Marshal.PtrToStringUni(sni.Key.Host) + ":" + port, Thumbprint = Hex(sni.Param.SslHash, sni.Param.SslHashLength), AppId = sni.Param.AppId };
        }

        public static List<SslBinding> List()
        {
            var found = new List<SslBinding>();
            Initialize();
            try
            {
                foreach (int id in new[] { SslCertInfo, SslSniCertInfo })
                {
                    Walk(id, (output, size) => { found.Add(Read(id, output)); return true; });
                }
            }
            finally { HttpTerminate(InitializeConfig, IntPtr.Zero); }
            return found;
        }

        // The binding moved to another certificate in LocalMachine\My: deleted and set again with every other parameter as it was, then read
        // back; when the new one cannot be set or read back, the old one is put back.
        public static void Replace(string kind, string endpoint, string thumbprint)
        {
            int id = kind == "ipport" ? SslCertInfo : SslSniCertInfo;
            var hash = new byte[thumbprint.Length / 2];
            for (int i = 0; i < hash.Length; i++) hash[i] = Convert.ToByte(thumbprint.Substring(i * 2, 2), 16);
            bool done = false;
            Initialize();
            try
            {
                Walk(id, (output, size) =>
                {
                    var binding = Read(id, output);
                    if (!string.Equals(binding.Endpoint, endpoint, StringComparison.OrdinalIgnoreCase)) return true;
                    IntPtr newHash = Marshal.AllocHGlobal(hash.Length);
                    IntPtr store = Marshal.StringToHGlobalUni("MY");
                    int length = id == SslCertInfo ? Marshal.SizeOf(typeof(SslSet)) : Marshal.SizeOf(typeof(SniSet));
                    IntPtr changed = Marshal.AllocHGlobal(length);
                    try
                    {
                        Marshal.Copy(hash, 0, newHash, hash.Length);
                        if (id == SslCertInfo)
                        {
                            var set = (SslSet)Marshal.PtrToStructure(output, typeof(SslSet));
                            set.Param.SslHash = newHash; set.Param.SslHashLength = hash.Length; set.Param.SslCertStoreName = store;
                            Marshal.StructureToPtr(set, changed, false);
                        }
                        else
                        {
                            var set = (SniSet)Marshal.PtrToStructure(output, typeof(SniSet));
                            set.Param.SslHash = newHash; set.Param.SslHashLength = hash.Length; set.Param.SslCertStoreName = store;
                            Marshal.StructureToPtr(set, changed, false);
                        }
                        uint result = HttpDeleteServiceConfiguration(IntPtr.Zero, id, output, length, IntPtr.Zero);
                        if (result != NoError) throw new Win32Exception((int)result);
                        result = HttpSetServiceConfiguration(IntPtr.Zero, id, changed, length, IntPtr.Zero);
                        if (result != NoError)
                        {
                            uint restored = HttpSetServiceConfiguration(IntPtr.Zero, id, output, length, IntPtr.Zero);
                            throw new Win32Exception((int)result, new Win32Exception((int)result).Message + (restored == NoError ? "; the old binding was put back" : "; the old binding could not be put back either"));
                        }
                        done = true;
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(changed);
                        Marshal.FreeHGlobal(store);
                        Marshal.FreeHGlobal(newHash);
                    }
                    return false;
                });
            }
            finally { HttpTerminate(InitializeConfig, IntPtr.Zero); }
            if (!done) throw new InvalidOperationException("The binding " + endpoint + " is no longer there.");
            foreach (var now in List())
            {
                if (now.Kind == kind && string.Equals(now.Endpoint, endpoint, StringComparison.OrdinalIgnoreCase))
                {
                    if (now.Thumbprint != thumbprint.ToUpperInvariant()) throw new InvalidOperationException("The binding " + endpoint + " reads back " + now.Thumbprint + ".");
                    return;
                }
            }
            throw new InvalidOperationException("The binding " + endpoint + " is not there after it was set.");
        }
    }
}
'@
}

# Every http.sys HTTPS binding that uses an earlier 2Pint iPXE certificate, moved to this one; http.sys uses it from the next connection.
function Update-HttpBindings {
    [CmdletBinding(SupportsShouldProcess)]
    param([System.String] $Thumbprint, $Older, $Changes)
    try { $bindings = [TwoPintIpxe.HttpSsl]::List() }
    catch { Write-Warning "Could not read the http.sys HTTPS bindings: $($_.Exception.Message)"; return }
    foreach ($binding in $bindings) {
        if (-not $Older.Contains($binding.Thumbprint)) { continue }
        $what = "http.sys binding $($binding.Endpoint)"
        if (-not $PSCmdlet.ShouldProcess($what, "Use certificate $Thumbprint instead of $($binding.Thumbprint)")) { continue }
        try {
            [TwoPintIpxe.HttpSsl]::Replace($binding.Kind, $binding.Endpoint, $Thumbprint)
            $Changes.Add($what)
            Write-Info "Moved the $what to $Thumbprint."
        }
        catch { Write-Warning "Could not move the $what to the new certificate: $($_.Exception.Message)" }
    }
}

# The running services whose settings changed, restarted with a bounded wait; one that does not come back is warned about.
function Restart-ProductServices {
    [CmdletBinding(SupportsShouldProcess)]
    param($Patterns, $Restarted)
    if ($Patterns.Count -eq 0) { return }
    foreach ($service in (Get-Service | Sort-Object -Property Name)) {
        if (-not ($Patterns | Where-Object { $service.DisplayName -match $_ })) { continue }
        if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            Write-Info "$($service.DisplayName) is not running; it takes the certificate when it next starts."
            continue
        }
        if (-not $RestartServices) { Write-Info "$($service.DisplayName) takes the certificate when it next starts, or restart it now (-RestartServices)."; continue }
        if (-not $PSCmdlet.ShouldProcess($service.DisplayName, 'Restart')) { continue }
        try {
            $service.Stop()
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [System.TimeSpan]::FromMinutes(2))
            $service.Start()
            $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [System.TimeSpan]::FromMinutes(2))
            $Restarted.Add($service.DisplayName)
            Write-Info "Restarted $($service.DisplayName)."
        }
        catch { Write-Warning "Could not restart $($service.DisplayName); restart it to use the new certificate: $($_.Exception.Message)" }
    }
}

# Points every 2Pint product at the certificate and returns what changed.
function Update-Products {
    [CmdletBinding(SupportsShouldProcess)]
    param([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate, $Others)
    $changes = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
    $restarted = New-Object -TypeName 'System.Collections.Generic.List[System.String]'
    if (-not $UpdateProductSettings) { return [pscustomobject]@{ Changed = $changes.ToArray(); Restarted = $restarted.ToArray() } }
    $thumbprint = $Certificate.Thumbprint.ToUpperInvariant()
    $older = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($other in $Others) { if ($other.Thumbprint -ne $thumbprint) { [void] $older.Add($other.Thumbprint) } }
    $inStore = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    $personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try { foreach ($installed in $personal.Certificates) { [void] $inStore.Add($installed.Thumbprint) } }
    finally { $personal.Close() }
    $restart = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    Update-ProductSettings -Thumbprint $thumbprint -Older $older -InStore $inStore -Changes $changes -Restart $restart
    Update-HttpBindings -Thumbprint $thumbprint -Older $older -Changes $changes
    Restart-ProductServices -Patterns $restart -Restarted $restarted
    if ($changes.Count -eq 0) { Write-Info 'The 2Pint products already use this certificate.' }
    [pscustomobject]@{ Changed = $changes.ToArray(); Restarted = $restarted.ToArray() }
}

# --- The root -----------------------------------------------------------------------------------------------------------------

$roots = New-Object -TypeName 'System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]'
try {
    $answer = Invoke-WebRequest -Uri $caUrl -Method Get -UseBasicParsing -TimeoutSec 30
    $content = $answer.Content
    $text = if ($content -is [byte[]]) {
        if ($content.Length -gt 0 -and $content[0] -eq 0x30) { ConvertTo-Pem 'CERTIFICATE' $content } else { [System.Text.Encoding]::UTF8.GetString($content) }
    }
    else { "$content" }
    foreach ($certificate in (ConvertFrom-PemCertificates $text)) {
        $authority = $certificate.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] -and $_.CertificateAuthority }
        if ($authority -and $certificate.Subject -eq $certificate.Issuer) { $roots.Add($certificate) }
    }
    if ($roots.Count -eq 0) { Write-Warning "The service's answer at $caUrl holds no root certificate." }
}
catch {
    Write-Warning "The root could not be fetched from ${caUrl}: $($_.Exception.Message)"
}

$rootFlags = if ($WhatIfPreference) { [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly } else { [System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite }
$rootStore = Open-Store 'Root' $rootFlags
try {
    foreach ($root in $roots) {
        if ($rootStore.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $root.Thumbprint, $false).Count -gt 0) {
            Write-Info "Root already installed: $($root.Subject) ($($root.Thumbprint))"
        }
        elseif ($PSCmdlet.ShouldProcess("LocalMachine\Root", "Add $($root.Subject) ($($root.Thumbprint))")) {
            $rootStore.Add($root)
            Write-Info "Root installed: $($root.Subject) ($($root.Thumbprint))"
        }
    }
    if ($roots.Count -eq 0) {
        # Without the service's answer, the roots installed before stand for it, so a run without network still checks what it has.
        foreach ($installed in $rootStore.Certificates) {
            if ($installed.Subject -match 'CN=2Pint iPXE Root CA') { $roots.Add($installed) }
        }
    }
}
finally { $rootStore.Close() }

# --- The certificate installed ---------------------------------------------------------------------------------------------------

$now = [System.DateTime]::Now
$mine = New-Object -TypeName 'System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]'
$personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
try {
    foreach ($certificate in $personal.Certificates) {
        if ($roots.Count -gt 0 -and (Get-ChainRoot $certificate $roots)) { $mine.Add($certificate) }
    }
}
finally { $personal.Close() }

$current = $null
foreach ($certificate in ($mine | Sort-Object NotAfter -Descending)) {
    if (-not $certificate.HasPrivateKey -or -not (Test-ServerCertificate $certificate)) { continue }
    if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) { continue }
    $covered = Get-DnsNames $certificate
    if ($names | Where-Object { -not $covered.Contains($_) }) { continue }
    $current = $certificate
    break
}

if ($current -and -not $Force -and $current.NotAfter -gt $now.AddDays($RenewDays)) {
    Write-Info "Kept: $($current.Thumbprint), valid until $($current.NotAfter), covers every name; renews from $($current.NotAfter.AddDays(-$RenewDays))."
    $readers = Grant-KeyAccess -Certificate $current
    $products = Update-Products -Certificate $current -Others $mine
    return [pscustomobject]@{
        Action     = 'Kept'
        Thumbprint = $current.Thumbprint
        Subject    = $current.Subject
        Names      = (Get-DnsNames $current).ToArray()
        NotAfter   = $current.NotAfter
        RenewFrom  = $current.NotAfter.AddDays(-$RenewDays)
        KeyAccess  = $readers.ToArray()
        Changed    = $products.Changed
        Restarted  = $products.Restarted
    }
}

if ($roots.Count -eq 0 -and -not $WhatIfPreference) { throw "No 2Pint iPXE root is known: the service at $caUrl did not answer with one and none is installed." }
$action = if ($current) { 'Renewed' } else { 'Issued' }
$why = if ($Force) { 'requested with -Force' } elseif ($current) { "$($current.Thumbprint) has $([System.Math]::Floor(($current.NotAfter - $now).TotalDays)) days left" } else { 'no installed certificate covers every name' }
Write-Info "Requesting a certificate: $why."

# --- The key and the signing request -------------------------------------------------------------------------------------------

$keyName = "iPXE HTTPS $primary $([System.Guid]::NewGuid().ToString('N').Substring(0, 8))"
$persisted = $PSCmdlet.ShouldProcess("the machine's key store", "Create RSA 2048 key '$keyName' ($KeyStorage)")
$cngKey = $null
if (-not $persisted) {
    # -WhatIf: a key held only in memory, to show the request; nothing is stored.
    $rsa = New-Object -TypeName 'System.Security.Cryptography.RSACng' -ArgumentList 2048
}
elseif ($KeyStorage -eq 'Cng') {
    $parameters = New-Object -TypeName 'System.Security.Cryptography.CngKeyCreationParameters'
    $parameters.Provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::MachineKey
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::AllUsages
    $length = New-Object -TypeName 'System.Security.Cryptography.CngProperty' -ArgumentList 'Length', ([System.BitConverter]::GetBytes([System.Int32] 2048)), ([System.Security.Cryptography.CngPropertyOptions]::None)
    $parameters.Parameters.Add($length)
    $cngKey = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::Rsa, $keyName, $parameters)
    $rsa = New-Object -TypeName 'System.Security.Cryptography.RSACng' -ArgumentList $cngKey
}
else {
    $csp = New-Object -TypeName 'System.Security.Cryptography.CspParameters' -ArgumentList 24, 'Microsoft Enhanced RSA and AES Cryptographic Provider', $keyName
    $csp.Flags = [System.Security.Cryptography.CspProviderFlags]::UseMachineKeyStore -bor [System.Security.Cryptography.CspProviderFlags]::UseNonExportableKey
    $csp.KeyNumber = [System.Int32] [System.Security.Cryptography.KeyNumber]::Exchange
    $rsa = New-Object -TypeName 'System.Security.Cryptography.RSACryptoServiceProvider' -ArgumentList 2048, $csp
    $rsa.PersistKeyInCsp = $true
}

# The key made for this request goes again unless the certificate is installed with it.
$keep = $false
try {
    $subject = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.X500DistinguishedName' -ArgumentList "CN=$primary"
    $request = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.CertificateRequest' -ArgumentList $subject, $rsa,
        ([System.Security.Cryptography.HashAlgorithmName]::SHA256), ([System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $alternative = New-Object -TypeName 'System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder'
    foreach ($name in $names) { $alternative.AddDnsName($name) }
    $request.CertificateExtensions.Add($alternative.Build())
    $csrPem = ConvertTo-Pem 'CERTIFICATE REQUEST' $request.CreateSigningRequest()

    if (-not $persisted) {
        Write-Info "What if: the signing request for $primary would be sent to $caUrl."
        Write-Host $csrPem
        return
    }

    # --- The service --------------------------------------------------------------------------------------------------------

    $sha = [System.Security.Cryptography.SHA512]::Create()
    try { $apiKey = [System.Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($LicenseKey.Trim()))) }
    finally { $sha.Dispose() }
    $headers = @{ 'X-API-Key' = $apiKey; 'X-API-Client-Version' = 'Install-IpxeCertificate.ps1 1.0'; 'Accept' = 'text/plain' }
    $body = @{ pem = $csrPem; sans = $names.ToArray() } | ConvertTo-Json -Compress

    $leafPem = $null
    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $answer = Invoke-WebRequest -Uri $caUrl -Method Post -Headers $headers -ContentType 'application/json' -Body $body -UseBasicParsing -TimeoutSec 60
            $leafPem = if ($answer.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($answer.Content) } else { "$($answer.Content)" }
            break
        }
        catch {
            $status = Get-HttpStatus $_
            if ($status -in 401, 403) { throw 'The service does not accept the license key.' }
            $retryable = ($null -eq $status) -or $status -eq 429 -or $status -ge 500
            if (-not $retryable -or $attempt -eq $MaxAttempts) {
                $said = if ($status) { "answered $status" } else { 'gave no answer' }
                throw "The service $said after $attempt attempt(s): $($_.Exception.Message)"
            }
            $wait = Get-RetryAfterSeconds $_
            if (-not $wait) { $wait = 30 * $attempt }
            $wait = [System.Math]::Min([System.Math]::Max($wait, 5), 300)
            Write-Warning "The service $(if ($status) { "answered $status" } else { 'gave no answer' }); asking again in $wait s (attempt $attempt of $MaxAttempts)."
            Start-Sleep -Seconds $wait
        }
    }

    # --- The answer, checked ------------------------------------------------------------------------------------------------

    if ($leafPem.TrimStart().StartsWith('{')) {
        # An answer wrapped in JSON: the first string in it that holds a certificate.
        $wrapped = $leafPem | ConvertFrom-Json
        $leafPem = $wrapped.PSObject.Properties | ForEach-Object { "$($_.Value)" } | Where-Object { $_ -match 'BEGIN CERTIFICATE' } | Select-Object -First 1
        if (-not $leafPem) { throw "The service's answer holds no certificate." }
    }
    $issued = (ConvertFrom-PemCertificates $leafPem) | Select-Object -First 1
    if (-not $issued) { throw "The service's answer is not a certificate." }
    $ours = $request.PublicKey.EncodedKeyValue.RawData
    $theirs = $issued.PublicKey.EncodedKeyValue.RawData
    if ([System.Convert]::ToBase64String($ours) -ne [System.Convert]::ToBase64String($theirs)) { throw 'The certificate is not for the key this request was made with.' }
    if (-not (Test-ServerCertificate $issued)) { throw 'The service sent an authority or a certificate that is not for servers.' }
    if ($issued.NotAfter -le $now -or $issued.NotBefore -gt $now.AddDays(2)) { throw 'The certificate is not in date.' }
    $issuer = Get-ChainRoot $issued $roots
    if (-not $issuer) { throw "The certificate ($($issued.Issuer)) does not chain to the 2Pint iPXE root." }
    $covered = Get-DnsNames $issued
    $missing = $names | Where-Object { -not $covered.Contains($_) }
    if ($missing) { Write-Warning "The certificate leaves out: $($missing -join ', ')" }

    # --- Installed -----------------------------------------------------------------------------------------------------------

    $withKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($issued, $rsa)
    $withKey.FriendlyName = $FriendlyName
    if (-not $PSCmdlet.ShouldProcess('LocalMachine\My', "Add $($issued.Subject) ($($issued.Thumbprint))")) { return }
    $personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try { $personal.Add($withKey) }
    finally { $personal.Close() }

    # Read back from a fresh handle: the store must link the certificate to the persisted key, not to this session's.
    $personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $stored = $personal.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $issued.Thumbprint, $false)
        $linked = $stored.Count -gt 0 -and $stored[0].HasPrivateKey
    }
    finally { $personal.Close() }
    if (-not $linked) {
        $personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        try { foreach ($added in $personal.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $issued.Thumbprint, $false)) { $personal.Remove($added) } }
        finally { $personal.Close() }
        throw 'The certificate could not be stored with its private key; nothing was installed.'
    }
    $keep = $true
    Write-Info "$action`: $($issued.Thumbprint), $($issued.Subject), issued by $($issued.Issuer), valid until $($issued.NotAfter)."
    $readers = Grant-KeyAccess -Certificate $stored[0]
    $products = Update-Products -Certificate $stored[0] -Others $mine

    $personal = Open-Store 'My' ([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        if ($RemoveReplaced) {
            foreach ($old in $mine) {
                # An earlier 2Pint iPXE certificate for this machine's name: the subject's name among its names.
                if ($old.Thumbprint -eq $issued.Thumbprint -or -not (Get-DnsNames $old).Contains($primary)) { continue }
                if (-not $PSCmdlet.ShouldProcess('LocalMachine\My', "Remove replaced $($old.Thumbprint)")) { continue }
                $oldKey = $null
                try { $oldKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($old) } catch { }
                $personal.Remove($old)
                if ($oldKey -is [System.Security.Cryptography.RSACng]) { $oldKey.Key.Delete() }
                elseif ($oldKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $oldKey.PersistKeyInCsp = $false; $oldKey.Clear() }
                Write-Info "Removed replaced certificate $($old.Thumbprint) and its key."
            }
        }
    }
    finally { $personal.Close() }

    # --- Copies for reference -------------------------------------------------------------------------------------------------

    if ($PSCmdlet.ShouldProcess($OutputDirectory, 'Write the request, certificate and root as PEM')) {
        New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
        $utf8 = New-Object -TypeName 'System.Text.UTF8Encoding' -ArgumentList $false
        [System.IO.File]::WriteAllText((Join-Path $OutputDirectory "$primary.csr"), $csrPem, $utf8)
        [System.IO.File]::WriteAllText((Join-Path $OutputDirectory "$primary.cer"), (ConvertTo-Pem 'CERTIFICATE' $issued.RawData), $utf8)
        [System.IO.File]::WriteAllText((Join-Path $OutputDirectory '2Pint-iPXE-Root-CA.cer'), (ConvertTo-Pem 'CERTIFICATE' $issuer.RawData), $utf8)
    }

    [pscustomobject]@{
        Action     = $action
        Thumbprint = $issued.Thumbprint
        Subject    = $issued.Subject
        Names      = $covered.ToArray()
        NotAfter   = $issued.NotAfter
        RenewFrom  = $issued.NotAfter.AddDays(-$RenewDays)
        Root       = $issuer.Thumbprint
        Replaced   = if ($current) { $current.Thumbprint } else { $null }
        KeyAccess  = $readers.ToArray()
        Changed    = $products.Changed
        Restarted  = $products.Restarted
    }
}
finally {
    if (-not $keep -and $persisted) {
        # Nothing was installed with it: the key goes, so a failed run leaves nothing behind.
        if ($cngKey) { $cngKey.Delete() }
        elseif ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) { $rsa.PersistKeyInCsp = $false; $rsa.Clear() }
    }
}
