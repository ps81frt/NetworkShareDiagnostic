#Requires -Version 5.1
<#
.SYNOPSIS
    NetworkShareDiagnostic - Outil de diagnostic complet Partages Reseau & SMB Windows

.DESCRIPTION
    Diagnostic complet des partages reseau pour Windows 10/11.
    Analyse la configuration SMB (serveur + client), pare-feu, politique d'authentification,
    connectivite, journaux d'evenements, historique des connexions et genere un rapport HTML en francais.

.AUTHOR
    ps81frt

.VERSION
    1.1.0

.LICENSE
    MIT License
    Copyright (c) 2025 ps81frt
    https://github.com/ps81frt/NetworkShareDiagnostic

.LINK
    https://github.com/ps81frt/NetworkShareDiagnostic

.NOTES
    - Lecture seule : AUCUNE modification systeme
    - Droits eleves recommandes pour acces complet (fonctionne en mode degrade sinon)
    - Compatible : PowerShell 5.1 / 7.x — Windows 10/11 Pro/Entreprise
    - Rapport HTML entierement en francais
#>

[CmdletBinding()]
param(
    [ValidateSet('COMPLET','PUBLIC')]
    [string]$Mode,

    [string]$OutputPath = "C:\Temp",

    [switch]$EnableDebug
)

$DebugEnabled = $EnableDebug.IsPresent

function Write-DebugHost {
    param([string]$Message, [ConsoleColor]$Color = [ConsoleColor]::Gray)
    if ($DebugEnabled) {
        Write-Host $Message -ForegroundColor $Color
    }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'

# ─────────────────────────────────────────────────────────────────────────────
# REGION: VERIFICATION VERSION PS
# ─────────────────────────────────────────────────────────────────────────────
$PSVersionFull  = $PSVersionTable.PSVersion
if ($PSVersionFull.Major -lt 5 -or ($PSVersionFull.Major -eq 5 -and $PSVersionFull.Minor -lt 1)) {
    Write-Host "[CRITIQUE] PowerShell 5.1 minimum requis. Version actuelle : $PSVersionFull" -ForegroundColor Red
    exit 1
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: BANNIERE
# ─────────────────────────────────────────────────────────────────────────────
Clear-Host
$banner = @"
╔══════════════════════════════════════════════════════════════════╗
║          NetworkShareDiagnostic  v1.1.0                          ║
║          Auteur  : ps81frt                                       ║
║          Licence : MIT                                           ║
║          GitHub  : github.com/ps81frt/NetworkShareDiagnostic     ║
║          PS      : $PSVersionFull $(if($PSVersionFull.Major -ge 7){'(Core) ✓'}else{'(Windows) ✓'})
╚══════════════════════════════════════════════════════════════════╝
"@
Write-Host $banner -ForegroundColor Cyan

# ─────────────────────────────────────────────────────────────────────────────
# REGION: VERIFICATION ELEVATION
# ─────────────────────────────────────────────────────────────────────────────
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[AVERTISSEMENT] Pas execute en Administrateur. Certaines donnees seront indisponibles." -ForegroundColor Yellow
    Write-Host "          Relancer avec : Start-Process powershell -Verb RunAs -ArgumentList '-File $PSCommandPath'" -ForegroundColor Yellow
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: CREATION DOSSIER DE SORTIE
# ─────────────────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Host "[INFO] Dossier de sortie cree : $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "[ERREUR] Impossible de creer '$OutputPath' : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "         Utilisation du dossier temporaire systeme : $env:TEMP" -ForegroundColor Yellow
        $OutputPath = $env:TEMP
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: SELECTION DU MODE
# ─────────────────────────────────────────────────────────────────────────────
if (-not $Mode) {
    Write-Host "Selectionnez le mode de rapport :" -ForegroundColor White
    Write-Host ""
    Write-Host "  [1] COMPLET  - Toutes les donnees affichees (usage personnel/interne)" -ForegroundColor Green
    Write-Host "  [2] PUBLIC   - Donnees sensibles masquees (partage externe/support)"   -ForegroundColor Blue
    Write-Host ""
    Write-Host "  [Q] Quitter" -ForegroundColor Gray
    Write-Host ""
    do {
        $choice = Read-Host "Choix"
        switch ($choice.ToUpper()) {
            '1' { $Mode = 'COMPLET'; break }
            '2' { $Mode = 'PUBLIC';  break }
            'Q' { Write-Host "Fermeture." -ForegroundColor Gray; exit 0 }
            default { Write-Host "Choix invalide. Entrez 1, 2 ou Q." -ForegroundColor Red }
        }
    } while (-not $Mode)
}

Write-Host ""
Write-Host "[MODE] $Mode selectionne" -ForegroundColor $(if($Mode -eq 'COMPLET'){'Green'}else{'Cyan'})
Write-Host "[INFO] Demarrage de la collecte... (lecture seule, aucune modification systeme)" -ForegroundColor Gray
Write-Host ""

$ScriptStartTime = Get-Date

# ─────────────────────────────────────────────────────────────────────────────
# DEBUG: MODE ET CHEMIN DE SORTIE
# ─────────────────────────────────────────────────────────────────────────────

$EnableDebug = $Debug.IsPresent
function Write-DebugHost {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    if ($EnableDebug) {
        Write-Host $Message -ForegroundColor $Color
    }
}
# ─────────────────────────────────────────────────────────────────────────────
# REGION: FONCTIONS UTILITAIRES
# ─────────────────────────────────────────────────────────────────────────────

function SET-Mask-IP {
    param([string]$IP)
    if ($Mode -eq 'PUBLIC' -and $IP -match '^\d+\.\d+\.\d+\.\d+$') {
        $parts = $IP.Split('.')
        return "$($parts[0]).$($parts[1]).x.xxx"
    }
    return $IP
}

function Set-Mask-MAC {
    param([string]$MAC)
    if ($Mode -eq 'PUBLIC') { return 'XX:XX:XX:XX:XX:XX' }
    return $MAC
}

function Set-Mask-Host {
    param([string]$Hostname)
    if ($Mode -eq 'PUBLIC' -and $Hostname -ne '' -and $Hostname -ne 'N/A') {
        if ($Hostname.Length -gt 3) { return $Hostname.Substring(0,3) + ('*' * [Math]::Min(5,$Hostname.Length-3)) }
        return '***'
    }
    return $Hostname
}

function Set-Mask-SID {
    param([string]$SID)
    if ($Mode -eq 'PUBLIC') { return 'S-1-5-***-***' }
    return $SID
}

function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
        'OK'       { return '<span class="badge ok">✅ OK</span>' }
        'WARN'     { return '<span class="badge warn">⚠️ AVERT.</span>' }
        'CRITICAL' { return '<span class="badge critical">❌ CRITIQUE</span>' }
        'INFO'     { return '<span class="badge info">ℹ️ INFO</span>' }
        default    { return "<span class='badge info'>$Status</span>" }
    }
}

function Write-Step {
    param([string]$Message)
    Write-Host "  → $Message" -ForegroundColor DarkCyan
}

function Set-Safe-Get {
    param([scriptblock]$Block, $Default = $null)
    try { return (& $Block) }
    catch { return $Default }
}

function Set-Safe-String {
    param($Value, [string]$Default = 'N/A')
    if ($null -eq $Value -or "$Value" -eq '') { return $Default }
    return "$Value"
}

function HtmlEncode {
    param([string]$s)
    $s = $s -replace '&','&amp;'
    $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;'
    $s = $s -replace '"','&quot;'
    return $s
}

function Get-RegValue {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return 'NON DEFINI' }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: COLLECTE DES DONNEES
# ─────────────────────────────────────────────────────────────────────────────

# 1. IDENTITE MACHINE
Write-Step "Collecte de l'identite machine..."
$OS = Set-Safe-Get { Get-CimInstance Win32_OperatingSystem }
$CS = Set-Safe-Get { Get-CimInstance Win32_ComputerSystem }
$Identity = [PSCustomObject]@{
    Hostname     = $env:COMPUTERNAME
    Domaine      = if ($CS -and $CS.PartOfDomain) { $CS.Domain } else { "WORKGROUP: $(if($CS){$CS.Workgroup}else{'N/A'})" }
    OS           = if ($OS) { $OS.Caption }         else { 'N/A' }
    Build        = if ($OS) { $OS.BuildNumber }     else { 'N/A' }
    Version      = if ($OS) { $OS.Version }         else { 'N/A' }
    Architecture = if ($OS) { $OS.OSArchitecture }  else { 'N/A' }
    Uptime       = if ($OS) { (New-TimeSpan -Start $OS.LastBootUpTime -End (Get-Date)).ToString("dd'd 'hh'h 'mm'm'") } else { 'N/A' }
    DernierBoot  = if ($OS) { $OS.LastBootUpTime.ToString("yyyy-MM-dd HH:mm:ss") } else { 'N/A' }
    Utilisateur  = "$env:USERDOMAIN\$env:USERNAME"
    SID          = Set-Mask-SID (Set-Safe-Get { [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } 'N/A')
    EstAdmin     = $IsAdmin
    PSVersion    = $PSVersionFull
    PSEdition    = $PSVersionTable.PSEdition
}

# 2. INTERFACES RESEAU
Write-Step "Collecte des interfaces reseau..."
$NetAdapters   = Set-Safe-Get { Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } } @()
$NetInterfaces = foreach ($Adapter in $NetAdapters) {
    try {
        $IPConfig  = Get-NetIPConfiguration -InterfaceIndex $Adapter.InterfaceIndex
        $IPAddr    = ($IPConfig.IPv4Address | Where-Object { $_.IPAddress -notmatch '^169\.' } | Select-Object -First 1)
        $DNS       = ($IPConfig.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', '
        $IsVirtual = $Adapter.InterfaceDescription -match 'Hyper-V|VMware|VirtualBox|TAP|Loopback|Miniport|WAN|VPN|Tunnel'
        $MTU       = Set-Safe-Get { (Get-NetIPInterface -InterfaceIndex $Adapter.InterfaceIndex -AddressFamily IPv4).NlMtu } 'N/A'
        [PSCustomObject]@{
            Nom         = $Adapter.Name
            Description = $Adapter.InterfaceDescription
            MAC         = Set-Mask-MAC ($Adapter.MacAddress)
            IP          = if ($IPAddr) { SET-Mask-IP $IPAddr.IPAddress } else { 'N/A' }
            Masque      = if ($IPAddr) { $IPAddr.PrefixLength }      else { 'N/A' }
            Passerelle  = if ($IPConfig.IPv4DefaultGateway) { SET-Mask-IP $IPConfig.IPv4DefaultGateway.NextHop } else { 'N/A' }
            DNS         = if ($Mode -eq 'PUBLIC') { ($DNS -replace '\d+\.\d+\.\d+\.\d+','x.x.x.x') } else { $DNS }
            DHCP        = if ($IPConfig.NetIPv4Interface.Dhcp -eq 'Enabled') { 'DHCP' } else { 'Statique' }
            Vitesse     = Set-Safe-String $Adapter.LinkSpeed
            Type        = if ($IsVirtual) { '⚠️ Virtuel/VPN' } else { 'Physique' }
            MTU         = $MTU
            Statut      = $Adapter.Status
        }
    } catch {
        [PSCustomObject]@{
            Nom='N/A'; Description=$Adapter.InterfaceDescription; MAC='N/A'; IP='N/A'
            Masque='N/A'; Passerelle='N/A'; DNS='N/A'; DHCP='N/A'
            Vitesse='N/A'; Type='N/A'; MTU='N/A'; Statut='Erreur'
        }
    }
}

# 3. PROFILS RESEAU
Write-Step "Collecte des profils reseau..."
$NetProfiles = Set-Safe-Get {
    Get-NetConnectionProfile | ForEach-Object {
        [PSCustomObject]@{
            Interface = $_.InterfaceAlias
            Nom       = $_.Name
            Profil    = $_.NetworkCategory
            IPv4      = $_.IPv4Connectivity
            IPv6      = $_.IPv6Connectivity
            Risque    = switch ($_.NetworkCategory) {
                'Public'  { 'CRITICAL' }
                'Private' { 'OK' }
                'Domain'  { 'OK' }
                default   { 'WARN' }
            }
        }
    }
} @()

# 4. LECTEURS MAPPES & HISTORIQUE MRU
Write-Step "Collecte des lecteurs mappes et historique MRU..."
$MappedDrives = Set-Safe-Get {
    Get-PSDrive -PSProvider FileSystem | Where-Object { $_.DisplayRoot -like '\\*' } | ForEach-Object {
        [PSCustomObject]@{
            Lecteur = $_.Name
            Cible   = if ($Mode -eq 'PUBLIC') { ($_.DisplayRoot -replace '\\\\[^\\]+','\\***') } else { $_.DisplayRoot }
            Utilise = if ($_.Used) { [Math]::Round($_.Used/1GB,2).ToString() + ' Go' } else { 'N/A' }
            Libre   = if ($_.Free) { [Math]::Round($_.Free/1GB,2).ToString() + ' Go' } else { 'N/A' }
        }
    }
} @()

# Lecteurs reseau persistants depuis HKCU:\Network
$PersistentDrives = Set-Safe-Get {
    $netKey = 'HKCU:\Network'
    if (Test-Path $netKey) {
        Get-ChildItem $netKey | ForEach-Object {
            $props = Get-ItemProperty $_.PSPath
            [PSCustomObject]@{
                Lecteur     = $_.PSChildName + ':'
                Cible       = if ($Mode -eq 'PUBLIC') { ($props.RemotePath -replace '\\\\[^\\]+','\\***') } else { Set-Safe-String $props.RemotePath }
                Fournisseur = Set-Safe-String $props.ProviderName
                Utilisateur = if ($Mode -eq 'PUBLIC') { '***' } else { Set-Safe-String $props.UserName }
                Source      = 'Registre HKCU:\Network'
            }
        }
    }
} @()

$MRUKeys = @(
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU',
    'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Network\Persistent Connections'
)
$MRUEntries = foreach ($Key in $MRUKeys) {
    try {
        if (Test-Path $Key) {
            $props = Get-ItemProperty $Key
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                [PSCustomObject]@{
                    Source = $Key.Split('\')[-1]
                    Cle    = $_.Name
                    Valeur = if ($Mode -eq 'PUBLIC') { ($_.Value -replace '\\\\[^\\]+','\\***') } else { "$($_.Value)" }
                }
            }
        }
    } catch { }
}

# 5. CONFIGURATION SMB SERVEUR
Write-Step "Collecte de la configuration SMB serveur..."
$SMBServerConfig = $null
$SMBv1Server     = $false
$SMBv2Server     = $true
try {
    $SMBServerConfig = Get-SmbServerConfiguration -ErrorAction Stop
    $SMBv1Server     = $SMBServerConfig.EnableSMB1Protocol
    $SMBv2Server     = $SMBServerConfig.EnableSMB2Protocol
} catch {
    Write-Host "  [AVERT.] Get-SmbServerConfiguration inaccessible : $($_.Exception.Message)" -ForegroundColor Yellow
}

$SMBServerItems = if ($SMBServerConfig) {
    @(
        [PSCustomObject]@{ Parametre='SMBv1 (Serveur)';            Valeur=if($SMBv1Server){'ACTIVE'}else{'Desactive'};            Risque=if($SMBv1Server){'CRITICAL'}else{'OK'}; Note='Obsolete - vulnerable EternalBlue/MS17-010' }
        [PSCustomObject]@{ Parametre='SMBv2/v3 (Serveur)';         Valeur=if($SMBv2Server){'Active'}else{'DESACTIVE'};            Risque=if($SMBv2Server){'OK'}else{'CRITICAL'}; Note='Requis pour le partage modern' }
        [PSCustomObject]@{ Parametre='Signature requise (Serveur)'; Valeur=if($SMBServerConfig.RequireSecuritySignature){'Requise'}else{'Non requise'}; Risque=if($SMBServerConfig.RequireSecuritySignature){'OK'}else{'WARN'}; Note='Previent les attaques MITM/relay' }
        [PSCustomObject]@{ Parametre='Signature activee (Serveur)'; Valeur=if($SMBServerConfig.EnableSecuritySignature){'Activee'}else{'Desactivee'}; Risque=if($SMBServerConfig.EnableSecuritySignature){'OK'}else{'WARN'}; Note='' }
        [PSCustomObject]@{ Parametre='Chiffrement (Serveur)';       Valeur=if($SMBServerConfig.EncryptData){'Active'}else{'Desactive'}; Risque=if($SMBServerConfig.EncryptData){'OK'}else{'INFO'}; Note='Chiffrement SMB3' }
        [PSCustomObject]@{ Parametre='Protocole Maximum';           Valeur=Set-Safe-String $SMBServerConfig.MaxProtocol;              Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Protocole Minimum';           Valeur=Set-Safe-String $SMBServerConfig.MinProtocol;              Risque=if($SMBServerConfig.MinProtocol -eq 'SMB1'){'CRITICAL'}else{'OK'}; Note='' }
        [PSCustomObject]@{ Parametre='Deconnexion auto (min)';      Valeur=Set-Safe-String $SMBServerConfig.AutoDisconnectTimeout;    Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Sessions null (pipes)';       Valeur=if($SMBServerConfig.NullSessionPipes){'Configure'}else{'Aucun'}; Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Partages null';               Valeur=if($SMBServerConfig.NullSessionShares){'Configure'}else{'Aucun'}; Risque='INFO'; Note='' }
    )
} else {
    @([PSCustomObject]@{ Parametre='Erreur'; Valeur='Get-SmbServerConfiguration indisponible'; Risque='WARN'; Note='Verifier droits admin et module SMB' })
}

# 6. CONFIGURATION SMB CLIENT
Write-Step "Collecte de la configuration SMB client..."
$SMBClientConfig = $null
$SMBClientSource = 'cmdlet'
try {
    $SMBClientConfig = Get-SmbClientConfiguration -ErrorAction Stop
} catch {
    $SMBClientSource = 'registre'

    $regPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    $clientReg = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue -ErrorVariable err -PSProvider Registry::HKEY_LOCAL_MACHINE
    if ($clientReg) {
        $SMBClientConfig = [PSCustomObject]@{
            RequireSecuritySignature = $clientReg.RequireSecuritySignature
            EnableSecuritySignature  = $clientReg.EnableSecuritySignature
            MaxProtocol              = $clientReg.MaxProtocol
            MinProtocol              = $clientReg.MinProtocol
            SessionTimeout           = $clientReg.SessionTimeout
            DirectoryCacheLifetime   = $clientReg.DirectoryCacheLifetime
            FileInfoCacheLifetime    = $clientReg.FileInfoCacheLifetime
            WindowSizeThreshold      = $clientReg.WindowSizeThreshold
        }
    }

    if (-not $SMBClientConfig) {
        Write-Host "  [AVERT.] Registre LanmanWorkstation inaccessible ou LongPathsEnabled non actif." -ForegroundColor Yellow
        Write-Host "           Relancer en Administrateur et verifier :" -ForegroundColor DarkYellow
        Write-Host "           reg add HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v LongPathsEnabled /t REG_DWORD /d 1 /f" -ForegroundColor DarkYellow
        Write-Host "           ⚠️ Un redemarrage peut etre necessaire pour que la modification soit effective." -ForegroundColor DarkYellow
    }
}

$SMBClientItems = if ($SMBClientConfig) {
    $sourceNote = if ($SMBClientSource -eq 'registre') { ' (source: registre)' } else { '' }
    @(
        [PSCustomObject]@{ Parametre='Signature requise (Client)';  Valeur=if($SMBClientConfig.RequireSecuritySignature){'Requise'}else{'Non requise'}; Risque=if($SMBClientConfig.RequireSecuritySignature){'OK'}else{'WARN'}; Note="Application cote client$sourceNote" }
        [PSCustomObject]@{ Parametre='Signature activee (Client)';  Valeur=if($SMBClientConfig.EnableSecuritySignature){'Activee'}else{'Desactivee'}; Risque=if($SMBClientConfig.EnableSecuritySignature){'OK'}else{'WARN'}; Note=$sourceNote.Trim() }
        [PSCustomObject]@{ Parametre='Protocole Max (Client)';      Valeur=Set-Safe-String $SMBClientConfig.MaxProtocol 'N/A';      Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Protocole Min (Client)';      Valeur=Set-Safe-String $SMBClientConfig.MinProtocol 'N/A';      Risque=if((Set-Safe-String $SMBClientConfig.MinProtocol 'N/A') -eq 'SMB1'){'CRITICAL'}else{'OK'}; Note='' }
        [PSCustomObject]@{ Parametre='Delai session (s)';           Valeur=Set-Safe-String $SMBClientConfig.SessionTimeout 'N/A';   Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Duree cache repertoire (s)';  Valeur=Set-Safe-String $SMBClientConfig.DirectoryCacheLifetime 'N/A'; Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Cache entrees fichier (s)';   Valeur=Set-Safe-String $SMBClientConfig.FileInfoCacheLifetime 'N/A'; Risque='INFO'; Note='' }
        [PSCustomObject]@{ Parametre='Windows pour Large Reads';    Valeur=Set-Safe-String $SMBClientConfig.WindowSizeThreshold 'N/A'; Risque='INFO'; Note='' }
    )
} else {
    @([PSCustomObject]@{ Parametre='Erreur'; Valeur='Registre LanmanWorkstation inaccessible ou LongPathsEnabled non actif'; Risque='WARN'; Note='' })
}

# 6.1 VERIFICATION DE LA DISPONIBILITE DES SERVICES SMB

$SMBServerAvailable = (Get-Service -Name LanmanServer -ErrorAction SilentlyContinue).Status -eq 'Running'
$SMBClientAvailable = (Get-Service -Name LanmanWorkstation -ErrorAction SilentlyContinue).Status -eq 'Running'

# 7 PARTAGES SMB (parametres etendus)
Write-Step "Collecte des partages SMB (parametres etendus)..."
if ($SMBServerAvailable) {
    $SMBShares     = @()
    $SMBSharesTemp = @()
    $rawShares     = Set-Safe-Get { Get-SmbShare -ErrorAction Stop } @()

    $hasShareConfig = [bool](Get-Command Get-SmbShareConfiguration -ErrorAction SilentlyContinue)
    if (-not $hasShareConfig) {
        Write-Host "  [INFO] Get-SmbShareConfiguration absent sur cette version de Windows. ABE/Cache_HS non disponibles." -ForegroundColor Yellow
    }

    Write-DebugHost "DEBUG: rawShares=$(@($rawShares).Count) hasShareConfig=$hasShareConfig"

    if (-not $rawShares) {
        Write-Host "  [AVERT.] Aucun partage SMB lu ou Get-SmbShare a echoue." -ForegroundColor Yellow
    }

    foreach ($share in $rawShares) {
        $sName = $share.Name
        Write-DebugHost "DEBUG: traitant share $sName"

        $perms = Set-Safe-Get {
            Get-SmbShareAccess -Name $sName -ErrorAction Stop |
            ForEach-Object { "$($_.AccountName):$($_.AccessRight)" }
        } @()

        $sConf = $null
        if ($hasShareConfig) {
            $sConf = Set-Safe-Get { Get-SmbShareConfiguration -Name $sName -ErrorAction Stop } $null
        }

        Write-DebugHost "DEBUG RAW SHARE: Name='$($share.Name)' Path='$($share.Path)'"

        $maxAllowed = if ($share.PSObject.Properties['MaximumAllowed']) { $share.MaximumAllowed } else { [uint32]::MaxValue }

        try {
            $entry = [PSCustomObject]@{
                Nom             = $sName
                Chemin          = Set-Safe-String $share.Path
                Description     = Set-Safe-String $share.Description
                Type            = if ($share.Special) { 'Systeme' } else { 'Utilisateur' }
                Permissions     = ($perms -join ' | ')
                ABE             = if ($sConf) { if ($sConf.FolderEnumerationMode -eq 'AccessBased') {'Actif'} else {'Inactif'} } else { 'N/A' }
                Cache_HS        = if ($sConf) { Set-Safe-String $sConf.CachingMode } else { 'N/A' }
                MaxUtilisateurs = if ($null -eq $maxAllowed -or $maxAllowed -eq [uint32]::MaxValue) { 'Illimite' } else { "$maxAllowed" }
                Disponibilite   = if ($share.ContinuouslyAvailable) { 'Oui' } else { 'Non' }
            }
        } catch {
            Write-DebugHost "DEBUG: entry creation failed for $sName : $($_.Exception.Message)" -ForegroundColor Red
            continue
        }

        Write-DebugHost "DEBUG ENTRY TYPE: $($entry.GetType().FullName)"
        Write-DebugHost "DEBUG ENTRY PROPS: $($entry.PSObject.Properties.Name -join ', ')"
        Write-DebugHost "DEBUG ENTRY VALUES: $($entry.Nom) | $($entry.Chemin) | $($entry.Permissions)"

        $SMBSharesTemp += $entry
        Write-DebugHost "DEBUG: added $sName, tempCount=$($SMBSharesTemp.Count)"
    }

    $SMBShares = $SMBSharesTemp
    Write-DebugHost "DEBUG: firstShare=$($SMBShares[0].Nom) path=$($SMBShares[0].Chemin)"
} else {
    $SMBShares = @()
    Write-Host "  [AVERT.] Collecte des partages SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
}


# DEBUG : Affichage du nombre d'objets collectes pour SMB (pour aider a identifier les erreurs d'acces aux cmdlets)
Write-DebugHost "DEBUG: SMBShares=$(@($SMBShares).Count) SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"

# 8. SESSIONS SMB ACTIVES
Write-Step "Collecte des sessions SMB actives..."
if ($SMBServerAvailable) {
    $SMBSessions = @()
    try {
        $rawSessions = Get-SmbSession -ErrorAction Stop
    } catch {
        Write-DebugHost "DEBUG: Get-SmbSession failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $rawSessions = @()
    }

    Write-DebugHost "DEBUG: rawSessions=$(@($rawSessions).Count)"

    if ($rawSessions) {
        $SMBSessions = foreach ($session in $rawSessions) {
            try {
                [PSCustomObject]@{
                    Client      = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $session.ClientComputerName } else { $session.ClientComputerName }
                    Utilisateur = if ($Mode -eq 'PUBLIC') { ($session.ClientUserName -replace '^[^\\]+\\','***\') } else { $session.ClientUserName }
                    Dialecte    = $session.Dialect
                    Signe       = if ($session.PSObject.Properties['IsSigned'])    { $session.IsSigned }    else { 'N/A' }
                    Chiffre     = if ($session.PSObject.Properties['IsEncrypted']) { $session.IsEncrypted } else { 'N/A' }
                    Duree_s     = $session.SecondsExists
                }
            } catch {
                Write-DebugHost "DEBUG: session object failed: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
    }
} else {
    $SMBSessions = @()
    Write-Host "  [AVERT.] Collecte des sessions SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
}

# 9. CONNEXIONS SMB ACTIVES
Write-Step "Collecte des connexions SMB actives..."
if ($SMBClientAvailable) {
    $SMBConnections = @()
    try {
        $rawConnections = Get-SmbConnection -ErrorAction Stop
    } catch {
        Write-DebugHost "DEBUG: Get-SmbConnection failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $rawConnections = @()
    }

    Write-DebugHost "DEBUG: rawConnections=$(@($rawConnections).Count)"

    if ($rawConnections) {
        $SMBConnections = foreach ($conn in $rawConnections) {
            try {
                [PSCustomObject]@{
                    Serveur     = if ($Mode -eq 'PUBLIC') { Set-Mask-Host $conn.ServerName } else { $conn.ServerName }
                    Partage     = if ($Mode -eq 'PUBLIC') { ($conn.ShareName -replace '(?<=\\).*','***') } else { $conn.ShareName }
                    Dialecte    = $conn.Dialect
                    Signe       = if ($conn.PSObject.Properties['IsSigned'])    { $conn.IsSigned }    else { 'N/A' }
                    Chiffre     = if ($conn.PSObject.Properties['IsEncrypted']) { $conn.IsEncrypted } else { 'N/A' }
                    Utilisateur = if ($Mode -eq 'PUBLIC') { '***' } else { $conn.UserName }
                }
            } catch {
                Write-DebugHost "DEBUG: connection object failed: $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            }
        }
    }
} else {
    $SMBConnections = @()
    Write-Host "  [AVERT.] Collecte des connexions SMB annulee : LanmanWorkstation n'est pas demarre." -ForegroundColor Yellow
}

Write-DebugHost "DEBUG: SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"

# 9.1 RESOLUTION DES INTERFACES LOCALES POUR LES CONNEXIONS SMB
function Set-Parse-UNCPath { # modified
    param([string]$Path)
    $result = [PSCustomObject]@{ Serveur='N/A'; Partage='N/A' }
    if ($Path -match '^\\\\([^\\]+)\\([^\\]+)') {
        $result.Serveur = $matches[1]
        $result.Partage = $matches[2]
    }
    return $result
}

function Get-LocalInterfaceForHost {
    param([string]$RemoteHost)
    $info = [PSCustomObject]@{ Interface='N/A'; LocalIP='N/A' }
    try {
        $addresses = @()
        if ($RemoteHost -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
            $addresses = @($RemoteHost)
        } else {
            $addresses = [System.Net.Dns]::GetHostAddresses($RemoteHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | ForEach-Object { $_.IPAddressToString }
        }
        foreach ($addr in $addresses) {
            if (-not $addr) { continue }
            $route = Get-NetRoute -DestinationPrefix "$addr/32" -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1
            if ($route) {
                $iface = Get-NetIPConfiguration -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
                if ($iface) {
                    $info.Interface = Set-Safe-String $iface.InterfaceAlias 'N/A'
                    $info.LocalIP   = if ($iface.IPv4Address) { $iface.IPv4Address[0].IPAddress } else { 'N/A' }
                }
                break
            }
        }
    } catch {
        # Ignore failures, keep N/A values
    }
    return $info
}

$RemoteSMBShares = @()

$MappedDrives | ForEach-Object {
    $unc = Set-Parse-UNCPath $_.Cible
    $RemoteSMBShares += [PSCustomObject]@{
        Source      = 'Lecteur mappe'
        Serveur     = $unc.Serveur
        Partage     = $unc.Partage
        Cible       = $_.Cible
        Utilisateur = 'N/A'
        Type        = 'Lecteur mappe'
    }
}

$PersistentDrives | ForEach-Object {
    $unc = Set-Parse-UNCPath $_.Cible
    $RemoteSMBShares += [PSCustomObject]@{
        Source      = 'Lecteur persistant'
        Serveur     = $unc.Serveur
        Partage     = $unc.Partage
        Cible       = $_.Cible
        Utilisateur = $_.Utilisateur
        Type        = 'Persistant'
    }
}

$SMBConnections | ForEach-Object {
    $RemoteSMBShares += [PSCustomObject]@{
        Source      = 'Connexion active'
        Serveur     = $_.Serveur
        Partage     = $_.Partage
        Cible       = "$($_.Serveur)\$($_.Partage)"
        Utilisateur = $_.Utilisateur
        Type        = 'Session SMB'
    }
}

# 10.0 Vérification de l'audit SMB des partages de fichiers
$SMBShareAuditStatus = 'Unknown'
try {
    $auditOutput = (auditpol /get /subcategory:"Partage de fichiers" 2>$null) -join "`n"
    foreach ($line in $auditOutput -split "`n") {
        if ($line -match '^\s*(?:Partage de fichiers|File Share)\s+(.*)$') {
            $SMBShareAuditStatus = $matches[1].Trim()
            break
        }
    }
} catch {
    $SMBShareAuditStatus = 'Inaccessible'
}
Write-DebugHost "DEBUG: SMBShareAuditStatus='$SMBShareAuditStatus'"

# 10.1 HISTORIQUE CONNEXIONS RESEAU
Write-Step "Collecte de l'historique des connexions reseau (7 derniers jours)..."
$ConnHistory = @()
try {
    $histStart  = (Get-Date).AddDays(-7)
    $histEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        StartTime = $histStart
        Id        = @(5140, 5142, 5143, 5144)
    } -MaxEvents 150 -ErrorAction SilentlyContinue
    $ConnHistory = $histEvents | ForEach-Object {
        $msg   = $_.Message
        $ip    = if ($msg -match '(?:Adresse reseau source|Source Address)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
        $share = if ($msg -match '(?:Nom du partage|Share Name)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
        $user  = if ($msg -match '(?:Nom du compte|Account Name)\s*:\s*(\S+)') { $matches[1] } else { 'N/A' }
        [PSCustomObject]@{
            Horodatage  = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            EventID     = $_.Id
            TypeEvenemt = switch ($_.Id) {
                5140 { 'Acces partage' }
                5142 { 'Ajout partage' }
                5143 { 'Modif. partage' }
                5144 { 'Suppression partage' }
                default { 'Autre' }
            }
            Partage     = if ($Mode -eq 'PUBLIC') { ($share -replace '\\\\[^\\]+','\\***') } else { $share }
            IPSource    = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $ip } else { $ip }
            Compte      = if ($Mode -eq 'PUBLIC') { '***' } else { $user }
        }
    }
} catch {
    $ConnHistory = @([PSCustomObject]@{
        Horodatage='N/A'; EventID='N/A'; TypeEvenemt='Acces admin requis'
        Partage='Journaux de securite inaccessibles sans elevation'
        IPSource='N/A'; Compte='N/A'
    })
}

# Connexions net use en temps reel
$NetUseRaw     = Set-Safe-Get { & net use 2>$null } @()
$NetUseEntries = @()
if ($NetUseRaw) {
    $NetUseRaw | Where-Object { $_ -match '\\\\' } | ForEach-Object {
        $parts = $_.Trim() -split '\s{2,}'
        if ($parts.Count -ge 2) {
            $NetUseEntries += [PSCustomObject]@{
                Statut  = Set-Safe-String $parts[0]
                Local   = if ($parts.Count -ge 3) { $parts[1] } else { 'N/A' }
                Distant = if ($Mode -eq 'PUBLIC') { ($parts[-1] -replace '\\\\[^\\]+','\\***') } else { $parts[-1] }
            }
        }
    }
}

# 11. PARE-FEU
Write-Step "Collecte de la configuration du pare-feu..."
$FWProfiles = Set-Safe-Get {
    Get-NetFirewallProfile | ForEach-Object {
        [PSCustomObject]@{
            Profil         = $_.Name
            Active         = $_.Enabled
            EntreeDefaut   = $_.DefaultInboundAction
            SortieDefaut   = $_.DefaultOutboundAction
            LogAutorise    = $_.LogAllowed
            LogBloque      = $_.LogBlocked
            Risque         = if (-not $_.Enabled) { 'WARN' } else { 'OK' }
        }
    }
} @()

$SmbPorts = @(445, 139, 137, 138)
$FWRules = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
        $_.Enabled -eq $true -and
        ($_.DisplayName -match 'SMB|File|Share|Network Discovery|NetBIOS|Partage|Fichiers' -or
         ($_.Direction -eq 'Inbound' -and ($_ | Get-NetFirewallPortFilter | Where-Object { $_.LocalPort -in $SmbPorts })))
    } | ForEach-Object {
        $pf = $_ | Get-NetFirewallPortFilter
        [PSCustomObject]@{
            Nom       = $_.DisplayName
            Direction = $_.Direction
            Action    = $_.Action
            Profil    = $_.Profile
            Protocole = $pf.Protocol
            Port      = $pf.LocalPort
            Active    = $_.Enabled
            Risque    = if ($_.Action -eq 'Block' -and $_.Direction -eq 'Inbound') { 'WARN' } else { 'OK' }
        }
    }
} @()

# 12. POLITIQUE D'AUTHENTIFICATION
Write-Step "Collecte de la politique d'authentification..."
$RegPaths = @{
    Lsa     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    MSV1_0  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
    Policies= 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    DNS     = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
}

$LmLevel = Get-RegValue $RegPaths.Lsa 'LmCompatibilityLevel'
$LATFP   = Get-RegValue $RegPaths.Policies 'LocalAccountTokenFilterPolicy'

$AuthPolicy = @(
    [PSCustomObject]@{ Cle='LmCompatibilityLevel';         Valeur=$LmLevel; Recommande='5'; Risque=if($LmLevel-eq'NON DEFINI'){'WARN'}elseif([int]$LmLevel-lt 3){'CRITICAL'}elseif([int]$LmLevel-ge 5){'OK'}else{'WARN'}; Note='NTLMv2 uniquement (5=optimal). Valeur basse = capture hash LM/NTLMv1' }
    [PSCustomObject]@{ Cle='RestrictAnonymous';            Valeur=(Get-RegValue $RegPaths.Lsa 'RestrictAnonymous'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'RestrictAnonymous')-eq'0'){'WARN'}else{'OK'}; Note='Bloque enumeration anonyme partages/comptes' }
    [PSCustomObject]@{ Cle='RestrictAnonymousSAM';         Valeur=(Get-RegValue $RegPaths.Lsa 'RestrictAnonymousSAM'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'RestrictAnonymousSAM')-eq'0'){'WARN'}else{'OK'}; Note='Bloque enumeration anonyme des comptes SAM' }
    [PSCustomObject]@{ Cle='LocalAccountTokenFilterPolicy'; Valeur=$LATFP; Recommande='1 (admin distant)'; Risque=if($LATFP-ne'1'){'WARN'}else{'OK'}; Note='Doit etre 1 pour acces distant avec compte local' }
    [PSCustomObject]@{ Cle='NoLMHash';                    Valeur=(Get-RegValue $RegPaths.Lsa 'NoLMHash'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Lsa 'NoLMHash')-ne'1'){'WARN'}else{'OK'}; Note='Empeche stockage hash LM (vol de credentials)' }
    [PSCustomObject]@{ Cle='EnableLUA (UAC)';             Valeur=(Get-RegValue $RegPaths.Policies 'EnableLUA'); Recommande='1'; Risque=if((Get-RegValue $RegPaths.Policies 'EnableLUA')-eq'0'){'WARN'}else{'OK'}; Note='Etat du Controle de Compte Utilisateur' }
    [PSCustomObject]@{ Cle='NTLMMinClientSecurity'; Valeur=(Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec'); Recommande='537395200'; Risque= if ([int](Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec') -lt 537395200) {'WARN'} else {'OK'}; Note='NTLMv2 activé, compatible W10 mais 537395200 reste recommandé pour le chiffrement 128 bits' }
    [PSCustomObject]@{ Cle='NTLMMinServerSecurity'; Valeur=(Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec'); Recommande='537395200'; Risque= if ([int](Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec') -lt 537395200) {'WARN'} else {'OK'}; Note='NTLMv2 activé, compatible W10 mais 537395200 reste recommandé pour le chiffrement 128 bits' }
)

$LocalAccounts = Set-Safe-Get {
    Get-LocalUser | ForEach-Object {
        # Definir un booleen si le compte a un mot de passe
        $HasPassword = [bool]$_.PasswordLastSet

        [PSCustomObject]@{
            Nom           = if ($Mode -eq 'PUBLIC') { ($_.Name.Substring(0,[Math]::Min(3,$_.Name.Length))+'***') } else { $_.Name }
            Active        = $_.Enabled
            DernConnexion = if ($_.LastLogon) { $_.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { 'Jamais' }
            MdpRequis     = $HasPassword
            MdpExpire     = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('yyyy-MM-dd') } else { 'N/A' }
            SID           = Set-Mask-SID $_.SID.Value
            Risque        = if ($_.Enabled -and -not $HasPassword) { 'CRITICAL' } elseif ($_.Enabled) { 'INFO' } else { 'OK' }
        }
    }
} @()

$CredmanOutput = Set-Safe-Get { & cmdkey /list 2>$null } @()
$CredEntries = if ($CredmanOutput) {
    $CredmanOutput | Where-Object { $_ -match 'Target|Cible' } | ForEach-Object {
        $target = ($_ -replace '.*(?:Target|Cible):\s*','').Trim()
        [PSCustomObject]@{
            Cible = if ($Mode -eq 'PUBLIC') { ($target -replace '(?<=\\\\)[^\\]+','***') } else { $target }
            Type  = if ($target -match '\\\\') { 'Reseau' } else { 'Generique' }
        }
    }
} else { @() }



# 13.SERVICES & PROTOCOLES DE DECOUVERTE
Write-Step "Collecte des services et protocoles de decouverte..."
$CriticalServices = @(
    @{Name='LanmanServer';    Friendly='Serveur SMB (LanmanServer)';             Risk='CRITICAL'}
    @{Name='LanmanWorkstation'; Friendly='Client SMB (Workstation)';             Risk='CRITICAL'}
    @{Name='MrxSmb';          Friendly='Mini-redirecteur SMB';                   Risk='WARN'}
    @{Name='Browser';         Friendly='Explorateur reseau (Computer Browser)';  Risk='INFO'}
    @{Name='FDResPub';        Friendly='Publication ressources (FDResPub)';       Risk='WARN'}
    @{Name='SSDPSRV';         Friendly='Decouverte SSDP';                         Risk='WARN'}
    @{Name='upnphost';        Friendly='Hote peripherique UPnP';                 Risk='INFO'}
    @{Name='Dnscache';        Friendly='Client DNS';                              Risk='WARN'}
    @{Name='WinRM';           Friendly='Gestion a distance Windows (WinRM)';     Risk='INFO'}
    @{Name='NlaSvc';          Friendly='Detection reseau (NLA)';                 Risk='WARN'}
    @{Name='netlogon';        Friendly='Ouverture de session reseau';             Risk='INFO'}
    @{Name='mpsdrv';          Friendly='Pilote Pare-feu Windows';                Risk='WARN'}
    @{Name='BFE';             Friendly='Moteur de filtrage de base (BFE)';       Risk='CRITICAL'}
    @{Name='mpssvc';          Friendly='Service Pare-feu Windows';               Risk='WARN'}
    @{Name='Spooler';         Friendly='Spouleur impression';                     Risk='INFO'}
)

$ServicesData = foreach ($Svc in $CriticalServices) {
    $s = Set-Safe-Get { Get-Service -Name $Svc.Name -ErrorAction Stop } $null
    [PSCustomObject]@{
        Nom       = $Svc.Name
        Libelle   = $Svc.Friendly
        Statut    = if ($s) { "$($s.Status)" } else { 'Introuvable' }
        Demarrage = if ($s) { "$($s.StartType)" } else { 'N/A' }
        Risque    = if (-not $s) { 'INFO' }
                    elseif ($s.Status -ne 'Running' -and $Svc.Risk -eq 'CRITICAL') { 'CRITICAL' }
                    elseif ($s.Status -ne 'Running' -and $Svc.Risk -eq 'WARN') { 'WARN' }
                    else { 'OK' }
    }
}

$DNSClientPath   = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
$DNSClientParent = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT'
$LLMNRVal        = Get-RegValue $RegPaths.DNS 'EnableMulticast'
$DNSClientExists = Test-Path $DNSClientPath
$NetBIOSAdapters = Set-Safe-Get { Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.TcpipNetbiosOptions -ne $null } } @()
$NetBIOSStatus = ($NetBIOSAdapters | ForEach-Object {
    switch ($_.TcpipNetbiosOptions) { 0{'Par defaut (DHCP)'} 1{'Active'} 2{'Desactive'} }
}) | Select-Object -Unique

$DiscoveryItems = @(
    [PSCustomObject]@{ Protocole='LLMNR';              Etat=if($LLMNRVal -eq '0'){'Desactive'}else{'Active (defaut)'}; Risque=if($LLMNRVal -eq '0'){'OK'}else{'WARN'}; Note='Nom multicast local - risque MITM (Responder)' }
    [PSCustomObject]@{ Protocole='NetBIOS over TCP/IP'; Etat=($NetBIOSStatus -join ', '); Risque='INFO'; Note='Resolution noms legacy' }
    [PSCustomObject]@{ Protocole='mDNS';               Etat='Active (defaut)'; Risque='INFO'; Note='DNS multicast - protocole Bonjour' }
    [PSCustomObject]@{ Protocole='WSD (Web Services)'; Etat=if((Set-Safe-Get{(Get-Service FDResPub).Status}'Stopped') -eq 'Running'){'En cours'}else{'Arrete'}; Risque='INFO'; Note='Publication decouverte reseau' }
)


# 14. JOURNAL D'EVENEMENTS — 24H
Write-Step "Collecte des evenements (24 dernieres heures)..."
$EventStart = (Get-Date).AddHours(-24)
$EventIDs   = @(4625, 4648, 4776, 5140, 5145, 7036, 7045)
$EventLogs  = @()
try {
    $EventLogs = Get-WinEvent -FilterHashtable @{
        LogName   = @('Security','System','Application')
        StartTime = $EventStart
        Id        = $EventIDs
    } -MaxEvents 200 -ErrorAction Stop | ForEach-Object {
        [PSCustomObject]@{
            Horodatage = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
            Journal    = $_.LogName
            EventID    = $_.Id
            Niveau     = $_.LevelDisplayName
            Source     = $_.ProviderName
            Message    = ($_.Message -replace '\r?\n',' ').Substring(0,[Math]::Min(200,$_.Message.Length)) + '...'
            Categorie  = switch ($_.Id) {
                4625 { 'Echec auth.' }
                4648 { 'Session explicite' }
                4776 { 'Auth. NTLM' }
                5140 { 'Acces partage' }
                5145 { 'Acces objet partage' }
                7036 { 'Etat service' }
                7045 { 'Nouveau service' }
                default { 'Autre' }
            }
        }
    }
} catch {
    $EventLogs = @([PSCustomObject]@{
        Horodatage='N/A'; Journal='N/A'; EventID='N/A'; Niveau='N/A'
        Source='Droits admin requis'; Message="Acces aux journaux d'evenements necessite une elevation de droits"; Categorie='N/A'
    })
}

# 15. TABLE ARP
Write-Step "Collecte de la table ARP..."
$ArpOutput = Set-Safe-Get { & arp -a 2>$null } @()
$ArpEntries = @()
if ($ArpOutput) {
    $ArpOutput | Where-Object { $_ -match '^\s+\d' } | ForEach-Object {
        $parts = $_.Trim() -split '\s+'
        if ($parts.Count -ge 3) {
            $ArpEntries += [PSCustomObject]@{
                IP   = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $parts[0] } else { $parts[0] }
                MAC  = Set-Mask-MAC ($parts[1])
                Type = $parts[2]
            }
        }
    }
}

# 16. FICHIER HOSTS
Write-Step "Collecte du fichier hosts..."
$HostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsEntries = @()
if (Test-Path $HostsPath) {
    try {
        Get-Content $HostsPath | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } | ForEach-Object {
            $parts = $_.Trim() -split '\s+'
            if ($parts.Count -ge 2) {
                $HostsEntries += [PSCustomObject]@{
                    IP       = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $parts[0] } else { $parts[0] }
                    Hostname = if ($Mode -eq 'PUBLIC') { Set-Mask-Host $parts[1] } else { $parts[1] }
                    Note     = if ($parts.Count -gt 2) { $parts[2..($parts.Count-1)] -join ' ' } else { '' }
                }
            }
        }
    } catch { }
}

# 17. TESTS DE CONNECTIVITE
Write-Step "Execution des tests de connectivite..."

$Neighbors = @()
$ArpEntries | Where-Object {
    $_.Type -eq 'dynamic' -and
    $_.IP -notmatch '^(224\.|255\.|169\.|fe80:|ff[0-9a-fA-F]*:|::1$)'
} | ForEach-Object { $Neighbors += $_.IP }

$SMBSessions | Where-Object {
    $_.Client -and $_.Client -notmatch '^fe80:'
} | ForEach-Object { $Neighbors += $_.Client }

$Neighbors = $Neighbors | Where-Object { $_ -ne '' } | Sort-Object -Unique | Select-Object -First 10

$ConnTests = @()
foreach ($Target in $Neighbors) {
    try {
        $DisplayTarget = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $Target } else { $Target }

        # Ping
        $PingResult = Test-Connection -ComputerName $Target -Count 1 -Quiet

        # Port 445
        $PortResult = Set-Safe-Get { Test-NetConnection -ComputerName $Target -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue } $false

        # UNC IPC
        $UNCResult = 'N/A'
        if ($PortResult) {
            try {
                $null = [System.IO.Directory]::GetDirectories("\\$Target\IPC$")
                $UNCResult = 'OK'
            } catch {
                $UNCResult = $_.Exception.Message.Substring(0,[Math]::Min(60,$_.Exception.Message.Length))
            }
        }

        # Resultat global
        $Overall = if ($PingResult -and $PortResult -and $UNCResult -eq 'OK') { 'OK' }
                   elseif ($PingResult -and $PortResult) { 'WARN' }
                   elseif ($PingResult) { 'WARN' }
                   else { 'CRITICAL' }

        $ConnTests += [PSCustomObject]@{
            Cible   = $DisplayTarget
            Ping    = if ($PingResult) { 'OK' } else { 'ECHEC' }
            Port445 = if ($PortResult) { 'OUVERT' } else { 'FERME/FILTRE' }
            UNC_IPC = if ($Mode -eq 'PUBLIC') { ($UNCResult -replace '\\\\[^\\]+','\\***') } else { $UNCResult }
            Resultat= $Overall
        }

    } catch {
        $ConnTests += [PSCustomObject]@{
            Cible   = $Target
            Ping    = 'N/A'
            Port445 = 'N/A'
            UNC_IPC = 'Erreur'
            Resultat= 'WARN'
        }
    }
}

# 18. PARTAGES SMB
Write-Step "Collecte des partages SMB..."
if ($SMBServerAvailable) {
    $Shares = Set-Safe-Get {
        Get-SmbShare -ErrorAction Stop | ForEach-Object {
            $ShareName = $_.Name
            $Path      = $_.Path

            $Permissions = Get-SmbShareAccess -Name $ShareName -ErrorAction SilentlyContinue

            $Folders = if (Test-Path $Path) {
                Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty Name
            } else { @() }

            [PSCustomObject]@{
                Nom        = if ($Mode -eq 'PUBLIC') { ($ShareName.Substring(0,[Math]::Min(3,$ShareName.Length))+'***') } else { $ShareName }
                Chemin     = $Path
                Acces      = ($Permissions | ForEach-Object {
                    "$($_.AccountName) ($($_.AccessRight))"
                }) -join "; "
                Dossiers   = if ($Folders) { $Folders -join ", " } else { "Aucun / inaccessible" }
                Risque     = if ($Permissions.AccountName -match 'Everyone') { 'WARN' } else { 'OK' }
            }
        }
    } @()
} else {
    $Shares = @()
    Write-Host "  [AVERT.] Collecte des partages SMB annulee : LanmanServer n'est pas demarre." -ForegroundColor Yellow
}


# DEBUG: Affichage des compteurs de donnees collectees
Write-DebugHost "DEBUG: Shares=$(@($Shares).Count) SMBShares=$(@($SMBShares).Count) SMBSessions=$(@($SMBSessions).Count) SMBConnections=$(@($SMBConnections).Count)"
Write-DebugHost "DEBUG: SMBServerAvailable=$SMBServerAvailable SMBClientAvailable=$SMBClientAvailable"


# Fallback si aucun voisin detecte
if (-not $ConnTests -or $ConnTests.Count -eq 0) {
    $ConnTests = foreach ($Target in $Neighbors) {
        [PSCustomObject]@{
            Cible   = if ($Mode -eq 'PUBLIC') { SET-Mask-IP $Target } else { $Target }
            Ping    = 'N/A'
            Port445 = 'N/A'
            UNC_IPC = 'N/A'
            Resultat= 'WARN'
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: MOTEUR D'ANALYSE & RECOMMANDATIONS
# ─────────────────────────────────────────────────────────────────────────────
Write-Step "Analyse des resultats et generation des recommandations..."
$Findings = @()

# SMBv1 SERVEUR
if ($SMBv1Server) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv1 est ACTIVE (serveur)'; Detail='SMBv1 obsolete et vulnerable (EternalBlue/MS17-010). Desactiver immediatement.'; Correction='Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force' }
}

# SMBv2 SERVEUR
if (-not $SMBv2Server) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv2 est DESACTIVE (serveur)'; Detail='SMBv2/v3 doit etre active pour le partage Windows moderne.'; Correction='Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force' }
}

# SMBv1 CLIENT
if ($SMBClientConfig -and "$($SMBClientConfig.MinProtocol)" -eq 'SMB1') {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Protocole SMB'; Constat='SMBv1 autorise cote CLIENT'; Detail='Le client SMB accepte SMB1. Risque identique cote serveur.'; Correction='Set-SmbClientConfiguration -MinimumProtocol SMB2 -Force' }
}

# PROFIL RESEAU PUBLIC
foreach ($P in $NetProfiles) {
    if ($P.Profil -eq 'Public') {
        $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Profil reseau'; Constat="Interface '$($P.Interface)' sur profil PUBLIC"; Detail='Le profil Public bloque le partage de fichiers. Passer en Prive.'; Correction="Set-NetConnectionProfile -InterfaceAlias '$($P.Interface)' -NetworkCategory Private" }
    }
}

# LmCompatibilityLevel
if ($LmLevel -eq 'NON DEFINI') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='LmCompatibilityLevel absent du registre'; Detail='Valeur par defaut differente entre W10 et W11, peut causer des echecs de partage reseau entre machines mixtes.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 3 -Type DWord' }
} elseif ([int]$LmLevel -lt 3) {
    $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Authentification'; Constat="LmCompatibilityLevel = $LmLevel (trop bas)"; Detail='Authentification LM/NTLMv1 autorisee. Risque majeur de vol de credentials.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord' }
} elseif ([int]$LmLevel -lt 5) {
    $Findings += [PSCustomObject]@{
        Severite='WARN'
        Categorie='Authentification'
        Constat="LmCompatibilityLevel = $LmLevel (trop bas)"
        Detail='NTLMv2 uniquement recommandé. Valeur 5 est optimale.'
        Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5 -Type DWord'
    }
}
# RestrictAnonymous
if ((Get-RegValue $RegPaths.Lsa 'restrictanonymous') -eq '0') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='RestrictAnonymous = 0'; Detail='Enumeration anonyme des partages autorisee.'; Correction='Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name restrictanonymous -Value 1 -Type DWord' }
}

# LocalAccountTokenFilterPolicy
if ($LATFP -ne '1') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='LocalAccountTokenFilterPolicy non defini a 1'; Detail='Connexions distantes avec compte local peuvent echouer (restriction UAC distante active).'; Correction='New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWORD -Force' }
}

# UAC DESACTIVE
if ((Get-RegValue $RegPaths.Policies 'EnableLUA') -eq '0') {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Authentification'; Constat='UAC desactive (EnableLUA=0)'; Detail='Controle de compte utilisateur desactive. Risque elevation silencieuse de privileges.'; Correction='Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name EnableLUA -Value 1' }
}

# PARE-FEU DESACTIVE
foreach ($FWP in $FWProfiles) {
    if (-not $FWP.Active) {
        $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Pare-feu'; Constat="Pare-feu DESACTIVE sur le profil : $($FWP.Profil)"; Detail='Pare-feu Windows desactive. Verifier presence pare-feu tiers.'; Correction="Set-NetFirewallProfile -Profile $($FWP.Profil) -Enabled True" }
    }
}

# SERVICES CRITICAL ARRETES
foreach ($Svc in $ServicesData) {
    if ($Svc.Statut -ne 'Running' -and $Svc.Risque -eq 'CRITICAL') {
        if ($Svc.Demarrage -eq 'Disabled') {
            $Findings += [PSCustomObject]@{
                Severite  = 'CRITICAL'
                Categorie = 'Services'
                Constat   = "Service DESACTIVE : $($Svc.Libelle)"
                Detail    = "$($Svc.Nom) est desactive et ne peut pas demarrer sans changer son type de demarrage."
                Correction= "Set-Service -Name $($Svc.Nom) -StartupType Automatic; Start-Service -Name $($Svc.Nom)"
            }
        } else {
            $Findings += [PSCustomObject]@{
                Severite  = 'CRITICAL'
                Categorie = 'Services'
                Constat   = "Service ARRETE : $($Svc.Libelle)"
                Detail    = "$($Svc.Nom) doit etre actif pour le partage SMB."
                Correction= "Start-Service -Name $($Svc.Nom)"
            }
        }
    }
}

# SERVICES WARN ARRETES
foreach ($Svc in $ServicesData) {
    if ($Svc.Statut -ne 'Running' -and $Svc.Risque -eq 'WARN') {
        $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Services'; Constat="Service arrete : $($Svc.Libelle)"; Detail="$($Svc.Nom) arrete peut degrader la decouverte reseau ou les performances SMB."; Correction="Start-Service -Name $($Svc.Nom)" }
    }
}

# SIGNATURE SMB SERVEUR
if ($SMBServerConfig -and -not $SMBServerConfig.EnableSecuritySignature) {
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Securite SMB'; Constat='Signature SMB non activee cote serveur'; Detail='Sans signature, attaques SMB relay (NTLM relay) possibles.'; Correction='Set-SmbServerConfiguration -EnableSecuritySignature $true -Force' }
}

# COMPTES LOCAUX SANS MOT DE PASSE
foreach ($Acct in $LocalAccounts) {
    if ($Acct.Active -and $Acct.MdpRequis -eq $false) {
        $Findings += [PSCustomObject]@{ Severite='CRITICAL'; Categorie='Comptes locaux'; Constat="Compte sans mot de passe requis : $($Acct.Nom)"; Detail='Compte active sans exigence de mot de passe.'; Correction="Set-LocalUser -Name '$($Acct.Nom)' -PasswordRequired `$true" }
    }
}

# PARTAGES OUVERTS A EVERYONE
foreach ($Share in $Shares) {
    if ($Share.Risque -eq 'WARN') {
        $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Partages'; Constat="Partage accessible a Everyone : $($Share.Nom)"; Detail='Acces non restreint au partage. Tout utilisateur du reseau peut y acceder.'; Correction="Revoir les permissions : Set-SmbShareAccess -Name '$($Share.Nom)'" }
    }
}

# LLMNR ACTIVE
if ($LLMNRVal -ne '0') {
    if (-not $DNSClientExists) {
        $Correction = "New-Item -Path '$DNSClientParent' -Name 'DNSClient' -Force; New-ItemProperty -Path '$DNSClientPath' -Name EnableMulticast -PropertyType DWORD -Value 0 -Force"
    } else {
        $Correction = "Set-ItemProperty -Path '$DNSClientPath' -Name EnableMulticast -Value 0 -Type DWord"
    }
    $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Protocoles decouverte'; Constat='LLMNR est active'; Detail='LLMNR exploitable pour capturer credentials (outil Responder).'; Correction=$Correction }
}

# CONNECTIVITE
if ($ConnTests -and $ConnTests.Count -gt 0) {
    $ConnTests | Where-Object { $_.Resultat -eq 'CRITICAL' } | ForEach-Object {
        $Findings += [PSCustomObject]@{ Severite='WARN'; Categorie='Connectivite'; Constat="Impossible de joindre $($_.Cible)"; Detail="Ping : $($_.Ping) | Port 445 : $($_.Port445) | UNC : $($_.UNC_IPC)"; Correction='Verifier regles pare-feu, profil reseau et service SMB sur la machine cible.' }
    }
}

# AUTRES VERIFICATIONS
$RestrictNullSessAccess = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'RestrictNullSessAccess'
if ($RestrictNullSessAccess -ne '0') {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'SMB / Sécurité'
        Constat   = "RestrictNullSessAccess = $RestrictNullSessAccess"
        Detail    = 'Les sessions nulles sont autorisées côté serveur SMB.'
        Correction= 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name RestrictNullSessAccess -Value 0 -Type DWord -Force'
    }
}

$EveryoneIncludesAnonymous = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'everyoneincludesanonymous'
if ($EveryoneIncludesAnonymous -ne '1') {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'SMB / Sécurité'
        Constat   = "everyoneincludesanonymous = $EveryoneIncludesAnonymous"
        Detail    = "Acces anonyme global n'est pas activé, ce qui peut bloquer certains partages Windows légitimes en environnement local"
        Correction= 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous -Value 1 -Type DWord -Force'
    }
}

$SMB2Feature      = Set-Safe-Get { Get-WindowsOptionalFeature -Online -FeatureName FS-SMB2 -ErrorAction Stop } $null
$SMBDirectFeature = Set-Safe-Get { Get-WindowsOptionalFeature -Online -FeatureName FS-SMBDIRECT -ErrorAction Stop } $null

if ($SMB2Feature -and $SMB2Feature.State -ne 'Enabled') {
    $Findings += [PSCustomObject]@{
        Severite  = 'INFO'
        Categorie = 'SMB'
        Constat   = 'Feature FS-SMB2 non activée'
        Detail    = 'Le support SMB2/SMB3 peut ne pas être entièrement disponible.'
        Correction= 'Enable-WindowsOptionalFeature -Online -FeatureName FS-SMB2 -NoRestart'
    }
}

if ($SMBDirectFeature -and $SMBDirectFeature.State -ne 'Enabled') {
    $Findings += [PSCustomObject]@{
        Severite  = 'INFO'
        Categorie = 'SMB'
        Constat   = 'Feature FS-SMBDIRECT non activée'
        Detail    = 'Le support SMB Direct est pas activé.'
        Correction= 'Enable-WindowsOptionalFeature -Online -FeatureName FS-SMBDIRECT -NoRestart'
    }
}

$FWNetworkDiscovery = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
        $_.DisplayGroup -match 'Network Discovery|Découverte' -and $_.Enabled -eq $false
    }
} @()
if ($FWNetworkDiscovery.Count -gt 0) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Pare-feu'
        Constat   = "Règles de découverte réseau désactivées : $($FWNetworkDiscovery.Count)"
        Detail    = 'Les règles de découverte réseau doivent être activées pour que la découverte SMB fonctionne correctement.'
        Correction= 'Get-NetFirewallRule | Where-Object { $_.DisplayGroup -match "Network Discovery|Découverte" } | Set-NetFirewallRule -Enabled True'
    }
}

$FWFileAndPrinter = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object {
        $_.DisplayGroup -match 'File and Printer Sharing|Partage' -and $_.Enabled -eq $false
    }
} @()

if ($FWFileAndPrinter.Count -gt 0) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Pare-feu'
        Constat   = "Règles File and Printer Sharing désactivées : $($FWFileAndPrinter.Count)"
        Detail    = 'Les règles de partage de fichiers et imprimantes doivent être activées pour SMB.'
        Correction= 'Get-NetFirewallRule | Where-Object { $_.DisplayGroup -match "File and Printer Sharing|Partage" } | Set-NetFirewallRule -Enabled True'
    }
}

$ExistingBlockRules = Set-Safe-Get {
    Get-NetFirewallRule | Where-Object { $SMBBlockRules -contains $_.DisplayName -and $_.Action -eq 'Block' }
} @()
if ($ExistingBlockRules.Count -gt 0) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Pare-feu'
        Constat   = "Règles de blocage SMB détectées : $($ExistingBlockRules.DisplayName -join ', ')"
        Detail    = 'Des règles de blocage SMB explicites peuvent empêcher les connexions réseau.'
        Correction= 'Remove-NetFirewallRule -DisplayName "Bloquer SMB entrant 445","Bloquer SMB entrant 139","Bloquer NetBIOS entrant","Bloquer SMB sortant 445","Bloquer SMB sortant 139"'
    }
}

$NetBIOSProps = Set-Safe-Get {
    Get-NetAdapterAdvancedProperty -DisplayName 'NetBIOS over Tcpip' -ErrorAction Stop
} @()
$NonDefaultNetBIOS = $NetBIOSProps | Where-Object {
    $_.DisplayValue -notin 'Default','Par défaut','Default'
}
if ($NetBIOSProps.Count -gt 0 -and $NonDefaultNetBIOS.Count -gt 0) {
    $Findings += [PSCustomObject]@{
        Severite  = 'INFO'
        Categorie = 'SMB / Réseau'
        Constat   = "NetBIOS over Tcpip non en mode Default sur certains adaptateurs"
        Detail    = 'Pour un comportement standard SMB, NetBIOS devrait être en mode Default si possible.'
        Correction= 'Get-NetAdapterAdvancedProperty -DisplayName "NetBIOS over Tcpip" | Set-NetAdapterAdvancedProperty -DisplayValue "Default"'
    }
}

$NmClient = Get-RegValue $RegPaths.MSV1_0 'NTLMMinClientSec'
if ($NmClient -ne 'NON DEFINI' -and [int]$NmClient -lt 537395200) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Authentification'
        Constat   = "NTLMMinClientSec = $NmClient"
        Detail = 'NTLMv2 est activé, mais la valeur est inférieure à la recommandation NTLMv2 + chiffrement 128 bits. Valeur 536870912 compatible W10 mais pas optimale.'
        Correction= 'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name NtlmMinClientSec -Value 537395200 -Type DWord -Force'
    }
}

$NmServer = Get-RegValue $RegPaths.MSV1_0 'NTLMMinServerSec'
if ($NmServer -ne 'NON DEFINI' -and [int]$NmServer -lt 537395200) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Authentification'
        Constat   = "NTLMMinServerSec = $NmServer"
        Detail = 'NTLMv2 est activé, mais la valeur est inférieure à la recommandation NTLMv2 + chiffrement 128 bits. Valeur 536870912 compatible W10 mais pas optimale.'
        Correction= 'Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 -Name NtlmMinServerSec -Value 537395200 -Type DWord -Force'
    }
}

$SMBBlockRules = @(
    'Bloquer SMB entrant 445',
    'Bloquer SMB entrant 139',
    'Bloquer NetBIOS entrant',
    'Bloquer SMB sortant 445',
    'Bloquer SMB sortant 139'
)

if ($SMBShareAuditStatus -in @("Pas d'audit", "No auditing")) {
    $Findings += [PSCustomObject]@{
        Severite  = 'WARN'
        Categorie = 'Audit SMB'
        Constat   = 'Audit des partages de fichiers non activé'
        Detail    = 'Sans audit SMB actif, les événements 5140/5142/5143/5144 ne sont pas collectés.'
        Correction= 'auditpol /set /subcategory:"Partage de fichiers" /success:enable /failure:enable'
    }
}
# AUCUN PROBLEME
if ($Findings.Count -eq 0) {
    $Findings += [PSCustomObject]@{ Severite='OK'; Categorie='General'; Constat='Aucun probleme critique detecte'; Detail='Configuration correcte pour le partage de fichiers en reseau local.'; Correction='N/A' }
}

$CriticalCount = ($Findings | Where-Object { $_.Severite -eq 'CRITICAL' }).Count
$WarnCount     = ($Findings | Where-Object { $_.Severite -eq 'WARN' }).Count
$OKCount       = ($Findings | Where-Object { $_.Severite -eq 'OK' }).Count
$Score         = [Math]::Max(0, 100 - ($CriticalCount*20) - ($WarnCount*5))
$ScoreStatus   = if ($Score -ge 80) { 'Sain' } elseif ($Score -ge 50) { 'Degrade' } else { 'Critique' }
$ScoreColor    = if ($Score -ge 80) { '#22c55e' } elseif ($Score -ge 50) { '#f59e0b' } else { '#ef4444' }
$ScriptEndTime = Get-Date
$ScriptDuration= (New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime).TotalSeconds
$ConnOK        = if ($ConnTests) { ($ConnTests | Where-Object { $_.Resultat -eq 'OK' }).Count } else { 0 }
$ConnTotal     = if ($ConnTests) { @($ConnTests).Count } else { 0 }

Write-Step "Generation du rapport HTML..."

# ─────────────────────────────────────────────────────────────────────────────
# REGION: GENERATION HTML
# ─────────────────────────────────────────────────────────────────────────────

function Build-Table {
    param([string]$ID, [array]$Data, [string[]]$Columns, [string]$RiskColumn = 'Risque')
    if (-not $Data -or $Data.Count -eq 0) { return "<p class='no-data'>Aucune donnee disponible</p>" }
    $h  = "<div class='table-wrap'><div class='table-toolbar'>"
    $h += "<input type='text' class='search-input' placeholder='Filtrer...' oninput='filterTable(this, &quot;$ID&quot;)'>"
    $h += "<button class='export-btn' onclick='exportCSV(&quot;$ID&quot;)'>CSV</button><button class='export-btn' onclick='exportTXT(&quot;$ID&quot;)'>TXT</button></div>"
    $h += "<table id='$ID' class='data-table'><thead><tr>"
    foreach ($Col in $Columns) { $h += "<th onclick='sortTable(this, &quot;$ID&quot;)'>$Col <span class='sort-arrow'>⇅</span></th>" }
    $h += "</tr></thead><tbody>"
    foreach ($Row in $Data) {
        $rClass = ''
        if ($Row.PSObject.Properties[$RiskColumn]) {
            $rClass = switch ($Row.$RiskColumn) { 'CRITICAL'{'row-critical'} 'WARN'{'row-warn'} 'OK'{'row-ok'} default{''} }
        }
        $h += "<tr class='$rClass'>"
        foreach ($Col in $Columns) {
            $val  = if ($Row.PSObject.Properties[$Col]) { "$($Row.$Col)" } else { '' }
            $cell = if ($Col -eq $RiskColumn -or $Col -eq 'Severite') { Get-StatusBadge $val } else { HtmlEncode $val }
            $h += "<td>$cell</td>"
        }
        $h += "</tr>"
    }
    $h += "</tbody></table></div>"
    return $h
}

function Build-Section {
    param([string]$ID, [string]$Title, [string]$Icon, [string]$Content, [string]$BadgeCount = '')
    $badge = if ($BadgeCount) { "<span class='section-badge'>$BadgeCount</span>" } else { '' }
    return @"
<section class="section" id="sec-$ID">
  <div class="section-header" onclick="toggleSection('$ID')">
    <span class="section-icon">$Icon</span>
    <span class="section-title">$Title</span>
    $badge
    <span class="section-toggle" id="tog-$ID">▼</span>
  </div>
  <div class="section-body" id="body-$ID">$Content</div>
</section>
"@
}

$ReportDate  = $ScriptStartTime.ToString("yyyy-MM-dd HH:mm:ss")
$ModeDisplay = $Mode
$FileName    = "DiagReseau_${ModeDisplay}_$($env:COMPUTERNAME)_$($ScriptStartTime.ToString('yyyyMMdd_HHmmss')).html"
$OutputFile  = Join-Path $OutputPath $FileName
$BaseName    = [System.IO.Path]::GetFileNameWithoutExtension($FileName)

$SMBSrvHTML  = "<h4>Configuration Serveur SMB</h4>" + (Build-Table -ID 'tbl-smb-srv' -Data $SMBServerItems -Columns @('Parametre','Valeur','Risque','Note'))
$SMBCliHTML  = "<h4>Configuration Client SMB</h4>"  + (Build-Table -ID 'tbl-smb-cli' -Data $SMBClientItems -Columns @('Parametre','Valeur','Risque','Note'))
$SMBShrHTML  = "<h4>Partages</h4>"                  + (Build-Table -ID 'tbl-shares'  -Data $SMBShares      -Columns @('Nom','Chemin','Type','Description','Permissions','ABE','Cache_HS','MaxUtilisateurs','Disponibilite'))
$SMBShrHTML2 = "<h4>Partages SMB</h4>" + 
              (Build-Table -ID 'tbl-shares' -Data $Shares -Columns @('Nom','Chemin','Acces','Dossiers','Risque') -RiskColumn 'Risque')
$SMBSesHTML  = "<h4>Sessions actives</h4>"           + (Build-Table -ID 'tbl-sessions'-Data $SMBSessions    -Columns @('Client','Utilisateur','Dialecte','Signe','Chiffre','Duree_s'))
$SMBConHTML  = "<h4>Connexions actives</h4>"         + (Build-Table -ID 'tbl-conn'    -Data $SMBConnections -Columns @('Serveur','Partage','Utilisateur','Dialecte','Signe','Chiffre'))

$RemoteSMBHTML = "<h4>Partages SMB distants / par interface</h4>" + (Build-Table -ID 'tbl-remote-smb' -Data $RemoteSMBShares -Columns @('Source','Type','Serveur','Partage','Interface','LocalIP','Cible','Utilisateur'))

$HistHTML    = "<h4>Evenements acces partage (7 derniers jours - IDs 5140/5142/5143/5144)</h4>" + (Build-Table -ID 'tbl-hist'    -Data $ConnHistory    -Columns @('Horodatage','EventID','TypeEvenemt','Partage','IPSource','Compte'))
$NetUseHTML  = "<h4>Connexions actives (net use)</h4>" + (if ($NetUseEntries.Count -gt 0) { Build-Table -ID 'tbl-netuse' -Data $NetUseEntries -Columns @('Statut','Local','Distant') } else { "<p class='no-data'>Aucune connexion net use active</p>" })
$PersHTML    = "<h4>Lecteurs persistants (HKCU:\Network)</h4>" + (if ($PersistentDrives.Count -gt 0) { Build-Table -ID 'tbl-persist' -Data $PersistentDrives -Columns @('Lecteur','Cible','Fournisseur','Utilisateur') } else { "<p class='no-data'>Aucun lecteur persistant enregistre</p>" })

$HTML = @"
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Diagnostic Reseau - $($Identity.Hostname) - $ReportDate</title>
<style>
:root{--bg:#0d1117;--surface:#161b22;--surface2:#21262d;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#58a6ff;--ok:#22c55e;--warn:#f59e0b;--critical:#ef4444;--info:#3b82f6;--radius:8px;--font:'Consolas','Cascadia Code','Fira Code',monospace}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px;line-height:1.6}
body.light{--bg:#f0f4f8;--surface:#fff;--surface2:#e8ecf0;--border:#d0d7de;--text:#1f2328;--muted:#636c76}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 24px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}
.topbar-left{display:flex;align-items:center;gap:12px}
.topbar-title{font-size:15px;font-weight:700;color:var(--accent)}
.mode-badge{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700;text-transform:uppercase}
.mode-complet{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
.mode-public{background:rgba(88,166,255,.15);color:#58a6ff;border:1px solid rgba(88,166,255,.3)}
.topbar-right{display:flex;gap:8px}
.topbar-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 12px;border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
.topbar-btn:hover{border-color:var(--accent);color:var(--accent)}
.nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;display:flex;gap:4px;overflow-x:auto;position:sticky;top:45px;z-index:99}
.nav-tab{padding:8px 14px;cursor:pointer;border-bottom:2px solid transparent;color:var(--muted);font-size:12px;white-space:nowrap;transition:all .2s}
.nav-tab:hover,.nav-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.main{max-width:1400px;margin:0 auto;padding:20px 24px}
.dashboard{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:24px}
.dash-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:14px 16px}
.dash-card-icon{font-size:22px;margin-bottom:6px}
.dash-card-label{font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:4px}
.dash-card-value{font-size:14px;font-weight:700;color:var(--text)}
.dash-card-sub{font-size:11px;color:var(--muted);margin-top:2px}
.score-bar-wrap{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px 20px;margin-bottom:24px}
.score-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.score-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.score-value{font-size:28px;font-weight:800}
.score-bar-bg{background:var(--surface2);border-radius:99px;height:10px;overflow:hidden}
.score-bar-fill{height:100%;border-radius:99px;transition:width 1s ease}
.score-label{font-size:11px;color:var(--muted);margin-top:6px}
.findings-summary{display:flex;gap:16px;margin-top:12px}
.finding-chip{padding:4px 12px;border-radius:99px;font-size:12px;font-weight:600}
.chip-critical{background:rgba(239,68,68,.15);color:#ef4444}
.chip-warn{background:rgba(245,158,11,.15);color:#f59e0b}
.chip-ok{background:rgba(34,197,94,.15);color:#22c55e}
.filter-bar{display:flex;gap:8px;margin-bottom:20px;flex-wrap:wrap}
.filter-btn{background:var(--surface);border:1px solid var(--border);color:var(--muted);padding:5px 14px;border-radius:99px;cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
.filter-btn:hover,.filter-btn.active{border-color:var(--accent);color:var(--accent)}
.filter-btn.f-critical.active{border-color:var(--critical);color:var(--critical)}
.filter-btn.f-warn.active{border-color:var(--warn);color:var(--warn)}
.filter-btn.f-ok.active{border-color:var(--ok);color:var(--ok)}
.section{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden}
.section-header{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none;transition:background .2s}
.section-header:hover{background:var(--surface2)}
.section-icon{font-size:16px}
.section-title{font-size:13px;font-weight:600;flex:1}
.section-badge{background:var(--surface2);border:1px solid var(--border);padding:1px 8px;border-radius:99px;font-size:11px;color:var(--muted)}
.section-toggle{font-size:11px;color:var(--muted);transition:transform .3s}
.section-toggle.collapsed{transform:rotate(-90deg)}
.section-body{padding:16px;border-top:1px solid var(--border)}
.section-body.hidden{display:none}
h4{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:16px 0 8px}
h4:first-child{margin-top:0}
.table-wrap{overflow-x:auto;margin-bottom:12px}
.table-toolbar{display:flex;gap:8px;margin-bottom:8px;align-items:center}
.search-input{background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:var(--radius);font-family:var(--font);font-size:12px;flex:1;outline:none}
.search-input:focus{border-color:var(--accent)}
.export-btn{background:var(--surface2);border:1px solid var(--border);color:var(--muted);padding:5px 12px;border-radius:var(--radius);cursor:pointer;font-family:var(--font);font-size:12px;white-space:nowrap;transition:all .2s}
.export-btn:hover{border-color:var(--accent);color:var(--accent)}
.data-table{width:100%;border-collapse:collapse;font-size:12px}
.data-table th{background:var(--surface2);padding:8px 12px;text-align:left;font-weight:600;border-bottom:1px solid var(--border);cursor:pointer;white-space:nowrap;user-select:none;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.data-table th:hover{color:var(--accent)}
.data-table td{padding:7px 12px;border-bottom:1px solid var(--border);vertical-align:top;word-break:break-all}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:hover td{background:rgba(88,166,255,.04)}
.row-critical td{border-left:3px solid var(--critical)}
.row-warn td{border-left:3px solid var(--warn)}
.row-ok td{border-left:3px solid var(--ok)}
.sort-arrow{font-size:10px;opacity:.5}
.badge{padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;display:inline-block}
.badge.ok{background:rgba(34,197,94,.15);color:#22c55e}
.badge.warn{background:rgba(245,158,11,.15);color:#f59e0b}
.badge.critical{background:rgba(239,68,68,.15);color:#ef4444}
.badge.info{background:rgba(59,130,246,.15);color:#3b82f6}
.no-data{color:var(--muted);font-size:12px;padding:12px 0}
.id-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:8px}
.id-row{display:flex;gap:8px;background:var(--surface2);padding:8px 12px;border-radius:var(--radius)}
.id-key{color:var(--muted);font-size:11px;min-width:150px}
.id-val{color:var(--text);font-size:12px;font-weight:500;word-break:break-all}
.footer{margin-top:32px;padding:20px 24px;border-top:1px solid var(--border);text-align:center;color:var(--muted);font-size:11px;line-height:2}
.footer a{color:var(--accent);text-decoration:none}
@media print{.topbar,.nav,.filter-bar,.table-toolbar,.topbar-btn{display:none!important}.section-body.hidden{display:block!important}body{background:#fff;color:#000}}
</style>
</head>
<body>

<div class="topbar">
  <div class="topbar-left">
    <span class="topbar-title">🔍 Diagnostic Reseau &amp; Partages SMB</span>
    <span class="mode-badge mode-$(if($Mode -eq 'COMPLET'){'complet'}else{'public'})">Mode $ModeDisplay</span>
  </div>
  <div class="topbar-right">
    <button class="topbar-btn" onclick="exportAllTXT()">⬇ TXT global</button>
    <button class="topbar-btn" onclick="exportAllCSV()">⬇ CSV global</button>
    <button class="topbar-btn" onclick="expandAll()">⊞ Tout deplier</button>
    <button class="topbar-btn" onclick="collapseAll()">⊟ Tout replier</button>
    <button class="topbar-btn" onclick="toggleTheme()">🌓 Theme</button>
    <button class="topbar-btn" onclick="copyReport()">📋 Copier</button>
  </div>
</div>

<div class="nav">
  <div class="nav-tab active" onclick="scrollToSection('sec-dashboard')">📊 Tableau de bord</div>
  <div class="nav-tab" onclick="scrollToSection('sec-identity')">🖥️ Identite</div>
  <div class="nav-tab" onclick="scrollToSection('sec-interfaces')">🌐 Interfaces</div>
  <div class="nav-tab" onclick="scrollToSection('sec-profiles')">📡 Profils</div>
  <div class="nav-tab" onclick="scrollToSection('sec-drives')">🗂️ Lecteurs</div>
  <div class="nav-tab" onclick="scrollToSection('sec-history')">🕐 Historique</div>
  <div class="nav-tab" onclick="scrollToSection('sec-smb')">📁 SMB</div>
  <div class="nav-tab" onclick="scrollToSection('sec-remote-shares')">🌍 Partages distants</div>
  <div class="nav-tab" onclick="scrollToSection('sec-firewall')">🔥 Pare-feu</div>
  <div class="nav-tab" onclick="scrollToSection('sec-auth')">🔐 Auth.</div>
  <div class="nav-tab" onclick="scrollToSection('sec-services')">⚙️ Services</div>
  <div class="nav-tab" onclick="scrollToSection('sec-events')">📋 Evenements</div>
  <div class="nav-tab" onclick="scrollToSection('sec-arp')">🔗 ARP</div>
  <div class="nav-tab" onclick="scrollToSection('sec-hosts')">📝 Hosts</div>
  <div class="nav-tab" onclick="scrollToSection('sec-connectivity')">🧪 Tests</div>
  <div class="nav-tab" onclick="scrollToSection('sec-findings')">⚠️ Recommandations</div>
</div>

<div class="main">

<div class="score-bar-wrap" id="sec-dashboard">
  <div class="score-header">
    <span class="score-title">Score de sante global</span>
    <span class="score-value" style="color:$ScoreColor">$Score / 100 — $ScoreStatus</span>
  </div>
  <div class="score-bar-bg"><div class="score-bar-fill" id="scoreFill" style="width:0%;background:$ScoreColor" data-target="$Score"></div></div>
  <div class="findings-summary">
    <span class="finding-chip chip-critical">❌ Critiques : $CriticalCount</span>
    <span class="finding-chip chip-warn">⚠️ Avertissements : $WarnCount</span>
    <span class="finding-chip chip-ok">✅ OK : $OKCount</span>
  </div>
  <div class="score-label">Duree du scan : $($ScriptDuration.ToString('0.0'))s — Genere le : $ReportDate — Hote : $($Identity.Hostname) — PS : $($Identity.PSVersion)</div>
</div>

<div class="dashboard">
  <div class="dash-card"><div class="dash-card-icon">🖥️</div><div class="dash-card-label">Machine</div><div class="dash-card-value">$($Identity.Hostname)</div><div class="dash-card-sub">$($Identity.OS.Replace('Microsoft ',''))</div><div class="dash-card-sub">Build $($Identity.Build) | Uptime : $($Identity.Uptime)</div></div>
  <div class="dash-card"><div class="dash-card-icon">🌐</div><div class="dash-card-label">Reseau</div><div class="dash-card-value">$(@($NetInterfaces).Count) interface(s) active(s)</div><div class="dash-card-sub">$(($NetProfiles | ForEach-Object { $_.Profil } | Select-Object -Unique) -join ' / ')</div></div>
  <div class="dash-card"><div class="dash-card-icon">📁</div><div class="dash-card-label">SMB</div><div class="dash-card-value">v1 : $(if($SMBv1Server){'⚠️ ACTIVE'}else{'✅ Desactive'}) | v2 : $(if($SMBv2Server){'✅ Active'}else{'❌ Desactive'})</div><div class="dash-card-sub">Signature : $(if($SMBServerConfig -and $SMBServerConfig.EnableSecuritySignature){'Activee'}else{'⚠️ Desactivee'})</div></div>
  <div class="dash-card"><div class="dash-card-icon">🗂️</div><div class="dash-card-label">Partages</div><div class="dash-card-value">$(@($SMBShares).Count) partage(s) SMB</div><div class="dash-card-sub">$(@($MappedDrives).Count) lecteur(s) mappe(s)</div></div>
  <div class="dash-card"><div class="dash-card-icon">🔥</div><div class="dash-card-label">Pare-feu</div><div class="dash-card-value">$(($FWProfiles | Where-Object {$_.Active}).Count)/$(@($FWProfiles).Count) profils actifs</div><div class="dash-card-sub">$(@($FWRules).Count) regles SMB actives</div></div>
  <div class="dash-card"><div class="dash-card-icon">🔐</div><div class="dash-card-label">Authentification</div><div class="dash-card-value">LmLevel : $LmLevel</div><div class="dash-card-sub">LATFP : $LATFP</div></div>
  <div class="dash-card"><div class="dash-card-icon">🧪</div><div class="dash-card-label">Connectivite</div><div class="dash-card-value">$ConnOK / $ConnTotal joignable(s)</div><div class="dash-card-sub">Port 445 ouvert : $(($ConnTests | Where-Object {$_.Port445 -eq 'OUVERT'}).Count) / $ConnTotal</div></div>
  <div class="dash-card"><div class="dash-card-icon">👤</div><div class="dash-card-label">Contexte</div><div class="dash-card-value">$(if($IsAdmin){'✅ Administrateur'}else{'⚠️ Non admin'})</div><div class="dash-card-sub">$($Identity.Utilisateur)</div></div>
</div>

<div class="filter-bar">
  <span style="color:var(--muted);font-size:12px;padding:5px 4px">Filtrer :</span>
  <button class="filter-btn active" onclick="document.querySelectorAll('.data-table tbody tr').forEach(r => r.style.display='');">Tout afficher</button>
  <button class="filter-btn f-critical" onclick="filterSections('critical',this)">❌ Critiques</button>
  <button class="filter-btn f-warn" onclick="filterSections('warn',this)">⚠️ Avertissements</button>
  <button class="filter-btn f-ok" onclick="filterSections('ok',this)">✅ OK</button>
</div>

$(Build-Section 'identity' "Identite de la machine" '🖥️' @"
<div class='id-grid'>
  <div class='id-row'><span class='id-key'>Nom d'hote</span><span class='id-val'>$($Identity.Hostname)</span></div>
  <div class='id-row'><span class='id-key'>Domaine / Workgroup</span><span class='id-val'>$($Identity.Domaine)</span></div>
  <div class='id-row'><span class='id-key'>Systeme d'exploitation</span><span class='id-val'>$($Identity.OS)</span></div>
  <div class='id-row'><span class='id-key'>Build</span><span class='id-val'>$($Identity.Build) — $($Identity.Version)</span></div>
  <div class='id-row'><span class='id-key'>Architecture</span><span class='id-val'>$($Identity.Architecture)</span></div>
  <div class='id-row'><span class='id-key'>Dernier demarrage</span><span class='id-val'>$($Identity.DernierBoot)</span></div>
  <div class='id-row'><span class='id-key'>Uptime</span><span class='id-val'>$($Identity.Uptime)</span></div>
  <div class='id-row'><span class='id-key'>Utilisateur courant</span><span class='id-val'>$($Identity.Utilisateur)</span></div>
  <div class='id-row'><span class='id-key'>SID</span><span class='id-val'>$($Identity.SID)</span></div>
  <div class='id-row'><span class='id-key'>Droits administrateur</span><span class='id-val'>$(if($Identity.EstAdmin){'✅ Oui'}else{'⚠️ Non (donnees limitees)'})</span></div>
  <div class='id-row'><span class='id-key'>PowerShell</span><span class='id-val'>$($Identity.PSVersion) ($($Identity.PSEdition))</span></div>
</div>
"@)

$(Build-Section 'interfaces' 'Interfaces reseau' '🌐' (Build-Table -ID 'tbl-ifaces' -Data $NetInterfaces -Columns @('Nom','IP','Masque','Passerelle','DNS','MAC','DHCP','MTU','Vitesse','Type','Statut')))

$(Build-Section 'profiles' 'Profils reseau' '📡' (Build-Table -ID 'tbl-profiles' -Data $NetProfiles -Columns @('Interface','Nom','Profil','IPv4','IPv6','Risque')))

$(Build-Section 'drives' 'Lecteurs mappes et historique MRU' '🗂️' @"
<h4>Lecteurs mappes actifs</h4>
$(if ($MappedDrives) { Build-Table -ID 'tbl-drives' -Data $MappedDrives -Columns @('Lecteur','Cible','Utilise','Libre') } else { "<p class='no-data'>Aucun lecteur reseau mappe actif</p>" })
<h4>Registre MRU (connexions passees)</h4>
$(if ($MRUEntries) { Build-Table -ID 'tbl-mru' -Data $MRUEntries -Columns @('Source','Cle','Valeur') } else { "<p class='no-data'>Aucune entree MRU </p>" })
"@)

$(Build-Section 'history' 'Historique des connexions reseau' '🕐' ($HistHTML + $NetUseHTML + $PersHTML) "$(@($ConnHistory).Count) evenement(s)")

$(Build-Section 'smb' 'Configuration SMB' '📁' ($SMBSrvHTML + $SMBCliHTML + $SMBShrHTML + $SMBSesHTML + $SMBConHTML) "$(@($Shares).Count) partage(s)")

$(Build-Section 'shares' 'Partages SMB' '📂' ($SMBShrHTML2) "$(@($Shares).Count) partage(s)")
$(Build-Section 'remote-shares' 'Partages SMB distants' '🌍' ($RemoteSMBHTML) "$(@($RemoteSMBShares).Count) partage(s) distants")
$(Build-Section 'firewall' 'Pare-feu Windows' '🔥' @"
<h4>Profils</h4>
$(Build-Table -ID 'tbl-fw-profiles' -Data $FWProfiles -Columns @('Profil','Active','EntreeDefaut','SortieDefaut','LogAutorise','LogBloque','Risque'))
<h4>Regles actives (SMB / Partage)</h4>
$(Build-Table -ID 'tbl-fw-rules' -Data $FWRules -Columns @('Nom','Direction','Action','Profil','Protocole','Port','Active','Risque'))
"@)

$(Build-Section 'auth' 'Authentification et politique de securite' '🔐' @"
<h4>Politique d'authentification (registre)</h4>
$(Build-Table -ID 'tbl-auth' -Data $AuthPolicy -Columns @('Cle','Valeur','Recommande','Risque','Note'))
<h4>Comptes locaux</h4>
$(Build-Table -ID 'tbl-accounts' -Data $LocalAccounts -Columns @('Nom','Active','DernConnexion','MdpRequis','MdpExpire','SID','Risque'))
<h4>Gestionnaire d'informations d'identification</h4>
$(if ($CredEntries) { Build-Table -ID 'tbl-cred' -Data $CredEntries -Columns @('Cible','Type') } else { "<p class='no-data'>Aucune entree dans le gestionnaire de credentials</p>" })
"@)

$(Build-Section 'services' 'Services et protocoles de decouverte' '⚙️' @"
<h4>Services critiques</h4>
$(Build-Table -ID 'tbl-services' -Data $ServicesData -Columns @('Nom','Libelle','Statut','Demarrage','Risque'))
<h4>Protocoles de decouverte reseau</h4>
$(Build-Table -ID 'tbl-discovery' -Data $DiscoveryItems -Columns @('Protocole','Etat','Risque','Note'))
"@)

$(Build-Section 'events' "Journal d'evenements - 24 dernieres heures (Auth/Partage)" '📋' (Build-Table -ID 'tbl-events' -Data $EventLogs -Columns @('Horodatage','Journal','EventID','Niveau','Categorie','Source','Message')) "$(@($EventLogs).Count) evenement(s)")

$(Build-Section 'arp' 'Table ARP' '🔗' (Build-Table -ID 'tbl-arp' -Data $ArpEntries -Columns @('IP','MAC','Type')) "$(@($ArpEntries).Count) entree(s)")

$(Build-Section 'hosts' 'Fichier Hosts' '📝' (Build-Table -ID 'tbl-hosts' -Data $HostsEntries -Columns @('IP','Hostname','Note')))

$(Build-Section 'connectivity' 'Tests de connectivite' '🧪' (Build-Table -ID 'tbl-conn-tests' -Data @(if ($ConnTests) { $ConnTests } else { @() }) -Columns @('Cible','Ping','Port445','UNC_IPC','Resultat') -RiskColumn 'Resultat'))

$(Build-Section 'findings' 'Constats et Recommandations' '⚠️' (Build-Table -ID 'tbl-findings' -Data $Findings -Columns @('Severite','Categorie','Constat','Detail','Correction') -RiskColumn 'Severite') "$CriticalCount critique(s) / $WarnCount avertissement(s)")

</div>

<div class="footer">
  <strong>NetworkShareDiagnostic v1.1.0</strong> par
  <a href="https://github.com/ps81frt/NetworkShareDiagnostic" target="_blank">ps81frt</a> —
  Licence MIT<br>
  Genere le $ReportDate — Hote : $($Identity.Hostname) — Mode : $ModeDisplay — PS : $($Identity.PSVersion)<br>
  Scan en lecture seule. Aucune modification systeme effectuee.
</div>
    <script>
        function toggleTheme(){document.body.classList.toggle('light');localStorage.setItem('theme',document.body.classList.contains('light')?'light':'dark')}
        if(localStorage.getItem('theme')==='light')document.body.classList.add('light');
        function toggleSection(id){var b=document.getElementById('body-'+id),t=document.getElementById('tog-'+id);b.classList.toggle('hidden');t.classList.toggle('collapsed')}
        function expandAll(){document.querySelectorAll('.section-body').forEach(b=>b.classList.remove('hidden'));document.querySelectorAll('.section-toggle').forEach(t=>t.classList.remove('collapsed'))}
        function collapseAll(){document.querySelectorAll('.section-body').forEach(b=>b.classList.add('hidden'));document.querySelectorAll('.section-toggle').forEach(t=>t.classList.add('collapsed'))}
        function scrollToSection(id){var el=document.getElementById(id);if(el)el.scrollIntoView({behavior:'smooth',block:'start'});document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));event.target.classList.add('active')}
        function sortTable(th,tableId){var table=document.getElementById(tableId),col=Array.from(th.parentNode.children).indexOf(th),rows=Array.from(table.querySelectorAll('tbody tr')),asc=th.dataset.sort!=='asc';rows.sort(function(a,b){var A=(a.cells[col]?a.cells[col].textContent:'').trim(),B=(b.cells[col]?b.cells[col].textContent:'').trim();return asc?A.localeCompare(B,'fr',{numeric:true}):B.localeCompare(A,'fr',{numeric:true})});th.dataset.sort=asc?'asc':'desc';var tbody=table.querySelector('tbody');rows.forEach(r=>tbody.appendChild(r))}
        function filterTable(input,tableId){var filter=input.value.toLowerCase(),rows=document.getElementById(tableId).querySelectorAll('tbody tr');rows.forEach(function(row){row.style.display=row.textContent.toLowerCase().includes(filter)?'':'none'})}
        function globalSearch(val){var filter=val.toLowerCase();document.querySelectorAll('.data-table tbody tr').forEach(function(row){row.style.display=(!filter||row.textContent.toLowerCase().includes(filter))?'':'none'});if(filter)expandAll()}
        function getExportText(cell){var clone=cell.cloneNode(true);var arrow=clone.querySelector('.sort-arrow');if(arrow)arrow.remove();var text=clone.textContent.trim();text=text.replace(/✅/g,'').replace(/⚠️/g,'').replace(/❌/g,'').replace(/ℹ️/g,'').replace(/\s{2,}/g,' ').trim();return text}
        function formatDateTime(){var d=new Date();return d.getFullYear().toString()+('0'+(d.getMonth()+1)).slice(-2)+('0'+d.getDate()).slice(-2)+'_'+d.getHours()+'h'+d.getMinutes()+'m'+d.getSeconds()+'s'}
        function exportCSV(tableId){var table=document.getElementById(tableId);if(!table)return;var rows=table.querySelectorAll('tr'),csv=[];rows.forEach(function(row){var cells=Array.from(row.querySelectorAll('th,td'));csv.push(cells.map(function(c){return '"'+getExportText(c).replace(/"/g,'""')+'"'}).join(','))});var blob=new Blob(['\uFEFF'+csv.join('\n')],{type:'text/csv;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=tableId+'_'+formatDateTime()+'.csv';a.click()}
        function exportTXT(tableId){var table=document.getElementById(tableId);if(!table)return;var headers=Array.from(table.querySelectorAll('thead th')).map(function(th){return getExportText(th)});var rows=Array.from(table.querySelectorAll('tbody tr')).filter(function(row){return row.style.display!=='none'});var lines=[];rows.forEach(function(row,index){var cells=Array.from(row.querySelectorAll('th,td')).map(function(cell){return getExportText(cell)});var title=cells[0]||('Ligne '+(index+1));var separator='======= '+title+' =======';lines.push(separator);headers.forEach(function(h,i){lines.push(h+': '+(cells[i]||''))});lines.push('')} );if(lines.length>0){lines.pop()}else{lines.push('Aucune donnee disponible')}var blob=new Blob([lines.join('\r\n')],{type:'text/plain;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=tableId+'_'+formatDateTime()+'.txt';a.click()}
        function exportAllTXT(){var lines=[];document.querySelectorAll('.data-table').forEach(function(table){var title=(table.closest('.section')&&table.closest('.section').querySelector('.section-title')?table.closest('.section').querySelector('.section-title').textContent.trim():table.id||'report');lines.push('======= '+title+' =======');var headers=Array.from(table.querySelectorAll('thead th')).map(function(th){return getExportText(th)});Array.from(table.querySelectorAll('tbody tr')).filter(function(row){return row.style.display!=='none'}).forEach(function(row){var cells=Array.from(row.querySelectorAll('th,td')).map(function(cell){return getExportText(cell)});var rowLines=[];headers.forEach(function(h,i){if(cells[i])rowLines.push(h+': '+cells[i])});if(rowLines.length){lines.push(rowLines.join('\r\n'));lines.push('')}});lines.push('')});if(lines.length===0){lines.push('Aucune donnee disponible')}var blob=new Blob([lines.join('\r\n')],{type:'text/plain;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='report-all-'+formatDateTime()+'.txt';a.click()}
        function exportAllCSV(){var SEP=';',rows=[],now=new Date(),total=0,esc=function(v){return'"'+(v===undefined||v===null?'':String(v).replace(/"/g,'""'))+'"'},fmtDate=function(d){return d.toLocaleDateString('fr-FR')+' '+d.toLocaleTimeString('fr-FR')},fmtFile=function(d){return d.getFullYear()+'-'+(d.getMonth()+1)+'-'+d.getDate()+'_'+d.getHours()+'-'+d.getMinutes()};document.querySelectorAll('.data-table').forEach(function(t){total+=t.querySelectorAll('tbody tr:not([style*="display: none"])').length});rows.push(['Rapport','Export complet',fmtDate(now),total+' ligne(s)'].join(SEP));document.querySelectorAll('.data-table').forEach(function(t,i){var title=(t.closest('.section')&&t.closest('.section').querySelector('.section-title')?t.closest('.section').querySelector('.section-title').textContent.trim():t.id||'sans_titre')||'section';var headers=Array.from(t.querySelectorAll('thead th')).map(function(th){return esc(th.textContent.trim())});rows.push(esc('['+(i+1)+'] '+title));if(headers.length)rows.push(headers.join(SEP));Array.from(t.querySelectorAll('tbody tr')).filter(function(r){return r.style.display!=='none'}).forEach(function(tr){var cells=Array.from(tr.querySelectorAll('td')).map(function(td){return esc(td.textContent.trim())});rows.push(cells.join(SEP))});if(i<document.querySelectorAll('.data-table').length-1)rows.push('')});if(rows.length===2)rows.push(esc('Aucune donnée'));var blob=new Blob(['\uFEFF'+rows.join('\n')],{type:'text/csv;charset=utf-8'});var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='export_'+fmtFile(now)+'.csv';a.click()}
        function filterSections(level,btn){document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');if(level==='all'){expandAll();return}document.querySelectorAll('.data-table tbody tr').forEach(function(row){var show=false;if(level==='critical'&&row.classList.contains('row-critical'))show=true;if(level==='warn'&&row.classList.contains('row-warn'))show=true;if(level==='ok'&&row.classList.contains('row-ok'))show=true;row.style.display=show?'':'none'});expandAll()}
        function copyReport(){navigator.clipboard.writeText(document.body.innerText).then(function(){alert('Texte du rapport copie dans le presse-papiers.')})}
        window.addEventListener('load',function(){var f=document.getElementById('scoreFill');if(f){var t=f.dataset.target;setTimeout(function(){f.style.width=t+'%'},150)}});
    </script>
</body>
</html>
"@

$ReportSections = @(
    [PSCustomObject]@{ Title='Identite'; Data=@($Identity); Columns=@('Hostname','Domaine','OS','Build','Version','Architecture','Uptime','DernierBoot','Utilisateur','SID','EstAdmin','PSVersion','PSEdition') },
    [PSCustomObject]@{ Title='Interfaces reseau'; Data=$NetInterfaces; Columns=@('Nom','IP','Masque','Passerelle','DNS','MAC','DHCP','MTU','Vitesse','Type','Statut') },
    [PSCustomObject]@{ Title='Profils reseau'; Data=$NetProfiles; Columns=@('Interface','Nom','Profil','IPv4','IPv6','Risque') },
    [PSCustomObject]@{ Title='Lecteurs mappes'; Data=$MappedDrives; Columns=@('Lecteur','Cible','Utilise','Libre') },
    [PSCustomObject]@{ Title='Lecteurs persistants'; Data=$PersistentDrives; Columns=@('Lecteur','Cible','Fournisseur','Utilisateur','Source') },
    [PSCustomObject]@{ Title='Partages SMB (etendus)'; Data=$SMBShares; Columns=@('Nom','Chemin','Description','Type','Permissions','ABE','Cache_HS','MaxUtilisateurs','Disponibilite') },
    [PSCustomObject]@{ Title='Sessions SMB actives'; Data=$SMBSessions; Columns=@('Client','Utilisateur','Dialecte','Signe','Chiffre','Duree_s') },
    [PSCustomObject]@{ Title='Connexions SMB actives'; Data=$SMBConnections; Columns=@('Serveur','Partage','Utilisateur','Dialecte','Signe','Chiffre') },
    [PSCustomObject]@{ Title='Partages SMB distants'; Data=$RemoteSMBShares; Columns=@('Source','Type','Serveur','Partage','Interface','LocalIP','Cible','Utilisateur') },
    [PSCustomObject]@{ Title='Historique connectivite'; Data=$ConnHistory; Columns=@('Horodatage','EventID','TypeEvenemt','Partage','IPSource','Compte') },
    [PSCustomObject]@{ Title='Connexions net use'; Data=$NetUseEntries; Columns=@('Statut','Local','Distant') },
    [PSCustomObject]@{ Title='Services pare-feu'; Data=$FWProfiles; Columns=@('Profil','Active','EntreeDefaut','SortieDefaut','LogAutorise','LogBloque','Risque') },
    [PSCustomObject]@{ Title='Regles firewall'; Data=$FWRules; Columns=@('Nom','Direction','Action','Profil','Protocole','Port','Active','Risque') },
    [PSCustomObject]@{ Title='Politique SMB client'; Data=$SMBClientItems; Columns=@('Parametre','Valeur','Risque','Note') },
    [PSCustomObject]@{ Title='Politique SMB serveur'; Data=$SMBServerItems; Columns=@('Parametre','Valeur','Risque','Note') },
    [PSCustomObject]@{ Title='Authentification'; Data=$AuthPolicy; Columns=@('Cle','Valeur','Recommande','Risque','Note') },
    [PSCustomObject]@{ Title='Comptes locaux'; Data=$LocalAccounts; Columns=@('Nom','Active','DernConnexion','MdpRequis','MdpExpire','SID','Risque') },
    [PSCustomObject]@{ Title='Entrées credentials'; Data=$CredEntries; Columns=@('Cible','Type') },
    [PSCustomObject]@{ Title='Services critiques'; Data=$ServicesData; Columns=@('Nom','Libelle','Statut','Demarrage','Risque') },
    [PSCustomObject]@{ Title='Protocoles de decouverte'; Data=$DiscoveryItems; Columns=@('Protocole','Etat','Risque','Note') },
    [PSCustomObject]@{ Title='Evenements'; Data=$EventLogs; Columns=@('Horodatage','Journal','EventID','Niveau','Categorie','Source','Message') },
    [PSCustomObject]@{ Title='Table ARP'; Data=$ArpEntries; Columns=@('IP','MAC','Type') },
    [PSCustomObject]@{ Title='Hosts'; Data=$HostsEntries; Columns=@('IP','Hostname','Note') },
    [PSCustomObject]@{ Title='Tests connectivite'; Data=$ConnTests; Columns=@('Cible','Ping','Port445','UNC_IPC','Resultat') },
    [PSCustomObject]@{ Title='Constats'; Data=$Findings; Columns=@('Severite','Categorie','Constat','Detail','Correction') }
)

function Export-TableText {
    param([string]$Title, [array]$Data, [string[]]$Columns)
    $lines = @()
    $lines += "======= $Title ======="
    foreach ($row in $Data) {
        foreach ($column in $Columns) {
            $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
            $lines += "${column}: $value"
        }
        $lines += ''
    }
    return $lines
}

function Export-TableText {
    param([string]$Title, [array]$Data, [string[]]$Columns)
    $lines = @()
    $lines += "======= $Title ======="
    foreach ($row in $Data) {
        foreach ($column in $Columns) {
            $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
            $lines += "${column}: $value"
        }
        $lines += ''
    }
    return $lines
}

function Export-ReportAllText {
    $allLines = @()
    $AllTxtFile = Join-Path $OutputPath "$BaseName-all.txt"
    foreach ($section in $ReportSections) {
        $allLines += Export-TableText -Title $section.Title -Data $section.Data -Columns $section.Columns
        $allLines += ''
    }
    [System.IO.File]::WriteAllLines($AllTxtFile, $allLines, [System.Text.Encoding]::UTF8)
}

function Export-ReportAllCsv {
    $rows = @('Section,Row,Field,Value')
    $AllCsvFile = Join-Path $OutputPath "$BaseName-all.csv"
    foreach ($section in $ReportSections) {
        $rowIndex = 0
        foreach ($row in $section.Data) {
            $rowIndex++
            foreach ($column in $section.Columns) {
                $value = if ($row.PSObject.Properties[$column]) { $row.$column } else { '' }
                $escaped = '"' + ($section.Title -replace '"','""') + '",' + $rowIndex + ',"' + ($column -replace '"','""') + '","' + ($value -replace '"','""') + '"'
                $rows += $escaped
            }
        }
    }
    [System.IO.File]::WriteAllLines($AllCsvFile, $rows, [System.Text.Encoding]::UTF8)
}

# ─────────────────────────────────────────────────────────────────────────────
# REGION: EXPORT DU RAPPORT
# ─────────────────────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputPath)) {
    try {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    } catch {
        Write-Host "[ERREUR] Impossible de recreer '$OutputPath'. Bascule vers $env:TEMP" -ForegroundColor Red
        $OutputPath = $env:TEMP
        $OutputFile = Join-Path $OutputPath $FileName
    }
}

Write-DebugHost "DEBUG: HTML block created"
Write-DebugHost "DEBUG: HTML length = $($HTML.Length)"
Write-DebugHost "DEBUG: HTML variable defined? $([bool](Get-Variable HTML -ErrorAction SilentlyContinue))"

try {
    [System.IO.File]::WriteAllText($OutputFile, $HTML, [System.Text.Encoding]::UTF8)
} catch {
    Write-Host "[ERREUR] Impossible d'ecrire le rapport : $($_.Exception.Message)" -ForegroundColor Red
    $OutputPath = $env:TEMP
    $OutputFile = Join-Path $OutputPath $FileName

    try {
        [System.IO.File]::WriteAllText($OutputFile, $HTML, [System.Text.Encoding]::UTF8)
        Write-Host "[INFO] Rapport ecrit dans le dossier temporaire : $OutputFile" -ForegroundColor Yellow
    } catch {
        Write-Host "[CRITIQUE] Ecriture impossible meme dans $env:TEMP : $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  ✅ Rapport genere avec succes" -ForegroundColor Green
Write-Host ""
Write-Host "  📄 Fichier      : $OutputFile" -ForegroundColor White
Write-Host "  🎯 Mode         : $ModeDisplay" -ForegroundColor $(if($Mode -eq 'COMPLET'){'Red'}else{'Cyan'})
Write-Host "  ⏱  Duree        : $($ScriptDuration.ToString('0.0'))s" -ForegroundColor Gray
Write-Host "  ❌ Critiques    : $CriticalCount" -ForegroundColor Red
Write-Host "  ⚠️  Avert.       : $WarnCount" -ForegroundColor Yellow
Write-Host "  ✅ OK           : $OKCount" -ForegroundColor Green
Write-Host "  🏆 Score        : $Score/100 ($ScoreStatus)" -ForegroundColor $(if($Score -ge 80){'Green'}elseif($Score -ge 50){'Yellow'}else{'Red'})
Write-Host ""
Write-Host "  Ouverture du rapport dans le navigateur par defaut..." -ForegroundColor Gray
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan

try {
    Start-Process -FilePath $OutputFile -ErrorAction Stop
} catch {
    Write-Host "[ERREUR] Impossible d'ouvrir le rapport : $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         Ouvrez manuellement : $OutputFile" -ForegroundColor Yellow
}
Write-DebugHost "DEBUG: Arrive a la fin du script"
