# NetworkShareDiagnostic

**Auteur :** ps81frt  
**Version :** 1.1.0  
**Licence :** MIT  
**Dépendances :** aucune (modules Windows natifs uniquement)  
**Effet sur le système :** lecture seule — aucune écriture registre, aucune modification de service, aucune création de règle réseau  

---

## Table des matières

1. [Résumé technique](#1-résumé-technique)
2. [Prérequis](#2-prérequis)
3. [Paramètres](#3-paramètres)
4. [Modes de rapport](#4-modes-de-rapport)
5. [Invocation](#5-invocation)
6. [Flux d'exécution](#6-flux-dexécution)
7. [Module 01 — Identité machine](#7-module-01--identité-machine)
8. [Module 02 — Interfaces réseau](#8-module-02--interfaces-réseau)
9. [Module 03 — Profils réseau](#9-module-03--profils-réseau)
10. [Module 04 — Lecteurs mappés et historique MRU](#10-module-04--lecteurs-mappés-et-historique-mru)
11. [Module 05 — Configuration SMB Serveur](#11-module-05--configuration-smb-serveur)
12. [Module 06 — Configuration SMB Client](#12-module-06--configuration-smb-client)
13. [Module 07 — Partages SMB](#13-module-07--partages-smb)
14. [Module 08 — Sessions SMB actives](#14-module-08--sessions-smb-actives)
15. [Module 09 — Connexions SMB actives](#15-module-09--connexions-smb-actives)
16. [Module 10 — Historique connexions réseau (7 jours)](#16-module-10--historique-connexions-réseau-7-jours)
17. [Module 11 — Pare-feu Windows](#17-module-11--pare-feu-windows)
18. [Module 12 — Politique d'authentification](#18-module-12--politique-dauthentification)
19. [Module 13 — Services et protocoles de découverte](#19-module-13--services-et-protocoles-de-découverte)
20. [Module 14 — Journal d'événements (24 h)](#20-module-14--journal-dévénements-24-h)
21. [Module 15 — Table ARP](#21-module-15--table-arp)
22. [Module 16 — Fichier Hosts](#22-module-16--fichier-hosts)
23. [Module 17 — Tests de connectivité](#23-module-17--tests-de-connectivité)
24. [Moteur d'analyse et recommandations](#24-moteur-danalyse-et-recommandations)
25. [Calcul du score de santé](#25-calcul-du-score-de-santé)
26. [Rapport HTML — structure et comportement](#26-rapport-html--structure-et-comportement)
27. [Fonctions utilitaires internes](#27-fonctions-utilitaires-internes)
28. [Système de masquage (Mode PUBLIC)](#28-système-de-masquage-mode-public)
29. [Registres Windows consultés](#29-registres-windows-consultés)
30. [Event IDs collectés](#30-event-ids-collectés)
31. [Services Windows analysés](#31-services-windows-analysés)
32. [Nommage du fichier de sortie](#32-nommage-du-fichier-de-sortie)
33. [Comportement en mode non-administrateur](#33-comportement-en-mode-non-administrateur)
34. [Limitations connues](#34-limitations-connues)
35. [Dépannage](#35-dépannage)
36. [Changelog](#36-changelog)

---

## 1. Résumé technique

Le script est un fichier `.ps1` monolithique de 1 204 lignes. Il collecte séquentiellement des données depuis 17 sources distinctes (cmdlets PowerShell, WMI/CIM, registre, journaux d'événements, binaires système), construit des objets `PSCustomObject` pour chaque jeu de données, génère un score de santé numérique, puis produit un fichier HTML autonome contenant le rapport complet avec JavaScript embarqué pour l'interactivité.

Il n'installe rien, n'importe aucun module tiers, ne crée aucun processus persistant. La seule écriture disque est le fichier de rapport final.

---

## 2. Prérequis

### PowerShell

```
#Requires -Version 5.1
```

Le script vérifie `$PSVersionTable.PSVersion.Major` au démarrage. Si la version est inférieure à 5, il appelle `exit 1`. Testé et fonctionnel sur :

- Windows PowerShell 5.1 (inclus dans Windows 10/11)
- PowerShell 7.x (Core) — détecté via `$PSVersionTable.PSEdition`

### Système d'exploitation

- Windows 10 (toutes éditions)
- Windows 11 (toutes éditions)
- Windows Server 2016 / 2019 / 2022 (non officiellement ciblé mais fonctionnel)

### Droits

Le script fonctionne sans élévation en mode **dégradé** : les modules qui nécessitent des droits administrateur (journaux Security, `Get-SmbServerConfiguration`, accès au registre HKLM en lecture sur certaines clés) retournent soit une valeur de substitution soit un message d'avertissement. Aucune fonctionnalité ne lève d'exception fatale à cause de droits insuffisants — les blocs `try/catch` avec valeurs par défaut couvrent tous les appels potentiellement restreints.

L'exécution en **administrateur** est nécessaire pour accéder aux journaux `Security` (Event IDs 4625, 5140, etc.), à `Get-SmbSession`, à `Get-SmbServerConfiguration` complète, et à certaines clés HKLM.

### Politique d'exécution

Le script doit pouvoir être exécuté. Selon la politique en place :

```powershell
# Vérifier la politique courante
Get-ExecutionPolicy -List

# Débloquer uniquement ce fichier (sans changer la politique globale)
Unblock-File -Path .\NetworkShareDiagnostic.ps1

# Ou exécution directe avec bypass de session
powershell.exe -ExecutionPolicy Bypass -File .\NetworkShareDiagnostic.ps1
```

---

## 3. Paramètres

Le script expose deux paramètres via `[CmdletBinding()]` :

### `-Mode`

```powershell
[Parameter(Mandatory=$false)]
[ValidateSet('COMPLET','PUBLIC')]
[string]$Mode
```

- **Optionnel.** Si omis, le script affiche un menu interactif dans la console.
- `COMPLET` : toutes les données sont affichées sans masquage.
- `PUBLIC` : les données sensibles sont masquées via les fonctions `Set-Mask-*` (voir [section 28](#28-système-de-masquage-mode-public)).
- La valeur est validée par `[ValidateSet]` — toute autre valeur lève une erreur avant l'exécution.

### `-OutputPath`

```powershell
[Parameter(Mandatory=$false)]
[string]$OutputPath = "C:\Temp"
```

- **Optionnel.** Chemin du dossier de destination du fichier HTML.
- Valeur par défaut : `C:\Temp`.
- Si le dossier n'existe pas, le script tente de le créer avec `New-Item -ItemType Directory -Force`.
- En cas d'échec de création, le script bascule automatiquement vers `$env:TEMP`.

---

## 4. Modes de rapport

### COMPLET

Toutes les données collectées sont écrites telles quelles dans le rapport :
- Adresses IP complètes (ex. `192.168.1.42`)
- Adresses MAC complètes (ex. `AA:BB:CC:DD:EE:FF`)
- Noms d'hôtes complets
- Chemins UNC complets (ex. `\\SERVEUR\Partage`)
- Noms de comptes complets (ex. `DOMAINE\utilisateur`)
- SIDs complets (ex. `S-1-5-21-123456789-987654321-111111111-1001`)

### PUBLIC

Conçu pour partager le rapport avec un tiers (support, équipe externe) sans exposer la topologie réseau interne ni les identités. Les transformations appliquées :

| Type de donnée | COMPLET | PUBLIC |
|---|---|---|
| Adresse IPv4 | `192.168.1.42` | `192.168.x.xxx` |
| Adresse MAC | `AA:BB:CC:DD:EE:FF` | `XX:XX:XX:XX:XX:XX` |
| Nom d'hôte | `SERVEUR-PROD-01` | `SER*****` (3 chars + astérisques) |
| SID | `S-1-5-21-...-1001` | `S-1-5-***-***` |
| Chemin UNC | `\\SERVEUR\Partage` | `\\***\Partage` |
| Nom de compte | `DOMAINE\user` | `***\user` |
| Serveur DNS | `192.168.1.1` | `x.x.x.x` |

Le masquage est appliqué **à la collecte**, pas à l'affichage — les données brutes ne sont jamais stockées en mémoire en mode PUBLIC.

---

## 5. Invocation

### Interactive (menu console)

```powershell
.\NetworkShareDiagnostic.ps1
```

Affiche un menu numéroté `[1] COMPLET / [2] PUBLIC / [Q] Quitter`.

### Non-interactive (CI, déploiement)

```powershell
.\NetworkShareDiagnostic.ps1 -Mode COMPLET
.\NetworkShareDiagnostic.ps1 -Mode PUBLIC
.\NetworkShareDiagnostic.ps1 -Mode COMPLET -OutputPath "D:\Rapports\Diag"
```

### Avec élévation automatique depuis une session non-admin

```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-File "C:\Scripts\NetworkShareDiagnostic.ps1" -Mode COMPLET'
```

### PowerShell 7 (pwsh)

```powershell
pwsh -ExecutionPolicy Bypass -File .\NetworkShareDiagnostic.ps1 -Mode PUBLIC -OutputPath "$env:USERPROFILE\Desktop"
```

### Depuis une GPO ou une tâche planifiée

```
powershell.exe -NonInteractive -ExecutionPolicy Bypass -File "\\SERVEUR\Scripts\NetworkShareDiagnostic.ps1" -Mode PUBLIC -OutputPath "C:\Temp"
```

> **Attention :** en mode non-interactif planifié, `-Mode` est obligatoire, sinon `Read-Host` bloque indéfiniment.

---

## 6. Flux d'exécution

```
Démarrage
│
├─ Vérification version PS ($PSVersionTable.PSVersion.Major < 5 → exit 1)
├─ Affichage bannière ASCII (Write-Host)
├─ Détection élévation ([Security.Principal.WindowsPrincipal])
├─ Création dossier OutputPath (si absent)
├─ Sélection Mode (paramètre ou menu interactif)
├─ $ScriptStartTime = Get-Date
│
├─ Collecte séquentielle (17 modules)
│   ├─ 01 Identité machine         (CIM Win32_OperatingSystem, Win32_ComputerSystem)
│   ├─ 02 Interfaces réseau        (Get-NetAdapter, Get-NetIPConfiguration)
│   ├─ 03 Profils réseau           (Get-NetConnectionProfile)
│   ├─ 04 Lecteurs mappés / MRU    (Get-PSDrive, HKCU:\Network, registre MRU)
│   ├─ 05 SMB Serveur              (Get-SmbServerConfiguration)
│   ├─ 06 SMB Client               (Get-SmbClientConfiguration → fallback registre)
│   ├─ 07 Partages SMB             (Get-SmbShare, Get-SmbShareAccess, Get-SmbShareConfiguration)
│   ├─ 08 Sessions SMB             (Get-SmbSession)
│   ├─ 09 Connexions SMB           (Get-SmbConnection)
│   ├─ 10 Historique connexions    (Get-WinEvent Security 5140/5142/5143/5144, net use)
│   ├─ 11 Pare-feu                 (Get-NetFirewallProfile, Get-NetFirewallRule, Get-NetFirewallPortFilter)
│   ├─ 12 Authentification         (Get-ItemProperty HKLM Lsa, Get-LocalUser, cmdkey /list)
│   ├─ 13 Services / découverte    (Get-Service x15, Get-WmiObject Win32_NetworkAdapterConfiguration)
│   ├─ 14 Journaux événements 24h  (Get-WinEvent Security+System+Application)
│   ├─ 15 Table ARP                (arp -a)
│   ├─ 16 Fichier Hosts            (Get-Content $env:SystemRoot\System32\drivers\etc\hosts)
│   └─ 17 Tests connectivité       (Test-Connection, Test-NetConnection, [System.IO.Directory]::GetDirectories)
│
├─ Moteur d'analyse (11 règles → $Findings[])
├─ Calcul score (100 - critiques×20 - warnings×5)
├─ $ScriptEndTime = Get-Date
│
├─ Build HTML (here-string + Build-Table() + Build-Section())
│
└─ Écriture fichier ([System.IO.File]::WriteAllText UTF-8)
    ├─ Succès → Start-Process $OutputFile (ouvre dans le navigateur)
    └─ Échec → retry dans $env:TEMP
```

---

## 7. Module 01 — Identité machine

**Cmdlets / API :** `Get-CimInstance Win32_OperatingSystem`, `Get-CimInstance Win32_ComputerSystem`, `[System.Security.Principal.WindowsIdentity]::GetCurrent()`

**Données collectées :**

| Champ interne | Source | Description |
|---|---|---|
| `Hostname` | `$env:COMPUTERNAME` | Nom NetBIOS de la machine |
| `Domaine` | `$CS.Domain` / `$CS.Workgroup` | Domaine AD ou groupe de travail |
| `OS` | `$OS.Caption` | Nom complet de l'OS (ex. `Windows 11 Pro`) |
| `Build` | `$OS.BuildNumber` | Numéro de build Windows (ex. `22631`) |
| `Version` | `$OS.Version` | Version complète (ex. `10.0.22631`) |
| `Architecture` | `$OS.OSArchitecture` | `64 bits` ou `32 bits` |
| `Uptime` | `New-TimeSpan -Start $OS.LastBootUpTime` | Durée depuis le dernier démarrage, format `dd'd 'hh'h 'mm'm'` |
| `DernierBoot` | `$OS.LastBootUpTime` | Date/heure du dernier démarrage `yyyy-MM-dd HH:mm:ss` |
| `Utilisateur` | `$env:USERDOMAIN\$env:USERNAME` | Compte courant |
| `SID` | `WindowsIdentity::GetCurrent().User.Value` | SID du compte courant (masqué en PUBLIC) |
| `EstAdmin` | `WindowsPrincipal.IsInRole(Administrator)` | Booléen élévation |
| `PSVersion` | `$PSVersionTable.PSVersion` | Version PowerShell complète |
| `PSEdition` | `$PSVersionTable.PSEdition` | `Desktop` ou `Core` |

**Fallback :** chaque propriété CIM est wrappée dans `Set-Safe-Get {}`. Si `Get-CimInstance` échoue (WMI indisponible), toutes les propriétés dépendantes retournent `'N/A'`.

---

## 8. Module 02 — Interfaces réseau

**Cmdlets :** `Get-NetAdapter`, `Get-NetIPConfiguration`, `Get-NetIPInterface`

**Périmètre :** uniquement les interfaces avec `Status -eq 'Up'`.

**Données collectées par interface :**

| Champ | Source | Détail |
|---|---|---|
| `Nom` | `$Adapter.Name` | Nom Windows de l'adaptateur (ex. `Ethernet`, `Wi-Fi`) |
| `Description` | `$Adapter.InterfaceDescription` | Description complète du pilote |
| `MAC` | `$Adapter.MacAddress` | Adresse physique |
| `IP` | `Get-NetIPConfiguration.IPv4Address` | Première IPv4 hors APIPA (`169.x.x.x` exclus par regex `^169\.`) |
| `Masque` | `IPAddress.PrefixLength` | Longueur de préfixe CIDR (ex. `24`) |
| `Passerelle` | `IPv4DefaultGateway.NextHop` | Gateway par défaut |
| `DNS` | `DNSServer` (`AddressFamily -eq 2` = IPv4) | Serveurs DNS joints par `, ` |
| `DHCP` | `NetIPv4Interface.Dhcp` | `DHCP` ou `Statique` |
| `Vitesse` | `$Adapter.LinkSpeed` | Vitesse négociée (ex. `1 Gbps`) |
| `Type` | Regex sur `InterfaceDescription` | `Physique` ou `⚠️ Virtuel/VPN` |
| `MTU` | `Get-NetIPInterface.NlMtu` | MTU de l'interface IPv4 |
| `Statut` | `$Adapter.Status` | `Up` (toujours, par construction du filtre) |

**Détection virtuel/VPN :** regex `'Hyper-V|VMware|VirtualBox|TAP|Loopback|Miniport|WAN|VPN|Tunnel'` appliqué sur `InterfaceDescription`.

**En mode PUBLIC :** IP, passerelle, DNS masqués via `SET-Mask-IP`, MAC via `Set-Mask-MAC`.

---

## 9. Module 03 — Profils réseau

**Cmdlet :** `Get-NetConnectionProfile`

**Données collectées :**

| Champ | Source |
|---|---|
| `Interface` | `InterfaceAlias` |
| `Nom` | `Name` (nom réseau détecté par Windows) |
| `Profil` | `NetworkCategory` : `Public`, `Private`, `Domain` |
| `IPv4` | `IPv4Connectivity` |
| `IPv6` | `IPv6Connectivity` |
| `Risque` | Calculé : `Public` → `CRITICAL`, `Private`/`Domain` → `OK` |

**Importance pour le diagnostic SMB :** le partage de fichiers Windows est bloqué par le pare-feu sur le profil `Public`. C'est l'une des causes d'échec les plus fréquentes sur les réseaux domestiques ou Wi-Fi inconnus. Le moteur d'analyse génère un finding `CRITICAL` si une interface active est sur profil `Public`.

---

## 10. Module 04 — Lecteurs mappés et historique MRU

Ce module collecte trois sources distinctes.

### 4a — Lecteurs mappés actifs (session courante)

**Cmdlet :** `Get-PSDrive -PSProvider FileSystem`

Filtre : `DisplayRoot -like '\\*'` (uniquement les lecteurs réseau UNC).

| Champ | Source |
|---|---|
| `Lecteur` | `$_.Name` (lettre du lecteur, ex. `Z`) |
| `Cible` | `$_.DisplayRoot` (chemin UNC complet) |
| `Utilise` | `$_.Used / 1GB` arrondi à 2 décimales + ` Go` |
| `Libre` | `$_.Free / 1GB` arrondi à 2 décimales + ` Go` |

### 4b — Lecteurs persistants (HKCU:\Network)

**Source :** registre `HKCU:\Network`

Chaque sous-clé correspond à une lettre de lecteur persistant configuré. Propriétés lues :

| Propriété registre | Champ |
|---|---|
| `RemotePath` | `Cible` |
| `ProviderName` | `Fournisseur` |
| `UserName` | `Utilisateur` |

Ces entrées existent même quand le lecteur n'est pas connecté (reconnexion différée au prochain logon).

### 4c — Historique MRU (Map Network Drive)

**Sources registre :**

```
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Network\Persistent Connections
```

Toutes les propriétés non-PS (filtre `$_.Name -notmatch '^PS'`) sont lues. Ces clés conservent l'historique des partages accédés même après déconnexion ou redémarrage.

**En mode PUBLIC :** le segment `\\HOSTNAME` de chaque chemin UNC est remplacé par `\\***` via `-replace '\\\\[^\\]+','\\***'`.

---

## 11. Module 05 — Configuration SMB Serveur

**Cmdlet :** `Get-SmbServerConfiguration`

Requiert des droits administrateur. En cas d'échec, le module produit une ligne d'erreur avec `Risque = 'WARN'` et continue sans interrompre le script.

**Paramètres collectés :**

| Paramètre affiché | Propriété objet | Risque si état dégradé |
|---|---|---|
| SMBv1 (Serveur) | `EnableSMB1Protocol` | `CRITICAL` si `$true` |
| SMBv2/v3 (Serveur) | `EnableSMB2Protocol` | `CRITICAL` si `$false` |
| Signature requise | `RequireSecuritySignature` | `WARN` si `$false` |
| Signature activée | `EnableSecuritySignature` | `WARN` si `$false` |
| Chiffrement SMB3 | `EncryptData` | `INFO` si `$false` |
| Protocole Maximum | `MaxProtocol` | `INFO` |
| Protocole Minimum | `MinProtocol` | `CRITICAL` si valeur `SMB1` |
| Déconnexion auto (min) | `AutoDisconnectTimeout` | `INFO` |
| Sessions null (pipes) | `NullSessionPipes` | `INFO` |
| Partages null | `NullSessionShares` | `INFO` |

**Logique de risque SMBv1 :** `EnableSMB1Protocol = $true` génère un finding `CRITICAL` dans le moteur d'analyse avec la commande de correction :
```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

**Logique de risque signature :** `EnableSecuritySignature = $false` génère un finding `WARN`. Sans signature SMB, les attaques NTLM relay (Responder + ntlmrelayx) sont possibles si l'attaquant est en position MITM sur le segment.

---

## 12. Module 06 — Configuration SMB Client

**Cmdlet principal :** `Get-SmbClientConfiguration`

**Fallback registre :** si `Get-SmbClientConfiguration` échoue (droits insuffisants ou module SMB non disponible), le script lit directement :

```
HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
```

Propriétés lues depuis le registre en fallback :

```
RequireSecuritySignature
EnableSecuritySignature
MaxProtocol
MinProtocol
SessionTimeout
DirectoryCacheLifetime
FileInfoCacheLifetime
WindowSizeThreshold
```

**Paramètres collectés (cmdlet ou registre) :**

| Paramètre affiché | Propriété | Risque |
|---|---|---|
| Signature requise (Client) | `RequireSecuritySignature` | `WARN` si `$false` |
| Signature activée (Client) | `EnableSecuritySignature` | `WARN` si `$false` |
| Protocole Max (Client) | `MaxProtocol` | `INFO` |
| Protocole Min (Client) | `MinProtocol` | `CRITICAL` si valeur `SMB1` |
| Délai session (s) | `SessionTimeout` | `INFO` |
| Cache répertoire (s) | `DirectoryCacheLifetime` | `INFO` |
| Cache entrées fichier (s) | `FileInfoCacheLifetime` | `INFO` |
| Windows Large Reads | `WindowSizeThreshold` | `INFO` |

La source utilisée (cmdlet vs registre) est annotée dans la colonne `Note` du tableau HTML avec la mention `(source: registre)`.

---

## 13. Module 07 — Partages SMB

**Cmdlets :** `Get-SmbShare`, `Get-SmbShareAccess`, `Get-SmbShareConfiguration`

Pour chaque partage retourné par `Get-SmbShare` :

| Champ | Source | Détail |
|---|---|---|
| `Nom` | `$_.Name` | Nom du partage (ex. `ADMIN$`, `C$`, `Docs`) |
| `Chemin` | `$_.Path` | Chemin local (ex. `C:\Users\Public\Documents`) |
| `Description` | `$_.Description` | Description textuelle du partage |
| `Type` | `$_.Special` | `Systeme` (partages `$`) ou `Utilisateur` |
| `Permissions` | `Get-SmbShareAccess` | Format `Compte:Droit` joints par ` \| ` |
| `ABE` | `Get-SmbShareConfiguration.FolderEnumerationMode` | `Actif` si `AccessBased`, sinon `Inactif` |
| `Cache_HS` | `Get-SmbShareConfiguration.CachingMode` | Mode de cache hors ligne (`Manual`, `None`, `Documents`, `Programs`, `BranchCache`) |
| `MaxUtilisateurs` | `$_.MaximumAllowed` | `Illimite` si `[uint32]::MaxValue` ou `$null` |
| `Disponibilite` | `$_.ContinuouslyAvailable` | `Oui`/`Non` (CA — Continuously Available pour Scale-out/Cluster) |

**ABE (Access-Based Enumeration) :** quand activé (`FolderEnumerationMode = AccessBased`), les utilisateurs ne voient que les éléments auxquels ils ont accès. Son absence sur les partages multi-utilisateurs est un vecteur de fuite d'information.

---

## 14. Module 08 — Sessions SMB actives

**Cmdlet :** `Get-SmbSession`

Requiert des droits administrateur. Retourne les connexions **entrantes** actives vers le serveur SMB local.

| Champ | Source | Mode PUBLIC |
|---|---|---|
| `Client` | `ClientComputerName` | IP masquée via `SET-Mask-IP` |
| `Utilisateur` | `ClientUserName` | Partie domaine remplacée par `***\` |
| `Dialecte` | `Dialect` | Version SMB négociée (ex. `3.1.1`, `2.1`, `2.0.2`) |
| `Signe` | `IsSigned` | Booléen — signature active sur cette session |
| `Chiffre` | `IsEncrypted` | Booléen — chiffrement SMB3 actif sur cette session |
| `Duree_s` | `SecondsExists` | Durée en secondes depuis l'établissement de la session |

---

## 15. Module 09 — Connexions SMB actives

**Cmdlet :** `Get-SmbConnection`

Retourne les connexions **sortantes** — partages distants auxquels la machine locale accède en tant que client SMB.

| Champ | Source | Mode PUBLIC |
|---|---|---|
| `Serveur` | `ServerName` | Masqué via `Set-Mask-Host` |
| `Partage` | `ShareName` | Segment après `\\SERVEUR` remplacé par `***` via regex |
| `Dialecte` | `Dialect` | Version du protocole SMB négociée |
| `Signe` | `IsSigned` | Booléen |
| `Chiffre` | `IsEncrypted` | Booléen |
| `Utilisateur` | `UserName` | Remplacé par `***` en PUBLIC |

---

## 16. Module 10 — Historique connexions réseau (7 jours)

### 10a — Journaux de sécurité Windows

**Cmdlet :** `Get-WinEvent`

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    StartTime = (Get-Date).AddDays(-7)
    Id        = @(5140, 5142, 5143, 5144)
} -MaxEvents 150
```

| Event ID | Signification |
|---|---|
| `5140` | Un objet réseau partagé a été accédé |
| `5142` | Un objet réseau partagé a été créé |
| `5143` | Un objet réseau partagé a été modifié |
| `5144` | Un objet réseau partagé a été supprimé |

**Extraction des champs depuis `$_.Message` par regex :**

- IP source : `(?:Adresse réseau source|Source Address)\s*:\s*(\S+)`
- Nom du partage : `(?:Nom du partage|Share Name)\s*:\s*(\S+)`
- Compte : `(?:Nom du compte|Account Name)\s*:\s*(\S+)`

Le double regex (français/anglais) gère les deux localisations Windows courantes.

**Droits requis :** journal `Security` inaccessible sans élévation. En cas d'échec du `Get-WinEvent`, une ligne unique avec `TypeEvenemt = 'Acces admin requis'` est retournée à la place du tableau.

### 10b — Connexions actives `net use`

**Binaire :** `& net use 2>$null`

Les lignes contenant `\\` sont parsées avec `-split '\s{2,}'` pour extraire `Statut`, `Local` (lettre de lecteur) et `Distant` (chemin UNC).

---

## 17. Module 11 — Pare-feu Windows

### 11a — Profils pare-feu

**Cmdlet :** `Get-NetFirewallProfile`

| Champ | Source |
|---|---|
| `Profil` | `Name` : `Domain`, `Private`, `Public` |
| `Active` | `Enabled` |
| `EntreeDefaut` | `DefaultInboundAction` : `Allow`/`Block`/`NotConfigured` |
| `SortieDefaut` | `DefaultOutboundAction` |
| `LogAutorise` | `LogAllowed` : `True`/`False` |
| `LogBloque` | `LogBlocked` : `True`/`False` |
| `Risque` | `WARN` si `Enabled = $false`, sinon `OK` |

### 11b — Règles pare-feu actives (SMB/Partage)

**Cmdlets :** `Get-NetFirewallRule`, `Get-NetFirewallPortFilter`

**Filtre :** règles avec `Enabled = $true` et l'une des conditions suivantes :
- `DisplayName` matche regex `'SMB|File|Share|Network Discovery|NetBIOS|Partage|Fichiers'`
- Direction `Inbound` avec port local dans `@(445, 139, 137, 138)`

| Champ | Source |
|---|---|
| `Nom` | `DisplayName` |
| `Direction` | `Direction` : `Inbound`/`Outbound` |
| `Action` | `Action` : `Allow`/`Block` |
| `Profil` | `Profile` : `Domain`, `Private`, `Public`, `Any` |
| `Protocole` | `Get-NetFirewallPortFilter.Protocol` |
| `Port` | `Get-NetFirewallPortFilter.LocalPort` |
| `Active` | `Enabled` |
| `Risque` | `WARN` si `Action = Block` et `Direction = Inbound` |

**Ports SMB analysés :**

| Port | Protocole | Usage |
|---|---|---|
| 445 | TCP | SMB direct (Windows 2000+) |
| 139 | TCP | SMB sur NetBIOS Session Service |
| 137 | UDP | NetBIOS Name Service (NBNS) |
| 138 | UDP | NetBIOS Datagram Service |

---

## 18. Module 12 — Politique d'authentification

### 12a — Clés de registre d'authentification

**Chemins lus :**

```
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
```

**Paramètres analysés :**

| Clé | Chemin registre | Valeur recommandée | Risque si mauvaise valeur |
|---|---|---|---|
| `LmCompatibilityLevel` | `Lsa` | `5` | `CRITICAL` si `< 3`, `WARN` si non défini |
| `RestrictAnonymous` | `Lsa` | `1` | `WARN` si `0` |
| `RestrictAnonymousSAM` | `Lsa` | `1` | `WARN` si `0` |
| `LocalAccountTokenFilterPolicy` | `Policies\System` | `1` | `WARN` si `!= 1` |
| `NoLMHash` | `Lsa` | `1` | `WARN` si `!= 1` |
| `EnableLUA` | `Policies\System` | `1` | `WARN` si `0` |
| `NTLMMinClientSec` | `MSV1_0` | `537395200` | `INFO` |
| `NTLMMinServerSec` | `MSV1_0` | `537395200` | `INFO` |

**`LmCompatibilityLevel` — détail des valeurs :**

| Valeur | Comportement | Risque |
|---|---|---|
| `0` | LM et NTLMv1 envoyés | CRITICAL |
| `1` | NTLMv2 si demandé, sinon LM/NTLMv1 | CRITICAL |
| `2` | NTLMv2 uniquement côté client | CRITICAL |
| `3` | NTLMv2 uniquement (client) | WARN |
| `4` | NTLMv2 + refus LM côté serveur | WARN |
| `5` | NTLMv2 uniquement, refus LM/NTLMv1 côté serveur | OK (recommandé) |

**`NTLMMinClientSec` / `NTLMMinServerSec` = 537395200 (0x20080000) :**

Ce flag est la combinaison de `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` (0x00080000) + `NTLMSSP_NEGOTIATE_128` (0x20000000). Il impose NTLMv2 et chiffrement 128 bits.

### 12b — Comptes locaux

**Cmdlet :** `Get-LocalUser`

| Champ | Source | Risque |
|---|---|---|
| `Nom` | `Name` (tronqué en PUBLIC : 3 chars + `***`) | — |
| `Active` | `Enabled` | — |
| `DernConnexion` | `LastLogon` (format `yyyy-MM-dd HH:mm`) | — |
| `MdpRequis` | `[bool]$_.PasswordLastSet` | `CRITICAL` si compte actif et `$false` |
| `MdpExpire` | `PasswordExpires` | — |
| `SID` | `SID.Value` | Masqué en PUBLIC |

### 12c — Gestionnaire de credentials

**Binaire :** `& cmdkey /list 2>$null`

Les lignes contenant `Target` ou `Cible` sont parsées pour extraire les cibles stockées. Le type est déduit : `Reseau` si la cible contient `\\`, sinon `Generique`.

---

## 19. Module 13 — Services et protocoles de découverte

### 13a — Services Windows

**Cmdlet :** `Get-Service -Name <nom>`

**15 services analysés :**

| Nom service | Libellé affiché | Risque si `Status != Running` |
|---|---|---|
| `LanmanServer` | Serveur SMB (LanmanServer) | CRITICAL |
| `LanmanWorkstation` | Client SMB (Workstation) | CRITICAL |
| `MrxSmb` | Mini-redirecteur SMB | WARN |
| `Browser` | Explorateur réseau (Computer Browser) | INFO |
| `FDResPub` | Publication ressources (FDResPub) | WARN |
| `SSDPSRV` | Découverte SSDP | WARN |
| `upnphost` | Hôte périphérique UPnP | INFO |
| `Dnscache` | Client DNS | WARN |
| `WinRM` | Gestion à distance Windows | INFO |
| `NlaSvc` | Détection réseau (NLA) | WARN |
| `netlogon` | Ouverture de session réseau | INFO |
| `mpsdrv` | Pilote Pare-feu Windows | WARN |
| `BFE` | Moteur de filtrage de base | CRITICAL |
| `mpssvc` | Service Pare-feu Windows | WARN |
| `Spooler` | Spouleur impression | INFO |

**Logique de niveau de risque du moteur d'analyse :**
- Service marqué `CRITICAL` dans la table + statut `!= Running` → finding `CRITICAL`
- Service marqué `WARN` dans la table + statut `!= Running` → finding `WARN`
- Service introuvable → `INFO` (service peut être absent selon l'édition Windows)

### 13b — Protocoles de découverte réseau

| Protocole | Source de l'état | Risque |
|---|---|---|
| LLMNR | `HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast` | `WARN` si `!= '0'` |
| NetBIOS over TCP/IP | `Get-WmiObject Win32_NetworkAdapterConfiguration.TcpipNetbiosOptions` | INFO |
| mDNS | Présumé actif par défaut (pas de lecture registre) | INFO |
| WSD | Statut service `FDResPub` | INFO |

**LLMNR :** si `EnableMulticast` n'est pas défini à `0`, LLMNR est actif. Un attaquant sur le même segment peut répondre aux requêtes LLMNR non résolues avec Responder et capturer des hashes NTLMv2. Le moteur d'analyse génère un finding `WARN`.

**NetBIOS `TcpipNetbiosOptions` — valeurs :**

| Valeur | Signification |
|---|---|
| `0` | Par défaut (via DHCP) |
| `1` | NetBIOS activé |
| `2` | NetBIOS désactivé |

---

## 20. Module 14 — Journal d'événements (24 h)

**Cmdlet :** `Get-WinEvent`

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = @('Security', 'System', 'Application')
    StartTime = (Get-Date).AddHours(-24)
    Id        = @(4625, 4648, 4776, 5140, 5145, 7036, 7045)
} -MaxEvents 200
```

**Event IDs collectés :**

| Event ID | Journal | Signification | Catégorie affichée |
|---|---|---|---|
| `4625` | Security | Échec d'ouverture de session | Echec auth. |
| `4648` | Security | Ouverture de session avec credentials explicites | Session explicite |
| `4776` | Security | Validation de credentials NTLM (DC ou local) | Auth. NTLM |
| `5140` | Security | Accès à un partage réseau | Acces partage |
| `5145` | Security | Vérification d'accès à un objet partagé (audit détaillé) | Acces objet partage |
| `7036` | System | Changement d'état d'un service (démarré/arrêté) | Etat service |
| `7045` | System | Nouveau service installé dans le système | Nouveau service |

**Champs extraits :**

| Champ | Source |
|---|---|
| `Horodatage` | `TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')` |
| `Journal` | `LogName` |
| `EventID` | `Id` |
| `Niveau` | `LevelDisplayName` |
| `Source` | `ProviderName` |
| `Message` | `Message` tronqué à 200 chars via `[Math]::Min(200, ...)`, sauts de ligne remplacés par espaces |

**Droits requis :** journal `Security` inaccessible sans élévation. Un seul objet fictif est retourné en cas d'accès refusé (`Source = 'Droits admin requis'`).

---

## 21. Module 15 — Table ARP

**Binaire :** `& arp -a 2>$null`

Les lignes commençant par un espace suivi d'un chiffre (entrées IP, regex `^\s+\d`) sont parsées par `-split '\s+'` :

| Index | Champ | Mode PUBLIC |
|---|---|---|
| `[0]` | IP | Masquée via `SET-Mask-IP` |
| `[1]` | MAC | Remplacée par `XX:XX:XX:XX:XX:XX` |
| `[2]` | Type | `dynamic`, `static` — retourné tel quel |

Les adresses `224.x.x.x` (multicast), `255.x.x.x` (broadcast) et `169.x.x.x` (APIPA) sont présentes dans la table ARP mais exclues de la liste des voisins pour les tests de connectivité (module 17).

---

## 22. Module 16 — Fichier Hosts

**Source :** `$env:SystemRoot\System32\drivers\etc\hosts`

Les lignes sont filtrées pour exclure :
- Commentaires : regex `^\s*#`
- Lignes vides ou ne contenant que des espaces : `-match '\S'`

Les lignes valides sont parsées par `-split '\s+'` :

| Index | Champ |
|---|---|
| `[0]` | IP (`SET-Mask-IP` en PUBLIC) |
| `[1]` | Hostname (`Set-Mask-Host` en PUBLIC) |
| `[2..n]` | Note (commentaire inline éventuel, joint par espace) |

---

## 23. Module 17 — Tests de connectivité

Ce module construit dynamiquement une liste de cibles depuis deux sources :

1. **Table ARP** : entrées `dynamic` dont l'IP ne matche pas `^(224\.|255\.|169\.)` — voisins physiques sur le segment local.
2. **Sessions SMB** : `ClientComputerName` des sessions actives — machines actuellement connectées.

Les listes sont fusionnées, dédupliquées (`Sort-Object -Unique`) et limitées à **10 cibles maximum** (`Select-Object -First 10`).

**Tests réalisés pour chaque cible :**

### Test 1 — Ping ICMP

```powershell
Test-Connection -ComputerName $Target -Count 1 -Quiet
```

Retourne `$true`/`$false`.

### Test 2 — Port TCP 445

```powershell
Test-NetConnection -ComputerName $Target -Port 445 -InformationLevel Quiet -WarningAction SilentlyContinue
```

Retourne `$true`/`$false`.

### Test 3 — Accès UNC IPC$

```powershell
[System.IO.Directory]::GetDirectories("\\$Target\IPC$")
```

Tenté uniquement si le test Port 445 réussit. `IPC$` est le partage Inter-Process Communication utilisé pour les connexions authentifiées SMB initiales. En cas de succès, retourne `'OK'`. En cas d'exception, retourne le message d'erreur tronqué à 60 caractères.

**Logique du résultat global (`Resultat`) :**

| Ping | Port 445 | UNC IPC$ | Résultat |
|---|---|---|---|
| OK | Ouvert | OK | `OK` |
| OK | Ouvert | Erreur | `WARN` |
| OK | Fermé | — | `WARN` |
| Échec | — | — | `CRITICAL` |

**Fallback :** si aucun voisin n'est détecté (réseau isolé, ARP vide, aucune session SMB), le tableau de tests est vide — aucune erreur n'est générée.

---

## 24. Moteur d'analyse et recommandations

Après la collecte complète, le script évalue 11 règles séquentiellement et accumule les résultats dans le tableau `$Findings` (objets `PSCustomObject` avec champs `Severite`, `Categorie`, `Constat`, `Detail`, `Correction`).

### Règle 1 — SMBv1 activé côté serveur

**Condition :** `$SMBv1Server -eq $true`

**Correction proposée dans le rapport :**
```powershell
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

### Règle 2 — SMBv2/v3 désactivé côté serveur

**Condition :** `-not $SMBv2Server`

**Correction proposée :**
```powershell
Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
```

### Règle 3 — Interface sur profil réseau PUBLIC

**Condition :** pour chaque entrée `$NetProfiles` avec `Profil -eq 'Public'`

**Correction proposée (dynamique, intègre le nom de l'interface) :**
```powershell
Set-NetConnectionProfile -InterfaceAlias '<Interface>' -NetworkCategory Private
```

### Règle 4 — LmCompatibilityLevel trop bas

**Condition :** `$LmLevel -ne 'NON DÉFINI' -and [int]$LmLevel -lt 3`

**Correction proposée :**
```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel -Value 5
```

### Règle 5 — LocalAccountTokenFilterPolicy absent ou != 1

**Condition :** `$LATFP -ne '1'`

**Correction proposée :**
```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWORD -Force
```

### Règle 6 — Profil pare-feu désactivé

**Condition :** pour chaque `$FWProfiles` avec `Active = $false`

**Correction proposée :**
```powershell
Set-NetFirewallProfile -Profile <Profil> -Enabled True
```

### Règle 7 — Service CRITICAL arrêté

**Condition :** pour chaque `$ServicesData` avec `Statut != 'Running'` et `Risque = 'CRITICAL'`

**Correction proposée :**
```powershell
Start-Service -Name <Nom>
```

### Règle 8 — Signature SMB désactivée côté serveur

**Condition :** `$SMBServerConfig -and -not $SMBServerConfig.EnableSecuritySignature`

**Correction proposée :**
```powershell
Set-SmbServerConfiguration -EnableSecuritySignature $true -Force
```

### Règle 9 — Compte local actif sans mot de passe requis

**Condition :** pour chaque `$LocalAccounts` avec `Active = $true` et `MdpRequis = $false`

**Correction proposée :**
```powershell
Set-LocalUser -Name '<Nom>' -PasswordRequired $true
```

### Règle 10 — LLMNR activé

**Condition :** `$LLMNRVal -ne '0'`

**Correction proposée :**
```powershell
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name EnableMulticast -Value 0
```

### Règle 11 — Cibles injoignables (test connectivité)

**Condition :** pour chaque `$ConnTests` avec `Resultat = 'CRITICAL'`

Génère un finding `WARN` (pas `CRITICAL`) car l'indisponibilité d'une cible peut être normale.

### Aucun problème détecté

Si `$Findings.Count -eq 0` après toutes les règles, un finding `OK` générique est inséré pour que le tableau ne soit pas vide dans le rapport.

---

## 25. Calcul du score de santé

```powershell
$CriticalCount = ($Findings | Where-Object { $_.Severite -eq 'CRITICAL' }).Count
$WarnCount     = ($Findings | Where-Object { $_.Severite -eq 'WARN' }).Count
$Score         = [Math]::Max(0, 100 - ($CriticalCount * 20) - ($WarnCount * 5))
```

**Barème de pénalités :**
- Chaque finding `CRITICAL` : -20 points
- Chaque finding `WARN` : -5 points
- Score minimum forcé à 0 via `[Math]::Max`

**Seuils d'interprétation :**

| Score | Statut | Couleur CSS |
|---|---|---|
| 80–100 | Sain | `#22c55e` |
| 50–79 | Dégradé | `#f59e0b` |
| 0–49 | Critique | `#ef4444` |

**Exemples :**

| Critiques | Warnings | Score | Statut |
|---|---|---|---|
| 0 | 0 | 100 | Sain |
| 0 | 4 | 80 | Sain |
| 1 | 2 | 70 | Dégradé |
| 2 | 3 | 45 | Critique |
| 5 | 0 | 0 | Critique |

---

## 26. Rapport HTML — structure et comportement

### Génération

Le rapport est construit par concaténation dans la variable `$HTML` via un here-string PowerShell (`@" ... "@`). Le fichier est écrit avec :

```powershell
[System.IO.File]::WriteAllText($OutputFile, $HTML, [System.Text.Encoding]::UTF8)
```

L'encodage UTF-8 sans BOM est utilisé (`System.Text.Encoding::UTF8`). Le HTML est un document complet et autonome — aucune ressource externe n'est chargée (pas de CDN, pas de polices web, pas d'images distantes).

### Contenu du fichier HTML

1. Bloc CSS embarqué dans `<style>` — environ 120 déclarations utilisant des variables CSS custom (`--bg`, `--surface`, `--text`, `--accent`, `--ok`, `--warn`, `--critical`, `--info`, `--radius`, `--font`)
2. Topbar sticky avec titre, badge de mode, boutons d'action globaux
3. Barre de navigation sticky (tabs, défilement horizontal sur petits écrans)
4. Tableau de bord (8 cards + barre de score animée)
5. Barre de filtres globaux par sévérité
6. 15 sections collapsibles (générées par `Build-Section()`)
7. Pied de page avec métadonnées de génération
8. Bloc JavaScript embarqué dans `<script>`

### Fonctions `Build-Table()` et `Build-Section()`

#### `Build-Table`

```powershell
function Build-Table {
    param([string]$ID, [array]$Data, [string[]]$Columns, [string]$RiskColumn = 'Risque')
}
```

- Génère un `<table id="$ID">` avec div wrapper et barre d'outils
- En-têtes cliquables : `onclick="sortTable(this, '$ID')"`
- Champ de filtre texte : `oninput="filterTable(this, '$ID')"`
- Bouton export CSV : `onclick="exportCSV('$ID')"`
- Colorisation des lignes selon `$RiskColumn` : `row-critical`, `row-warn`, `row-ok`
- Les colonnes `Risque` et `Severite` sont rendues via `Get-StatusBadge()` (badges HTML colorés)
- Toutes les autres valeurs passent par `HtmlEncode()` avant insertion

#### `Build-Section`

```powershell
function Build-Section {
    param([string]$ID, [string]$Title, [string]$Icon, [string]$Content, [string]$BadgeCount = '')
}
```

Génère un `<section id="sec-$ID">` avec header cliquable `onclick="toggleSection('$ID')"` et body `id="body-$ID"` basculant la classe CSS `hidden`.

### Fonctionnalités JavaScript embarquées

#### Tri de tableau — `sortTable(th, tableId)`

- Récupère l'index de la colonne par `Array.from(th.parentNode.children).indexOf(th)`
- Trie les `<tr>` du `<tbody>` par `textContent` avec `localeCompare` (locale `fr`, option `numeric: true`)
- Bascule `th.dataset.sort` entre `'asc'` et `'desc'`

#### Filtre par tableau — `filterTable(input, tableId)`

- Masque (`display: none`) les lignes dont `row.textContent.toLowerCase()` ne contient pas la valeur saisie

#### Export CSV — `exportCSV(tableId)`

- Extrait toutes les cellules `<th>` et `<td>`
- Entoure chaque valeur de `"`, échappe les guillemets internes en `""`
- Préfixe le contenu par BOM UTF-8 (`\uFEFF`) pour compatibilité Excel
- Téléchargement via `URL.createObjectURL(new Blob(...))` + clic simulé sur `<a href>`
- Nom du fichier : `<tableId>_<COMPUTERNAME>_<yyyyMMdd>.csv`

#### Filtre global par sévérité — `filterSections(level, btn)`

- Affiche uniquement les lignes avec classe CSS correspondante (`row-critical`, `row-warn`, `row-ok`)
- Appelle `expandAll()` automatiquement pour rendre les lignes visibles

#### Thème — `toggleTheme()`

- Bascule la classe `light` sur `<body>`
- Persiste l'état dans `localStorage` (clé `theme`)
- Restauré au chargement : `if(localStorage.getItem('theme')==='light') document.body.classList.add('light')`

#### Barre de score animée

```javascript
window.addEventListener('load', function() {
    var f = document.getElementById('scoreFill');
    if (f) {
        var t = f.dataset.target;
        setTimeout(function() { f.style.width = t + '%'; }, 150);
    }
});
```

La valeur cible est injectée dans `data-target="$Score"` lors de la génération PowerShell.

---

## 27. Fonctions utilitaires internes

### `Set-Safe-Get { block } $default`

```powershell
function Set-Safe-Get {
    param([scriptblock]$Block, $Default = $null)
    try { return (& $Block) }
    catch { return $Default }
}
```

Enveloppe un scriptblock dans un `try/catch`. Retourne `$default` en cas d'exception. Utilisé sur tous les appels cmdlet susceptibles d'échouer sans droits admin ou en cas d'indisponibilité de module.

### `Set-Safe-String $value $default`

Retourne `$default` (défaut : `'N/A'`) si `$value` est `$null` ou chaîne vide. Utilisé pour normaliser les propriétés optionnelles.

### `HtmlEncode $string`

```powershell
function HtmlEncode { param([string]$s)
    $s = $s -replace '&','&amp;'
    $s = $s -replace '<','&lt;'
    $s = $s -replace '>','&gt;'
    $s = $s -replace '"','&quot;'
    return $s
}
```

Appliqué sur toutes les valeurs de cellules avant injection dans le HTML via `Build-Table`.

### `Get-RegValue $Path $Name`

```powershell
function Get-RegValue { param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return 'NON DÉFINI' }
}
```

Retourne `'NON DÉFINI'` si la clé ou la valeur n'existe pas.

### `Write-Step $message`

```powershell
Write-Host "  → $message" -ForegroundColor DarkCyan
```

Affichage de progression dans la console pendant la collecte.

### `Get-StatusBadge $status`

| Valeur | HTML retourné |
|---|---|
| `OK` | `<span class="badge ok">✅ OK</span>` |
| `WARN` | `<span class="badge warn">⚠️ AVERT.</span>` |
| `CRITICAL` | `<span class="badge critical">❌ CRITIQUE</span>` |
| `INFO` | `<span class="badge info">ℹ️ INFO</span>` |
| autre | `<span class='badge info'>{valeur}</span>` |

---

## 28. Système de masquage (Mode PUBLIC)

Quatre fonctions de masquage sont appliquées **à la collecte**, pas à l'affichage.

### `SET-Mask-IP $IP`

Condition : `$Mode -eq 'PUBLIC'` et regex `^\d+\.\d+\.\d+\.\d+$`

```
192.168.1.42   →  192.168.x.xxx
10.0.50.100    →  10.0.x.xxx
```

Les deux premiers octets sont conservés, les deux derniers remplacés par `x` et `xxx`.

### `Set-Mask-MAC $MAC`

Condition : `$Mode -eq 'PUBLIC'` (inconditionnellement)

```
AA:BB:CC:DD:EE:FF  →  XX:XX:XX:XX:XX:XX
```

### `Set-Mask-Host $hostname`

Condition : `$Mode -eq 'PUBLIC'` et valeur non vide ni `'N/A'`

```powershell
$hostname.Substring(0,3) + ('*' * [Math]::Min(5, $hostname.Length-3))
```

```
SERVEUR-PROD-01  →  SER*****
AB               →  ***        (moins de 3 chars → retourne '***')
```

### `Set-Mask-SID $SID`

Condition : `$Mode -eq 'PUBLIC'`

```
S-1-5-21-123456789-987654321-111111111-1001  →  S-1-5-***-***
```

### Masquages inline (non-fonctions)

Dans les modules de collecte, des `-replace` inline complètent le masquage :

| Contexte | Regex | Résultat |
|---|---|---|
| Chemins UNC | `'\\\\[^\\]+'` → `'\\***'` | `\\SERVEUR\Share` → `\\***\Share` |
| DNS (interfaces) | `'\d+\.\d+\.\d+\.\d+'` → `'x.x.x.x'` | `8.8.8.8` → `x.x.x.x` |
| Comptes (sessions) | `'^[^\\]+\\'` → `'***\'` | `DOMAINE\user` → `***\user` |

---

## 29. Registres Windows consultés

Le script lit (jamais n'écrit) les chemins registre suivants :

```
HKCU:\Network\*
    └─ RemotePath
    └─ ProviderName
    └─ UserName

HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
    └─ toutes les valeurs non-PS

HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Network\Persistent Connections
    └─ toutes les valeurs non-PS

HKLM:\SYSTEM\CurrentControlSet\Control\Lsa
    └─ LmCompatibilityLevel
    └─ RestrictAnonymous
    └─ RestrictAnonymousSAM
    └─ NoLMHash

HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
    └─ NTLMMinClientSec
    └─ NTLMMinServerSec

HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters
    └─ RequireSecuritySignature
    └─ EnableSecuritySignature
    └─ MaxProtocol
    └─ MinProtocol
    └─ SessionTimeout
    └─ DirectoryCacheLifetime
    └─ FileInfoCacheLifetime
    └─ WindowSizeThreshold

HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    └─ LocalAccountTokenFilterPolicy
    └─ EnableLUA

HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
    └─ EnableMulticast
```

---

## 30. Event IDs collectés

| Event ID | Journal | Fenêtre temporelle | `-MaxEvents` |
|---|---|---|---|
| 4625 | Security | 24 h | 200 |
| 4648 | Security | 24 h | 200 |
| 4776 | Security | 24 h | 200 |
| 5140 | Security | 24 h ET 7 jours | 200 (24h) + 150 (7j) |
| 5142 | Security | 7 jours | 150 |
| 5143 | Security | 7 jours | 150 |
| 5144 | Security | 7 jours | 150 |
| 5145 | Security | 24 h | 200 |
| 7036 | System | 24 h | 200 |
| 7045 | System | 24 h | 200 |

Les journaux `Security`, `System` et `Application` sont interrogés en une seule requête pour le module 14 (24h). Le module 10 interroge uniquement `Security` pour 7 jours. Les événements sont retournés du plus récent au plus ancien (comportement par défaut de `Get-WinEvent`).

---

## 31. Services Windows analysés

| Nom service | Exécutable | Rôle pour SMB |
|---|---|---|
| `LanmanServer` | `svchost.exe` (srv2.sys) | Expose les partages SMB en écoute sur TCP 445 |
| `LanmanWorkstation` | `svchost.exe` (mrxsmb.sys) | Redirecteur réseau — accès aux partages distants |
| `MrxSmb` | Pilote noyau `mrxsmb.sys` | Composant bas niveau du redirecteur SMB |
| `Browser` | `svchost.exe` | Élection du maître navigateur réseau (obsolète W10+) |
| `FDResPub` | `svchost.exe` | Publie les ressources pour la découverte réseau (WSD) |
| `SSDPSRV` | `svchost.exe` | Découverte SSDP/UPnP des équipements réseau |
| `upnphost` | `svchost.exe` | Hôte de périphériques UPnP |
| `Dnscache` | `svchost.exe` | Cache client DNS — résolution des noms de serveurs |
| `WinRM` | `svchost.exe` | PowerShell Remoting / WS-Management |
| `NlaSvc` | `svchost.exe` | Détecte le type de réseau → détermine le profil pare-feu |
| `netlogon` | `lsass.exe` | Authentification Kerberos/NTLM en environnement domaine |
| `mpsdrv` | Pilote noyau | Pilote du pare-feu Windows |
| `BFE` | `svchost.exe` | Base Filtering Engine — couche de filtrage pour pare-feu et IPsec |
| `mpssvc` | `svchost.exe` | Service pare-feu Windows (dépend de BFE) |
| `Spooler` | `spoolsv.exe` | Spouleur d'impression (PrintNightmare si exposé sans correctif) |

---

## 32. Nommage du fichier de sortie

```powershell
$FileName = "DiagReseau_${ModeDisplay}_$($env:COMPUTERNAME)_$($ScriptStartTime.ToString('yyyyMMdd_HHmmss')).html"
$OutputFile = Join-Path $OutputPath $FileName
```

Exemple :

```
C:\Temp\DiagReseau_COMPLET_DESKTOP-ABC123_20250315_142037.html
C:\Temp\DiagReseau_PUBLIC_SRV-FILE01_20250315_142037.html
```

---

## 33. Comportement en mode non-administrateur

Le script ne requiert pas l'élévation pour démarrer (`[CmdletBinding()]` sans `#Requires -RunAsAdministrator`). Les modules suivants retournent des données partielles ou des messages de substitution :

| Module | Comportement sans élévation |
|---|---|
| `Get-SmbServerConfiguration` | Exception → ligne `Erreur: Get-SmbServerConfiguration indisponible` avec `Risque = WARN` |
| `Get-SmbClientConfiguration` | Fallback vers `HKLM:\...\LanmanWorkstation\Parameters` (souvent lisible) → si échec aussi, ligne `Erreur` |
| `Get-SmbSession` | Retourne `@()` sans erreur |
| `Get-WinEvent` journal Security | Exception → objet unique `Source = 'Droits admin requis'` |
| Registre `HKLM:\SYSTEM\...\Lsa` | Généralement lisible sans admin en lecture |
| `Get-LocalUser` | Accessible sans admin |
| `cmdkey /list` | Accessible — liste uniquement les credentials du profil courant |

---

## 34. Limitations connues

**Tests de connectivité limités à 10 hôtes.** La liste est construite depuis le cache ARP et les sessions SMB actives. Sur un réseau sans session SMB et avec ARP vide, aucun test n'est effectué.

**Masquage IP conserve les deux premiers octets.** En mode PUBLIC, `192.168.x.xxx` préserve assez d'information pour identifier un sous-réseau /16. Des adresses publiques routables seraient partiellement exposées.

**Parsing `net use` fragile sur localisations non-testées.** La sortie texte de `net use` est parsée par `-split '\s{2,}'`. Des chemins UNC contenant des espaces multiples ou des localisations Windows inhabituelles peuvent produire un découpage incorrect.

**Regex journaux bilingues uniquement (FR/EN).** L'extraction depuis `$_.Message` couvre les localisations français et anglais. D'autres langues Windows (espagnol, allemand, japonais, etc.) retourneront `'N/A'` pour les champs extraits par regex.

**`Get-WmiObject Win32_NetworkAdapterConfiguration` déprécié.** Utilisé pour `TcpipNetbiosOptions` car `Get-CimInstance` ne retourne pas cette propriété de manière cohérente sur toutes les versions Windows. Sur PowerShell 7 avec remoting WMI via DCOM désactivé, cet appel peut échouer silencieusement (wrappé dans `Set-Safe-Get`).

**Score non pondéré par contexte.** Chaque finding `CRITICAL` enlève 20 points quel que soit son impact réel. Un service `LanmanServer` arrêté (partage SMB complètement non-fonctionnel) a le même poids qu'un compte local sans mot de passe requis.

**Rapport HTML non signé.** Si le fichier est ouvert depuis un chemin UNC (`\\SERVEUR\...`), certains navigateurs (Edge Legacy, IE) bloquent l'exécution du JavaScript embarqué (zone Intranet/Internet). Copier le fichier localement avant ouverture.

**`Set-StrictMode -Version Latest` actif.** Toute variable non initialisée dans une fonction sans `param` ou tout accès à une propriété inexistante lèvera une erreur. Ce mode est activé globalement et peut causer des comportements inattendus sur des versions PowerShell 5.1 spécifiques ou avec des objets retournant des propriétés dynamiques.

---

## 35. Dépannage

### Execution de scripts désactivée

```powershell
# Vérifier la politique
Get-ExecutionPolicy -List

# Débloquer ce seul fichier (NTFS Zone.Identifier)
Unblock-File -Path .\NetworkShareDiagnostic.ps1

# Bypass pour la session courante uniquement
powershell.exe -ExecutionPolicy Bypass -File .\NetworkShareDiagnostic.ps1 -Mode COMPLET
```

### `Get-SmbServerConfiguration` échoue même en admin

Le module `SmbShare` peut être absent ou le service `LanmanServer` est arrêté :

```powershell
Get-Module -ListAvailable SmbShare
Get-Service LanmanServer
# Windows Server :
Get-WindowsFeature FS-SMB1, FS-SMB2
```

### Le rapport s'écrit dans `%TEMP%` au lieu de `-OutputPath`

Le dossier cible n'a pas pu être créé. Vérifier les droits ou spécifier un chemin accessible :

```powershell
.\NetworkShareDiagnostic.ps1 -Mode COMPLET -OutputPath "$env:USERPROFILE\Desktop"
.\NetworkShareDiagnostic.ps1 -Mode COMPLET -OutputPath "$env:TEMP"
```

### Le rapport s'ouvre mais les tableaux sont vides / JavaScript inactif

Le navigateur a bloqué le JS embarqué (fichier ouvert depuis un partage réseau ou politique de sécurité locale). Ouvrir le fichier depuis `C:\` ou `%USERPROFILE%` dans Chrome ou Firefox.

### Aucun test de connectivité dans le rapport

Cache ARP vide et aucune session SMB active :

```powershell
arp -a                  # Vérifier le cache ARP
Get-SmbSession          # Vérifier les sessions actives (admin requis)
ping <ip_voisin>        # Peupler l'ARP, puis relancer le script
```

### `LmCompatibilityLevel` affiché comme `NON DÉFINI`

La clé n'est pas écrite explicitement dans le registre. Windows 10/11 applique la valeur par défaut `3` sans créer l'entrée. C'est un comportement attendu, signalé comme `WARN` car la valeur effective n'est pas vérifiable sans la clé.

Pour forcer la valeur et la rendre visible :

```powershell
# Exécuter en administrateur
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name LmCompatibilityLevel -Value 5 -Type DWord
```

### Le rapport ne s'ouvre pas automatiquement dans le navigateur

`Start-Process $OutputFile` utilise l'association de fichier `.html`. Sur les Windows Server sans navigateur installé, la commande échoue silencieusement. Le chemin complet du fichier est affiché dans la console.

### `$ErrorActionPreference = 'SilentlyContinue'` masque les erreurs

Le script supprime globalement les erreurs non critiques. Pour déboguer un module spécifique, modifier temporairement la ligne :

```powershell
$ErrorActionPreference = 'Continue'   # ou 'Stop' pour arrêt à la première erreur
```

---

## 36. Changelog

### v1.1.0

- Ajout du mode `PUBLIC` avec masquage systématique par fonctions dédiées (`SET-Mask-IP`, `Set-Mask-MAC`, `Set-Mask-Host`, `Set-Mask-SID`) et regex inline
- Ajout collecte lecteurs persistants depuis `HKCU:\Network`
- Ajout test UNC `IPC$` dans le module de connectivité (module 17)
- Ajout fallback registre `LanmanWorkstation\Parameters` pour `Get-SmbClientConfiguration`
- Moteur d'analyse étendu : règles LLMNR, comptes locaux sans mot de passe, `LocalAccountTokenFilterPolicy`, `EnableSecuritySignature`
- Rapport HTML : navigation par tabs sticky, barre de score animée (transition CSS 1s), export CSV avec BOM UTF-8, thème persistant `localStorage`
- Regex journaux bilingues FR/EN pour extraction depuis `$_.Message`
- Ajout sections Sessions SMB et Connexions SMB dans le rapport
- Ajout collecte `cmdkey /list` pour le gestionnaire de credentials

### v1.0.0

- Version initiale : collecte SMB serveur/client, interfaces réseau, pare-feu, authentification NTLM, journaux événements, table ARP, fichier hosts
- Rapport HTML basique sans navigation ni tri

---

## Licence

MIT License — Copyright (c) 2025 ps81frt

Permission est accordée, sans frais, à toute personne obtenant une copie de ce logiciel, de l'utiliser, le copier, le modifier, le fusionner, le publier, le distribuer, le sous-licencier et/ou le vendre, sous réserve que la notice de copyright et la présente permission soient incluses dans toutes les copies.

LE LOGICIEL EST FOURNI « EN L'ÉTAT », SANS GARANTIE D'AUCUNE SORTE.
