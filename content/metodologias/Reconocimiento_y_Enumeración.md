---
title: "Metodología de reconocimiento y enumeración"
date: 2026-09-08
draft: true
tags: ["red-team", "reconocimiento", "enumeracion", "nmap", "metodologia"]
categories: ["metodologias"]
summary: "Metodología para las fases de reconocimiento y enumeración en un test de intrusión: footprinting pasivo y activo, fingerprinting, escaneo de puertos, Nmap en profundidad y enumeración de servicios."
---

## Introducción

Esta pieza recoge una síntesis metodológica propia sobre las fases de **reconocimiento** y **enumeración** en un test de intrusión, construida a partir de mi formación en seguridad ofensiva y contrastada con fuentes oficiales (MITRE ATT&CK, RFCs de los protocolos implicados y documentación de Nmap).
El objetivo es tener una referencia propia, ordenada, con comandos reales y verificados, a la que volver antes de enfrentarme a un objetivo nuevo, en lugar de reconstruir cada vez la misma lista de sintaxis suelta.

## Alcance

Esta metodología cubre:

- Information gathering: distinción entre footprinting y fingerprinting.
- Reconocimiento pasivo (OSINT, WHOIS, motores de búsqueda, Shodan, Maltego).
- Reconocimiento activo: descubrimiento de red y fundamentos de escaneo de puertos TCP/UDP.
- Nmap en profundidad, con sintaxis completa: técnicas de descubrimiento de equipos, técnicas de escaneo de puertos, detección de versión/SO, NSE, optimización y evasión.
- Enumeración de servicios habituales: DNS, SMTP y banner grabbing genérico, con comandos.
- El puente hacia el análisis de vulnerabilidades, sin entrar en explotación.

## Metodología

### 1. Information gathering: footprinting y fingerprinting

La fase de recolección de información se divide conceptualmente en dos partes:

- **Footprinting**: recopilación de información sobre la arquitectura interna y externa de un objetivo, con poca o ninguna interacción directa. Puede ser externo (desde fuera de la organización) o interno (una vez se dispone de acceso parcial a la red). El externo, a su vez, se subdivide en pasivo y activo según el grado de interacción con el objetivo.
- **Fingerprinting**: recolección de información interactuando directamente con los sistemas para conocer su configuración, comportamiento y medidas de seguridad. Aquí se ubican el escaneo de puertos, la identificación de versiones y la identificación de sistema operativo.

Los objetivos del footprinting son: conocer el nivel de seguridad del objetivo, reducir el área de enfoque, identificar vulnerabilidades y dibujar un mapa de red inicial.

### 2. Reconocimiento pasivo

El reconocimiento pasivo recopila información sin contacto directo con los sistemas del objetivo, por lo que resulta prácticamente indetectable. Es el punto de partida recomendado antes de pasar a técnicas activas.

| Técnica | Herramienta / recurso | Qué se obtiene |
|---|---|---|
| Consulta WHOIS | `whois`, ICANN Lookup, DomainTools, Netcraft, Complete DNS | Titular del dominio, contactos administrativo/técnico, servidores DNS, fechas de creación/caducidad, estado del dominio |
| Google/Bing Hacking | Operadores avanzados, Google Hacking Database, uDork | Archivos y directorios expuestos, paneles de administración, versiones de aplicaciones web |
| Repositorios de texto y código | Pastenum (Pastebin/Pastie), GitHub dorks | Credenciales, nombres de usuario o información confidencial filtrada accidentalmente |
| Motores de dispositivos expuestos | Shodan | Dispositivos y servicios expuestos a Internet por país, puerto o producto |
| Correlación de entidades | Maltego (transformadas sobre dominios, IPs, registros MX/NS, correos, personas y redes sociales) | Mapa relacional del objetivo: infraestructura y personas vinculadas, de forma visual y encadenable |

Ejemplos de comandos y búsquedas reales:

```bash
# WHOIS de un dominio en consola
whois dominio.com

# WHOIS de una IP
whois 8.8.8.8
```

```
# Búsqueda en Shodan de dispositivos SNMP expuestos en España
port:161 country:es
```

Un matiz relevante en WHOIS: gran parte de los dominios actuales usan protección de privacidad (Contact Privacy, WhoisProxy), por lo que los datos de contacto reales pueden estar enmascarados por el proveedor de privacidad del registrador.

### 3. Reconocimiento activo: descubrimiento de red

El reconocimiento activo implica generar tráfico hacia el objetivo, lo que lo hace más preciso pero también más intrusivo y detectable por IDS/IPS y firewalls. Antes de escanear puertos conviene identificar qué hosts están vivos:

| Técnica | Mecanismo | Ventaja | Limitación |
|---|---|---|---|
| Resolución ARP | ARP Request a broadcast (`FF:FF:FF:FF:FF:FF`) | Muy rápida y fiable | Solo funciona dentro de la misma red local |
| Ping (ICMP Echo) | ICMP Echo Request / Echo Reply | Funciona en cualquier red alcanzable | Bloqueable por firewalls; algunos SO no responden |
| ICMP Timestamp | Timestamp Request / Reply | Alternativa cuando Echo está filtrado | Muchos sistemas tampoco responden a este tipo |
| Conexión TCP/UDP directa | Intento de conexión a puertos comunes (80, 53, 443, 23, 22) | Detecta hosts con servicios expuestos | No detecta hosts sin ningún servicio publicado |
| Resolución inversa de DNS | Consulta de registro PTR | Detecta sistemas existentes aunque estén apagados | Depende de que el PTR esté configurado |
| Sniffing pasivo | Captura de tráfico broadcast o de todo el segmento | Identifica hosts activos sin enviar sondas propias | En red cableada, limitado a tráfico broadcast; en inalámbrica es más efectivo |
| Traceo de red | Manipulación del TTL/Hop Limit | Revela topología y routers intermedios | No identifica hosts finales, solo saltos de red |

```bash
# Traceo de red
traceroute dominio.com     # Linux
tracert dominio.com        # Windows
```

### 4. Fundamentos del escaneo de puertos TCP/UDP

**TCP** es un protocolo orientado a conexión. El establecimiento de sesión se hace mediante el *three-way handshake* (SYN → SYN-ACK → ACK). A partir de la respuesta a un paquete SYN se puede inferir el estado de un puerto:

1. Se recibe SYN-ACK → puerto **abierto**.
2. No se recibe nada → probablemente **filtrado** (firewall intermedio).
3. Se recibe RST-ACK → puerto **cerrado**.
4. Se recibe ICMP Port Unreachable → puerto **inaccesible**, normalmente por firewall.

**UDP** no está orientado a conexión, lo que complica la interpretación:

1. Se recibe una respuesta acorde al servicio → puerto **abierto**.
2. No se recibe nada → puede ser filtrado, cerrado, o abierto pero sin respuesta al paquete enviado (ambigüedad estructural del protocolo).
3. Se recibe ICMP Port Unreachable → puerto **inaccesible**.

Esta ambigüedad hace que los escaneos UDP sean intrínsecamente más lentos y menos fiables que los TCP, motivo por el que en la práctica se infravaloran pese a alojar servicios críticos como DNS (53), SNMP (161/162) o DHCP (67/68).

### 5. Nmap como herramienta central

Nmap es el estándar de facto para el reconocimiento activo. Su sintaxis general es:

```bash
nmap [Técnicas] [Opciones] [Objetivos]
```

Los objetivos aceptan IP única, rangos con guion, notación CIDR o dominios: `192.168.10.10`, `172.16.128-130.0-255`, `10.0.0.0/16`, `www.dominio.com/28`.

#### 5.1. Técnicas de descubrimiento de equipos

Determinan qué máquinas de un rango están activas antes de invertir tiempo escaneando puertos.

```bash
# NO PING: trata todos los objetivos como activos, salta el descubrimiento
nmap -Pn 192.168.1.0/24

# LIST SCAN: solo lista objetivos y hace resolución DNS inversa, sin enviar sondas
nmap -sL -v www.dominio.es/24

# PING SCAN (Ping Sweep): descubre hosts activos sin escanear puertos
nmap -sn -v www.dominio.es/24
nmap -sn 192.168.1.0/24

# PING ARP: automático en red local, muy rápido (no requiere invocación explícita)
# Se puede forzar el uso de IP en vez de ARP con:
nmap -sn --send-ip 192.168.1.0/24

# PING TCP SYN a un puerto o lista de puertos (por defecto, puerto 80)
nmap -sn -PS -v www.dominio.es/24
nmap -sn -PS22-25,80,443,8080 192.168.1.0/24

# PING TCP ACK (complementa a PS frente a firewalls sin estado)
nmap -sn -PA -v www.dominio.es/24
nmap -sn -PA80,443 192.168.1.0/24

# PING UDP a un puerto que se espera cerrado (por defecto, 31338)
nmap -sn -PU 192.168.1.0/24

# PING ICMP Echo / Timestamp / Addressmask
nmap -sn -PE -v www.dominio.es/24
nmap -sn -PP 192.168.1.0/24
nmap -sn -PM 192.168.1.0/24

# PING SCTP (handshake INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK)
nmap -PY 192.168.1.0/24

# IP PROTOCOL PING: sondas con protocolos concretos en cabecera IP
nmap -PO 192.168.1.0/24
nmap -PO1,2,4 192.168.1.0/24
```

Si no se especifica ninguna opción de descubrimiento y el usuario tiene privilegios administrativos, Nmap combina por defecto `-PA80`, `-PS443`, un ICMP Echo Request y un ICMP Timestamp Request; si el objetivo pertenece a la red local, usa directamente resolución ARP.

Ejemplo práctico de configuración completa para descubrimiento en una subred:

```bash
# 1. Obtención de nombres de máquina de los objetivos
nmap -sL -v www.dominio.es/24

# 2. Determinación del estado de las máquinas (combina PA80, PS443, PE y PP)
nmap -sn -v www.dominio.es/24
```

#### 5.2. Técnicas de escaneo de puertos

Cada técnica interpreta de forma distinta las respuestas del objetivo, con implicaciones directas en fiabilidad y sigilo.

```bash
# TCP SYN Scan (Half-Open): técnica por defecto con privilegios, rápida y sigilosa
nmap -sS 192.168.1.10
nmap -sS -sV 192.168.1.10          # combinada con detección de versión

# TCP Connect Scan: usada sin privilegios; completa la conexión (queda en logs)
nmap -sT 192.168.1.10

# UDP Scan: lento por naturaleza del protocolo
nmap -sU 192.168.1.10
nmap -sU -sV --version-intensity 0 192.168.1.10   # reduce el tiempo de -sV en UDP

# TCP ACK Scan: no distingue abierto/cerrado, solo filtrado/no filtrado (mapea firewall)
nmap -sA 192.168.1.10

# Null, FIN y Xmas Scan: explotan una ambigüedad del RFC 793
nmap -sN 192.168.1.10
nmap -sF 192.168.1.10
nmap -sX 192.168.1.10

# Combinación de flags personalizada
nmap --scanflags SYN,ACK 192.168.1.10

# TCP Maimon Scan (flags FIN+ACK)
nmap -sM 192.168.1.10

# TCP Window Scan (variante de ACK que sí distingue abierto/cerrado)
nmap -sW 192.168.1.10

# Idle Scan: el más sigiloso, requiere un equipo "zombie" con IP-ID predecible
nmap -sI <IP_zombie> 192.168.1.10

# Búsqueda de un zombie válido en una subred
nmap -P0 -sN -n -v -p 80 --scanflags SYN,ACK <subred_objetivo>

# SCTP INIT y COOKIE-ECHO Scan
nmap -sY 192.168.1.10
nmap -sZ 192.168.1.10

# IP Protocol Scan: enumera protocolos de transporte soportados, no puertos
nmap -sO 192.168.1.10
```

Ejemplos prácticos de descubrimiento inicial encadenado con escaneo:

```bash
# Ping sweep para descubrir hosts activos en una red corporativa
nmap -sn 192.168.1.0/24

# Escaneo de los primeros 1000 puertos de un host activo
nmap -p 1-1000 192.168.1.10

# Fingerprinting de servicios y SO en un mismo comando
nmap -sV -O 192.168.1.10
```

#### 5.3. Detección de versión y sistema operativo

```bash
# Detección de versión de servicios, con control de intensidad (0-9, por defecto 7)
nmap -sV 192.168.1.10
nmap -sV --version-intensity 0 192.168.1.10   # solo sondas más comunes, más rápido
nmap -sV --version-intensity 9 192.168.1.10   # todas las sondas disponibles

# Detección de sistema operativo (compara con base de firmas de la pila TCP/IP)
nmap -O 192.168.1.10

# Atajo agresivo: combina -O, -sV, -sC (scripts por defecto) y --traceroute
nmap -A 192.168.1.10
```

`-A` es exhaustivo pero incrementa notablemente el tiempo de análisis en redes lentas o congestionadas; conviene reservarlo para objetivos ya acotados, no para rangos completos.

#### 5.4. Nmap Scripting Engine (NSE)

NSE ejecuta scripts en Lua contra los objetivos, ampliando Nmap a detección de vulnerabilidades, fuerza bruta o enumeración avanzada. Los scripts se ubican en `/usr/share/nmap/scripts/`.

```bash
# Ejecutar los scripts por defecto para cada servicio descubierto
nmap -sC 192.168.1.10

# Ejecutar un script concreto
nmap --script smtp-enum-users.nse 192.168.1.10 -p 25

# Pasar argumentos a un script
nmap --script asn-query.nse --script-args dns=8.8.8.8 111.222.111.222

# Ejecutar por categoría
nmap -T4 -p80 --script discovery 192.168.100.1/24

# Combinar categorías con condicionales, comodines y negación
nmap -T4 -p80 --script "discovery,safe" 192.168.100.1/24
nmap -T4 -p80 --script "discovery and safe" 192.168.100.1/24
nmap -T4 -p80 --script "not safe" 192.168.100.1/24
nmap -T4 -p80 --script "http-*" 192.168.100.1/24

# Comprobación de vulnerabilidades SMB (algunas pruebas son intrusivas)
nmap --script smb-check-vulns 192.168.1.23

# DNS cache snooping vía script NSE
nmap --script dns-cache-snoop 8.8.8.8
```

Cada script sigue reglas de ejecución: `prerule` (una vez, antes de escanear ningún host), `hostrule`/`portrule` (justo después de escanear un host o puerto concreto) y `postrule` (al finalizar todos los hosts pendientes). Internamente, Nmap expone estructuras `host` y `port` con campos como `host.os`, `host.ip`, `host.name`, `port.state`, `port.service`, `port.version.product` o `port.version.name`, que los scripts consultan para decidir si ejecutarse y qué mostrar. El campo `port.state` en las reglas de un script solo puede ser `open` u `open|filtered`, ya que NSE no lanza scripts sobre puertos cerrados.

Ejemplos reales de scripts citados en la formación:

- `smtp-enum-users.nse` — enumera usuarios SMTP vía el comando EXPN; si EXPN está deshabilitado en el servidor, no devuelve resultados.
- `dns-cache-snoop` — variante en script de la técnica de DNS cache snooping.
- `smb-check-vulns` — comprueba si el servicio Samba de un equipo es vulnerable; el propio módulo advierte de que algunas de sus pruebas se consideran peligrosas para la estabilidad del objetivo.

#### 5.5. Optimización de rendimiento y sigilo

```bash
# Plantillas temporales: de -T0 (paranoid, máximo sigilo) a -T5 (insane, máxima velocidad)
nmap -T0 192.168.1.10    # evita alertas IDS, muy lento
nmap -T1 192.168.1.10    # sneaky
nmap -T3 192.168.1.10    # normal (comportamiento por defecto)
nmap -T4 192.168.1.10    # recomendado en redes locales / banda ancha
nmap -T5 192.168.1.10    # solo en redes muy rápidas y poco congestionadas

# Control fino de tasas y reintentos
nmap --min-rate 500 --max-rate 1000 192.168.1.10
nmap --max-retries 2 192.168.1.10
nmap --host-timeout 30s 192.168.1.10
nmap --scan-delay 1s --max-scan-delay 5s 192.168.1.10

# Control de paralelismo
nmap --min-parallelism 10 --max-parallelism 50 192.168.1.0/24
nmap --min-hostgroup 20 --max-hostgroup 100 192.168.1.0/24

# Acotar el alcance antes de optimizar tiempos: la optimización más rentable
nmap -F 192.168.1.10                 # Fast Scan: 100 puertos más comunes
nmap --top-ports 50 192.168.1.10     # los 50 puertos más frecuentes
nmap -p 22,80,443,6666-7000,8080,8443 192.168.1.10   # lista/rango personalizado
nmap -p U:53,111,T:21-25,80,139,S:9 192.168.1.10      # mezclando UDP/TCP/SCTP
nmap -p- 192.168.1.10                # los 65535 puertos, cuesta mucho tiempo

# Técnicas de evasión de firewalls / IDS
nmap -f 192.168.1.10                            # fragmentación de paquetes
nmap --mtu 16 192.168.1.10                      # tamaño de fragmento personalizado
nmap -D señuelo1,señuelo2,ME 192.168.1.10       # señuelos para enmascarar el origen
nmap -S 10.0.0.5 -e eth0 192.168.1.10           # IP de origen falsa e interfaz concreta
nmap --source-port 53 192.168.1.10              # falsificación del puerto de origen
nmap --data-length 25 192.168.1.10              # relleno aleatorio de paquetes
nmap --spoof-mac 0 192.168.1.10                 # MAC aleatoria
nmap --spoof-mac Apple 192.168.1.10             # MAC con prefijo de fabricante
nmap --randomize-hosts 192.168.1.0/24           # orden aleatorio de objetivos
nmap --badsum 192.168.1.10                      # checksum incorrecto (detecta validación en IDS)

# Salida de resultados en distintos formatos
nmap -oN salida.txt 192.168.1.10     # normal
nmap -oX salida.xml 192.168.1.10     # XML
nmap -oG salida.gnmap 192.168.1.10   # grepable
nmap -oA analisis 192.168.1.10       # normal + grepable + XML en un solo comando
```

En redes locales con firewalls stateful e IDS/IPS activos, la combinación práctica más habitual para reducir ruido es encadenar plantilla temporal baja, control de reintentos y fragmentación:

```bash
nmap -sS -T1 -f --max-retries 1 --scan-delay 2s 192.168.1.10
```

### 6. Enumeración de servicios

Una vez identificados los puertos abiertos y sus versiones, la enumeración busca extraer información específica de cada servicio.

**DNS**, con la herramienta `dig`:

```bash
# Consulta estándar (registro A por defecto)
dig dominio.com

# Respuesta abreviada
dig dominio.com +short

# Solo la sección de respuestas
dig dominio.com +noall +answer

# Consulta contra un servidor DNS concreto
dig @8.8.8.8 dominio.com

# Todos los tipos de registro disponibles
dig dominio.com ANY

# Tipos de registro específicos
dig dominio.com MX
dig dominio.com txt
dig dominio.com cname
dig dominio.com ns
dig dominio.com A

# Resolución iterativa desde la raíz
dig dominio.com +trace

# Resolución inversa (requiere registro PTR)
dig +answer -x 212.170.36.79

# Consultas por lotes desde un fichero (un dominio por línea)
dig -f nombre_dominio.txt +short

# Configuración persistente de opciones por defecto
echo "+noall +answer" > ~/.digrc
```

**DNS Cache Snooping** permite inferir qué dominios ha consultado previamente una organización, útil para perfilar hábitos de navegación de cara a phishing dirigido:

- *Non-recursive queries*: deshabilitar la recursividad en la consulta; si el dominio está en caché, el servidor lo devuelve igualmente, revelando que ya fue consultado.
- *Recursive queries*: se fuerza la recursividad y se comparan los valores TTL entre el servidor autoritativo y el servidor objetivo para inferir cuánto tiempo lleva cacheado el dato.
- Herramientas: `cache_snoop.pl` o el script NSE `dns-cache-snoop`.
- Metasploit dispone además de módulos DNS para bruteforce de nombres a partir de diccionario.

**SMTP**, con los comandos del propio protocolo (HELO/EHLO, VRFY, EXPN, RCPT TO, STARTTLS, DATA, MAIL, RSET, QUIT, HELP, AUTH):

```bash
# Identificación del banner
nc 192.168.1.15 25
telnet 192.168.1.15 25
nmap -sV -p25 192.168.1.15
nmap -sV -p25 192.168.1.15 --script=banner

# Vía Metasploit
use auxiliary/scanner/smtp/smtp_version
set RHOSTS 192.168.1.15
run

# Enumeración de usuarios manual (VRFY suele estar habilitado; EXPN, no)
# Tras conectar por telnet/netcat al puerto 25:
VRFY root
VRFY admin
EXPN root

# Enumeración de usuarios vía Nmap (depende de que EXPN esté habilitado)
nmap --script smtp-enum-users.nse 192.168.1.15 -p 25

# Enumeración de usuarios con smtp-user-enum (pentest-monkey, en Kali por defecto)
smtp-user-enum -M VRFY -U usuarios.txt -t 192.168.1.15

# Vía Metasploit (usa por defecto unix_users.txt)
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 192.168.1.15
run

# Test de SMTP Relay vía Metasploit
use auxiliary/scanner/smtp/smtp_relay
set MAIL_FROM origen@dominio.com
set MAILTO destino@dominio.com
run
```

Códigos de respuesta relevantes en la enumeración de usuarios: 250/251/252 indican dirección válida, reenviada o desconocida (pero aceptada); 550 indica que la dirección no existe y el servidor rechazará el mensaje. Herramientas más completas como iSMTP combinan enumeración de usuarios, test de relay y email spoofing en una sola ejecución.

**Banner grabbing genérico**, aplicable a cualquier servicio con banner:

```bash
nc <IP> <puerto>
telnet <IP> <puerto>
nmap -sV <IP> -p <puerto> --script=banner
whatweb <IP_o_dominio>
```

**Fingerprinting web**, mencionado como línea de trabajo específica dentro del footprinting activo: identificación del servidor web, del CMS y de sus plugins, con herramientas como Whatweb, BlindElephant o Plecost, para después buscar vulnerabilidades conocidas asociadas a esas versiones concretas.

### 7. El puente hacia el análisis de vulnerabilidades

El reconocimiento y la enumeración terminan donde empieza el análisis de vulnerabilidades. Las técnicas para identificar debilidades a partir de lo recopilado, ordenadas de menor a mayor riesgo de interacción con el objetivo, son:

1. **Comprobar versiones de software** conocidas y su histórico de CVEs.
2. **Comprobar versiones de protocolo** cuando la versión del software no es visible.
3. **Analizar el comportamiento del sistema remoto** ante entradas concretas.
4. **Analizar la configuración**, si se dispone de acceso local o remoto a ella.
5. **Lanzar un exploit** para confirmar la vulnerabilidad de forma directa.

Las dos primeras suelen implicar un riesgo bajo (equivalen al comportamiento normal del servicio); las dos últimas pueden degradar o tumbar el servicio si la vulnerabilidad probada es, por ejemplo, una denegación de servicio. Decidir qué pruebas son asumibles es responsabilidad del auditor y debe quedar acotado en el alcance de la auditoría.

## Análisis y criterio propio

De todo lo anterior, destaco tres ideas de cara a la práctica:

**El escaneo UDP se infravalora sistemáticamente.** Es lento y ambiguo por diseño, pero aloja servicios tan relevantes como DNS o SNMP. Saltárselo o limitarlo a los puertos más comunes deja fuera vectores reales; merece la pena, al menos, un `-sU --top-ports 50` dirigido en vez de omitirlo del todo.

**El sigilo se estudia más de lo que se practica.** Los timing templates, los señuelos o el Idle Scan son contenido recurrente en la formación, pero en la mayoría de laboratorios de práctica no hay IDS/IPS real que penalice un escaneo agresivo, así que se automatiza el hábito de escanear rápido y agresivo (`-T4`, `-A`) que no siempre es transferible a un entorno con controles de seguridad activos.

**La enumeración manual sigue aportando cuando la automatizada falla.** Scripts como `smtp-enum-users.nse` dependen de que el servicio no tenga deshabilitados EXPN o VRFY; cuando estos están cerrados, solo la combinación de varias técnicas (RCPT TO, banner grabbing, comportamiento ante distintos comandos) permite seguir avanzando. Automatizar es un punto de partida, no un sustituto del análisis manual cuando el objetivo está mínimamente endurecido.

## Limitaciones

Esta metodología es de propósito general: la profundidad real de cada técnica dependerá del objetivo, el alcance autorizado y el tiempo disponible. Las herramientas y su sintaxis exacta evolucionan con las versiones; conviene verificar la documentación oficial vigente antes de aplicar cualquier comando en un entorno real.

## Conclusiones

El reconocimiento y la enumeración condicionan todo lo que viene después en un test de intrusión: un mapa de servicios incompleto o mal interpretado limita directamente las hipótesis de explotación disponibles. Tener esta metodología documentada, verificada y con comandos reales sirve como punto de partida repetible, y quedará como base para piezas futuras sobre enumeración de Active Directory y fases posteriores del proceso.

## Referencias

- [MITRE ATT&CK — Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/)
- [RFC 3912 — WHOIS Protocol Specification](https://www.rfc-editor.org/rfc/rfc3912.txt)
- [RFC 1035 — Domain Names: Implementation and Specification](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 5321 — Simple Mail Transfer Protocol](https://www.rfc-editor.org/rfc/rfc5321)
- [RFC 793 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc793)
- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Nmap Scripting Engine API](https://nmap.org/book/nse-api.html)
