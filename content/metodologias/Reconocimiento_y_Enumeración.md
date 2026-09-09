---
title: "Metodología de reconocimiento y enumeración"
date: 2026-09-08
draft: false
tags: ["red-team", "reconocimiento", "enumeracion", "nmap", "metodologia"]
categories: ["metodologias"]
summary: "Metodología para las fases de reconocimiento y enumeración en un test de intrusión: footprinting pasivo y activo, fingerprinting, escaneo de puertos, Nmap en profundidad y enumeración de servicios."
---

## Introducción

Esta pieza recoge una síntesis metodológica propia sobre las fases de **reconocimiento** y **enumeración** en un test de intrusión, construida a partir de mi formación en seguridad ofensiva y contrastada con fuentes oficiales (MITRE ATT&CK, RFCs de los protocolos implicados y documentación de Nmap).

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

<pre class="cmd-block"><code><span class="comment"># WHOIS de un dominio en consola</span>
<span class="tool">whois</span> dominio.com

<span class="comment"># WHOIS de una IP</span>
<span class="tool">whois</span> 8.8.8.8</code></pre>

<pre class="cmd-block"><code><span class="comment"># Búsqueda en Shodan de dispositivos SNMP expuestos en España</span>
port:161 country:es</code></pre>

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

<pre class="cmd-block"><code><span class="comment"># Traceo de red</span>
<span class="tool">traceroute</span> dominio.com     <span class="comment"># Linux</span>
<span class="tool">tracert</span> dominio.com        <span class="comment"># Windows</span></code></pre>

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

<pre class="cmd-block"><code><span class="tool">nmap</span> [Técnicas] [Opciones] [Objetivos]</code></pre>

Los objetivos aceptan IP única, rangos con guion, notación CIDR o dominios: `192.168.10.10`, `172.16.128-130.0-255`, `10.0.0.0/16`, `www.dominio.com/28`.

#### 5.1. Técnicas de descubrimiento de equipos

Determinan qué máquinas de un rango están activas antes de invertir tiempo escaneando puertos.

<pre class="cmd-block"><code><span class="comment"># NO PING: trata todos los objetivos como activos, salta el descubrimiento</span>
<span class="tool">nmap</span> <span class="flag">-Pn</span> 192.168.1.0/24

<span class="comment"># LIST SCAN: solo lista objetivos y hace resolución DNS inversa, sin enviar sondas</span>
<span class="tool">nmap</span> <span class="flag">-sL</span> <span class="flag">-v</span> www.dominio.es/24

<span class="comment"># PING SCAN (Ping Sweep): descubre hosts activos sin escanear puertos</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-v</span> www.dominio.es/24
<span class="tool">nmap</span> <span class="flag">-sn</span> 192.168.1.0/24

<span class="comment"># PING ARP: automático en red local, muy rápido (no requiere invocación explícita)</span>
<span class="comment"># Se puede forzar el uso de IP en vez de ARP con:</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">--send-ip</span> 192.168.1.0/24

<span class="comment"># PING TCP SYN a un puerto o lista de puertos (por defecto, puerto 80)</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PS</span> <span class="flag">-v</span> www.dominio.es/24
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PS22-25,80,443,8080</span> 192.168.1.0/24

<span class="comment"># PING TCP ACK (complementa a PS frente a firewalls sin estado)</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PA</span> <span class="flag">-v</span> www.dominio.es/24
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PA80,443</span> 192.168.1.0/24

<span class="comment"># PING UDP a un puerto que se espera cerrado (por defecto, 31338)</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PU</span> 192.168.1.0/24

<span class="comment"># PING ICMP Echo / Timestamp / Addressmask</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PE</span> <span class="flag">-v</span> www.dominio.es/24
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PP</span> 192.168.1.0/24
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-PM</span> 192.168.1.0/24

<span class="comment"># PING SCTP (handshake INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK)</span>
<span class="tool">nmap</span> <span class="flag">-PY</span> 192.168.1.0/24

<span class="comment"># IP PROTOCOL PING: sondas con protocolos concretos en cabecera IP</span>
<span class="tool">nmap</span> <span class="flag">-PO</span> 192.168.1.0/24
<span class="tool">nmap</span> <span class="flag">-PO1,2,4</span> 192.168.1.0/24</code></pre>

Si no se especifica ninguna opción de descubrimiento y el usuario tiene privilegios administrativos, Nmap combina por defecto `-PA80`, `-PS443`, un ICMP Echo Request y un ICMP Timestamp Request; si el objetivo pertenece a la red local, usa directamente resolución ARP.

Ejemplo práctico de configuración completa para descubrimiento en una subred:

<pre class="cmd-block"><code><span class="comment"># 1. Obtención de nombres de máquina de los objetivos</span>
<span class="tool">nmap</span> <span class="flag">-sL</span> <span class="flag">-v</span> www.dominio.es/24

<span class="comment"># 2. Determinación del estado de las máquinas (combina PA80, PS443, PE y PP)</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> <span class="flag">-v</span> www.dominio.es/24</code></pre>

#### 5.2. Técnicas de escaneo de puertos

Cada técnica interpreta de forma distinta las respuestas del objetivo, con implicaciones directas en fiabilidad y sigilo.

<pre class="cmd-block"><code><span class="comment"># TCP SYN Scan (Half-Open): técnica por defecto con privilegios, rápida y sigilosa</span>
<span class="tool">nmap</span> <span class="flag">-sS</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sS</span> <span class="flag">-sV</span> 192.168.1.10          <span class="comment"># combinada con detección de versión</span>

<span class="comment"># TCP Connect Scan: usada sin privilegios; completa la conexión (queda en logs)</span>
<span class="tool">nmap</span> <span class="flag">-sT</span> 192.168.1.10

<span class="comment"># UDP Scan: lento por naturaleza del protocolo</span>
<span class="tool">nmap</span> <span class="flag">-sU</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sU</span> <span class="flag">-sV</span> <span class="flag">--version-intensity</span> 0 192.168.1.10   <span class="comment"># reduce el tiempo de -sV en UDP</span>

<span class="comment"># TCP ACK Scan: no distingue abierto/cerrado, solo filtrado/no filtrado (mapea firewall)</span>
<span class="tool">nmap</span> <span class="flag">-sA</span> 192.168.1.10

<span class="comment"># Null, FIN y Xmas Scan: explotan una ambigüedad del RFC 793</span>
<span class="tool">nmap</span> <span class="flag">-sN</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sF</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sX</span> 192.168.1.10

<span class="comment"># Combinación de flags personalizada</span>
<span class="tool">nmap</span> <span class="flag">--scanflags</span> SYN,ACK 192.168.1.10

<span class="comment"># TCP Maimon Scan (flags FIN+ACK)</span>
<span class="tool">nmap</span> <span class="flag">-sM</span> 192.168.1.10

<span class="comment"># TCP Window Scan (variante de ACK que sí distingue abierto/cerrado)</span>
<span class="tool">nmap</span> <span class="flag">-sW</span> 192.168.1.10

<span class="comment"># Idle Scan: el más sigiloso, requiere un equipo "zombie" con IP-ID predecible</span>
<span class="tool">nmap</span> <span class="flag">-sI</span> &lt;IP_zombie&gt; 192.168.1.10

<span class="comment"># Búsqueda de un zombie válido en una subred</span>
<span class="tool">nmap</span> <span class="flag">-P0</span> <span class="flag">-sN</span> <span class="flag">-n</span> <span class="flag">-v</span> <span class="flag">-p</span> 80 <span class="flag">--scanflags</span> SYN,ACK &lt;subred_objetivo&gt;

<span class="comment"># SCTP INIT y COOKIE-ECHO Scan</span>
<span class="tool">nmap</span> <span class="flag">-sY</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sZ</span> 192.168.1.10

<span class="comment"># IP Protocol Scan: enumera protocolos de transporte soportados, no puertos</span>
<span class="tool">nmap</span> <span class="flag">-sO</span> 192.168.1.10</code></pre>

Ejemplos prácticos de descubrimiento inicial encadenado con escaneo:

<pre class="cmd-block"><code><span class="comment"># Ping sweep para descubrir hosts activos en una red corporativa</span>
<span class="tool">nmap</span> <span class="flag">-sn</span> 192.168.1.0/24

<span class="comment"># Escaneo de los primeros 1000 puertos de un host activo</span>
<span class="tool">nmap</span> <span class="flag">-p</span> 1-1000 192.168.1.10

<span class="comment"># Fingerprinting de servicios y SO en un mismo comando</span>
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">-O</span> 192.168.1.10</code></pre>

#### 5.3. Detección de versión y sistema operativo

<pre class="cmd-block"><code><span class="comment"># Detección de versión de servicios, con control de intensidad (0-9, por defecto 7)</span>
<span class="tool">nmap</span> <span class="flag">-sV</span> 192.168.1.10
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">--version-intensity</span> 0 192.168.1.10   <span class="comment"># solo sondas más comunes, más rápido</span>
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">--version-intensity</span> 9 192.168.1.10   <span class="comment"># todas las sondas disponibles</span>

<span class="comment"># Detección de sistema operativo (compara con base de firmas de la pila TCP/IP)</span>
<span class="tool">nmap</span> <span class="flag">-O</span> 192.168.1.10

<span class="comment"># Atajo agresivo: combina -O, -sV, -sC (scripts por defecto) y --traceroute</span>
<span class="tool">nmap</span> <span class="flag">-A</span> 192.168.1.10</code></pre>

`-A` es exhaustivo pero incrementa notablemente el tiempo de análisis en redes lentas o congestionadas; conviene reservarlo para objetivos ya acotados, no para rangos completos.

#### 5.4. Nmap Scripting Engine (NSE)

NSE ejecuta scripts en Lua contra los objetivos, ampliando Nmap a detección de vulnerabilidades, fuerza bruta o enumeración avanzada. Los scripts se ubican en `/usr/share/nmap/scripts/`.

<pre class="cmd-block"><code><span class="comment"># Ejecutar los scripts por defecto para cada servicio descubierto</span>
<span class="tool">nmap</span> <span class="flag">-sC</span> 192.168.1.10

<span class="comment"># Ejecutar un script concreto</span>
<span class="tool">nmap</span> <span class="flag">--script</span> smtp-enum-users.nse 192.168.1.10 <span class="flag">-p</span> 25

<span class="comment"># Pasar argumentos a un script</span>
<span class="tool">nmap</span> <span class="flag">--script</span> asn-query.nse <span class="flag">--script-args</span> dns=8.8.8.8 111.222.111.222

<span class="comment"># Ejecutar por categoría</span>
<span class="tool">nmap</span> <span class="flag">-T4</span> <span class="flag">-p80</span> <span class="flag">--script</span> discovery 192.168.100.1/24

<span class="comment"># Combinar categorías con condicionales, comodines y negación</span>
<span class="tool">nmap</span> <span class="flag">-T4</span> <span class="flag">-p80</span> <span class="flag">--script</span> "discovery,safe" 192.168.100.1/24
<span class="tool">nmap</span> <span class="flag">-T4</span> <span class="flag">-p80</span> <span class="flag">--script</span> "discovery and safe" 192.168.100.1/24
<span class="tool">nmap</span> <span class="flag">-T4</span> <span class="flag">-p80</span> <span class="flag">--script</span> "not safe" 192.168.100.1/24
<span class="tool">nmap</span> <span class="flag">-T4</span> <span class="flag">-p80</span> <span class="flag">--script</span> "http-*" 192.168.100.1/24

<span class="comment"># Comprobación de vulnerabilidades SMB (algunas pruebas son intrusivas)</span>
<span class="tool">nmap</span> <span class="flag">--script</span> smb-check-vulns 192.168.1.23

<span class="comment"># DNS cache snooping vía script NSE</span>
<span class="tool">nmap</span> <span class="flag">--script</span> dns-cache-snoop 8.8.8.8</code></pre>

Cada script sigue reglas de ejecución: `prerule` (una vez, antes de escanear ningún host), `hostrule`/`portrule` (justo después de escanear un host o puerto concreto) y `postrule` (al finalizar todos los hosts pendientes). Internamente, Nmap expone estructuras `host` y `port` con campos como `host.os`, `host.ip`, `host.name`, `port.state`, `port.service`, `port.version.product` o `port.version.name`, que los scripts consultan para decidir si ejecutarse y qué mostrar. El campo `port.state` en las reglas de un script solo puede ser `open` u `open|filtered`, ya que NSE no lanza scripts sobre puertos cerrados.

Ejemplos reales de scripts citados en la formación:

- `smtp-enum-users.nse` — enumera usuarios SMTP vía el comando EXPN; si EXPN está deshabilitado en el servidor, no devuelve resultados.
- `dns-cache-snoop` — variante en script de la técnica de DNS cache snooping.
- `smb-check-vulns` — comprueba si el servicio Samba de un equipo es vulnerable; el propio módulo advierte de que algunas de sus pruebas se consideran peligrosas para la estabilidad del objetivo.

#### 5.5. Optimización de rendimiento y sigilo

<pre class="cmd-block"><code><span class="comment"># Plantillas temporales: de -T0 (paranoid, máximo sigilo) a -T5 (insane, máxima velocidad)</span>
<span class="tool">nmap</span> <span class="flag">-T0</span> 192.168.1.10    <span class="comment"># evita alertas IDS, muy lento</span>
<span class="tool">nmap</span> <span class="flag">-T1</span> 192.168.1.10    <span class="comment"># sneaky</span>
<span class="tool">nmap</span> <span class="flag">-T3</span> 192.168.1.10    <span class="comment"># normal (comportamiento por defecto)</span>
<span class="tool">nmap</span> <span class="flag">-T4</span> 192.168.1.10    <span class="comment"># recomendado en redes locales / banda ancha</span>
<span class="tool">nmap</span> <span class="flag">-T5</span> 192.168.1.10    <span class="comment"># solo en redes muy rápidas y poco congestionadas</span>

<span class="comment"># Control fino de tasas y reintentos</span>
<span class="tool">nmap</span> <span class="flag">--min-rate</span> 500 <span class="flag">--max-rate</span> 1000 192.168.1.10
<span class="tool">nmap</span> <span class="flag">--max-retries</span> 2 192.168.1.10
<span class="tool">nmap</span> <span class="flag">--host-timeout</span> 30s 192.168.1.10
<span class="tool">nmap</span> <span class="flag">--scan-delay</span> 1s <span class="flag">--max-scan-delay</span> 5s 192.168.1.10

<span class="comment"># Control de paralelismo</span>
<span class="tool">nmap</span> <span class="flag">--min-parallelism</span> 10 <span class="flag">--max-parallelism</span> 50 192.168.1.0/24
<span class="tool">nmap</span> <span class="flag">--min-hostgroup</span> 20 <span class="flag">--max-hostgroup</span> 100 192.168.1.0/24

<span class="comment"># Acotar el alcance antes de optimizar tiempos: la optimización más rentable</span>
<span class="tool">nmap</span> <span class="flag">-F</span> 192.168.1.10                 <span class="comment"># Fast Scan: 100 puertos más comunes</span>
<span class="tool">nmap</span> <span class="flag">--top-ports</span> 50 192.168.1.10     <span class="comment"># los 50 puertos más frecuentes</span>
<span class="tool">nmap</span> <span class="flag">-p</span> 22,80,443,6666-7000,8080,8443 192.168.1.10   <span class="comment"># lista/rango personalizado</span>
<span class="tool">nmap</span> <span class="flag">-p</span> U:53,111,T:21-25,80,139,S:9 192.168.1.10      <span class="comment"># mezclando UDP/TCP/SCTP</span>
<span class="tool">nmap</span> <span class="flag">-p-</span> 192.168.1.10                <span class="comment"># los 65535 puertos, cuesta mucho tiempo</span>

<span class="comment"># Técnicas de evasión de firewalls / IDS</span>
<span class="tool">nmap</span> <span class="flag">-f</span> 192.168.1.10                            <span class="comment"># fragmentación de paquetes</span>
<span class="tool">nmap</span> <span class="flag">--mtu</span> 16 192.168.1.10                      <span class="comment"># tamaño de fragmento personalizado</span>
<span class="tool">nmap</span> <span class="flag">-D</span> señuelo1,señuelo2,ME 192.168.1.10       <span class="comment"># señuelos para enmascarar el origen</span>
<span class="tool">nmap</span> <span class="flag">-S</span> 10.0.0.5 <span class="flag">-e</span> eth0 192.168.1.10           <span class="comment"># IP de origen falsa e interfaz concreta</span>
<span class="tool">nmap</span> <span class="flag">--source-port</span> 53 192.168.1.10              <span class="comment"># falsificación del puerto de origen</span>
<span class="tool">nmap</span> <span class="flag">--data-length</span> 25 192.168.1.10              <span class="comment"># relleno aleatorio de paquetes</span>
<span class="tool">nmap</span> <span class="flag">--spoof-mac</span> 0 192.168.1.10                 <span class="comment"># MAC aleatoria</span>
<span class="tool">nmap</span> <span class="flag">--spoof-mac</span> Apple 192.168.1.10             <span class="comment"># MAC con prefijo de fabricante</span>
<span class="tool">nmap</span> <span class="flag">--randomize-hosts</span> 192.168.1.0/24           <span class="comment"># orden aleatorio de objetivos</span>
<span class="tool">nmap</span> <span class="flag">--badsum</span> 192.168.1.10                      <span class="comment"># checksum incorrecto (detecta validación en IDS)</span>

<span class="comment"># Salida de resultados en distintos formatos</span>
<span class="tool">nmap</span> <span class="flag">-oN</span> salida.txt 192.168.1.10     <span class="comment"># normal</span>
<span class="tool">nmap</span> <span class="flag">-oX</span> salida.xml 192.168.1.10     <span class="comment"># XML</span>
<span class="tool">nmap</span> <span class="flag">-oG</span> salida.gnmap 192.168.1.10   <span class="comment"># grepable</span>
<span class="tool">nmap</span> <span class="flag">-oA</span> analisis 192.168.1.10       <span class="comment"># normal + grepable + XML en un solo comando</span></code></pre>

En redes locales con firewalls stateful e IDS/IPS activos, la combinación práctica más habitual para reducir ruido es encadenar plantilla temporal baja, control de reintentos y fragmentación:

<pre class="cmd-block"><code><span class="tool">nmap</span> <span class="flag">-sS</span> <span class="flag">-T1</span> <span class="flag">-f</span> <span class="flag">--max-retries</span> 1 <span class="flag">--scan-delay</span> 2s 192.168.1.10</code></pre>

### 6. Enumeración de servicios

Una vez identificados los puertos abiertos y sus versiones, la enumeración busca extraer información específica de cada servicio.

**DNS**, con la herramienta `dig`:

<pre class="cmd-block"><code><span class="comment"># Consulta estándar (registro A por defecto)</span>
<span class="tool">dig</span> dominio.com

<span class="comment"># Respuesta abreviada</span>
<span class="tool">dig</span> dominio.com <span class="flag">+short</span>

<span class="comment"># Solo la sección de respuestas</span>
<span class="tool">dig</span> dominio.com <span class="flag">+noall</span> <span class="flag">+answer</span>

<span class="comment"># Consulta contra un servidor DNS concreto</span>
<span class="tool">dig</span> @8.8.8.8 dominio.com

<span class="comment"># Todos los tipos de registro disponibles</span>
<span class="tool">dig</span> dominio.com ANY

<span class="comment"># Tipos de registro específicos</span>
<span class="tool">dig</span> dominio.com MX
<span class="tool">dig</span> dominio.com txt
<span class="tool">dig</span> dominio.com cname
<span class="tool">dig</span> dominio.com ns
<span class="tool">dig</span> dominio.com A

<span class="comment"># Resolución iterativa desde la raíz</span>
<span class="tool">dig</span> dominio.com <span class="flag">+trace</span>

<span class="comment"># Resolución inversa (requiere registro PTR)</span>
<span class="tool">dig</span> <span class="flag">+answer</span> <span class="flag">-x</span> 212.170.36.79

<span class="comment"># Consultas por lotes desde un fichero (un dominio por línea)</span>
<span class="tool">dig</span> <span class="flag">-f</span> nombre_dominio.txt <span class="flag">+short</span>

<span class="comment"># Configuración persistente de opciones por defecto</span>
<span class="tool">echo</span> "+noall +answer" &gt; ~/.digrc</code></pre>

**DNS Cache Snooping** permite inferir qué dominios ha consultado previamente una organización, útil para perfilar hábitos de navegación de cara a phishing dirigido:

- *Non-recursive queries*: deshabilitar la recursividad en la consulta; si el dominio está en caché, el servidor lo devuelve igualmente, revelando que ya fue consultado.
- *Recursive queries*: se fuerza la recursividad y se comparan los valores TTL entre el servidor autoritativo y el servidor objetivo para inferir cuánto tiempo lleva cacheado el dato.
- Herramientas: `cache_snoop.pl` o el script NSE `dns-cache-snoop`.
- Metasploit dispone además de módulos DNS para bruteforce de nombres a partir de diccionario.

**SMTP**, con los comandos del propio protocolo (HELO/EHLO, VRFY, EXPN, RCPT TO, STARTTLS, DATA, MAIL, RSET, QUIT, HELP, AUTH):

<pre class="cmd-block"><code><span class="comment"># Identificación del banner</span>
<span class="tool">nc</span> 192.168.1.15 25
<span class="tool">telnet</span> 192.168.1.15 25
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">-p25</span> 192.168.1.15
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">-p25</span> 192.168.1.15 <span class="flag">--script=banner</span>

<span class="comment"># Vía Metasploit</span>
<span class="tool">use</span> auxiliary/scanner/smtp/smtp_version
<span class="tool">set</span> RHOSTS 192.168.1.15
<span class="tool">run</span>

<span class="comment"># Enumeración de usuarios manual (VRFY suele estar habilitado; EXPN, no)</span>
<span class="comment"># Tras conectar por telnet/netcat al puerto 25:</span>
<span class="tool">VRFY</span> root
<span class="tool">VRFY</span> admin
<span class="tool">EXPN</span> root

<span class="comment"># Enumeración de usuarios vía Nmap (depende de que EXPN esté habilitado)</span>
<span class="tool">nmap</span> <span class="flag">--script</span> smtp-enum-users.nse 192.168.1.15 <span class="flag">-p</span> 25

<span class="comment"># Enumeración de usuarios con smtp-user-enum (pentest-monkey, en Kali por defecto)</span>
<span class="tool">smtp-user-enum</span> <span class="flag">-M</span> VRFY <span class="flag">-U</span> usuarios.txt <span class="flag">-t</span> 192.168.1.15

<span class="comment"># Vía Metasploit (usa por defecto unix_users.txt)</span>
<span class="tool">use</span> auxiliary/scanner/smtp/smtp_enum
<span class="tool">set</span> RHOSTS 192.168.1.15
<span class="tool">run</span>

<span class="comment"># Test de SMTP Relay vía Metasploit</span>
<span class="tool">use</span> auxiliary/scanner/smtp/smtp_relay
<span class="tool">set</span> MAIL_FROM origen@dominio.com
<span class="tool">set</span> MAILTO destino@dominio.com
<span class="tool">run</span></code></pre>

Códigos de respuesta relevantes en la enumeración de usuarios: 250/251/252 indican dirección válida, reenviada o desconocida (pero aceptada); 550 indica que la dirección no existe y el servidor rechazará el mensaje. Herramientas más completas como iSMTP combinan enumeración de usuarios, test de relay y email spoofing en una sola ejecución.

**Banner grabbing genérico**, aplicable a cualquier servicio con banner:

<pre class="cmd-block"><code><span class="tool">nc</span> &lt;IP&gt; &lt;puerto&gt;
<span class="tool">telnet</span> &lt;IP&gt; &lt;puerto&gt;
<span class="tool">nmap</span> <span class="flag">-sV</span> &lt;IP&gt; <span class="flag">-p</span> &lt;puerto&gt; <span class="flag">--script=banner</span>
<span class="tool">whatweb</span> &lt;IP_o_dominio&gt;</code></pre>

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
