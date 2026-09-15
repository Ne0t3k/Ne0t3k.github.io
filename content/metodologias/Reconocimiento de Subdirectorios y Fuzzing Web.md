---
title: "Metodología de reconocimiento de subdirectorios y fuzzing web"
date: 2026-09-15
draft: false
tags: ["red-team", "reconocimiento", "fuzzing", "web"]
categories: ["metodologias"]
summary: "Metodología para el descubrimiento de contenido web en un test de intrusión: fundamentos del fuzzing, diccionarios y SecLists, content discovery con ffuf, gobuster, feroxbuster, dirsearch y wfuzz, fuzzing de extensiones, VHosts, parámetros, JSON/APIs, modos multi-wordlist, bypass de 403 y evasión de WAF."
---

## Introducción

Esta pieza recoge una síntesis metodológica propia sobre las fases de reconocimiento y enumeración, centrándose ahora en el **descubrimiento de contenido web** (content discovery) mediante fuzzing de subdirectorios, ficheros, parámetros y virtual hosts.

## Alcance

Esta metodología cubre:

- Fundamentos del fuzzing de contenido web: qué es, por qué complementa al crawling pasivo y qué falsos positivos genera.
- Diccionarios: SecLists, dirb, dirbuster, generación dinámica de wordlists y criterios para elegir según contexto.
- Herramientas principales en profundidad: ffuf, Gobuster, feroxbuster, dirsearch y Wfuzz, con sintaxis completa.
- Modos de combinación multi-wordlist en ffuf (clusterbomb, pitchfork, sniper).
- Fuzzing de extensiones, backups y ficheros de configuración expuestos.
- Fuzzing recursivo de subdirectorios.
- Fuzzing de Virtual Hosts y subdominios vía Host header.
- Fuzzing de parámetros GET/POST, cuerpos JSON y APIs REST.
- Fuzzing de cabeceras HTTP y técnicas de bypass de restricciones 401/403.
- Calibración de resultados: filtrado de falsos positivos y auto-calibración.
- Evasión básica de WAF/rate-limiting y uso de proxy/replay para análisis manual posterior.
- El puente hacia el análisis de vulnerabilidades sobre el contenido descubierto.

## Metodología

### 1. Fundamentos del fuzzing de contenido web

El fuzzing de contenido (content discovery) consiste en enviar un alto volumen de peticiones HTTP sustituyendo una palabra clave de la URL, cabecera o cuerpo por cada entrada de un diccionario, y observar qué respuestas difieren del comportamiento esperado. A diferencia del crawling, que solo sigue enlaces visibles en el HTML, el fuzzing revela recursos que existen en el servidor pero no están enlazados desde ningún sitio: paneles de administración, backups, ficheros de configuración, endpoints de API sin documentar o entornos de staging olvidados.

Conceptualmente se distinguen cuatro objetivos de fuzzing web:

- **Descubrimiento de rutas**: directorios y ficheros dentro de una misma aplicación.
- **Descubrimiento de hosts virtuales**: aplicaciones distintas servidas bajo la misma IP, diferenciadas por cabecera `Host`.
- **Descubrimiento de parámetros**: nombres de parámetros GET/POST/JSON no documentados que la aplicación procesa internamente.
- **Descubrimiento de comportamiento ante cabeceras**: identificación de cabeceras HTTP que alteran la respuesta (control de acceso, feature flags, cachés) y que pueden usarse para eludir restricciones.

El principal reto no es técnico sino de **señal-ruido**: sin filtrado adecuado, un fuzzing masivo devuelve miles de falsos positivos (páginas de error 200, redirecciones genéricas, contenido dinámico con tamaño variable) que enmascaran los hallazgos reales.

### 2. Diccionarios, generación dinámica y selección de wordlist

La calidad del resultado depende más del diccionario elegido que de la herramienta usada. SecLists es la referencia de facto y viene preinstalada en Kali bajo `/usr/share/seclists/`.

| Wordlist | Ubicación típica | Uso recomendado |
|---|---|---|
| `directory-list-2.3-{small,medium,big}.txt` | `SecLists/Discovery/Web-Content/` | Descubrimiento genérico de directorios, por tamaño según tiempo disponible |
| `raft-{small,medium,large}-directories.txt` | `SecLists/Discovery/Web-Content/` | Diccionarios curados a partir de crawls reales, buena relación cobertura/ruido |
| `raft-{small,medium,large}-files.txt` | `SecLists/Discovery/Web-Content/` | Ficheros concretos en vez de directorios |
| `common.txt` | `SecLists/Discovery/Web-Content/` | Fuzzing rápido inicial, pocos falsos positivos |
| `quickhits.txt` | `SecLists/Discovery/Web-Content/` | Rutas de alta probabilidad (paneles, backups típicos) para una primera pasada |
| `CMS-specific` (WordPress, Joomla, Drupal) | `SecLists/Discovery/Web-Content/CMS/` | Cuando el fingerprinting previo ya identificó el CMS |
| `subdomains-top1million-*.txt` | `SecLists/Discovery/DNS/` | Fuzzing de VHosts y subdominios |
| `burp-parameter-names.txt` | `SecLists/Discovery/Web-Content/` | Fuzzing de parámetros GET/POST |
| `api/api-endpoints.txt`, `api/objects.txt` | `SecLists/Discovery/Web-Content/` | Fuzzing de rutas y recursos típicos de APIs REST |
| `dirb` (`common.txt`, `big.txt`) | `/usr/share/wordlists/dirb/` | Alternativa histórica, más reducida que SecLists |

Además de las wordlists estáticas, conviene generar diccionarios **específicos del objetivo** a partir de su propio contenido, más eficaces que un diccionario genérico cuando la aplicación usa terminología propia (nombres de producto, siglas internas, convenciones de nomenclatura):

<pre class="cmd-block"><code><span class="comment"># CeWL: genera wordlist a partir de las palabras presentes en el sitio, con profundidad de rastreo</span>
<span class="tool">cewl</span> <span class="flag">-d</span> 2 <span class="flag">-m</span> 5 <span class="flag">-w</span> diccionario_objetivo.txt http://dominio.com

<span class="comment"># gau / waybackurls: recupera rutas históricas indexadas por motores de archivo web</span>
<span class="tool">gau</span> dominio.com <span class="flag">--o</span> rutas_historicas.txt
<span class="tool">waybackurls</span> dominio.com &gt; rutas_historicas.txt

<span class="comment"># Combinar y depurar varias fuentes en un único diccionario sin duplicados</span>
<span class="tool">cat</span> rutas_historicas.txt diccionario_objetivo.txt <span class="tool">|</span> <span class="tool">sort</span> <span class="flag">-u</span> &gt; diccionario_final.txt</code></pre>

Un criterio práctico: empezar siempre con un diccionario pequeño (`common.txt` o `quickhits.txt`) para detectar el comportamiento del servidor y calibrar filtros, y solo después escalar a `raft-large`, `directory-list-2.3-big.txt` o un diccionario propio generado con CeWL/gau si el alcance y el tiempo lo permiten.

### 3. ffuf en profundidad

ffuf ("Fuzz Faster U Fool") es actualmente el fuzzer más versátil por su soporte nativo de múltiples puntos de inyección, filtrado avanzado y auto-calibración[web:3][web:6].

#### 3.1. Sintaxis general y fuzzing básico de directorios

La palabra clave `FUZZ` marca el punto de sustitución en la URL, cabeceras o cuerpo de la petición.

<pre class="cmd-block"><code><span class="comment"># Fuzzing básico de directorios</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/common.txt

<span class="comment"># Filtrando por códigos de estado de interés</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/common.txt <span class="flag">-mc</span> 200,204,301,302,307,401,403

<span class="comment"># Excluyendo únicamente los 404 (más ruidoso, útil cuando -mc oculta hallazgos atípicos)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/common.txt <span class="flag">-fc</span> 404</code></pre>

#### 3.2. Fuzzing de extensiones y multi-wordlist

<pre class="cmd-block"><code><span class="comment"># Añade cada extensión a cada palabra del diccionario</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt <span class="flag">-e</span> .php,.html,.txt,.bak,.old,.zip

<span class="comment"># Dos wordlists distintas, cada una con su propia palabra clave</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/USER/PASS <span class="flag">-w</span> usuarios.txt:USER <span class="flag">-w</span> contrasenas.txt:PASS</code></pre>

#### 3.3. Modos de combinación multi-wordlist: clusterbomb, pitchfork y sniper

Cuando se usan dos o más wordlists en la misma petición, ffuf permite elegir cómo se combinan sus entradas mediante `-mode`. La elección del modo tiene un impacto directo en el número de peticiones generadas y, por tanto, en el tiempo total del fuzzing[web:31][web:39].

| Modo | Comportamiento | Número de peticiones | Caso de uso típico |
|---|---|---|---|
| `clusterbomb` (por defecto) | Producto cartesiano: prueba cada entrada de la primera lista contra todas las de la segunda | n₁ × n₂ × ... (crece muy rápido) | Cobertura exhaustiva cuando no hay relación conocida entre las listas |
| `pitchfork` | Combinación posicional: primera entrada de cada lista junto con la primera de las demás, segunda con segunda, y así sucesivamente | máx(n₁, n₂, ...), se detiene en la lista más corta | Pares ya conocidos (usuario:contraseña de una filtración, credenciales emparejadas) |
| `sniper` | Una sola wordlist, probada en cada posición FUZZ por turnos, no simultáneamente | Depende de la wordlist y el número de posiciones | Fuzzing de un mismo diccionario contra varios puntos de inyección sin combinarlos entre sí |

<pre class="cmd-block"><code><span class="comment"># Clusterbomb (explícito, aunque es el modo por defecto): prueba todas las combinaciones usuario/contraseña</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/login <span class="flag">-w</span> usuarios.txt:USER <span class="flag">-w</span> contrasenas.txt:PASS <span class="flag">-X</span> POST <span class="flag">-d</span> "username=USER&password=PASS" <span class="flag">-H</span> "Content-Type: application/x-www-form-urlencoded" <span class="flag">-mode</span> clusterbomb

<span class="comment"># Pitchfork: usuario y contraseña avanzan en paralelo (pares ya conocidos, p. ej. de una filtración)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/login <span class="flag">-w</span> usuarios.txt:USER <span class="flag">-w</span> contrasenas.txt:PASS <span class="flag">-X</span> POST <span class="flag">-d</span> "username=USER&password=PASS" <span class="flag">-H</span> "Content-Type: application/x-www-form-urlencoded" <span class="flag">-mode</span> pitchfork</code></pre>

#### 3.4. Fuzzing recursivo

<pre class="cmd-block"><code><span class="comment"># Fuzzing recursivo: al encontrar un directorio, relanza el diccionario dentro de él</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/common.txt <span class="flag">-recursion</span> <span class="flag">-recursion-depth</span> 2 <span class="flag">-mc</span> 200,301,403

<span class="comment"># Limitando la recursión a una extensión de status concreta y con estrategia de fuzzing especificada</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-recursion</span> <span class="flag">-recursion-depth</span> 3 <span class="flag">-recursion-strategy</span> greedy</code></pre>

#### 3.5. Fuzzing de Virtual Hosts (VHost)

<pre class="cmd-block"><code><span class="comment"># FUZZ en la cabecera Host en vez de en la ruta, para descubrir vhosts tras la misma IP</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://192.168.1.10 <span class="flag">-H</span> "Host: FUZZ.dominio.com" <span class="flag">-w</span> /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt <span class="flag">-fs</span> &lt;tamaño_respuesta_por_defecto&gt;</code></pre>

Es imprescindible filtrar por `-fs` (tamaño de respuesta) en el fuzzing de VHosts, ya que un servidor mal configurado devuelve HTTP 200 con el mismo contenido por defecto para cualquier host no reconocido; sin ese filtro, todo el diccionario aparentaría ser un hallazgo válido.

#### 3.6. Fuzzing de parámetros GET/POST, cuerpos JSON y cookies

<pre class="cmd-block"><code><span class="comment"># Descubrimiento de parámetros GET no documentados</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> "http://dominio.com/buscar.php?FUZZ=valor_prueba" <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt <span class="flag">-fs</span> &lt;tamaño_respuesta_base&gt;

<span class="comment"># Fuzzing de parámetros POST (cuerpo de la petición, formulario clásico)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/login <span class="flag">-X</span> POST <span class="flag">-d</span> "FUZZ=valor_prueba" <span class="flag">-H</span> "Content-Type: application/x-www-form-urlencoded" <span class="flag">-w</span> parametros.txt

<span class="comment"># Fuzzing de un campo dentro de un cuerpo JSON, típico en APIs REST</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/api/v1/login <span class="flag">-X</span> POST <span class="flag">-H</span> "Content-Type: application/json" <span class="flag">-d</span> '{"username":"admin","password":"FUZZ"}' <span class="flag">-w</span> contrasenas.txt <span class="flag">-fc</span> 401

<span class="comment"># Envío de cookies de sesión ya autenticada, para fuzzing de contenido restringido a usuarios logueados</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/panel/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-b</span> "session=&lt;valor&gt;; otra_cookie=&lt;valor&gt;"</code></pre>

#### 3.7. Fuzzing de cabeceras HTTP y bypass de restricciones 401/403

Muchos controles de acceso implementados a nivel de proxy o balanceador confían en cabeceras que el cliente puede falsificar. Fuzzing dirigido a cabeceras y variantes de ruta permite en ocasiones eludir un bloqueo 403/401 sin necesidad de credenciales válidas[web:32].

<pre class="cmd-block"><code><span class="comment"># Fuzzing del valor de una cabecera de origen, para simular que la petición viene de localhost</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/admin <span class="flag">-H</span> "X-Forwarded-For: FUZZ" <span class="flag">-w</span> ips_internas.txt

<span class="comment"># Prueba de múltiples cabeceras de bypass habituales contra una misma ruta bloqueada (un valor por línea del diccionario)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/panel-restringido <span class="flag">-H</span> "FUZZ" <span class="flag">-w</span> cabeceras_bypass_403.txt <span class="flag">-mc</span> 200,301,302

<span class="comment"># Variación de mayúsculas, barras y sufijos sobre una misma ruta bloqueada (bypass por manipulación de path)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> variantes_ruta_403.txt <span class="flag">-mc</span> 200,301,302

<span class="comment"># Fuzzing del método HTTP (verb tampering) contra un mismo endpoint restringido</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/admin <span class="flag">-X</span> FUZZ <span class="flag">-w</span> metodos_http.txt <span class="flag">-mc</span> 200,301,302</code></pre>

Herramientas especializadas como `dontgo403` o el propio módulo de bypass de Trickest automatizan esta combinatoria de cabeceras, rutas y métodos en una sola ejecución, siendo más prácticas que construir manualmente cada diccionario de variantes para un uso recurrente.

#### 3.8. Calibración de resultados y filtrado de falsos positivos

<pre class="cmd-block"><code><span class="comment"># Auto-calibración: detecta y filtra automáticamente respuestas repetitivas de tipo "falso 200" o "falso 404 con código 200"</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-ac</span>

<span class="comment"># Auto-calibración por host, útil en fuzzing de VHosts o de múltiples objetivos a la vez</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-ach</span>

<span class="comment"># Cadena de calibración personalizada (implica -ac)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-acc</span> "404"

<span class="comment"># Filtrado manual combinable: por tamaño, número de palabras y líneas de la respuesta</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-fs</span> 1234 <span class="flag">-fw</span> 42 <span class="flag">-fl</span> 10

<span class="comment"># Filtrado por expresión regular sobre el cuerpo de la respuesta</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-fr</span> "Página no encontrada"

<span class="comment"># Coincidencia (en vez de filtrado) por expresión regular, útil para localizar un mensaje concreto de interés</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-mr</span> "index of|directory listing"</code></pre>

Según la documentación consolidada del propio proyecto, `-ac` debería considerarse un flag prácticamente obligatorio salvo motivo justificado: sin auto-calibración, gran parte del análisis posterior se dedica a descartar ruido manualmente en lugar de a interpretar hallazgos reales[web:26].

#### 3.9. Rendimiento, proxy y exportación

<pre class="cmd-block"><code><span class="comment"># Control de hilos concurrentes (por defecto 40)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-t</span> 100

<span class="comment"># Retardo entre peticiones, fijo o en rango (mitiga rate-limiting y reduce huella en logs)</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-p</span> 0.1
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-p</span> 0.1-0.5

<span class="comment"># Límite de tiempo total de ejecución</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-maxtime</span> 60

<span class="comment"># Enrutado del tráfico a través de Burp Suite u otro proxy, para inspección manual posterior de cada hallazgo</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-x</span> http://127.0.0.1:8080

<span class="comment"># Reanudar una sesión de fuzzing a partir de una petición guardada (formato raw HTTP), reemplazando FUZZ en el fichero</span>
<span class="tool">ffuf</span> <span class="flag">-request</span> peticion_guardada.txt <span class="flag">-request-proto</span> https <span class="flag">-w</span> diccionario.txt

<span class="comment"># Exportación de resultados en varios formatos</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-o</span> resultados.json <span class="flag">-of</span> json
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-o</span> resultados.html <span class="flag">-of</span> html</code></pre>

La opción `-request` es especialmente útil para integrar ffuf con Burp Suite: se envía una petición interceptada a fichero ("Copy to file" o `Ctrl+R`), se sustituye manualmente el valor a fuzzear por `FUZZ` dentro del fichero, y se reproduce con todas las cabeceras, cookies y cuerpo originales intactos.

### 4. Gobuster

Gobuster prioriza velocidad y simplicidad de uso sobre la flexibilidad de filtrado de ffuf; es preferible para pasadas rápidas de descubrimiento en `dir`, `dns`, `vhost`, `fuzz` o `s3` sin necesidad de calibración fina[web:2][web:9].

<pre class="cmd-block"><code><span class="comment"># Enumeración básica de directorios y ficheros</span>
<span class="tool">gobuster</span> <span class="flag">dir</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/common.txt

<span class="comment"># Con extensiones de fichero</span>
<span class="tool">gobuster</span> <span class="flag">dir</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-x</span> php,html,js,txt,bak

<span class="comment"># Filtrado por código de estado y ocultando longitud de respuesta</span>
<span class="tool">gobuster</span> <span class="flag">dir</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-s</span> 200,301,302 <span class="flag">-l</span>

<span class="comment"># Cabeceras y cookies personalizadas (útil tras autenticación previa)</span>
<span class="tool">gobuster</span> <span class="flag">dir</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-H</span> "Authorization: Bearer &lt;token&gt;" <span class="flag">-c</span> "session=&lt;valor&gt;"

<span class="comment"># Enumeración recursiva</span>
<span class="tool">gobuster</span> <span class="flag">dir</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-r</span>

<span class="comment"># Modo DNS: enumeración de subdominios, con resolución de wildcard y CNAME</span>
<span class="tool">gobuster</span> <span class="flag">dns</span> <span class="flag">-d</span> dominio.com <span class="flag">-w</span> /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
<span class="tool">gobuster</span> <span class="flag">dns</span> <span class="flag">-d</span> dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-i</span> <span class="flag">--wildcard</span>

<span class="comment"># Modo VHost: fuzzing de virtual hosts vía cabecera Host</span>
<span class="tool">gobuster</span> <span class="flag">vhost</span> <span class="flag">-u</span> http://dominio.com <span class="flag">-w</span> /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

<span class="comment"># Modo FUZZ: sustituye la palabra clave FUZZ en cualquier parte de la URL, cabeceras o cuerpo (equivalente a ffuf)</span>
<span class="tool">gobuster</span> <span class="flag">fuzz</span> <span class="flag">-u</span> http://dominio.com/index.php?page=FUZZ <span class="flag">-w</span> diccionario.txt

<span class="comment"># Modo S3: enumeración de buckets S3 con nombre predecible a partir de un diccionario</span>
<span class="tool">gobuster</span> <span class="flag">s3</span> <span class="flag">-w</span> nombres_bucket.txt</code></pre>

Un matiz relevante: la propia documentación de Gobuster advierte que el modo `dir` no soporta recursión encadenada de forma nativa en algunas versiones; en esos casos conviene tratar cada directorio hallado como un nuevo objetivo y relanzar el comando manualmente contra él en lugar de asumir cobertura completa con `-r`[web:4].

### 5. feroxbuster

feroxbuster está diseñado específicamente para el descubrimiento **recursivo** de directorios, con paralelización eficiente y detección automática de comportamientos anómalos del servidor[web:1].

<pre class="cmd-block"><code><span class="comment"># Escaneo recursivo por defecto (no requiere flag adicional, a diferencia de ffuf/gobuster)</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

<span class="comment"># Limitando la profundidad de recursión</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">--depth</span> 2

<span class="comment"># Con extensiones y filtrado de códigos de estado</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-x</span> php,html,bak <span class="flag">-C</span> 404,400

<span class="comment"># Filtrado automático de respuestas repetitivas por tamaño de página (equivalente a la auto-calibración de ffuf)</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">--auto-tune</span>

<span class="comment"># Modo silencioso, mostrando solo resultados válidos, útil para integrarlo en scripts</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-q</span> <span class="flag">-s</span>

<span class="comment"># Control de hilos y de tasa de peticiones por segundo</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-t</span> 50 <span class="flag">--rate-limit</span> 100

<span class="comment"># Reanudar un escaneo interrumpido a partir del estado guardado</span>
<span class="tool">feroxbuster</span> <span class="flag">--resume-from</span> estado_guardado.state

<span class="comment"># Exportación de resultados en varios formatos</span>
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-o</span> resultados.txt
<span class="tool">feroxbuster</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">--json</span> <span class="flag">-o</span> resultados.json</code></pre>

### 6. dirsearch

dirsearch aporta una sintaxis de sustitución de extensiones distinta a la de ffuf/gobuster: en vez de anexar la extensión a cada palabra automáticamente, sustituye el marcador `%EXT%` presente en el propio diccionario, salvo que se fuerce lo contrario[web:24][web:27].

<pre class="cmd-block"><code><span class="comment"># Escaneo con extensiones especificadas</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-e</span> php,asp,jsp,html,js

<span class="comment"># Forzar que las extensiones se anexen a cada entrada del diccionario aunque no contenga %EXT%</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-e</span> php,html <span class="flag">-f</span>

<span class="comment"># Excluir extensiones del diccionario</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-X</span> asp,jsp

<span class="comment"># Control de hilos (por defecto 25; cuidado con provocar una denegación de servicio involuntaria)</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-t</span> 50

<span class="comment"># Escaneo recursivo, con control de profundidad máxima</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-w</span> diccionario.txt <span class="flag">-r</span> <span class="flag">--recursion-depth</span> 2

<span class="comment"># Múltiples objetivos desde fichero</span>
<span class="tool">dirsearch</span> <span class="flag">-l</span> objetivos.txt <span class="flag">-e</span> php,html

<span class="comment"># Filtrado por códigos de estado y por expresiones excluidas del cuerpo de respuesta</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">-i</span> 200,204,301,302,403 <span class="flag">--exclude-texts</span> "no encontrado"

<span class="comment"># Uso de proxy para inspección manual con Burp Suite</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">--proxy</span> http://127.0.0.1:8080

<span class="comment"># Exportación de resultados</span>
<span class="tool">dirsearch</span> <span class="flag">-u</span> https://dominio.com <span class="flag">--format</span> json <span class="flag">-o</span> resultados.json</code></pre>

La propia documentación advierte que un número de hilos demasiado alto puede degradar el servicio objetivo hasta el punto de generar una denegación de servicio no intencionada; el límite razonable depende del tiempo de respuesta observado del servidor, no de la capacidad de la máquina atacante[web:27].

### 7. Wfuzz

Wfuzz es más verboso en su sintaxis pero ofrece un control muy fino sobre filtros basados en una petición de referencia (baseline), lo que lo hace útil cuando el servidor tiene páginas de error personalizadas que dificultan distinguir 404 reales de 404 "camuflados" como 200[web:17][web:30].

<pre class="cmd-block"><code><span class="comment"># Fuzzing básico de directorios</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,/usr/share/seclists/Discovery/Web-Content/common.txt http://dominio.com/FUZZ

<span class="comment"># Ocultando por código de respuesta</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,diccionario.txt <span class="flag">--hc</span> 404 http://dominio.com/FUZZ

<span class="comment"># Ocultando por líneas/palabras/caracteres (calibración fina de falsos 404 camuflados de 200)</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,diccionario.txt <span class="flag">--hl</span> 0 <span class="flag">--hw</span> 0 http://dominio.com/FUZZ

<span class="comment"># Petición baseline: la primera respuesta define los valores BBB para comparación relativa</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,diccionario.txt <span class="flag">--hh</span> BBB http://dominio.com/FUZZ{baseline_value}

<span class="comment"># Fuzzing de dos puntos simultáneos con payloads independientes (FUZZ y FUZ2Z)</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,usuarios.txt <span class="flag">-z</span> file,contrasenas.txt "http://dominio.com/login?user=FUZZ&pass=FUZ2Z"

<span class="comment"># Fuzzing de cabeceras HTTP concretas</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,diccionario.txt <span class="flag">-H</span> "X-Forwarded-For: FUZZ" http://dominio.com/admin

<span class="comment"># Fuzzing con payload de tipo rango numérico, útil para IDs secuenciales (p. ej. IDOR)</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> range,1-1000 <span class="flag">--hc</span> 404 "http://dominio.com/api/usuario/FUZZ"

<span class="comment"># Multithreading y exportación a fichero</span>
<span class="tool">wfuzz</span> <span class="flag">-c</span> <span class="flag">-z</span> file,diccionario.txt <span class="flag">-t</span> 50 <span class="flag">-f</span> resultados.txt,raw http://dominio.com/FUZZ</code></pre>

### 8. Enfoque combinado: de la pasada rápida a la exhaustiva

La secuencia recomendada para no invertir tiempo de forma desordenada:

1. **Pasada rápida con diccionario pequeño** (`common.txt` o `quickhits.txt`) usando ffuf o gobuster, para caracterizar el comportamiento del servidor (¿hay página 404 personalizada?, ¿hay redirecciones genéricas?, ¿hay rate-limiting?).
2. **Calibración de filtros** a partir de lo observado en el paso 1: fijar `-fs`/`-fc` en ffuf, `--hc`/`--hl` en Wfuzz, o simplemente activar `-ac` si el comportamiento es consistente.
3. **Pasada con diccionario intermedio** (`raft-medium-directories.txt` o un diccionario generado con CeWL/gau sobre el propio objetivo) y extensiones relevantes según el fingerprinting previo (por ejemplo, `.aspx` si el servidor es IIS, `.php` si es Apache/PHP).
4. **Fuzzing recursivo dirigido** solo sobre los directorios de mayor interés detectados en el paso 3, no sobre todo el árbol, para controlar el tiempo total.
5. **Fuzzing de VHosts, parámetros y cabeceras** en paralelo si el alcance incluye múltiples dominios, aplicaciones con lógica de negocio expuesta vía parámetros GET/POST/JSON, o rutas que devuelven 401/403 y merece la pena intentar eludir.
6. **Revisión manual con proxy** (Burp Suite u otro) de cada hallazgo relevante antes de darlo por confirmado, especialmente en respuestas límite (302 hacia login, 403 con contenido parcial) que la automatización puede clasificar de forma ambigua.

### 9. Evasión y consideraciones frente a WAF/rate-limiting

<pre class="cmd-block"><code><span class="comment"># Reducir hilos y añadir retardo cuando se detecta bloqueo o degradación de respuestas</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-t</span> 5 <span class="flag">-p</span> 1.0-2.0

<span class="comment"># Rotación de User-Agent para evitar firmas triviales de bloqueo por defecto</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-H</span> "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

<span class="comment"># Reintentos automáticos ante códigos de error transitorios (429, 503) típicos de rate-limiting</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-r</span> <span class="flag">-timeout</span> 10

<span class="comment"># Reintento explícito sobre códigos de estado concretos, con límite de intentos</span>
<span class="tool">ffuf</span> <span class="flag">-u</span> http://dominio.com/FUZZ <span class="flag">-w</span> diccionario.txt <span class="flag">-replay-proxy</span> http://127.0.0.1:8080 <span class="flag">-mc</span> 429</code></pre>

Igual que en el escaneo de puertos con Nmap, aquí también existe una tensión entre velocidad y sigilo: un fuzzing con cientos de hilos es más rápido pero dispara con facilidad reglas de rate-limiting o WAF, lo que en la práctica ralentiza el conjunto por reintentos y bloqueos, además de generar un rastro de logs mucho más evidente para el equipo defensor. La opción `-replay-proxy` de ffuf reenvía automáticamente al proxy configurado solo las peticiones que cumplan el matcher indicado, lo que permite revisar en Burp únicamente los casos ambiguos (por ejemplo, respuestas 429) sin tener que enrutar todo el tráfico del fuzzing.

### 10. El puente hacia el análisis de vulnerabilidades

El contenido descubierto por fuzzing alimenta directamente el análisis de vulnerabilidades sobre la aplicación web:

1. **Ficheros de configuración expuestos** (`.env`, `web.config`, `wp-config.php.bak`) pueden revelar credenciales o cadenas de conexión directamente, sin necesidad de explotación adicional.
2. **Paneles de administración descubiertos** se convierten en objetivo de pruebas de autenticación (fuerza bruta acotada, credenciales por defecto) o de vulnerabilidades específicas del panel identificado.
3. **Endpoints de API sin documentar** hallados vía fuzzing de rutas, parámetros o cuerpos JSON se contrastan después con pruebas de control de acceso (IDOR, autorización rota) o de inyección según el método HTTP aceptado.
4. **Backups y ficheros de versión anterior** (`.zip`, `.sql`, `.old`) permiten en ocasiones reconstruir código fuente o esquemas de base de datos sin necesidad de comprometer el servidor.
5. **Rutas bloqueadas con 401/403 eludidas mediante manipulación de cabeceras o método HTTP** exponen directamente una vulnerabilidad de control de acceso que puede documentarse sin necesidad de explotación posterior.

Como en la enumeración de servicios de red, decidir cuánto fuzzing es proporcional al alcance autorizado —profundidad de recursión, tamaño de diccionario, agresividad de hilos, alcance de las pruebas de bypass de 403— es responsabilidad del auditor y debe quedar acotado antes de empezar.

## Análisis y criterio propio

**La auto-calibración cambia la ecuación de tiempo más que cualquier optimización de hilos.** Es tentador centrarse en subir `-t` para ir más rápido, pero el cuello de botella real casi siempre está en distinguir señal de ruido a posteriori. Activar `-ac` desde la primera pasada ahorra más tiempo de análisis que cualquier ganancia de velocidad en la fase de envío de peticiones.

**La recursión indiscriminada es la forma más rápida de agotar el tiempo de una auditoría.** Lanzar `-recursion` o `feroxbuster` por defecto sobre todo un árbol sin acotar profundidad puede multiplicar el número de peticiones de forma no lineal si el servidor tiene muchos directorios "vacíos" que aun así devuelven 200. Es preferible una primera pasada plana, identificar manualmente los 2-3 directorios de interés real, y solo entonces aplicar recursión dirigida sobre ellos.

**El fuzzing de parámetros y de cabeceras se practica mucho menos que el de rutas, y suele ser más rentable.** La mayoría del entrenamiento en laboratorios se centra en encontrar directorios y ficheros, pero muchas aplicaciones modernas exponen su lógica de negocio a través de parámetros GET/POST/JSON no documentados sobre un único endpoint conocido, y muchos controles de acceso mal implementados ceden ante una simple cabecera `X-Forwarded-For` o un cambio de método HTTP. Reservar tiempo específico para fuzzing de parámetros y para pruebas de bypass de 403, además del fuzzing de rutas, cubre una superficie que de otro modo queda completamente fuera del mapa.

**Diccionarios genéricos y diccionarios generados a partir del propio objetivo no son intercambiables.** SecLists cubre bien el caso general, pero una aplicación con nomenclatura propia (nombres de producto, siglas internas, convenciones de commit) esconde rutas que ningún diccionario genérico va a acertar. Combinar CeWL o `gau` con las wordlists estándar suele producir hallazgos que uno u otro enfoque por separado no encuentran.

## Limitaciones

Esta metodología es de propósito general: la profundidad real de cada técnica dependerá del objetivo, el alcance autorizado y el tiempo disponible. La sintaxis exacta de cada herramienta evoluciona con las versiones (especialmente en el caso de ffuf y feroxbuster, con desarrollo activo); conviene verificar la documentación oficial vigente y el `--help` de cada herramienta antes de aplicar cualquier comando en un entorno real. El fuzzing agresivo sin autorización expresa sobre el alcance puede constituir una denegación de servicio involuntaria; su uso debe quedar siempre dentro de los límites acordados con el cliente o la plataforma de práctica. Las técnicas de bypass de 401/403 aquí descritas son de propósito educativo y de auditoría autorizada: aplicarlas contra sistemas sin permiso constituye un acceso no autorizado.

## Conclusiones

El descubrimiento de contenido web es, para las aplicaciones modernas, tan determinante como el escaneo de puertos lo es para la infraestructura de red: un directorio, parámetro o cabecera no explorada es una hipótesis de explotación que nunca llega a plantearse. Documentar esta metodología con sintaxis real de ffuf, Gobuster, feroxbuster, dirsearch y Wfuzz —incluyendo modos multi-wordlist, fuzzing de JSON, bypass de 403 y generación dinámica de diccionarios— junto con los criterios de calibración y de secuenciación, cierra el ciclo de reconocimiento activo iniciado con Nmap y sienta la base para piezas futuras sobre enumeración de Active Directory y análisis de vulnerabilidades web específico.

## Referencias

- [ffuf — Repositorio y documentación oficial](https://github.com/ffuf/ffuf)
- [ffuf — Wiki oficial (modos de entrada, multi-wordlist)](https://github.com/ffuf/ffuf/wiki)
- [ffuf man page (Debian)](https://manpages.debian.org/testing/ffuf/ffuf.1.en.html)
- [Gobuster — Repositorio oficial](https://github.com/OJ/gobuster)
- [feroxbuster — Repositorio oficial](https://github.com/epi052/feroxbuster)
- [dirsearch — Repositorio oficial](https://github.com/maurosoria/dirsearch)
- [Wfuzz man page (Debian)](https://manpages.debian.org/bullseye/wfuzz/wfuzz.1.en.html)
- [SecLists — Repositorio oficial](https://github.com/danielmiessler/SecLists)
- [Trickest — Bypass de endpoints 403](https://trickest.com/blog/bypass-403-endpoints-with-trickest)
- [MITRE ATT&CK — Active Scanning (T1595)](https://attack.mitre.org/techniques/T1595/)
