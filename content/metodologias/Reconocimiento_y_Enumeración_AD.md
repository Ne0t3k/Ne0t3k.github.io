---
title: "Metodología de reconocimiento y enumeración en Active Directory"
date: 2026-09-09
draft: true
tags: ["red-team", "reconocimiento", "enumeracion", "active-directory", "kerberos", "metodologia"]
categories: ["metodologias"]
summary: "Metodología para las fases de reconocimiento y enumeración en entornos Active Directory: descubrimiento del dominio, enumeración sin credenciales, LDAP, SMB, Kerberos, RID brute-force y recolección de relaciones con BloodHound."
---

## Introducción

Esta pieza continúa la metodología de reconocimiento y enumeración documentada para entornos genéricos, aplicada ahora a **Active Directory (AD)**. AD introduce una superficie de enumeración propia que no existe en un host aislado: un directorio LDAP con todo el árbol de objetos del dominio, un servicio Kerberos con comportamiento distinto según exista o no una cuenta, y un protocolo SMB/RPC heredado que, mal asegurado, sigue exponiendo listados completos de usuarios y grupos sin autenticación.

El objetivo es el mismo que en la pieza anterior: una referencia propia, verificada y con comandos reales, que cubra el recorrido lógico de la fase de reconocimiento en AD antes de plantear cualquier vector de explotación. Esta pieza cubre exclusivamente **descubrimiento y enumeración**; los ataques de obtención de credenciales (Kerberoasting activo, AS-REP Roasting, pass-the-hash y similares) quedan fuera de alcance y se documentarán en una pieza posterior centrada en explotación.

## Alcance

Esta metodología cubre:

- Descubrimiento del dominio: identificación de controladores de dominio (DC) mediante registros SRV de DNS.
- Enumeración sin credenciales (null session / bind anónimo): `enum4linux-ng`, `rpcclient`, `smbclient`.
- Fundamento y explotación del RID brute-force a partir de la estructura del SID.
- Enumeración LDAP con y sin autenticación, con filtros sobre `userAccountControl`: `ldapsearch`.
- Enumeración con credenciales de bajo privilegio: `netexec` (continuación mantenida de `crackmapexec`).
- Enumeración de usuarios vía Kerberos sin credenciales: `kerbrute`, y el mecanismo AS-REQ/AS-REP que lo hace posible.
- Enumeración de shares SMB: `smbmap`, `smbclient`.
- Recolección de relaciones y rutas de ataque: `BloodHound` mediante `bloodhound-python`.
- Enumeración de política de contraseñas y de objetos con delegación configurada.

## Metodología

### 1. Descubrimiento del dominio

Antes de enumerar, conviene confirmar la existencia de un dominio Active Directory y localizar su controlador. A diferencia de un host cualquiera, un DC se autoanuncia: publica registros SRV de DNS para que los propios equipos miembros del dominio puedan localizar automáticamente los servicios de Kerberos, LDAP y el Global Catalog sin configuración manual. Esa misma información sirve para el reconocimiento externo.

| Registro SRV | Servicio que localiza | Puerto asociado |
|---|---|---|
| `_ldap._tcp.dc._msdcs.<dominio>` | Controladores de dominio con servicio LDAP | 389 |
| `_kerberos._tcp.<dominio>` | Key Distribution Center (KDC) | 88 |
| `_gc._tcp.<dominio>` | Global Catalog (bosque completo) | 3268 |
| `_kpasswd._tcp.<dominio>` | Servicio de cambio de contraseña Kerberos | 464 |
| `_ldap._tcp.pdc._msdcs.<dominio>` | DC con el rol PDC Emulator (FSMO) | 389 |

<pre class="cmd-block"><code><span class="comment"># Resolución básica del nombre de dominio</span>
<span class="tool">nslookup</span> dominio.local

<span class="comment"># Localización del controlador de dominio vía registro SRV de LDAP</span>
<span class="tool">nslookup</span> <span class="flag">-type=SRV</span> _ldap._tcp.dc._msdcs.dominio.local

<span class="comment"># Localización del KDC de Kerberos vía registro SRV</span>
<span class="tool">nslookup</span> <span class="flag">-type=SRV</span> _kerberos._tcp.dominio.local

<span class="comment"># Localización del Global Catalog (bosques con varios dominios)</span>
<span class="tool">nslookup</span> <span class="flag">-type=SRV</span> _gc._tcp.dominio.local

<span class="comment"># Localización del DC con el rol PDC Emulator</span>
<span class="tool">nslookup</span> <span class="flag">-type=SRV</span> _ldap._tcp.pdc._msdcs.dominio.local

<span class="comment"># Equivalentes con dig</span>
<span class="tool">dig</span> _ldap._tcp.dc._msdcs.dominio.local <span class="flag">SRV</span>
<span class="tool">dig</span> _kerberos._tcp.dominio.local <span class="flag">SRV</span>
<span class="tool">dig</span> _gc._tcp.dominio.local <span class="flag">SRV</span>

<span class="comment"># Transferencia de zona DNS, si el servidor la permite (poco habitual pero de alto valor si funciona)</span>
<span class="tool">dig</span> <span class="flag">axfr</span> dominio.local <span class="flag">@</span>192.168.1.10</code></pre>

Confirmado el DC, conviene lanzar sobre él el escaneo de puertos genérico ya cubierto en la metodología anterior, ya que el conjunto de puertos abiertos por sí solo confirma el rol de la máquina como controlador de dominio antes de enumerar nada más:

<pre class="cmd-block"><code><span class="comment"># Puertos característicos de un controlador de dominio en una sola pasada</span>
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">-p</span> 53,88,135,139,389,445,464,593,636,3268,3269 192.168.1.10

<span class="comment"># Con scripts NSE de descubrimiento de AD incluidos</span>
<span class="tool">nmap</span> <span class="flag">-sV</span> <span class="flag">-p</span> 389,636,3268,3269 <span class="flag">--script</span> ldap-rootdse 192.168.1.10</code></pre>

### 2. Enumeración sin credenciales (null session)

Una **null session** es una conexión SMB establecida sin usuario ni contraseña (`-U "" -N`, en la sintaxis de las herramientas Samba). Es un remanente de versiones antiguas de Windows que muchos entornos siguen sin bloquear del todo: aunque las políticas modernas restringen el acceso anónimo a gran parte del árbol, ciertas consultas RPC (`enumdomusers`, `enumdomgroups`, `querydominfo`) pueden seguir respondiendo sin autenticación si el `RestrictAnonymous` del DC no está en su valor más restrictivo.

<pre class="cmd-block"><code><span class="comment"># Enumeración completa sin credenciales (equivale a -U -G -S -P -O -N)</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-A</span> 192.168.1.10

<span class="comment"># Solo usuarios vía RPC/SAM</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-U</span> 192.168.1.10

<span class="comment"># Solo grupos, incluyendo sus miembros con el modificador de detalle</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-G</span> <span class="flag">-d</span> 192.168.1.10

<span class="comment"># Shares vía RPC</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-S</span> 192.168.1.10

<span class="comment"># Política de contraseñas del dominio</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-P</span> 192.168.1.10

<span class="comment"># Información del sistema operativo del DC</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-O</span> 192.168.1.10

<span class="comment"># Enumeración vía LDAP (además de RPC)</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-L</span> 192.168.1.10

<span class="comment"># RID cycling con rango de RID personalizado (por defecto 500-550,1000-1050)</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-R</span> <span class="flag">-r</span> 500-1500 192.168.1.10

<span class="comment"># Con credenciales válidas, para ampliar el detalle obtenido</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-A</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' 192.168.1.10

<span class="comment"># Exportar resultados en JSON para procesarlos con otra herramienta</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-A</span> <span class="flag">-oJ</span> resultado 192.168.1.10</code></pre>

Con `rpcclient` se obtiene una sesión interactiva sobre el named pipe RPC, lo que permite ejecutar los mismos comandos que `enum4linux-ng` automatiza, pero de forma manual y encadenable:

<pre class="cmd-block"><code><span class="comment"># Sesión nula interactiva</span>
<span class="tool">rpcclient</span> <span class="flag">-U</span> "" <span class="flag">-N</span> 192.168.1.10

<span class="comment"># Sesión autenticada con credenciales válidas</span>
<span class="tool">rpcclient</span> <span class="flag">-U</span> usuario<span class="flag">%</span>contraseña 192.168.1.10

<span class="comment"># --- Comandos dentro de la sesión interactiva de rpcclient ---</span>

<span class="comment"># Enumerar usuarios del dominio</span>
enumdomusers

<span class="comment"># Enumerar grupos del dominio</span>
enumdomgroups

<span class="comment"># Enumerar alias (grupos locales del dominio)</span>
enumalsgroups domain

<span class="comment"># Información general del dominio: nombre NetBIOS, SID, número de usuarios</span>
querydominfo

<span class="comment"># Información detallada de cuentas, incluye descripciones y comentarios</span>
querydispinfo

<span class="comment"># Política de contraseñas: longitud mínima, complejidad, bloqueo de cuenta</span>
getdompwinfo

<span class="comment"># Detalle de un usuario concreto a partir de su RID</span>
queryuser 0x3e8

<span class="comment"># Grupos a los que pertenece un usuario concreto</span>
queryusergroups 0x3e8

<span class="comment"># Miembros de un grupo concreto a partir de su RID</span>
querygroupmem 0x200

<span class="comment"># Listado de nombres de share disponibles</span>
netshareenum

<span class="comment"># Información detallada de shares (incluye rutas y comentarios)</span>
netshareenumall

<span class="comment"># Enumerar impresoras compartidas, si las hubiera</span>
enumprinters

<span class="comment"># --- Fuera de la sesión interactiva: ejecutar un único comando ---</span>
<span class="tool">rpcclient</span> <span class="flag">-U</span> "" <span class="flag">-N</span> 192.168.1.10 <span class="flag">-c</span> "enumdomusers"
<span class="tool">rpcclient</span> <span class="flag">-U</span> "" <span class="flag">-N</span> 192.168.1.10 <span class="flag">-c</span> "querydominfo"</code></pre>

`smbclient` permite, además, listar los recursos compartidos visibles sin autenticación, lo que en ocasiones expone carpetas de despliegue, scripts de inicio de sesión o copias de seguridad accesibles por error:

<pre class="cmd-block"><code><span class="comment"># Listado de shares con sesión nula</span>
<span class="tool">smbclient</span> <span class="flag">-L</span> //192.168.1.10 <span class="flag">-N</span>

<span class="comment"># Listado de shares con credenciales válidas</span>
<span class="tool">smbclient</span> <span class="flag">-L</span> //192.168.1.10 <span class="flag">-U</span> usuario

<span class="comment"># Conexión interactiva a un share concreto, sesión nula</span>
<span class="tool">smbclient</span> //192.168.1.10/share <span class="flag">-N</span>

<span class="comment"># Conexión interactiva a un share concreto, con credenciales</span>
<span class="tool">smbclient</span> //192.168.1.10/share <span class="flag">-U</span> usuario<span class="flag">%</span>contraseña

<span class="comment"># --- Dentro de la sesión interactiva de smbclient ---</span>

<span class="comment"># Listar contenido del directorio actual</span>
ls

<span class="comment"># Descargar un fichero concreto</span>
get fichero.txt

<span class="comment"># Descargar todo el contenido del share de forma recursiva</span>
prompt off
recurse on
mget *</code></pre>

### 3. RID brute-force: por qué funciona incluso sin sesión LDAP

Cada objeto de seguridad en AD (usuario, grupo, equipo) tiene un **SID** (Security Identifier) con la forma `S-1-5-21-<identificador-de-dominio>-<RID>`. El identificador de dominio es fijo para todo el directorio; el **RID** (Relative Identifier) es el número que distingue a cada objeto dentro de ese dominio, y varios RID están reservados por convención independientemente del entorno:

| RID | Objeto |
|---|---|
| 500 | Administrador local/de dominio por defecto |
| 501 | Cuenta de invitado (Guest) |
| 502 | Cuenta KRBTGT (clave del propio Kerberos) |
| 512 | Grupo Domain Admins |
| 513 | Grupo Domain Users |
| 515 | Grupo Domain Computers |
| 519 | Grupo Enterprise Admins |

Como el identificador de dominio se puede obtener con una sola consulta (`querydominfo` en `rpcclient`, o directamente vía SMB con `netexec`), la enumeración de usuarios se reduce a **incrementar el RID sobre un identificador de dominio ya conocido** y consultar qué SID resuelve a un nombre de cuenta válido, sin necesidad de bind LDAP ni de conocer usuarios de antemano.

<pre class="cmd-block"><code><span class="comment"># RID brute-force vía netexec, sin necesidad de sesión LDAP</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--rid-brute</span>

<span class="comment"># RID brute-force acotando el rango máximo de RID a probar</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--rid-brute</span> 5000

<span class="comment"># RID brute-force con credenciales válidas (más fiable si el anónimo está restringido)</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--rid-brute</span> 10000

<span class="comment"># RID cycling equivalente desde enum4linux-ng, con rango personalizado</span>
<span class="tool">enum4linux-ng</span> <span class="flag">-R</span> <span class="flag">-r</span> 500-2000 192.168.1.10

<span class="comment"># Resolución manual de un SID conocido a nombre, vía rpcclient</span>
<span class="tool">rpcclient</span> <span class="flag">-U</span> "" <span class="flag">-N</span> 192.168.1.10 <span class="flag">-c</span> "lookupsids S-1-5-21-1234567890-1234567890-1234567890-500"</code></pre>

### 4. Enumeración LDAP

El servicio LDAP del controlador de dominio (puerto 389, o 636 para LDAPS cifrado) expone el árbol de directorio completo: usuarios, grupos, unidades organizativas, políticas de grupo (GPO) y ACLs. Muchos DC permiten un **bind anónimo** de solo lectura sobre determinados atributos (en particular el `defaultNamingContext`, el DN base del dominio), aunque las versiones de Windows Server recientes lo restringen por defecto salvo configuración explícita.

El atributo `userAccountControl` es una máscara de bits que codifica el estado de cada cuenta (activa, deshabilitada, contraseña sin caducidad, pre-autenticación desactivada, delegación...), y buena parte de la enumeración LDAP útil consiste en filtrar por bits concretos de ese atributo mediante el operador `LDAP_MATCHING_RULE_BIT_AND` (`1.2.840.113556.1.4.803`).

<pre class="cmd-block"><code><span class="comment"># Obtener el base DN del dominio con bind anónimo</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-s</span> base <span class="flag">-b</span> "" "(objectClass=*)" defaultNamingContext

<span class="comment"># Consulta anónima completa sobre el base DN del dominio, si el bind anónimo está permitido</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-b</span> "DC=dominio,DC=local" "(objectClass=*)"

<span class="comment"># Consulta autenticada con credenciales válidas, filtrando solo cuentas de usuario</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(objectClass=user)"

<span class="comment"># Limitar los atributos devueltos a sAMAccountName, para un listado limpio de cuentas</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectClass=user)(sAMAccountName=*))" sAMAccountName

<span class="comment"># Solo cuentas de equipo (computer objects)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(objectClass=computer)"

<span class="comment"># Solo grupos, con su distinguishedName</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(objectClass=group)" dn

<span class="comment"># Miembros de un grupo concreto (p. ej. Domain Admins)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=dominio,DC=local))"

<span class="comment"># Cuentas habilitadas únicamente (excluye el bit ACCOUNTDISABLE = 2)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

<span class="comment"># Cuentas con contraseña que nunca caduca (bit DONT_EXPIRE_PASSWORD = 65536)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"

<span class="comment"># Cuentas con pre-autenticación Kerberos desactivada (bit DONT_REQ_PREAUTH = 4194304)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"

<span class="comment"># Cuentas con delegación sin restricciones (bit TRUSTED_FOR_DELEGATION = 524288)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(userAccountControl:1.2.840.113556.1.4.803:=524288)"

<span class="comment"># Cuentas de servicio con SPN definido (candidatas a Kerberoasting en fase de explotación)</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-D</span> "usuario@dominio.local" <span class="flag">-w</span> 'contraseña' <span class="flag">-b</span> "DC=dominio,DC=local" "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName

<span class="comment"># Consulta anónima al RootDSE, para descubrir naming contexts sin conocer el dominio de antemano</span>
<span class="tool">ldapsearch</span> <span class="flag">-H</span> ldap://192.168.1.10 <span class="flag">-x</span> <span class="flag">-s</span> base <span class="flag">-b</span> "" "(objectClass=*)"</code></pre>

### 5. Enumeración con credenciales de bajo privilegio: netexec

`netexec` (continuación mantenida del proyecto `crackmapexec`, hoy archivado) centraliza enumeración SMB y LDAP contra Active Directory, tanto en modo anónimo como autenticado, y sustituye buena parte de lo que antes requería combinar `rpcclient`, `smbclient` y `ldapsearch` por separado.

<pre class="cmd-block"><code><span class="comment"># Comprobación anónima básica del host: SO, nombre de dominio, si exige firma SMB</span>
<span class="tool">netexec</span> smb 192.168.1.10

<span class="comment"># Contra un rango completo, para identificar todos los DC de una subred</span>
<span class="tool">netexec</span> smb 192.168.1.0/24

<span class="comment"># Listado de shares con sesión nula</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--shares</span>

<span class="comment"># Enumeración de usuarios del dominio vía SAMR</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--users</span>

<span class="comment"># Enumeración de grupos del dominio</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--groups</span>

<span class="comment"># Política de contraseñas sin credenciales, si el anónimo lo permite</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> '' <span class="flag">-p</span> '' <span class="flag">--pass-pol</span>

<span class="comment"># Con credenciales válidas de bajo privilegio: usuarios, grupos y política en una sola pasada</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--users</span> <span class="flag">--groups</span> <span class="flag">--pass-pol</span>

<span class="comment"># Password spraying con una única contraseña contra una lista de usuarios (validación de credenciales, no enumeración pura)</span>
<span class="tool">netexec</span> smb 192.168.1.10 <span class="flag">-u</span> usuarios.txt <span class="flag">-p</span> 'Temporada2026!' <span class="flag">--continue-on-success</span>

<span class="comment"># Enumeración vía LDAP con credenciales válidas</span>
<span class="tool">netexec</span> ldap 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--users</span>

<span class="comment"># Cuentas con delegación sin restricciones, sin requisito de contraseña, o con admin-count activo</span>
<span class="tool">netexec</span> ldap 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--trusted-for-delegation</span> <span class="flag">--password-not-required</span> <span class="flag">--admin-count</span>

<span class="comment"># Cuentas de servicio con SPN, vía LDAP (equivalente al filtro manual de ldapsearch)</span>
<span class="tool">netexec</span> ldap 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--kerberoasting</span> spns.txt

<span class="comment"># Política de contraseñas vía LDAP (a veces más completa que la vista por SMB)</span>
<span class="tool">netexec</span> ldap 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--pass-pol</span>

<span class="comment"># Listado de controladores de dominio del bosque</span>
<span class="tool">netexec</span> ldap 192.168.1.10 <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">--dc-list</span></code></pre>

El indicador `admin-count` merece explicación aparte: cuando una cuenta pertenece (o ha pertenecido alguna vez) a un grupo protegido como Domain Admins, AD marca su atributo `adminCount` a `1` y aplica una ACL heredada que sobrevive aunque después se saque a la cuenta del grupo. Filtrar por `admin-count` es, en la práctica, una forma de encontrar cuentas con privilegios elevados en su historial aunque ya no figuren en el grupo actual.

### 6. Enumeración de usuarios vía Kerberos: fundamento y kerbrute

Kerberos permite enumerar cuentas válidas sin credenciales aprovechando cómo responde el KDC (Key Distribution Center, el servicio Kerberos del DC) a una solicitud de ticket. El primer mensaje del protocolo de autenticación es un **AS-REQ** (Authentication Service Request): el cliente pide un TGT (Ticket Granting Ticket) indicando el nombre de usuario. Desde Windows 2000, todas las cuentas requieren por defecto **pre-autenticación**: el AS-REQ debe incluir un timestamp cifrado con la clave derivada de la contraseña del usuario, como prueba de que quien pide el ticket conoce esa contraseña.

El matiz que hace posible la enumeración está en qué responde el KDC cuando ese timestamp cifrado falta o es incorrecto, y esa respuesta **depende de si el usuario existe**:

| Respuesta del KDC | Código de error | Significado |
|---|---|---|
| `KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 | El usuario no existe en el directorio |
| `KRB5KDC_ERR_PREAUTH_REQUIRED` | 25 | El usuario existe y requiere pre-autenticación (comportamiento normal) |
| AS-REP válido, sin error | 0 | El usuario existe y tiene la pre-autenticación desactivada (`DONT_REQ_PREAUTH`) |

Es decir: tanto el error 25 como una respuesta sin error confirman la existencia del usuario, mientras que el error 6 la descarta. Esta enumeración no queda registrada como intento de inicio de sesión fallido en los logs habituales de autenticación, y no genera bloqueos de cuenta, porque desde el punto de vista del KDC no se ha llegado a intentar una autenticación completa.

<pre class="cmd-block"><code><span class="comment"># Enumeración de usuarios válidos a partir de una lista, contra un DC concreto</span>
<span class="tool">kerbrute</span> userenum <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 usuarios.txt

<span class="comment"># Guardando los resultados en un fichero</span>
<span class="tool">kerbrute</span> userenum <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 <span class="flag">-o</span> usuarios_validos.txt usuarios.txt

<span class="comment"># Modo seguro: aborta el proceso si detecta un bloqueo de cuenta durante la enumeración</span>
<span class="tool">kerbrute</span> userenum <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 <span class="flag">--safe</span> usuarios.txt

<span class="comment"># Aumentar el número de hilos para acelerar la enumeración en listas grandes</span>
<span class="tool">kerbrute</span> userenum <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 <span class="flag">-t</span> 100 usuarios.txt

<span class="comment"># Modo verboso, mostrando también los intentos fallidos, útil para depurar conectividad</span>
<span class="tool">kerbrute</span> userenum <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 <span class="flag">-v</span> usuarios.txt

<span class="comment"># Password spraying con kerbrute (validación de credenciales, no enumeración pura)</span>
<span class="tool">kerbrute</span> passwordspray <span class="flag">-d</span> dominio.local <span class="flag">--dc</span> 192.168.1.10 usuarios_validos.txt 'Temporada2026!'</code></pre>

Cuando `kerbrute` encuentra una cuenta con pre-autenticación desactivada (la tercera fila de la tabla anterior), esa cuenta es candidata directa a AS-REP Roasting: la extracción del ticket queda fuera del alcance de reconocimiento y pertenece a la fase de explotación, pero identificar esas cuentas sí es parte legítima de la enumeración.

### 7. Enumeración de shares SMB: smbmap

`smbmap` complementa a `smbclient` mostrando de forma más directa los permisos efectivos (lectura, escritura, denegado) sobre cada share visible, en lugar de tener que probar la conexión share por share.

<pre class="cmd-block"><code><span class="comment"># Listado de shares y permisos con sesión nula</span>
<span class="tool">smbmap</span> <span class="flag">-H</span> 192.168.1.10

<span class="comment"># Listado con credenciales válidas</span>
<span class="tool">smbmap</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-H</span> 192.168.1.10

<span class="comment"># Contra un dominio completo especificando el nombre de dominio</span>
<span class="tool">smbmap</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-d</span> dominio.local <span class="flag">-H</span> 192.168.1.10

<span class="comment"># Recorrido recursivo de un share concreto, listando todo su contenido</span>
<span class="tool">smbmap</span> <span class="flag">-R</span> share <span class="flag">-H</span> 192.168.1.10

<span class="comment"># Recorrido recursivo de todos los shares accesibles</span>
<span class="tool">smbmap</span> <span class="flag">-R</span> <span class="flag">-H</span> 192.168.1.10

<span class="comment"># Búsqueda de un patrón de nombre de fichero en todos los shares accesibles</span>
<span class="tool">smbmap</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-H</span> 192.168.1.10 <span class="flag">-A</span> "contraseña" <span class="flag">-R</span>

<span class="comment"># Descarga de un fichero concreto de un share</span>
<span class="tool">smbmap</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-H</span> 192.168.1.10 <span class="flag">--download</span> "share\ruta\fichero.txt"</code></pre>

### 8. Recolección de relaciones: BloodHound

`BloodHound` no enumera un dato aislado, sino las **relaciones** entre objetos del directorio: pertenencia a grupos (incluida la anidada), sesiones de usuario activas en cada equipo, ACLs sobre objetos concretos, y relaciones de delegación Kerberos. El valor no está en un solo dato, sino en el grafo resultante: una cuenta de bajo privilegio puede tener, por una cadena de tres o cuatro relaciones heredadas, un camino real hacia Domain Admins que ninguna herramienta de enumeración aislada mostraría por sí sola.

Existen tres tipos de delegación Kerberos que BloodHound señala explícitamente por su relevancia como vector de escalada, y que conviene poder identificar en el grafo antes de plantear cualquier explotación:

- **Delegación sin restricciones** (*unconstrained delegation*): el equipo o servicio puede reutilizar el TGT de cualquier usuario que se autentique contra él frente a cualquier otro servicio del dominio.
- **Delegación restringida** (*constrained delegation*): el servicio solo puede reutilizar credenciales para autenticarse frente a una lista concreta de servicios de destino.
- **Delegación restringida basada en recursos** (*RBCD*, resource-based constrained delegation): es el recurso de destino, no el servicio de origen, quien decide qué cuentas pueden delegar hacia él.

`bloodhound-python` es el recolector en Python, útil cuando se trabaja desde Linux sin necesidad de ejecutar binarios en el entorno Windows objetivo (alternativa a `SharpHound`, que se ejecuta de forma nativa en PowerShell/.NET dentro del dominio).

<pre class="cmd-block"><code><span class="comment"># Recolección completa con credenciales válidas, indicando el DC como servidor DNS</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> All

<span class="comment"># Recolección limitada a información del controlador de dominio (más rápida, menos ruidosa)</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> DCOnly

<span class="comment"># Acumular varios métodos de recolección concretos, separados por comas</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> Group,Session,ACL

<span class="comment"># Solo información de sesiones activas (la parte más lenta y más ruidosa)</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> Session

<span class="comment"># Solo relaciones de confianza entre dominios/bosques</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> Trusts

<span class="comment"># Autenticación mediante hash NTLM en lugar de contraseña en claro</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">--hashes</span> :hashntlm <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> All

<span class="comment"># Empaquetar la salida en un único zip para importar en la interfaz de BloodHound</span>
<span class="tool">bloodhound-python</span> <span class="flag">-u</span> usuario <span class="flag">-p</span> 'contraseña' <span class="flag">-ns</span> 192.168.1.10 <span class="flag">-d</span> dominio.local <span class="flag">-c</span> All <span class="flag">--zip</span></code></pre>

Acotar el método de recolección (`Group,Session,ACL` frente a `All`) tiene sentido operativo en entornos grandes o cuando el objetivo es minimizar el tráfico generado contra el DC: `Session` en particular requiere consultar cada equipo del inventario uno por uno, lo que en un dominio con miles de máquinas es la parte más lenta y más ruidosa de toda la recolección.

## Análisis y criterio propio

**El bind LDAP anónimo ya es la excepción, no el punto de partida real.** Rara vez devuelve más que el `defaultNamingContext` del RootDSE en entornos con un mínimo de hardening. El verdadero punto de inflexión de la fase sigue siendo la primera credencial válida, por bajo que sea su privilegio: a partir de ahí, LDAP autenticado con filtros de `userAccountControl` da más información accionable en una sola consulta que combinar `rpcclient` y `smbmap` durante media hora.

**El RID brute-force se sobrevalora como técnica de descubrimiento y se infravalora como técnica de confirmación.** Su aporte real no es encontrar usuarios al azar, sino revelar la convención de nombres del dominio (`nombre.apellido`, inicial+apellido...) a partir de un puñado de aciertos; esa convención es la que después alimenta cualquier lista para `kerbrute` o un password spray. Tratarlo como un fin en sí mismo, en vez de como insumo para lo siguiente, es el error más habitual.

**`kerbrute` compite con LDAP en sigilo, no en profundidad.** No aporta ni de lejos el contexto que da LDAP autenticado, pero es la única técnica de esta pieza que no toca SMB ni RPC, lo que importa en entornos con EDR agresivo monitorizando named pipes. Validar una lista de candidatos por Kerberos antes de lanzar una sesión SMB completa es más prudente que asumir que toda enumeración pesa lo mismo en términos de detección.

## Limitaciones

Esta metodología es de propósito general: la disponibilidad real de sesiones nulas, bind LDAP anónimo o RID brute-force sin credenciales depende del hardening del entorno concreto, cada vez más restrictivo por defecto en despliegues recientes. La sintaxis de las herramientas evoluciona entre versiones; conviene verificar la documentación oficial vigente antes de aplicar cualquier comando en un entorno real. Los ejemplos de salida no se incluyen porque no proceden de una ejecución verificada propia en el momento de escribir esta pieza.

## Conclusiones

El reconocimiento en Active Directory condiciona todo lo que viene después igual que en cualquier otro test de intrusión, pero con una asimetría propia: el directorio expone voluntariamente gran parte de su estructura a quien sepa dónde preguntar, sin necesidad de explotar nada. Tener esta metodología documentada, verificada y con comandos reales sirve como punto de partida repetible, y queda como base para una pieza futura centrada en explotación —Kerberoasting, AS-REP Roasting, abuso de delegación— sobre los mismos hallazgos que aquí solo se identifican.

## Referencias

- [MITRE ATT&CK — Reconnaissance (TA0043)](https://attack.mitre.org/tactics/TA0043/)
- [MITRE ATT&CK — Discovery (TA0007)](https://attack.mitre.org/tactics/TA0007/)
- [MITRE ATT&CK — Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [enum4linux-ng — GitHub](https://github.com/cddmp/enum4linux-ng)
- [NetExec — GitHub](https://github.com/Pennyw0rth/NetExec)
- [Kerbrute — GitHub](https://github.com/ropnop/kerbrute)
- [BloodHound.py — GitHub](https://github.com/dirkjanm/BloodHound.py)
- [rpcclient(1) — Samba man pages](https://man.archlinux.org/man/rpcclient.1.en)
- [RFC 4120 — The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120)
