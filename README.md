# Ne0t3k Hugo

Este repositorio contiene un sitio Hugo diseñado para GitHub Pages.

## Publicar por primera vez en GitHub

1. Descarga y descomprime este proyecto.
2. En tu repositorio `Ne0t3k.github.io`, elimina el antiguo `index.html`.
3. Sube **el contenido descomprimido** de esta carpeta al directorio raíz del repositorio. Debes ver `hugo.toml`, `content`, `layouts`, `assets` y `.github` en la raíz; no una carpeta adicional que los contenga.
4. Haz commit de los cambios.
5. Abre `Settings` → `Pages` y cambia **Source** a **GitHub Actions**. No selecciones `Deploy from a branch`.
6. Abre `Actions`. El workflow `Publicar sitio Hugo en GitHub Pages` construirá y desplegará el sitio. Cuando aparezca en verde, estará disponible en `https://ne0t3k.github.io/`.

## Crear una publicación

Crea un archivo en una de estas ubicaciones:

- `content/writeups/nombre-del-reto.md`
- `content/investigaciones/nombre-de-la-investigacion.md`
- `content/reflexiones/titulo-de-la-reflexion.md`

Usa esta plantilla:

```md
---
title: "Título de la publicación"
date: 2026-08-09T10:00:00+02:00
description: "Resumen breve que aparecerá en las tarjetas y buscadores."
plataforma: "Hack The Box" # opcional
categorias: ["Write-ups"]
etiquetas: ["ctf", "web"]
draft: false
---

## Resumen

Escribe aquí.
```

Haz commit. Hugo crea automáticamente la página, el índice, las etiquetas, las categorías, el tiempo de lectura, la tabla de contenidos y los enlaces relacionados.

## Vista previa local opcional

En Linux/Kali instala Hugo y ejecuta el servidor local desde la raíz del proyecto:

```bash
sudo apt update
sudo apt install hugo
hugo server -D
```

Abre la URL indicada por Hugo, normalmente `http://localhost:1313/`. Para producción, `draft` debe ser `false`.
