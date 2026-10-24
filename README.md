# perico
Pentesting Ridícilamente Cómodo. Un simple automatizador de escáneres con kali linux para pentesting web
```
#   ██████╗ ███████╗██████╗ ██╗ ██████╗ ██████╗ 
#   ██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔═══██╗
#   ██████╔╝█████╗  ██████╔╝██║██║     ██║   ██║
#   ██╔═══╝ ██╔══╝  ██╔══██╗██║██║     ██║   ██║
#   ██║     ███████╗██║  ██║██║╚██████╗╚██████╔╝
#   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═════╝ 

    ##     PENTESTING RIDÍCULAMENTE CÓMODO    ##
```

Herramientas que ejecuta:

    Datos de whois
    Info de la IP (ipinfo.io): Proveedor, país...
    testssl: suites de cifrado y posibles vulnerabilidades
    theHarverster: subdominios y correos por OSINT
    nmap: todos los puertos de TCP y los top100 de UDP, con detección de versión y servicio
    wafw00f: por cada puerto http, comprueba si tiene algún WAF
    whatweb: algo de info de las tecnologías usadas
    curl: petición GET y POST a cada puerto http
    wpscan: si whatweb detecta un wordpress, escanea plugins y temas vulnerables y usuarios
    gobuster DNS: bruteforce para detectar subdominios
    gobuster DIR: para detectar directorios
    wapiti: busca varias vulnerabilidades (XSS, LFI. SQLi..)


![image](https://github.com/joseaguardia/perico/assets/16305835/53799cc8-c60b-4e48-a3c1-2393e2964dc7)


## Ejecución

En el primer arranque el contenedor instala todo lo necesario (paquetes, testssl, identYwaf y las wordlists de SecLists), así que ten paciencia: puede tardar varios minutos.

### Docker (Ubuntu, Debian...)

```
docker compose up -d
docker exec -it kali perico dominio.com
```

### Podman (Fedora, RHEL, Kinoite...)

Podman tiene dos diferencias frente a Docker que hay que tener en cuenta:

- **SELinux**: los volúmenes necesitan la opción `:Z` para que el contenedor pueda leerlos (ya incluida en `docker-compose.yaml`).
- **Capabilities de red**: `nmap` usa escaneo SYN/UDP y necesita `CAP_NET_RAW`. Docker lo concede por defecto; Podman **rootless no**, y además el escaneo a través de la red rootless es poco fiable. Por eso en Podman hay que lanzarlo **rootful** (con `sudo`), que es justo como corre Docker (su demonio es root).

Lo más sencillo y fiable es lanzarlo con `podman run` (ejecuta los comandos desde la carpeta del repo):

```
sudo podman run -d --name kali --hostname kali-docker --restart unless-stopped \
  --cap-add NET_RAW --cap-add NET_ADMIN --cap-add SYS_MODULE \
  -e TZ=Europe/Madrid \
  -v "$(pwd)/perico:/root/proyectos_hack:Z" \
  -v "$(pwd)/entrypoint.sh:/entrypoint.sh:Z" \
  --entrypoint /entrypoint.sh \
  docker.io/kalilinux/kali-rolling sleep infinity

sudo podman exec -it kali perico dominio.com
```

> Para usar los tokens de wpscan/AbuseIPDB, crea un archivo `.env` (copia de `.env.example`) y añade `--env-file .env` al comando `run`.

