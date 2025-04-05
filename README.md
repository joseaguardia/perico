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


Para ejecutarlo desde docker en cualquier sistema:
```
docker compose up -d
docker exec -it kali perico dominio.com
```
En el primer "up" instala todo lo necesario, así que ten un poco de paciencia, puede tardar varios minutos :)

