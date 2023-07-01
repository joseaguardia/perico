#!/bin/bash

#Versión: 20230701a

#https://github.com/joseaguardia/perico


#   ██████╗ ███████╗██████╗ ██╗ ██████╗ ██████╗ 
#   ██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔═══██╗
#   ██████╔╝█████╗  ██████╔╝██║██║     ██║   ██║
#   ██╔═══╝ ██╔══╝  ██╔══██╗██║██║     ██║   ██║
#   ██║     ███████╗██║  ██║██║╚██████╗╚██████╔╝
#   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═════╝ 

    ##     PENTESTING RIDÍCULAMENTE CÓMODO    ##


# Recibe en $1 una IP o una URL y en $2 el nivel [null|high]
# y lanza algunas herramientas guardando todo en archivos en una misma carpeta
# y haciendo un resumen rápido

#Todo:
# Unificar diccionarios para wp en gobuster
#/usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt


### REQUISITOS
# Instalar gobuster y jq
# Clonar https://github.com/danielmiessler/SecLists
# Clonar en /opt https://github.com/drwetter/testssl.sh.git

#Descomenta la siguiente línea y pon el token para la API de WPSCAN
#WPSCAN_TOKEN='1234567890qwertyuiopasdfghjkl'



#Contador de tiempo a cero
SECONDS=0

#Colores
color_letras="\e[30m"  
color_fondo="\e[42m"   
reset="\e[0m"          

#Debe venir la URL o IP como $1
if [[ -z $1 ]]; then
  echo 'Hay que pasar la URL o IP como $1'
  exit 1
fi

#Si no hay nivel en $2, ponemos por defecto nivel LOW
if [[ -z $2 ]]; then
  #Nivel de escaneado (influye en el tamaño de diccionarios y en las herramientas usadas). [low|high]
  NIVEL='low'
else
  NIVEL="$2"
fi
  
#ExprReg para ver si es una IP
IP='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'


#Dejamos la URL limpia, quitando protocolo y espacios
SITIO="$(sed 's/http[s]\?:\/\///' <<<$1 | tr -d '/' | tr -d ' ')"

#Sacamos el dominio raíz si no es una IP, por si pasamos un sudominio
if ! [[ $SITIO =~ $IP ]]; then
  DOMINIO="$(rev <<<$SITIO | cut -d '.' -f1,2 | rev)"
fi

#Ruta raíz para guardar proyectos:
RUTA="/root/proyectos_hack/$SITIO"


#Crear carpeta del proyecto
if mkdir -p $RUTA ; then

  echo "Creada carpeta $RUTA"

else

  echo "[!] Error al crear $RUTA, posiblemente ya exista"
  exit 1

fi

cd $RUTA

#Creamos un archivo para las notas manuales
touch $RUTA/_notas.txt


### ATACA PERICO, ATACA !!

##########################
#   whois
##########################
#Solo lo lanza si es un dominio (no funcionará en .es y otros dominios)
if ! [[ $SITIO =~ $IP ]]; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Comprobando datos de whois\e[0m" | tee -a $RUTA/RESUMEN.txt
  whois -H "$SITIO" | egrep -iv '(#|please query|personal data|redacted|whois|you agree)' | sed '/^$/d' > $RUTA/whois.txt
  grep "Registrar URL:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  grep "Creation Date:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  grep "Registry Expiry Date:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  #echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"
fi


##########################
#   IP Info
##########################
if ! [[ $SITIO =~ $IP ]]; then
  IP="$(dig +short $SITIO)"
else
  IP="$SITIO"
fi
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Obteniendo información de la IP (${IP})\e[0m" | tee -a $RUTA/RESUMEN.txt
curl -s "https://ipinfo.io/${IP}" > $RUTA/IP_info-${IP}.txt
echo "$(cat $RUTA/IP_info-${IP}.txt  | jq '.org + " - " + .city + " (" + .country + ")"')" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ]${reset} [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   SSL
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Verificando configuración SSL\e[0m" | tee -a $RUTA/RESUMEN.txt
/opt/testssl.sh/testssl.sh --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36" --protocols --vulnerable --quiet $SITIO > $RUTA/SSL.txt
echo | openssl s_client -connect ${SITIO}:443 2>/dev/null | openssl x509 -noout -dates -issuer | grep -i "notAfter\|issuer" | tac | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
grep -v "(OK)" $RUTA/SSL.txt | grep -v "not offered" | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ]${reset} [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   theHarvester
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Obteniendo datos con theHarvester\e[0m" | tee -a $RUTA/RESUMEN.txt
theHarvester -d $SITIO -b all -f $RUTA/theHarvester.txt > /dev/null
jq . $RUTA/theHarvester.json > $RUTA/theHarvester_pretty.json && rm -f $RUTA/theHarvester.json && rm -f $RUTA/theHarvester.xml
cat theHarvester_pretty.json | jq '.emails, .hosts' | grep -v "\[\|\]" | tr -d '"' | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ]${reset} [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   nmap
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Pasando nmap para TCP\e[0m" | tee -a $RUTA/RESUMEN.txt
nmap -T4 --open -n -Pn -p- -sV -sC -O -oG $RUTA/nmap_TCP_grepeable.txt -oN $RUTA/nmap_TCP_completo.txt $SITIO > /dev/null
#Si marcamos 'high', lanzamos también escaneo UDP
if [[ $NIVEL = "high" ]]; then
  echo -e "\e[32m[+]\e[0m Pasando nmap para UDP..." | tee -a $RUTA/RESUMEN.txt
  nmap -T4 --open -n -Pn --top-ports 100 -sU -sV -oG $RUTA/nmap_UDP_grepeable.txt -oN $RUTA/nmap_UDP_completo.txt $SITIO > /dev/null
fi
cat $RUTA/nmap_*_grepeable.txt | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ]${reset} [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   wafw00f
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Comprobando WAF con wafw00f\e[0m" | tee -a $RUTA/RESUMEN.txt
grep "Ports: " $RUTA/nmap_*grepeable.txt  | tr ' ' \\n | grep http | grep -v httpd | cut -d '/' -f1 | sort -u | while read PORT; do
  if [[ $PORT = "443" ]] || [[ $PORT = "8443" ]]; then
    PROTOCOLO="https"
  else
    PROTOCOLO="http"
  fi
  wafw00f -o /tmp/wafw00f_${PROTOCOLO}_${SITIO}_puerto$PORT.txt $PROTOCOLO://$SITIO:$PORT > /dev/null
  echo "\\n" >> /tmp/wafw00f_${PROTOCOLO}_${SITIO}_puerto$PORT.txt    #Añadimos una nueva línea al final
done
#Unimos las salidas en un mismo archivo
cat /tmp/wafw00f_http*${SITIO}*.txt > $RUTA/wafw00f.txt && rm -f /tmp/wafw00f_http*${SITIO}*.txt
cat $RUTA/wafw00f.txt | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ]${reset} [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   whatweb
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Detectando tecnologías y CMS con whatweb\e[0m" | tee -a $RUTA/RESUMEN.txt
touch $RUTA/whatweb.txt
grep "Ports: " $RUTA/nmap_*grepeable.txt  | tr ' ' \\n | grep "http" | grep -v "httpd" | cut -d '/' -f1 | while read PORT; do
  if [[ $PORT = "443" ]] || [[ $PORT = "8443" ]]; then
    PROTOCOLO="https"
  else
    PROTOCOLO="http"
  fi

  echo "Puerto $PORT por ${PROTOCOLO}:" >> $RUTA/whatweb.txt
  whatweb --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" ${PROTOCOLO}://$SITIO:$PORT >> $RUTA/whatweb.txt
  echo "---" >> $RUTA/whatweb.txt
done
cat $RUTA/whatweb.txt | fold -w 155 | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ]${reset} [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   curl 
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Sacando cabeceras y estados con curl\e[0m" | tee -a $RUTA/RESUMEN.txt
echo "." > $RUTA/curl.txt
grep "Ports: " $RUTA/nmap_*grepeable.txt  | tr ' ' \\n | grep http | cut -d '/' -f1 | while read PORT; do
  echo "Puerto $PORT:" >> $RUTA/curl.txt
  echo "Por http (GET):" >> $RUTA/curl.txt
  curl -kLIs http://$SITIO:$PORT | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  echo "Por https: (GET)" >> $RUTA/curl.txt
  curl -kLIs https://$SITIO:$PORT | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  echo "Por http (POST):" >> $RUTA/curl.txt
  curl -X POST -kLIs http://$SITIO:$PORT | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  echo "Por https: (POST)" >> $RUTA/curl.txt
  curl -X POST -kLIs https://$SITIO:$PORT | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  echo "---" >> $RUTA/curl.txt
done
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ]${reset} [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"


##########################
#   wpscan
##########################
if grep -i "WordPress" $RUTA/whatweb.txt > /dev/null; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Detectada instalación de wordpress. Pasando wpscan\e[0m" | tee -a $RUTA/RESUMEN.txt
  wpscan --update > /dev/null
  wpscan --url http://$SITIO --enumerate vp,vt,dbe,cb,u --plugins-detection mixed --random-user-agent -o $RUTA/wpscan.txt --api-token "$WPSCAN_TOKEN"
  cat wpscan.txt | grep "\[\!\]" | grep -v "The version is out of date" | sed 's/^[[:space:]]*//g' | tr -d '|' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  #echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ]${reset} [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]\r"
fi


##########################
#   gobuster DNS
##########################
if ! [[ $SITIO =~ $IP ]]; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Pasando gobuster para subdominios\e[0m" | tee -a $RUTA/RESUMEN.txt
  if [[ $NIVEL = "high" ]]; then
    WORDLIST='/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt'
  else
    WORDLIST='/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt'
  fi

  gobuster dns -d $DOMINIO -z -q -o /tmp/gobuster_subdomains_$SITIO.txt -w $WORDLIST > /dev/null

  #Quitamos duplicados
  cat /tmp/gobuster_subdomains_$SITIO.txt | tr '[:upper:]' '[:lower:]' | grep . | sort | uniq > $RUTA/gobuster_subdomains.txt
  rm /tmp/gobuster_subdomains_$SITIO.txt -f
  cat $RUTA/gobuster_subdomains.txt | sed 's/found: //g' | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  #echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ]${reset} [ GOBUSTER DIR ] [ WAPITI ]\r"
fi


##########################
#   gobuster DIR
##########################
if [[ $NIVEL = "high" ]]; then
  WORDLIST='/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt'
else
  WORDLIST='/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
fi

echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Pasando gobuster DIR con diccionario $(rev <<<$WORDLIST | cut -d '/' -f1 | rev)\e[0m" | tee -a $RUTA/RESUMEN.txt
gobuster dir --random-agent -s "200,204,302,307,401" -b "" -w $WORDLIST -u https://$SITIO -q -o $RUTA/gobuster_dir.txt > /dev/null
echo "    Directorios encontrados (Código 200):"  | tee -a $RUTA/RESUMEN.txt
cat $RUTA/gobuster_dir.txt | grep -v "(Status: 301)\|(Status: 302)\|(Status: 401)" | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
echo "    Directorios protegidos con contraseña (Código 401):"  | tee -a $RUTA/RESUMEN.txt
grep "Status: 401" gobuster_dir.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ]${reset} [ WAPITI ]\r"


##########################
#   gobuster FUZZ
##########################
EXTENSIONES="html,js,log,php,sh,sql,dmp,txt,cfg,yml,conf,gz,tgz,tar.gz,zip,rar,bak,new"
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Buscando archivos con extensiones $EXTENSIONES\e[0m" | tee -a $RUTA/RESUMEN.txt
echo $EXTENSIONES | tr ',' \\n | while read EXTENSION; do
  gobuster fuzz --follow-redirect --random-agent --excludestatuscodes "300-302,400-404,500-503" --exclude-length 0 --url https://${SITIO}/FUZZ.$EXTENSION --wordlist /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -q -o $RUTA/gobuster_archivos_${EXTESION}.txt > /dev/null 
done
#Unificamos las salidas
cat $RUTA/gobuster_archivos_*.txt > $RUTA/gobuster_extensiones.txt
cat $RUTA/gobuster_extensiones.txt | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
rm -f $RUTA/gobuster_archivos_*.txt


#Si whatweb nos dice que es un WordPress, lanzamos otros gobuster específico para WP
if grep -i "WordPress" $RUTA/whatweb.txt > /dev/null; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Buscando backups de wp-config.php de WordPress\e[0m" | tee -a $RUTA/RESUMEN.txt

  #Fuzzing al archivo wp-config con varias extensiones
  gobuster fuzz --follow-redirect --random-agent --excludestatuscodes "300-302,400-404,500-503" --url https://${SITIO}/wp-configFUZZ --wordlist /opt/perico/wordlist/extensiones_wp_backs.txt -q -o $RUTA/gobuster_wpconfig.txt > /dev/null
cat $RUTA/gobuster_wpconfig.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
fi


##########################
#   wapiti
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Escaneando con wapiti\e[0m" | tee -a $RUTA/RESUMEN.txt
wapiti -u http://$SITIO -o $RUTA/wapiti.txt -f txt >/dev/null
sed -n '/Summary of vulnerabilities/,/\*\*\*\*/p' $RUTA/wapiti.txt | grep -v "\*\*\*" | grep -v ":   0" | tee -a $RUTA/RESUMEN.txt
#echo -ne "${color_letras}${color_fondo}[ WHOIS ] [ IPInfo ] [ SSL ] [ HARVESTER ] [ NMAP ] [ WAFW00F ] [ WHATWEB ] [ CURL ] [ WPSCAN ] [ GOBUSTER DNS ] [ GOBUSTER DIR ] [ WAPITI ]${reset}\r"


#Eliminamos archivos que ya no son necesarios:
rm -f $RUTA/nmap_*_grepeable.txt


# Venga Perico, a dormir la siesta que te lo has ganado

echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32mTodas las pruebas terminadas en $(date -u -d @${SECONDS} +'%Hh:%Mm')\e[0m" | tee -a $RUTA/RESUMEN.txt
