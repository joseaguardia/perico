#!/bin/bash

#	  $$$$$$$\  $$$$$$$$\ $$$$$$$\  $$$$$$\  $$$$$$\   $$$$$$\  
#	  $$  __$$\ $$  _____|$$  __$$\ \_$$  _|$$  __$$\ $$  __$$\ 
#	  $$ |  $$ |$$ |      $$ |  $$ |  $$ |  $$ /  \__|$$ /  $$ |
#	  $$$$$$$  |$$$$$\    $$$$$$$  |  $$ |  $$ |      $$ |  $$ |
#	  $$  ____/ $$  __|   $$  __$$<   $$ |  $$ |      $$ |  $$ |
#	  $$ |      $$ |      $$ |  $$ |  $$ |  $$ |  $$\ $$ |  $$ |
#	  $$ |      $$$$$$$$\ $$ |  $$ |$$$$$$\ \$$$$$$  | $$$$$$  |
#	  \__|      \________|\__|  \__|\______| \______/  \______/ 

    ###        	PENTESTING RIDÍCULAMENTE CÓMODO            ###

# Recibe en $1 una IP o una URL y en $2 el nivel [low|high]
# y lanza ciertos escáneres guardando todo en archivos en una misma carpeta

# !! Es necesario instalar gobuster y jq


#Coge el token de las variables del sistema
#Añade 'export WPSCAN_TOKEN='1234567890qwertyuiopasdfghjkl' a .zshrc o .bashrc o descomenta la siguiente línea
#WPSCAN_TOKEN='1234567890qwertyuiopasdfghjkl'

#Contador de tiempo a cero
SECONDS=0


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

  echo "Error al crear $RUTA, posiblemente ya exista"
  exit 1

fi

cd $RUTA

#Creamos un archivo para las notas
touch $RUTA/_notas.txt


### ATACA PERICO, ATACA !!


#whois
#Solo lo lanza si es un dominio (no funcionará en .es y otros dominios)
if ! [[ $SITIO =~ $IP ]]; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+]\e[0m Comprobando datos de whois..." | tee -a $RUTA/RESUMEN.txt
  whois -H "$SITIO" | egrep -iv '(#|please query|personal data|redacted|whois|you agree)' | sed '/^$/d' > $RUTA/whois.txt
fi


#IP Info
if ! [[ $SITIO =~ $IP ]]; then
  IP="$(dig +short $SITIO)"
else
  IP="$SITIO"
fi
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Obteniendo información de la IP (${IP})" | tee -a $RUTA/RESUMEN.txt
curl -s "https://ipinfo.io/${IP}" > $RUTA/IP_info-${IP}.txt
echo "$(cat $RUTA/IP_info-${IP}.txt  | jq '.org + " - " + .city + " (" + .country + ")"')" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


#SSL
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Verificando configuración SSL..." | tee -a $RUTA/RESUMEN.txt
sslyze $SITIO --resum --reneg --heartbleed --certinfo --sslv2 --sslv3 --openssl_ccs > $RUTA/SSL.txt
grep "Session Renegotiation:\|SSL 3.0 Cipher Suites:\|OpenSSL CCS Injection\|OpenSSL Heartbleed" SSL.txt -A1 | grep -v '\-\-' | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


#theHarvester
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Obteniendo datos con theHarvester..." | tee -a $RUTA/RESUMEN.txt
theHarvester -d $SITIO -b all -f $RUTA/theHarvester.txt > /dev/null
jq . $RUTA/theHarvester.json > $RUTA/theHarvester_pretty.json && rm -f $RUTA/theHarvester.json && rm -f $RUTA/theHarvester.xml
cat theHarvester_pretty.json | jq '.emails, .hosts' | grep -v "\[\|\]" | tr -d '"' | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


#nmap
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Pasando nmap..." | tee -a $RUTA/RESUMEN.txt
if [[ $NIVEL = "high" ]]; then 
  nmap -T4 --open -n -Pn -p- -sV -sC -O -oG $RUTA/nmap_TCP_completo.txt $SITIO > /dev/null
  nmap -T4 --open -n -Pn -p- -sU -sV -sC -O -oG $RUTA/nmap_UDP_completo.txt $SITIO > /dev/null
else
  nmap -T4 --open -n -Pn -sV -oG $RUTA/nmap_TCP_simple.txt $SITIO > /dev/null
  nmap -T4 --open -n -Pn --top-ports 100 -sU -sV -oG $RUTA/nmap_UDP_simple.txt $SITIO > /dev/null
fi
cat $RUTA/nmap_*_simple.txt | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


#wafw00f por cada puerto HTTP, tanto http como https
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Comprobando WAF con wafw00f..." | tee -a $RUTA/RESUMEN.txt
grep "Ports: " $RUTA/nmap_*.txt  | tr ' ' \\n | grep http | cut -d '/' -f1 | while read PORT; do
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


#whatweb por cada puerto http detectado en nmap
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Detectando versiones y tipo de CMS con whatweb..."
touch $RUTA/whatweb.txt
grep "Ports: " $RUTA/nmap_*.txt  | tr ' ' \\n | grep http | cut -d '/' -f1 | while read PORT; do
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


#curl (solo cabeceras y estados) por cada puerto http detectado en nmap
echo | tee -a $RUTA/RESUMEN.txt
echo "i\e[32m[+]\e[0m Sacando cabeceras y estados con curl..."
echo "." > $RUTA/curl.txt
grep "Ports: " $RUTA/nmap_*.txt  | tr ' ' \\n | grep http | cut -d '/' -f1 | while read PORT; do
  echo "Puerto $PORT:" >> $RUTA/curl.txt
  echo "Por http:" >> $RUTA/curl.txt
  curl -kLIs http://$SITIO:$PORT >> $RUTA/curl.txt
  echo "Por https:" >> $RUTA/curl.txt
  curl -kLIs https://$SITIO:$PORT >> $RUTA/curl.txt
  echo "---" >> $RUTA/curl.txt
done


#wpscan
if grep -i "WordPress" $RUTA/whatweb.txt > /dev/null; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+]\e[0m Pasando wpscan..."
  wpscan --update > /dev/null
  wpscan --url http://$SITIO --enumerate vp,vt,dbe,cb --plugins-detection mixed --random-user-agent -o $RUTA/wpscan.txt --api-token "$WPSCAN_TOKEN"
  cat wpscan.txt | grep "\[\!\]" | sed 's/^[[:space:]]*//g' | tr -d '|' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
fi


#gobuster DNS
if ! [[ $SITIO =~ $IP ]]; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+]\e[0m Pasando gobuster para subdominios..." | tee -a $RUTA/RESUMEN.txt
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
fi


#gobuster directorios
if [[ $NIVEL = "high" ]]; then
  WORDLIST='/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt'
else
  WORDLIST='/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt'
fi

echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+]\e[0m Pasando gobuster DIR con diccionario $(rev <<<$WORDLIST | cut -d '/' -f1 | rev)"
gobuster dir --follow-redirect --random-agent -s "200,204,301,302,307,401" -b "" -w $WORDLIST -u https://$SITIO -q -o $RUTA/gobuster_dir.txt > /dev/null
cat $RUTA/gobuster_dir.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
echo "  Directorios protegidos con contraseña (Código 401):"  | tee -a $RUTA/RESUMEN.txt
grep "Status: 401" gobuster_dir.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


#Si whatweb nos dice que es un WordPress, lanzamos otros gobuster específico para WP
if grep -i "WordPress" $RUTA/whatweb.txt > /dev/null; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+]\e[0m Pasando gobuster específico para WordPress..."

  #Buscar directorios específicos de WP
  gobuster dir --follow-redirect --random-agent -s "200,204,301,302,307,401" -b "" -w /usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt -u https://$SITIO -q -o $RUTA/gobuster_dir_WP.txt > /dev/null

  #Fuzzing al archivo wp-config con varias extensiones
  gobuster fuzz --follow-redirect --random-agent --excludestatuscodes "300-302,400-404,500-503" --url https://${SITIO}/wp-configFUZZ --wordlist /opt/perico/wordlist/extensiones_wp_backs.txt -q -o $RUTA/gobuster_wpconfig.txt > /dev/null
cat $RUTA/gobuster_wpconfig.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
fi


#uniscan
if [[ $NIVEL = "high" ]]; then
  echo | tee -a $RUTA/RESUMEN.txt 
  echo -e "\e[32m[+]\e[0m Pasando uniscan..." | tee -a $RUTA/RESUMEN.txt
  uniscan -u https://$SITIO -qwedsgj > $RUTA/uniscan.txt
fi


#nikto
if [[ $NIVEL = "high" ]]; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+]\e[0m Escaneando con nikto..." | tee -a $RUTA/RESUMEN.txt
  nikto -followredirects -useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36" -nointeractive -Format txt -output $RUTA/nikto.txt -h $SITIO > /dev/null
fi



# Venga Perico, a dormir la siesta que te lo has ganado

echo | tee -a $RUTA/RESUMEN.txt
echo "Todas las pruebas terminadas en $(date -u -d @${SECONDS} +'%Hh:%Mm')" | tee -a $RUTA/RESUMEN.txt
