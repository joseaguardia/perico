#!/bin/bash

#Versión: 20230719

#https://github.com/joseaguardia/perico

clear
echo -e "\e[1;35m"
echo -e "   ██████╗ ███████╗██████╗ ██╗ ██████╗ ██████╗ "
echo -e "   ██╔══██╗██╔════╝██╔══██╗██║██╔════╝██╔═══██╗"
echo -e "   ██████╔╝█████╗  ██████╔╝██║██║     ██║   ██║"
echo -e "   ██╔═══╝ ██╔══╝  ██╔══██╗██║██║     ██║   ██║"
echo -e "   ██║     ███████╗██║  ██║██║╚██████╗╚██████╔╝"
echo -e "   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═════╝ "
echo -e "\e[0m"
echo "   ##     PENTESTING RIDÍCULAMENTE CÓMODO    ##"
echo
echo

# Recibe en $1 una IP o una URL y lanza algunas herramientas básicas de pentesting
# guardando todo en archivos en una misma carpeta y haciendo un resumen rápido
# Al terminar pregunta si quieres lanzar un escaneo más profundo

#Todo:
# Preguntar si se quiere pasar gobuster DIR y FUZZ en el resto de subdominios encontrados en la misma máquina
# XssPy.py o xxser?
# Spider de comentarios <!--
# Gestion de errores en gobuster

### REQUISITOS
# Instalar gobuster, cmseek y jq
# Clonar https://github.com/danielmiessler/SecLists en /usr/share/wordlists
# Clonar https://github.com/drwetter/testssl.sh.git en /opt

#Configura el token de la API de WPSCAN
#WPSCAN_TOKEN='1234567890qwertyuiopasdfghjkl'



#Contador de tiempo a cero
SECONDS=0

#Debe venir la URL o IP como $1
if [[ -z $1 ]]; then
  echo 'Hay que pasar la URL o IP como $1'
  exit 1
fi
  
#Para sitios sin SSL, $2 debe valer http
if [[ $2 = "http" ]]; then
  HTTP="http"
else
  HTTP="https"
fi


#ExprReg para ver si es una IP
IP='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'


#Dejamos la URL limpia, quitando protocolo y espacios
SITIO="$(sed 's/http[s]\?:\/\///' <<<$1 | tr -d '/' | tr -d ' ')"

#Sacamos el dominio raíz si no es una IP, por si pasamos un sudominio
if ! [[ $SITIO =~ $IP ]]; then
  DOMINIO="$(rev <<<$SITIO | cut -d '.' -f1,2 | rev)"
  DOMINIO_ROOT="$(rev <<<$SITIO | cut -d '.' -f1 | rev)"
fi

#Ruta raíz para guardar proyectos:
RUTA="/root/proyectos_hack/$SITIO"

if [[ -e $RUTA ]]; then 
  echo
  echo -e "\e[1;35m[?] ¿La carpeta $RUTA ya existe. Eliminar su contenido y continuar\e[0m"
  read -p "[y/N] " CONTINUAR
  if ! [[ $CONTINUAR = "Y" || $CONTINUAR = "y" ]]; then
    exit 1
  fi
  rm -rf $RUTA/*
fi

mkdir -p $RUTA
echo " " | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[i] Creada carpeta $RUTA\e[0m" | tee -a $RUTA/RESUMEN.txt

cd $RUTA

#Creamos un archivo para las notas manuales
touch $RUTA/_notas.txt


### ATACA PERICO, ATACA !!

##########################
#   whois
##########################
#Solo lo lanza si no es un dominio .es
if ! [[ $DOMINIO_ROOT = "es" ]]; then
	if ! [[ $SITIO =~ $IP ]]; then
	  echo | tee -a $RUTA/RESUMEN.txt
	  echo -e "\e[32m[+] Comprobando datos de whois\e[0m" | tee -a $RUTA/RESUMEN.txt
	  whois -H "$DOMINIO" | egrep -iv '(#|please query|personal data|redacted|whois|you agree)' | sed '/^$/d' > $RUTA/whois.txt
	  grep "Registrar URL:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
	  grep "Creation Date:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
	  grep "Registry Expiry Date:" $RUTA/whois.txt | head -1 | cut -d 'T' -f1 | xargs | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
	fi
fi


##########################
#   IP Info
##########################
if ! [[ $SITIO =~ $IP ]]; then
  IPSITIO="$(dig +short $SITIO | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
else
  IPSITIO="$SITIO"
fi
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Obteniendo información de la IP (${IPSITIO})\e[0m" | tee -a $RUTA/RESUMEN.txt
curl -s "https://ipinfo.io/${IPSITIO}" > $RUTA/IP_info-${IPSITIO}.txt
echo "$(cat $RUTA/IP_info-${IPSITIO}.txt  | jq '.org + " - " + .city + " (" + .country + ")"')" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


##########################
#   nmap TCP básico
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Pasando nmap para TCP\e[0m" | tee -a $RUTA/RESUMEN.txt
nmap -T3 -sS --open -n -Pn -p- -oG $RUTA/nmap_TCP_grepeable.txt -oN $RUTA/nmap_TCP_completo.txt $SITIO > /dev/null
cat $RUTA/nmap_TCP_grepeable.txt | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


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
  wafw00f -o /tmp/wafw00f_${PROTOCOLO}_${SITIO}_puerto$PORT.txt $PROTOCOLO://$SITIO:$PORT > /dev/null 2>/dev/null
  echo -e "\n" >> /tmp/wafw00f_${PROTOCOLO}_${SITIO}_puerto$PORT.txt    #Añadimos una nueva línea al final
done
#Unimos las salidas en un mismo archivo
cat /tmp/wafw00f_http*${SITIO}*.txt > $RUTA/wafw00f.txt && rm -f /tmp/wafw00f_http*${SITIO}*.txt
cat $RUTA/wafw00f.txt | sed 's/(None)//g' | awk '{gsub(/None/, "\033[32m&\033[0m")}1' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


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
cat $RUTA/whatweb.txt | fold -w 165 | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


##########################
#   cmseek
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Detectando CMS con cmseek\e[0m" | tee -a $RUTA/RESUMEN.txt
cmseek --random-agent --batch --follow-redirect --url ${HTTP}://$SITIO >/dev/null
cat /usr/share/cmseek/Result/${SITIO}/cms.json | jq | tee -a $RUTA/RESUMEN.txt $RUTA/cmseek.txt
rm -f /usr/share/cmseek/Result/${SITIO}/cms.json


##########################
#   robots.txt 
##########################
echo -e "\e[32m[+] Archivo robots.txt\e[0m" | tee -a $RUTA/RESUMEN.txt
if ! curl ${HTTP}://$SITIO/robots.txt -Lks | grep -qi "404\|Captcha"; then
  echo | tee -a $RUTA/RESUMEN.txt
  curl ${HTTP}://$SITIO/robots.txt -Lks | grep . | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
else  
  echo -e "\t\e[1;35m[!] Archivo robots.txt no encontrado o tiene captcha\e[0m" | tee -a $RUTA/RESUMEN.txt
fi

##########################
#   curl 
##########################
echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Sacando cabeceras y estados con curl\e[0m" | tee -a $RUTA/RESUMEN.txt
echo "." > $RUTA/curl.txt
grep "Ports: " $RUTA/nmap_*grepeable.txt  | tr ' ' \\n | grep "http" | grep -v "httpd" | cut -d '/' -f1 | while read PORT; do

  #GET
  if [[ $PORT =~ 443 ]]; then
    echo -e "\t\e[32mGET\e[0m https://${SITIO}:\e[32m$PORT\e[0m" | tee -a $RUTA/RESUMEN.txt $RUTA/curl.txt
    curl -X GET -kLIs https://$SITIO:$PORT | grep "HTTP/" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
    echo "---" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  else
    echo -e "\t\e[32mGET\e[0m http://${SITIO}:\e[32m$PORT\e[0m" | tee -a $RUTA/RESUMEN.txt $RUTA/curl.txt
    curl -X GET -kLIs http://$SITIO:$PORT | grep "HTTP/" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
    echo "---" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  fi 

  #POST
  if [[ $PORT =~ 443 ]]; then
    echo -e "\t\e[32mPOST\e[0m https://${SITIO}:\e[32m$PORT\e[0m" | tee -a $RUTA/RESUMEN.txt $RUTA/curl.txt
    curl -X POST -kLIs https://$SITIO:$PORT | grep "HTTP/" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
    echo "---" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  else
    echo -e "\t\e[32mPOST\e[0m http://${SITIO}:\e[32m$PORT\e[0m" | tee -a $RUTA/RESUMEN.txt $RUTA/curl.txt
    curl -X POST -kLIs http://$SITIO:$PORT | grep "HTTP/" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
    echo "---" | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
  fi 

done


##########################
#   wpscan
##########################
if grep -i "WordPress" $RUTA/whatweb.txt > /dev/null; then
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Detectada instalación de wordpress. Pasando wpscan\e[0m" | tee -a $RUTA/RESUMEN.txt
  wpscan --update > /dev/null
  wpscan --url ${HTTP}://$SITIO --enumerate vp,vt,dbe,cb,u --plugins-detection mixed --random-user-agent -o $RUTA/wpscan.txt --api-token "$WPSCAN_TOKEN"
  cat wpscan.txt | grep "\[\!\]\|Scan Aborted" | grep -v "The version is out of date" | sed 's/^[[:space:]]*//g' | tr -d '|' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
fi


##########################
#   gobuster DIR small
##########################

#WORDLIST='/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt'
WORDLIST='/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt'

echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32m[+] Pasando gobuster DIR con diccionario $(rev <<<$WORDLIST | cut -d '/' -f1 | rev)\e[0m" | tee -a $RUTA/RESUMEN.txt
gobuster dir --timeout 3s --threads 10 --random-agent -s "200,204,302,307,401" -b "" -w $WORDLIST -u ${HTTP}://$SITIO -o $RUTA/gobuster_dir_small.txt 2>$RUTA/gobuster_errores.log | grep -v "Timeout:\|Method:\|Status codes:\|Starting gobuster in directory enumeration mode\|\=\=\=\|Gobuster v3.\|by OJ Reeves\|User Agent:\|Threads:"
echo " " | tee -a $RUTA/RESUMEN.txt
echo -e "    Directorios \e[32mencontrados\e[0m (Código 200):"  | tee -a $RUTA/RESUMEN.txt
cat $RUTA/gobuster_dir_small.txt | grep -v "(Status: 301)\|(Status: 302)\|(Status: 401)" | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
echo -e "    Directorios \e[32mprotegidos\e[0m con contraseña (Código 401):"  | tee -a $RUTA/RESUMEN.txt
grep "Status: 401" gobuster_dir_small.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
echo -e "    \e[1;35m[!!] Errores: $(grep -c '[ERROR]' $RUTA/gobuster_errores.log) / $(wc -l $WORDLIST | cut -d ' ' -f1)\e[0m" | tee -a $RUTA/RESUMEN.txt
###rm -f $RUTA/gobuster_errores.log

echo | tee -a $RUTA/RESUMEN.txt
echo -e "\e[32mPruebas iniciales terminadas en $(date -u -d @${SECONDS} +'%Hh:%Mm')\e[0m" | tee -a $RUTA/RESUMEN.txt


################################################
## Continuar con escaneo más profundo
################################################
echo
echo -e "\e[1;35m[?] ¿Quieres continuar con un escaneo más profundo?\e[0m"
read -p "[y/N] " CONTINUAR
if [[ $CONTINUAR = "Y" || $CONTINUAR = "y" ]]; then
  SECONDS=0

	
	##########################
	#   SSL
	##########################
	if [[ $HTTP = "https" ]]; then
		echo | tee -a $RUTA/RESUMEN.txt
		echo -e "\e[32m[+] Verificando configuración SSL\e[0m" | tee -a $RUTA/RESUMEN.txt
		/opt/testssl.sh/testssl.sh --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36" --protocols --vulnerable --quiet $SITIO > $RUTA/SSL.txt
		echo | openssl s_client -connect ${SITIO}:443 2>/dev/null | openssl x509 -noout -dates -issuer | grep -i "notAfter\|issuer" | tac | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
		grep -v "(OK)" $RUTA/SSL.txt | grep -v "not offered" | tee -a $RUTA/RESUMEN.txt
  fi	

	
	##########################
	#   theHarvester
	##########################
	echo | tee -a $RUTA/RESUMEN.txt
	echo -e "\e[32m[+] Obteniendo datos con theHarvester\e[0m" | tee -a $RUTA/RESUMEN.txt
	theHarvester -d $DOMINIO -b all -f $RUTA/theHarvester.txt > /dev/null
	jq . $RUTA/theHarvester.json > $RUTA/theHarvester_pretty.json && rm -f $RUTA/theHarvester.json && rm -f $RUTA/theHarvester.xml
	cat theHarvester_pretty.json | jq '.emails, .hosts' | grep -v "\[\|\]" | tr -d '"' | sed 's/^[[:space:]]*//g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt

	
	##########################
	#   gobuster DNS
	##########################
	if ! [[ $SITIO =~ $IP ]]; then
	  echo | tee -a $RUTA/RESUMEN.txt
	  echo -e "\e[32m[+] Pasando gobuster para subdominios\e[0m" | tee -a $RUTA/RESUMEN.txt
	  WORDLIST='/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt'
	
	  gobuster dns --no-error --timeout 3s -d $DOMINIO -z -o /tmp/gobuster_subdomains_$SITIO.txt -w $WORDLIST | tail -n1
	
    echo "" > $RUTA/gobuster_subdomains.txt
    echo -e "\tRegistros DNS encontrados." 
    echo -e "\tEn \e[32mverde\e[0m los subdominios en la misma máquina que la víctima." 

    #Limpiamos y pasamos al bucle
	  cat /tmp/gobuster_subdomains_$SITIO.txt | tr '[:upper:]' '[:lower:]' | grep . | sort | uniq | sed 's/found: //g' | sed 's/^[[:space:]]*//g' | while read SUB; do

      #Resolución DNS de ese subdominio
      REGISTRO="$(dig +short $SUB)" 

		  #Eliminamos registros IPv6 y cname
		  if [[ $REGISTRO =~ $IP ]]; then
			  #Si el registro coincide con la IP de la víctima, lo ponemos en verde
		    if [[ $REGISTRO = "$IPSITIO" ]]; then
			    echo -e "\e[32m\t$REGISTRO\t$SUB\e[0m" >> $RUTA/gobuster_subdomains.txt
			  else
			    echo -e "\t$REGISTRO\t$SUB" >> $RUTA/gobuster_subdomains.txt
			  fi
		  fi
		done
	fi

  #Pasamos a pantalla y resumen
  sort -n $RUTA/gobuster_subdomains.txt | tee -a $RUTA/RESUMEN.txt

	rm /tmp/gobuster_subdomains_$SITIO.txt -f

	
	##########################
	#   wapiti
	##########################
	echo | tee -a $RUTA/RESUMEN.txt
	echo -e "\e[32m[+] Escaneando con wapiti\e[0m" | tee -a $RUTA/RESUMEN.txt
	wapiti -u ${HTTP}://$SITIO -o $RUTA/wapiti.txt -f txt >/dev/null
	sed -n '/Summary of vulnerabilities/,/\*\*\*\*/p' $RUTA/wapiti.txt | grep -v "\*\*\*" | grep -v ":   0" | tee -a $RUTA/RESUMEN.txt
	

  ##########################
  #   nmap TCP sC-sV
  ##########################
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[32m[+] Pasando nmap para TCP con opciones -sV y -sC\e[0m" | tee -a $RUTA/RESUMEN.txt
  nmap -T4 -sS --open -n -Pn -p$(cat $RUTA/nmap_TCP_grepeable.txt | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' ) -oN $RUTA/nmap_TCP_completo_sC-sV.txt $SITIO > /dev/null

	
	##########################
	#   nmap UDP
	##########################

  echo -e "\e[32m[+]\e[0m Pasando nmap para UDP..." | tee -a $RUTA/RESUMEN.txt
  nmap -T4 --open -n -Pn --top-ports 100 -sU -sV -oG $RUTA/nmap_UDP_grepeable.txt -oN $RUTA/nmap_UDP_completo.txt $SITIO > /dev/null
  cat $RUTA/nmap_UDP_grepeable.txt | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt


	##########################
	#   gobuster DIR medium
	##########################
	
	WORDLIST='/usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt'
	
	echo | tee -a $RUTA/RESUMEN.txt
	echo -e "\e[32m[+] Pasando gobuster DIR con diccionario $(rev <<<$WORDLIST | cut -d '/' -f1 | rev)\e[0m" | tee -a $RUTA/RESUMEN.txt
	gobuster dir --no-error --timeout 3s --threads 15 --random-agent -s "200,204,302,307,401" -b "" -w $WORDLIST -u ${HTTP}://$SITIO -o $RUTA/gobuster_dir_big.txt | tail -n1
	echo "    Directorios encontrados (Código 200):"  | tee -a $RUTA/RESUMEN.txt
	cat $RUTA/gobuster_dir_big.txt | grep -v "(Status: 301)\|(Status: 302)\|(Status: 401)" | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
	echo "    Directorios protegidos con contraseña (Código 401):"  | tee -a $RUTA/RESUMEN.txt
	grep "Status: 401" gobuster_dir_big.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt

	
	##########################
	#   gobuster FUZZ
	##########################
	EXTENSIONES="php,cfg,bak,sql,dmp,txt,log,conf,gz,tgz,tar.gz,zip,rar,new,old,sh,yml,php2,back"
	echo | tee -a $RUTA/RESUMEN.txt
	echo -e "\e[32m[+] Buscando archivos con extensiones $EXTENSIONES\e[0m" | tee -a $RUTA/RESUMEN.txt
	echo $EXTENSIONES | tr ',' \\n | while read EXTENSION; do
	  echo -e "\tComprobando extensión .$EXTENSION"
	  gobuster fuzz  --no-error --timeout 3s --threads 15 --follow-redirect --random-agent --excludestatuscodes "300-302,400-404,500-503" --exclude-length 0 --url ${HTTP}://${SITIO}/FUZZ.$EXTENSION --wordlist /usr/share/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt -o $RUTA/gobuster_archivos_${EXTENSION}.txt | tail -n1
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
	  gobuster fuzz --no-error --timeout 3s --threads 15 --follow-redirect --random-agent --excludestatuscodes "300-302,400-404,500-503" --url ${HTTP}://${SITIO}/wp-configFUZZ --wordlist /opt/perico/wordlist/extensiones_wp_backs.txt -q -o $RUTA/gobuster_wpconfig.txt | tail -n1
	cat $RUTA/gobuster_wpconfig.txt | awk '{print $1}' | sed ':a;N;$!ba;s/\n/, /g' | fold -w 135 | sed 's/^/\t/' | tee -a $RUTA/RESUMEN.txt
	fi


  #Eliminamos archivos que ya no son necesarios:
  rm -f $RUTA/nmap_*_grepeable.txt

  echo | tee -a $RUTA/RESUMEN.txt
  echo | tee -a $RUTA/RESUMEN.txt
  echo -e "\e[1;35mEscaneo profundo terminado en $(date -u -d @${SECONDS} +'%Hh:%Mm')\e[0m" | tee -a $RUTA/RESUMEN.txt

  rm -f $RUTA/nmap_*_grepeable.txt

else

  echo
  echo -e "\e[1;35mEscaneo inicial terminado\e[0m"
  #Eliminamos archivos que ya no son necesarios:
  rm -f $RUTA/nmap_*_grepeable.txt
  exit 0

fi
