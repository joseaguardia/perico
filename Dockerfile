FROM ubuntu:20.04

# Establecer la variable de entorno DEBIAN_FRONTEND para evitar preguntas interactivas
ENV DEBIAN_FRONTEND=noninteractive

# Instalar paquetes necesarios
RUN apt-get update && apt-get install -y \
    jq \
    nmap \
    whois \
    git \
    dnsutils \
    python3-pip \
    curl

# Instalar theHarvester
 RUN git clone https://github.com/laramies/theHarvester.git /theharvester && \
     cd /theharvester && \
     pip3 install -r requirements.txt && \
     echo "alias theHarvester='python3 /theharvester/theHarvester.py'" >> ~/.bashrc
 RUN ln -s /theharvester /usr/local/etc/ && mv /usr/local/etc/theharvester /usr/local/etc/theHarvester

# Install Python 3.9
RUN apt-get install -y software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && \
    apt-get install -y python3.9 python3-pip
RUN ln -sf /usr/bin/python3.9 /usr/bin/python3
RUN pip3 install aiodns pyyaml aiohttp shodan aiosqlite ujson netaddr uvloop aiomultiprocess censys pydantic python-dateutil bs4

#Instalar sslyze
RUN pip3 install sslyze

# Instalar wafw00f
RUN pip3 install wafw00f

# Instalar whatweb
RUN apt-get install -y whatweb

# Instalar wpscan
RUN apt install -y ruby-full && \
    gem install wpscan

#Instalar gobuster
RUN curl -OL https://golang.org/dl/go1.20.5.linux-amd64.tar.gz  && \
    tar -C /usr/local -xvf go1.20.5.linux-amd64.tar.gz && \
    rm go1.20.5.linux-amd64.tar.gz && \
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
ENV PATH=$PATH:/usr/local/go/bin
RUN git clone https://github.com/OJ/gobuster.git /gobuster && \
    cd /gobuster && \
    go get && \
    go build && \
    mv gobuster /usr/local/bin

# Añadimos los diccionarios
ADD https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt /usr/share/seclists/Discovery/DNS/
ADD https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt /usr/share/seclists/Discovery/DNS/
ADD https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt /usr/share/seclists/Discovery/Web-Content/CMS/
ADD https://raw.githubusercontent.com/igorhvr/zaproxy/master/src/dirbuster/directory-list-2.3-big.txt /usr/share/wordlists/seclists/Discovery/Web-Content/
ADD https://raw.githubusercontent.com/igorhvr/zaproxy/master/src/dirbuster/directory-list-2.3-medium.txt /usr/share/wordlists/seclists/Discovery/Web-Content/

# Descargar perico.sh desde el repositorio
RUN git clone https://github.com/joseaguardia/perico.git /perico

RUN mkdir -p /opt/perico/wordlist/
RUN cp /perico/wordlist/extensiones_wp_backs.txt /opt/perico/wordlist/extensiones_wp_backs.txt

# Establecer el directorio de trabajo
WORKDIR /perico

# Dar permiso de ejecución a perico.sh
RUN chmod +x perico.sh

# Habilitamos el uso de los alias del sistema dentro del script
RUN sed -i '2i\alias theHarvester='\''python3 /theharvester/theHarvester.py'\''' /perico/perico.sh
RUN sed -i '2i\shopt -s expand_aliases' /perico/perico.sh

# Establecer el entrypoint para ejecutar perico.sh
ENTRYPOINT ["./perico.sh"]
