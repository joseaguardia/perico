#!/bin/bash
set -e

# Initial configuration only on first run
if [ ! -f /root/.first_run ]; then
    echo -n
    echo "✨ All the necessary packages will be installed. Please be patient."
    echo -n
    touch /root/.first_run
    echo "kali-docker" > /etc/hostname
    mkdir -p /root/proyectos_hack
    
    echo "🧩 Updating and installing packages..."
    apt update -qq
    apt install -y git wget vim jq curl procps netcat-openbsd iproute2 telnet \
        iputils-ping git whois nmap cmseek jq wafw00f gobuster whatweb wpscan \
        theharvester nikto wapiti wireguard bind9-dnsutils vim bsdmainutils > /dev/null

    # Install perico
    echo "🧩 Cloning and Installing perico..."
    cd /opt && git clone --quiet https://github.com/joseaguardia/perico.git
    chmod +x /opt/perico/perico.sh
    ln -s /opt/perico/perico.sh /usr/local/bin/perico
    
    # Install testssl.sh
    echo "🧩 Cloning and Installing testssl..."
    cd /opt && git clone --quiet https://github.com/drwetter/testssl.sh.git
    
    #Install identyWAF
    echo "🧩 Cloning and Installing identYwaf..."
    cd /opt && git clone --depth 1 --quiet  https://github.com/stamparm/identYwaf

    # Configure wordlists
    echo "🧩 Cloning wordlists from SecLists..."
    rm -rf /usr/share/wordlists
    mkdir -p /usr/share/wordlists/SecLists/Discovery/Web-Content/
    mkdir -p /usr/share/wordlists/SecLists/Discovery/DNS
    wget --quiet https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-small-words-lowercase.txt -O /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
    wget --quiet https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-5000.txt -O /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
    wget --quiet https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt

    echo "cd /root/proyectos_hack/" >> /root/.bashrc

else
    # Update repos on every startup
    echo "🧩 Updating perico..."
    cd /opt/perico && git pull
    echo "🧩 Updating testssl..."
    cd /opt/testssl.sh && git pull
    echo "🧩 Updating identYwaf..."
    cd /opt/identYwaf && git pull
fi

# Execute main command (bash by default)
exec "$@"