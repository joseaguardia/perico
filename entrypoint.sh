#!/bin/bash
set -e

# Download a file and fail loudly if it is missing or empty, retrying a few
# times so a flaky first boot (slow network, container restart) doesn't leave
# a half-installed container marked as "done".
download() {
    local url="$1" dest="$2" attempt
    for attempt in 1 2 3; do
        if wget -q "$url" -O "$dest" && [ -s "$dest" ]; then
            return 0
        fi
        echo "⚠️  Download failed (attempt ${attempt}/3): ${url}"
        rm -f "$dest"
        sleep 3
    done
    echo "❌ Could not download ${url}"
    return 1
}

# Initial configuration only on first run
if [ ! -f /root/.first_run ]; then
    echo -n
    echo "✨ All the necessary packages will be installed. Please be patient."
    echo -n
    echo "kali-docker" > /etc/hostname
    mkdir -p /root/proyectos_hack
    
    echo "🧩 Updating and installing packages..."
    apt update -qq
    apt install -y git wget vim jq curl procps netcat-openbsd iproute2 telnet \
        iputils-ping git whois nmap cmseek jq wafw00f gobuster whatweb wpscan \
        theharvester nikto wapiti wireguard bind9-dnsutils vim bsdmainutils exploitdb > /dev/null
    nmap --script-updatedb

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
    cd /opt && git clone --depth 1 --quiet https://github.com/stamparm/identYwaf

    # Install hakrawler
    echo "🧩 Installing hakrawler..."
    apt install -y hakrawler

    #Clone and configure owasp-zap proxy
    # apt install python3-pip -y
    # pip3 install --break-system-packages --root-user-action ignore --upgrade setuptools zaproxy pyyaml > /dev/null
    # ln -s /usr/bin/python3 /usr/bin/python
    # git clone https://github.com/zaproxy/zaproxy.git
    # cd /opt/zaproxy
    # find /opt/zaproxy/ -mindepth 1 !  -path "/opt/zaproxy/docker*" -exec rm -rf {} \;


    # Configure wordlists
    echo "🧩 Cloning wordlists from SecLists..."
    rm -rf /usr/share/wordlists
    mkdir -p /usr/share/wordlists/SecLists/Discovery/Web-Content/
    mkdir -p /usr/share/wordlists/SecLists/Discovery/DNS
    download https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/raft-small-words-lowercase.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt
    download https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-5000.txt /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
    download https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
    download https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt


    echo "cd /root/proyectos_hack/" >> /root/.bashrc

    # Mark setup as complete only here, at the very end: if any step above
    # failed, set -e aborts before this and the next boot retries the install.
    touch /root/.first_run
    echo "✅ Initial setup completed."

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