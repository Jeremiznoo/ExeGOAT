FROM debian:13-slim

# Supprimer action apt
ENV DEBIAN_FRONTEND=noninteractive 
# GUI
ENV QT_X11_NO_MITSHM=1
# Python sortie
ENV PYTHONUNBUFFERED=1
# Caido Version
ENV CAIDO_VERSION=0.54.1
# erreur debus session usier
ENV DBUS_SESSION_BUS_ADDRESS=/dev/null
# Format zsh
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8

# Paquet Systeme
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    zsh \
    curl \
    tmux \
    # Python
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    python3-tk \
    tk \
    tk-dev \
    build-essential \
    # Réseau
    wireshark \
    fping \
    iputils-ping \
    # X11 app GUI
    dbus-x11 \
    x11-apps \
    wget \
    ca-certificates \
    # Dépendances
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2t64 \
    libatspi2.0-0 \
    # Outils
    chromium \
    hashcat \
    dnsenum \
    ocl-icd-libopencl1 \
    pocl-opencl-icd \
    locales \
    # Dépendances Impacket & NetExec
    libssl-dev \
    libffi-dev \
    libkrb5-dev \
    libxml2-dev \
    libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen en_US.UTF-8


# SqlMAP
RUN git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Caido
RUN wget -q https://caido.download/releases/v${CAIDO_VERSION}/caido-desktop-v${CAIDO_VERSION}-linux-x86_64.tar.gz -O /tmp/caido.tar.gz && \
    tar -xzf /tmp/caido.tar.gz -C /opt && \
    mv /opt/caido-desktop-* /opt/caido && \
    ln -s /opt/caido/caido /usr/local/bin/caido && \
    rm /tmp/caido.tar.gz

# Clone Impacket
RUN git clone https://github.com/fortra/impacket.git /opt/impacket

# Create user
RUN groupadd -r wireshark 2>/dev/null || true && \
    useradd -m -s /usr/bin/zsh exegoat && \
    usermod -aG wireshark exegoat

# ExeGOAT
WORKDIR /opt/exegoat

#  fichiers locaux vers l'image
COPY --chown=exegoat:exegoat requirements.txt .
COPY --chown=exegoat:exegoat main.py .
COPY --chown=exegoat:exegoat ./tools ./tools
COPY --chown=exegoat:exegoat logo.png .

# Setup phyton Impacket et NetExec dans le venv
RUN python3 -m venv /opt/exegoat/venv && \
    /opt/exegoat/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/exegoat/venv/bin/pip install /opt/impacket && \
    /opt/exegoat/venv/bin/pip install git+https://github.com/Pennyw0rth/NetExec.git && \
    chown -R exegoat:exegoat /opt/exegoat/venv

# Install requirment.txt
RUN if [ -f "requirements.txt" ]; then /opt/exegoat/venv/bin/pip install -r requirements.txt; fi

# Impaket 
RUN mkdir -p /usr/local/bin && \
    cd /opt/impacket/examples && \
    for script in *.py; do \
        script_name="${script%.py}"; \
        echo '#!/bin/bash' > "/usr/local/bin/$script_name"; \
        echo "/opt/exegoat/venv/bin/python3 /opt/impacket/examples/$script \"\$@\"" >> "/usr/local/bin/$script_name"; \
        chmod +x "/usr/local/bin/$script_name"; \
    done

# netExec
RUN echo '#!/bin/bash' > /usr/local/bin/nxc && \
    echo '/opt/exegoat/venv/bin/netexec "$@"' >> /usr/local/bin/nxc && \
    chmod +x /usr/local/bin/nxc && \
    ln -s /usr/local/bin/nxc /usr/local/bin/netexec

# Conf user
USER exegoat
WORKDIR /home/exegoat
RUN git clone https://github.com/danielmiessler/SecLists.git

# ZSH
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# Config Zsh
RUN sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="agnoster"/' ~/.zshrc && \
    echo 'export PATH="/opt/exegoat/venv/bin:$PATH"' >> ~/.zshrc && \
    echo 'alias ws="wireshark"' >> ~/.zshrc && \
    echo 'alias caido="/usr/local/bin/caido"' >> ~/.zshrc && \
    echo 'alias ll="ls -lah"' >> ~/.zshrc && \
    echo 'alias exegoat="python3 /opt/exegoat/main.py"' >> ~/.zshrc && \
    echo 'alias cme="nxc"' >> ~/.zshrc

RUN mkdir -p ~/wordlists ~/output ~/pcaps ~/.caido ~/.nxc

ENV PATH="/opt/exegoat/venv/bin:${PATH}"

EXPOSE 8080 445 139 88 389 636 1433 3389 5985 5986

CMD ["/usr/bin/zsh"]
