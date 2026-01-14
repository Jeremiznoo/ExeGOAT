FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV QT_X11_NO_MITSHM=1
ENV PYTHONUNBUFFERED=1
ENV CAIDO_VERSION=0.54.1
ENV DBUS_SESSION_BUS_ADDRESS=/dev/null


RUN apt-get update && apt-get install -y \
    # Python
    python3 \
    python3-venv \
    python3-pip \
    python3-dev \
    build-essential \
    # Outils réseau
    wireshark \
    wireshark-qt \
    # X11 pour outils GUI
    dbus-x11 \
    x11-apps \
    # Caido
    wget \
    ca-certificates \
    # Dépendances Caido
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
    libasound2 \
    libatspi2.0-0 \
    # Chromium
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Configuration Wireshark
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

# Installer Caido
RUN wget -q https://caido.download/releases/v${CAIDO_VERSION}/caido-desktop-v${CAIDO_VERSION}-linux-x86_64.tar.gz -O /tmp/caido.tar.gz && \
    tar -xzf /tmp/caido.tar.gz -C /opt && \
    mv /opt/caido-desktop-* /opt/caido && \
    ln -s /opt/caido/caido /usr/local/bin/caido && \
    rm /tmp/caido.tar.gz

# Créer le user
RUN groupadd -r wireshark 2>/dev/null || true && \
    useradd -m -s /bin/bash exegoat && \
    usermod -aG wireshark exegoat

# Créer les répertoires de travail
RUN mkdir -p /opt/exegoat/wordlists /opt/exegoat/output /opt/exegoat/pcaps && \
    chown -R exegoat:exegoat /opt/exegoat

# Copier les fichiers ExeGOAT
WORKDIR /opt/exegoat
COPY --chown=exegoat:exegoat requirements.txt .
COPY --chown=exegoat:exegoat main.py .
COPY --chown=exegoat:exegoat tools/ ./tools/

# Installer les dépendances Python 
RUN python3 -m venv /opt/exegoat/venv && \
    /opt/exegoat/venv/bin/pip install --upgrade pip setuptools wheel && \
    /opt/exegoat/venv/bin/pip install --no-cache-dir -r requirements.txt

# Alias exécutable
RUN echo '#!/bin/bash' > /usr/local/bin/exegoat && \
    echo '/opt/exegoat/venv/bin/python /opt/exegoat/main.py "$@"' >> /usr/local/bin/exegoat && \
    chmod +x /usr/local/bin/exegoat

# User
USER exegoat
WORKDIR /home/exegoat

# Dossiers user
RUN mkdir -p ~/wordlists ~/output ~/pcaps ~/.caido

# Alias
RUN echo '# ExeGOAT aliases' >> ~/.bashrc && \
    echo 'alias ws="wireshark"' >> ~/.bashrc && \
    echo 'alias caido="/usr/local/bin/caido"' >> ~/.bashrc

# PATH du venv
ENV PATH="/opt/exegoat/venv/bin:${PATH}"

# Exposer le port Caido
EXPOSE 8080

CMD ["/bin/bash"]