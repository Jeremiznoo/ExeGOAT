FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV QT_X11_NO_MITSHM=1
ENV PYTHONUNBUFFERED=1


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
    # X11 pour Wireshark GUI
    dbus-x11 \
    x11-apps \

    && rm -rf /var/lib/apt/lists/*

# Configuration Wireshark
RUN setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap

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
RUN python3 -m venv /opt/exegoat/venv &&  /opt/exegoat/venv/bin/pip install --upgrade pip setuptools wheel &&  /opt/exegoat/venv/bin/pip install --no-cache-dir -r requirements.txt

# alias éxécutable
RUN echo '#!/bin/bash' > /usr/local/bin/exegoat
RUN echo '/opt/exegoat/venv/bin/python /opt/exegoat/main.py "$@"' >> /usr/local/bin/exegoat 
RUN chmod +x /usr/local/bin/exegoat

# User
USER exegoat
WORKDIR /home/exegoat

# Dossiers user
RUN mkdir -p ~/wordlists ~/output ~/pcaps

# Alias
RUN echo '# ExeGOAT aliases' >> ~/.bashrc 
RUN echo 'alias ws="wireshark"' >> ~/.bashrc

# PATH du  venv
ENV PATH="/opt/exegoat/venv/bin:${PATH}"


CMD ["/bin/bash"]