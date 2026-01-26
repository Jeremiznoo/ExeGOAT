# ExeGOAT 🐐

<p align="center">
  <img src="logo.png" alt="ExeGOAT Logo">
</p>

**ExeGOAT** is an offensive security (Pentest) toolkit written in Python inspired by **EXEGOL**. It features a powerful suite of modules for web enumeration, network scanning, and brute-force attacks, all accessible via a unified Command Line Interface (CLI) and a Graphical User Interface (GUI) for the network scanner.

---

## Features

ExeGOAT integrates the following tools:

1.  **Web Fuzzer**: A blazing-fast asynchronous web fuzzer supporting multiple modes (directories, GET/POST parameters, and forms).
2.  **nGOAT (Network Scanner)**: A network scanner with a modern GUI, supporting ARP discovery, SNMP (v2c/v3), NetBIOS, and MAC vendor lookup.
3.  **FTPGOAT**: A comprehensive tool for FTP auditing (anonymous check, brute-force, recursive enumeration, and interactive shell).
4.  **BruteGOAT**: A modular, multi-threaded brute-force engine (supporting SSH and FTP, Hydra-style).

---

## Installation

1.  **Clone the repository:**
```bash
    git clone https://github.com/your-user/ExeGOAT.git
    cd ExeGOAT
```

2.  **Install dependencies:**
```bash
    pip install -r requirements.txt
```

    > **Note**: `paramiko` is required for the `BruteGOAT` SSH module. For advanced SNMP scanning, `pysnmp` is used. Both are included in `requirements.txt`.

---

## General Usage

The main entry point is `main.py`.
```bash
python main.py  [options]
```

Display the general help menu:
```bash
python main.py -h
```

---

## Module Details & Examples

### 1. Web Fuzzer (`fuzzer`)

Advanced web fuzzer designed to discover hidden resources or vulnerabilities.

**Available modes:**
*   `dir`: Directory/file enumeration.
*   `param`: GET parameter fuzzing.
*   `post`: POST parameter fuzzing.
*   `form`: Automatic form fuzzing.

**Examples:**

*   **Directory enumeration:**
```bash
    python main.py fuzzer -u http://target.com -w wordlists/common.txt -t 50
```

*   **GET parameter fuzzing (XSS/SQLi):**
```bash
    python main.py fuzzer -u http://target.com/page.php -m param -p id -w wordlists/payloads.txt
```

*   **Form fuzzing with status code filtering:**
```bash
    python main.py fuzzer -u http://target.com/login -m form -p username --field-values "password=admin" -w wordlists/users.txt --hide-codes 404,403
```

### 2. nGOAT - Network Scanner (`nGOAT`)

Launches a Graphical User Interface (GUI) to scan the local network.

**Command:**
```bash
python main.py nGOAT
```

**Key features:**
*   Fast ARP scanning.
*   ARP table retrieval via SNMP (v2c and v3).
*   NetBIOS name resolution.
*   MAC vendor lookup.
*   CSV export of results.

### 3. FTPGOAT (`ftpGOAT`)

Dedicated auditing tool for the FTP protocol.

**Modes (`--filter-mode`):** `anon`, `brute`, `enum`, `shell`, `all`.

**Examples:**

*   **Check anonymous access:**
```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode anon
```

*   **FTP brute-force:**
```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode brute -L users.txt -P passwords.txt
```

*   **Interactive FTP shell (pseudo-shell):**
```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode shell -l admin -p secret
```

### 4. BruteGOAT (`BruteGOAT`)

Generic multi-threaded brute-force tool (Hydra-style) supporting SSH and FTP.

**Examples:**

*   **SSH brute-force:**
```bash
    python main.py BruteGOAT ssh://192.168.1.10 -l root -P rockyou.txt -t 4
```

*   **FTP brute-force (from user and password lists):**
```bash
    python main.py BruteGOAT ftp://192.168.1.10 -L users.txt -P passwords.txt
```

---

## Docker Usage

ExeGOAT can be run inside a Docker container to avoid local dependency conflicts.

**Start the container:**

From the project root:
```bash
docker compose up -d
```

**Access the shell:**
```bash
docker exec -it exegoat zsh
```

> [!IMPORTANT]
> GUI applications (like nGOAT) require an X11 environment to display. Windows users should use WSL2 with a configured X Server.

---

## ⚠️ Legal Disclaimer

This software is designed for **educational purposes and authorized security testing** only. Using this tool against targets without prior written consent is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this program.
