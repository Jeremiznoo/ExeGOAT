# ExeGOAT 🐐

**ExeGOAT** est une suite d'outils de sécurité offensive (Pentest) écrite en Python. Elle regroupe plusieurs modules puissants pour l'énumération web, le scan réseau, et les attaques par force brute, le tout accessible via une interface en ligne de commande (CLI) unifiée et une interface graphique (GUI) pour le scanneur réseau.

## Fonctionnalités

ExeGOAT intègre les outils suivants :

1.  **Web Fuzzer** : Un fuzzer web asynchrone ultra-rapide supportant plusieurs modes (répertoires, paramètres GET/POST, formulaires).
2.  **nGOAT (Network Scanner)** : Un scanner réseau avec interface graphique moderne, supportant la découverte ARP, SNMP (v2c/v3), NetBIOS et la résolution de vendeurs MAC.
3.  **FTPGOAT** : Un outil complet pour l'audit FTP (check anonyme, brute-force, énumération récursive, shell interactif).
4.  **BruteGOAT** : Un moteur de brute-force modulaire multi-threadé (support SSH et FTP style Hydra).

## Installation

1.  Clonez le dépôt :
    ```bash
    git clone https://github.com/votre-user/ExeGOAT.git
    cd ExeGOAT
    ```

2.  Installez les dépendances :
    ```bash
    pip install -r requirements.txt
    ```

    > **Note** : Pour utiliser le module SSH de `BruteGOAT`, `paramiko` est requis (inclus dans requirements.txt). Pour le scan SNMP avancé, `pysnmp` est utilisé.

## 📖 Utilisation Générale

Le point d'entrée principal est `main.py`.

```bash
python main.py <outil> [options]
```

Affichez l'aide générale :
```bash
python main.py -h
```

---

## Modules Détails & Exemples

### 1. Web Fuzzer (`fuzzer`)

Fuzzer web avancé pour découvrir des ressources cachées ou des vulnérabilités.

**Modes disponibles :**
*   `dir` : Énumération de répertoires/fichiers.
*   `param` : Fuzzing d'un paramètre GET.
*   `post` : Fuzzing d'un paramètre POST.
*   `form` : Fuzzing automatique de formulaire.

**Exemples :**

*   **Énumération de répertoires :**
    ```bash
    python main.py fuzzer -u http://cible.com -w wordlists/common.txt -t 50
    ```

*   **Fuzzing de paramètre GET (XSS/SQLi) :**
    ```bash
    python main.py fuzzer -u http://cible.com/page.php -m param -p id -w wordlists/payloads.txt
    ```

*   **Fuzzing de formulaire avec filtre de codes :**
    ```bash
    python main.py fuzzer -u http://cible.com/login -m form -p username --field-values "password=admin" -w wordlists/users.txt --hide-codes 404,403
    ```

### 2. nGOAT - Network Scanner (`nGOAT`)

Lance une interface graphique (GUI) pour scanner le réseau local.

**Commande :**
```bash
python main.py nGOAT
```

**Fonctionnalités clé de l'interface :**
*   Scan ARP rapide.
*   Récupération table ARP via SNMP (v2c et v3).
*   Résolution de noms NetBIOS.
*   Résolution des constructeurs (MAC Vendor Lookup).
*   Export des résultats en CSV.

### 3. FTPGOAT (`ftpGOAT`)

Outil d'audit dédié au protocole FTP.

**Modes (`--filter-mode`) :** `anon`, `brute`, `enum`, `shell`, `all`.

**Exemples :**

*   **Vérifier l'accès anonyme :**
    ```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode anon
    ```

*   **Brute-force FTP :**
    ```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode brute -L users.txt -P passwords.txt
    ```

*   **Shell Interactif FTP (pseudo-shell) :**
    ```bash
    python main.py ftpGOAT -u 192.168.1.10 --filter-mode shell -l admin -p secret
    ```

### 4. BruteGOAT (`BruteGOAT`)

Outil de brute-force générique (style Hydra) supportant SSH et FTP.

**Exemples :**

*   **Brute-force SSH :**
    ```bash
    python main.py BruteGOAT ssh://192.168.1.10 -l root -P rocksyou.txt -t 4
    ```

*   **Brute-force FTP (depuis une liste d'utilisateurs et de mots de passe) :**
    ```bash
    python main.py BruteGOAT ftp://192.168.1.10 -L users.txt -P passwords.txt
    ```

---

## ⚠️ Avertissement Légal

Ce logiciel est conçu à des fins **éducatives et de tests de sécurité autorisés** uniquement. L'utilisation de cet outil sur des cibles sans autorisation écrite préalable est illégale. Les développeurs déclinent toute responsabilité en cas de mauvaise utilisation.