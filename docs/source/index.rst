ExeGOAT Documentation
=====================
ExeGOAT est destiné uniquement à des fins éducatives et de test de sécurité autorisé

ExeGOAT est un wrapper de tools dans un environnement Docker

Fonctionnalités principales
----------------------------

* **Web Fuzzer**
* **nGOAT** 
* **ftpGOAT** 
* **BruteGOAT** 
* **Wireshark**
* **Caido**
* **SQLMAP**
* **Impaket**
* **Netexec**
* **Dsnenmun**
* **fping**
* **hashcat**

Installation rapide
--------------------

.. code-block:: bash

   # Construire l'image Docker
   docker build -t exegoat .

   # Lancer le conteneur
   docker compose up -d

   # Aller dans le container
   docker exec -it exegaot zsh

Guide de démarrage
------------------

Pour utiliser les outils ExeGOAT maison il suffit de faire : 

.. code-block:: bash

   # Fuzzer web
   exegoat fuzzer -u http://example.com -w wordlist.txt

   # Scanner réseau
   exegoat nGOAT

   # Scanner FTP
   exegoat ftpGOAT ftp://192.168.1.10

   # Brute-force
   exegoat BruteGOAT ssh://192.168.1.10 -L wordlist/users.txt -P wordlist/passwords.txt
   

Sinon pour utiliser les tools qui sont implémenter il existe des alias : 

* wireshark ou ws
* sqlmap
* caido
* netexec
* dsnenum
* hashcat

Table des matières
------------------

.. toctree::
   :maxdepth: 2
   :caption: Modules

   modules/main
   modules/fuzz
   modules/ngoat
   modules/ftpgoat
   modules/brutegoat

.. toctree::
   :maxdepth: 2
   :caption: Guides

   guides/fuzzer
   guides/network_scanner
   guides/ftp_scanner
   guides/bruteforce

.. toctree::
   :maxdepth: 1
   :caption: Référence

   api/index

Indices et tables
=================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`