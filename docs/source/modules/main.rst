Module Principal (main.py)
==========================

Le module **main** est le point d'entrée principal d'ExeGOAT. Il gère l'interface en ligne de commande (CLI) et dispatche les commandes vers les différents outils.

Vue d'ensemble
--------------

Le module principal utilise ``argparse`` pour créer une CLI modulaire avec des sous-commandes pour chaque outil :

* ``fuzzer`` - Fuzzing web et énumération
* ``nGOAT`` - Scanner réseau avec interface graphique
* ``ftpGOAT`` - Scanner et shell FTP
* ``BruteGOAT`` - Brute-force multi-protocole

Architecture CLI
----------------

ExeGOAT utilise une architecture de parseurs parents pour partager des options communes :

.. code-block:: text

   main.py
   ├── parser (principal)
   │   ├── fuzzer (subparser)
   │   │   └── hérite de: parent_common
   │   ├── nGOAT (subparser)
   │   │   └── hérite de: parent_common
   │   ├── ftpGOAT (subparser)
   │   │   └── hérite de: parent_common, parent_auth
   │   └── BruteGOAT (subparser)
   │       └── hérite de: parent_common, parent_auth

Fonctions
---------

.. autofunction:: main.main

   Point d'entrée principal du programme. Configure les parseurs d'arguments, valide les entrées utilisateur et dispatche vers l'outil approprié.

.. autofunction:: main.run_fuzzer

   Lance le fuzzer web avec la configuration fournie. Gère tous les modes de fuzzing (dir, param, post, form).

   **Arguments validés :**
   
   * Mode ``dir`` : requiert ``--wordlist``
   * Mode ``param`` : requiert ``--wordlist`` et ``--param``
   * Mode ``post`` : requiert ``--wordlist`` et ``--param``
   * Mode ``form`` : requiert ``--wordlist``, ``--param``, et ``--form-url``

Parseurs parents
----------------

parent_common
~~~~~~~~~~~~~

Options communes à tous les outils :

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Option
     - Type
     - Description
   * - ``target``
     - str (positionnel)
     - Cible (URL, IP, ou protocole://cible)
   * - ``-u, --url``
     - str
     - URL cible (alternative à l'argument positionnel)
   * - ``-v, --verbose``
     - flag
     - Active le mode verbeux
   * - ``-q, --quiet``
     - flag
     - Active le mode silencieux

parent_auth
~~~~~~~~~~~

Options d'authentification (style Hydra) :

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Option
     - Type
     - Description
   * - ``-l, --username``
     - str
     - Login unique
   * - ``-p, --password``
     - str
     - Mot de passe unique
   * - ``-L, --user-list``
     - str
     - Fichier de liste d'utilisateurs
   * - ``-P, --pass-list``
     - str
     - Fichier de liste de mots de passe

Sous-commandes
--------------

fuzzer
~~~~~~

Fuzzer web pour l'énumération et la détection de vulnérabilités.

**Groupes d'options :**

* **Requis** : ``-w/--wordlist``
* **Mode** : ``-m/--mode``, ``--param``, ``--post-data``, ``--form-url``, ``--field-values``
* **Réseau** : ``-t/--threads``, ``--timeout``, ``--follow-redirects``, ``--cookie``, ``--delay``
* **Filtres** : ``--hide-codes``, ``--show-codes``
* **Payloads** : ``--extensions``, ``--prefix``, ``--suffix``, ``--xss-marker``
* **Export** : ``-o/--output``, ``--auto-export``

**Exemples :**

.. code-block:: bash

   # Énumération de répertoires
   exegoat fuzzer -u http://example.com -w dirs.txt --hide-codes 404,403

   # Fuzzing de paramètre GET avec XSS
   exegoat fuzzer -u http://example.com/search -w xss.txt -m param --param q

   # Fuzzing de formulaire POST
   exegoat fuzzer -w passwords.txt -m form --form-url http://example.com/login \
       --param password --field-values "username=admin"

nGOAT
~~~~~

Scanner réseau avec interface graphique.

**Exemple :**

.. code-block:: bash

   exegoat nGOAT

ftpGOAT
~~~~~~~

Scanner FTP avec test d'accès anonyme, brute-force et shell interactif.

**Options spécifiques :**

* ``--filter-mode`` : Mode de fonctionnement (anon, brute, enum, all, shell)
* ``--port`` : Port FTP (défaut: 21)

**Exemples :**

.. code-block:: bash

   # Test d'accès anonyme
   exegoat ftpGOAT ftp://192.168.1.10 --filter-mode anon

   # Brute-force
   exegoat ftpGOAT ftp://192.168.1.10 -L users.txt -P passwords.txt --filter-mode brute

   # Shell interactif
   exegoat ftpGOAT ftp://192.168.1.10 -l admin -p password --filter-mode shell

BruteGOAT
~~~~~~~~~

Outil de brute-force multi-protocole (SSH, FTP).

**Options spécifiques :**

* ``--service`` : Service cible (ssh, ftp) si non détecté via l'URL

**Exemples :**

.. code-block:: bash

   # Brute-force SSH
   exegoat BruteGOAT ssh://192.168.1.10 -L users.txt -P passwords.txt

   # Brute-force FTP
   exegoat BruteGOAT ftp://192.168.1.10 -l admin -P passwords.txt


Affichage de la configuration
------------------------------

En mode non-silencieux, le fuzzer affiche une configuration détaillée :

.. code-block:: text

   ============================================================
   CONFIGURATION FUZZER
   ============================================================

   Cible:
     URL            : http://example.com
     Wordlist       : wordlist.txt

   Mode:
     Type           : param
     Paramètre      : q

   Réseau:
     Concurrence    : 50
     Timeout        : 5.0s
     Suivre redirects : True

   Filtres:
     Cacher codes   : 404,403

   Payloads:
     Extensions     : php,html
     Préfixe        : test_

