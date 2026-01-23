Module FTPGOAT (FTPGOAT.py)
==========================

Le module **FTPGOAT** est un scanner FTP complet.

Vue d'ensemble
--------------

FTPGOAT permet d'effectuer diverses opérations sur des serveurs FTP :

* Vérification de l'accès anonyme
* Brute-force d'authentification
* Énumération récursive des fichiers
* Shell interactif

Classe Principale
~~~~~~~~~~~~~~~~~

.. autoclass:: tools.FTPGOAT.FTPGOAT
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__

   **Principales méthodes**

   .. automethod:: check_anonymous
   
   .. automethod:: brute_force

   .. automethod:: enumerate

   .. automethod:: interactive_shell


Point d'entrée
--------------

.. autofunction:: tools.FTPGOAT.run_ftp_scanner
