Module BruteGOAT (BruteGOAT.py)
==============================

Le module **BruteGOAT** est un outil de brute-force multi-protocole (SSH, FTP).

Vue d'ensemble
--------------

BruteGOAT permet de lancer des attaques par dictionnaire contre des services SSH et FTP. Il supporte :

* L'attaque multi-threadée
* L'utilisation de listes d'utilisateurs et de mots de passe
* La détection automatique du service via l'URL (ssh:// ou ftp://)
* L'arrêt automatique dès qu'un mot de passe est trouvé

BruteForcer
~~~~~~~~~~~

.. autoclass:: tools.BruteGOAT.BruteForcer
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__

   **Attributs principaux**

   .. attribute:: service
      :type: str

      Service à attaquer ('ssh' ou 'ftp')

   .. attribute:: target
      :type: str

      Adresse de la cible

   .. attribute:: user_list
      :type: list

      Liste des utilisateurs à tester

   .. attribute:: pass_list
      :type: list

      Liste des mots de passe à tester

   .. attribute:: threads
      :type: int

      Nombre de threads simultanés

Modules spécifiques
~~~~~~~~~~~~~~~~~~~

.. autoclass:: tools.BruteGOAT.BruteModule
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: tools.BruteGOAT.SSHBrute
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: tools.BruteGOAT.FTPBrute
   :members:
   :undoc-members:
   :show-inheritance:

Point d'entrée
--------------

.. autofunction:: tools.BruteGOAT.run_brutegoat

   Fonction principale appelée par le module main pour lancer BruteGOAT.
