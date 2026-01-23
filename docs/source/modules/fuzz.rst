Module Fuzzer (fuzz.py)
=======================

Le module **fuzz** est le fuzzer

Vue d'ensemble
--------------

Le fuzzer ExeGOAT permet de :

* Énumérer des répertoires et fichiers cachés
* Détecter des vulnérabilités XSS et SQLi
* Fuzzer des paramètres GET et POST
* Extraire et fuzzer automatiquement des formulaires HTML
* Filtrer les résultats par codes HTTP
* Exporter les résultats au format texte
* Ajouter des suffix et prefix au payload

WebFuzzer
~~~~~~~~~

.. autoclass:: tools.fuzz.WebFuzzer
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__

   **Attributs principaux**

   .. attribute:: base_url
      :type: str

      URL de base de la cible (ex: "https://example.com")

   .. attribute:: timeout
      :type: float

      Timeout en secondes pour les requêtes HTTP (défaut: 5.0)

   .. attribute:: cookies
      :type: dict

      Dictionnaire de cookies de session (ex: {"PHPSESSID": "abc123"})

   .. attribute:: show_codes
      :type: list

      Liste des codes HTTP à afficher uniquement

   .. attribute:: hide_codes
      :type: list

      Liste des codes HTTP à masquer

   .. attribute:: follow_redirect
      :type: bool

      Suivre ou non les redirections HTTP

   .. attribute:: xss_marker
      :type: str

      Marqueur utilisé pour détecter les XSS (défaut: "xss")

   .. attribute:: results
      :type: list

      Liste stockant tous les résultats de fuzzing

   .. attribute:: baseline_length
      :type: int

      Longueur de la réponse baseline pour détecter les anomalies

   .. attribute:: baseline_tags
      :type: int

      Nombre de balises HTML dans la réponse baseline

   **Méthodes principales**

   .. automethod:: fuzz_directories
   
   .. automethod:: fuzz_parameter
   
   .. automethod:: fuzz_post_parameter
   
   .. automethod:: fuzz_form
   
   .. automethod:: extract_form_fields
   
   .. automethod:: export_results_txt

   **Méthodes privées**

   .. automethod:: _detect_anomalies
   
   .. automethod:: _include_result
   
   .. automethod:: _print_result

Fonctions utilitaires
---------------------

.. autofunction:: tools.fuzz.parse_status_codes

.. autofunction:: tools.fuzz.transform_payloads


Détection d'anomalies
~~~~~~~~~~~~~~~~~~~~~

Le fuzzer détecte automatiquement plusieurs types d'anomalies :

**Vulnérabilités XSS**

* Contexte HTML non échappé (``XSS_HTML``)
* Contexte JavaScript (``XSS_JS``)

**Injections SQL**

* Erreurs de syntaxe SQL (``SQL_SYNTAX``, ``SQL_ERROR``)
* Erreurs MySQL (``MYSQL_ERROR``)
* Erreurs PostgreSQL (``POSTGRES_ERROR``)
* Erreurs Oracle (``ORACLE_ERROR``)
* Erreurs SQLite (``SQLITE_ERROR``)

**Erreurs applicatives**

* Erreurs fatales (``FATAL_ERROR``)
* Traceback Python/PHP (``TRACEBACK``)
* Warnings PHP (``PHP_WARNING``)
* Variables non définies (``UNDEFINED_VAR``)
* Exceptions générales (``EXCEPTION``)

**Anomalies de réponse**

* Différence de taille significative (``SIZE_DIFF``)
* Réponse anormalement longue (``LARGE``)
* Réponse anormalement courte (``SHORT``)
* Balises HTML supplémentaires (``EXTRA_TAGS``)


Export des résultats
--------------------

Les résultats peuvent être exportés au format texte

Format du fichier d'export :

.. code-block:: text

   [200] https://example.com/admin | payload='admin' | length=5234 bytes | reasons=['SIZE_DIFF (+1234)']
   [200] https://example.com/config.php | payload='config.php' | length=8956 bytes | reasons=['EXTRA_TAGS (+15)']
   [500] https://example.com/search?q=' | payload="'" | length=1024 bytes | reasons=['SQL_SYNTAX', 'SERVER_ERROR_500']