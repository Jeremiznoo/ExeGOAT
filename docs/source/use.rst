Utilisation
===========

Build the image
---------------

.. code-block:: bash

   docker build -t exegoat .

Run the container
-----------------
.. code-block:: bash

   docker run exegoat

Fuzzer option
--------------
TODO

Fuzzer command example
----------------------

.. code-block:: bash
    
    python main.py fuzzer -u "http://localhost:4280/vulnerabilities/sqli/" -w wordlists/sqli.txt -m form -p id --cookie "PHPSESSID=example; security=low" -o results_sqli_auth.txt
