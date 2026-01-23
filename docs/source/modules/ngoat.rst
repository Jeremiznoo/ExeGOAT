Module nGOAT (nGOAT.py)
=======================

Le module **nGOAT** est un scanner réseau avec interface graphique (GUI).

Vue d'ensemble
--------------

nGOAT combine plusieurs techniques de reconnaissance réseau dans une interface Tkinter moderne :

* Scan de plage IP
* Résolution NetBIOS
* Résolution DNS inverse
* Lookup de constructeur MAC (via API)
* Scan SNMP (v2c et v3) pour récupération de table ARP

Interface Graphique
~~~~~~~~~~~~~~~~~~~

.. autoclass:: tools.nGOAT.NetworkScannerGUI
   :members:
   :undoc-members:
   :show-inheritance:
   :special-members: __init__

Utilitaires
~~~~~~~~~~~

.. autoclass:: tools.nGOAT.MACVendorLookup
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: tools.nGOAT.NetBIOSQuery
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: tools.nGOAT.CustomDNSResolver
   :members:
   :undoc-members:
   :show-inheritance:

Point d'entrée
--------------

.. autofunction:: tools.nGOAT.run_gui
