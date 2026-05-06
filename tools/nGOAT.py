#!/usr/bin/env python3
"""
nGOAT - Network Scanner with SNMP Support

Made by Jeremy D.
https://github.com/jeremiznoo
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import ipaddress
import threading
import subprocess
import platform
import re
import json
import csv
from queue import Queue
import urllib.request
import urllib.error
import os
import sys
import shutil
import logging
from datetime import datetime
from PIL import Image, ImageTk

# Windows-specific imports (optional)
try:
    import ctypes
    WINDOWS_ADMIN_CHECK = True
except ImportError:
    WINDOWS_ADMIN_CHECK = False

# ==========================================
# SNMP - Solution universelle (Windows/Linux)
# ==========================================
# Essaie d'abord snmpwalk (Linux), puis pysnmp synchrone (Windows/Linux)
PYSNMP_AVAILABLE = False
try:
    from pysnmp.hlapi import (
        nextCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, UsmUserData
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    try:
        # Fallback: essayer l'ancienne API v1arch (mais en synchrone)
        from pysnmp.hlapi.v1arch import (
            nextCmd, CommunityData, UdpTransportTarget,
            ObjectType, ObjectIdentity, UsmUserData
        )
        PYSNMP_AVAILABLE = True
    except ImportError:
        PYSNMP_AVAILABLE = False

# ==========================================
# MODULES RÉSEAU
# ==========================================

class CustomDNSResolver:
    """
    Résolveur DNS personnalisé pour les requêtes PTR manuelles
    """
    def __init__(self, dns_server):
        """
        Initialise le résolveur

        Args:
            dns_server (str): Adresse IP du serveur DNS
        """
        self.dns_server = dns_server
        self.port = 53

    def resolve_ptr(self, ip_address):
        """
        Tente une résolution inverse (PTR) via un serveur DNS spécifique sans utiliser le système

        Args:
            ip_address (str): Adresse IP à résoudre

        Returns:
            str: Nom de domaine trouvé ou None
        """
        if not self.dns_server: return None
        try:
            reversed_ip = '.'.join(reversed(ip_address.split('.'))) + ".in-addr.arpa"
            packet = b'\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            qname = b''
            for part in reversed_ip.split('.'): qname += bytes([len(part)]) + part.encode('ascii')
            qname += b'\x00\x00\x0C\x00\x01'

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(packet + qname, (self.dns_server, self.port))
            data, _ = sock.recvfrom(1024)
            sock.close()

            if len(data) > 12:
                clean_data = re.sub(r'[^a-zA-Z0-9\-\.]', '.', data[12:].decode('latin-1', errors='ignore'))
                parts = [p for p in clean_data.split('.') if len(p) > 2]
                if parts: return ".".join(parts[-3:])

        except Exception: 
            return None
        return None

class NetBIOSQuery:
    """
    Classe pour effectuer des requêtes NetBIOS (NBNS)
    """
    def __init__(self): self.port = 137
    def get_info(self, ip):
        """
        Récupère les informations NetBIOS d'une IP

        Args:
            ip (str): Adresse IP cible

        Returns:
            tuple: (Nom NetBIOS, Adresse MAC) ou (None, None)
        """
        try:
            packet = b'\x80\x96\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(packet, (str(ip), self.port))
            data, _ = sock.recvfrom(1024)
            sock.close()
            if len(data) > 57:
                nb_name = data[57:72].decode('utf-8', errors='ignore').strip()
                mac = ':'.join(f'{b:02X}' for b in data[-6:])
                return nb_name, (mac if mac != "00:00:00:00:00:00" else None)

        except Exception: 
            pass
        return None, None

class MACVendorLookup:
    """
    Classe pour la recherche de fournisseurs MAC via API externe
    """
    def __init__(self):
        """
        Initialise le lookup avec un cache
        """
        self.cache = {}  # Cache pour éviter les requêtes répétées

    def get_vendor(self, mac, force_refresh=False):
        """
        Récupère le vendor UNIQUEMENT via l'API macvendorlookup.com

        Args:
            mac (str): Adresse MAC (format XX:XX:XX:XX:XX:XX)
            force_refresh (bool): Forcer la requête même si en cache

        Returns:
            str: Nom du constructeur ou chaîne vide
        """
        if not mac or mac == "N/A": 
            return ""

        # Nettoyer la MAC pour extraire l'OUI (premiers 6 caractères hex)
        mac_clean = mac.replace(":", "").replace("-", "").replace(".", "").upper()
        if len(mac_clean) < 6:
            return ""

        oui = mac_clean[:6]  # OUI complet (6 caractères)

        # Vérifier le cache (sauf si on force le refresh)
        if not force_refresh and oui in self.cache:
            cached = self.cache[oui]
            # Si le cache contient quelque chose, le retourner
            if cached:
                return cached
            # Si le cache est vide et qu'on ne force pas, retourner vide
            # (pour éviter de spammer l'API)
            return ""

        # Utiliser UNIQUEMENT l'API macvendorlookup.com
        vendor = None

        # Essayer d'abord avec la MAC complète (meilleur résultat)
        if len(mac_clean) >= 12:
            vendor = self._try_macvendorlookup(mac_clean)

        # Si pas trouvé avec la MAC complète, essayer avec l'OUI seulement (6 caractères)
        if not vendor:
            vendor = self._try_macvendorlookup(oui)

        # Si toujours pas trouvé, essayer avec 8 caractères (pour OUI36)
        if not vendor and len(mac_clean) >= 8:
            vendor = self._try_macvendorlookup(mac_clean[:8])

        # Mettre en cache (même si vide) pour éviter les requêtes répétées
        self.cache[oui] = vendor or ""
        return vendor or ""

    def _try_macvendorlookup(self, mac_format):
        """
        Essaie l'API macvendorlookup.com (https://www.macvendorlookup.com/api)

        Args:
            mac_format (str): Adresse MAC ou OUI (nettoyée ou non)

        Returns:
            str: Nom du constructeur ou None
        """
        try:
            # Nettoyer le format MAC (enlever tous les séparateurs pour l'URL)
            mac_clean = str(mac_format).replace(":", "").replace("-", "").replace(".", "").upper()

            # L'API nécessite au moins 6 caractères hex
            if len(mac_clean) < 6:
                return None

            # URL de l'API: https://www.macvendorlookup.com/api/v2/{MAC_Address}
            url = f"https://www.macvendorlookup.com/api/v2/{mac_clean}"

            req = urllib.request.Request(url, headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json'
            })

            with urllib.request.urlopen(req, timeout=5) as r:
                # L'API retourne 200 OK avec des données ou 204 No Content si pas trouvé
                if r.status == 200:
                    data = r.read().decode('utf-8')
                    if data:
                        try:
                            # L'API retourne un tableau JSON
                            results = json.loads(data)
                            if results and len(results) > 0:
                                # Prendre le premier résultat (le plus pertinent)
                                company = results[0].get('company', '')
                                if company:
                                    return company.strip()
                        except json.JSONDecodeError:
                            pass
                elif r.status == 204:
                    # No Content = pas trouvé
                    return None

        except urllib.error.HTTPError as e:
            # 204 = pas trouvé (normal), autres erreurs = problème
            if e.code != 204:
                pass  # Autre erreur HTTP
        except urllib.error.URLError:
            # Problème de connexion
            pass
        except Exception:
            # Autre erreur
            pass

        return None


# ==========================================
# INTERFACE GRAPHIQUE
# ==========================================

class NetworkScannerGUI:
    """
    Interface graphique principale pour le scanner réseau nGOAT
    """
    def __init__(self, root):
        """
        Initialise l'application GUI

        Args:
            root (tk.Tk): Fenêtre racine Tkinter
        """
        self.root = root
        self.root.title("nGOAT Scanner")
        self.root.geometry("1400x850")

        # Logo Palette (Dark Mode)
        # Red: ~#e74c3c, Blue: ~#5dade2, BG: Black/Dark
        self.colors = {
            'sidebar': '#000000', 
            'bg_main': '#121212', 
            'card': '#1e1e1e', 
            'accent': '#5dade2', # Light Blue
            'secondary': '#e74c3c', # Red
            'text_main': '#ffffff', 
            'text_muted': '#b0b0b0',
            'success': '#2ecc71', 
            'danger': '#e74c3c'
        }

        self.snmp_mac_cache = {} # { 'IP': 'MAC' }
        self.snmp_cache_lock = threading.Lock()
        self.scanning = False
        self.continuous_mode = False

        self.mac_lookup = MACVendorLookup()
        self.netbios = NetBIOSQuery()

        # --- Variables de Configuration ---
        self.ip_range_var = tk.StringVar(value="10.0.0.0/24")

        # Options
        self.opt_netbios = tk.BooleanVar(value=True)
        self.opt_dns = tk.BooleanVar(value=True)
        self.opt_mac_vendor = tk.BooleanVar(value=True)
        self.opt_snmp = tk.BooleanVar(value=False)

        # SNMP Config
        self.snmp_version = tk.StringVar(value="v2c")
        self.snmp_target_var = tk.StringVar(value="10.0.0.1")
        self.snmp_community_var = tk.StringVar(value="public")
        # SNMP v3
        self.snmp_user = tk.StringVar(value="")
        self.snmp_auth_proto = tk.StringVar(value="SHA")
        self.snmp_auth_pass = tk.StringVar(value="")
        self.snmp_priv_proto = tk.StringVar(value="AES")
        self.snmp_priv_pass = tk.StringVar(value="")
        self.dns_ip_var = tk.StringVar(value="1.1.1.1")

        # ==========================================
        # INFRASTRUCTURE & CONFIGURATION
        # ==========================================
        
        # Détection OS
        self.is_windows = platform.system() == 'Windows'
        self.is_linux = platform.system() == 'Linux'
        self.is_macos = platform.system() == 'Darwin'
        
        # Répertoires de configuration
        self.config_dir = self._get_config_dir()
        self.scans_dir = os.path.join(self.config_dir, 'scans')
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.scans_dir, exist_ok=True)
        
        # Logging
        self.setup_logging()
        self.logger.info(f"nGOAT démarré sur {platform.system()}")
        
        # Thème
        self.theme = "dark"  # dark ou light
        
        # Variable pour tracking du tri
        self.sort_reverse = {}  # {column: bool} pour alternance asc/desc
        
        # Configuration
        self.setup_style()
        self.setup_layout()
        
        # Auto-charger la configuration sauvegardée
        self.root.after(100, self.load_config)
        
        # Vérifier les permissions admin sur Windows
        if self.is_windows:
            self.root.after(200, self.check_admin_windows)

    def setup_style(self):
        """
        Configure les styles ttk pour l'interface (Dark Mode)
        """
        style = ttk.Style()
        style.theme_use('clam')

        # Couleurs
        bg = self.colors['bg_main']
        sidebar_bg = self.colors['sidebar']
        accent = self.colors['accent']
        card_bg = self.colors['card']
        text = self.colors['text_main']
        text_muted = self.colors['text_muted']

        # Frames
        style.configure("Sidebar.TFrame", background=sidebar_bg)
        style.configure("Main.TFrame", background=bg)
        style.configure("Card.TFrame", background=card_bg, relief="flat", borderwidth=0)

        # Labels
        style.configure("Sidebar.TLabel", background=sidebar_bg, foreground=text, font=("Segoe UI", 10))
        # Ensure Status label specifically is visible

        style.configure("Title.TLabel", background=card_bg, foreground=accent, font=("Segoe UI", 11, "bold"))
        style.configure("Normal.TLabel", background=card_bg, foreground=text, font=("Segoe UI", 9))

        # Checkbuttons & Radiobuttons
        style.configure("TCheckbutton", background=card_bg, foreground=text, font=("Segoe UI", 9))
        style.map("TCheckbutton", background=[("active", card_bg)], foreground=[("active", accent)])

        style.configure("TRadiobutton", background=card_bg, foreground=text, font=("Segoe UI", 9))
        style.map("TRadiobutton", background=[("active", card_bg)], foreground=[("active", accent)])

        # Entries (Dark input)
        style.configure("TEntry", fieldbackground="#2d2d2d", foreground=text, insertcolor=text, borderwidth=0)

        # Buttons
        style.configure("Action.TButton", background=accent, foreground="#000000", font=("Segoe UI", 10, "bold"), borderwidth=0)
        style.map("Action.TButton", background=[("active", "#3498db"), ("disabled", "#555")])

        # Treeview (Dark Table)
        style.configure("Treeview", 
                        background="#2d2d2d", 
                        fieldbackground="#2d2d2d", 
                        foreground=text,
                        rowheight=30, 
                        font=("Segoe UI", 9), 
                        borderwidth=0)

        style.configure("Treeview.Heading", 
                        font=("Segoe UI", 9, "bold"), 
                        background="#1e1e1e", 
                        foreground=accent,
                        relief="flat")

        style.map("Treeview", background=[("selected", self.colors['secondary'])], foreground=[("selected", "white")])

    def setup_layout(self):
        """
        Organise la disposition principale des widgets
        """
        container = ttk.Frame(self.root)
        container.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        sidebar = ttk.Frame(container, style="Sidebar.TFrame", width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        # Logo
        logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logo.png")
        if os.path.exists(logo_path):
            try:
                pil_img = Image.open(logo_path)
                # Resize keeping aspect ratio (width=200 max)
                base_width = 200
                w_percent = (base_width / float(pil_img.size[0]))
                h_size = int((float(pil_img.size[1]) * float(w_percent)))
                pil_img = pil_img.resize((base_width, h_size), Image.Resampling.LANCZOS)
                
                self.logo_img = ImageTk.PhotoImage(pil_img)
                lbl_logo = ttk.Label(sidebar, image=self.logo_img, style="Sidebar.TLabel")
                lbl_logo.pack(pady=(20, 10))
            except Exception:
                ttk.Label(sidebar, text="nGOAT", font=("Segoe UI", 20, "bold"), foreground=self.colors['secondary'], background=self.colors['sidebar']).pack(pady=30)
        else:
            ttk.Label(sidebar, text="nGOAT SCANNER", font=("Segoe UI", 16, "bold"), foreground=self.colors['secondary'], background=self.colors['sidebar']).pack(pady=30)

        self.btn_scan = ttk.Button(sidebar, text="▶ LANCER SCAN", style="Action.TButton", command=self.start_single_scan)
        self.btn_scan.pack(fill=tk.X, padx=20, pady=10)

        self.btn_cont = ttk.Button(sidebar, text="∞ MODE CONTINU", command=self.toggle_continuous_scan)
        self.btn_cont.pack(fill=tk.X, padx=20, pady=5)

        self.btn_stop = ttk.Button(sidebar, text="■ ARRÊTER", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(fill=tk.X, padx=20, pady=5)

        ttk.Separator(sidebar, orient='horizontal').pack(fill=tk.X, padx=20, pady=20)
        
        # Boutons d'export
        ttk.Button(sidebar, text="Exporte CSV", command=self.export_csv).pack(fill=tk.X, padx=20, pady=5)
        ttk.Button(sidebar, text="Effacer", command=self.clear_results).pack(fill=tk.X, padx=20, pady=5)

        self.status_label = ttk.Label(sidebar, text="Prêt", style="Sidebar.TLabel")
        self.status_label.pack(side=tk.BOTTOM, pady=10)
        self.progress = ttk.Progressbar(sidebar, mode='indeterminate')

        # Main Area
        main = ttk.Frame(container, style="Main.TFrame", padding=20)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # --- Settings Area (Top) ---
        settings_frame = ttk.Frame(main, style="Card.TFrame", padding=15)
        settings_frame.pack(fill=tk.X, pady=(0, 20))

        # Title
        ttk.Label(settings_frame, text="CONFIGURATION DU SCAN", style="Title.TLabel").pack(anchor="w", pady=(0, 10))

        # Grid layout pour les settings
        grid_frame = ttk.Frame(settings_frame, style="Card.TFrame")
        grid_frame.pack(fill=tk.X)

        # Col 1: Scan Target & DNS
        col1 = ttk.Frame(grid_frame, style="Card.TFrame")
        col1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.create_field(col1, "Plage IP", self.ip_range_var)
        self.create_field(col1, "Serveur DNS", self.dns_ip_var)

        # Col 2: Options
        col2 = ttk.Frame(grid_frame, style="Card.TFrame")
        col2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        ttk.Label(col2, text="Options Actives", style="Normal.TLabel").pack(anchor="w", pady=(0, 5))
        ttk.Checkbutton(col2, text="Résolution NetBIOS", variable=self.opt_netbios).pack(anchor="w")
        ttk.Checkbutton(col2, text="Résolution DNS", variable=self.opt_dns).pack(anchor="w")
        ttk.Checkbutton(col2, text="MAC Vendor Lookup", variable=self.opt_mac_vendor).pack(anchor="w")
        ttk.Checkbutton(col2, text="Activer Scan SNMP", variable=self.opt_snmp, command=self.toggle_snmp_options).pack(anchor="w")

        # Col 3: SNMP Details
        self.col3 = ttk.Frame(grid_frame, style="Card.TFrame")
        self.col3.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)

        # SNMP Frame (dynamique)
        self.snmp_frame_content = ttk.Frame(self.col3, style="Card.TFrame")
        self.snmp_frame_content.pack(fill=tk.X)
        self.refresh_snmp_ui()

        # --- Results Area (Bottom) ---
        # Treeview
        cols = ('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports')
        tree_frame = ttk.Frame(main, style="Card.TFrame", padding=1)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(tree_frame, columns=cols, show='headings')
        for c in cols: 
            self.tree.heading(c, text=c)
            width = 100 if c in ['Statut', 'OS', 'Ports'] else 150
            if c == 'Vendor': width = 200
            self.tree.column(c, width=width)

        # Scrollbar
        sb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.tag_configure('online', foreground=self.colors['success'])
        
        # --- Bindings UX ---
        # 1. Tri des colonnes au clic sur l'en-tête
        for col in cols:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
        
        # 2. Suppression par touche Delete
        self.tree.bind('<Delete>', self.delete_selected_items)
        
        # 3. Auto-resize au double-clic sur les en-têtes
        for col in cols:
            self.tree.heading(col, text=col, command=lambda c=col: self.sort_column(c))
            # Note: Double-clic géré via <Double-1> sur la région de l'en-tête
        self.tree.bind('<Double-1>', self.auto_resize_column)

    def toggle_snmp_options(self):
        """Active/Désactive l'UI SNMP"""
        if self.opt_snmp.get():
            self.refresh_snmp_ui()
        else:
            for widget in self.snmp_frame_content.winfo_children(): widget.destroy()
            ttk.Label(self.snmp_frame_content, text="SNMP Désactivé", style="Normal.TLabel", foreground="#666").pack(anchor="w", pady=10)

    def refresh_snmp_ui(self):
        """Reconstruit l'interface SNMP selon la version"""
        for widget in self.snmp_frame_content.winfo_children(): widget.destroy()

        if not self.opt_snmp.get():
            self.toggle_snmp_options()
            return

        ttk.Label(self.snmp_frame_content, text="Version SNMP", style="Normal.TLabel").pack(anchor="w")
        v_frame = ttk.Frame(self.snmp_frame_content, style="Card.TFrame")
        v_frame.pack(fill=tk.X, pady=(0, 5))
        ttk.Radiobutton(v_frame, text="v2c", variable=self.snmp_version, value="v2c", command=self.refresh_snmp_ui).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(v_frame, text="v3", variable=self.snmp_version, value="v3", command=self.refresh_snmp_ui).pack(side=tk.LEFT)

        self.create_field(self.snmp_frame_content, "Routeur IP", self.snmp_target_var)

        if self.snmp_version.get() == "v2c":
            self.create_field(self.snmp_frame_content, "Communauté", self.snmp_community_var)
        else:
            # v3 fields
            self.create_field(self.snmp_frame_content, "User", self.snmp_user)
            self.create_field(self.snmp_frame_content, "Auth Pass", self.snmp_auth_pass)
            self.create_field(self.snmp_frame_content, "Priv Pass", self.snmp_priv_pass)

    def create_field(self, parent, label, var):
        """
        Crée un champ de saisie labellisé propre avec validation IP
        """
        f = ttk.Frame(parent, style="Card.TFrame")
        f.pack(fill=tk.X, pady=2)
        ttk.Label(f, text=label, style="Normal.TLabel").pack(anchor="w")
        
        entry = ttk.Entry(f, textvariable=var)
        
        # Appliquer validation si le champ concerne une IP
        if any(keyword in label.lower() for keyword in ['ip', 'dns', 'routeur', 'plage']):
            # Enregistrer la validation
            vcmd = (self.root.register(self.validate_ip_entry), '%P')
            entry.config(validate='key', validatecommand=vcmd)
        
        entry.pack(fill=tk.X)

# ==========================================
# FONCTIONNALITÉS UX / Quality of Life
# ==========================================

    def validate_ip_entry(self, new_value):
        """
        Valide les entrées pour les champs IP (Plage IP, DNS, Routeur)
        N'autorise que : chiffres (0-9), points (.), slash (/), espace
        
        Args:
            new_value (str): Nouvelle valeur proposée
        
        Returns:
            bool: True si valide, False sinon
        """
        # Autoriser vide (pour pouvoir effacer)
        if new_value == "":
            return True
        
        # Regex: seulement chiffres, points, slash, espaces
        # Pattern: ^[0-9./\s]*$
        import re
        pattern = r'^[0-9./\s]*$'
        return bool(re.match(pattern, new_value))
    
    def sort_column(self, col):
        """
        Trie le Treeview par colonne avec logique intelligente
        - Colonne 'IP' : tri numérique via ipaddress.IPv4Address
        - Autres colonnes : tri alphabétique
        Alterne entre ascendant/descendant à chaque clic
        
        Args:
            col (str): Nom de la colonne à trier
        """
        # Toggle reverse pour cette colonne
        self.sort_reverse[col] = not self.sort_reverse.get(col, False)
        reverse = self.sort_reverse[col]
        
        # Récupérer tous les items
        items = [(self.tree.set(item, col), item) for item in self.tree.get_children('')]
        
        # Fonction de tri différente selon la colonne
        if col == 'IP':
            # Tri numérique pour les IPs
            def sort_key(item):
                try:
                    return ipaddress.IPv4Address(item[0])
                except:
                    # Si ce n'est pas une IP valide, mettre à la fin
                    return ipaddress.IPv4Address('255.255.255.255')
            items.sort(key=sort_key, reverse=reverse)
        else:
            # Tri alphabétique pour les autres colonnes
            items.sort(key=lambda item: item[0].lower(), reverse=reverse)
        
        # Réorganiser les items dans le Treeview
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
        
        # Mettre à jour l'en-tête pour indiquer le sens du tri
        heading_text = col
        if reverse:
            heading_text = f"{col} ▼"
        else:
            heading_text = f"{col} ▲"
        
        self.tree.heading(col, text=heading_text)
        
        # Réinitialiser les autres en-têtes
        for c in ('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports'):
            if c != col:
                self.tree.heading(c, text=c)
    
    def delete_selected_items(self, event=None):
        """
        Supprime les lignes sélectionnées du Treeview
        Lié à la touche <Delete>
        
        Args:
            event: Événement Tkinter (optionnel)
        """
        selected_items = self.tree.selection()
        
        if not selected_items:
            return
        
        # Demander confirmation si plusieurs lignes
        if len(selected_items) > 1:
            confirm = messagebox.askyesno(
                "Confirmation",
                f"Supprimer {len(selected_items)} lignes sélectionnées ?"
            )
            if not confirm:
                return
        
        # Supprimer les items
        for item in selected_items:
            self.tree.delete(item)
    
    def auto_resize_column(self, event):
        """
        Ajuste automatiquement la largeur de la colonne au double-clic
        Adapte la largeur au contenu le plus large (header inclus)
        
        Args:
            event: Événement Tkinter
        """
        # Identifier la région cliquée
        region = self.tree.identify_region(event.x, event.y)
        
        # Vérifier si c'est un double-clic sur l'en-tête
        if region != 'heading':
            return
        
        # Identifier la colonne
        col = self.tree.identify_column(event.x)
        if not col:
            return
        
        # Convertir #1, #2, etc. en nom de colonne
        col_index = int(col.replace('#', '')) - 1
        cols = ('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports')
        col_name = cols[col_index]
        
        # Calculer la largeur nécessaire
        # 1. Largeur du header
        header_width = len(col_name) * 10  # Approximation
        
        # 2. Largeur du contenu le plus large
        max_width = header_width
        for item in self.tree.get_children(''):
            value = str(self.tree.set(item, col_name))
            width = len(value) * 8  # Approximation (8 pixels par caractère)
            max_width = max(max_width, width)
        
        # Ajouter une marge
        max_width += 20
        
        # Limiter la largeur max (pour éviter des colonnes trop larges)
        max_width = min(max_width, 400)
        
        # Appliquer la nouvelle largeur
        self.tree.column(col_name, width=max_width)

# ==========================================
# INFRASTRUCTURE & CONFIGURATION
# ==========================================

    def _get_config_dir(self):
        """
        Retourne le répertoire de configuration selon l'OS
        Windows: %APPDATA%/nGOAT
        Linux/Mac: ~/.config/ngoat
        """
        if self.is_windows:
            base_dir = os.getenv('APPDATA', os.path.expanduser('~'))
            return os.path.join(base_dir, 'nGOAT')
        else:
            return os.path.expanduser('~/.config/ngoat')
    
    def setup_logging(self):
        """Configure le système de logging avec sortie fichier"""
        log_file = os.path.join(self.config_dir, 'ngoat.log')
        
        # Configuration logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('nGOAT')
    
    @staticmethod
    def resource_path(relative_path):
        """
        Obtient le chemin absolu des ressources (compatible .exe PyInstaller)
        
        Args:
            relative_path (str): Chemin relatif de la ressource
        
        Returns:
            str: Chemin absolu
        """
        try:
            # PyInstaller crée un dossier temp _MEIPASS
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        
        return os.path.join(base_path, relative_path)
    
    def load_config(self):
        """Charge la configuration depuis le fichier JSON"""
        config_file = os.path.join(self.config_dir, 'ngoat_config.json')
        
        if not os.path.exists(config_file):
            self.logger.info("Aucune configuration trouvée, utilisation des valeurs par défaut")
            return
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            # Charger les valeurs réseau
            if 'network' in config:
                self.ip_range_var.set(config['network'].get('ip_range', ''))
                self.dns_ip_var.set(config['network'].get('dns_server', '1.1.1.1'))
            
            # Charger SNMP
            if 'snmp' in config:
                self.opt_snmp.set(config['snmp'].get('enabled', False))
                self.snmp_version.set(config['snmp'].get('version', 'v2c'))
                self.snmp_target_var.set(config['snmp'].get('target', ''))
                self.snmp_community_var.set(config['snmp'].get('community', 'public'))
                self.snmp_user.set(config['snmp'].get('user', ''))
            
            # Charger options
            if 'options' in config:
                self.opt_netbios.set(config['options'].get('netbios', True))
                self.opt_dns.set(config['options'].get('dns', True))
                self.opt_mac_vendor.set(config['options'].get('mac_vendor', True))
            
            # Charger UI
            if 'ui' in config:
                self.theme = config['ui'].get('theme', 'dark')
            
            self.logger.info("Configuration chargée avec succès")
            
        except Exception as e:
            self.logger.error(f"Erreur chargement config: {e}")
    
    def check_admin_windows(self):
        """Vérifie si le script tourne avec privilèges admin sur Windows"""
        if not WINDOWS_ADMIN_CHECK or not self.is_windows:
            return
        
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                messagebox.showwarning(
                    "Privilèges Administrateur",
                    "⚠️ nGOAT n'est pas exécuté en tant qu'administrateur.\n\n"
                    "Certaines fonctionnalités (scan réseau, SNMP) peuvent\n"
                    "nécessiter des privilèges élevés.\n\n"
                    "Pour un scan complet:\n"
                    "→ Clic droit sur nGOAT.exe\n"
                    "→ 'Exécuter en tant qu'administrateur'"
                )
                self.logger.warning("Exécution sans privilèges administrateur")
        except Exception as e:
            self.logger.error(f"Erreur vérification admin: {e}")
    
    def get_ping_params(self):
        """Retourne les paramètres de ping adaptés à l'OS"""
        if self.is_windows:
            return ['-n', '1', '-w', '500']  # count, timeout ms
        else:
            return ['-c', '1', '-W', '0.5']  # count, timeout sec
    
    def get_arp_command(self):
        """Retourne la commande ARP adaptée à l'OS"""
        if self.is_windows:
            return ['arp', '-a']
        else:
            return ['arp', '-n']
    
    def export_excel(self):
        """Export les résultats en Excel (si openpyxl disponible)"""
        try:
            import openpyxl
        except ImportError:
            messagebox.showwarning(
                "Excel Export",
                "Le module 'openpyxl' n'est pas installé.\n\n"
                "Installation:\npip install openpyxl"
            )
            return
        
        if not self.tree.get_children():
            messagebox.showwarning("Export", "Aucune donnée à exporter")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".xlsx",
            filetypes=[("Excel", "*.xlsx"), ("Tous", "*.*")]
        )
        
        if not filename:
            return
        
        try:
            wb = openpyxl.Workbook()
            ws = wb.active
            ws.title = "Scan Results"
            
            # Headers
            headers = ['Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports']
            ws.append(headers)
            
            # Data
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                ws.append(values)
            
            # Style
            for cell in ws[1]:
                cell.font = openpyxl.styles.Font(bold=True)
            
            wb.save(filename)
            self.logger.info(f"Export Excel réussi: {filename}")
            messagebox.showinfo("Export", f"Export réussi:\n{filename}")
            
        except Exception as e:
            self.logger.error(f"Erreur export Excel: {e}")
            messagebox.showerror("Erreur", f"Erreur lors de l'export:\n{e}")
    
    def save_scan_history(self):
        """Sauvegarde l'historique du scan actuel"""
        if not self.tree.get_children():
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(self.scans_dir, f"scan_{timestamp}.json")
        
        try:
            results = {
                'scan_date': datetime.now().isoformat(),
                'scan_range': self.ip_range_var.get(),
                'total_hosts': len(self.tree.get_children()),
                'hosts': []
            }
            
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                results['hosts'].append({
                    'status': values[0],
                    'ip': values[1],
                    'os': values[2],
                    'hostname': values[3],
                    'mac': values[4],
                    'vendor': values[5],
                    'ports': values[6]
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Historique sauvegardé: {filename}")
            
        except Exception as e:
            self.logger.error(f"Erreur sauvegarde historique: {e}")

# ==========================================
# LOGIQUE DE SCAN ET SNMP
# ==========================================

    @staticmethod
    def clean_mac_address(raw_value):
        """
        Fonction universelle de nettoyage d'adresse MAC par Regex.
        Extrait exactement 12 caractères hexadécimaux, peu importe le format.
        
        Args:
            raw_value (str): Valeur brute (peut contenir 'Hex-STRING:', espaces, etc.)
        
        Returns:
            str: Adresse MAC formatée 'XX:XX:XX:XX:XX:XX' ou None si invalide
        """
        if not raw_value:
            return None
        
        value_str = str(raw_value)
        
        # Étape 1: Supprimer les préfixes de type SNMP connus
        # (important car "Hex-STRING" contient des caractères hexa valides!)
        type_prefixes = [
            'Hex-STRING:',
            'STRING:',
            'OCTET STRING:',
            'OctetString:',
            'HexString:',
        ]
        
        for prefix in type_prefixes:
            if prefix in value_str:
                # Prendre seulement ce qui suit le préfixe
                value_str = value_str.split(prefix, 1)[1]
                break
        
        # Étape 2: Extraire tous les caractères hexadécimaux (0-9, A-F, a-f)
        hex_chars = re.findall(r'[0-9A-Fa-f]', value_str)
        mac_clean = ''.join(hex_chars).upper()
        
        # Valider la longueur (exactement 12 caractères pour une MAC)
        if len(mac_clean) != 12:
            return None
        
        # Formater avec séparateurs ':'
        return ':'.join([mac_clean[i:i+2] for i in range(0, 12, 2)])

    @staticmethod
    def extract_ip_from_oid(oid_string, base_oid='1.3.6.1.2.1.4.22.1.2'):
        """
        Extrait l'adresse IP depuis un OID SNMP de manière infaillible.
        Gère la structure : [Base OID].[ifIndex].[IP_A.B.C.D]
        
        Args:
            oid_string (str): OID complet (peut commencer par 'iso' ou '1')
            base_oid (str): OID de base ipNetToMediaPhysAddress
        
        Returns:
            str: Adresse IP valide ou None
        """
        if not oid_string:
            return None
        
        # Étape 1: Normalisation - Remplacer 'iso' par '1'
        oid_normalized = oid_string.strip()
        if oid_normalized.startswith('iso.'):
            oid_normalized = '1.' + oid_normalized[4:]  # Remplace 'iso.' par '1.'
        elif oid_normalized.startswith('iso'):
            oid_normalized = '1' + oid_normalized[3:]  # Remplace 'iso' par '1'
        
        # Enlever le point initial si présent
        oid_normalized = oid_normalized.lstrip('.')
        
        # Étape 2: Vérifier que l'OID commence par le base_oid
        if not oid_normalized.startswith(base_oid):
            return None
        
        # Étape 3: Extraire le suffixe après le base_oid
        # Format: [base_oid].[ifIndex].[IP]
        suffix = oid_normalized[len(base_oid):].lstrip('.')
        parts = suffix.split('.')
        
        # Étape 4: Parser par soustraction
        # Le premier élément est l'ifIndex (longueur variable, à ignorer)
        # Les 4 éléments suivants forment l'IP
        if len(parts) < 5:  # Besoin d'au moins ifIndex + 4 octets IP
            # Cas particulier : pas d'ifIndex, directement l'IP
            if len(parts) == 4:
                try:
                    ip_candidate = '.'.join(parts)
                    ip_obj = ipaddress.ip_address(ip_candidate)
                    return str(ip_obj)
                except:
                    return None
            return None
        
        # Ignorer le premier élément (ifIndex) et prendre les 4 suivants
        ip_parts = parts[1:5]  # Skip ifIndex, take next 4
        
        try:
            ip_candidate = '.'.join(ip_parts)
            ip_obj = ipaddress.ip_address(ip_candidate)
            return str(ip_obj)
        except (ValueError, ipaddress.AddressValueError):
            return None

    def get_snmp_arp_table(self):
        """
        Récupère la table ARP (ipNetToMediaPhysAddress) via SNMP
        Met à jour le cache interne self.snmp_mac_cache
        Thread-safe, ne lève pas d'exception fatale
        """
        if not self.opt_snmp.get():
            return

        target = self.snmp_target_var.get()
        version = self.snmp_version.get()

        # Collect credentials
        creds = {}
        if version == "v2c":
            creds['community'] = self.snmp_community_var.get()
            if not creds['community']: 
                return
        else: # v3
            creds['user'] = self.snmp_user.get()
            if not creds['user']: 
                return
            creds['auth_proto'] = self.snmp_auth_proto.get()
            creds['auth_pass'] = self.snmp_auth_pass.get()
            creds['priv_proto'] = self.snmp_priv_proto.get()
            creds['priv_pass'] = self.snmp_priv_pass.get()

        self.log(f"Lecture Table ARP SNMP ({version}) : {target}...")

        mac_results = None
        
        try:
            # Méthode 1: snmpwalk (préféré)
            mac_results = self._get_snmp_via_snmpwalk(target, version, creds)
        except Exception as e:
            self.log(f"SNMP snmpwalk échec: {type(e).__name__}")

        # Méthode 2: pysnmp (fallback)
        if not mac_results and PYSNMP_AVAILABLE:
            try:
                mac_results = self._get_snmp_via_pysnmp(target, version, creds)
            except Exception as e:
                self.log(f"SNMP pysnmp échec: {type(e).__name__}")

        if mac_results:
            normalized_cache = {}
            for ip, mac in mac_results.items():
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    normalized_cache[str(ip_obj)] = mac
                except:
                    normalized_cache[ip] = mac

            with self.snmp_cache_lock:
                self.snmp_mac_cache = normalized_cache

            self.log(f"SNMP : {len(normalized_cache)} MACs récupérées")
        else:
            self.log("SNMP: Aucune donnée récupérée")

    def _get_snmp_via_snmpwalk(self, target, version, creds):
        """
        Récupère la table ARP via snmpwalk (v2c/v3)
        Gestion robuste : préfixe 'iso', ifIndex variable, parsing Hex-STRING
        
        Returns:
            dict: {ip: mac} ou None si échec
        """
        import shutil
        
        # Vérifier que snmpwalk est disponible
        if not shutil.which('snmpwalk'):
            return None
        
        try:
            oid_mac = '1.3.6.1.2.1.4.22.1.2'
            cmd = ['snmpwalk', '-O', 'n', '-t', '5']  # Output numérique, timeout 5s

            if version == "v2c":
                cmd.extend(['-v', '2c', '-c', creds.get('community', 'public')])
            else:
                cmd.extend(['-v', '3', '-u', creds.get('user'), '-l', 'authPriv'])
                # Auth
                if creds.get('auth_pass'):
                    cmd.extend(['-a', creds.get('auth_proto', 'SHA'), '-A', creds.get('auth_pass')])
                # Priv
                if creds.get('priv_pass'):
                    cmd.extend(['-x', creds.get('priv_proto', 'AES'), '-X', creds.get('priv_pass')])

            cmd.extend([target, oid_mac])

            # Exécution avec gestion d'erreurs
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=15,
                errors='ignore'  # Ignorer les erreurs d'encodage
            )

            if result.returncode != 0:
                return None

            mac_results = {}
            line_count = 0
            success_count = 0
            
            print("\n" + "="*80)
            print("DEBUG SNMP PARSING - Détail du traitement snmpwalk")
            print("="*80)
            
            # Parsing robuste de la sortie snmpwalk
            for line in result.stdout.strip().split('\n'):
                if not line or ' = ' not in line:
                    continue
                
                line_count += 1
                
                # Split OID = Value
                oid_part, _, val_part = line.partition(' = ')
                oid_part = oid_part.strip()
                val_part = val_part.strip()
                
                # Extraction IP depuis l'OID (gestion iso + ifIndex)
                ip = self.extract_ip_from_oid(oid_part, oid_mac)
                
                # Nettoyage MAC universel (Hex-STRING avec espaces)
                mac = self.clean_mac_address(val_part)
                
                # Debug output détaillé
                if ip and mac:
                    success_count += 1
                    mac_results[ip] = mac
                    if success_count <= 5 or success_count % 20 == 0:  # Afficher les 5 premiers puis tous les 20
                        print(f"  [{success_count:3d}] OID: {oid_part[:60]}<20chars>")
                        print(f"        ↪ IP: {ip:15s} | MAC: {mac}")
                else:
                    # Afficher les échecs pour debug
                    if line_count <= 3:  # Afficher seulement les 3 premiers échecs
                        print(f"  [✗] SKIP - OID: {oid_part[:60]}")
                        print(f"        Raison: IP={ip or 'FAIL'}, MAC={mac or 'FAIL'}")
            
            print("="*80)
            print(f"RÉSULTAT: {success_count}/{line_count} entrées extraites avec succès")
            print("="*80 + "\n")

            return mac_results if mac_results else None

        except subprocess.TimeoutExpired:
            print("⚠ SNMP Timeout: snmpwalk a dépassé le délai")
            return None
        except FileNotFoundError:
            print("⚠ SNMP Error: snmpwalk n'est pas installé")
            return None
        except Exception as e:
            print(f"⚠ SNMP Error: {type(e).__name__}: {e}")
            return None

    def _get_snmp_via_pysnmp(self, target, version, creds):
        """
        Récupère la table ARP via pysnmp synchrone (v2c principalement)
        Utilise un thread dédié pour isoler les opérations SNMP du main loop Tkinter
        
        Returns:
            dict: {ip: mac} ou None si échec
        """
        import concurrent.futures
        
        # Exécuter dans un thread séparé pour isolation complète
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._sync_get_snmp_pysnmp, target, version, creds)
            try:
                return future.result(timeout=20)
            except concurrent.futures.TimeoutError:
                return None
            except Exception:
                return None
    
    def _sync_get_snmp_pysnmp(self, target, version, creds):
        """
        Implémentation synchrone de pysnmp (pas d'asyncio)
        Exécutée dans un thread dédié pour compatibilité Tkinter
        
        Returns:
            dict: {ip: mac} ou None
        """
        mac_results = {}
        oid_mac = '1.3.6.1.2.1.4.22.1.2'
        
        try:
            # Prepare Auth Data
            if version == "v2c":
                auth_data = CommunityData(creds.get('community', 'public'), mpModel=1)
            else:
                # v3 support limité (complexe avec pysnmp)
                # Laisser snmpwalk gérer v3 de préférence
                return None
            
            # Créer les objets SNMP
            try:
                # API moderne pysnmp
                engine = SnmpEngine()
                transport = UdpTransportTarget((target, 161), timeout=5, retries=1)
                context = ContextData()
                
                # Itération sur la table ARP
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    engine, auth_data, transport, context,
                    ObjectType(ObjectIdentity(oid_mac)),
                    lexicographicMode=False,
                    maxRows=100
                ):
                    if errorIndication or errorStatus:
                        break
                    
                    if not varBinds:
                        break
                    
                    for varBind in varBinds:
                        oid_full = str(varBind[0])
                        val = varBind[1]
                        
                        # Vérifier que l'OID appartient bien à la table ARP
                        if not oid_full.startswith(oid_mac):
                            return mac_results
                        
                        # Extraction IP robuste
                        ip = self.extract_ip_from_oid(oid_full, oid_mac)
                        if not ip:
                            continue
                        
                        # Décodage MAC depuis les octets SNMP
                        try:
                            if hasattr(val, 'asOctets'):
                                mac_raw = val.asOctets()
                            elif hasattr(val, 'prettyPrint'):
                                # Fallback: utiliser la représentation texte
                                mac = self.clean_mac_address(val.prettyPrint())
                                if mac:
                                    mac_results[ip] = mac
                                continue
                            else:
                                continue
                            
                            # Formater les 6 octets en MAC
                            if len(mac_raw) == 6:
                                mac_fmt = ':'.join([f'{b:02X}' for b in mac_raw])
                                mac_results[ip] = mac_fmt
                        except Exception:
                            continue
                
            except NameError:
                # API v1arch (ancienne)
                transport = UdpTransportTarget((target, 161), timeout=5, retries=1)
                
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                    auth_data, transport,
                    ObjectType(ObjectIdentity(oid_mac)),
                    lexicographicMode=False
                ):
                    if errorIndication or errorStatus or not varBinds:
                        break
                    
                    for varBind in varBinds:
                        oid_full = str(varBind[0])
                        val = varBind[1]
                        
                        if not oid_full.startswith(oid_mac):
                            return mac_results
                        
                        ip = self.extract_ip_from_oid(oid_full, oid_mac)
                        if not ip:
                            continue
                        
                        if hasattr(val, 'asOctets'):
                            mac_raw = val.asOctets()
                            if len(mac_raw) == 6:
                                mac_fmt = ':'.join([f'{b:02X}' for b in mac_raw])
                                mac_results[ip] = mac_fmt
            
            return mac_results if mac_results else None
            
        except Exception:
            return None

    def get_mac_from_cache(self, ip_str):
        """
        Fonction centralisée pour récupérer une MAC depuis le cache SNMP
        Utilise une comparaison 'Force Brute' avec des objets IPv4Address
        pour gérer les variations de format (10.20.12.1 == 10.20.12.01)
        
        Args:
            ip_str (str): Adresse IP à rechercher
        
        Returns:
            str: Adresse MAC ou None si non trouvée
        """
        if not self.snmp_mac_cache:
            return None
        
        with self.snmp_cache_lock:
            # Étape 1: Normalisation de l'IP cible
            try:
                target_ip_obj = ipaddress.IPv4Address(ip_str)
            except (ValueError, ipaddress.AddressValueError):
                # Si l'IP n'est pas valide, essayer quand même une recherche string
                mac = self.snmp_mac_cache.get(ip_str)
                if mac:
                    return mac
                return None
            
            # Étape 2: Recherche directe avec IP normalisée
            ip_normalized = str(target_ip_obj)
            mac = self.snmp_mac_cache.get(ip_normalized)
            if mac:
                return mac
            
            # Étape 3: Force Brute - Comparer mathématiquement toutes les clés
            # Ceci gère les cas où les clés seraient stockées avec des formats différents
            # ou contiendraient des résidus d'OID
            for cached_key, cached_mac in self.snmp_mac_cache.items():
                try:
                    # Essayer d'extraire une IP valide depuis la clé
                    # (au cas où elle contiendrait des résidus comme '12.10.20.12.1')
                    
                    # D'abord, essayer la clé telle quelle
                    try:
                        cached_ip_obj = ipaddress.IPv4Address(cached_key)
                        # Comparaison mathématique des objets IPv4Address
                        if cached_ip_obj == target_ip_obj:
                            return cached_mac
                    except (ValueError, ipaddress.AddressValueError):
                        # Si la clé n'est pas une IP valide, essayer d'extraire
                        # les derniers 4 octets (au cas où résidu d'OID)
                        parts = cached_key.split('.')
                        if len(parts) >= 4:
                            # Tester toutes les sous-séquences de 4 nombres
                            for i in range(len(parts) - 3):
                                try:
                                    ip_candidate = '.'.join(parts[i:i+4])
                                    cached_ip_obj = ipaddress.IPv4Address(ip_candidate)
                                    if cached_ip_obj == target_ip_obj:
                                        return cached_mac
                                except (ValueError, ipaddress.AddressValueError):
                                    continue
                except Exception:
                    # Si tout échoue, essayer une comparaison string simple
                    if cached_key == ip_str or cached_key == ip_normalized:
                        return cached_mac
        
        return None
    
    def scan_host(self, ip):
        """
        Affiche le contenu complet du cache SNMP pour debug
        Écrit dans la console ET dans un fichier debug_snmp_cache.txt
        """
        import datetime
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        output_lines = []
        output_lines.append("="*70)
        output_lines.append(f"SNMP CACHE DUMP - {timestamp}")
        output_lines.append("="*70)
        
        with self.snmp_cache_lock:
            cache_size = len(self.snmp_mac_cache)
            output_lines.append(f"Taille du cache: {cache_size} entrées\n")
            
            if cache_size == 0:
                output_lines.append("⚠ CACHE VIDE - Aucune donnée SNMP récupérée\n")
            else:
                output_lines.append("Format: [Clé stockée] -> [Adresse MAC]\n")
                
                for idx, (cached_key, cached_mac) in enumerate(self.snmp_mac_cache.items(), 1):
                    # Analyser la clé pour détecter des anomalies
                    analysis = ""
                    try:
                        # Vérifier si c'est une IP valide
                        ipaddress.IPv4Address(cached_key)
                        analysis = "✓ IP valide"
                    except:
                        # Analyser les résidus potentiels
                        parts = cached_key.split('.')
                        if len(parts) > 4:
                            analysis = f"⚠ RÉSIDU OID ({len(parts)} parties)"
                        else:
                            analysis = "✗ Format invalide"
                    
                    output_lines.append(f"{idx:3d}. [{cached_key}] -> [{cached_mac}] ({analysis})")
        
        output_lines.append("="*70 + "\n")
        
        # Affichage console
        debug_text = "\n".join(output_lines)
        print(debug_text)
        
        # Écriture fichier
        try:
            debug_file = "debug_snmp_cache.txt"
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(debug_text)
            self.log(f"Debug dump → {debug_file}")
            messagebox.showinfo("Debug Dump", 
                f"Cache SNMP ({cache_size} entrées) dumpé dans:\n{debug_file}\n\nVoir aussi la console.")
        except Exception as e:
            self.log(f"Erreur dump fichier: {e}")
            messagebox.showinfo("Debug Dump", 
                f"Cache SNMP ({cache_size} entrées) affiché dans la console.")

    def scan_host(self, ip):
        """
        Analyse un hôte pour déterminer s'il est unique et récupérer ses infos

        Args:
            ip (str ou IPv4Address): Adresse IP à scanner

        Returns:
            None
        """
        ip_str = str(ip)
        
        # Normalisation stricte de l'IP pour correspondance avec le cache
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            ip_normalized = str(ip_obj)
        except:
            ip_normalized = ip_str
        
        # Ping pour vérifier si l'hôte est en ligne
        is_online, os_type = self.ping_host(ip_str)

        # Récupération MAC depuis le cache SNMP (avec fonction centralisée Force Brute)
        snmp_mac = self.get_mac_from_cache(ip_normalized) if self.opt_snmp.get() else None
        
        # Debug visuel temporaire
        if self.opt_snmp.get() and len(self.snmp_mac_cache) > 0:
            cache_keys_sample = list(self.snmp_mac_cache.keys())[:5]
            print(f"DEBUG: Looking for {ip_normalized} in cache keys: {cache_keys_sample}")
            if snmp_mac:
                print(f"DEBUG: ✓ Found SNMP MAC for {ip_normalized}: {snmp_mac}")
            else:
                print(f"DEBUG: ✗ No SNMP MAC found for {ip_normalized}")

        # Si on a une MAC SNMP, considérer l'hôte comme online
        # (même si le ping a échoué - important pour les hôtes qui bloquent ICMP)
        if snmp_mac and not is_online:
            is_online = True
            os_type = "Actif (SNMP Table)"

        if is_online:
            # Hostname logic
            hostname = "N/A"
            nb_mac = None

            # NetBIOS
            if self.opt_netbios.get():
                nb_name, nb_mac = self.netbios.get_info(ip_str)
                if nb_name: 
                    hostname = f"{nb_name} (NB)"

            # DNS (si pas de NetBIOS ou si on veut compléter)
            if self.opt_dns.get() and (hostname == "N/A" or "NB" not in hostname):
                res = CustomDNSResolver(self.dns_ip_var.get()).resolve_ptr(ip_str)
                if res: 
                    hostname = f"{res} (DNS)"

            # MAC Priority : SNMP > NetBIOS > ARP local
            # (SNMP est prioritaire car plus fiable sur réseau segmenté)
            mac = None
            
            # 1. Priorité SNMP si activé (données du routeur)
            if self.opt_snmp.get() and snmp_mac:
                mac = snmp_mac
            
            # 2. NetBIOS (si pas de SNMP ou SNMP non disponible)
            if not mac and nb_mac:
                mac = nb_mac
            
            # 3. ARP local (fallback)
            if not mac:
                mac = self.get_local_arp(ip_str)
            
            # 4. Dernier recours : réessayer SNMP même si option désactivée 
            # (au cas où le cache aurait été rempli précédemment)
            if not mac and not self.opt_snmp.get():
                mac = self.get_mac_from_cache(ip_normalized)

            if not mac:
                mac = "N/A"

            # Vendor Lookup : Lancé même si le ping a échoué, tant qu'on a une MAC
            # (Important pour les hôtes détectés uniquement via SNMP)
            vendor = ""
            if self.opt_mac_vendor.get() and mac != "N/A":
                 # Récupération initiale (cache)
                 vendor = self.mac_lookup.get_vendor(mac)
                 # Async refresh
                 threading.Thread(target=self._update_vendor_async, args=(ip_str, mac), daemon=True).start()

            # Affichage initial via root.after pour thread-safety
            data = ("🟢 Online", ip_str, os_type, hostname, mac, vendor, "Scanning...")
            self.root.after(0, lambda ip=ip_str, d=data: self.update_tree(d))

            # Lancer le scan de ports de manière asynchrone
            threading.Thread(target=self._scan_ports_async, args=(ip_str,), daemon=True).start()

    def _update_vendor_async(self, ip_str, mac):
        """
        Met à jour le vendor de manière asynchrone pour ne pas bloquer l'UI

        Args:
            ip_str (str): Adresse IP de l'hôte
            mac (str): Adresse MAC
        """
        # Forcer une nouvelle recherche (ne pas utiliser le cache vide)
        vendor = self.mac_lookup.get_vendor(mac, force_refresh=True)

        # Si toujours vide, essayer avec différentes variantes de la MAC
        if not vendor:
            # Essayer avec différents formats
            mac_variants = [
                mac.upper(),
                mac.lower(),
                mac.replace(":", "-"),
                mac.replace("-", ":")
            ]
            for mac_var in mac_variants:
                if mac_var != mac:
                    vendor = self.mac_lookup.get_vendor(mac_var, force_refresh=True)
                    if vendor:
                        break

        # Mettre à jour l'interface (même si vide, pour afficher "N/A" ou le résultat)
        final_vendor = vendor if vendor else "N/A"
        self.root.after(0, lambda ip=ip_str, v=final_vendor: self._update_tree_vendor(ip, v))

    def _scan_ports_async(self, ip_str):
        """
        Scanne les ports de manière asynchrone

        Args:
            ip_str (str): Adresse IP cible
        """
        open_ports = self.scan_ports(ip_str)
        ports_str = ", ".join(map(str, open_ports)) if open_ports else "Aucun"
        self.root.after(0, lambda ip=ip_str, p=ports_str: self._update_tree_ports(ip, p))

    def scan_ports(self, ip_str):
        """
        Scanne les ports TCP communs sur un hôte

        Args:
            ip_str (str): Adresse IP cible

        Returns:
            list: Liste des ports ouverts (int)
        """
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 3389, 8080]
        open_ports = []

        for port in common_ports:
            if not self.scanning:  # Arrêter si le scan est interrompu
                break
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((ip_str, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            except Exception:
                pass

        return open_ports

    def _update_tree_ports(self, ip_str, ports_str):
        """Met à jour uniquement les ports dans le treeview"""
        for item in self.tree.get_children():
            values = list(self.tree.item(item)['values'])
            if len(values) > 1 and values[1] == ip_str:
                # Mettre à jour la colonne Ports (index 6)
                if len(values) > 6:
                    values[6] = ports_str
                    self.tree.item(item, values=values)
                break

    def _update_tree_vendor(self, ip_str, vendor):
        """
        Met à jour uniquement le vendor dans le treeview

        Args:
            ip_str (str): IP identifiant la ligne
            vendor (str): Nouveau nom de vendeur
        """
        for item in self.tree.get_children():
            values = list(self.tree.item(item)['values'])
            if len(values) > 1 and values[1] == ip_str:
                # Mettre à jour la colonne Vendor (index 5)
                if len(values) > 5:
                    values[5] = vendor if vendor else "N/A"
                    self.tree.item(item, values=values)
                break

    def ping_host(self, ip):
        """
        Envoie un ping ICMP pour vérifier la présence et estimer l'OS via le TTL

        Args:
            ip (str): Adresse IP à pinger

        Returns:
            tuple: (bool is_online, str os_guess)
        """
        # Utiliser les paramètres OS-specific
        ping_params = self.get_ping_params()
        cmd = ['ping'] + ping_params + [ip]
        
        try:
            # Windows: création sans fenêtre de console
            creation_flags = 0x08000000 if self.is_windows else 0
            
            out = subprocess.check_output(
                cmd,
                creationflags=creation_flags,
                stderr=subprocess.STDOUT,
                timeout=2
            ).decode(errors='ignore')
            
            if "TTL=" in out.upper() or "ttl=" in out.lower():
                ttl_match = re.search(r'TTL=(\d+)', out, re.I)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    os_guess = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Cisco/Network"
                    return True, os_guess
                return True, "Unknown"
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
                self.logger.debug(f"Ping error for {ip}: {e}")
        
        return False, ""

    def get_local_arp(self, ip):
        """
        Récupère l'adresse MAC depuis la table ARP locale du système

        Args:
            ip (str): Adresse IP cible

        Returns:
            str: Adresse MAC ou None
        """
        try:
            # Utiliser la commande ARP OS-specific
            cmd = self.get_arp_command()
            
            # Windows: création sans fenêtre de console
            creation_flags = 0x08000000 if self.is_windows else 0
            
            out = subprocess.check_output(
                cmd,
                creationflags=creation_flags,
                stderr=subprocess.DEVNULL
            ).decode(errors='ignore')
            
            # Chercher la ligne contenant l'IP
            for line in out.split('\n'):
                if ip in line:
                    m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if m:
                        return m.group(0).upper().replace('-', ':')
            
            return None
            
        except Exception as e:
            self.logger.debug(f"ARP error for {ip}: {e}")
            return None

    def start_single_scan(self):
        """
        Démarre un scan unique sur la plage sélectionnée
        """
        if self.scanning: return
        self.scanning = True
        self.btn_scan.config(state=tk.DISABLED); self.btn_stop.config(state=tk.NORMAL)
        self.progress.pack(fill=tk.X, padx=20); self.progress.start()
        threading.Thread(target=self.run_main_scan, daemon=True).start()

    def run_main_scan(self):
        """
        Fonction principale du scan exécutée dans un thread séparé
        """
        # 1. SNMP Table Pre-load
        self.get_snmp_arp_table()

        # 2. Network Scan
        try:
            net = ipaddress.ip_network(self.ip_range_var.get(), strict=False)
            queue = Queue()
            for host in net.hosts(): queue.put(host)

            threads = []
            for _ in range(50): # 50 Workers
                t = threading.Thread(target=self.worker, args=(queue,))
                t.start(); threads.append(t)

            queue.join()
        except Exception as e: self.log(f"Erreur Plage: {e}")

        self.scanning = False
        self.root.after(0, self.reset_ui)

    def worker(self, q):
        while not q.empty() and self.scanning:
            host = q.get()
            self.scan_host(host)
            q.task_done()

    def log(self, msg): self.status_label.config(text=msg)
    def reset_ui(self):
        self.btn_scan.config(state=tk.NORMAL); self.btn_stop.config(state=tk.DISABLED)
        self.progress.stop(); self.progress.pack_forget(); self.log("Scan terminé")
    def stop_scan(self): self.scanning = False; self.continuous_mode = False
    def clear_results(self):
        for i in self.tree.get_children(): self.tree.delete(i)
    def toggle_continuous_scan(self):
        self.continuous_mode = not self.continuous_mode
        self.btn_cont.config(text="⏸ PAUSE" if self.continuous_mode else "∞ MODE CONTINU")
        if self.continuous_mode: threading.Thread(target=self.continuous_loop, daemon=True).start()
    def continuous_loop(self):
        while self.continuous_mode:
            self.start_single_scan()
            import time
            for _ in range(60): 
                if not self.continuous_mode: break
                time.sleep(1)
    def update_tree(self, data):
        """
        Met à jour ou insère une ligne dans le tableau de résultats

        Args:
            data (tuple): Données de la ligne (Status, IP, OS, Hostname, MAC, Vendor, Ports)
        """
        for item in self.tree.get_children():
            if self.tree.item(item)['values'][1] == data[1]: self.tree.delete(item)
        self.tree.insert('', 'end', values=data, tags=('online',))
    def export_csv(self):
        """
        Exporte les résultats actuels vers un fichier CSV
        Ouvre une boite de dialogue pour choisir le fichier.
        """
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, 'w', newline='') as file:
                w = csv.writer(file); w.writerow(('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports'))
                for i in self.tree.get_children(): w.writerow(self.tree.item(i)['values'])

def run_gui():
    """
    Fonction point d'entrée pour lancer l'interface graphique
    """
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui() 