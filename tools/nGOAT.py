#!/usr/bin/env python3
"""
nGOAT
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
from PIL import Image, ImageTk
import asyncio

# ==========================================
# SNMP - Solution universelle (Windows/Linux)
# ==========================================
# Essaie d'abord snmpwalk (Linux), puis pysnmp (Windows/Linux)
PYSNMP_AVAILABLE = False
try:
    from pysnmp.hlapi.v1arch.asyncio import (
        next_cmd, Slim, CommunityData, UdpTransportTarget,
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

        self.setup_style()
        self.setup_layout()

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
        ttk.Checkbutton(col2, text="Résolution DNS Inverse", variable=self.opt_dns).pack(anchor="w")
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
        Crée un champ de saisie labellisé propre
        """
        f = ttk.Frame(parent, style="Card.TFrame")
        f.pack(fill=tk.X, pady=2)
        ttk.Label(f, text=label, style="Normal.TLabel").pack(anchor="w")
        ttk.Entry(f, textvariable=var).pack(fill=tk.X)

# ==========================================
# LOGIQUE DE SCAN ET SNMP
# ==========================================

    def get_snmp_arp_table(self):
        """
        Récupère la table ARP (ipNetToMediaPhysAddress) via SNMP
        Met à jour le cache interne self.snmp_mac_cache
        """
        if not self.opt_snmp.get():
            return

        target = self.snmp_target_var.get()
        version = self.snmp_version.get()

        # Collect credentials
        creds = {}
        if version == "v2c":
            creds['community'] = self.snmp_community_var.get()
            if not creds['community']: return
        else: # v3
            creds['user'] = self.snmp_user.get()
            if not creds['user']: return
            creds['auth_proto'] = self.snmp_auth_proto.get()
            creds['auth_pass'] = self.snmp_auth_pass.get()
            creds['priv_proto'] = self.snmp_priv_proto.get()
            creds['priv_pass'] = self.snmp_priv_pass.get()

        self.log(f"Lecture Table ARP SNMP ({version}) : {target}...")

        # Méthode 1: snmpwalk
        mac_results = self._get_snmp_via_snmpwalk(target, version, creds)

        # Méthode 2: pysnmp
        if not mac_results and PYSNMP_AVAILABLE:
            mac_results = self._get_snmp_via_pysnmp(target, version, creds)

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
            self.log("Erreur SNMP: Impossible de récupérer la table ARP")

    def _get_snmp_via_snmpwalk(self, target, version, creds):
        """Récupère la table ARP via snmpwalk (v2c/v3)"""
        try:
            oid_mac = '1.3.6.1.2.1.4.22.1.2'
            cmd = ['snmpwalk', '-O', 'n'] # Output numérique pour parsing facile

            if version == "v2c":
                cmd.extend(['-v', '2c', '-c', creds.get('community')])
            else:
                cmd.extend(['-v', '3', '-u', creds.get('user'), '-l', 'authPriv'])
                # Auth
                if creds.get('auth_pass'):
                    cmd.extend(['-a', creds.get('auth_proto', 'SHA'), '-A', creds.get('auth_pass')])
                # Priv
                if creds.get('priv_pass'):
                    cmd.extend(['-x', creds.get('priv_proto', 'AES'), '-X', creds.get('priv_pass')])

            cmd.extend([target, oid_mac])

            # Note: subprocess peut échouer si snmpwalk n'est pas installé ou arguments invalides
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode != 0:
                return None

            mac_results = {}
            # Parsing robuste de la sortie snmpwalk
            # Format attendu (avec -On): .1.3.6.1.2.1.4.22.1.2.X.X.X.X = Hex-STRING: ...
            for line in result.stdout.strip().split('\n'):
                # Split OID = Value
                parts = line.split(' = ')
                if len(parts) < 2: continue

                oid_part = parts[0].strip()
                val_part = parts[1].strip().upper()

                # Extract IP from OID suffix (last 4 numbers)
                oid_nums = oid_part.split('.')
                # Need at least base OID + 4 IP parts. Base OID in numbers usually starts with .1...
                if len(oid_nums) >= 4:
                    ip_parts = oid_nums[-4:]
                    try:
                        # Verify valid IP logic
                        ip = ".".join(ip_parts)
                        ipaddress.ip_address(ip) # Check validity
                        
                        # Clean MAC Value
                        # Identify and remove type prefix if present (e.g. "HEX-STRING: ", "STRING: ")
                        # Heuristic: split by first colon if it looks like a type label
                        # Common labels: Hex-STRING, STRING, INTEGER, etc.
                        # But also MAC address itself might contain colons.
                        
                        # Strategy: Just keep hex characters from the value part
                        # If it contains "HEX-STRING:" we remove it implicitly by keeping hex chars? 
                        # No, "HEX-STRING" contains 'E' and 'C' which are hex.
                        
                        # Better: Split by ': ' if a space follows the colon, or just remove known prefixes.
                        # Standard snmpwalk output format usually has "Type: Value"
                        
                        val_content = val_part
                        if ": " in val_part:
                             # Likely "Type: Value"
                             # But check if it's just a MAC like "00:11:..." (no space usually, unless "00: 11: ...")
                             # HEX-STRING: 00 00 ...
                             # STRING: 00:00...
                             # If the part BEFORE the first ": " is a known type or just text, we skip it.
                             
                             split_val = val_part.split(": ", 1)
                             # If split_val[0] is like "HEX-STRING", "STRING", "OCTETSTRING", etc.
                             # If split_val[0] looks like a MAC byte (e.g. "00"), don't split.
                             
                             prefix = split_val[0]
                             if len(prefix) > 2 or "STRING" in prefix: 
                                 val_content = split_val[1]
                        
                        # Clean all non-hex chars
                        mac_clean = "".join(c for c in val_content if c in '0123456789ABCDEF')
                        
                        # MAC should be 12 hex chars
                        if len(mac_clean) == 12:
                            mac_fmt = ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)])
                            mac_results[ip] = mac_fmt
                    except: continue

            return mac_results if mac_results else None




        except Exception:
            return None

    def _get_snmp_via_pysnmp(self, target, version, creds):
        """Récupère la table ARP via pysnmp (v2c/v3)"""
        try:
            # Prepare Auth Data
            auth_data = None
            if version == "v2c":
                auth_data = CommunityData(creds.get('community'), mpModel=1)
            else:
                # v3 mapping
                auth_proto_map = {'MD5': 'usmHMACMD5AuthProtocol', 'SHA': 'usmHMACSHAAuthProtocol'}
                priv_proto_map = {'DES': 'usmDESPrivProtocol', 'AES': 'usmAesCfb128Protocol'}

                # Import dynamique des constantes si besoin, mais ici on passe les strings si pysnmp supporte
                # ou on suppose l'import direct. Pour simplicité, on laisse pysnmp gérer si possible ou on maps.
                # NOTE: Pour pysnmp v1arch, UsmUserData prend les OIDs protocol. 
                # Simplification: on tente l'approche standard si l'import a réussi.

                # Besoin de mappings réels si on veut supporter auth/priv
                # Pour cet exercice, on assume que l'utilisateur a pysnmp installé avec les bons symboles
                # ou on fait un effort minimal pour v3 qui est complexe en pysnmp pur.

                # On va construire UsmUserData avec les arguments
                # Attention: il faut mapper les strings 'SHA', 'AES' aux OIDs pysnmp.
                # Faute d'imports complets de tous les OIDs, on va faire un best-effort.

                # Si pysnmp est présent, on a accès aux constantes via pysnmp.hlapi... 
                # Mais on a importé que v1arch.asyncio...

                # Pour éviter des erreurs d'import complexes, on va laisser le fallback snmpwalk gérer v3
                # Si pysnmp est requis pour v3, il faudra ajouter plus d'imports.
                # Pour l'instant, on supporte v2c pleinement en pysnmp.
                if version == "v3":
                    return None # Fallback to snmpwalk ideally, or incomplete implement

            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, self._async_get_snmp_pysnmp(target, auth_data))
                        return future.result(timeout=15)
            except RuntimeError: pass

            return asyncio.run(self._async_get_snmp_pysnmp(target, auth_data))
        except Exception:
            return None

    async def _async_get_snmp_pysnmp(self, target, auth_data):
        mac_results = {}
        oid_mac = '1.3.6.1.2.1.4.22.1.2'

        try:
            transport = await UdpTransportTarget.create((target, 161))
            dispatcher = Slim()
            oid = ObjectType(ObjectIdentity(oid_mac))

            current_oid = oid_mac
            for _ in range(1000):
                errorIndication, errorStatus, errorIndex, varBinds = await next_cmd(
                    dispatcher, auth_data, transport,
                    ObjectType(ObjectIdentity(current_oid)),
                    lexicographicMode=False
                )

                if errorIndication or errorStatus or not varBinds: break

                for varBind in varBinds:
                    oid_full = str(varBind[0])
                    val = varBind[1]

                    if not oid_full.startswith(oid_mac): return mac_results

                    # Extract IP
                    parts = oid_full.split('.')
                    if len(parts) >= 11: # .1.3.6.1.2.1.4.22.1.2.X.X.X.X (base is 10 parts if starting with 1)
                        # Base OID length is 10: 1.3.6.1.2.1.4.22.1.2
                        # IP is last 4
                        ip_parts = parts[-4:]
                        try:
                            ip = ".".join(ip_parts)
                            # Decode MAC
                            if hasattr(val, 'asOctets'):
                                mac_raw = val.asOctets()
                                if len(mac_raw) == 6:
                                    mac_fmt = ":".join([f"{b:02X}" for b in mac_raw])
                                    mac_results[ip] = mac_fmt
                            current_oid = oid_full
                            current_oid = oid_full
                        except (ValueError, IndexError): 
                            continue
        except Exception: 
            pass
        return mac_results

    def scan_host(self, ip):
        """
        Analyse un hôte pour déterminer s'il est unique et récupérer ses infos

        Args:
            ip (str ou IPv4Address): Adresse IP à scanner

        Returns:
            None
        """
        ip_str = str(ip)
        is_online, os_type = self.ping_host(ip_str)

        # Vérification cache SNMP (si offline ou online)
        # Essayer plusieurs formats d'IP pour être sûr de trouver la MAC
        snmp_mac = None
        with self.snmp_cache_lock:
            # Normaliser l'IP pour la recherche
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                ip_normalized = str(ip_obj)
            except:
                ip_normalized = ip_str

            # Essayer avec l'IP normalisée
            snmp_mac = self.snmp_mac_cache.get(ip_normalized)

            # Si pas trouvé, essayer une recherche plus large (au cas où le format diffère)
            if not snmp_mac and len(self.snmp_mac_cache) > 0:
                # Chercher dans toutes les clés (debug)
                for cached_ip, cached_mac in self.snmp_mac_cache.items():
                    try:
                        # Comparer les IPs normalisées
                        cached_ip_obj = ipaddress.ip_address(cached_ip)
                        if str(cached_ip_obj) == ip_normalized:
                            snmp_mac = cached_mac
                            break

                    except Exception:
                        # Si l'IP en cache n'est pas valide, comparer directement
                        if cached_ip == ip_normalized or cached_ip == ip_str:
                            snmp_mac = cached_mac
                            break

        # Si on a une MAC SNMP, considérer l'hôte comme online
        if snmp_mac:
            if not is_online:
                is_online = True
                os_type = "Actif (SNMP Table)"

        if is_online:
            # Hostname logic
            hostname = "N/A"
            nb_mac = None

            # NetBIOS
            if self.opt_netbios.get():
                nb_name, nb_mac = self.netbios.get_info(ip_str)
                if nb_name: hostname = f"{nb_name} (NB)"

            # DNS (si pas de NetBIOS ou si on veut compléter, mais ici on remplace si N/A)
            if self.opt_dns.get() and (hostname == "N/A" or "NB" not in hostname):
                res = CustomDNSResolver(self.dns_ip_var.get()).resolve_ptr(ip_str)
                if res: hostname = f"{res} (DNS)"

            # MAC Priority
            mac = None
            if nb_mac: mac = nb_mac
            if not mac: mac = self.get_local_arp(ip_str)
            if not mac and snmp_mac: mac = snmp_mac

            if not mac: mac = "N/A"

            # Vendor Lookup
            vendor = ""
            if self.opt_mac_vendor.get() and mac != "N/A":
                 # Récupération initiale (cache)
                 vendor = self.mac_lookup.get_vendor(mac)
                 # Async refresh
                 threading.Thread(target=self._update_vendor_async, args=(ip_str, mac), daemon=True).start()

            # Affichage initial
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
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            out = subprocess.check_output(['ping', param, '1', '-w', '500', ip], 
                                         creationflags=0x08000000 if platform.system() == 'Windows' else 0,
                                         stderr=subprocess.STDOUT).decode(errors='ignore')
            if "TTL=" in out.upper():
                ttl = int(re.search(r'TTL=(\d+)', out, re.I).group(1))
                os_guess = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Cisco/Network"
                return True, os_guess
        except Exception: 
            pass
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
            out = subprocess.check_output(['arp', '-a', ip], creationflags=0x08000000 if platform.system() == 'Windows' else 0).decode()
            m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', out)
            return m.group(0).upper().replace('-', ':') if m else None
        except Exception: return None

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