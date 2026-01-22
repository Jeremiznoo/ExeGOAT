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
import sys

# ==========================================
# SNMP - Solution universelle (Windows/Linux)
# ==========================================
# Essaie d'abord snmpwalk (Linux), puis pysnmp (Windows/Linux)
import asyncio
PYSNMP_AVAILABLE = False
try:
    from pysnmp.hlapi.v1arch.asyncio import (
        next_cmd, Slim, CommunityData, UdpTransportTarget,
        ObjectType, ObjectIdentity
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

# ==========================================
# MODULES RÉSEAU
# ==========================================

class CustomDNSResolver:
    def __init__(self, dns_server):
        self.dns_server = dns_server
        self.port = 53
    
    def resolve_ptr(self, ip_address):
        """Tente une résolution inverse via un serveur DNS spécifique"""
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
        except: return None
        return None

class NetBIOSQuery:
    def __init__(self): self.port = 137
    def get_info(self, ip):
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
        except: pass
        return None, None

class MACVendorLookup:
    def __init__(self):
        self.cache = {}  # Cache pour éviter les requêtes répétées
    
    def get_vendor(self, mac, force_refresh=False):
        """Récupère le vendor UNIQUEMENT via l'API macvendorlookup.com"""
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
        """Essaie l'API macvendorlookup.com (https://www.macvendorlookup.com/api)"""
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
    def __init__(self, root):
        self.root = root
        self.root.title("nGOAT Scanner")
        self.root.geometry("1400x850")
        self.colors = {'sidebar': '#2c3e50', 'bg_main': '#f4f6f9', 'card': '#ffffff', 'accent': '#e67e22', 'text_dark': '#2c3e50', 'text_light': '#ecf0f1', 'success': '#27ae60', 'danger': '#e74c3c'}
        
        self.snmp_mac_cache = {} # { 'IP': 'MAC' }
        self.snmp_cache_lock = threading.Lock()
        self.scanning = False
        self.continuous_mode = False
        
        self.mac_lookup = MACVendorLookup()
        self.netbios = NetBIOSQuery()
        
        self.setup_style()
        self.setup_layout()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Sidebar.TFrame", background=self.colors['sidebar'])
        style.configure("Main.TFrame", background=self.colors['bg_main'])
        style.configure("Card.TFrame", background=self.colors['card'])
        style.configure("Sidebar.TLabel", background=self.colors['sidebar'], foreground=self.colors['text_light'], font=("Segoe UI", 10))
        style.configure("Action.TButton", background=self.colors['accent'], foreground="white", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 10))
        style.map("Treeview", background=[("selected", self.colors['accent'])])

    def setup_layout(self):
        container = ttk.Frame(self.root)
        container.pack(fill=tk.BOTH, expand=True)
        
        # Sidebar
        sidebar = ttk.Frame(container, style="Sidebar.TFrame", width=250)
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)
        
        ttk.Label(sidebar, text="nGOAT SCANNER", font=("Segoe UI", 14, "bold"), foreground=self.colors['accent'], background=self.colors['sidebar']).pack(pady=20)
        
        self.btn_scan = ttk.Button(sidebar, text="▶ LANCER SCAN", style="Action.TButton", command=self.start_single_scan)
        self.btn_scan.pack(fill=tk.X, padx=20, pady=5)
        
        self.btn_cont = ttk.Button(sidebar, text="∞ MODE CONTINU", command=self.toggle_continuous_scan)
        self.btn_cont.pack(fill=tk.X, padx=20, pady=5)
        
        self.btn_stop = ttk.Button(sidebar, text="■ ARRÊTER", command=self.stop_scan, state=tk.DISABLED)
        self.btn_stop.pack(fill=tk.X, padx=20, pady=5)
        
        ttk.Separator(sidebar, orient='horizontal').pack(fill=tk.X, padx=20, pady=20)
        ttk.Button(sidebar, text="Exporte CSV", command=self.export_csv).pack(fill=tk.X, padx=20, pady=2)
        ttk.Button(sidebar, text="Effacer", command=self.clear_results).pack(fill=tk.X, padx=20, pady=10)

        self.status_label = ttk.Label(sidebar, text="Prêt", style="Sidebar.TLabel")
        self.status_label.pack(side=tk.BOTTOM, pady=10)
        self.progress = ttk.Progressbar(sidebar, mode='indeterminate')

        # Main Area
        main = ttk.Frame(container, style="Main.TFrame", padding=20)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Config Card
        cfg = ttk.Frame(main, style="Card.TFrame", padding=15)
        cfg.pack(fill=tk.X, pady=(0, 20))
        
        self.ip_range_var = tk.StringVar(value="10.99.12.0/23")
        self.snmp_target_var = tk.StringVar(value="10.99.0.254")
        self.snmp_community_var = tk.StringVar(value="CYBER_ARP")
        self.dns_ip_var = tk.StringVar(value="10.199.156.50")
        
        top_row = ttk.Frame(cfg, style="Card.TFrame")
        top_row.pack(fill=tk.X)
        self.create_field(top_row, "Plage IP cible", self.ip_range_var)
        self.create_field(top_row, "Routeur SNMP", self.snmp_target_var)
        
        bot_row = ttk.Frame(cfg, style="Card.TFrame")
        bot_row.pack(fill=tk.X, pady=10)
        self.create_field(bot_row, "Communauté", self.snmp_community_var)
        self.create_field(bot_row, "DNS AD", self.dns_ip_var)

        # Treeview
        cols = ('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports')
        self.tree = ttk.Treeview(main, columns=cols, show='headings')
        for c in cols: self.tree.heading(c, text=c); self.tree.column(c, width=120)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.tag_configure('online', foreground=self.colors['text_dark'])

    def create_field(self, parent, label, var):
        f = ttk.Frame(parent, style="Card.TFrame")
        f.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=5)
        ttk.Label(f, text=label, font=("Segoe UI", 9), background="white").pack(anchor="w")
        ttk.Entry(f, textvariable=var).pack(fill=tk.X)

# ==========================================
# LOGIQUE DE SCAN ET SNMP
# ==========================================

    def get_snmp_arp_table(self):
        """Récupère la table ARP (ipNetToMediaPhysAddress) via SNMP"""
        target = self.snmp_target_var.get()
        community = self.snmp_community_var.get()
        if not target or not community: return

        self.log(f"Lecture Table ARP SNMP : {target}...")
        
        # Méthode 1: Essayer snmpwalk (Linux/Unix, plus rapide)
        mac_results = self._get_snmp_via_snmpwalk(target, community)
        
        # Méthode 2: Si snmpwalk échoue, utiliser pysnmp (Windows/Linux)
        if not mac_results and PYSNMP_AVAILABLE:
            mac_results = self._get_snmp_via_pysnmp(target, community)
        
        if mac_results:
            # Normaliser les IPs dans le cache (s'assurer qu'elles sont au format string standard)
            normalized_cache = {}
            for ip, mac in mac_results.items():
                try:
                    # Normaliser l'IP pour garantir la correspondance
                    ip_obj = ipaddress.ip_address(ip)
                    normalized_cache[str(ip_obj)] = mac
                except:
                    # Si l'IP n'est pas valide, la garder telle quelle
                    normalized_cache[ip] = mac
            
            with self.snmp_cache_lock:
                self.snmp_mac_cache = normalized_cache
            
            # Debug: afficher quelques exemples et vérifier la plage scannée
            sample_ips = list(normalized_cache.keys())[:5]
            try:
                scan_range = self.ip_range_var.get()
                self.log(f"SNMP : {len(normalized_cache)} MACs récupérées")
                # Compter combien d'IPs du cache sont dans la plage scannée
                if scan_range:
                    net = ipaddress.ip_network(scan_range, strict=False)
                    in_range = sum(1 for ip in normalized_cache.keys() 
                                 if ipaddress.ip_address(ip) in net)
                    if in_range > 0:
                        self.log(f"SNMP : {in_range} MACs dans la plage scannée")
            except:
                pass
        else:
            self.log("Erreur SNMP: Impossible de récupérer la table ARP")
    
    def _get_snmp_via_snmpwalk(self, target, community):
        """Récupère la table ARP via snmpwalk (méthode 1 - Linux/Unix)"""
        try:
            oid_mac = '1.3.6.1.2.1.4.22.1.2'
            cmd = ['snmpwalk', '-v', '2c', '-c', community, target, oid_mac]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return None
            
            mac_results = {}
            lines = result.stdout.strip().split('\n')
            
            for line in lines:
                if not line.strip() or '=' not in line:
                    continue
                
                oid_part, value_part = line.split('=', 1)
                oid_full = oid_part.strip()
                value = value_part.strip()
                
                # Extraction de l'IP depuis l'OID
                oid_clean = oid_full.replace('iso.', '1.').replace('iso', '1')
                parts = oid_clean.split('.')
                oid_base_parts = oid_mac.split('.')
                
                if len(parts) > len(oid_base_parts):
                    index_parts = parts[len(oid_base_parts):]
                    if len(index_parts) >= 5:
                        ip_parts = index_parts[-4:]
                        try:
                            ip_bytes = [int(p) for p in ip_parts]
                            if all(0 <= b <= 255 for b in ip_bytes):
                                ip_key = ".".join(ip_parts)
                                
                                # Extraction de la MAC depuis Hex-STRING
                                mac_match = re.search(r'Hex-STRING:\s*([0-9A-Fa-f\s]+)', value)
                                if mac_match:
                                    mac_hex = mac_match.group(1).strip()
                                    mac_bytes = [int(b, 16) for b in mac_hex.split()]
                                    if len(mac_bytes) == 6:
                                        mac_fmt = ":".join([f"{b:02X}" for b in mac_bytes])
                                        mac_results[ip_key] = mac_fmt
                        except (ValueError, IndexError):
                            continue
            
            return mac_results if mac_results else None
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None
        except Exception:
            return None
    
    def _get_snmp_via_pysnmp(self, target, community):
        """Récupère la table ARP via pysnmp (méthode 2 - Windows/Linux)"""
        try:
            # Exécuter la coroutine de manière synchrone
            # Gérer le cas où un event loop est déjà en cours
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Si un loop est déjà en cours, créer une nouvelle tâche
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as executor:
                        future = executor.submit(asyncio.run, self._async_get_snmp_pysnmp(target, community))
                        return future.result(timeout=15)
            except RuntimeError:
                # Pas de loop en cours, on peut utiliser asyncio.run()
                pass
            
            return asyncio.run(self._async_get_snmp_pysnmp(target, community))
        except Exception:
            return None
    
    async def _async_get_snmp_pysnmp(self, target, community):
        """Récupère la table ARP via pysnmp (asyncio)"""
        mac_results = {}
        oid_mac = '1.3.6.1.2.1.4.22.1.2'
        
        try:
            transport = await UdpTransportTarget.create((target, 161))
            dispatcher = Slim()
            auth_data = CommunityData(community, mpModel=1)
            oid = ObjectType(ObjectIdentity(oid_mac))
            
            # Récupération des MAC addresses - parcourir toutes les entrées
            current_oid = oid_mac
            max_iterations = 1000  # Limite de sécurité
            
            for iteration in range(max_iterations):
                errInd, errStat, errIdx, varBinds = await next_cmd(
                    dispatcher,
                    auth_data,
                    transport,
                    ObjectType(ObjectIdentity(current_oid)),
                    lexicographicMode=False
                )
                
                if errInd:
                    # Fin de la table ou erreur
                    break
                if errStat:
                    # Erreur de statut
                    break
                if not varBinds:
                    # Plus d'entrées
                    break
                
                for varBind in varBinds:
                    oid_full = str(varBind[0])
                    val = varBind[1]
                    
                    # Vérifier si on a dépassé l'OID de base
                    if not oid_full.startswith(oid_mac):
                        return mac_results if mac_results else None
                    
                    # Extraction de l'IP depuis l'OID
                    parts = oid_full.split('.')
                    oid_base_parts = oid_mac.split('.')
                    
                    if len(parts) > len(oid_base_parts):
                        index_parts = parts[len(oid_base_parts):]
                        if len(index_parts) >= 5:
                            ip_parts = index_parts[-4:]
                            try:
                                ip_bytes = [int(p) for p in ip_parts]
                                if all(0 <= b <= 255 for b in ip_bytes):
                                    ip_key = ".".join(ip_parts)
                                    
                                    # Décodage de la MAC address
                                    if hasattr(val, 'asOctets'):
                                        mac_raw = val.asOctets()
                                        if len(mac_raw) == 6:
                                            mac_fmt = ":".join([f"{b:02X}" for b in mac_raw])
                                            mac_results[ip_key] = mac_fmt
                                    
                                    # Mettre à jour current_oid pour la prochaine itération
                                    current_oid = oid_full
                            except (ValueError, IndexError):
                                continue
        
        except Exception:
            pass
        
        return mac_results if mac_results else None

    def scan_host(self, ip):
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
                    except:
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
            nb_name, nb_mac = self.netbios.get_info(ip_str)
            if nb_name: hostname = f"{nb_name} (NB)"
            else:
                res = CustomDNSResolver(self.dns_ip_var.get()).resolve_ptr(ip_str)
                if res: hostname = f"{res} (DNS)"

            # MAC Priority: NetBIOS > Local ARP > SNMP Cache
            # Mais si on a une MAC SNMP, l'utiliser en priorité si les autres sont vides
            mac = nb_mac or self.get_local_arp(ip_str) or snmp_mac or "N/A"
            
            # Forcer l'utilisation de la MAC SNMP si disponible et que les autres méthodes ont échoué
            if (mac == "N/A" or not mac) and snmp_mac:
                mac = snmp_mac
            
            # Récupération initiale du vendor (peut être vide si pas en cache)
            vendor = self.mac_lookup.get_vendor(mac)
            
            # Affichage initial
            data = ("🟢 Online", ip_str, os_type, hostname, mac, vendor, "Scanning...")
            self.root.after(0, lambda ip=ip_str, d=data: self.update_tree(d))
            
            # Mettre à jour le vendor de manière asynchrone (même s'il est vide, pour forcer la recherche)
            if mac != "N/A":
                threading.Thread(target=self._update_vendor_async, args=(ip_str, mac), daemon=True).start()
            
            # Lancer le scan de ports de manière asynchrone
            threading.Thread(target=self._scan_ports_async, args=(ip_str,), daemon=True).start()
    
    def _update_vendor_async(self, ip_str, mac):
        """Met à jour le vendor de manière asynchrone"""
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
        """Scanne les ports de manière asynchrone"""
        open_ports = self.scan_ports(ip_str)
        ports_str = ", ".join(map(str, open_ports)) if open_ports else "Aucun"
        self.root.after(0, lambda ip=ip_str, p=ports_str: self._update_tree_ports(ip, p))
    
    def scan_ports(self, ip_str):
        """Scanne les ports communs sur un hôte"""
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
            except:
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
        """Met à jour uniquement le vendor dans le treeview"""
        for item in self.tree.get_children():
            values = list(self.tree.item(item)['values'])
            if len(values) > 1 and values[1] == ip_str:
                # Mettre à jour la colonne Vendor (index 5)
                if len(values) > 5:
                    values[5] = vendor if vendor else "N/A"
                    self.tree.item(item, values=values)
                break

    def ping_host(self, ip):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        try:
            out = subprocess.check_output(['ping', param, '1', '-w', '500', ip], 
                                         creationflags=0x08000000 if platform.system() == 'Windows' else 0,
                                         stderr=subprocess.STDOUT).decode(errors='ignore')
            if "TTL=" in out.upper():
                ttl = int(re.search(r'TTL=(\d+)', out, re.I).group(1))
                os_guess = "Linux" if ttl <= 64 else "Windows" if ttl <= 128 else "Cisco/Network"
                return True, os_guess
        except: pass
        return False, ""

    def get_local_arp(self, ip):
        try:
            out = subprocess.check_output(['arp', '-a', ip], creationflags=0x08000000 if platform.system() == 'Windows' else 0).decode()
            m = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', out)
            return m.group(0).upper().replace('-', ':') if m else None
        except: return None

    def start_single_scan(self):
        if self.scanning: return
        self.scanning = True
        self.btn_scan.config(state=tk.DISABLED); self.btn_stop.config(state=tk.NORMAL)
        self.progress.pack(fill=tk.X, padx=20); self.progress.start()
        threading.Thread(target=self.run_main_scan, daemon=True).start()

    def run_main_scan(self):
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
        for item in self.tree.get_children():
            if self.tree.item(item)['values'][1] == data[1]: self.tree.delete(item)
        self.tree.insert('', 'end', values=data, tags=('online',))
    def export_csv(self):
        f = filedialog.asksaveasfilename(defaultextension=".csv")
        if f:
            with open(f, 'w', newline='') as file:
                w = csv.writer(file); w.writerow(('Statut', 'IP', 'OS', 'Hostname', 'MAC', 'Vendor', 'Ports'))
                for i in self.tree.get_children(): w.writerow(self.tree.item(i)['values'])

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()