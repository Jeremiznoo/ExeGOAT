import threading
import time
import socket
import abc
from colorama import Fore, Style

# Import Paramiko for SSH
try:
    import paramiko
    paramiko_available = True
except ImportError:
    paramiko_available = False

# Couleurs
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

class BruteModule(abc.ABC):
    """
    Classe abstraite pour les modules de brute-force
    """
    def __init__(self, target, port, timeout=5):
        """
        Initialise le module de base
        
        Args:
            target (str): Adresse de la cible
            port (int): Port du service
            timeout (int): Temps d'attente maximum en secondes (défaut: 5)
        """
        self.target = target
        self.port = port
        self.timeout = timeout

    @abc.abstractmethod
    def attempt_login(self, username, password):
        """
        Tente une connexion avec username/password.
        
        Args:
            username (str): Nom d'utilisateur à tester
            password (str): Mot de passe à tester
            
        Returns:
            bool: True si la connexion est réussie, False sinon
        """
        pass

class SSHBrute(BruteModule):
    """
    Module de brute-force SSH basé sur Paramiko
    """
    def attempt_login(self, username, password):
        """
        Tente une connexion SSH avec paramiko
        
        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe
            
        Returns:
            bool: True si authentification réussie, False sinon
        """
        if not paramiko_available:
            return False
        
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            # logging.getLogger("paramiko").setLevel(logging.WARNING) 
            client.connect(
                self.target, 
                port=self.port, 
                username=username, 
                password=password, 
                timeout=self.timeout,
                banner_timeout=10
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except socket.error:
            # Erreur réseau
            return False
        except Exception:
            return False
        finally:
            client.close()

class FTPBrute(BruteModule):
    """
    Module de brute-force FTP basé sur ftplib
    """
    def attempt_login(self, username, password):
        """
        Tente une connexion FTP
        
        Args:
            username (str): Nom d'utilisateur
            password (str): Mot de passe
            
        Returns:
            bool: True si authentification réussie, False sinon
        """
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, self.port, timeout=self.timeout)
            ftp.login(username, password)
            ftp.quit()
            return True
        except ftplib.all_errors:
            return False

class BruteForcer:
    """
    Moteur principal de brute-force multi-threadé
    """
    def __init__(self, service, target, port, user_list, pass_list, threads=10, stop_on_success=False):
        """
        Initialise le moteur de brute-force
        
        Args:
            service (str): Service à attaquer ('ssh' ou 'ftp')
            target (str): Adresse de la cible
            port (int): Port du service
            user_list (list): Liste des utilisateurs à tester
            pass_list (list): Liste des mots de passe à tester
            threads (int): Nombre de threads simultanés (défaut: 10)
            stop_on_success (bool): Arrêter le scan dès qu'un mot de passe est trouvé (défaut: False)
        """
        self.service = service
        self.target = target
        self.port = port
        self.user_list = user_list
        self.pass_list = pass_list
        self.threads = threads
        self.stop_on_success = stop_on_success
        
        self.found = []
        self.running = True
        self.lock = threading.Lock()
        
        # Sélection du module
        if service.lower() == 'ssh':
            if not paramiko_available:
                print(f"{RED}[!] Module SSH non disponible (paramiko manquant){RESET}")
                self.module_class = None
            else:
                self.module_class = SSHBrute
                if not self.port: self.port = 22
        elif service.lower() == 'ftp':
            self.module_class = FTPBrute
            if not self.port: self.port = 21
        else:
            print(f"{RED}[!] Service non supporté: {service}{RESET}")
            self.module_class = None

    def worker(self, queue):
        """
        Fonction exécutée par chaque thread (Non utilisée dans l'implémentation actuelle 
        qui utilise une fonction interne thread_target)
        
        Args:
            queue (queue.Queue): File d'attente des tâches
            
        Returns:
            None
        """
        module = self.module_class(self.target, self.port)
        
        while self.running:
            try:
                # Récupérer une tâche (user, password)
                # Note: ici on utilise une approche simpliste sans Queue standard 
                # pour l'exemple, mais on itère sur les listes.
                # Pour un vrai pool, on utiliserait queue.Queue.
                # Dans cette implémentation simple, on va juste laisser le boucle principale dispatcher.
                pass
            except Exception:
                break

    def run(self):
        """
        Lance le processus de brute-force multi-threadé
        
        Returns:
            None
        """
        if not self.module_class:
            return

        print(f"{BLUE}[*] Démarrage de BruteGOAT sur {self.target}:{self.port} (Service: {self.service}){RESET}")
        print(f"{BLUE}[*] Users: {len(self.user_list)} | Passwords: {len(self.pass_list)} | Threads: {self.threads}{RESET}")

        # Génération de la queue de tâches
        tasks = []
        for u in self.user_list:
            for p in self.pass_list:
                tasks.append((u, p))
        
        # Queue thread-safe
        import queue
        q = queue.Queue()
        for t in tasks:
            q.put(t)

        def thread_target():
            module = self.module_class(self.target, self.port)
            while not q.empty() and self.running:
                try:
                    user, password = q.get(timeout=1)
                    print(f"{YELLOW}[*] Test {user}:{password}...{RESET}", end='\r')
                    
                    if module.attempt_login(user, password):
                        with self.lock:
                            print(f"{GREEN}[+] SUCCESS: {user}:{password}{RESET}                      ")
                            self.found.append((user, password))
                            if self.stop_on_success:
                                self.running = False
                                # Vider la queue pour arrêter les autres threads plus vite
                                with q.mutex:
                                    q.queue.clear()
                    
                    q.task_done()
                except queue.Empty:
                    break
                except Exception as e:
                    # print(e)
                    pass

        threads_list = []
        for _ in range(self.threads):
            t = threading.Thread(target=thread_target)
            t.daemon = True
            t.start()
            threads_list.append(t)

        try:
            for t in threads_list:
                t.join()
        except KeyboardInterrupt:
            self.running = False
            print(f"\n{RED}[!] Interruption...{RESET}")

        print(f"\n{GREEN}{'='*60}{RESET}")
        print(f"{GREEN}FIN DU BRUTE-FORCE{RESET}")
        if self.found:
            print(f"{GREEN}[+] Identifiants trouvés :{RESET}")
            for u, p in self.found:
                print(f"    - {u}:{p}")
        else:
            print(f"{RED}[-] Aucun mot de passe trouvé.{RESET}")
        print(f"{GREEN}{'='*60}{RESET}")

def run_brutegoat(args):
    """
    Point d'entrée principal pour l'outil BruteGOAT
    
    Args:
        args (argparse.Namespace): Arguments parsés de la ligne de commande contenant:
            - username/user_list: Utilisateurs cibles
            - password/pass_list: Mots de passe cibles
            - url/service/port: Cible
            - threads: Nombre de threads
            
    Returns:
        None
    """
    users = []
    passwords = []

    # 1. Gestion des logins
    if args.username:
        users.append(args.username)
    if args.user_list:
        try:
            with open(args.user_list, 'r') as f:
                users.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{RED}[!] Fichier utilisateurs introuvable: {args.user_list}{RESET}")
            return

    # 2. Gestion des mots de passe
    if args.password:
        passwords.append(args.password)
    if args.pass_list:
        try:
            with open(args.pass_list, 'r') as f:
                passwords.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"{RED}[!] Fichier mots de passe introuvable: {args.pass_list}{RESET}")
            return

    if not users or not passwords:
        print(f"{RED}[!] Il manque des utilisateurs ou des mots de passe.{RESET}")
        print(f"{YELLOW}Utilisez -l/-L pour les utilisateurs et -p/-P pour les mots de passe.{RESET}")
        return

    # 3. Parsing de la cible (URL/Service)
    target = args.url # Vient de positional 'target' ou -u
    service = args.service
    port = args.port

    # Détection protocol://target
    if target and "://" in target:
        parts = target.split("://")
        proto = parts[0].lower()
        rest = parts[1]
        
        # Mapping protocole -> service
        if proto in ['ssh', 'sftp']:
            service = 'ssh'
            if not port: port = 22
        elif proto in ['ftp', 'ftps']:
            service = 'ftp'
            if not port: port = 21
        else:
            print(f"{YELLOW}[!] Protocole '{proto}' non reconnu par défaut, tentative d'utilisation comme service...{RESET}")
            service = proto

        # Parsing host:port
        if ":" in rest:
            host_parts = rest.split(":")
            target = host_parts[0]
            if not port: # Si port pas déjà forcé
                try:
                    # Gère le cas [IPv6]:port ou host:port
                    if "]" in rest: # IPv6
                        pass # TODO: parsing IPv6 complexe, on simplifie pour l'instant
                    else:
                        port = int(host_parts[1].split('/')[0]) # vire le path éventuel
                except ValueError:
                    pass
        else:
            target = rest.split('/')[0]

    if not service:
        print(f"{RED}[!] Aucun service spécifié. Utilisez --service ou protocol://target{RESET}")
        return

    bruter = BruteForcer(
        service=service,
        target=target,
        port=port,
        user_list=users,
        pass_list=passwords,
        threads=args.threads if hasattr(args, 'threads') else 10
    )
    bruter.run()
