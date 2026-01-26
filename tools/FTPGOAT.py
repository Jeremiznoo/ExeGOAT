import ftplib
from colorama import Fore, Style
import socket

# Couleurs pour l'affichage
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
RESET = Style.RESET_ALL

class FTPGOAT:
    """
    FTP Fuzzer framework for ExeGOAT
        Attributes:
            host (str): Host cible (IP ou domaine)
            port (int): Port FTP (Défaut: 21)
            timeout (float): Timeout en secondes pour les connexions
    """
    def __init__(self, host: str, port: int = 21, timeout: float = 10.0):
        """
        Initialise le scanner FTP
        
        Args:
            host (str): Host cible (IP ou domaine)
            port (int): Port FTP (Défaut: 21)
            timeout (float): Timeout en secondes pour les connexions
        """
        self.host = host
        self.port = port
        self.timeout = timeout

    def check_anonymous(self) -> bool:
        """
        Vérifie si la connexion anonyme est autorisée

        Returns:
            bool: True si la connexion est réussie, False sinon
        """
        print(f"{BLUE}[*] Test de connexion anonyme sur {self.host}:{self.port}...{RESET}")
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftp.login('anonymous', 'anonymous')
            print(f"{GREEN}[+] Connexion anonyme réussie !{RESET}")
            print(f"{GREEN}[+] Message de bienvenue :{RESET}\n{ftp.getwelcome()}")
            ftp.quit()
            return True
        except ftplib.all_errors as e:
            print(f"{RED}[-] Connexion anonyme refusée : {e}{RESET}")
            return False

    def brute_force(self, users: list, passwords: list) -> list:
        """
        Tente de se connecter avec une liste d'utilisateurs et de mots de passe

        Args:
            users (list): Liste des noms d'utilisateurs
            passwords (list): Liste des mots de passe

        Returns:
            list: Liste de tuples (user, password) valides trouvés
        """
        print(f"{BLUE}[*] Démarrage du brute-force...{RESET}")
        
        found_credentials = []

        for user in users:
            for password in passwords:
                try:
                    print(f"{YELLOW}[*] Test {user}:{password}...{RESET}", end='\r')
                    ftp = ftplib.FTP()
                    ftp.connect(self.host, self.port, timeout=self.timeout)
                    ftp.login(user, password)
                    print(f"{GREEN}[+] Créneaux trouvés ! {user}:{password}{RESET}          ")
                    found_credentials.append((user, password))
                    ftp.quit()
                    # On continue pour trouver d'autres comptes potentiels, 
                    # ou on break si on veut juste un accès. Ici on continue.
                except ftplib.all_errors:
                    pass
        
        if not found_credentials:
            print(f"{RED}[-] Aucun mot de passe trouvé.{RESET}          ")
        
        return found_credentials

    def list_files_recursive(self, ftp: ftplib.FTP, path: str = ""):
        """
        Liste récursivement les fichiers sur le serveur

        Args:
            ftp (ftplib.FTP): Instance de connexion FTP active
            path (str): Chemin du répertoire à lister
        """
        try:
            ftp.cwd(path)
            current_files = ftp.nlst()
        except ftplib.error_perm as e:
            # Probablement pas un dossier ou permission denied
            return

        for file in current_files:
            if file in ['.', '..']:
                continue
            
            full_path = f"{path}/{file}" if path != "/" else f"/{file}"
            
            try:
                # Tente de changer de dossier pour voir si c'est un dossier
                ftp.cwd(file)
                # C'est un dossier
                print(f"{BLUE}[D] {full_path}{RESET}")
                # Appel récursif (attention à la profondeur)
                self.list_files_recursive(ftp, full_path)
                # Remonter
                ftp.cwd('..') 
            except ftplib.error_perm:
                # C'est probablement un fichier
                print(f"{GREEN}[F] {full_path}{RESET}")

    def enumerate(self, user: str, password: str):
        """
        Initie l'énumération des fichiers

        Args:
            user (str): Nom d'utilisateur
            password (str): Mot de passe
        """
        print(f"{BLUE}[*] Énumération des fichiers pour {user}...{RESET}")
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftp.login(user, password)
            self.list_files_recursive(ftp, "/")
            ftp.quit()
        except ftplib.all_errors as e:
            print(f"{RED}[-] Erreur lors de l'énumération : {e}{RESET}")

    def interactive_shell(self, user: str, password: str):
        """
        Lance un shell FTP interactif

        Args:
            user (str): Nom d'utilisateur
            password (str): Mot de passe
        """
        import getpass
        
        # Si aucun utilisateur n'est fourni (ou par défaut anonymous qui fail), on demande
        # Mais ici on a déjà une valeur par défaut.
        # On va tenter de se connecter. Si ça fail avec 530, on redemande.
        
        print(f"{BLUE}[*] Tentative de connexion au shell en {user}...{RESET}")
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            
            try:
                ftp.login(user, password)
            except ftplib.error_perm as e:
                if str(e).startswith('530'):
                    print(f"{YELLOW}[!] Login échoué ou anonyme refusé.{RESET}")
                    user = input(f"{YELLOW}Procéder avec un utilisateur spécifique ? (Laissez vide pour quitter) > {RESET}").strip()
                    if not user:
                         return
                    password = getpass.getpass(f"{YELLOW}Mot de passe pour {user} > {RESET}")
                    ftp.login(user, password)
                else:
                    raise e
            
            print(f"{GREEN}[+] Connecté ! Tapez 'help' pour les commandes, 'exit' pour quitter.{RESET}")

            
            while True:
                try:
                    cmd_input = input(f"{BLUE}ftp@{self.host}:{ftp.pwd()} > {RESET}").strip()
                except EOFError:
                    break
                
                if not cmd_input:
                    continue

                parts = cmd_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ['exit', 'quit']:
                    print(f"{YELLOW}Fermeture de la session...{RESET}")
                    break
                
                elif cmd == 'help':
                    print(f"{YELLOW}Commandes disponibles : ls, cd, pwd, get <fichier>, cat <fichier>, exit{RESET}")

                elif cmd == 'ls':
                    try:
                        ftp.retrlines('LIST')
                    except ftplib.all_errors as e:
                        print(f"{RED}Erreur : {e}{RESET}")

                elif cmd == 'pwd':
                    try:
                        print(ftp.pwd())
                    except ftplib.all_errors as e:
                        print(f"{RED}Erreur : {e}{RESET}")

                elif cmd == 'cd':
                    if not args:
                        print(f"{RED}Usage: cd <dossier>{RESET}")
                    else:
                        try:
                            ftp.cwd(args[0])
                        except ftplib.all_errors as e:
                            print(f"{RED}Erreur : {e}{RESET}")
                
                elif cmd == 'get':
                    if not args:
                        print(f"{RED}Usage: get <fichier>{RESET}")
                    else:
                        filename = args[0]
                        try:
                            with open(filename, 'wb') as f:
                                ftp.retrbinary(f'RETR {filename}', f.write)
                            print(f"{GREEN}[+] Fichier {filename} téléchargé !{RESET}")
                        except Exception as e:
                            print(f"{RED}Erreur : {e}{RESET}")

                elif cmd == 'cat':
                    if not args:
                        print(f"{RED}Usage: cat <fichier>{RESET}")
                    else:
                        try:
                            # Utilise retrlines pour afficher le contenu texte
                            ftp.retrlines(f'RETR {args[0]}')
                        except ftplib.all_errors as e:
                             print(f"{RED}Erreur : {e}{RESET}")
                else:
                    try:
                        resp = ftp.sendcmd(cmd_input)
                        print(resp)
                    except ftplib.all_errors as e:
                        print(f"{RED}Erreur commande inconnue ou invalide : {e}{RESET}")

            ftp.quit()
        except ftplib.all_errors as e:
            print(f"{RED}[-] Erreur connexion : {e}{RESET}")


def run_ftp_scanner(args):
    """
    Fonction wrapper pour être appelée depuis main.py

    Args:
        args (argparse.Namespace): Arguments parséms depuis la ligne de commande
    """
    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{GREEN}SCANNER FTP FTPGOAT{RESET}")
    print(f"{GREEN}{'='*60}{RESET}\n")

    port = args.port if args.port else 21
    # Gestion simplifiée de l'URL pour extraire le host si nécessaire
    # Si l'utilisateur passe http://site.com, on nettoie
    host = args.url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]

    scanner = FTPGOAT(host, port, timeout=args.timeout if hasattr(args, 'timeout') else 10)

    # 1. Test Anonyme
    if args.filter_mode == 'anon' or args.filter_mode == 'all':
        scanner.check_anonymous()

    # 2. Brute Force
    if args.filter_mode == 'brute' or args.filter_mode == 'all':
        if args.user_list and args.pass_list:
            try:
                with open(args.user_list, 'r') as f:
                    users = [line.strip() for line in f if line.strip()]
                with open(args.pass_list, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                scanner.brute_force(users, passwords)
            except FileNotFoundError as e:
                print(f"{RED}[!] Erreur fichier introuvable : {e}{RESET}")
        elif args.username and args.password:
            # Login simple check
             scanner.brute_force([args.username], [args.password])
        else:
             if args.filter_mode == 'brute':
                 print(f"{YELLOW}[!] Pour le mode brute, spécifiez --user-list/--pass-list ou --user/--password{RESET}")

    # 3. Enumération (si on a des identifiants valides ou anonymous)
    if args.filter_mode == 'enum' or args.filter_mode == 'all':
        user = args.username if args.username else 'anonymous'
        password = args.password if args.password else 'anonymous'
        scanner.enumerate(user, password)

    # 4. Shell Interactif
    if args.filter_mode == 'shell':
        # On passe ce qu'on a, interactive_shell gérera si ça fail
        user = args.username if args.username else 'anonymous'
        password = args.password if args.password else 'anonymous'
        scanner.interactive_shell(user, password)
