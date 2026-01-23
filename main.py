import argparse
import asyncio
import sys
from colorama import init, Fore, Style
from tools.fuzz import WebFuzzer, parse_status_codes, transform_payloads
from tools.nGOAT import run_gui
from tools.FTPGOAT import run_ftp_scanner
from tools.BruteGOAT import run_brutegoat

BLUE = Fore.BLUE
WHITE = Fore.WHITE
RED = Fore.RED
GREEN = Fore.GREEN
RESET = Style.RESET_ALL
YELLOW = Fore.YELLOW

def main():
    """
    Fonction main
    """
    init(autoreset=True)

    BANNER = rf"""
{BLUE}___________ {WHITE}         {RED}        {GREEN}  ________  ________       _____    ___________{RESET}
{BLUE}\_   _____/ {WHITE}___  ___ {RED}  ____  {GREEN} /  _____/  \_____  \     /  _  \   \__    ___/{RESET}
{BLUE} |    __)_  {WHITE}\  \/  / {RED}_/ __ \ {GREEN}/   \  ___   /   |   \   /  /_\  \    |    |   {RESET}
{BLUE} |        \ {WHITE} >    <  {RED}\  ___/ {GREEN}\    \_\  \ /    |    \ /    |    \   |    |   {RESET}
{BLUE}/_______  / {WHITE}/__/\_ \ {RED} \___  >{GREEN} \______  / \_______  / \____|__  /   |____|   {RESET}
{BLUE}        \/  {WHITE}      \/ {RED}     \/ {GREEN}        \/          \/          \/             {RESET}"""

    print(BANNER)

    # ═══════════════════════════════════════════════════════
    # PARENT PARSERS (Options communes)
    # ═══════════════════════════════════════════════════════

    # --- Parent: Common (Options globales) ---
    parent_common = argparse.ArgumentParser(add_help=False)
    common_group = parent_common.add_argument_group('options communes')
    common_group.add_argument(
        'target',
        nargs='?',
        help='Cible (URL, IP, ou protocole://cible)'
    )
    common_group.add_argument(
        '-u', '--url',
        type=str,
        required=False,
        metavar='URL',
        help='URL cible (alternative à l\'argument positionnel)'
    )
    common_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux'
    )
    common_group.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Mode silencieux'
    )

    # --- Parent: Authentication (Hydra-style) ---
    parent_auth = argparse.ArgumentParser(add_help=False)
    auth_group = parent_auth.add_argument_group('Authentication')
    auth_group.add_argument('-l', '--username', type=str, help="Login unique (-l)")
    auth_group.add_argument('-p', '--password', type=str, help='Mot de passe unique (-p)')
    auth_group.add_argument('-L', '--user-list', type=str, help="Fichier liste utilisateurs (-L)")
    auth_group.add_argument('-P', '--pass-list', type=str, help='Fichier liste mots de passe (-P)')


    # ═══════════════════════════════════════════════════════
    # PARSER PRINCIPAL & SUBPARSERS
    # ═══════════════════════════════════════════════════════

    parser = argparse.ArgumentParser(
        prog="ExeGOAT",
        description="Suite d'outils de sécurité web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(
        dest='tool',
        title='Outils disponibles',
        description='Outil à utiliser',
        help='Utilisez "main.py <outil> -h" pour l\'aide spécifique à un outil',
        required=True
    )

    # ═══════════════════════════════════════════════════════
    # SUBPARSER: FUZZER
    # ═══════════════════════════════════════════════════════
    parser_fuzzer = subparsers.add_parser(
        'fuzzer',
        parents=[parent_common],
        help='Fuzzer web / énumération de répertoires',
        description='Fuzzer web avancé (dir, param, post, form)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # ... Fuzzer Required ...
    fuzz_req = parser_fuzzer.add_argument_group('Requis')
    fuzz_req.add_argument('-w', '--wordlist', type=str, metavar='FILE', help='Fichier wordlist')

    # ... Fuzzer Mode ...
    fuzz_mode = parser_fuzzer.add_argument_group('Mode de fuzzing')
    fuzz_mode.add_argument('-m', '--mode', choices=['dir', 'param', 'post', 'form'], default='dir', help='Mode (dir, param, post, form)')
    fuzz_mode.add_argument('--param', type=str, metavar='PARAM', help='Paramètre GET/POST à fuzzer')
    fuzz_mode.add_argument('--post-data', type=str, metavar='DATA', help='Données POST (key=v&k=v)')
    fuzz_mode.add_argument('--form-url', type=str, metavar='URL', help='URL du formulaire')
    fuzz_mode.add_argument('--field-values', type=str, metavar='DATA', help='Valeurs champs fixes du form')

    # ... Fuzzer Network ...
    fuzz_net = parser_fuzzer.add_argument_group('Réseau')
    fuzz_net.add_argument('-t', '--threads', type=int, default=50, help='Threads (Défaut: 50)')
    fuzz_net.add_argument('--timeout', type=float, default=5.0, help='Timeout (s)')
    fuzz_net.add_argument('--follow-redirects', action='store_true', help='Suivre redirections')
    fuzz_net.add_argument('--cookie', type=str, metavar='COOKIE', help='Cookies (k=v; k=v)')
    fuzz_net.add_argument('--delay', type=float, metavar='SEC', help='Délai entre requêtes')

    # ... Fuzzer Filters ...
    fuzz_filt = parser_fuzzer.add_argument_group('Filtres')
    fuzz_filt.add_argument('--hide-codes', type=str, metavar='CODES', help='Cacher codes (404,403)')
    fuzz_filt.add_argument('--show-codes', type=str, metavar='CODES', help='Montrer codes (200,301)')

    # ... Fuzzer Payloads ...
    fuzz_pay = parser_fuzzer.add_argument_group('Payloads')
    fuzz_pay.add_argument('--extensions', type=str, help='Extensions (php,html)')
    fuzz_pay.add_argument('--prefix', type=str, help='Préfixe')
    fuzz_pay.add_argument('--suffix', type=str, help='Suffixe')
    fuzz_pay.add_argument('--xss-marker', type=str, help='Marqueur XSS')

    # ... Fuzzer Export ...
    fuzz_out = parser_fuzzer.add_argument_group('Export')
    fuzz_out.add_argument('-o', '--output', type=str, help='Fichier de sortie')
    fuzz_out.add_argument('--auto-export', action='store_true', help='Export auto')

    # ═══════════════════════════════════════════════════════
    # SUBPARSER: nGOAT
    # ═══════════════════════════════════════════════════════
    parser_ngoat = subparsers.add_parser(
        'nGOAT',
        parents=[parent_common],
        help='Scanner réseau nGOAT (GUI)',
        description='Lance l\'interface graphique de nGOAT scanner'
    )

    # ═══════════════════════════════════════════════════════
    # SUBPARSER: ftpGOAT
    # ═══════════════════════════════════════════════════════
    parser_ftp = subparsers.add_parser(
        'ftpGOAT',
        parents=[parent_common, parent_auth],
        help='Scanner FTP & Shell',
        description='Outil FTP : check anonyme, brute-force, shell interactif'
    )
    ftp_grp = parser_ftp.add_argument_group('Options FTP')
    ftp_grp.add_argument('--filter-mode', choices=['anon', 'brute', 'enum', 'all', 'shell'], default='shell', help='Mode (anon, brute, enum, all, shell). Défaut: shell')
    ftp_grp.add_argument('--port', type=int, default=21, help='Port FTP (Défaut: 21)')

    # ═══════════════════════════════════════════════════════
    # SUBPARSER: BruteGOAT
    # ═══════════════════════════════════════════════════════
    parser_brute = subparsers.add_parser(
        'BruteGOAT',
        parents=[parent_common, parent_auth],
        help='Brute-Force modulaire (SSH, FTP...)',
        description='Outil de brute-force multi-protocole style Hydra'
    )
    brute_grp = parser_brute.add_argument_group('Options BruteGOAT')
    brute_grp.add_argument('--service', choices=['ssh', 'ftp'], help='Service (si non détecté via protocole://)')
    brute_grp.add_argument('--port', type=int, help='Port du service (Optionnel)')


    # ═══════════════════════════════════════════════════════
    # PARSING & DISPATCH
    # ═══════════════════════════════════════════════════════
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Normalisation target/url
    if hasattr(args, 'target') and args.target and not args.url:
        args.url = args.target

    if args.tool != 'nGOAT' and not args.url:
         # Pour ftpGOAT/BruteGOAT/fuzzer une cible est requise
         # Note: fuzzer vérifie aussi args.wordlist plus tard
         print(f"{RED}[!] Cible requise (argument positionnel ou -u/--url){RESET}")
         parser.print_usage() # Affiche l'usage du subparser actif
         sys.exit(1)

    if args.tool == 'fuzzer':
        run_fuzzer(args)

    elif args.tool == 'nGOAT':
        run_gui()

    elif args.tool == 'ftpGOAT':
        run_ftp_scanner(args)

    elif args.tool == 'BruteGOAT':
        run_brutegoat(args)

def run_fuzzer(args):
    """
    Lance le fuzzer avec les options fournies

    Args:
        args: Arguments parsés
    """

    # ═══════════════════════════════════════════════════════
    # VALIDATION DES ARGUMENTS
    # ═══════════════════════════════════════════════════════

    if not args.wordlist:
        print(f"{RED}[!] Erreur: -w/--wordlist requis pour le fuzzer{RESET}")
        return

    if args.mode == 'param' and not args.param:
        print(f"{RED}[!] Erreur: -p/--param requis pour le mode param{RESET}")
        return

    if args.mode == 'post' and not args.param:
        print(f"{RED}[!] Erreur: -p/--param requis pour le mode post{RESET}")
        return

    if args.mode == 'form' and not args.form_url:
        # Si --form-url n'est pas spécifié, utiliser -u comme URL du formulaire
        args.form_url = args.url

    if args.mode == 'form' and not args.param:
        print(f"{RED}[!] Erreur: -p/--param requis pour le mode form (champ à fuzzer){RESET}")
        return

    if args.verbose and args.quiet:
        print(f"{RED}[!] Erreur: -v/--verbose et -q/--quiet sont incompatibles{RESET}")
        return

    if args.hide_codes and args.show_codes:
        print(f"{RED}[!] Erreur: --hide-codes et --show-codes sont incompatibles{RESET}")
        return

    # ═══════════════════════════════════════════════════════
    # AFFICHER LA CONFIGURATION
    # ═══════════════════════════════════════════════════════

    if not args.quiet:
        print(f"\n{GREEN}{'='*60}{RESET}")
        print(f"{GREEN}CONFIGURATION FUZZER{RESET}")
        print(f"{GREEN}{'='*60}{RESET}\n")

        print(f"{BLUE}Cible:{RESET}")
        print(f"  URL            : {args.url}")
        print(f"  Wordlist       : {args.wordlist}\n")

        print(f"{BLUE}Mode:{RESET}")
        print(f"  Type           : {args.mode}")

        if args.mode == 'param':
            print(f"  Paramètre      : {args.param}\n")

        if args.mode == 'post':
            print(f"  Paramètre      : {args.param}")
            if args.post_data:
                print(f"  Données POST   : {args.post_data}\n")
            else:
                print()

        if args.mode == 'form':
            if args.form_url and args.form_url != args.url:
                print(f"  URL formulaire : {args.form_url}")
            print(f"  Champ à fuzzer : {args.param}")
            if args.field_values:
                print(f"  Valeurs champs : {args.field_values}\n")
            else:
                print()

        print(f"{BLUE}Réseau:{RESET}")
        print(f"  Concurrence    : {args.threads}")
        print(f"  Timeout        : {args.timeout}s")
        print(f"  Suivre redirects : {args.follow_redirects}")

        if args.cookie:
            cookie_preview = args.cookie[:50] + "..." if len(args.cookie) > 50 else args.cookie
            print(f"  Cookie         : {cookie_preview}")

        if args.hide_codes or args.show_codes:
            print(f"{BLUE}Filtres:{RESET}")
            if args.hide_codes:
                print(f"  Cacher codes   : {args.hide_codes}")
            if args.show_codes:
                print(f"  Montrer codes  : {args.show_codes}")

        if args.extensions or args.prefix or args.suffix or args.xss_marker:
            print(f"{BLUE}Payloads:{RESET}")
            if args.extensions:
                print(f"  Extensions     : {args.extensions}")
            if args.prefix:
                print(f"  Préfixe        : {args.prefix}")
            if args.suffix:
                print(f"  Suffixe        : {args.suffix}\n")
            if args.suffix:
                print(f"  Xss Marker        : {args.xss_marker}\n")

        print(f"{BLUE}Détections:{RESET}")

        if args.output:
            print(f"  Fichier        : {args.output}")
        elif args.auto_export:
            print("  Mode           : Auto (results_YYYYMMDD_HHMMSS.txt)")
        else:
            print("  Mode           : Désactivé\n")

        if args.delay:
            print(f"{BLUE}Autres:{RESET}")
            print(f"  Délai          : {args.delay}s entre requêtes\n")


    # ═══════════════════════════════════════════════════════
    # LANCER LE FUZZER
    # ═══════════════════════════════════════════════════════

    try:
        print(f"{BLUE}[*] Démarrage du fuzzer...{RESET}\n")

        # Parser les cookies si fournis
        cookies = None
        if args.cookie:
            cookies = {}
            for cookie_pair in args.cookie.split(';'):
                cookie_pair = cookie_pair.strip()
                if '=' in cookie_pair:
                    name, value = cookie_pair.split('=', 1)
                    cookies[name.strip()] = value.strip()

        if args.hide_codes:
            hide_codes = parse_status_codes(args.hide_codes, "--hide-codes")
        else:
            hide_codes = []

        if args.show_codes:
            show_codes = parse_status_codes(args.show_codes, "--show-codes")
        else:
            show_codes = []

        fuzzer = WebFuzzer(
            base_url=args.url,
            timeout=args.timeout,
            cookies=cookies,
            follow_redirect=args.follow_redirects,
            show_codes=show_codes,
            hide_codes=hide_codes,
            xss_marker=args.xss_marker
        )

        # Lancer selon le mode
        if args.mode == 'dir':
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                payloads = []
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        payloads.append(stripped)

            payloads = transform_payloads(payloads, prefix=args.prefix,
                                          suffix=args.suffix, extensions=args.extensions)

            if args.mode == 'dir':
                asyncio.run(
                    fuzzer.fuzz_directories(
                        payloads=payloads,
                        max_concurrent=args.threads
                    )
                )

        elif args.mode == 'param':
            # Charger les payloads
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                payloads = []
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        payloads.append(stripped)

            payloads = transform_payloads(payloads, prefix=args.prefix, suffix=args.suffix, extensions=args.extensions)

            asyncio.run(
                fuzzer.fuzz_parameter(
                    endpoint="",
                    param_name=args.param,
                    payloads=payloads,
                    max_concurrent=args.threads,
                )
            )

        elif args.mode == 'post':
            # Charger les payloads
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                payloads = []
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        payloads.append(stripped)

            # Parser les données POST additionnelles
            post_data = {}
            if args.post_data:
                for pair in args.post_data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        post_data[key] = value

            asyncio.run(
                fuzzer.fuzz_post_parameter(
                    endpoint="",
                    param_name=args.param,
                    payloads=payloads,
                    additional_data=post_data,
                    max_concurrent=args.threads,
                )
            )

        elif args.mode == 'form':
            # Charger les payloads
            with open(args.wordlist, 'r', encoding='utf-8') as f:
                payloads = []
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        payloads.append(stripped)

            # Parser les valeurs de champs personnalisées
            field_values = {}
            if args.field_values:
                for pair in args.field_values.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        field_values[key] = value

            asyncio.run(
                fuzzer.fuzz_form(
                    form_url=args.form_url,
                    param_to_fuzz=args.param,
                    payloads=payloads,
                    field_values=field_values if field_values else None,
                    max_concurrent=args.threads
                )
            )

        # Export si demandé
        if args.output:
            fuzzer.export_results_txt(args.output)
        elif args.auto_export:
            fuzzer.export_results_txt()

        print(f"\n{GREEN}{'='*60}{RESET}")
        print(f"{GREEN}[✓] Fuzzing terminé avec succès!{RESET}")
        print(f"{GREEN}{'='*60}{RESET}")

    except FileNotFoundError:
        print(f"{RED}[!] Erreur: Wordlist non trouvée: {args.wordlist}{RESET}")

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interruption par l'utilisateur{RESET}")

    except Exception as e:
        print(f"{RED}[!] Erreur: {e}{RESET}")

 # ═══════════════════════════════════════════════════════
    # LANCER LE FUZZER
    # ═══════════════════════════════════════════════════════


if __name__ == "__main__":
    main()
