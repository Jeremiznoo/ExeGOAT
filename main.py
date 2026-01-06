import argparse
import asyncio
from colorama import init, Fore, Style
from tools.fuzz import WebFuzzer

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

    parser = argparse.ArgumentParser(
        prog="ExeGOAT",
        description="Suite d'outils de sécurité web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ═══════════════════════════════════════════════════════
    # SÉLECTION DE L'OUTIL
    # ═══════════════════════════════════════════════════════

    parser.add_argument(
        'tool',
        type=str,
        choices=['fuzzer',],
        help='Outil à utiliser'
    )

    # ═══════════════════════════════════════════════════════
    # OPTIONS COMMUNES
    # ═══════════════════════════════════════════════════════

    common = parser.add_argument_group('options communes')

    common.add_argument(
        '-u', '--url',
        type=str,
        required=True,
        metavar='URL',
        help='URL cible (ex: http://example.com ou http://example.com/path)'
    )

    common.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux (afficher plus de détails)'
    )

    common.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Mode silencieux (afficher uniquement les résultats)'
    )

    # ═══════════════════════════════════════════════════════
    #  FUZZER - OBLIGATOIRES
    # ═══════════════════════════════════════════════════════

    fuzzer_required = parser.add_argument_group('fuzzer - arguments obligatoires')

    fuzzer_required.add_argument(
        '-w', '--wordlist',
        type=str,
        metavar='FILE',
        help='Chemin vers le fichier wordlist (requis pour fuzzer)'
    )

    # ═══════════════════════════════════════════════════════
    #  FUZZER - MODE DE FUZZING
    # ═══════════════════════════════════════════════════════

    fuzzer_mode = parser.add_argument_group('fuzzer - mode de fuzzing')

    fuzzer_mode.add_argument(
        '-m', '--mode',
        type=str,
        choices=['dir', 'param', 'post', 'form'],
        default='dir',
        metavar='MODE',
        help='Fuzzing mode: dir (répertoires), param (paramètres GET), post (paramètres POST), form (formulaire auto) Défaut: dir'
    )

    fuzzer_mode.add_argument(
        '-p', '--param',
        type=str,
        metavar='PARAM',
        help='Nom du paramètre GET/POST à fuzzer (requis si mode=param/post) Ex: -p id'
    )

    fuzzer_mode.add_argument(
        '--post-data',
        type=str,
        metavar='DATA',
        help='Données POST supplémentaires (format: key1=value1&key2=value2) Ex: --post-data "username=admin&password=test"'
    )

    fuzzer_mode.add_argument(
        '--form-url',
        type=str,
        metavar='URL',
        help='URL de la page contenant le formulaire (optionnel, utilise -u par défaut) Ex: --form-url "http://example.com/login.php"'
    )

    fuzzer_mode.add_argument(
        '--field-values',
        type=str,
        metavar='DATA',
        help='Valeurs personnalisées pour les champs du formulaire (format: key1=value1&key2=value2) Ex: --field-values "username=admin&email=test@test.com"'
    )

    # ═══════════════════════════════════════════════════════
    #  FUZZER - CONFIGURATION RÉSEAU
    # ═══════════════════════════════════════════════════════

    fuzzer_network = parser.add_argument_group('fuzzer - configuration réseau')

    fuzzer_network.add_argument(
        '-t', '--threads',
        type=int,
        default=50,
        metavar='NUM',
        help='Nombre de requêtes simultanées (concurrence) Défaut: 50'
    )

    fuzzer_network.add_argument(
        '--timeout',
        type=float,
        default=5.0,
        metavar='SEC',
        help='Timeout en secondes pour chaque requête Défaut: 5.0'
    )

    fuzzer_network.add_argument(
        '--follow-redirects',
        action='store_true',
        help='Suivre les redirections HTTP (301, 302) Défaut: False'
    )

    fuzzer_network.add_argument(
        '--cookie',
        type=str,
        metavar='COOKIE',
        help='Cookie de session (format: "name1=value1; name2=value2")"'
    )

    # ═══════════════════════════════════════════════════════
    #  FUZZER - FILTRES DE RÉSULTATS
    # ═══════════════════════════════════════════════════════

    fuzzer_filter = parser.add_argument_group('fuzzer - filtres de résultats')

    fuzzer_filter.add_argument(
        '--hide-codes',
        type=str,
        metavar='CODES',
        help='Codes de statut à cacher, séparés par des virgules Ex: --hide-codes 404,403'
    )

    fuzzer_filter.add_argument(
        '--show-codes',
        type=str,
        metavar='CODES',
        help='Afficher uniquement ces codes de statut Ex: --show-codes 200,301'
    )

    # ═══════════════════════════════════════════════════════
    # FUZZER - PAYLOADS
    # ═══════════════════════════════════════════════════════

    fuzzer_payload = parser.add_argument_group('fuzzer - configuration des payloads')

    fuzzer_payload.add_argument(
        '--extensions',
        type=str,
        metavar='EXT',
        help='Extensions à ajouter aux payloads Ex: --extensions php,html,txt'
    )

    fuzzer_payload.add_argument(
        '--prefix',
        type=str,
        metavar='PREFIX',
        help='Préfixe à ajouter aux payloads Ex: --prefix test_'
    )

    fuzzer_payload.add_argument(
        '--suffix',
        type=str,
        metavar='SUFFIX',
        help='Suffixe à ajouter aux payloads Ex: --suffix _backup'
    )

    # ═══════════════════════════════════════════════════════
    # FUZZER - EXPORT
    # ═══════════════════════════════════════════════════════

    fuzzer_output = parser.add_argument_group('fuzzer - export des résultats')

    fuzzer_output.add_argument(
        '-o', '--output',
        type=str,
        metavar='FILE',
        help='Fichier de sortie pour exporter les résultats Si non spécifié, pas d\'export'
    )

    fuzzer_output.add_argument(
        '--auto-export',
        action='store_true',
        help='Exporter automatiquement dans results_YYYYMMDD_HHMMSS.txt'
    )

    # ═══════════════════════════════════════════════════════
    # FUZZER - AUTRES
    # ═══════════════════════════════════════════════════════

    fuzzer_misc = parser.add_argument_group('fuzzer -  diverses')

    fuzzer_misc.add_argument(
        '--delay',
        type=float,
        metavar='SEC',
        help='Délai entre chaque requête en secondes. Ex: --delay 0.1'
    )

    # ═══════════════════════════════════════════════════════
    # PARSER LES ARGUMENTS
    # ═══════════════════════════════════════════════════════

    args = parser.parse_args()

    # ═══════════════════════════════════════════════════════
    # ROUTER VERS L'OUTIL APPROPRIÉ
    # ═══════════════════════════════════════════════════════

    if args.tool == 'fuzzer':
        run_fuzzer(args)

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

        if args.extensions or args.prefix or args.suffix:
            print(f"{BLUE}Payloads:{RESET}")
            if args.extensions:
                print(f"  Extensions     : {args.extensions}")
            if args.prefix:
                print(f"  Préfixe        : {args.prefix}")
            if args.suffix:
                print(f"  Suffixe        : {args.suffix}\n")

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

        fuzzer = WebFuzzer(
            base_url=args.url,
            timeout=args.timeout,
            cookies=cookies,
            follow_redirect=args.follow_redirects
        )

        # Lancer selon le mode
        if args.mode == 'dir':
            asyncio.run(
                fuzzer.fuzz_directories(
                    wordlist_path=args.wordlist,
                    max_concurrent=args.threads,
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

            results = asyncio.run(
                fuzzer.fuzz_parameter(
                    endpoint="",
                    param_name=args.param,
                    payloads=payloads,
                    max_concurrent=args.threads,
                    follow_redirect=args.follow_redirects
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

            results = asyncio.run(
                fuzzer.fuzz_post_parameter(
                    endpoint="",
                    param_name=args.param,
                    payloads=payloads,
                    additional_data=post_data,
                    max_concurrent=args.threads,
                    follow_redirect=args.follow_redirects
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

            results = asyncio.run(
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


if __name__ == "__main__":
    main()