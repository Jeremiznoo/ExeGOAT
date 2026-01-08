"""
ExeGOAT - WEB FUZZER
"""
from typing import List
from datetime import datetime
import re
from urllib.parse import urlparse
import os
import asyncio
from bs4 import BeautifulSoup
import httpx
class WebFuzzer:
    """
    Web Fuzzer tools for ExeGOAT
        Attributes:
            base_url (str): URL de base de la cible (ex: "https://example.com")
            timeout (float): Timeout en secondes pour les requêtes
            cookies (dict): Cookies de session (ex: {"PHPSESSID": "abc123"})
            show_codes (list): Code http que l'utilisateur souhaite voir
            hide_codes (list): Code http que l'utilisateur ne souhaite pas voir
            follow_redirect (bool): Permet de suivre ou non les redirections
            xss_marker (str): Marqueur qui permet de detecter les xss 
    """
    def __init__(self, base_url: str, timeout: float = 5.0, cookies: dict = None,
                 follow_redirect = False, show_codes: list = None, hide_codes: list = None,
                 xss_marker: str ="xss"):
        """
        Initialise le fuzzer web
        
        Args:
            base_url (str): URL de base de la cible (ex: "https://example.com")
            timeout (float): Timeout en secondes pour les requêtes
            cookies (dict): Cookies de session (ex: {"PHPSESSID": "abc123"})
            show_codes (list): Code http que l'utilisateur souhaite voir
            hide_codes (list): Code http que l'utilisateur ne souhaite pas voir
            follow_redirect (bool): Permet de suivre ou non les redirections
            xss_marker (str): Marqueur qui permet de detecter les xss 

        """
        self.base_url = base_url
        self.timeout = timeout
        self.cookies = cookies
        self.hide_codes = hide_codes
        self.show_codes = show_codes
        self.follow_redirect = follow_redirect
        self.xss_marker = xss_marker
        self.results = []
        self.baseline_length = None
        self.baseline_tags = None

        if self.show_codes is None:
            self.show_codes = []

        if self.hide_codes is None:
            self.hide_codes = []

    def _include_result(self, result: dict) -> bool:
        """
        Détermine si un résultat doit être inclus selon les filtres
        
        Args:
            result (dict): Résultat à vérifier
        
        Returns:
            bool: True si le résultat doit être inclus
        """
        status = result.get('status')

        # Filtrer par codes à masquer
        if self.hide_codes and status in self.hide_codes:
            return False

        # Filtrer par codes à afficher uniquement
        if self.show_codes and status not in self.show_codes:
            return False

        return True


    def export_results_txt(self, output_file: str = None) -> None:
        """
        Exporte les résultats en format texte brut
        
        Args:
            output_file (str): Chemin du fichier de sortie
        
        Returns:
            None
        """
        if not self.results:
            print("[!] Aucun résultat à exporter")
            return

        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"results_{timestamp}.txt"

        full_path = os.path.join(os.getcwd(), output_file)

        with open(full_path, 'w', encoding='utf-8') as f:
            for r in self.results:
                status = r.get('status')
                url = r.get('url')
                payload = r.get('payload', '')
                length = r.get('length', 0)

                reasons = r.get('reasons', [])

                line = (
                    f"[{status}] {url} | "
                    f"payload={payload!r} | "
                    f"length={length} bytes | "
                    f"reasons={reasons}"
                )
                f.write(line + "\n")

        print(f"[✓] Résultats exportés vers: {full_path}")



    async def fuzz_directories(self,  payloads: list[str], max_concurrent: int = 50) -> list:
        """
        Fuzz des répertoires / fichiers à partir de payloads préparés

        Args:
            payloads (list[str]): Liste des chemins à tester
            max_concurrent (int): Nombre maximum de requêtes simultanées

        Returns:
            list: Résultats filtrés et conservés
        """

        print(f"[*] Chargé {len(payloads)} payloads")
        print(f"[*] Cible: {self.base_url}")
        print(f"[*] Concurrence: {max_concurrent}\n")

        # Permet de limiter le nombre de requêtes simultanées
        req_paralalize_max = asyncio.Semaphore(max_concurrent)

        async def test_url_paralalize(client: httpx.AsyncClient, payload: str) -> dict:
            async with req_paralalize_max:
                url = f"{self.base_url.rstrip('/')}/{payload.lstrip('/')}"

                try:
                    response = await client.get(url)
                    return {
                        "url": url,
                        "path": payload,
                        "status": response.status_code,
                        "length": len(response.content),
                    }

                except Exception:
                    return {
                        "url": url,
                        "path": payload,
                        "status": "ERROR",
                        "length": 0,
                    }

        # Lancer toutes les requêtes
        async with httpx.AsyncClient(follow_redirects=self.follow_redirect,
                                     cookies=self.cookies) as client:
            tasks = []
            for payload in payloads:
                task = test_url_paralalize(client, payload)
                tasks.append(task)

            results = await asyncio.gather(*tasks)

        # Filtrer et afficher les résultats
        for result in results:

            if self._include_result(result):
                self._print_result(result)

            self.results.append(result)

        print(f"\n[✓] Terminé ! {len(self.results)} URLs trouvées")
        return self.results


    def _print_result(self, result: dict) -> None:
        """
        Affiche un résultat de façon lisible
        
        Args:
            result (dict): Résultat à afficher
        
        Returns:
            None
        """
        status = result.get('status')
        url = result.get('url')
        length = result.get('length', 0)

        if status == 200:
            print(f"[{status}] {url} ({length} bytes)")

        elif status == 301 or status == 302:
            redirect = result.get('redirect')
            print(f"[{status}] {url} → {redirect}")

        elif status == 403:
            print(f"[{status}] {url} [FORBIDDEN]")

        elif status == 'TIMEOUT':
            print(f"[TIMEOUT] {url}")

        else:
            print(f"[{status}] {url}")

    async def fuzz_parameter(self, endpoint: str, param_name: str,
                              payloads: List[str], max_concurrent: int = 20) -> list:
        """
        Fuzze un paramètre GET avec différents payloads
        
        Args:
            endpoint (str): Endpoint à tester (ex: "/search")
            param_name (str): Nom du paramètre (ex: "q")
            payloads (list): Liste des payloads à tester
            max_concurrent (int): Nombre de requêtes simultanées
        
        Returns:
            list: Liste des résultats avec anomalies détectées
        """
        print(f"[*] Fuzzing paramètre '{param_name}' sur {endpoint}")
        print(f"[*] {len(payloads)} payloads à tester\n")

        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_payload(client, payload):
            """
            Teste un payload spécifique
            
            Args:
                client (httpx.AsyncClient): Client HTTP
                payload (str): Payload à tester
            
            Returns:
                dict: Résultat du test avec anomalies
            """
            async with semaphore:
                url = f"{self.base_url}/{endpoint}"
                params = {param_name: payload}

                try:
                    response = await client.get(url, params=params, timeout=self.timeout)
                    is_valid, reasons = self._detect_anomalies(response, payload)

                    result = {
                        'payload': payload,
                        'url': str(response.url),
                        'status': response.status_code,
                        'length': len(response.content),
                        'valid': is_valid,
                        'reasons': reasons
                    }

                    if is_valid:
                        payload_preview = payload[:50]
                        size_diff = len(response.content) - self.baseline_length if self.baseline_length else 0
                        if self._include_result(result):
                            print(f"[✓] Payload valide: {payload_preview}")
                            print(f"    └─ Status: {response.status_code}, Length: {len(response.content)} (Δ{size_diff:+d})")
                            if reasons:
                                print(f"    └─ Raisons: {', '.join(reasons)}")

                    return result

                except Exception as e:
                    return {
                        'payload': payload, 
                        'status': 'ERROR', 
                        'error': str(e)
                    }

        # Exécution des tests en parallèle
        async with httpx.AsyncClient(follow_redirects=self.follow_redirect,
                                     cookies=self.cookies) as client:
            tasks = [test_payload(client, payload) for payload in payloads]
            results = await asyncio.gather(*tasks)

        # Filtrage des résultats intéressants
        interesting = []
        for result in results:
            if result.get('valid'):
                self.results.append(result)
                interesting.append(result)

        print(f"\n[✓] {len(interesting)} payloads valides trouvés")
        return interesting

    def _detect_anomalies(self, response: httpx.Response, payload: str) -> tuple:
        """
        Détecte si le payload a provoqué une anomalie et retourne les raisons
        
        Args:
            response (httpx.Response): Réponse HTTP à analyser
            payload (str): Payload envoyé
        
        Returns:
            tuple: (bool, list) - (est_valide, liste_des_raisons)
        """
        text = response.text.lower()
        content_length = len(response.content)
        reasons = []
        marker = self.xss_marker

        # contexte HTML non échappé
        if '<' in payload and '<img' in text:
            reasons.append("XSS_HTML")

        # contexte JS
        if f'alert("{marker}")' in text:
            reasons.append("XSS_JS")

        # Erreurs SQL
        sql_errors = [
            ('sql syntax', 'SQL_SYNTAX'),
            ('SQLSTATE', 'MYSQL_ERROR'),
            ('sqlite', 'SQLITE_ERROR'),
            ('postgresql', 'POSTGRES_ERROR'),
            ('ora-', 'ORACLE_ERROR'),
            ('sqlstate', 'SQL_STATE'),
            ('you have an error in your sql', 'SQL_ERROR'),
            ('database error', 'DB_ERROR'),
            ('table does not exist', 'TABLE_NOT_FOUND'),
            ('column not found', 'COLUMN_NOT_FOUND'),
        ]

        for error_str, error_name in sql_errors:
            if error_str in text:
                reasons.append(error_name)
                break

        # Erreurs de code
        code_errors = [
            ('fatal error', 'FATAL_ERROR'),
            ('traceback', 'TRACEBACK'),
            ('warning:', 'PHP_WARNING'),
            ('parse error', 'PARSE_ERROR'),
            ('undefined variable', 'UNDEFINED_VAR'),
            ('exception', 'EXCEPTION'),
        ]

        for error_str, error_name in code_errors:
            if error_str in text:
                reasons.append(error_name)
                break

        # Erreur serveur
        if response.status_code >= 500:
            reasons.append(f"SERVER_ERROR_{response.status_code}")

        # Recupere la page d'origine (baseline)
        if self.baseline_length is None:
            if content_length is None :
                self.baseline_length = 0
            else :
                self.baseline_length = content_length

            self.baseline_tags = len(re.findall(r'<[^>]+>', response.text))
            return False, []

        # Compter les balises HTML

        if self.baseline_tags is not None:
            tags_in_response = len(re.findall(r'<[^>]+>', response.text))

            if tags_in_response > self.baseline_tags + 6:
                diff = tags_in_response - self.baseline_tags
                reasons.append(f"EXTRA_TAGS (+{diff})")

        # Différence de taille
        size_diff = content_length - self.baseline_length

        if abs(size_diff) > 500:
            reasons.append(f"SIZE_DIFF ({size_diff:+d})")

        elif content_length > self.baseline_length * 1.3:
            percent = int((content_length / self.baseline_length - 1) * 100)
            reasons.append(f"LARGE (+{percent}%)")

        elif content_length < self.baseline_length * 0.7:
            percent = int((1 - content_length / self.baseline_length) * 100)
            reasons.append(f"SHORT (-{percent}%)")


        return len(reasons) > 0, reasons

    async def fuzz_post_parameter(self, endpoint: str, param_name: str,
                                   payloads: List[str], additional_data: dict = None,
                                   max_concurrent: int = 20) -> list:
        """
        Fuzze un paramètre POST avec différents payloads
        
        Args:
            endpoint (str): Endpoint à tester (ex: "/login")
            param_name (str): Nom du paramètre POST à fuzzer (ex: "password")
            payloads (list): Liste des payloads à tester
            additional_data (dict): Données POST additionnelles (ex: {"username": "admin"})
            max_concurrent (int): Nombre de requêtes simultanées
        
        Returns:
            list: Liste des résultats avec anomalies détectées
        """

        print(f"[*] Fuzzing paramètre POST '{param_name}' sur {endpoint}")
        print(f"[*] {len(payloads)} payloads à tester")
        if additional_data:
            print(f"[*] Données additionnelles: {additional_data}")
        print()

        # Limitation des requêtes
        semaphore = asyncio.Semaphore(max_concurrent)

        async def test_payload(client, payload):
            """
            Teste un payload POST spécifique
            
            Args:
                client (httpx.AsyncClient): Client HTTP
                payload (str): Payload à tester
            
            Returns:
                dict: Résultat du test avec anomalies
            """
            async with semaphore:
                # Construction de l'URL
                if endpoint:
                    url = f"{self.base_url}/{endpoint}"
                else:
                    url = self.base_url

                # Préparation des données POST
                if additional_data:
                    post_data = additional_data.copy()
                else:
                    post_data = {}
                post_data[param_name] = payload

                try:
                    # Envoi de la requête POST
                    response = await client.post(url, data=post_data, timeout=self.timeout)

                    # Détection des anomalies
                    is_valid, reasons = self._detect_anomalies(response, payload)

                    # Construction du résultat
                    result = {
                        'payload': payload,
                        'url': str(response.url),
                        'status': response.status_code,
                        'length': len(response.content),
                        'valid': is_valid,
                        'reasons': reasons,
                        'post_data': post_data
                    }
                    print(is_valid)
                    # Affichage si payload valide
                    if is_valid :
                        payload_preview = payload[:50]
                        size_diff = len(response.content) - self.baseline_length if self.baseline_length else 0
                        print(f"[✓] Payload valide: {payload_preview}")
                        print(f"    └─ Status: {response.status_code}, Length: {len(response.content)} (Δ{size_diff:+d})")
                        if reasons:
                            print(f"    └─ Raisons: {', '.join(reasons)}")

                    return result

                except Exception as e:
                    return {
                        'payload': payload, 
                        'status': 'ERROR', 
                        'error': str(e)
                    }

        # Exécution des tests en parallèle
        async with httpx.AsyncClient(follow_redirects=self.follow_redirect,
                                     cookies=self.cookies) as client:
            tasks = [test_payload(client, payload) for payload in payloads]
            results = await asyncio.gather(*tasks)

        # Filtrage des résultats intéressants
        interesting = []
        for result in results:
            if result.get('valid'):
                print(result)
                self.results.append(result)
                interesting.append(result)

        print(f"\n[✓] {len(interesting)} payloads valides trouvés")
        return interesting

    async def extract_form_fields(self, url: str) -> dict:
        """
        Extrait automatiquement les champs d'un formulaire HTML
        
        Args:
            url (str): URL de la page contenant le formulaire
        
        Returns:
            dict: Informations du formulaire ou None
        """
        try:
            async with httpx.AsyncClient(follow_redirects=True, cookies=self.cookies) as client:
                print(f"[*] Récupération du formulaire depuis {url}")
                response = await client.get(url, timeout=self.timeout)

                print(f"[*] Status: {response.status_code}, Taille: {len(response.text)} bytes")

                soup = BeautifulSoup(response.text, 'html.parser')

                # Trouver tous les formulaires
                forms = soup.find_all('form')

                if not forms:
                    print("[!] Aucun formulaire trouvé sur la page")
                    print("[*] Début du HTML (500 premiers caractères):")
                    print(response.text[:500])
                    return None

                # Utiliser le premier formulaire
                form = forms[0]

                if len(forms) > 1:
                    print(f"[*] {len(forms)} formulaires trouvés, utilisation du premier")

                # Extraire les informations du formulaire
                form_data = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'GET').upper(),
                    'fields': {},
                    'inputs': []
                }

                # Extraire tous les champs
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        value = input_tag.get('value', '')
                        input_type = input_tag.get('type', 'text')

                        form_data['fields'][name] = value
                        form_data['inputs'].append({
                            'name': name,
                            'type': input_type,
                            'value': value
                        })

                print("[✓] Formulaire trouvé:")
                print(f"    Action: {form_data['action']}")
                print(f"    Méthode: {form_data['method']}")
                print(f"    Champs trouvés: {len(form_data['inputs'])}")

                for inp in form_data['inputs']:
                    print(f"      - {inp['name']} (type: {inp['type']})")

                return form_data

        except Exception as e:
            print(f"[!] Erreur lors de l'extraction du formulaire: {e}")
            return None

    async def fuzz_form(self, form_url: str, param_to_fuzz: str,
                        payloads: List[str], field_values: dict = None,
                        max_concurrent: int = 20) -> list:
        """
        Fuzze automatiquement un formulaire en extrayant d'abord ses champs
        
        Args:
            form_url (str): URL de la page contenant le formulaire
            param_to_fuzz (str): Nom du champ à fuzzer (ex: "password")
            payloads (list): Liste des payloads à tester
            field_values (dict): Valeurs personnalisées pour les autres champs
            max_concurrent (int): Nombre de requêtes simultanées
        
        Returns:
            list: Liste des résultats avec anomalies détectées
        """
        print("[*] Démarrage du fuzzing automatique de formulaire")
        print(f"[*] URL: {form_url}")
        print(f"[*] Paramètre à fuzzer: {param_to_fuzz}\n")

        # Extraire le formulaire
        form_info = await self.extract_form_fields(form_url)

        # Si le form n'est pas trouvé
        if not form_info:
            print("[!] Impossible de continuer sans formulaire")
            return []

        post_data = {}

        # Mettre les champs en valeur par défaut
        for field_name, default_value in form_info['fields'].items():
            if field_name != param_to_fuzz:
                post_data[field_name] = default_value if default_value else ''

        # Si des champs sont avec des valeurs personalisé
        if field_values:
            for field_name, value in field_values.items():
                if field_name != param_to_fuzz:
                    post_data[field_name] = value

        print("\n[*] Données du formulaire préparées:")
        for key, value in post_data.items():
            value_preview = str(value)[:50]
            print(f"    {key} = {value_preview}")
        print()

        # URL d'action du formulaire
        action = form_info['action']

        # Url absolue
        if action.startswith('http'):
            target_url = action
        elif action.startswith('/'):  # si url depuis la racine
            parsed = urlparse(form_url)
            target_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        else:
            # URL relative
            base_path = '/'.join(form_url.split('/')[:-1])
            target_url = f"{base_path}/{action}"

        # Extraire les composants de l'URL cible
        parsed_target = urlparse(target_url)
        target_base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        target_endpoint = parsed_target.path.lstrip('/')

        # redirection vers le chemin du formulaire
        original_base_url = self.base_url
        self.base_url = target_base_url

        # Lance le fuzzing selon la méthode du formulaire
        if form_info['method'] == 'POST':
            print(f"[*] Fuzzing POST sur {target_url}\n")

            results = await self.fuzz_post_parameter(
                endpoint=target_endpoint,
                param_name=param_to_fuzz,
                payloads=payloads,
                additional_data=post_data,
                max_concurrent=max_concurrent
            )

        else:
            # Méthode GET
            print(f"[*] Fuzzing GET sur {target_url}\n")

            results = await self.fuzz_parameter(
                endpoint=target_endpoint,
                param_name=param_to_fuzz,
                payloads=payloads,
                max_concurrent=max_concurrent
            )

        self.base_url = original_base_url

        return results

def parse_status_codes(value: str, option_name: str) -> list[int]:
    """
        Permet de parser les codes https dans la commandes fourni par le user
        Args :
            value (str) : 
            option_name (str) : le nom de l'option (hide codes, show codes)
        
        Returns :
            list(set(int)) :  Les codes http
    """
    codes = []
    for code in value.split(','):
        code = code.strip()
        
        if not code:
            continue

        if not code.isdigit():
            raise ValueError(f"{option_name}: code invalide '{code}'")
        codes.append(int(code))

    return list(set(codes)) # Permet de ne pas avoir de doublons

def transform_payloads(payloads, prefix=None, suffix=None, extensions=None) -> str:
    """
    Permet de transformet les payloads ajouter un suffix, prefix ou une extenstion 
    
    Args:
        payloads (str): le payloads que l'on shouaite modifié
        prefix (str): la valeur à ajouter avant le au payload (Ex : test_PAYLOAD)
        suffix (str): la valeur à ajouter après le au payload ( Ex : PAYLOAD_backup)
        extensions (str): la valeur à ajouter après le au payload ( Ex: PAYLOAD.ext, PAYLOAD.html )

    Returns : 
        str : le payload modifié
    """
    results = set()

    # Parser extensions
    ext_list = []
    if extensions:
        ext_list = [
            ext.strip().lstrip('.')
            for ext in extensions.split(',')
            if ext.strip()
        ]

    for payload in payloads:
        base = payload.strip()
        if not base:
            continue

        if prefix:
            base = f"{prefix}{base}"

        if suffix:
            base = f"{base}{suffix}"

        # Payload sans extension
        results.add(base)

        # Payloads avec extensions
        for ext in ext_list:
            results.add(f"{base}.{ext}")

    return list(results)
