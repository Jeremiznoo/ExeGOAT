# tests/test_ftpgoat.py
import pytest
from unittest.mock import Mock, patch, MagicMock, mock_open, call
import ftplib
from io import StringIO
from tools.FTPGOAT import FTPGOAT, run_ftp_scanner


class TestFTPGOAT:
    """Tests pour la classe FTPGOAT"""
    
    @pytest.fixture
    def ftp_scanner(self):
        """Fixture pour créer une instance FTPGOAT"""
        return FTPGOAT("192.168.1.100", port=21, timeout=10.0)
    
    def test_init_default_values(self):
        """Test l'initialisation avec valeurs par défaut"""
        scanner = FTPGOAT("example.com")
        
        assert scanner.host == "example.com"
        assert scanner.port == 21
        assert scanner.timeout == 10.0
    
    def test_init_custom_values(self):
        """Test l'initialisation avec valeurs personnalisées"""
        scanner = FTPGOAT("ftp.example.com", port=2121, timeout=30.0)
        
        assert scanner.host == "ftp.example.com"
        assert scanner.port == 2121
        assert scanner.timeout == 30.0
    
    @patch('ftplib.FTP')
    def test_check_anonymous_success(self, mock_ftp_class, ftp_scanner, capsys):
        """Test connexion anonyme réussie"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.getwelcome.return_value = "220 Welcome to FTP server"
        
        result = ftp_scanner.check_anonymous()
        
        assert result is True
        mock_ftp.connect.assert_called_once_with("192.168.1.100", 21, timeout=10.0)
        mock_ftp.login.assert_called_once_with('anonymous', 'anonymous')
        mock_ftp.quit.assert_called_once()
        
        captured = capsys.readouterr()
        assert "Connexion anonyme réussie" in captured.out
    
    @patch('ftplib.FTP')
    def test_check_anonymous_failure(self, mock_ftp_class, ftp_scanner, capsys):
        """Test connexion anonyme échouée"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")
        
        result = ftp_scanner.check_anonymous()
        
        assert result is False
        
        captured = capsys.readouterr()
        assert "Connexion anonyme refusée" in captured.out
    
    @patch('ftplib.FTP')
    def test_check_anonymous_connection_error(self, mock_ftp_class, ftp_scanner, capsys):
        """Test erreur de connexion"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.connect.side_effect = ftplib.error_temp("Connection refused")
        
        result = ftp_scanner.check_anonymous()
        
        assert result is False
        
        captured = capsys.readouterr()
        assert "Connexion anonyme refusée" in captured.out
    
    @patch('ftplib.FTP')
    def test_brute_force_no_credentials_found(self, mock_ftp_class, ftp_scanner, capsys):
        """Test brute-force sans trouver de credentials"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.login.side_effect = ftplib.error_perm("530 Login incorrect")
        
        users = ["admin", "user"]
        passwords = ["password", "123456"]
        
        result = ftp_scanner.brute_force(users, passwords)
        
        assert result == []
        assert mock_ftp.connect.call_count == 4  # 2 users * 2 passwords
        
        captured = capsys.readouterr()
        assert "Aucun mot de passe trouvé" in captured.out
    
    @patch('ftplib.FTP')
    def test_brute_force_credentials_found(self, mock_ftp_class, ftp_scanner, capsys):
        """Test brute-force avec succès"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        
        # Premier et troisième essais valide
        call_count = [0]
        def login_side_effect(user, password):
            call_count[0] += 1
            if call_count[0] in [1, 3]:  # admin:password et user:password
                return None
            raise ftplib.error_perm("530 Login incorrect")
        
        mock_ftp.login.side_effect = login_side_effect
        
        users = ["admin", "user"]
        passwords = ["password", "wrong"]
        
        result = ftp_scanner.brute_force(users, passwords)
        
        assert len(result) == 2
        assert ("admin", "password") in result
        assert ("user", "password") in result
        
        captured = capsys.readouterr()
        assert "Créneaux trouvés" in captured.out
    
    @patch('ftplib.FTP')
    def test_brute_force_single_credential(self, mock_ftp_class, ftp_scanner):
        """Test brute-force avec un seul credential trouvé"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        
        # Seul le deuxième essai réussit
        call_count = [0]
        def login_side_effect(user, password):
            call_count[0] += 1
            if user == "admin" and password == "admin123":
                return None
            raise ftplib.error_perm("530 Login incorrect")
        
        mock_ftp.login.side_effect = login_side_effect
        
        result = ftp_scanner.brute_force(["admin"], ["wrong", "admin123", "test"])
        
        assert len(result) == 1
        assert result[0] == ("admin", "admin123")
    
    @patch('ftplib.FTP')
    def test_enumerate_success(self, mock_ftp_class, ftp_scanner, capsys):
        """Test énumération des fichiers avec succès"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        
        #retourne une liste vide pour éviter la récursion
        mock_ftp.nlst.return_value = []
        mock_ftp.cwd.return_value = None
        
        ftp_scanner.enumerate("testuser", "testpass")
        
        mock_ftp.connect.assert_called_once_with("192.168.1.100", 21, timeout=10.0)
        mock_ftp.login.assert_called_once_with("testuser", "testpass")
        mock_ftp.quit.assert_called_once()
        
        captured = capsys.readouterr()
        assert "Énumération des fichiers" in captured.out
        
    @patch('ftplib.FTP')
    def test_enumerate_connection_error(self, mock_ftp_class, ftp_scanner, capsys):
        """Test énumération avec erreur de connexion"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.connect.side_effect = ftplib.error_temp("Connection failed")
        
        ftp_scanner.enumerate("testuser", "testpass")
        
        captured = capsys.readouterr()
        assert "Erreur lors de l'énumération" in captured.out
    
    @patch('ftplib.FTP')
    def test_list_files_recursive_with_subdirectories(self, mock_ftp_class, ftp_scanner, capsys):
        """Test du listing récursif avec sous-dossiers"""
        mock_ftp = MagicMock()
        
        # Compteur pour suivre les appels
        call_counts = {'nlst': 0}
        
        def mock_nlst():
            call_counts['nlst'] += 1
            if call_counts['nlst'] == 1:
                return ["subdir", "file.txt"]
            elif call_counts['nlst'] == 2:
                return ["subfile.txt"]
            else:
                return []  
        
        def mock_cwd(path):
            if path == "subdir": 
                return None
            elif path in ["file.txt", "subfile.txt"]:
                raise ftplib.error_perm("Not a directory")
            elif path in ["..", "/"]:
                return None
            else:
                return None
        
        mock_ftp.nlst.side_effect = mock_nlst
        mock_ftp.cwd.side_effect = mock_cwd
        
        ftp_scanner.list_files_recursive(mock_ftp, "/")
        
        
        assert call_counts['nlst'] >= 2
        
        captured = capsys.readouterr()
        assert "[D]" in captured.out or "[F]" in captured.out
    
    @patch('ftplib.FTP')
    def test_list_files_recursive_permission_denied(self, mock_ftp_class, ftp_scanner):
        """Test du listing avec permission refusée"""
        mock_ftp = MagicMock()
        mock_ftp.cwd.side_effect = ftplib.error_perm("550 Permission denied")
        
        ftp_scanner.list_files_recursive(mock_ftp, "/restricted")
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['exit'])
    def test_interactive_shell_exit(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test du shell interactif avec commande exit"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/home"
        
        ftp_scanner.interactive_shell("testuser", "testpass")
        
        mock_ftp.login.assert_called_once_with("testuser", "testpass")
        
        captured = capsys.readouterr()
        assert "Connecté" in captured.out
        assert "Fermeture de la session" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['help', 'exit'])
    def test_interactive_shell_help(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande help dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        captured = capsys.readouterr()
        assert "Commandes disponibles" in captured.out
        assert "ls" in captured.out
        assert "cd" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['ls', 'exit'])
    def test_interactive_shell_ls(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test de la commande ls dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        mock_ftp.retrlines.assert_called_with('LIST')
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['pwd', 'exit'])
    def test_interactive_shell_pwd(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande pwd dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/home/user"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        captured = capsys.readouterr()
        assert "/home/user" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['cd /tmp', 'exit'])
    def test_interactive_shell_cd(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test de la commande cd dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        mock_ftp.cwd.assert_called_with('/tmp')
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['cd', 'exit'])
    def test_interactive_shell_cd_no_args(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande cd sans arguments"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        captured = capsys.readouterr()
        assert "Usage: cd" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['get test.txt', 'exit'])
    @patch('builtins.open', new_callable=mock_open)
    def test_interactive_shell_get(self, mock_file, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande get dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        mock_ftp.retrbinary.assert_called()
        
        captured = capsys.readouterr()
        assert "téléchargé" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['get', 'exit'])
    def test_interactive_shell_get_no_args(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande get sans arguments"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        captured = capsys.readouterr()
        assert "Usage: get" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['cat readme.txt', 'exit'])
    def test_interactive_shell_cat(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test de la commande cat dans le shell"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        mock_ftp.retrlines.assert_called_with('RETR readme.txt')
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['cat', 'exit'])
    def test_interactive_shell_cat_no_args(self, mock_input, mock_ftp_class, ftp_scanner, capsys):
        """Test de la commande cat sans arguments"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        captured = capsys.readouterr()
        assert "Usage: cat" in captured.out
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['SITE CHMOD 755 file.txt', 'exit'])
    def test_interactive_shell_custom_command(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test d'une commande FTP personnalisée"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        mock_ftp.sendcmd.return_value = "200 CHMOD command successful"
        
        ftp_scanner.interactive_shell("user", "pass")
        
        mock_ftp.sendcmd.assert_called_with('SITE CHMOD 755 file.txt')
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['', 'exit'])
    def test_interactive_shell_empty_command(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test avec une commande vide"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=EOFError())
    def test_interactive_shell_eof(self, mock_input, mock_ftp_class, ftp_scanner):
        """Test avec EOF (Ctrl+D)"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        ftp_scanner.interactive_shell("user", "pass")
    
    @patch('ftplib.FTP')
    @patch('builtins.input', side_effect=['testuser', 'exit'])
    @patch('getpass.getpass', return_value='testpass')
    def test_interactive_shell_login_failure_then_retry(self, mock_getpass, mock_input, 
                                                        mock_ftp_class, ftp_scanner, capsys):
        """Test échec de login puis retry"""
        mock_ftp = MagicMock()
        mock_ftp_class.return_value = mock_ftp
        mock_ftp.pwd.return_value = "/"
        
        mock_ftp.login.side_effect = [
            ftplib.error_perm("530 Login incorrect"),
            None
        ]
        
        ftp_scanner.interactive_shell("anonymous", "anonymous")
        
        captured = capsys.readouterr()
        assert "Login échoué" in captured.out


class TestRunFTPScanner:
    """Tests pour la fonction run_ftp_scanner"""
    
    @pytest.fixture
    def mock_args_anon(self):
        """Args mock pour test anonyme"""
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "anon"
        args.user_list = None
        args.pass_list = None
        args.username = None
        args.password = None
        return args
    
    @pytest.fixture
    def mock_args_brute(self, tmp_path):
        """Args mock pour brute-force"""
        
        # Créer des fichiers temporaires
        user_file = tmp_path / "users.txt"
        user_file.write_text("admin\nroot\n")
        
        pass_file = tmp_path / "passwords.txt"
        pass_file.write_text("password\n123456\n")
        
        args = Mock()
        args.url = "192.168.1.100"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "brute"
        args.user_list = str(user_file)
        args.pass_list = str(pass_file)
        args.username = None
        args.password = None
        return args
    
    @pytest.fixture
    def mock_args_enum(self):
        """Args mock pour énumération"""
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 2121
        args.timeout = 15
        args.filter_mode = "enum"
        args.username = "testuser"
        args.password = "testpass"
        args.user_list = None
        args.pass_list = None
        return args
    
    @pytest.fixture
    def mock_args_shell(self):
        """Args mock pour shell interactif"""
        args = Mock()
        args.url = "ftp://ftp.example.com:2121"
        args.port = None
        args.filter_mode = "shell"
        args.username = "admin"
        args.password = "admin123"
        args.user_list = None
        args.pass_list = None
        return args
    
    @patch('tools.FTPGOAT.FTPGOAT.check_anonymous')
    def test_run_ftp_scanner_anon_mode(self, mock_check_anon, mock_args_anon, capsys):
        """Test du mode anonyme"""
        mock_check_anon.return_value = True
        
        run_ftp_scanner(mock_args_anon)
        
        mock_check_anon.assert_called_once()
        
        captured = capsys.readouterr()
        assert "SCANNER FTP FTPGOAT" in captured.out
    
    @patch('tools.FTPGOAT.FTPGOAT.brute_force')
    def test_run_ftp_scanner_brute_mode(self, mock_brute, mock_args_brute):
        """Test du mode brute-force avec fichiers"""
        mock_brute.return_value = [("admin", "password")]
        
        run_ftp_scanner(mock_args_brute)
        
        mock_brute.assert_called_once()
        # Vérifier que les listes sont lu
        users_arg = mock_brute.call_args[0][0]
        passwords_arg = mock_brute.call_args[0][1]
        
        assert "admin" in users_arg
        assert "root" in users_arg
        assert "password" in passwords_arg
        assert "123456" in passwords_arg
    
    @patch('tools.FTPGOAT.FTPGOAT.brute_force')
    def test_run_ftp_scanner_brute_single_credential(self, mock_brute):
        """Test brute-force avec credential unique"""
        args = Mock()
        args.url = "192.168.1.100"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "brute"
        args.user_list = None
        args.pass_list = None
        args.username = "admin"
        args.password = "password"
        
        mock_brute.return_value = []
        
        run_ftp_scanner(args)
        
        mock_brute.assert_called_once_with(["admin"], ["password"])
    
    @patch('tools.FTPGOAT.FTPGOAT.enumerate')
    def test_run_ftp_scanner_enum_mode(self, mock_enum, mock_args_enum):
        """Test du mode énumération"""
        run_ftp_scanner(mock_args_enum)
        
        mock_enum.assert_called_once_with("testuser", "testpass")
    
    @patch('tools.FTPGOAT.FTPGOAT.enumerate')
    def test_run_ftp_scanner_enum_mode_anonymous(self, mock_enum):
        """Test énumération avec anonymous"""
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "enum"
        args.username = None
        args.password = None
        args.user_list = None
        args.pass_list = None
        
        run_ftp_scanner(args)
        
        mock_enum.assert_called_once_with("anonymous", "anonymous")
    
    @patch('tools.FTPGOAT.FTPGOAT.interactive_shell')
    def test_run_ftp_scanner_shell_mode(self, mock_shell, mock_args_shell):
        """Test du mode shell"""
        run_ftp_scanner(mock_args_shell)
        
        mock_shell.assert_called_once_with("admin", "admin123")
    
    @patch('tools.FTPGOAT.FTPGOAT.check_anonymous')
    @patch('tools.FTPGOAT.FTPGOAT.brute_force')
    @patch('tools.FTPGOAT.FTPGOAT.enumerate')
    def test_run_ftp_scanner_all_mode(self, mock_enum, mock_brute, mock_anon, tmp_path):
        """Test du mode 'all'"""
        user_file = tmp_path / "users.txt"
        user_file.write_text("admin\n")
        pass_file = tmp_path / "passwords.txt"
        pass_file.write_text("password\n")
        
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "all"
        args.user_list = str(user_file)
        args.pass_list = str(pass_file)
        args.username = None
        args.password = None
        
        mock_anon.return_value = False
        mock_brute.return_value = []
        
        run_ftp_scanner(args)
        
        mock_anon.assert_called_once()
        mock_brute.assert_called_once()
        mock_enum.assert_called_once()
    
    def test_run_ftp_scanner_url_parsing(self, capsys):
        """Test du parsing d'URL"""
        args = Mock()
        args.url = "http://ftp.example.com:8080/path"
        args.port = None
        args.filter_mode = "anon"
        args.user_list = None
        args.pass_list = None
        args.username = None
        args.password = None
        
        with patch('tools.FTPGOAT.FTPGOAT.check_anonymous'):
            run_ftp_scanner(args)
        
    
    def test_run_ftp_scanner_brute_no_credentials(self, capsys):
        """Test brute-force sans credentials fournis"""
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "brute"
        args.user_list = None
        args.pass_list = None
        args.username = None
        args.password = None
        
        run_ftp_scanner(args)
        
        captured = capsys.readouterr()
        assert "spécifiez --user-list/--pass-list" in captured.out
    
    def test_run_ftp_scanner_brute_file_not_found(self, capsys):
        """Test brute-force avec fichier inexistant"""
        args = Mock()
        args.url = "ftp.example.com"
        args.port = 21
        args.timeout = 10
        args.filter_mode = "brute"
        args.user_list = "/nonexistent/users.txt"
        args.pass_list = "/nonexistent/passwords.txt"
        args.username = None
        args.password = None
        
        run_ftp_scanner(args)
        
        captured = capsys.readouterr()
        assert "fichier introuvable" in captured.out


