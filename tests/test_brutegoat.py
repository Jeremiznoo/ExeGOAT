# tests/test_brutegoat.py
import pytest
from unittest.mock import Mock, patch, MagicMock, create_autospec
import socket
import queue
import sys
from tools.BruteGOAT import (
    BruteModule, SSHBrute, FTPBrute, BruteForcer, run_brutegoat
)


class TestBruteModule:
    """Tests pour la classe abstraite BruteModule"""
    
    def test_cannot_instantiate_abstract_class(self):
        """Test qu'on ne peut pas instancier BruteModule directement"""
        with pytest.raises(TypeError):
            BruteModule("localhost", 22)
    
    def test_subclass_must_implement_attempt_login(self):
        """Test que les sous-classes doivent implémenter attempt_login"""
        class IncompleteBrute(BruteModule):
            pass
        
        with pytest.raises(TypeError):
            IncompleteBrute("localhost", 22)


class TestSSHBrute:
    """Tests pour le module SSH"""
    
    @pytest.fixture
    def ssh_brute(self):
        """Fixture pour créer une instance SSHBrute"""
        return SSHBrute("192.168.1.100", 22, timeout=5)
    
    def test_init(self, ssh_brute):
        """Test l'initialisation de SSHBrute"""
        assert ssh_brute.target == "192.168.1.100"
        assert ssh_brute.port == 22
        assert ssh_brute.timeout == 5
    
    def test_init_custom_timeout(self):
        """Test avec timeout personnalisé"""
        brute = SSHBrute("localhost", 2222, timeout=10)
        assert brute.timeout == 10
    
    @patch('tools.BruteGOAT.paramiko_available', False)
    def test_attempt_login_no_paramiko(self, ssh_brute):
        """Test quand paramiko n'est pas disponible"""
        result = ssh_brute.attempt_login("admin", "password")
        assert result is False
    
    def test_attempt_login_success(self, ssh_brute):
        """Test une connexion SSH réussie"""
        # Mock paramiko avant de l'utiliser
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        
        # Patcher paramiko_available ET le module paramiko
        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                # Simuler une connexion réussie
                mock_ssh_client.connect.return_value = None
                
                result = ssh_brute.attempt_login("admin", "password")
                
                assert result is True
                mock_ssh_client.connect.assert_called_once()
                assert mock_ssh_client.close.call_count >= 1
    
    def test_attempt_login_auth_failure(self, ssh_brute):
        """Test un échec d'authentification SSH"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()

        # Vraie classe d'exception
        mock_paramiko.AuthenticationException = type(
            'AuthenticationException',
            (Exception,),
            {}
        )

        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                mock_ssh_client.connect.side_effect = mock_paramiko.AuthenticationException()

                result = ssh_brute.attempt_login("admin", "wrongpass")

                assert result is False
                mock_ssh_client.close.assert_called()
    
    def test_attempt_login_network_error(self, ssh_brute):
        """Test une erreur réseau"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.AuthenticationException = type(
            'AuthenticationException',
            (Exception,),
            {}
        )

        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                mock_ssh_client.connect.side_effect = socket.error("Connection refused")

                result = ssh_brute.attempt_login("admin", "password")

                assert result is False
                mock_ssh_client.close.assert_called()

        
    def test_attempt_login_generic_exception(self, ssh_brute):
        """Test une exception générique"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_paramiko.AuthenticationException = type(
            'AuthenticationException',
            (Exception,),
            {}
        )

        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                mock_ssh_client.connect.side_effect = Exception("Unknown error")

                result = ssh_brute.attempt_login("admin", "password")

                assert result is False
                mock_ssh_client.close.assert_called()


class TestFTPBrute:
    """Tests pour le module FTP"""
    
    @pytest.fixture
    def ftp_brute(self):
        """Fixture pour créer une instance FTPBrute"""
        return FTPBrute("192.168.1.100", 21, timeout=5)
    
    def test_init(self, ftp_brute):
        """Test l'initialisation de FTPBrute"""
        assert ftp_brute.target == "192.168.1.100"
        assert ftp_brute.port == 21
        assert ftp_brute.timeout == 5
    
    @patch('ftplib.FTP')
    def test_attempt_login_success(self, mock_ftp, ftp_brute):
        """Test une connexion FTP réussie"""
        mock_ftp_instance = MagicMock()
        mock_ftp.return_value = mock_ftp_instance
        
        mock_ftp_instance.connect.return_value = None
        mock_ftp_instance.login.return_value = None
        
        result = ftp_brute.attempt_login("admin", "password")
        
        assert result is True
        mock_ftp_instance.connect.assert_called_once_with(
            "192.168.1.100", 21, timeout=5
        )
        mock_ftp_instance.login.assert_called_once_with("admin", "password")
        mock_ftp_instance.quit.assert_called_once()
    
    @patch('ftplib.FTP')
    def test_attempt_login_failure(self, mock_ftp, ftp_brute):
        """Test un échec d'authentification FTP"""
        import ftplib
        mock_ftp_instance = MagicMock()
        mock_ftp.return_value = mock_ftp_instance
        mock_ftp_instance.login.side_effect = ftplib.error_perm("530 Login incorrect")
        
        result = ftp_brute.attempt_login("admin", "wrongpass")
        
        assert result is False
    
    @patch('ftplib.FTP')
    def test_attempt_login_connection_error(self, mock_ftp, ftp_brute):
        """Test une erreur de connexion FTP"""
        import ftplib
        mock_ftp_instance = MagicMock()
        mock_ftp.return_value = mock_ftp_instance
        mock_ftp_instance.connect.side_effect = ftplib.error_temp("Connection refused")
        
        result = ftp_brute.attempt_login("admin", "password")
        
        assert result is False


class TestBruteForcer:
    """Tests pour le moteur de brute-force"""
    
    @pytest.fixture
    def basic_users(self):
        return ["admin", "root", "user"]
    
    @pytest.fixture
    def basic_passwords(self):
        return ["password", "123456", "admin"]
    
    @patch('tools.BruteGOAT.paramiko_available', True)
    def test_init_ssh(self, basic_users, basic_passwords):
        """Test l'initialisation pour SSH"""
        bruter = BruteForcer(
            service="ssh",
            target="192.168.1.100",
            port=22,
            user_list=basic_users,
            pass_list=basic_passwords,
            threads=5
        )
        
        assert bruter.service == "ssh"
        assert bruter.target == "192.168.1.100"
        assert bruter.port == 22
        assert bruter.user_list == basic_users
        assert bruter.pass_list == basic_passwords
        assert bruter.threads == 5
        assert bruter.module_class == SSHBrute
    
    def test_init_ftp(self, basic_users, basic_passwords):
        """Test l'initialisation pour FTP"""
        bruter = BruteForcer(
            service="ftp",
            target="192.168.1.100",
            port=21,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        assert bruter.service == "ftp"
        assert bruter.module_class == FTPBrute
    
    @patch('tools.BruteGOAT.paramiko_available', True)
    def test_init_default_ssh_port(self, basic_users, basic_passwords):
        """Test que le port SSH par défaut est 22"""
        bruter = BruteForcer(
            service="ssh",
            target="192.168.1.100",
            port=None,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        assert bruter.port == 22
    
    def test_init_default_ftp_port(self, basic_users, basic_passwords):
        """Test que le port FTP par défaut est 21"""
        bruter = BruteForcer(
            service="ftp",
            target="192.168.1.100",
            port=None,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        assert bruter.port == 21
    
    def test_init_unsupported_service(self, basic_users, basic_passwords):
        """Test avec un service non supporté"""
        bruter = BruteForcer(
            service="telnet",
            target="192.168.1.100",
            port=23,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        assert bruter.module_class is None
    
    @patch('tools.BruteGOAT.paramiko_available', False)
    def test_init_ssh_without_paramiko(self, basic_users, basic_passwords, capsys):
        """Test SSH sans paramiko installé"""
        bruter = BruteForcer(
            service="ssh",
            target="192.168.1.100",
            port=22,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        captured = capsys.readouterr()
        assert "Module SSH non disponible" in captured.out
        assert bruter.module_class is None
    
    def test_run_success(self, basic_users, basic_passwords, capsys):
        """Test un run avec succès"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        
        call_count = [0]
        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                return None
            raise Exception("Auth failed")
        
        mock_ssh_client.connect.side_effect = side_effect
        
        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                bruter = BruteForcer(
                    service="ssh",
                    target="192.168.1.100",
                    port=22,
                    user_list=basic_users[:2],
                    pass_list=basic_passwords[:2],
                    threads=1,
                    stop_on_success=True
                )
                
                bruter.run()
        
        assert len(bruter.found) >= 1
    
    def test_run_no_module(self, basic_users, basic_passwords):
        """Test run sans module valide"""
        bruter = BruteForcer(
            service="invalid",
            target="192.168.1.100",
            port=22,
            user_list=basic_users,
            pass_list=basic_passwords
        )
        
        bruter.run()
        assert bruter.found == []
    
    def test_stop_on_success(self, basic_users, basic_passwords):
        """Test que stop_on_success arrête bien le brute-force"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_ssh_client.connect.return_value = None
        
        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                bruter = BruteForcer(
                    service="ssh",
                    target="192.168.1.100",
                    port=22,
                    user_list=basic_users[:2],
                    pass_list=basic_passwords[:2],
                    threads=1,
                    stop_on_success=True
                )
                
                bruter.run()
        
        assert len(bruter.found) >= 1


class TestRunBrutegoat:
    """Tests pour la fonction run_brutegoat"""
    
    @pytest.fixture
    def mock_args_ssh(self):
        """Args mock pour SSH"""
        args = Mock()
        args.username = "admin"
        args.user_list = None
        args.password = "password123"
        args.pass_list = None
        args.url = "ssh://192.168.1.100"
        args.service = None
        args.port = None
        args.threads = 10
        return args
    
    @pytest.fixture
    def mock_args_with_files(self, tmp_path):
        """Args mock avec fichiers"""
        user_file = tmp_path / "users.txt"
        user_file.write_text("admin\nroot\nuser\n")
        
        pass_file = tmp_path / "passwords.txt"
        pass_file.write_text("password\n123456\nadmin\n")
        
        args = Mock()
        args.username = None
        args.user_list = str(user_file)
        args.password = None
        args.pass_list = str(pass_file)
        args.url = "192.168.1.100"
        args.service = "ssh"
        args.port = 22
        args.threads = 5
        return args
    
    def test_run_brutegoat_basic(self, mock_args_ssh):
        """Test run_brutegoat basique"""
        with patch('tools.BruteGOAT.BruteForcer.run') as mock_run:
            with patch('tools.BruteGOAT.paramiko_available', True):
                run_brutegoat(mock_args_ssh)
                mock_run.assert_called_once()
    
    def test_run_brutegoat_with_files(self, mock_args_with_files):
        """Test avec fichiers de wordlists"""
        with patch('tools.BruteGOAT.BruteForcer.run') as mock_run:
            with patch('tools.BruteGOAT.paramiko_available', True):
                run_brutegoat(mock_args_with_files)
                mock_run.assert_called_once()
    
    def test_run_brutegoat_missing_users(self, capsys):
        """Test sans utilisateurs"""
        args = Mock()
        args.username = None
        args.user_list = None
        args.password = "password"
        args.pass_list = None
        args.url = "192.168.1.100"
        args.service = "ssh"
        args.port = 22
        args.threads = 10
        
        run_brutegoat(args)
        
        captured = capsys.readouterr()
        assert "manque des utilisateurs" in captured.out
    
    def test_run_brutegoat_missing_passwords(self, capsys):
        """Test sans mots de passe"""
        args = Mock()
        args.username = "admin"
        args.user_list = None
        args.password = None
        args.pass_list = None
        args.url = "192.168.1.100"
        args.service = "ssh"
        args.port = 22
        args.threads = 10
        
        run_brutegoat(args)
        
        captured = capsys.readouterr()
        assert "manque des utilisateurs ou des mots de passe" in captured.out
    
    def test_run_brutegoat_file_not_found(self, capsys):
        """Test avec fichier inexistant"""
        args = Mock()
        args.username = None
        args.user_list = "/path/to/nonexistent/users.txt"
        args.password = "password"
        args.pass_list = None
        args.url = "192.168.1.100"
        args.service = "ssh"
        args.port = 22
        args.threads = 10
        
        run_brutegoat(args)
        
        captured = capsys.readouterr()
        assert "introuvable" in captured.out
    
    def test_run_brutegoat_parse_ssh_url(self):
        """Test parsing d'URL SSH"""
        args = Mock()
        args.username = "admin"
        args.user_list = None
        args.password = "password"
        args.pass_list = None
        args.url = "ssh://192.168.1.100:2222"
        args.service = None
        args.port = None
        args.threads = 10
        
        with patch('tools.BruteGOAT.BruteForcer.run') as mock_run:
            with patch('tools.BruteGOAT.paramiko_available', True):
                run_brutegoat(args)
                mock_run.assert_called_once()
    
    def test_run_brutegoat_parse_ftp_url(self):
        """Test parsing d'URL FTP"""
        args = Mock()
        args.username = "admin"
        args.user_list = None
        args.password = "password"
        args.pass_list = None
        args.url = "ftp://ftp.example.com"
        args.service = None
        args.port = None
        args.threads = 10
        
        with patch('tools.BruteGOAT.BruteForcer.run') as mock_run:
            run_brutegoat(args)
            mock_run.assert_called_once()
    
    def test_run_brutegoat_no_service(self, capsys):
        """Test sans service spécifié"""
        args = Mock()
        args.username = "admin"
        args.user_list = None
        args.password = "password"
        args.pass_list = None
        args.url = "192.168.1.100"
        args.service = None
        args.port = 22
        args.threads = 10
        
        run_brutegoat(args)
        
        captured = capsys.readouterr()
        assert "Aucun service spécifié" in captured.out


class TestThreadSafety:
    """Tests de sécurité des threads"""
    
    def test_concurrent_access_to_found_list(self):
        """Test l'accès concurrent à la liste found"""
        mock_paramiko = MagicMock()
        mock_ssh_client = MagicMock()
        mock_paramiko.SSHClient.return_value = mock_ssh_client
        mock_paramiko.AutoAddPolicy.return_value = MagicMock()
        mock_ssh_client.connect.return_value = None
        
        with patch('tools.BruteGOAT.paramiko_available', True):
            with patch('tools.BruteGOAT.paramiko', mock_paramiko):
                bruter = BruteForcer(
                    service="ssh",
                    target="192.168.1.100",
                    port=22,
                    user_list=["user1", "user2", "user3"],
                    pass_list=["pass1", "pass2"],
                    threads=3,
                    stop_on_success=False
                )
                
                bruter.run()
        
        assert len(bruter.found) == 6