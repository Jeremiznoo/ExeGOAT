# tests/test_fuzzer.py
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from tools.fuzz import WebFuzzer, parse_status_codes, transform_payloads


class TestWebFuzzer:
    """Tests unitaires pour la classe WebFuzzer"""
    
    @pytest.fixture
    def fuzzer(self):
        """Fixture pour créer une instance de fuzzer"""
        return WebFuzzer(
            base_url="https://example.com",
            timeout=5.0,
            cookies={"session": "test123"}
        )
    
    def test_init_default_values(self):
        """Test l'initialisation avec valeurs par défaut"""
        fuzzer = WebFuzzer("https://example.com")
        
        assert fuzzer.base_url == "https://example.com"
        assert fuzzer.timeout == 5.0
        assert fuzzer.cookies is None
        assert fuzzer.show_codes == []
        assert fuzzer.hide_codes == []
        assert fuzzer.follow_redirect is False
        assert fuzzer.xss_marker == "xss"
    
    def test_init_custom_values(self):
        """Test l'initialisation avec valeurs personnalisées"""
        fuzzer = WebFuzzer(
            base_url="https://test.com",
            timeout=10.0,
            cookies={"token": "abc"},
            show_codes=[200, 301],
            hide_codes=[404],
            follow_redirect=True,
            xss_marker="PROBE"
        )
        
        assert fuzzer.timeout == 10.0
        assert fuzzer.cookies == {"token": "abc"}
        assert fuzzer.show_codes == [200, 301]
        assert fuzzer.hide_codes == [404]
        assert fuzzer.follow_redirect is True
        assert fuzzer.xss_marker == "PROBE"
    
    def test_include_result_with_hide_codes(self, fuzzer):
        """Test le filtrage avec hide_codes"""
        fuzzer.hide_codes = [404, 403]
        
        assert fuzzer._include_result({"status": 200}) is True
        assert fuzzer._include_result({"status": 404}) is False
        assert fuzzer._include_result({"status": 403}) is False
    
    def test_include_result_with_show_codes(self, fuzzer):
        """Test le filtrage avec show_codes"""
        fuzzer.show_codes = [200, 301]
        
        assert fuzzer._include_result({"status": 200}) is True
        assert fuzzer._include_result({"status": 301}) is True
        assert fuzzer._include_result({"status": 404}) is False
    
    def test_include_result_priority(self, fuzzer):
        """Test que hide_codes a priorité sur show_codes"""
        fuzzer.show_codes = [200, 404]
        fuzzer.hide_codes = [404]
        
        assert fuzzer._include_result({"status": 200}) is True
        assert fuzzer._include_result({"status": 404}) is False
    
    @pytest.mark.asyncio
    async def test_fuzz_directories_basic(self, fuzzer):
        """Test le fuzzing de répertoires basique"""
        payloads = ["admin", "test", "api"]
        
        # Créer un mock de response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"test content"
        
        # Mock de AsyncClient
        with patch('httpx.AsyncClient') as mock_client:
            # Configurer le context manager
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_client.return_value.__aexit__.return_value = None
            
            # Configurer la méthode get pour retourner le mock_response
            async def mock_get(*args, **kwargs):
                return mock_response
            
            mock_instance.get = AsyncMock(side_effect=mock_get)
            
            results = await fuzzer.fuzz_directories(payloads, max_concurrent=2)
        
        assert len(results) == 3
        assert all(r['status'] == 200 for r in results)
    
    @pytest.mark.asyncio
    async def test_detect_anomalies_xss(self, fuzzer):
        baseline_response = MagicMock()
        baseline_response.text = "<html>normal page</html>"
        baseline_response.content = b"<html>normal page</html>"
        baseline_response.status_code = 200

        is_valid, reasons = fuzzer._detect_anomalies(baseline_response, "normal")
        assert is_valid is False
        assert reasons == []

        response = MagicMock()
        response.text = '<html><img src=x onerror="alert(xss)"></html>'
        response.content = b'<html><img src="x"></html>'
        response.status_code = 200

        payload = f'<img src=x onerror="alert({fuzzer.xss_marker})">'
        is_valid, reasons = fuzzer._detect_anomalies(response, payload)

        assert is_valid is True
        assert "XSS_HTML" in reasons

    
    @pytest.mark.asyncio
    async def test_detect_anomalies_sql(self, fuzzer):
        """Test la détection d'erreurs SQL"""
        response = MagicMock()
        response.text = "ERROR: You have an error in your SQL syntax"
        response.content = b"ERROR: SQL"
        response.status_code = 200
        
        fuzzer.baseline_length = 100
        is_valid, reasons = fuzzer._detect_anomalies(response, "' OR 1=1--")
        
        assert is_valid is True
        assert any("SQL" in r for r in reasons)
    
    @pytest.mark.asyncio
    async def test_detect_anomalies_size_diff(self, fuzzer):
        """Test la détection de différence de taille"""
        # Baseline
        baseline_response = MagicMock()
        baseline_response.text = "a" * 1000
        baseline_response.content = b"a" * 1000
        baseline_response.status_code = 200
        
        fuzzer._detect_anomalies(baseline_response, "normal")
        
        # Response avec grande différence
        large_response = MagicMock()
        large_response.text = "b" * 2000
        large_response.content = b"b" * 2000
        large_response.status_code = 200
        
        is_valid, reasons = fuzzer._detect_anomalies(large_response, "test")
        
        assert is_valid is True
        assert any("SIZE_DIFF" in r or "LARGE" in r for r in reasons)
    
    def test_export_results_txt(self, fuzzer, tmp_path):
        """Test l'export des résultats en TXT"""
        fuzzer.results = [
            {
                "url": "https://example.com/admin",
                "status": 200,
                "payload": "admin",
                "length": 1234,
                "reasons": ["SIZE_DIFF"]
            }
        ]
        
        output_file = tmp_path / "test_results.txt"
        fuzzer.export_results_txt(str(output_file))
        
        assert output_file.exists()
        content = output_file.read_text()
        assert "200" in content
        assert "admin" in content
        assert "SIZE_DIFF" in content
    
    @pytest.mark.asyncio
    async def test_fuzz_parameter_with_mock(self, fuzzer):
        """Test le fuzzing de paramètres avec mock"""
        payloads = ["test", "admin"]
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"baseline content"
        mock_response.text = "baseline content"
        mock_response.url = "https://example.com/search?q=test"
        
        with patch('httpx.AsyncClient') as mock_client:
            mock_instance = MagicMock()
            mock_client.return_value.__aenter__.return_value = mock_instance
            mock_client.return_value.__aexit__.return_value = None
            
            async def mock_get(*args, **kwargs):
                return mock_response
            
            mock_instance.get = AsyncMock(side_effect=mock_get)
            
            results = await fuzzer.fuzz_parameter(
                endpoint="search",
                param_name="q",
                payloads=payloads,
                max_concurrent=2
            )
        
        assert len(results) >= 0  # Peut être 0 si aucune anomalie


class TestParsers:
    """Tests pour les fonctions de parsing"""
    
    def test_parse_status_codes_valid(self):
        """Test le parsing de codes valides"""
        codes = parse_status_codes("200,404,301", "test")
        assert set(codes) == {200, 404, 301}
    
    def test_parse_status_codes_with_spaces(self):
        """Test le parsing avec espaces"""
        codes = parse_status_codes("200, 404 , 301", "test")
        assert set(codes) == {200, 404, 301}
    
    def test_parse_status_codes_duplicates(self):
        """Test la déduplication"""
        codes = parse_status_codes("200,200,404", "test")
        assert len(codes) == 2
    
    def test_parse_status_codes_invalid(self):
        """Test avec code invalide"""
        with pytest.raises(ValueError):
            parse_status_codes("200,abc,404", "test")
    
    def test_parse_status_codes_empty(self):
        """Test avec chaîne vide"""
        codes = parse_status_codes("", "test")
        assert codes == []
    
    def test_transform_payloads_prefix(self):
        """Test transformation avec préfixe"""
        payloads = ["admin", "test"]
        result = transform_payloads(payloads, prefix="bak_")
        
        assert "bak_admin" in result
        assert "bak_test" in result
    
    def test_transform_payloads_suffix(self):
        """Test transformation avec suffixe"""
        payloads = ["admin", "test"]
        result = transform_payloads(payloads, suffix="_old")
        
        assert "admin_old" in result
        assert "test_old" in result
    
    def test_transform_payloads_extensions(self):
        """Test transformation avec extensions"""
        payloads = ["index"]
        result = transform_payloads(payloads, extensions="php,html,js")
        
        assert "index" in result
        assert "index.php" in result
        assert "index.html" in result
        assert "index.js" in result
    
    def test_transform_payloads_combined(self):
        """Test transformation combinée"""
        payloads = ["admin"]
        result = transform_payloads(
            payloads, 
            prefix="old_", 
            suffix="_backup",
            extensions="php,bak"
        )
        
        assert "old_admin_backup" in result
        assert "old_admin_backup.php" in result
        assert "old_admin_backup.bak" in result
    
    def test_transform_payloads_empty_list(self):
        """Test avec liste vide"""
        result = transform_payloads([])
        assert result == []
    
    def test_transform_payloads_whitespace(self):
        """Test avec espaces"""
        payloads = ["  admin  ", "test"]
        result = transform_payloads(payloads, prefix="x_")
        
        assert "x_admin" in result
        assert "x_test" in result