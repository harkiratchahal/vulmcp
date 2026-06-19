from vulnixmcp.scanner import is_ip_public, identify_ai_components

def test_is_ip_public():
    assert is_ip_public("8.8.8.8") is True
    assert is_ip_public("192.168.1.1") is False
    assert is_ip_public("10.0.0.1") is False

def test_identify_ai_components():
    services = [
        {"port": 11434, "protocol": "tcp", "state": "open", "service": "ollama", "version": "0.1.32", "product": "Ollama", "target": "10.0.0.1"}
    ]
    enriched = identify_ai_components(services)
    assert len(enriched) == 1
    assert enriched[0]["component_name"] == "ollama"
    assert enriched[0]["is_public"] is False
