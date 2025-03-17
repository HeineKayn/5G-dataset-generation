from src import *

def test_manipulation():
    """
        CN neeed to be up and running
        One UE need to be registered with supi = imsi-208930000000001
    """
    
    # Ping NRF 
    code, _ = ping_nf("NRF", display=False)
    assert 200 <= code < 300
    
    # Add instance
    nf_instance_id = generate_variables("uuid")
    code, _ = add_nf(nf_instance_id, "AMF", display=False)
    assert 200 <= code < 300
    
    # Create token 
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)
    assert len(token) > 0
    
    # Find a UDM instance
    code, infos = get_nf_info("AMF", token, "UDM", display=False)
    assert 200 <= code < 300
    assert len(infos) > 0
    
    supi = "imsi-208930000000001"
    code, infos = get_user_data(supi, token, display=True)
    assert 200 <= code < 300
    assert len(infos) < 0
    
    # Remove instance
    code, _ = remove_nf(nf_instance_id, token, display=False)
    assert 200 <= code < 300