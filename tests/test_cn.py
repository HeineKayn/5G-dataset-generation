from src import *

def test_manipulation():
    code, _ = ping_nf("NRF")
    assert 200 <= code < 300
    
    nf_instance_id = generate_variables("uuid")
    code, _ = add_nf(nf_instance_id, "AMF", display=False)
    assert 200 <= code < 300
    
    token = get_token(nf_instance_id, "AMF", "nnrf-disc", "NRF", display=False)
    assert len(token) > 0
    
    code, _ = remove_nf(nf_instance_id, token)
    assert 200 <= code < 300