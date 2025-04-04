import yaml
from src import *

def test_extract_parameters():
    
    fuzzer = GeneralCNFuzzing()

    file_path = f"{fuzzer.api_source_folder}/TS29510_Nnrf_NFManagement.yaml"
    with open(file_path, 'r', encoding='utf-8') as f:
        yaml_content = yaml.safe_load(f)
        paths  = yaml_content["paths"]

    # ----- With everything (headers and uri)
    uri    = "/nf-instances/{nfInstanceID}"
    method = "put"
    
    new_uri, header = fuzzer.extract_parameters(paths[uri][method]['parameters'], uri, file_path, False)

    # New_uri should look like /nf-instances/40bc80c8-3054-4318-8e98-e99b84f115b7
    # print(new_uri)
    assert new_uri != uri and len(new_uri) == 50
    assert len(header) == 2

    # ----- Without the non-mandatory (headers and uri)
    new_uri, header = fuzzer.extract_parameters(paths[uri][method]['parameters'], uri, file_path, True)
    assert len(header) == 0

    # ----- With parameters in request
    uri    = "/nf-instances"
    method = "get"
    new_uri, header = fuzzer.extract_parameters(paths[uri][method]['parameters'], uri, file_path, False)
    # New_uri should look like /nf-instances?nf-type=zkQWwoOSMf&limit=347876863&page-number=1437820234&page-size=89580458
    assert new_uri != uri and len(new_uri) > 30
    assert len(header) == 0

    # ----- With $ref to replace
    file_path = "../5GC_APIs/TS29510_Nnrf_NFDiscovery.yaml"
    with open(file_path, 'r', encoding='utf-8') as f:
        yaml_content = yaml.safe_load(f)
        paths  = yaml_content["paths"]

    uri    = "/searches/{searchId}"
    method = "get"
    new_uri, header = fuzzer.extract_parameters(paths[uri][method]['parameters'], uri, file_path, False)
    # New uri should look like /searches/CxpKdmkzIo
    assert "{" not in new_uri
    
# def test_fuzz():
#     results = general_fuzz(nb_file=1,nb_url=1,nb_ite=1,nb_method=1,nf_list=["NRF"],only_required=True,display=False)
#     assert len(results) == 1