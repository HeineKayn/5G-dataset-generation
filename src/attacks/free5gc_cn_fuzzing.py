import random
from pathlib import Path

from .general_cn_fuzzing import GeneralCNFuzzing

"""
    To run this code you'll need to clone https://github.com/free5gc/openapi.git in the same parent folder than this project
"""

class Free5GCCNFuzzing(GeneralCNFuzzing):
    
    def __init__(self):
        self.api_source_folder = "../openapi"

    def sample_file(self,nf:str,k:int) -> list:
        """
            Return a list of random files that concern a certain nf
        """
        nf_file_name  = "N" + nf.lower()
        directory     = Path(self.api_source_folder)
        files         = directory.rglob('openapi.yaml')
        openapi_files = [str(file) for file in files if nf_file_name in str(file)]
        k = min(k,len(openapi_files))
        return random.sample(openapi_files,k)