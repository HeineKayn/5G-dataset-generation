import yaml 

# Get the IP list of the CN components
file_path = "./src/const/addresses.yaml"
with open(file_path, 'r', encoding='utf-8') as file:
    ip_list = yaml.safe_load(file)
    
from .const import *
from .common import *
from .attacks import *
from .setup_plateform import *
from .victims import *