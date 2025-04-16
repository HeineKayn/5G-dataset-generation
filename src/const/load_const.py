import yaml 

# Get the IP list of the CN components
with open("./src/const/addresses.yaml", 'r', encoding='utf-8') as file:
    ip_list = yaml.safe_load(file)