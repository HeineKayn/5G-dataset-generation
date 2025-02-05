import yaml
import uuid
import base64
import datetime
import random
import exrex
import re
import os

SOURCE_FOLDER = "../5GC_APIs"

def extract_ref(original_file, ref):
    file,path = ref.split("#")
    if not file : file = original_file

    file_path = f"{SOURCE_FOLDER}/{file}"
    with open(file_path, 'r', encoding='utf-8') as file:
        yaml_content = yaml.safe_load(file)

    keys = path.strip("/").split("/")
    for key in keys:
        yaml_content = yaml_content[key]
    return yaml_content  

def replace_refs_recursively(file,d):
    
    for key in d.copy().keys():

        if isinstance(d[key], dict):
            replace_refs_recursively(file,d[key])

        if key == "$ref" :

            try:
                extracted_ref = extract_ref(file,d[key])
                d.update(extracted_ref)
                del d[key]
            except:
                print(f"Can't find {d[key]}") 
        
def generate_variables(ptype):
    values = {
        "uuid": str(uuid.uuid4()),  # UUID format
        "binary": base64.b64encode(bytes(random.getrandbits(8) for _ in range(10))).decode("utf-8") if random.choice([True, False]) else None,  # Binary string or None
        "bytes": base64.b64encode(bytes(random.getrandbits(8) for _ in range(10))).decode("utf-8"),  # Byte string
        "string": ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=10)),  # Random string of length 10
        "date": datetime.date.today().isoformat(),  # Current date in ISO 8601 format
        "date-time": datetime.datetime.now().isoformat(),  # Current datetime in ISO 8601 format
        "float": random.uniform(0, 1e6),  # Random positive float
        "double": random.uniform(0, 1e12),  # Random positive double (in Python, float is double precision)
        "integer": random.randint(0, 2**31 - 1),  # Random positive int32
        "int32": random.randint(0, 2**31 - 1),  # Random positive int32
        "int64": random.randint(0, 2**63 - 1),  # Random positive int64
        "boolean" : random.choice([True,False]),
        "array": [random.randint(0, 100) for _ in range(random.randint(1, 10))],  # Tableau de 1 à 10 entiers

    }
    if ptype in values : 
        return values[ptype]
    else : 
        return f"<{ptype}>"
    
def schema_extractor(schema):
    if 'anyOf' in schema:
        schema = random.choice(schema["anyOf"]) 

    value = ""

    # A dict can have 3 at the same time and the most important will be the last
    if 'type' in schema:
        value = generate_variables(schema["type"])
    if 'format' in schema:
        value = generate_variables(schema["format"])
    if 'pattern' in schema:
        value = exrex.getone(schema["pattern"]) # '^[0-9]{5,6}-(x3Lf57A:nid=[A-Fa-f0-9]{11}:)$'
    if "enum" in schema:
        value = random.choice(schema["enum"])  

    if not value : print("UNRECOGNIZED SCHEMA",schema)

    return re.sub(r"[^a-zA-Z0-9\-_]", "", str(value)) # remove all character except number, letter and - _

def extract_parameters(parameters, uri, file, only_required):

    param_extracted = {}
    for parameter in parameters:
            
        if ("required" in parameter and parameter["required"]) or not only_required:

            counter = 0
            while "$ref" in str(parameter) and counter <= 3:  # Continue jusqu'à ce qu'il n'y ait plus de $ref
                replace_refs_recursively(file, parameter)
                counter += 1

            if "name" not in parameter : print(parameter)
            pname = parameter["name"]

            if "schema" in parameter : 
                schema = parameter["schema"]

                if parameter["in"] not in param_extracted:
                    param_extracted[parameter["in"]] = {}
                param_extracted[parameter["in"]][pname] = schema_extractor(schema)

    new_uri = uri

    if "path" in param_extracted : 
        new_uri = uri.format(**param_extracted["path"])
        del param_extracted["path"]

    if "query" in param_extracted : 
        queries = [f"{key}={value}" for key, value in param_extracted["query"].items()]
        new_uri += "?" + "&".join(queries)
        del param_extracted["query"]

    header = param_extracted["header"] if "header" in param_extracted else {}
    return new_uri, header

def extract_body(body, file, only_required):

    body_extracted = {}
    for accept,parameter in body.items():
        counter = 0
        while "$ref" in str(parameter) and counter <= 3:  # Continue jusqu'à ce qu'il n'y ait plus de $ref
            replace_refs_recursively(file, parameter)
            counter += 1

        if "schema" in parameter : 
            schema = parameter["schema"]
            for property, property_desc in schema["properties"].items():

                if not "required" in schema or ("required" in schema and property in schema["required"]) or not only_required:
                    value = schema_extractor(property_desc)
                    body_extracted[property] = value

        return accept, body_extracted
