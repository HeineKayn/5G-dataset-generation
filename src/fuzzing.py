import yaml
import uuid
import base64
import datetime
import random
import exrex
import re
import os

SOURCE_FOLDER = "../5GC_APIs"

def extract_ref(original_file:str, ref:str):
    """
        Sometimes the data in the yaml point to a ref (location in a file). 
        - Can be in the same file : #/components/schemas/AmfCreateEventSubscription
        - Or in a different one : TS29571_CommonData.yaml#/components/responses/307\n
    """

    # If file is empty the ref is in the same file
    file,path = ref.split("#")
    if not file : file = original_file

    # Read the content
    file_path = f"{SOURCE_FOLDER}/{file}"
    with open(file_path, 'r', encoding='utf-8') as file:
        yaml_content = yaml.safe_load(file)

    # Travel the yaml_content to the location
    # (What's after the # is the path to the location)
    steps = path.strip("/").split("/")
    for step in steps:
        yaml_content = yaml_content[step]
    return yaml_content  

def replace_refs_recursively(file:str,yaml_content:dict):
    """
       Recursively parses a dictionary and replaces all the $ref keys with their actual values.
        Args:
            file (str): The path to the YAML file being processed.
            yaml_content (dict): The dictionary content of the YAML file.
        Raises:
            Exception: If the reference cannot be replaced, an exception is raised.
    """
    
    for key in yaml_content.copy().keys():

        # Depth first
        value = yaml_content[key]
        if isinstance(value, dict):
            replace_refs_recursively(file,value)

        if key == "$ref" :

            # Try to replace the ref (path of data) by the actual value
            try:
                extracted_ref = extract_ref(file,value)
                yaml_content.update(extracted_ref)
                del value
            except:
                ref_file,path = value.split("#")
                if not ref_file : ref_file = file
                # print(f"Can't find {SOURCE_FOLDER}/{ref_file}{path}") 
        
def generate_variables(ptype:str)-> str|int|float|bool|list|None:
    """
    Generate a variable of a specified type with random or default values.
    Args:
        ptype (str): The type of variable to generate. Supported types include:
            - "uuid": A random UUID string.
            - "binary": A base64-encoded binary string or None.
            - "bytes": A base64-encoded byte string.
            - "string": A random string of length 10.
            - "date": The current date in ISO 8601 format.
            - "date-time": The current datetime in ISO 8601 format.
            - "float": A random positive float.
            - "double": A random positive double.
            - "integer": A random positive int32.
            - "int32": A random positive int32.
            - "int64": A random positive int64.
            - "boolean": A random boolean value.
            - "array": An array of 1 to 10 random integers.
    Returns:
        Union[str, int, float, bool, list, None]: The generated variable of the specified type.
        If the specified type is not supported, returns a string in the format "<ptype>".
    """

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
    
def schema_extractor(schema:str)-> str:

    """
        For every parameter we create a value that correspond to its schema\n
        Example of a schema :
        ```
        parameters:
            - name: nf-type
            in: query
            description: Type of NF
            required: true
            schema:
                $ref: '#/components/schemas/NFType'
            - name: limit
            in: header
            description: How many items to return at one time
            required: false
            schema:
                type: integer
                minimum: 1
        ```
    """

    value    = ""
    var_type = None

    # Sometimes the schema is a list of possible schema
    if 'anyOf' in schema:
        # Use enum in priority if possible 
        for i,schema_type in enumerate(schema["anyOf"]):
            if "enum" in schema_type:
                var_type =  schema["anyOf"][i]
                break
        # If no enum we take a random one
        if not var_type : 
            var_type = random.choice(schema) 
    else : 
        var_type = schema

    # Generate the value corresponding to the schema
    if 'type' in var_type:
        value = generate_variables(var_type["type"])
    if 'format' in var_type:
        value = generate_variables(var_type["format"])
    if 'pattern' in var_type:
        value = exrex.getone(var_type["pattern"])
    if "enum" in var_type:
        value = random.choice(var_type["enum"])  

    if not value : print("UNRECOGNIZED SCHEMA", var_type)
    return re.sub(r"[^a-zA-Z0-9\-_]", "", str(value)) # remove all character except number, letter and - _

def extract_parameters(parameters:dict, uri:str, file:str, only_required:bool) -> tuple[str,dict]:
    """
    Extracts and formats parameters from a given dictionary and URI.
    Args:
        parameters (dict): A dictionary containing parameter definitions.
        uri (str): The URI to be formatted with the extracted parameters.
        file (str): The file path to resolve references from.
        only_required (bool): If True, only required parameters are extracted.
    Returns:
        tuple[str, dict]: A tuple containing the formatted URI and a dictionary of headers.
    The function performs the following steps:
    1. Iterates over the parameters and resolves any references.
    2. Extracts required parameters or all parameters based on the `only_required` flag.
    3. Formats the URI with path parameters.
    4. Appends query parameters to the URI.
    5. Returns the formatted URI and any remaining parameters as headers.
    """

    param_extracted = {}
    for parameter in parameters:
            
        # If the parameter is a reference we replace it by the actual value
        if "$ref" in str(parameter):
            counter = 0
            # Repeat maximum 3 times
            while "$ref" in str(parameter) and counter <= 3: 
                replace_refs_recursively(file, parameter)
                counter += 1

        # For every parameter that is required
        if ("required" in parameter and parameter["required"]) or not only_required:

            pname = parameter["name"]
            if "schema" in parameter : 
                schema = parameter["schema"]

                # "in" represent the place where we need to put the variable
                # here we just put the new variable in a dict, with the "in" value as the key
                if parameter["in"] not in param_extracted:
                    param_extracted[parameter["in"]] = {}
                param_extracted[parameter["in"]][pname] = schema_extractor(schema)

    new_uri = uri

    # For parameters "in" path we format the uri with the value   
    if "path" in param_extracted : 
        new_uri = uri.format(**param_extracted["path"])
        del param_extracted["path"]

    # For parameters "in" query we add the value to the uri separated by ? and &
    if "query" in param_extracted : 
        queries = [f"{key}={value}" for key, value in param_extracted["query"].items()]
        new_uri += "?" + "&".join(queries)
        del param_extracted["query"]

    # The rest is in the header so we return it
    header = param_extracted["header"] if "header" in param_extracted else {}
    return new_uri, header

def extract_body(body:dict, file:str, only_required:bool) -> tuple[str,dict]:

    """
        Same that extract_parameters but for the requestBody 
    """

    body_extracted = {}
    for accept,parameter in body.items():
        counter = 0
        # Repeat maximum 3 times
        while "$ref" in str(parameter) and counter <= 3: 
            replace_refs_recursively(file, parameter)
            counter += 1

        if "schema" in parameter : 
            schema = parameter["schema"]
            if "properties" in schema:
                for property, property_desc in schema["properties"].items():
                    if not "required" in schema or ("required" in schema and property in schema["required"]) or not only_required:
                        value = schema_extractor(property_desc)
                        body_extracted[property] = value

        return accept, body_extracted
