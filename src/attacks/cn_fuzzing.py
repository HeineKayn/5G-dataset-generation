import yaml
import random
import exrex
import re
import os

from src import *

API_SOURCE_FOLDER = "../5GC_APIs"

def _extract_ref(original_file:str, ref:str):
    """
        Sometimes the data in the yaml point to a ref (location in a file). 
        - Can be in the same file : #/components/schemas/AmfCreateEventSubscription
        - Or in a different one : TS29571_CommonData.yaml#/components/responses/307\n
    """

    # If file is empty the ref is in the same file
    file,path = ref.split("#")
    if not file : file = original_file

    # Read the content
    file_path = f"{API_SOURCE_FOLDER}/{file}"
    with open(file_path, 'r', encoding='utf-8') as file:
        yaml_content = yaml.safe_load(file)

    # Travel the yaml_content to the location
    # (What's after the # is the path to the location)
    steps = path.strip("/").split("/")
    for step in steps:
        yaml_content = yaml_content[step]
    return yaml_content  

def _replace_refs_recursively(file:str,yaml_content:dict):
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
            _replace_refs_recursively(file,value)

        if key == "$ref" :

            # Try to replace the ref (path of data) by the actual value
            try:
                extracted_ref = _extract_ref(file,value)
                yaml_content.update(extracted_ref)
                del value
            except:
                ref_file,path = value.split("#")
                if not ref_file : ref_file = file
                # print(f"Can't find {API_SOURCE_FOLDER}/{ref_file}{path}") 
         
def _schema_extractor(schema:str)-> str:

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

def extract_parameters(parameters:dict, uri:str, file:str, only_required:bool):
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
        counter = 0
        # Repeat maximum 3 times
        while "$ref" in str(parameter) and counter <= 3: 
            _replace_refs_recursively(file, parameter)
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
                param_extracted[parameter["in"]][pname] = _schema_extractor(schema)

    new_url = uri

    # For parameters "in" path we format the uri with the value   
    if "path" in param_extracted : 
        new_url = uri.format(**param_extracted["path"])
        del param_extracted["path"]

    # For parameters "in" query we add the value to the uri separated by ? and &
    if "query" in param_extracted : 
        queries = [f"{key}={value}" for key, value in param_extracted["query"].items()]
        new_url += "?" + "&".join(queries)
        del param_extracted["query"]

    # The rest is in the header so we return it
    header = param_extracted["header"] if "header" in param_extracted else {}
    return new_url, header

def _extract_body(body:dict, file:str, only_required:bool):

    """
        Same that extract_parameters but for the requestBody 
    """

    body_extracted = {}
    for accept,parameter in body.items():
        counter = 0
        # Repeat maximum 3 times
        while "$ref" in str(parameter) and counter <= 3: 
            _replace_refs_recursively(file, parameter)
            counter += 1

        if "schema" in parameter : 
            schema = parameter["schema"]
            if "properties" in schema:
                for property, property_desc in schema["properties"].items():
                    if not "required" in schema or ("required" in schema and property in schema["required"]) or not only_required:
                        value = _schema_extractor(property_desc)
                        body_extracted[property] = value

        return accept, body_extracted

def _sample_file(nf:str,k:int) -> list:
    """
        Return a list of random files that concern a certain nf
    """
    nf_file_name = "N" + nf.lower()
    files = [f for f in os.listdir(API_SOURCE_FOLDER) if nf_file_name in f]
    k = min(k,len(files))
    return random.sample(files,k)

def _get_spec(file:str):
    """
        Read a yaml file and return its content
    """
    file_path = f"{API_SOURCE_FOLDER}/{file}"
    with open(file_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)
        
def _sample_url(api_spec,k:int):
    """
        Parse a yaml file, get the available paths and return a list of random urls
    """
    paths = api_spec["paths"]
    urls  = list(paths.keys())
    k = min(k,len(urls))
    return random.sample(urls,k)

def _sample_method(api_spec, url:str, k:int):
    """
        Parse a yaml file, get the available method for a given url and return a list of random methods
    """
    paths = api_spec["paths"]
    methods = list(paths[url].keys())
    k = min(k,len(methods))
    return random.sample(methods,k)

def _setup_fuzzer(api_spec, nf:str, display:bool=True) -> str:
    
    """
        Create a nf and get a token with a scope depending on the need expressed in the api specification
        Return a token if success else an empty string
    """

    scope = None
    token = ""
    try : 
        scope = api_spec["servers"][0]["url"].split("/")[1]
        nf_instance_id = generate_variables("uuid")
        token = setup_rogue(nf_instance_id,scope=scope,target_type=nf)
        
        if display : 
            print("==========")
            print(file_path)
            print(f"Creating {nf} {nf_instance_id} with scope {scope}...")
    
    except:
        print(f"Couldn't create access-token for nf {nf} scope {scope}")
        
    return token

def fuzz(nf_list=["NRF","UDM","AMF"],nb_file=1, nb_url=1, nb_method=1, nb_ite=1, only_required=True, display=True):
    
    request_result_list = []
    for nf in nf_list:
        for file in _sample_file(nf,nb_file): 
            api_spec = _get_spec(file)
            token    = _setup_fuzzer(api_spec,nf,display)
            
            if not token : 
                return # If we can't get a token we stop the fuzzing
            
            for url in _sample_url(api_spec,nb_url):
                
                for method in _sample_method(api_spec,url,nb_method):
                    
                    header = {}
                    body   = {}
                    
                    new_url = url 
                    
                    if 'parameters' in api_spec["paths"][url][method] :
                        try : 
                            parameters = api_spec["paths"][url][method]['parameters']
                            new_url, header = extract_parameters(parameters, url, file, only_required)
                        except :
                            pass

                    if 'requestBody' in api_spec["paths"][url][method]:
                        try : 
                            body = api_spec["paths"][url][method]['requestBody']['content']
                            accept, body = _extract_body(body, file, only_required)
                        except :
                            pass

                    # If its a file that use the '{apiRoot}/nnrf-nfm/v1' prefix we use it
                    try : 
                        pre_url = api_spec["servers"][0]["url"].replace("{apiRoot}","")
                        new_url = pre_url + new_url
                    except : 
                        pass

                    # When receiving some NF check if the requester/sender NF is the same as the one in the token
                    # So we force the value if it's present in the uri
                    new_url = re.sub('target-nf-type=(.+?)(&|$)', f'target-nf-type={nf}&', new_url)
                    new_url = re.sub('requester-nf-type=(.+?)(&|$)', f'requester-nf-type=AMF&', new_url)

                    for _ in range(nb_ite):
                        # print(f"{nf} {method} : {new_url} (header : {header}, body : {body})")
                        try : 
                            code, result = request_cn(nf,body,method,new_url,header,token=token)
                            request_result_list.append(code)
                        except Exception as e:
                            print(f"Error sending the request: {e}")
        
    return request_result_list