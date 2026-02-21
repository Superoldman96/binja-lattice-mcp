import requests
import json
import logging
import sys
from typing import Optional, Dict, Any, List, Tuple, Union
from urllib.parse import urljoin

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Lattice:
    """Client for communicating with a BinjaLattice server"""
    
    def __init__(self, host: str = "localhost", port: int = 9000, use_ssl: bool = False):
        """
        Initialize the client.
        
        Args:
            host: Host address of the server
            port: Port number of the server
            use_ssl: Whether to use SSL/TLS encryption
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.auth_token = None
        self.base_url = f"{'https' if use_ssl else 'http'}://{host}:{port}"
        self.session = requests.Session()
        if not use_ssl:
            self.session.verify = False  # Disable SSL verification for non-SSL connections
    
    def connect(self) -> bool:
        """Connect to the server"""
        #try:
        response = self.session.get(urljoin(self.base_url, '/binary/info'))
        if response.status_code == 200:
            logger.info(f"Connected to {self.host}:{self.port}")
            return True
        elif response.status_code == 401:
            logger.error(f"Authentication failed with status code: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return False
        else:
            logger.error(f"Failed to connect: {response.status_code}")
            return False
        #except Exception as e:
        #    logger.error(f"Failed to connect: {e}")
        #    return False
    
    def authenticate(self, username: str, password: str) -> bool:
        """
        Authenticate with the server using username/password
        
        Args:
            username: Username for authentication
            password: Password (API key) for authentication
            
        Returns:
            True if authentication successful, False otherwise
        """
        response = self.session.post(
            urljoin(self.base_url, '/auth'),
            json={
                'username': username,
                'password': password
            }
        )
        
        if response.status_code == 200:
            print(response.content)
            data = json.loads(response.content)
            if data.get('status') == 'success':
                self.auth_token = data.get('token')
                self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
                logger.info("Authentication successful")
                return True
            else:
                logger.error(f"Authentication failed: {data.get('message')}")
        else:
            logger.error(f"Authentication failed with status code: {response.status_code}")
        
        return False
    
    def authenticate_with_token(self, token: str) -> bool:
        """
        Authenticate with the server using a token
        
        Args:
            token: Authentication token
            
        Returns:
            True if authentication successful, False otherwise
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, '/auth'),
                json={'token': token}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    self.auth_token = token
                    self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
                    logger.info("Token authentication successful")
                    return True
                else:
                    logger.error(f"Token authentication failed: {data.get('message')}")
            else:
                logger.error(f"Token authentication failed with status code: {response.status_code}")
            
            return False
            
        except Exception as e:
            logger.error(f"Token authentication error: {e}")
            return False
    
    def get_binary_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the binary"""
        try:
            response = self.session.get(urljoin(self.base_url, '/binary/info'))
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            logger.error(f"Error getting binary info: {e}")
            return None
    
    def get_function_context(self, address: int) -> Optional[Dict[str, Any]]:
        """
        Get context for a function at the specified address
        
        Args:
            address: Address of the function
            
        Returns:
            Dictionary containing function context
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{address}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function context'}
        except Exception as e:
            logger.error(f"Error getting function context: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_context_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get context for a function by name
        
        Args:
            name: Name of the function
            
        Returns:
            Dictionary containing function context
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/name/{name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function context by name'}
        except Exception as e:
            logger.error(f"Error getting function context by name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_all_function_names(self) -> Optional[Dict[str, Any]]:
        """
        Get all function names
        """
        try:
            response = self.session.get(urljoin(self.base_url, '/functions'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get all function names'}
        except Exception as e:
            logger.error(f"Error getting all function names: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def update_function_name(self, name: str, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a function
        
        Args:
            name: Current name of the function
            new_name: New name for the function
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/functions/{name}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to update function name'}
        except Exception as e:
            logger.error(f"Error updating function name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def update_variable_name(self, function_name: str, var_name: str, new_name: str) -> Optional[Dict[str, Any]]:
        """
        Update the name of a variable in a function
        
        Args:
            function_name: Name of the function containing the variable
            var_name: Name of the variable to rename
            new_name: New name for the variable
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/variables/{function_name}/{var_name}/name'),
                json={'name': new_name}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to update variable name'}
        except Exception as e:
            logger.error(f"Error updating variable name: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_global_variable_data(self, function_name: str, global_var_name: str) -> Optional[Dict[str, Any]]:
        """
        Get data for a global variable
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/global_variable_data/{function_name}/{global_var_name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get global variable data'}
        except Exception as e:
            logger.error(f"Error getting global variable data: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def add_comment_to_address(self, address: int, comment: str) -> Optional[Dict[str, Any]]:
        """
        Add a comment at the specified address
        
        Args:
            address: Address to add the comment at
            comment: Comment text to add
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, f'/comments/{address}'),
                json={'comment': comment}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to add comment'}
        except Exception as e:
            logger.error(f"Error adding comment: {e}")
            return {'status': 'error', 'message': str(e)}

    def add_comment_to_function(self, name: str, comment: str) -> Optional[Dict[str, Any]]:
        """
        Add a comment to a function with specified function name
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, f'/functions/{name}/comments'),
                json={'comment': comment}
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to add comment'}  
        except Exception as e:
            logger.error(f"Error adding comment to function: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_function_disassembly(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get disassembly for a function with specified function name
        
        Args:
            name: Address of the function
            
        Returns:
            Dictionary containing function disassembly
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/disassembly'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function disassembly'}
        except Exception as e:
            logger.error(f"Error getting function disassembly: {e}")
            return {'status': 'error', 'message': str(e)}
        
    def get_cross_references_to_function(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get cross references to a function
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/cross-references/{name}'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get cross references to function'}
        except Exception as e:
            logger.error(f"Error getting cross references to function: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_pseudocode(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get pseudocode for a function with specified function name
        
        Args:
            name: Name of the function
            
        Returns:
            Dictionary containing function pseudocode
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/pseudocode'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function pseudocode'}
        except Exception as e:
            logger.error(f"Error getting function pseudocode: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_function_variables(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Get variables for a function at the specified address
        
        Args:
            name: Name of function 
            
        Returns:
            Dictionary containing function variables
        """
        try:
            response = self.session.get(urljoin(self.base_url, f'/functions/{name}/variables'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get function variables'}
        except Exception as e:
            logger.error(f"Error getting function variables: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def get_strings(self, min_length: int = 4, filter: str = None) -> Optional[Dict[str, Any]]:
        """
        Get strings from the binary with optional filtering
        
        Args:
            min_length: Minimum string length to return (default: 4)
            filter: Substring filter for string values (case-insensitive)
            
        Returns:
            Dictionary containing list of strings with address, value, and length
        """
        try:
            params = {'min_length': min_length}
            if filter is not None:
                params['filter'] = filter
            response = self.session.get(urljoin(self.base_url, '/strings'), params=params)
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get strings'}
        except Exception as e:
            logger.error(f"Error getting strings: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_imports(self) -> Optional[Dict[str, Any]]:
        """
        Get imported functions from the binary
        
        Returns:
            Dictionary containing list of imports with name, address, and library
        """
        try:
            response = self.session.get(urljoin(self.base_url, '/imports'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get imports'}
        except Exception as e:
            logger.error(f"Error getting imports: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_exports(self) -> Optional[Dict[str, Any]]:
        """
        Get exported functions from the binary
        
        Returns:
            Dictionary containing list of exports with name and address
        """
        try:
            response = self.session.get(urljoin(self.base_url, '/exports'))
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get exports'}
        except Exception as e:
            logger.error(f"Error getting exports: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_data_at_address(self, address: int, length: int = 16, type_name: str = None) -> Optional[Dict[str, Any]]:
        """
        Read raw bytes or typed data at a specific address
        
        Args:
            address: Memory address to read from
            length: Number of bytes to read (default: 16)
            type_name: Optional type name for typed interpretation
            
        Returns:
            Dictionary containing hex data, length, and optional typed value
        """
        try:
            params = {'length': length}
            if type_name is not None:
                params['type'] = type_name
            response = self.session.get(urljoin(self.base_url, f'/data/{address}'), params=params)
            if response.status_code == 200:
                return response.json()
            return response.json() if response.status_code == 400 else {'status': 'error', 'message': 'Failed to read data'}
        except Exception as e:
            logger.error(f"Error reading data at address: {e}")
            return {'status': 'error', 'message': str(e)}

    def search_bytes(self, pattern: str, max_results: int = 100) -> Optional[Dict[str, Any]]:
        """
        Search for byte patterns in the binary
        
        Args:
            pattern: Hex byte pattern to search for (e.g., "48 89 5c 24" or "48??5c??")
                     Use ?? for wildcard bytes that match any value
            max_results: Maximum number of results to return (default: 100)
            
        Returns:
            Dictionary containing list of matching addresses and count
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, '/search/bytes'),
                json={'pattern': pattern, 'max_results': max_results}
            )
            if response.status_code == 200:
                return response.json()
            return response.json() if response.status_code == 400 else {'status': 'error', 'message': 'Failed to search bytes'}
        except Exception as e:
            logger.error(f"Error searching bytes: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_types(self, filter: str = None) -> Optional[Dict[str, Any]]:
        """
        Get defined types from the binary with optional filtering
        
        Args:
            filter: Substring filter for type names (case-insensitive)
            
        Returns:
            Dictionary containing list of types with name, kind, size, and members
        """
        try:
            params = {}
            if filter is not None:
                params['filter'] = filter
            response = self.session.get(urljoin(self.base_url, '/types'), params=params)
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get types'}
        except Exception as e:
            logger.error(f"Error getting types: {e}")
            return {'status': 'error', 'message': str(e)}

    def create_struct(self, name: str, members: List[Dict], overwrite: bool = False) -> Optional[Dict[str, Any]]:
        """
        Create a new structure type in Binary Ninja
        
        Args:
            name: Name of the structure to create
            members: List of member definitions, each with:
                     - name: Member name
                     - type: Type string (e.g., "uint32_t", "char*")
                     - count: Optional array count (default: 1)
            overwrite: If True, overwrite existing structure with same name
            
        Returns:
            Dictionary containing the created structure info
        """
        try:
            response = self.session.post(
                urljoin(self.base_url, '/types/struct'),
                json={'name': name, 'members': members, 'overwrite': overwrite}
            )
            return response.json()
        except Exception as e:
            logger.error(f"Error creating structure: {e}")
            return {'status': 'error', 'message': str(e)}

    def update_struct(self, name: str, members: List[Dict]) -> Optional[Dict[str, Any]]:
        """
        Update an existing structure type in Binary Ninja
        
        Args:
            name: Name of the structure to update
            members: List of member definitions, each with:
                     - name: Member name
                     - type: Type string (e.g., "uint32_t", "char*")
                     - count: Optional array count (default: 1)
            
        Returns:
            Dictionary containing the updated structure info
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/types/struct/{name}'),
                json={'members': members}
            )
            return response.json()
        except Exception as e:
            logger.error(f"Error updating structure: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def set_variable_type(self, function_name: str, variable_name: str, type_name: str) -> Optional[Dict[str, Any]]:
        """
        Set the type annotation for a variable in a function
        
        Args:
            function_name: Name of the function containing the variable
            variable_name: Name of the variable to update
            type_name: C-style type string (e.g., "uint32_t", "char*")
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/functions/{function_name}/variables/{variable_name}/type'),
                json={'type': type_name}
            )
            return response.json()
        except Exception as e:
            logger.error(f"Error setting variable type: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def set_function_signature(self, function_name: str, signature: str) -> Optional[Dict[str, Any]]:
        """
        Update a function's signature/prototype
        
        Args:
            function_name: Name of the function to update
            signature: C-style function signature (e.g., "int foo(char* arg1, int arg2)")
            
        Returns:
            Dictionary containing the result of the operation
        """
        try:
            response = self.session.put(
                urljoin(self.base_url, f'/functions/{function_name}/signature'),
                json={'signature': signature}
            )
            return response.json()
        except Exception as e:
            logger.error(f"Error setting function signature: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_call_graph(self, function_name: str, depth: int = 1) -> Optional[Dict[str, Any]]:
        """
        Get the call graph for a function
        
        Args:
            function_name: Name of the function to get call graph for
            depth: Depth of call graph traversal (default: 1, max: 10)
            
        Returns:
            Dictionary containing the call graph with callers and callees
        """
        try:
            params = {'depth': depth}
            response = self.session.get(
                urljoin(self.base_url, f'/functions/{function_name}/callgraph'),
                params=params
            )
            if response.status_code == 200:
                return response.json()
            return response.json() if response.status_code != 500 else {'status': 'error', 'message': 'Failed to get call graph'}
        except Exception as e:
            logger.error(f"Error getting call graph: {e}")
            return {'status': 'error', 'message': str(e)}

    def create_tag(self, address: int, tag_type: str, data: str = None) -> Optional[Dict[str, Any]]:
        """
        Create a tag at a specific address
        
        Args:
            address: The address to tag
            tag_type: The type/category of the tag
            data: Optional data/description for the tag
            
        Returns:
            Dictionary containing the created tag information
        """
        try:
            payload = {
                'address': address,
                'tag_type': tag_type
            }
            if data is not None:
                payload['data'] = data
            
            response = self.session.post(
                urljoin(self.base_url, '/tags'),
                json=payload
            )
            if response.status_code == 200:
                return response.json()
            return response.json() if response.status_code == 400 else {'status': 'error', 'message': 'Failed to create tag'}
        except Exception as e:
            logger.error(f"Error creating tag: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_tags(self, tag_type: str = None) -> Optional[Dict[str, Any]]:
        """
        Get all tags with optional type filtering
        
        Args:
            tag_type: Optional filter to only return tags of this type
            
        Returns:
            Dictionary containing list of tags with address, type, data, and function
        """
        try:
            params = {}
            if tag_type is not None:
                params['type'] = tag_type
            
            response = self.session.get(
                urljoin(self.base_url, '/tags'),
                params=params
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get tags'}
        except Exception as e:
            logger.error(f"Error getting tags: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_analysis_progress(self) -> Optional[Dict[str, Any]]:
        """
        Get the current analysis progress state
        
        Returns:
            Dictionary containing:
            - state: Current analysis state name
            - is_complete: Boolean indicating if analysis is complete
            - progress: Float from 0.0 to 1.0 indicating progress
            - description: Human-readable status description
        """
        try:
            response = self.session.get(
                urljoin(self.base_url, '/analysis/progress')
            )
            if response.status_code == 200:
                return response.json()
            return {'status': 'error', 'message': 'Failed to get analysis progress'}
        except Exception as e:
            logger.error(f"Error getting analysis progress: {e}")
            return {'status': 'error', 'message': str(e)}
    
    def close(self):
        """Close the connection to the server"""
        self.session.close()
        logger.info("Connection closed")
