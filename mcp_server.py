from mcp.server.fastmcp import FastMCP
from lib.lattice import Lattice
import os, json

# Initialize FastMCP server
mcp = FastMCP("binja-lattice", log_level="ERROR")

@mcp.tool()
def get_all_function_names() -> str:
    """List all function names in the binary."""
    response = lattice_client.get_all_function_names()
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{func['name']}" for func in response['function_names']])
    return "Error: Could not retrieve function names"

@mcp.tool()
def get_binary_info() -> str:
    """Get metadata about the binary: filename, architecture, entry point, segments, sections, function count."""
    response = lattice_client.get_binary_info()
    if response and 'status' in response and response['status'] == 'success':
        return json.dumps(response, indent=2)
    return "Error: Could not retrieve binary information"

@mcp.tool()
def get_strings(min_length: int = 4, filter: str = None) -> str:
    """Get strings from the binary. min_length filters by length, filter matches substring (case-insensitive)."""
    response = lattice_client.get_strings(min_length, filter)
    if response and 'status' in response and response['status'] == 'success':
        strings = response.get('strings', [])
        if not strings:
            return "No strings found matching the criteria"
        return '\n'.join([f"0x{s['address']:x}: {s['value']} (len={s['length']})" for s in strings])
    return "Error: Could not retrieve strings"

@mcp.tool()
def get_imports() -> str:
    """List imported functions with addresses and source libraries."""
    response = lattice_client.get_imports()
    if response and 'status' in response and response['status'] == 'success':
        imports = response.get('imports', [])
        if not imports:
            return "No imports found"
        return '\n'.join([f"0x{imp['address']:x}: {imp['name']} ({imp['library']})" if imp['library'] else f"0x{imp['address']:x}: {imp['name']}" for imp in imports])
    return "Error: Could not retrieve imports"

@mcp.tool()
def get_exports() -> str:
    """List exported functions with addresses."""
    response = lattice_client.get_exports()
    if response and 'status' in response and response['status'] == 'success':
        exports = response.get('exports', [])
        if not exports:
            return "No exports found"
        return '\n'.join([f"0x{exp['address']:x}: {exp['name']}" for exp in exports])
    return "Error: Could not retrieve exports"

@mcp.tool()
def get_data_at_address(address: int, length: int = 16, type_name: str = None) -> str:
    """Read bytes at address. address is integer, length is byte count, type_name optionally interprets as C type."""
    response = lattice_client.get_data_at_address(address, length, type_name)
    if response and 'status' in response:
        if response['status'] == 'success':
            result = f"Address: 0x{response['address']:x}\n"
            result += f"Length: {response['length']} bytes\n"
            
            # Format hex output readably (16 bytes per line)
            hex_str = response['hex']
            hex_lines = []
            for i in range(0, len(hex_str), 32):  # 32 hex chars = 16 bytes
                chunk = hex_str[i:i+32]
                # Add spaces between bytes
                spaced = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                hex_lines.append(spaced)
            result += f"Hex:\n" + '\n'.join(hex_lines)
            
            if response.get('truncated'):
                result += f"\n\nWarning: {response.get('warning', 'Data truncated')}"
            
            if response.get('typed_value'):
                result += f"\n\nTyped value ({type_name}): {response['typed_value']}"
            elif response.get('type_error'):
                result += f"\n\nType error: {response['type_error']}"
            
            return result
        else:
            return f"Error: {response.get('message', 'Unknown error')}"
    return "Error: Could not read data at address"

@mcp.tool()
def search_bytes(pattern: str, max_results: int = 100) -> str:
    """Search for hex byte pattern. Example: '48 89 5c 24' or '48??5c??' where ?? is wildcard."""
    response = lattice_client.search_bytes(pattern, max_results)
    if response and 'status' in response:
        if response['status'] == 'success':
            results = response.get('results', [])
            if not results:
                return f"No matches found for pattern: {pattern}"
            
            result = f"Found {response['count']} matches for pattern: {pattern}\n\n"
            result += '\n'.join([f"0x{r['address']:x}" for r in results])
            
            if response.get('truncated'):
                result += f"\n\n(Results limited to {max_results})"
            
            return result
        else:
            return f"Error: {response.get('message', 'Unknown error')}"
    return "Error: Could not search bytes"

@mcp.tool()
def get_types(filter: str = None) -> str:
    """List defined types (structs, enums, typedefs). filter matches type name substring."""
    response = lattice_client.get_types(filter)
    if response and 'status' in response and response['status'] == 'success':
        types = response.get('types', [])
        if not types:
            return "No types found" + (f" matching filter: {filter}" if filter else "")
        
        result_lines = []
        for t in types:
            line = f"{t['name']} ({t['kind']}, size={t['size']})"
            
            # Add member details for structures and enums
            members = t.get('members', [])
            if members:
                if t['kind'] == 'struct':
                    member_strs = [f"  +{m['offset']:04x}: {m['type']} {m['name']}" for m in members]
                elif t['kind'] == 'enum':
                    member_strs = [f"  {m['name']} = {m['value']}" for m in members]
                else:
                    member_strs = []
                
                if member_strs:
                    line += "\n" + "\n".join(member_strs)
            
            result_lines.append(line)
        
        return '\n\n'.join(result_lines)
    return "Error: Could not retrieve types"

@mcp.tool()
def create_struct(name: str, members: str, overwrite: bool = False) -> str:
    """Create a struct. members is JSON: [{"name":"field1","type":"uint32_t"},{"name":"field2","type":"char*"}]"""
    try:
        members_list = json.loads(members)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON for members: {str(e)}"
    
    response = lattice_client.create_struct(name, members_list, overwrite)
    if response and 'status' in response:
        if response['status'] == 'success':
            struct_info = response.get('structure', {})
            if struct_info:
                result = f"Structure '{name}' created successfully (size={struct_info.get('size', 'unknown')})"
                members_info = struct_info.get('members', [])
                if members_info:
                    result += "\nMembers:"
                    for m in members_info:
                        result += f"\n  +{m['offset']:04x}: {m['type']} {m['name']}"
                return result
            return response.get('message', 'Structure created successfully')
        else:
            return f"Error: {response.get('message', 'Unknown error')}"
    return "Error: Could not create structure"

@mcp.tool()
def update_struct(name: str, members: str) -> str:
    """Update existing struct. members is JSON: [{"name":"field1","type":"uint32_t"}]"""
    try:
        members_list = json.loads(members)
    except json.JSONDecodeError as e:
        return f"Error: Invalid JSON for members: {str(e)}"
    
    response = lattice_client.update_struct(name, members_list)
    if response and 'status' in response:
        if response['status'] == 'success':
            struct_info = response.get('structure', {})
            if struct_info:
                result = f"Structure '{name}' updated successfully (size={struct_info.get('size', 'unknown')})"
                members_info = struct_info.get('members', [])
                if members_info:
                    result += "\nMembers:"
                    for m in members_info:
                        result += f"\n  +{m['offset']:04x}: {m['type']} {m['name']}"
                return result
            return response.get('message', 'Structure updated successfully')
        else:
            return f"Error: {response.get('message', 'Unknown error')}"
    return "Error: Could not update structure"

@mcp.tool()
def update_function_name(name: str, new_name: str) -> str:
    """Rename a function. name is current name, new_name is desired name."""
    response = lattice_client.update_function_name(name, new_name)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully renamed function {name} to {new_name}"
    return f"Error: Could not update function name {name}"

@mcp.tool()
def add_comment_to_address(address: int, comment: str) -> str:
    """Add comment at address. address is integer."""
    response = lattice_client.add_comment_to_address(address, comment)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully added comment to address {address}"
    return f"Error: Could not add comment to address {address}"

@mcp.tool()
def add_comment_to_function(name: str, comment: str) -> str:
    """Add comment to function by name."""
    response = lattice_client.add_comment_to_function(name, comment)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully added comment to function {name}"
    return f"Error: Could not add comment to function {name}"

@mcp.tool()
def get_function_disassembly(name: str) -> str:
    """Get assembly instructions for function by name."""
    response = lattice_client.get_function_disassembly(name)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{block['address']}: {block['text']}" for block in response['disassembly']])
    return f"Error: Could not retrieve function disassembly for function {name}"

@mcp.tool()
def get_function_pseudocode(name: str) -> str:
    """Get decompiled C-like pseudocode for function by name."""
    response = lattice_client.get_function_pseudocode(name)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{block['address']}: {block['text']}" for block in response['pseudocode']])
    return f"Error: Could not retrieve function pseudocode for function {name}"

@mcp.tool()
def get_function_variables(name: str) -> str:
    """Get parameters, local variables, and global variables for function by name."""
    response = lattice_client.get_function_variables(name)
    if response and 'status' in response and response['status'] == 'success':
        rstr = 'Parameters: ' + '\n'.join([f"{param['name']}: {param['type']}" for param in response['variables']['parameters']]) \
        + '\nLocal Variables: ' + '\n'.join([f"{var['name']}: {var['type']}" for var in response['variables']['local_variables']]) \
        + '\nGlobal Variables: ' + '\n'.join([f"{var['name']}: {var['type']}" for var in response['variables']['global_variables']])
        return rstr

    return f"Error: Could not retrieve function variables for function {name}"

@mcp.tool()
def update_variable_name(function_name: str, var_name: str, new_name: str) -> str:
    """Rename variable in function. Provide function_name, current var_name, and new_name."""
    response = lattice_client.update_variable_name(function_name, var_name, new_name)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully renamed variable {var_name} to {new_name}"
    return f"Error: Could not update variable name {var_name}"

@mcp.tool()
def set_variable_type(function_name: str, variable_name: str, type_name: str) -> str:
    """Set variable type. type_name is C-style like 'uint32_t' or 'char*'."""
    response = lattice_client.set_variable_type(function_name, variable_name, type_name)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully set variable '{variable_name}' type to '{type_name}' in function '{function_name}'"
    error_msg = response.get('message', 'Unknown error') if response else 'No response'
    return f"Error: Could not set variable type - {error_msg}"

@mcp.tool()
def set_function_signature(function_name: str, signature: str) -> str:
    """Set function prototype. signature is C-style like 'int foo(char* arg1, int arg2)'."""
    response = lattice_client.set_function_signature(function_name, signature)
    if response and 'status' in response and response['status'] == 'success':
        return f"Successfully updated function '{function_name}' signature to '{signature}'"
    error_msg = response.get('message', 'Unknown error') if response else 'No response'
    return f"Error: Could not set function signature - {error_msg}"

@mcp.tool()
def get_global_variable_data(function_name: str, global_var_name: str) -> str:
    """Read data from global variable referenced in function."""
    response = lattice_client.get_global_variable_data(function_name, global_var_name)
    if response and 'status' in response and response['status'] == 'success':
        return response['message']
    return f"Error: Could not retrieve global variable data for function {function_name} and variable {global_var_name}"

@mcp.tool()
def get_cross_references_to_function(name: str) -> str:
    """List functions that call the specified function."""
    response = lattice_client.get_cross_references_to_function(name)
    if response and 'status' in response and response['status'] == 'success':
        return '\n'.join([f"{ref['function']}" for ref in response['cross_references']])
    return f"Error: Could not retrieve cross references for function {name}"

def _format_call_graph_tree(nodes: list, prefix: str = "", is_last: bool = True, direction: str = "callee") -> list:
    """Helper function to format call graph nodes as a tree structure"""
    lines = []
    for i, node in enumerate(nodes):
        is_node_last = (i == len(nodes) - 1)
        connector = "└── " if is_node_last else "├── "
        lines.append(f"{prefix}{connector}{node['name']} @ 0x{node['address']:x}")
        
        # Get nested nodes based on direction
        nested_key = 'callees' if direction == 'callee' else 'callers'
        nested = node.get(nested_key, [])
        if nested:
            extension = "    " if is_node_last else "│   "
            lines.extend(_format_call_graph_tree(nested, prefix + extension, is_node_last, direction))
    return lines

@mcp.tool()
def get_call_graph(function_name: str, depth: int = 1) -> str:
    """Get callers and callees of function. depth controls traversal depth (1-10)."""
    response = lattice_client.get_call_graph(function_name, depth)
    if response and 'status' in response and response['status'] == 'success':
        call_graph = response.get('call_graph', {})
        
        result_lines = []
        result_lines.append(f"Call Graph for: {call_graph['name']} @ 0x{call_graph['address']:x}")
        result_lines.append(f"Depth: {depth}")
        result_lines.append("")
        
        # Format callers
        callers = call_graph.get('callers', [])
        result_lines.append(f"Callers ({len(callers)}):")
        if callers:
            result_lines.extend(_format_call_graph_tree(callers, "  ", True, "caller"))
        else:
            result_lines.append("  (none)")
        
        result_lines.append("")
        
        # Format callees
        callees = call_graph.get('callees', [])
        result_lines.append(f"Callees ({len(callees)}):")
        if callees:
            result_lines.extend(_format_call_graph_tree(callees, "  ", True, "callee"))
        else:
            result_lines.append("  (none)")
        
        return '\n'.join(result_lines)
    
    # Handle error responses
    if response and 'message' in response:
        return f"Error: {response['message']}"
    return f"Error: Could not retrieve call graph for function {function_name}"

@mcp.tool()
def create_tag(address: int, tag_type: str, data: str = None) -> str:
    """Create tag at address. tag_type is category name, data is optional description."""
    response = lattice_client.create_tag(address, tag_type, data)
    if response and 'status' in response and response['status'] == 'success':
        tag = response.get('tag', {})
        result_lines = [f"Tag created at 0x{tag.get('address', address):x}"]
        result_lines.append(f"Type: {tag.get('type', tag_type)}")
        if tag.get('data'):
            result_lines.append(f"Data: {tag.get('data')}")
        if tag.get('function'):
            result_lines.append(f"Function: {tag.get('function')}")
        return '\n'.join(result_lines)
    
    if response and 'message' in response:
        return f"Error: {response['message']}"
    return "Error: Could not create tag"

@mcp.tool()
def get_tags(tag_type: str = None) -> str:
    """List all tags. tag_type optionally filters by category."""
    response = lattice_client.get_tags(tag_type)
    if response and 'status' in response and response['status'] == 'success':
        tags = response.get('tags', [])
        if not tags:
            return "No tags found" + (f" with type '{tag_type}'" if tag_type else "")
        
        result_lines = [f"Found {len(tags)} tag(s):"]
        for tag in tags:
            line = f"  0x{tag['address']:x}: [{tag['type']}]"
            if tag.get('data'):
                line += f" - {tag['data']}"
            if tag.get('function'):
                line += f" (in {tag['function']})"
            result_lines.append(line)
        return '\n'.join(result_lines)
    
    if response and 'message' in response:
        return f"Error: {response['message']}"
    return "Error: Could not retrieve tags"


@mcp.tool()
def get_analysis_progress() -> str:
    """Get Binary Ninja analysis status: state, completion, and progress percentage."""
    response = lattice_client.get_analysis_progress()
    if response and 'status' in response and response['status'] == 'success':
        state = response.get('state', 'Unknown')
        is_complete = response.get('is_complete', False)
        progress = response.get('progress', 0.0)
        description = response.get('description', '')
        
        status_str = "Complete" if is_complete else "In Progress"
        progress_pct = f"{progress * 100:.1f}%"
        
        return f"Analysis Status: {status_str}\nState: {state}\nProgress: {progress_pct}\nDescription: {description}"
    
    if response and 'message' in response:
        return f"Error: {response['message']}"
    return "Error: Could not retrieve analysis progress"


# Initialize and run the server
api_key = os.getenv("BNJLAT")
if not api_key:
    raise ValueError("BNJLAT environment variable not set")

global lattice_client
lattice_client = Lattice()
print(f"Authenticating with {api_key}")
lattice_client.authenticate("mcp-user", api_key)
mcp.run(transport='stdio')
