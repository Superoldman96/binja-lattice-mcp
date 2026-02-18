![BinjaLattice Logo](img/lattice-logo.png)

# BinjaLattice

BinjaLattice is a secure communication protocol for Binary Ninja that enables interaction with external Model Context Protocol (MCP) servers and tools. It provides a structured way to acquire information from Binary Ninja and the ability to modify an active Binary Ninja database over HTTP with a REST API.

## Demo

[![BinjaLattice Demo](https://img.youtube.com/vi/xfDRVn0VIA0/0.jpg)](https://www.youtube.com/watch?v=xfDRVn0VIA0)

## Features

- **Secure Authentication**: Token-based authentication system
- **Encrypted Communication**: Optional SSL/TLS encryption
- **Binary Analysis Context**: Export pseudocode, disassembly, variable names, binary information etc.
- **Binary Modification**: Update function names, add comments, rename variables
- **Token Management**: Automatic expiration and renewal of authentication tokens

## Installation

### Windows (Automated)

Run the PowerShell installer for a one-shot setup:

```powershell
.\scripts\install_windows.ps1
```

This will:
- Install the plugin to `%APPDATA%\Binary Ninja\plugins\`
- Create a Python virtual environment (`.venv`)
- Install all dependencies
- Output a ready-to-use MCP configuration

### Manual Installation (All Platforms)

1. Copy `plugin/lattice_server_plugin.py` to your Binary Ninja plugins directory:
   - Linux: `~/.binaryninja/plugins/`
   - macOS: `~/Library/Application Support/Binary Ninja/plugins/`
   - Windows: `%APPDATA%\Binary Ninja\plugins\`

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

3. Activate and install dependencies:
   ```bash
   # Linux/macOS
   source .venv/bin/activate
   
   # Windows
   .venv\Scripts\activate
   
   pip install -r requirements.txt
   ```

## Usage

### Starting the Server in Binary Ninja

1. Open Binary Ninja and load a binary file
2. Go to `Plugins > Start Lattice Protocol Server`
3. The server will start and display the API key in the log console
4. Set the API key as the `BNJLAT` environment variable in your MCP configuration

Example MCP configuration (`mcp.json`):
```json
{
    "mcpServers": {
      "binja-lattice-mcp": {
        "command": "/path/to/BinjaLattice/.venv/bin/python",
        "args": ["/path/to/BinjaLattice/mcp_server.py"],
        "env": {
            "BNJLAT": "your_api_key_here"
        }
      }
    }
}
```

On Windows, use backslashes:
```json
{
    "mcpServers": {
      "binja-lattice-mcp": {
        "command": "C:\\path\\to\\BinjaLattice\\.venv\\Scripts\\python.exe",
        "args": ["C:\\path\\to\\BinjaLattice\\mcp_server.py"],
        "env": {
            "BNJLAT": "your_api_key_here"
        }
      }
    }
}
```

> **Tip**: The Windows installer outputs a ready-to-paste configuration with the correct paths.

### Available MCP Tools

The following tools are available through the MCP server:

#### Binary Information
- `get_binary_info`: Get metadata about the binary (filename, architecture, entry point, segments, sections, function count)
- `get_all_function_names`: List all function names in the binary
- `get_strings`: Get strings with optional min_length and substring filter
- `get_imports`: List imported functions with addresses and source libraries
- `get_exports`: List exported functions with addresses
- `get_analysis_progress`: Get Binary Ninja analysis status and progress percentage

#### Function Analysis
- `get_function_disassembly`: Get assembly instructions for function by name
- `get_function_pseudocode`: Get decompiled C-like pseudocode for function
- `get_function_variables`: Get parameters, local variables, and global variables
- `get_cross_references_to_function`: List functions that call the specified function
- `get_call_graph`: Get callers and callees of function with configurable depth
- `get_global_variable_data`: Read data from global variable referenced in function

#### Data Access
- `get_data_at_address`: Read bytes at address with optional type interpretation
- `search_bytes`: Search for hex byte pattern with wildcard support (e.g., '48 89 ?? 24')

#### Type Management
- `get_types`: List defined types (structs, enums, typedefs) with optional filter
- `create_struct`: Create a new struct type with JSON member definitions
- `update_struct`: Update an existing struct type

#### Annotations
- `update_function_name`: Rename a function
- `update_variable_name`: Rename a variable in a function
- `set_variable_type`: Set variable type annotation (C-style like 'uint32_t')
- `set_function_signature`: Set function prototype (C-style like 'int foo(char* arg1)')
- `add_comment_to_address`: Add comment at address
- `add_comment_to_function`: Add comment to function
- `create_tag`: Create tag at address with type and optional description
- `get_tags`: List all tags with optional type filter

### Client Library Usage

The `Lattice` client library provides a Python interface for interacting with the BinjaLattice server:

```python
from lib.lattice import Lattice

# Initialize client
client = Lattice(host='localhost', port=9000, use_ssl=False)

# Authenticate with API key
client.authenticate("username", "API_KEY")

# Example: Get binary information
binary_info = client.get_binary_info()

# Example: Update function name
client.update_function_name("old_name", "new_name")

# Example: Add comment to function
client.add_comment_to_function("function_name", "This function handles authentication")
```

### Command Line Interface

The project includes `lattice_client.py`, which provides an interactive command-line interface for testing and debugging the BinjaLattice server:

```bash
python lattice_client.py --host localhost --port 9000 [--ssl] --username user --password YOUR_API_KEY
```

#### Command Line Options

- `--host`: Server host (default: localhost)
- `--port`: Server port (default: 9000)
- `--ssl`: Enable SSL/TLS encryption
- `--interactive`, `-i`: Run in interactive mode
- `--username`: Username for authentication
- `--password`: Password/API key for authentication
- `--token`: Authentication token (if you have one from previous authentication)

#### Interactive Mode

The interactive mode provides a menu-driven interface with the following options:

1. Get Binary Information
2. Get Function Context by Address
3. Get Function Context by Name
4. Update Function Name
5. Update Variable Name
6. Add Comment to Function
7. Add Comment to Address
8. Reconnect to Server
9. Get All Function Names
10. Get Function Disassembly
11. Get Function Pseudocode
12. Get Function Variables
13. Get Cross References to Function
14. Exit

Example usage with interactive mode:

```bash
python lattice_client.py -i --ssl --username user --password YOUR_API_KEY
```

#### Non-Interactive Commands

You can also use the client to execute single commands:

```bash
# Get binary information
python lattice_client.py --username user --password YOUR_API_KEY --get-binary-info

# Get function disassembly
python lattice_client.py --username user --password YOUR_API_KEY --get-function-disassembly "main"

# Add comment to a function
python lattice_client.py --username user --password YOUR_API_KEY --add-comment-to-function "main" "Entry point of the program"
```

### Security Notes

- The API key is generated randomly on server start and shown in the Binary Ninja log
- Tokens expire after 8 hours by default
- SSL/TLS requires a certificate and key be provided by the user (disabled by default)
- All requests require authentication via API key or token
- The server runs locally by default on port 9000

## Development

- The main server implementation is in `plugin/lattice_server_plugin.py`
- MCP server implementation is in `mcp_server.py`
- Client library is in `lib/lattice.py`

### Adding New Features

To add new functionality:

1. Add new endpoint handlers in `LatticeRequestHandler` class in `lattice_server_plugin.py`
2. Add corresponding client methods in `Lattice` class in `lib/lattice.py`
3. Add new MCP tools in `mcp_server.py`

### Running Tests

1. Create a Python virtual environment and install the `requirements.txt`
2. Install the Binary Ninja Python API with the `install_api.py` provided in your Binary Ninja installation directory
3. Run the tests with `pytest tests/ -v`

## License

[MIT License](LICENSE) 
