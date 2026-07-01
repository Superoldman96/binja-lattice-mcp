from lib.lattice import Lattice
import argparse
import json
import sys


def parse_address(value: str) -> int:
    """Parse a decimal or 0x-prefixed address."""
    return int(value, 0)


def parse_members(value: str):
    """Parse a JSON struct member list."""
    members = json.loads(value)
    if not isinstance(members, list):
        raise argparse.ArgumentTypeError("members must be a JSON list")
    return members


def print_result(result):
    """Print API responses consistently."""
    print(json.dumps(result, indent=2))


COMMAND_HANDLERS = {
    "binary-info": lambda client, args: client.get_binary_info(),
    "function-context": lambda client, args: client.get_function_context(args.address),
    "function-context-by-name": lambda client, args: client.get_function_context_by_name(args.name),
    "functions": lambda client, args: client.get_all_function_names(),
    "rename-function": lambda client, args: client.update_function_name(args.name, args.new_name),
    "rename-variable": lambda client, args: client.update_variable_name(args.function_name, args.var_name, args.new_name),
    "global-data": lambda client, args: client.get_global_variable_data(args.function_name, args.global_var_name),
    "comment-address": lambda client, args: client.add_comment_to_address(args.address, args.comment),
    "comment-function": lambda client, args: client.add_comment_to_function(args.name, args.comment),
    "disassembly": lambda client, args: client.get_function_disassembly(args.name),
    "xrefs": lambda client, args: client.get_cross_references_to_function(args.name),
    "pseudocode": lambda client, args: client.get_function_pseudocode(args.name),
    "variables": lambda client, args: client.get_function_variables(args.name),
    "strings": lambda client, args: client.get_strings(args.min_length, args.filter),
    "imports": lambda client, args: client.get_imports(),
    "exports": lambda client, args: client.get_exports(),
    "data": lambda client, args: client.get_data_at_address(args.address, args.length, args.type_name),
    "search-bytes": lambda client, args: client.search_bytes(args.pattern, args.max_results),
    "types": lambda client, args: client.get_types(args.filter),
    "create-struct": lambda client, args: client.create_struct(args.name, args.members, args.overwrite),
    "update-struct": lambda client, args: client.update_struct(args.name, args.members),
    "set-variable-type": lambda client, args: client.set_variable_type(args.function_name, args.variable_name, args.type_name),
    "set-function-signature": lambda client, args: client.set_function_signature(args.function_name, args.signature),
    "call-graph": lambda client, args: client.get_call_graph(args.function_name, args.depth),
    "create-tag": lambda client, args: client.create_tag(args.address, args.tag_type, args.data),
    "tags": lambda client, args: client.get_tags(args.tag_type),
    "analysis-progress": lambda client, args: client.get_analysis_progress(),
}


def run_command(client: Lattice, args):
    """Execute a parsed CLI command against the Lattice client."""
    try:
        handler = COMMAND_HANDLERS[args.command]
    except KeyError:
        raise ValueError(f"Unsupported command: {args.command}") from None

    return handler(client, args)


def build_parser():
    parser = argparse.ArgumentParser(description='BinjaLattice Client - Communicate with Binary Ninja Lattice Protocol Server')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=9000, help='Server port (default: 9000)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS encryption')

    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--username', help='Username for authentication')
    auth_group.add_argument('--password', help='Password/API key for authentication')
    auth_group.add_argument('--token', help='Authentication token')

    subparsers = parser.add_subparsers(dest='command', metavar='command')

    subparsers.add_parser('binary-info', help='Get binary metadata')

    function_context = subparsers.add_parser('function-context', help='Get function context at address')
    function_context.add_argument('address', type=parse_address, help='Function address, decimal or hex')

    function_context_name = subparsers.add_parser('function-context-by-name', help='Get function context by name')
    function_context_name.add_argument('name')

    subparsers.add_parser('functions', help='List all function names')

    rename_function = subparsers.add_parser('rename-function', help='Rename a function')
    rename_function.add_argument('name')
    rename_function.add_argument('new_name')

    rename_variable = subparsers.add_parser('rename-variable', help='Rename a variable in a function')
    rename_variable.add_argument('function_name')
    rename_variable.add_argument('var_name')
    rename_variable.add_argument('new_name')

    global_data = subparsers.add_parser('global-data', help='Read data from a global referenced by a function')
    global_data.add_argument('function_name')
    global_data.add_argument('global_var_name')

    comment_address = subparsers.add_parser('comment-address', help='Add a comment at an address')
    comment_address.add_argument('address', type=parse_address)
    comment_address.add_argument('comment')

    comment_function = subparsers.add_parser('comment-function', help='Add a comment to a function')
    comment_function.add_argument('name')
    comment_function.add_argument('comment')

    disassembly = subparsers.add_parser('disassembly', help='Get function disassembly by name')
    disassembly.add_argument('name')

    xrefs = subparsers.add_parser('xrefs', help='Get cross references to a function')
    xrefs.add_argument('name')

    pseudocode = subparsers.add_parser('pseudocode', help='Get function pseudocode by name')
    pseudocode.add_argument('name')

    variables = subparsers.add_parser('variables', help='Get function variables by name')
    variables.add_argument('name')

    strings = subparsers.add_parser('strings', help='Get strings with optional filters')
    strings.add_argument('--min-length', type=int, default=4)
    strings.add_argument('--filter')

    subparsers.add_parser('imports', help='List imported functions')
    subparsers.add_parser('exports', help='List exported functions')

    data = subparsers.add_parser('data', help='Read bytes at an address')
    data.add_argument('address', type=parse_address)
    data.add_argument('--length', type=int, default=16)
    data.add_argument('--type-name')

    search_bytes = subparsers.add_parser('search-bytes', help='Search for a hex byte pattern')
    search_bytes.add_argument('pattern')
    search_bytes.add_argument('--max-results', type=int, default=100)

    types = subparsers.add_parser('types', help='List defined types')
    types.add_argument('--filter')

    create_struct = subparsers.add_parser('create-struct', help='Create a struct from JSON members')
    create_struct.add_argument('name')
    create_struct.add_argument('members', type=parse_members, help='JSON list of member definitions')
    create_struct.add_argument('--overwrite', action='store_true')

    update_struct = subparsers.add_parser('update-struct', help='Update a struct from JSON members')
    update_struct.add_argument('name')
    update_struct.add_argument('members', type=parse_members, help='JSON list of member definitions')

    set_variable_type = subparsers.add_parser('set-variable-type', help='Set a variable type annotation')
    set_variable_type.add_argument('function_name')
    set_variable_type.add_argument('variable_name')
    set_variable_type.add_argument('type_name')

    set_function_signature = subparsers.add_parser('set-function-signature', help='Set a function signature')
    set_function_signature.add_argument('function_name')
    set_function_signature.add_argument('signature')

    call_graph = subparsers.add_parser('call-graph', help='Get callers and callees for a function')
    call_graph.add_argument('function_name')
    call_graph.add_argument('--depth', type=int, default=1)

    create_tag = subparsers.add_parser('create-tag', help='Create a tag at an address')
    create_tag.add_argument('address', type=parse_address)
    create_tag.add_argument('tag_type')
    create_tag.add_argument('--data')

    tags = subparsers.add_parser('tags', help='List tags')
    tags.add_argument('--tag-type')

    subparsers.add_parser('analysis-progress', help='Get Binary Ninja analysis progress')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    client = Lattice(host=args.host, port=args.port, use_ssl=args.ssl)

    if args.token:
        if not client.authenticate_with_token(args.token):
            print("Authentication failed with token")
            client.close()
            sys.exit(1)
    elif args.username and args.password:
        if not client.authenticate(args.username, args.password):
            print("Authentication failed with username/password")
            client.close()
            sys.exit(1)
    else:
        print("Authentication credentials required (--token or --username/--password)")
        client.close()
        sys.exit(1)

    try:
        print_result(run_command(client, args))
    finally:
        client.close()

if __name__ == "__main__":
    main() 
