from lib.lattice import Lattice
import argparse, sys, json, logging

logger = logging.getLogger(__name__)

def print_menu():
    """Print the interactive menu"""
    print("\nBinjaLattice Client Menu:")
    print("1. Get Binary Information")
    print("2. Get Function Context by Address")
    print("3. Get Function Context by Name")
    print("4. Update Function Name")
    print("5. Update Variable Name")
    print("6. Add Comment to Function")
    print("7. Add Comment to Address")
    print("8. Reconnect to Server")
    print("9. Get All Function Names")
    print("10. Get Function Disassembly")
    print("11. Get Function Pseudocode")
    print("12. Get Function Variables")
    print("13. Get Cross References to Function")
    print("14. Get Global Variable Data")
    print("15. Exit")
    print()

def interactive_mode(client: Lattice):
    """Run the interactive REPL mode"""
    while True:
        print_menu()
        try:
            choice = input("Enter your choice (1-15): ").strip()
            
            if choice == '1':
                result = client.get_binary_info()
                print(json.dumps(result, indent=2))
                
            elif choice == '2':
                addr = input("Enter function address (hex or decimal): ").strip()
                try:
                    address = int(addr, 0)
                    result = client.get_function_context(address)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid address format")
            elif choice == '3':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_function_context_by_name(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
                    
            elif choice == '4':
                name = input("Enter function name: ").strip()
                new_name = input("Enter new function name: ").strip()
                try:
                    result = client.update_function_name(name, new_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
                    
            elif choice == '5':
                func_name = input("Enter function name: ").strip()
                var_name = input("Enter variable name: ").strip()
                new_name = input("Enter new variable name: ").strip()
                try:
                    result = client.update_variable_name(func_name, var_name, new_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid input format")
                    
            elif choice == '6':
                name = input("Enter function name: ").strip()
                comment = input("Enter comment: ").strip()
                try:
                    result = client.add_comment_to_function(name, comment)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '7':
                address = input("Enter address (hex or decimal): ").strip()
                comment = input("Enter comment: ").strip()
                try:
                    result = client.add_comment_to_address(address, comment)
                    logger.error(json.dumps(result, indent=2))
                except ValueError:
                    print("Invalid address format")
            elif choice == '8':
                client.close()
                if client.connect():
                    print("Reconnected successfully")
                    if client.auth_token:
                        print("Previous authentication token is still valid")
                else:
                    logger.error("Failed to reconnect")
            elif choice == '9':
                result = client.get_all_function_names()
                print(json.dumps(result, indent=2))
            elif choice == '10':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_function_disassembly(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '11':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_function_pseudocode(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '12':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_function_variables(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '13':
                name = input("Enter function name: ").strip()
                try:
                    result = client.get_cross_references_to_function(name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '14':
                func_name = input("Enter function name: ").strip()
                var_name = input("Enter variable name: ").strip()
                try:
                    result = client.get_global_variable_data(func_name, var_name)
                    print(json.dumps(result, indent=2))
                except ValueError:
                    logger.error("Invalid function name")
            elif choice == '15':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please try again.")
                
        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            logger.error(f"Error: {e}")
            print("Try reconnecting to the server (option 8)")

def main():
    parser = argparse.ArgumentParser(description='BinjaLattice Client - Communicate with Binary Ninja Lattice Protocol Server')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=9000, help='Server port (default: 9000)')
    parser.add_argument('--ssl', action='store_true', help='Use SSL/TLS encryption')
    parser.add_argument('--interactive', '-i', action='store_true', help='Run in interactive mode')
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--username', help='Username for authentication')
    auth_group.add_argument('--password', help='Password/API key for authentication')
    auth_group.add_argument('--token', help='Authentication token')
    
    # Command options (only used in non-interactive mode)
    command_group = parser.add_argument_group('Commands')
    command_group.add_argument('--get-binary-info', action='store_true', help='Get binary information')
    command_group.add_argument('--get-function-context', type=lambda x: int(x, 0), help='Get function context at address (hex or decimal)')
    command_group.add_argument('--get-basic-block-context', type=lambda x: int(x, 0), help='Get basic block context at address (hex or decimal)')
    command_group.add_argument('--update-function-name', nargs=2, help='Update function name: <address> <new_name>')
    command_group.add_argument('--update-variable-name', nargs=3, help='Update variable name: <function_address> <var_id> <new_name>')
    command_group.add_argument('--add-comment-to-address', nargs=2, help='Add comment to address: <address> <comment>')
    command_group.add_argument('--add-comment-to-function', nargs=2, help='Add comment to function: <function_name> <comment>')
    command_group.add_argument('--get-function-disassembly', type=str, help='Get function disassembly for function name')
    command_group.add_argument('--get-function-pseudocode', type=str, help='Get function pseudocode for function name')
    command_group.add_argument('--get-function-variables', type=str, help='Get function variables for function name')
    command_group.add_argument('--get-cross-references-to-function', type=str, help='Get cross references to function name')
    args = parser.parse_args()
    
    # Create client
    client = Lattice(host=args.host, port=args.port, use_ssl=args.ssl)
    
    # Authenticate
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
        if args.interactive:
            interactive_mode(client)
        else:
            # Execute requested command
            if args.get_binary_info:
                result = client.get_binary_info()
                print(json.dumps(result, indent=2))
                
            elif args.get_function_context:
                result = client.get_function_context(args.get_function_context)
                print(json.dumps(result, indent=2))
            elif args.update_function_name:
                address = int(args.update_function_name[0], 0)
                new_name = args.update_function_name[1]
                result = client.update_function_name(address, new_name)
                print(json.dumps(result, indent=2))
                
            elif args.update_variable_name:
                func_addr = int(args.update_variable_name[0], 0)
                var_id = int(args.update_variable_name[1])
                new_name = args.update_variable_name[2]
                result = client.update_variable_name(func_addr, var_id, new_name)
                print(json.dumps(result, indent=2))
                
            elif args.add_comment_to_address:
                address = int(args.add_comment_to_address[0], 0)
                comment = args.add_comment_to_address[1]
                result = client.add_comment_to_address(address, comment)
                print(json.dumps(result, indent=2))

            elif args.add_comment_to_function:
                name = args.add_comment_to_function[0]
                comment = args.add_comment_to_function[1]
                result = client.add_comment_to_function(name, comment)

                print(json.dumps(result, indent=2))
            elif args.get_function_disassembly:
                result = client.get_function_disassembly(args.get_function_disassembly)
                print(json.dumps(result, indent=2))
                
            elif args.get_function_pseudocode:
                result = client.get_function_pseudocode(args.get_function_pseudocode)
                print(json.dumps(result, indent=2))
                
            elif args.get_function_variables:
                result = client.get_function_variables(args.get_function_variables)
                print(json.dumps(result, indent=2))

            elif args.get_cross_references_to_function:
                result = client.get_cross_references_to_function(args.get_cross_references_to_function)
                print(json.dumps(result, indent=2))
            else:
                print("No command specified. Use --help to see available commands.")
                
    finally:
        client.close()

if __name__ == "__main__":
    main() 
