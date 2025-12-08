#!/usr/bin/env python3
"""
ORCA Enhanced Multi-Agentic Workflow CLI
Provides a comprehensive command-line interface for binary analysis using Langgraph agents
Focuses on capabilities identification by default with enhanced chatbot interface
"""
import os
import sys
import argparse
import cmd
import json
from typing import Dict, List, Any, Optional
from pathlib import Path

# Add the orca module path to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'orca', 'src', 'cmd'))

# Import workflow module
from workflow import run_workflow, WorkflowState
from chatbot import ORCAChatbot
from enhanced_chatbot_complete import EnhancedORCAChatbot
from enhanced_string_analysis import EnhancedStringAnalyzer

class ORCACLI(cmd.Cmd):
    """
    Command-line interface for ORCA multi-agentic workflow
    Enhanced with interactive chatbot capabilities
    """
    intro = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║                        ORCA CLI                          ║
    ║              Multi-Agentic Binary Analysis               ║
    ║                                                          ║
    ║  A multi-agentic binary analysis framework using LLMs    ║
    ║                Enhanced with Interactive Chatbot         ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    
    Type 'help' or '?' to list commands.
    After analysis, use 'chat' to enter enhanced interactive mode.
    """
    prompt = "orca> "
    
    def __init__(self):
        super().__init__()
        self.binary_path = None
        self.binary_functionality = None
        self.goal = "capabilities"  # Default to capabilities analysis
        self.workflow_state = None
        self.analysis_complete = False
        self.chatbot = None
        self.enhanced_chatbot = None
        self.string_analyzer = EnhancedStringAnalyzer()
    
    def do_set_binary(self, arg):
        """
        Set the binary file path for analysis
        Usage: set_binary <path_to_binary>
        """
        if not arg:
            print("Error: Please provide a path to the binary file.")
            return
        
        path = Path(arg)
        if not path.exists():
            print(f"Error: File not found: {path}")
            return
        
        self.binary_path = str(path.absolute())
        print(f"Binary path set to: {self.binary_path}")
    
    def do_set_functionality(self, arg):
        """
        Set the binary's intended functionality
        Usage: set_functionality <description>
        """
        if not arg:
            print("Error: Please provide a description of the binary's functionality.")
            return
        
        self.binary_functionality = arg
        print(f"Binary functionality set to: {self.binary_functionality}")
    
    def do_set_goal(self, arg):
        """
        Set the analysis goal
        Usage: set_goal <goal>
        Examples: set_goal capabilities, set_goal malware_analysis
        """
        if not arg:
            print("Error: Please provide an analysis goal.")
            return
        
        valid_goals = ["capabilities", "malware_analysis", "malware analysis"]
        if arg.lower() not in valid_goals and not "capabilities" in arg.lower() and not "malware" in arg.lower():
            print(f"Warning: '{arg}' is not a standard goal. Standard goals are: {', '.join(valid_goals)}")
            confirm = input("Do you want to continue with this custom goal? (y/n): ")
            if confirm.lower() != 'y':
                return
        
        self.goal = arg
        print(f"Analysis goal set to: {self.goal}")
    
    def do_analyze(self, arg):
        """
        Run the analysis workflow with the current settings
        Usage: analyze
        """
        # Check if all required parameters are set
        if not self.binary_path:
            print("Error: Binary path not set. Use 'set_binary <path>' first.")
            return
        
        if not self.binary_functionality:
            print("Error: Binary functionality not set. Use 'set_functionality <description>' first.")
            return
        
        if not self.goal:
            print("Error: Analysis goal not set. Use 'set_goal <goal>' first.")
            return
        
        print("\n🔍 Starting ORCA analysis workflow...")
        print(f"Binary: {self.binary_path}")
        print(f"Functionality: {self.binary_functionality}")
        print(f"Goal: {self.goal}")
        print("\nThis may take some time. Please wait...\n")
        
        try:
            # Run the workflow
            self.workflow_state = run_workflow(
                binary_path=self.binary_path,
                binary_functionality=self.binary_functionality,
                goal=self.goal
            )
            
            # Print the final messages
            for message in self.workflow_state.get("messages", []):
                if message.type == "ai":
                    print(f"AI: {message.content}")
                elif message.type == "human":
                    print(f"Human: {message.content}")
            
            self.analysis_complete = True
            
            # Initialize enhanced chatbot with analysis context and state
            try:
                # Create analysis state from workflow state if available
                analysis_state = None
                if hasattr(self.workflow_state, 'binary_view'):
                    analysis_state = self.workflow_state
                
                # Initialize enhanced chatbot
                self.enhanced_chatbot = EnhancedORCAChatbot(
                    analysis_context=self.workflow_state,
                    analysis_state=analysis_state
                )
                print("Enhanced chatbot initialized successfully.")
                
                # Also keep basic chatbot for fallback
                self.chatbot = ORCAChatbot(self.workflow_state)
                
            except Exception as e:
                print(f"Warning: Enhanced chatbot initialization failed: {e}")
                # Fallback to basic chatbot
                self.chatbot = ORCAChatbot(self.workflow_state)
                print("Using basic chatbot as fallback.")
            
            print("\n🎉 ORCA Analysis complete. You can now:")
            print("- Use 'ask <question>' for quick questions")
            print("- Use 'chat' to enter enhanced interactive chatbot mode")
            print("- Use 'list_apis' to see all APIs used by the binary")
            print("- Use 'api_usage <api_name>' to analyze how an API is used")
            print("- Use 'function_analysis <function_name>' to analyze a function")
            print("- Use 'malware_check' for malware analysis")
            print("- Use 'suspicious_strings' to analyze suspicious strings")
            
        except Exception as e:
            print(f"Error during analysis: {str(e)}")
    
    def do_list_apis(self, arg):
        """
        List all APIs used by the binary with enhanced analysis
        Usage: list_apis
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        if self.enhanced_chatbot:
            response = self.enhanced_chatbot.chat("list apis")
            print(f"\n{response}")
        else:
            # Fallback to basic API listing
            static_results = self.workflow_state.get("static_analysis_results", {})
            imports = static_results.get("imports", [])
            
            if not imports:
                print("No APIs/imports found in the analysis results.")
                return
            
            print(f"\n=== APIs Used in Binary ===")
            print(f"Total APIs found: {len(imports)}\n")
            
            for i, api in enumerate(imports, 1):
                print(f"{i:3d}. {api}")
    
    def do_api_usage(self, arg):
        """
        Analyze how a specific API is being used
        Usage: api_usage <api_name>
        Example: api_usage CreateFile
        """
        if not arg:
            print("Error: Please provide an API name to analyze.")
            print("Usage: api_usage <api_name>")
            return
        
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        if self.enhanced_chatbot:
            response = self.enhanced_chatbot.chat(f"How is {arg} used?")
            print(f"\n{response}")
        else:
            print(f"Enhanced chatbot not available. Basic API search for: {arg}")
            # Basic fallback implementation
            static_results = self.workflow_state.get("static_analysis_results", {})
            imports = static_results.get("imports", [])
            
            matching_apis = [api for api in imports if arg.lower() in api.lower()]
            if matching_apis:
                print(f"Found matching APIs: {', '.join(matching_apis)}")
            else:
                print(f"No APIs matching '{arg}' found.")

    def do_function_analysis(self, arg):
        """
        Analyze a specific function in the binary
        Usage: function_analysis <function_name>
        Example: function_analysis main
        """
        if not arg:
            print("Error: Please provide a function name to analyze.")
            print("Usage: function_analysis <function_name>")
            return
        
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        if self.enhanced_chatbot:
            response = self.enhanced_chatbot.chat(f"analyze function {arg}")
            print(f"\n{response}")
        else:
            print(f"Enhanced chatbot not available. Basic function search for: {arg}")
            # Basic fallback implementation
            static_results = self.workflow_state.get("static_analysis_results", {})
            functions = static_results.get("functions", [])
            
            matching_functions = [func for func in functions if arg.lower() in func.get('name', '').lower()]
            if matching_functions:
                print(f"Found {len(matching_functions)} matching function(s):")
                for func in matching_functions:
                    print(f"- {func.get('name', 'unknown')} at {func.get('address', 'unknown')}")
            else:
                print(f"No functions matching '{arg}' found.")
    
    def do_malware_check(self, arg):
        """
        Perform malware analysis and vulnerability research
        Usage: malware_check
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        if self.enhanced_chatbot:
            response = self.enhanced_chatbot.chat("Is this binary malicious?")
            print(f"\n{response}")
        else:
            # Fallback to basic malware analysis display
            malware_analysis = self.workflow_state.get("malware_analysis")
            if malware_analysis:
                print("\n=== Malware Analysis Results ===\n")
                print(json.dumps(malware_analysis, indent=2))
            else:
                print("Malware analysis not available. Make sure your goal includes 'malware_analysis'.")
    
    def do_ask(self, arg):
        """
        Ask a question about the analyzed binary
        Usage: ask <question>
        Example: ask What are the main capabilities of this binary?
        """
        if not arg:
            print("Error: Please provide a question.")
            return
        
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        # Use enhanced chatbot if available, otherwise use workflow
        if self.enhanced_chatbot:
            response = self.enhanced_chatbot.chat(arg)
            print(f"\n{response}")
        else:
            try:
                # Run the workflow with the user's question using the existing state
                updated_state = run_workflow(
                    binary_path=self.binary_path,
                    binary_functionality=self.binary_functionality,
                    goal=self.goal,
                    user_message=arg
                )
                
                # Update the workflow state
                self.workflow_state = updated_state
                
                # Print the response
                if updated_state.get("messages", []):
                    last_message = updated_state["messages"][-1]
                    if hasattr(last_message, 'type') and last_message.type == "ai":
                        print(f"\n{last_message.content}\n")
                    elif hasattr(last_message, 'content'):
                        print(f"\n{last_message.content}\n")
                
            except Exception as e:
                print(f"Error processing question: {str(e)}")
    
    def do_capabilities(self, arg):
        """
        Show the capabilities of the analyzed binary
        Usage: capabilities
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        capabilities = self.workflow_state.get("capabilities")
        if not capabilities:
            print("Capabilities analysis not available. Make sure your goal includes 'capabilities'.")
            return
        
        print("\n=== Binary Capabilities ===\n")
        print(json.dumps(capabilities, indent=2))
    
    def do_malware(self, arg):
        """
        Show the malware analysis results
        Usage: malware
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        malware_analysis = self.workflow_state.get("malware_analysis")
        if not malware_analysis:
            print("Malware analysis not available. Make sure your goal includes 'malware_analysis'.")
            return
        
        print("\n=== Malware Analysis Results ===\n")
        print(json.dumps(malware_analysis, indent=2))
    
    def do_status(self, arg):
        """
        Show the current status of the workflow
        Usage: status
        """
        print("\n=== ORCA Status ===\n")
        print(f"Binary path: {self.binary_path or 'Not set'}")
        print(f"Binary functionality: {self.binary_functionality or 'Not set'}")
        print(f"Analysis goal: {self.goal or 'Not set'}")
        print(f"Analysis complete: {'Yes' if self.analysis_complete else 'No'}")
        print(f"Enhanced chatbot: {'Available' if self.enhanced_chatbot else 'Not available'}")
        
        if self.analysis_complete and self.workflow_state:
            completed_steps = self.workflow_state.get("completed_steps", [])
            print(f"Completed steps: {', '.join(completed_steps)}")
    
    def do_save(self, arg):
        """
        Save the analysis results to a file
        Usage: save <filename>
        """
        if not arg:
            print("Error: Please provide a filename.")
            return
        
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        try:
            # Create a serializable version of the state
            serializable_state = {
                "binary_path": self.workflow_state.get("binary_path"),
                "binary_functionality": self.workflow_state.get("binary_functionality"),
                "goal": self.workflow_state.get("goal"),
                "static_analysis_results": self.workflow_state.get("static_analysis_results"),
                "api_crossrefs_results": self.workflow_state.get("api_crossrefs_results"),
                "api_clustering_results": self.workflow_state.get("api_clustering_results"),
                # "dynamic_analysis_results": self.workflow_state.get("dynamic_analysis_results"),  # Dynamic analysis disabled by user
                "capabilities": self.workflow_state.get("capabilities"),
                "malware_analysis": self.workflow_state.get("malware_analysis"),
                "completed_steps": self.workflow_state.get("completed_steps")
            }
            
            # Remove binary_view as it's not serializable
            if "binary_view" in serializable_state:
                del serializable_state["binary_view"]
            
            # Save to file
            with open(arg, 'w') as f:
                json.dump(serializable_state, f, indent=2)
            
            print(f"Analysis results saved to {arg}")
            
        except Exception as e:
            print(f"Error saving results: {str(e)}")
    
    def do_exit(self, arg):
        """
        Exit the ORCA CLI
        Usage: exit
        """
        print("Exiting ORCA CLI. Goodbye!")
        return True
    
    def do_chat(self, arg):
        """
        Enter interactive chatbot mode for binary analysis
        Usage: chat
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        # Use enhanced chatbot if available, otherwise fallback to basic
        active_chatbot = self.enhanced_chatbot if self.enhanced_chatbot else self.chatbot
        
        if not active_chatbot:
            print("Error: Chatbot not initialized. Please run 'analyze' first.")
            return
        
        chatbot_type = "Enhanced" if self.enhanced_chatbot else "Basic"
        print(f"\n=== {chatbot_type} Interactive Chatbot Mode ===")
        print("Ask questions about the binary analysis. Type 'exit' to return to main CLI.")
        
        if self.enhanced_chatbot:
            print("Enhanced workflows available:")
            print("- 'list apis' - Show all APIs used")
            print("- 'how is <API> used?' - Analyze API usage")
            print("- 'analyze function <name>' - Function analysis")
            print("- 'malware analysis' - Security assessment")
        
        print("Examples:")
        print("- What are the suspicious strings in this binary?")
        print("- Find string \"CreateFile\"")
        print("- Find API \"WriteFile\"")
        print("- What malware capabilities does this binary have?")
        print()
        
        while True:
            try:
                user_input = input("chat> ").strip()
                
                if user_input.lower() in ['exit', 'quit', 'back']:
                    print("Exiting chatbot mode.")
                    break
                
                if not user_input:
                    continue
                
                # Get chatbot response
                response = active_chatbot.chat(user_input)
                print(f"\n{response}\n")
                
            except KeyboardInterrupt:
                print("\nExiting chatbot mode.")
                break
            except EOFError:
                print("\nExiting chatbot mode.")
                break

    def do_suspicious_strings(self, arg):
        """
        Analyze strings for suspicious patterns indicating malware behavior
        Usage: suspicious_strings [save_to_file]
        """
        if not self.analysis_complete:
            print("Error: No analysis has been completed yet. Run 'analyze' first.")
            return
        
        # Get strings from static analysis
        static_results = self.workflow_state.get("static_analysis_results", {})
        strings_data = static_results.get("strings", {})
        
        if not strings_data:
            print("No strings found in static analysis results.")
            return
        
        # Collect all strings
        all_strings = []
        for category, strings_list in strings_data.items():
            if isinstance(strings_list, list):
                all_strings.extend(strings_list)
        
        if not all_strings:
            print("No strings found to analyze.")
            return
        
        print(f"\n🔍 Analyzing {len(all_strings)} strings for suspicious patterns...")
        
        try:
            # Analyze for suspicious strings
            results = self.string_analyzer.find_suspicious_strings(all_strings)
            
            print(f"\n=== Suspicious Strings Analysis ===")
            print(f"Risk Score: {results['risk_score']}/100")
            print(f"\nSummary:\n{results['summary']}")
            
            # Display suspicious strings by category
            for category, strings in results["suspicious_strings"].items():
                if strings:
                    print(f"\n{category.replace('_', ' ').title()}:")
                    for string_info in strings:
                        print(f"  - String: `{string_info['string']}`")
                        print(f"    Reason: {string_info['reason']}")
                        print(f"    Risk Level: {string_info['risk_level']}")
                        print()
            
            # Display high-risk strings
            if results["high_risk_strings"]:
                print(f"\nHigh-Risk Keywords:")
                for string_info in results["high_risk_strings"]:
                    print(f"  - String: `{string_info['string']}`")
                    print(f"    Reason: {string_info['reason']}")
                    print()
            
            # Display suspicious paths
            if results["suspicious_paths"]:
                print(f"\nSuspicious Paths:")
                for path_info in results["suspicious_paths"]:
                    print(f"  - Path: `{path_info['string']}`")
                    print(f"    Reason: {path_info['reason']}")
                    print()
            
            # Display encoded strings
            if results["encoded_strings"]:
                print(f"\nPotentially Encoded Strings:")
                for enc_info in results["encoded_strings"]:
                    print(f"  - String: `{enc_info['string']}`")
                    print(f"    Encoding: {enc_info['encoding']}")
                    print(f"    Reason: {enc_info['reason']}")
                    print()
            
            # Save results if requested
            if arg:
                self.string_analyzer.save_suspicious_strings(results, arg)
                print(f"\nSuspicious strings analysis saved to {arg}")
            
        except Exception as e:
            print(f"Error analyzing suspicious strings: {str(e)}")
    
    def do_save_conversation(self, arg):
        """
        Save the chatbot conversation history to a file
        Usage: save_conversation <filename>
        """
        if not arg:
            print("Error: Please provide a filename.")
            return
        
        active_chatbot = self.enhanced_chatbot if self.enhanced_chatbot else self.chatbot
        
        if not active_chatbot:
            print("Error: No chatbot conversation to save.")
            return
        
        try:
            if hasattr(active_chatbot, 'conversation_history'):
                # Enhanced chatbot
                with open(arg, 'w') as f:
                    json.dump(active_chatbot.conversation_history, f, indent=2)
                print(f"Conversation saved to {arg}")
            else:
                # Basic chatbot
                active_chatbot.save_conversation(arg)
                print(f"Conversation saved to {arg}")
        except Exception as e:
            print(f"Error saving conversation: {str(e)}")
    
    def do_quick_analyze(self, arg):
        """
        Quick analysis with minimal setup - automatically sets capabilities as goal
        Usage: quick_analyze <binary_path> <functionality_description>
        Example: quick_analyze /path/to/binary "Text editor application"
        """
        if not arg:
            print("Error: Please provide binary path and functionality description.")
            print("Usage: quick_analyze <binary_path> <functionality_description>")
            return
        
        # Parse arguments
        parts = arg.split(' ', 1)
        if len(parts) < 2:
            print("Error: Please provide both binary path and functionality description.")
            print("Usage: quick_analyze <binary_path> <functionality_description>")
            return
        
        binary_path, functionality = parts
        
        # Set parameters
        self.do_set_binary(binary_path)
        self.do_set_functionality(functionality)
        self.goal = "capabilities"  # Always use capabilities for quick analysis
        
        # Run analysis
        self.do_analyze("")
    
    def do_comprehensive_analyze(self, arg):
        """
        Comprehensive analysis including both capabilities and malware analysis
        Usage: comprehensive_analyze <binary_path> <functionality_description>
        Example: comprehensive_analyze /path/to/binary "Text editor application"
        """
        if not arg:
            print("Error: Please provide binary path and functionality description.")
            print("Usage: comprehensive_analyze <binary_path> <functionality_description>")
            return
        
        # Parse arguments  
        parts = arg.split(' ', 1)
        if len(parts) < 2:
            print("Error: Please provide both binary path and functionality description.")
            print("Usage: comprehensive_analyze <binary_path> <functionality_description>")
            return
        
        binary_path, functionality = parts
        
        # Set parameters
        self.do_set_binary(binary_path)
        self.do_set_functionality(functionality)
        self.goal = "capabilities and malware analysis"  # Comprehensive analysis
        
        # Run analysis
        self.do_analyze("")
    
    def do_quit(self, arg):
        """
        Exit the ORCA CLI
        Usage: quit
        """
        return self.do_exit(arg)

def parse_args():
    """
    Parse command-line arguments
    """
    parser = argparse.ArgumentParser(description="ORCA Multi-Agentic Binary Analysis Workflow CLI")
    parser.add_argument("--binary", "-b", help="Path to the binary file")
    parser.add_argument("--functionality", "-f", help="Description of the binary's functionality")
    parser.add_argument("--goal", "-g", help="Analysis goal (e.g., 'capabilities', 'malware_analysis')")
    parser.add_argument("--analyze", "-a", action="store_true", help="Run analysis immediately")
    
    return parser.parse_args()

def main():
    """
    Main entry point
    """
    args = parse_args()
    
    cli = ORCACLI()
    
    # Set parameters from command-line arguments if provided
    if args.binary:
        cli.do_set_binary(args.binary)
    
    if args.functionality:
        cli.do_set_functionality(args.functionality)
    
    if args.goal:
        cli.do_set_goal(args.goal)
    
    # Run analysis immediately if requested
    if args.analyze and args.binary and args.functionality and args.goal:
        cli.do_analyze("")
    
    # Start the CLI
    cli.cmdloop()

if __name__ == "__main__":
    main()
