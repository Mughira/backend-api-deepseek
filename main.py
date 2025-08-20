"""Main application entry point for Smart Contract Vulnerability Analyzer."""

import json
import argparse
import sys
from pathlib import Path
from typing import List
from vulnerability_analyzer import SmartContractVulnerabilityAnalyzer, VulnerabilityReport
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


def load_contract_code(file_path: str) -> str:
    """Load smart contract code from file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Contract file not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error reading contract file: {e}{Style.RESET_ALL}")
        sys.exit(1)


def load_vulnerabilities_from_json(file_path: str) -> List[VulnerabilityReport]:
    """Load vulnerability reports from JSON file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vulnerabilities = []
        for item in data.get('vulnerabilities', []):
            vuln = VulnerabilityReport(
                id=item.get('id', 'unknown'),
                description=item.get('description', ''),
                severity=item.get('severity', 'unknown'),
                category=item.get('category', 'unknown'),
                line_numbers=item.get('line_numbers', [])
            )
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    except FileNotFoundError:
        print(f"{Fore.RED}Error: Vulnerabilities file not found: {file_path}{Style.RESET_ALL}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Fore.RED}Error parsing JSON file: {e}{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}Error loading vulnerabilities: {e}{Style.RESET_ALL}")
        sys.exit(1)


def create_sample_vulnerabilities() -> List[VulnerabilityReport]:
    """Create sample vulnerability reports for testing."""
    return [
        VulnerabilityReport(
            id="VULN-001",
            description="Potential reentrancy vulnerability in withdraw function",
            severity="high",
            category="Reentrancy"
        ),
        VulnerabilityReport(
            id="VULN-002", 
            description="Integer overflow possible in balance calculation",
            severity="medium",
            category="Integer Overflow"
        ),
        VulnerabilityReport(
            id="VULN-003",
            description="Missing access control on admin functions",
            severity="critical",
            category="Access Control"
        )
    ]


def interactive_mode():
    """Run the analyzer in interactive mode."""
    print(f"{Fore.CYAN}Smart Contract Vulnerability Analyzer - Interactive Mode{Style.RESET_ALL}")
    print("=" * 60)
    
    # Get contract code
    while True:
        contract_path = input("Enter path to smart contract file (.sol): ").strip()
        if Path(contract_path).exists():
            break
        print(f"{Fore.RED}File not found. Please try again.{Style.RESET_ALL}")
    
    contract_code = load_contract_code(contract_path)
    
    # Get vulnerabilities
    print("\nChoose vulnerability input method:")
    print("1. Load from JSON file")
    print("2. Use sample vulnerabilities")
    print("3. Enter manually")
    
    choice = input("Enter choice (1-3): ").strip()
    
    if choice == "1":
        vuln_path = input("Enter path to vulnerabilities JSON file: ").strip()
        vulnerabilities = load_vulnerabilities_from_json(vuln_path)
    elif choice == "2":
        vulnerabilities = create_sample_vulnerabilities()
        print(f"{Fore.YELLOW}Using sample vulnerabilities for demonstration{Style.RESET_ALL}")
    elif choice == "3":
        vulnerabilities = []
        print("Enter vulnerabilities (press Enter with empty description to finish):")
        i = 1
        while True:
            desc = input(f"Vulnerability {i} description: ").strip()
            if not desc:
                break
            vuln = VulnerabilityReport(
                id=f"MANUAL-{i:03d}",
                description=desc,
                severity=input("Severity (critical/high/medium/low): ").strip() or "unknown",
                category=input("Category: ").strip() or "unknown"
            )
            vulnerabilities.append(vuln)
            i += 1
    else:
        print(f"{Fore.RED}Invalid choice. Using sample vulnerabilities.{Style.RESET_ALL}")
        vulnerabilities = create_sample_vulnerabilities()
    
    if not vulnerabilities:
        print(f"{Fore.RED}No vulnerabilities to analyze. Exiting.{Style.RESET_ALL}")
        return
    
    # Run analysis
    analyzer = SmartContractVulnerabilityAnalyzer()
    results = analyzer.analyze_vulnerabilities(vulnerabilities, contract_code)
    
    # Show summary and export option
    analyzer.print_summary()
    
    export_choice = input(f"\n{Fore.CYAN}Export results to JSON? (y/n): {Style.RESET_ALL}").strip().lower()
    if export_choice in ['y', 'yes']:
        filename = input("Enter filename (default: vulnerability_analysis_results.json): ").strip()
        if not filename:
            filename = "vulnerability_analysis_results.json"
        analyzer.export_results(filename)


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Smart Contract Vulnerability Analyzer using DeepSeek API"
    )
    parser.add_argument(
        "--contract", "-c",
        help="Path to smart contract file (.sol)"
    )
    parser.add_argument(
        "--vulnerabilities", "-v",
        help="Path to vulnerabilities JSON file"
    )
    parser.add_argument(
        "--output", "-o",
        default="vulnerability_analysis_results.json",
        help="Output file for results (default: vulnerability_analysis_results.json)"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Run in interactive mode"
    )
    parser.add_argument(
        "--sample", "-s",
        action="store_true",
        help="Use sample data for testing"
    )
    parser.add_argument(
        "--api", "-a",
        action="store_true",
        help="Start API server mode"
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="API server host (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="API server port (default: 8000)"
    )
    
    args = parser.parse_args()

    if args.api:
        # Start API server
        print(f"{Fore.CYAN}Starting Smart Contract Vulnerability Analyzer API Server...{Style.RESET_ALL}")
        print(f"Host: {args.host}")
        print(f"Port: {args.port}")
        print(f"API Documentation: http://{args.host}:{args.port}/docs")
        print(f"Health Check: http://{args.host}:{args.port}/health")
        print("Press Ctrl+C to stop the server")

        try:
            import uvicorn
            from api_main import app
            uvicorn.run(app, host=args.host, port=args.port, log_level="info")
        except ImportError:
            print(f"{Fore.RED}Error: FastAPI and uvicorn are required for API mode{Style.RESET_ALL}")
            print("Install with: pip install fastapi uvicorn")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}API server stopped{Style.RESET_ALL}")
        return

    if args.interactive:
        interactive_mode()
        return
    
    if args.sample:
        # Use sample data for demonstration
        contract_code = """
        pragma solidity ^0.8.0;
        
        contract VulnerableContract {
            mapping(address => uint256) public balances;
            
            function withdraw(uint256 amount) public {
                require(balances[msg.sender] >= amount, "Insufficient balance");
                (bool success, ) = msg.sender.call{value: amount}("");
                require(success, "Transfer failed");
                balances[msg.sender] -= amount;  // State change after external call
            }
            
            function deposit() public payable {
                balances[msg.sender] += msg.value;
            }
        }
        """
        vulnerabilities = create_sample_vulnerabilities()
    else:
        if not args.contract or not args.vulnerabilities:
            print(f"{Fore.RED}Error: Both --contract and --vulnerabilities are required in non-interactive mode{Style.RESET_ALL}")
            print("Use --interactive for interactive mode or --sample for sample data")
            sys.exit(1)
        
        contract_code = load_contract_code(args.contract)
        vulnerabilities = load_vulnerabilities_from_json(args.vulnerabilities)
    
    # Run analysis
    analyzer = SmartContractVulnerabilityAnalyzer()
    results = analyzer.analyze_vulnerabilities(vulnerabilities, contract_code)
    
    # Export results
    analyzer.export_results(args.output)
    analyzer.print_summary()


if __name__ == "__main__":
    main()
