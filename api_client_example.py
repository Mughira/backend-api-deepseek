"""Example client for the Smart Contract Vulnerability Analyzer API."""

import requests
import json
from typing import Dict, Any, List


class VulnerabilityAnalyzerClient:
    """Client for interacting with the Vulnerability Analyzer API."""
    
    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
    
    def health_check(self) -> Dict[str, Any]:
        """Check API health status."""
        try:
            response = self.session.get(f"{self.base_url}/health")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Health check failed: {str(e)}"}
    
    def analyze_vulnerabilities(self, contract_code: str, vulnerability_names: List[str]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities in smart contract code.

        Args:
            contract_code: Smart contract source code
            vulnerability_names: List of vulnerability names to check for

        Returns:
            Analysis results
        """
        vulnerabilities = [{"name": name} for name in vulnerability_names]
        payload = {
            "contract_code": contract_code,
            "vulnerabilities": vulnerabilities
        }
        
        try:
            response = self.session.post(
                f"{self.base_url}/analyze",
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"Analysis request failed: {str(e)}"}
    
    def get_vulnerability_categories(self) -> List[str]:
        """Get supported vulnerability categories."""
        try:
            response = self.session.get(f"{self.base_url}/vulnerabilities/categories")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return [f"Error: {str(e)}"]
    
    def get_api_info(self) -> Dict[str, Any]:
        """Get API information."""
        try:
            response = self.session.get(f"{self.base_url}/api-info")
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"error": f"API info request failed: {str(e)}"}


def example_usage():
    """Example usage of the API client."""
    print("Smart Contract Vulnerability Analyzer API Client Example")
    print("=" * 60)
    
    # Initialize client
    client = VulnerabilityAnalyzerClient()
    
    # Check health
    print("1. Checking API health...")
    health = client.health_check()
    print(f"Health Status: {health}")
    print()
    
    # Get supported categories
    print("2. Getting supported vulnerability categories...")
    categories = client.get_vulnerability_categories()
    print(f"Supported Categories: {categories}")
    print()
    
    # Example contract with vulnerabilities
    contract_code = """
    pragma solidity ^0.8.0;
    
    contract VulnerableContract {
        mapping(address => uint256) public balances;
        address public owner;
        
        constructor() {
            owner = msg.sender;
        }
        
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            
            // Vulnerable: External call before state change (reentrancy)
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            
            // State change after external call - vulnerable to reentrancy
            balances[msg.sender] -= amount;
        }
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
        
        function emergencyWithdraw() public {
            // Missing access control - should be onlyOwner
            payable(msg.sender).transfer(address(this).balance);
        }
    }
    """
    
    # Example vulnerability names to check for
    vulnerability_names = [
        "Reentrancy",
        "Access Control",
        "Integer Overflow",
        "Unchecked External Calls",
        "Denial of Service",
        "Time Manipulation"  # This should not be found in the example contract
    ]
    
    # Analyze vulnerabilities
    print("3. Analyzing vulnerabilities...")
    print(f"Contract Code Length: {len(contract_code)} characters")
    print(f"Vulnerability Types to Check: {', '.join(vulnerability_names)}")
    print()

    results = client.analyze_vulnerabilities(contract_code, vulnerability_names)
    
    if "error" in results:
        print(f"Error: {results['error']}")
        return
    
    # Display results
    print("4. Analysis Results:")
    print("=" * 40)
    print(f"Success: {results['success']}")
    print(f"Total Checked: {results['total_checked']}")
    print(f"Vulnerabilities Found: {results['vulnerabilities_found']}")
    print(f"Vulnerabilities Not Found: {results['vulnerabilities_not_found']}")
    print(f"Processing Time: {results['processing_time_seconds']}s")
    print()

    # Display individual results
    for i, result in enumerate(results['results'], 1):
        print(f"Result {i}: {result['vulnerability_name']}")
        print(f"  Status: {'🔴 FOUND' if result['exists'] else '✅ NOT FOUND'}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Explanation: {result['explanation']}")

        if result['exists'] and result['issue_code']:
            print(f"  Issue Code: {result['issue_code'][:100]}...")
            if result['fixed_code']:
                print(f"  Fixed Code: {result['fixed_code'][:100]}...")

        if result['recommendations']:
            print(f"  Recommendations: {', '.join(result['recommendations'])}")
        print()


def test_api_endpoints():
    """Test all API endpoints."""
    print("Testing API Endpoints")
    print("=" * 30)
    
    client = VulnerabilityAnalyzerClient()
    
    # Test health endpoint
    print("Testing /health...")
    health = client.health_check()
    print(f"Health: {health.get('status', 'unknown')}")
    
    # Test categories endpoint
    print("Testing /vulnerabilities/categories...")
    categories = client.get_vulnerability_categories()
    print(f"Categories count: {len(categories)}")
    
    # Test API info endpoint
    print("Testing /api-info...")
    info = client.get_api_info()
    print(f"API Title: {info.get('title', 'unknown')}")
    
    print("All endpoint tests completed!")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_api_endpoints()
    else:
        example_usage()
