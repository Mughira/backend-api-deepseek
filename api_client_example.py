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
    
    def analyze_vulnerabilities(self, contract_code: str, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze vulnerabilities in smart contract code.
        
        Args:
            contract_code: Smart contract source code
            vulnerabilities: List of vulnerability reports
            
        Returns:
            Analysis results
        """
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
    
    # Example vulnerabilities to test
    vulnerabilities = [
        {
            "id": "VULN-001",
            "description": "Reentrancy vulnerability detected in withdraw function. The contract makes an external call before updating the balance, allowing for potential reentrancy attacks.",
            "severity": "critical",
            "category": "Reentrancy",
            "line_numbers": [14, 15, 18]
        },
        {
            "id": "VULN-002",
            "description": "Missing access control on emergencyWithdraw function allows any user to drain the contract.",
            "severity": "critical",
            "category": "Access Control",
            "line_numbers": [25]
        },
        {
            "id": "VULN-003",
            "description": "SQL injection vulnerability in smart contract",  # This should be detected as invalid
            "severity": "high",
            "category": "Injection"
        },
        {
            "id": "VULN-004",
            "description": "Buffer overflow in deposit function",  # This should be detected as invalid for Solidity
            "severity": "medium",
            "category": "Buffer Overflow"
        }
    ]
    
    # Analyze vulnerabilities
    print("3. Analyzing vulnerabilities...")
    print(f"Contract Code Length: {len(contract_code)} characters")
    print(f"Number of Vulnerabilities to Analyze: {len(vulnerabilities)}")
    print()
    
    results = client.analyze_vulnerabilities(contract_code, vulnerabilities)
    
    if "error" in results:
        print(f"Error: {results['error']}")
        return
    
    # Display results
    print("4. Analysis Results:")
    print("=" * 40)
    print(f"Success: {results['success']}")
    print(f"Total Analyzed: {results['total_analyzed']}")
    print(f"Valid Vulnerabilities: {results['valid_vulnerabilities']}")
    print(f"Invalid Vulnerabilities: {results['invalid_vulnerabilities']}")
    print(f"False Positive Rate: {results['false_positive_rate']}%")
    print(f"Processing Time: {results['processing_time_seconds']}s")
    print()
    
    # Display individual results
    for i, result in enumerate(results['results'], 1):
        print(f"Result {i}: {result['vulnerability_id']}")
        print(f"  Status: {'✅ VALID' if result['is_valid'] else '❌ INVALID'}")
        print(f"  Confidence: {result['confidence']}")
        print(f"  Explanation: {result['explanation']}")
        
        if result['is_valid'] and result['issue_code']:
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
