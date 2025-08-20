"""Test script for the new API format that accepts vulnerability names."""

import requests
import json


def test_new_api_format():
    """Test the new API format with vulnerability names."""
    
    # API endpoint
    url = "http://localhost:8000/analyze"
    
    # Sample vulnerable contract
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
    
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}
"""
    
    # Vulnerability names to check for
    vulnerability_names = [
        "Reentrancy",           # Should be found
        "Access Control",       # Should be found (emergencyWithdraw)
        "Integer Overflow",     # Should NOT be found (Solidity 0.8.0+ has built-in protection)
        "Time Manipulation",    # Should NOT be found
        "Unchecked External Calls",  # Might be found
        "Denial of Service"     # Should NOT be found
    ]
    
    # Prepare request payload
    payload = {
        "contract_code": contract_code,
        "vulnerabilities": [{"name": name} for name in vulnerability_names]
    }
    
    print("🔍 Testing New API Format")
    print("=" * 50)
    print(f"Contract: {len(contract_code)} characters")
    print(f"Checking for: {', '.join(vulnerability_names)}")
    print()
    
    try:
        # Make API request
        print("📡 Sending request to API...")
        response = requests.post(url, json=payload, headers={"Content-Type": "application/json"})
        
        if response.status_code == 200:
            result = response.json()
            
            print("✅ API Response Received")
            print("=" * 30)
            print(f"Success: {result['success']}")
            print(f"Total Checked: {result['total_checked']}")
            print(f"Vulnerabilities Found: {result['vulnerabilities_found']}")
            print(f"Vulnerabilities Not Found: {result['vulnerabilities_not_found']}")
            print(f"Processing Time: {result['processing_time_seconds']}s")
            print()
            
            # Display detailed results
            print("📊 Detailed Results:")
            print("-" * 30)
            
            for i, vuln_result in enumerate(result['results'], 1):
                status_emoji = "🔴" if vuln_result['exists'] else "✅"
                status_text = "FOUND" if vuln_result['exists'] else "NOT FOUND"
                
                print(f"{i}. {vuln_result['vulnerability_name']}")
                print(f"   Status: {status_emoji} {status_text}")
                print(f"   Confidence: {vuln_result['confidence']}")
                print(f"   Explanation: {vuln_result['explanation'][:100]}...")
                
                if vuln_result['exists']:
                    if vuln_result['issue_code']:
                        print(f"   Issue Code: {vuln_result['issue_code'][:80]}...")
                    if vuln_result['fixed_code']:
                        print(f"   Fixed Code: {vuln_result['fixed_code'][:80]}...")
                    if vuln_result['recommendations']:
                        print(f"   Recommendations: {', '.join(vuln_result['recommendations'][:2])}")
                    if vuln_result['severity']:
                        print(f"   Severity: {vuln_result['severity']}")
                
                print()
            
            # Summary
            found_vulns = [r['vulnerability_name'] for r in result['results'] if r['exists']]
            not_found_vulns = [r['vulnerability_name'] for r in result['results'] if not r['exists']]
            
            print("📋 Summary:")
            print(f"🔴 Vulnerabilities Found: {', '.join(found_vulns) if found_vulns else 'None'}")
            print(f"✅ Vulnerabilities Not Found: {', '.join(not_found_vulns) if not_found_vulns else 'None'}")
            
        else:
            print(f"❌ API Error: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection Error: Make sure the API server is running on http://localhost:8000")
        print("Start the server with: python main.py --api")
    except Exception as e:
        print(f"❌ Error: {str(e)}")


def test_health_endpoint():
    """Test the health endpoint."""
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            health = response.json()
            print("🏥 Health Check:")
            print(f"   Status: {health['status']}")
            print(f"   Version: {health['version']}")
            print(f"   Uptime: {health['uptime_seconds']}s")
            print(f"   DeepSeek Status: {health['deepseek_status']}")
            return True
        else:
            print(f"❌ Health check failed: {response.status_code}")
            return False
    except:
        print("❌ Health check failed: Server not reachable")
        return False


def test_categories_endpoint():
    """Test the vulnerability categories endpoint."""
    try:
        response = requests.get("http://localhost:8000/vulnerabilities/categories")
        if response.status_code == 200:
            categories = response.json()
            print("📚 Supported Vulnerability Categories:")
            for i, category in enumerate(categories, 1):
                print(f"   {i:2d}. {category}")
            print(f"\nTotal: {len(categories)} categories supported")
            return True
        else:
            print(f"❌ Categories request failed: {response.status_code}")
            return False
    except:
        print("❌ Categories request failed: Server not reachable")
        return False


if __name__ == "__main__":
    print("🧪 Smart Contract Vulnerability Analyzer - New API Format Test")
    print("=" * 70)
    print()
    
    # Test health first
    if test_health_endpoint():
        print()
        
        # Test categories
        if test_categories_endpoint():
            print()
            
            # Test main analysis
            test_new_api_format()
        else:
            print("Skipping main test due to categories endpoint failure")
    else:
        print("Skipping tests due to health check failure")
        print("\n💡 To start the API server:")
        print("   python main.py --api")
        print("   or")
        print("   ./docker-run.sh api")
