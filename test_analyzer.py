"""Test script for the Smart Contract Vulnerability Analyzer."""

import json
from vulnerability_analyzer import SmartContractVulnerabilityAnalyzer, VulnerabilityReport


def test_basic_functionality():
    """Test basic functionality with sample data."""
    print("Testing Smart Contract Vulnerability Analyzer...")
    
    # Sample contract with known vulnerabilities
    contract_code = """
    pragma solidity ^0.8.0;
    
    contract TestContract {
        mapping(address => uint256) public balances;
        
        function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount, "Insufficient balance");
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success, "Transfer failed");
            balances[msg.sender] -= amount;  // Reentrancy vulnerability
        }
        
        function deposit() public payable {
            balances[msg.sender] += msg.value;
        }
    }
    """
    
    # Test vulnerabilities - mix of valid and invalid
    vulnerabilities = [
        VulnerabilityReport(
            id="TEST-001",
            description="Reentrancy vulnerability in withdraw function - external call before state change",
            severity="critical",
            category="Reentrancy"
        ),
        VulnerabilityReport(
            id="TEST-002",
            description="SQL injection vulnerability in smart contract", # Invalid - not applicable to smart contracts
            severity="high",
            category="Injection"
        ),
        VulnerabilityReport(
            id="TEST-003",
            description="Missing access control on withdraw function", # Invalid - withdraw is public by design
            severity="medium",
            category="Access Control"
        )
    ]
    
    # Run analysis
    analyzer = SmartContractVulnerabilityAnalyzer()
    results = analyzer.analyze_vulnerabilities(vulnerabilities, contract_code)
    
    # Print results
    print(f"\nAnalysis completed. {len(results)} vulnerabilities analyzed.")
    
    valid_vulns = analyzer.get_valid_vulnerabilities()
    invalid_vulns = analyzer.get_invalid_vulnerabilities()
    
    print(f"Valid vulnerabilities: {len(valid_vulns)}")
    print(f"Invalid vulnerabilities: {len(invalid_vulns)}")
    
    # Export test results
    analyzer.export_results("test_results.json")
    
    return len(results) > 0


def test_json_export():
    """Test JSON export functionality."""
    print("\nTesting JSON export...")
    
    try:
        with open("test_results.json", 'r') as f:
            data = json.load(f)
        
        print(f"Export successful. File contains {data['total_analyzed']} analyzed vulnerabilities.")
        return True
    except Exception as e:
        print(f"Export test failed: {e}")
        return False


if __name__ == "__main__":
    print("=" * 60)
    print("Smart Contract Vulnerability Analyzer - Test Suite")
    print("=" * 60)
    
    # Run tests
    test1_passed = test_basic_functionality()
    test2_passed = test_json_export()
    
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    print(f"Basic functionality test: {'PASSED' if test1_passed else 'FAILED'}")
    print(f"JSON export test: {'PASSED' if test2_passed else 'FAILED'}")
    
    if test1_passed and test2_passed:
        print("\n✅ All tests passed! The analyzer is ready to use.")
        print("\nTo run the full application:")
        print("  python main.py --sample")
        print("  python main.py --interactive")
    else:
        print("\n❌ Some tests failed. Please check the configuration.")
