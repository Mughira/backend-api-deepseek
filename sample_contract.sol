// SPDX-License-Identifier: MIT
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
        // Potential overflow in older Solidity versions
        balances[msg.sender] += msg.value;
    }
    
    function emergencyWithdraw() public {
        // Missing access control - should be onlyOwner
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
    
    receive() external payable {
        deposit();
    }
}
