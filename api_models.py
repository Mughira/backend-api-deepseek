"""Pydantic models for API request/response schemas."""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ConfidenceLevel(str, Enum):
    """Analysis confidence levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class VulnerabilityInput(BaseModel):
    """Input model for vulnerability reports."""
    id: str = Field(..., description="Unique identifier for the vulnerability")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: SeverityLevel = Field(default=SeverityLevel.UNKNOWN, description="Severity level")
    category: str = Field(..., description="Vulnerability category")
    line_numbers: Optional[List[int]] = Field(default=None, description="Line numbers where vulnerability is suspected")


class AnalysisRequest(BaseModel):
    """Request model for vulnerability analysis."""
    contract_code: str = Field(..., description="Smart contract source code to analyze")
    vulnerabilities: List[VulnerabilityInput] = Field(..., description="List of vulnerability reports to validate")
    
    class Config:
        json_schema_extra = {
            "example": {
                "contract_code": "pragma solidity ^0.8.0;\n\ncontract Example {\n    mapping(address => uint256) public balances;\n    \n    function withdraw(uint256 amount) public {\n        require(balances[msg.sender] >= amount);\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success);\n        balances[msg.sender] -= amount;\n    }\n}",
                "vulnerabilities": [
                    {
                        "id": "VULN-001",
                        "description": "Reentrancy vulnerability in withdraw function",
                        "severity": "critical",
                        "category": "Reentrancy",
                        "line_numbers": [6, 7, 8, 9]
                    }
                ]
            }
        }


class AnalysisResultOutput(BaseModel):
    """Output model for individual vulnerability analysis result."""
    vulnerability_id: str = Field(..., description="ID of the analyzed vulnerability")
    is_valid: bool = Field(..., description="Whether the vulnerability actually exists")
    confidence: ConfidenceLevel = Field(..., description="Confidence level of the analysis")
    explanation: str = Field(..., description="Detailed explanation of the analysis")
    issue_code: Optional[str] = Field(default="", description="Code snippet showing the issue")
    fixed_code: Optional[str] = Field(default="", description="Corrected code snippet")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    vulnerability_type: Optional[str] = Field(default="", description="Specific vulnerability type")
    severity: Optional[SeverityLevel] = Field(default=None, description="Assessed severity level")
    vulnerable_lines: Optional[List[int]] = Field(default=None, description="Actual vulnerable line numbers")


class AnalysisResponse(BaseModel):
    """Response model for vulnerability analysis."""
    success: bool = Field(..., description="Whether the analysis was successful")
    total_analyzed: int = Field(..., description="Total number of vulnerabilities analyzed")
    valid_vulnerabilities: int = Field(..., description="Number of valid vulnerabilities found")
    invalid_vulnerabilities: int = Field(..., description="Number of invalid/false positive vulnerabilities")
    false_positive_rate: float = Field(..., description="Percentage of false positives")
    results: List[AnalysisResultOutput] = Field(..., description="Detailed analysis results")
    processing_time_seconds: float = Field(..., description="Time taken to process the request")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "total_analyzed": 1,
                "valid_vulnerabilities": 1,
                "invalid_vulnerabilities": 0,
                "false_positive_rate": 0.0,
                "processing_time_seconds": 2.5,
                "results": [
                    {
                        "vulnerability_id": "VULN-001",
                        "is_valid": True,
                        "confidence": "high",
                        "explanation": "Reentrancy vulnerability confirmed. The contract makes an external call before updating the balance.",
                        "issue_code": "(bool success, ) = msg.sender.call{value: amount}(\"\");\nrequire(success);\nbalances[msg.sender] -= amount;",
                        "fixed_code": "balances[msg.sender] -= amount;\n(bool success, ) = msg.sender.call{value: amount}(\"\");\nrequire(success);",
                        "recommendations": ["Use checks-effects-interactions pattern", "Implement reentrancy guard"],
                        "vulnerability_type": "Reentrancy",
                        "severity": "critical",
                        "vulnerable_lines": [7, 8, 9]
                    }
                ]
            }
        }


class ErrorResponse(BaseModel):
    """Error response model."""
    success: bool = Field(default=False, description="Always false for error responses")
    error: str = Field(..., description="Error message")
    error_code: str = Field(..., description="Error code for programmatic handling")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Additional error details")
    
    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "error": "Invalid smart contract code provided",
                "error_code": "INVALID_CONTRACT_CODE",
                "details": {
                    "line": 5,
                    "message": "Syntax error in Solidity code"
                }
            }
        }


class HealthResponse(BaseModel):
    """Health check response model."""
    status: str = Field(..., description="Service status")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    deepseek_api_status: str = Field(..., description="DeepSeek API connectivity status")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "healthy",
                "version": "1.0.0",
                "uptime_seconds": 3600.5,
                "deepseek_api_status": "connected"
            }
        }
