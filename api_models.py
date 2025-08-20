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
    """Input model for vulnerability names to check."""
    name: str = Field(..., description="Name/type of vulnerability to check for (e.g., 'Reentrancy', 'Access Control')")

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Reentrancy"
            }
        }


class AnalysisRequest(BaseModel):
    """Request model for vulnerability analysis."""
    contract_code: str = Field(..., description="Smart contract source code to analyze")
    vulnerabilities: List[VulnerabilityInput] = Field(..., description="List of vulnerability names to check for")

    class Config:
        json_schema_extra = {
            "example": {
                "contract_code": "pragma solidity ^0.8.0;\n\ncontract Example {\n    mapping(address => uint256) public balances;\n    \n    function withdraw(uint256 amount) public {\n        require(balances[msg.sender] >= amount);\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success);\n        balances[msg.sender] -= amount;\n    }\n}",
                "vulnerabilities": [
                    {
                        "name": "Reentrancy"
                    },
                    {
                        "name": "Access Control"
                    },
                    {
                        "name": "Integer Overflow"
                    }
                ]
            }
        }


class AnalysisResultOutput(BaseModel):
    """Output model for individual vulnerability analysis result."""
    vulnerability_name: str = Field(..., description="Name of the analyzed vulnerability")
    exists: bool = Field(..., description="Whether the vulnerability actually exists in the code")
    confidence: ConfidenceLevel = Field(..., description="Confidence level of the analysis")
    explanation: str = Field(..., description="Detailed explanation of the analysis")
    issue_code: Optional[str] = Field(default="", description="Code snippet showing the issue")
    fixed_code: Optional[str] = Field(default="", description="Corrected code snippet")
    recommendations: List[str] = Field(default_factory=list, description="Security recommendations")
    severity: Optional[SeverityLevel] = Field(default=None, description="Assessed severity level")
    vulnerable_lines: Optional[List[int]] = Field(default=None, description="Actual vulnerable line numbers")


class AnalysisResponse(BaseModel):
    """Response model for vulnerability analysis."""
    success: bool = Field(..., description="Whether the analysis was successful")
    total_checked: int = Field(..., description="Total number of vulnerability types checked")
    vulnerabilities_found: int = Field(..., description="Number of vulnerabilities found in the code")
    vulnerabilities_not_found: int = Field(..., description="Number of vulnerability types not present")
    results: List[AnalysisResultOutput] = Field(..., description="Detailed analysis results")
    processing_time_seconds: float = Field(..., description="Time taken to process the request")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "total_checked": 3,
                "vulnerabilities_found": 1,
                "vulnerabilities_not_found": 2,
                "processing_time_seconds": 2.5,
                "results": [
                    {
                        "vulnerability_name": "Reentrancy",
                        "exists": True,
                        "confidence": "high",
                        "explanation": "Reentrancy vulnerability confirmed. The contract makes an external call before updating the balance.",
                        "issue_code": "(bool success, ) = msg.sender.call{value: amount}(\"\");\nrequire(success);\nbalances[msg.sender] -= amount;",
                        "fixed_code": "balances[msg.sender] -= amount;\n(bool success, ) = msg.sender.call{value: amount}(\"\");\nrequire(success);",
                        "recommendations": ["Use checks-effects-interactions pattern", "Implement reentrancy guard"],
                        "severity": "critical",
                        "vulnerable_lines": [7, 8, 9]
                    },
                    {
                        "vulnerability_name": "Access Control",
                        "exists": False,
                        "confidence": "high",
                        "explanation": "No access control vulnerabilities found. Functions have appropriate visibility and access restrictions.",
                        "issue_code": "",
                        "fixed_code": "",
                        "recommendations": [],
                        "severity": None,
                        "vulnerable_lines": None
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
