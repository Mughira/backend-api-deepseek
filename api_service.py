"""API service layer for vulnerability analysis."""

import time
import logging
from typing import List, Dict, Any
from vulnerability_analyzer import SmartContractVulnerabilityAnalyzer, VulnerabilityReport, AnalysisResult
from api_models import (
    AnalysisRequest, AnalysisResponse, AnalysisResultOutput, 
    VulnerabilityInput, ErrorResponse, SeverityLevel, ConfidenceLevel
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class VulnerabilityAnalysisService:
    """Service class for handling vulnerability analysis requests."""
    
    def __init__(self):
        self.analyzer = SmartContractVulnerabilityAnalyzer()
        self.start_time = time.time()
    
    def get_uptime(self) -> float:
        """Get service uptime in seconds."""
        return time.time() - self.start_time
    
    def validate_contract_code(self, contract_code: str) -> bool:
        """Basic validation of smart contract code."""
        if not contract_code or not contract_code.strip():
            return False
        
        # Basic Solidity syntax checks
        contract_code = contract_code.strip()
        
        # Check for basic Solidity keywords
        solidity_keywords = ['pragma', 'contract', 'function', 'mapping', 'address', 'uint']
        has_solidity_syntax = any(keyword in contract_code.lower() for keyword in solidity_keywords)
        
        return has_solidity_syntax
    
    def convert_vulnerability_names_to_reports(self, vulnerability_names: List[VulnerabilityInput]) -> List[VulnerabilityReport]:
        """Convert vulnerability names to detailed vulnerability reports for analysis."""
        # Vulnerability descriptions based on names
        vulnerability_descriptions = {
            "Reentrancy": "Check for reentrancy vulnerabilities where external calls are made before state changes, allowing attackers to re-enter the function.",
            "Access Control": "Check for missing or improper access control mechanisms that could allow unauthorized users to execute privileged functions.",
            "Integer Overflow": "Check for integer overflow/underflow vulnerabilities in arithmetic operations.",
            "Integer Underflow": "Check for integer underflow vulnerabilities in arithmetic operations.",
            "Unchecked External Calls": "Check for external calls that don't properly handle return values or failures.",
            "Denial of Service": "Check for denial of service vulnerabilities including gas limit issues and unbounded loops.",
            "Front Running": "Check for front-running vulnerabilities where transaction ordering can be exploited.",
            "Time Manipulation": "Check for vulnerabilities related to block timestamp manipulation.",
            "Short Address Attack": "Check for short address attack vulnerabilities in token transfers.",
            "Uninitialized Storage Pointers": "Check for uninitialized storage pointer vulnerabilities.",
            "Delegatecall Injection": "Check for delegatecall injection vulnerabilities.",
            "Signature Malleability": "Check for signature malleability issues in cryptographic operations.",
            "Gas Limit Issues": "Check for gas limit related vulnerabilities and inefficient gas usage.",
            "Random Number Generation": "Check for weak or predictable random number generation.",
            "Logic Errors": "Check for general logic errors and business logic vulnerabilities.",
            "Tx.Origin": "Check for tx.origin usage instead of msg.sender for authentication.",
            "Unchecked Return Values": "Check for unchecked return values from external calls.",
            "State Variable Default Visibility": "Check for state variables with default (public) visibility.",
            "Floating Pragma": "Check for floating pragma versions that could lead to compilation with vulnerable compiler versions.",
            "Outdated Compiler Version": "Check for usage of outdated Solidity compiler versions.",
            "Function Default Visibility": "Check for functions with default visibility that should be explicitly declared.",
            "Unprotected Ether Withdrawal": "Check for functions that allow ether withdrawal without proper access control.",
            "Unprotected SELFDESTRUCT": "Check for selfdestruct calls without proper access control.",
            "Assert Violation": "Check for improper use of assert() that could lead to stuck contracts.",
            "Deprecated Solidity Functions": "Check for usage of deprecated Solidity functions.",
            "Centralization Risk": "Check for centralization risks where single points of failure exist.",
            "Price Oracle Manipulation": "Check for price oracle manipulation vulnerabilities.",
            "Flash Loan Attack": "Check for vulnerabilities related to flash loan attacks.",
            "MEV": "Check for MEV (Maximal Extractable Value) related vulnerabilities."
        }

        reports = []
        for i, vuln in enumerate(vulnerability_names):
            vuln_name = vuln.name.strip()
            description = vulnerability_descriptions.get(vuln_name, f"Check for {vuln_name} vulnerabilities in the smart contract code.")

            report = VulnerabilityReport(
                id=f"CHECK-{i+1:03d}",
                description=description,
                severity="unknown",
                category=vuln_name,
                line_numbers=[]
            )
            reports.append(report)
        return reports
    
    def convert_results_to_output(self, results: List[AnalysisResult], vulnerability_names: List[str]) -> List[AnalysisResultOutput]:
        """Convert internal analysis results to API output models."""
        outputs = []
        for i, result in enumerate(results):
            # Map confidence levels
            confidence_map = {
                "high": ConfidenceLevel.HIGH,
                "medium": ConfidenceLevel.MEDIUM,
                "low": ConfidenceLevel.LOW
            }
            confidence = confidence_map.get(result.confidence.lower(), ConfidenceLevel.UNKNOWN)

            # Map severity levels if available
            severity = None
            if hasattr(result, 'severity') and result.severity:
                severity_map = {
                    "critical": SeverityLevel.CRITICAL,
                    "high": SeverityLevel.HIGH,
                    "medium": SeverityLevel.MEDIUM,
                    "low": SeverityLevel.LOW
                }
                severity = severity_map.get(result.severity.lower(), SeverityLevel.UNKNOWN)

            # Get the original vulnerability name
            vuln_name = vulnerability_names[i] if i < len(vulnerability_names) else "Unknown"

            output = AnalysisResultOutput(
                vulnerability_name=vuln_name,
                exists=result.is_valid,
                confidence=confidence,
                explanation=result.explanation,
                issue_code=result.issue_code,
                fixed_code=result.fixed_code,
                recommendations=result.recommendations or [],
                severity=severity,
                vulnerable_lines=getattr(result, 'vulnerable_lines', None)
            )
            outputs.append(output)
        return outputs
    
    async def analyze_vulnerabilities(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Analyze vulnerabilities in smart contract code.
        
        Args:
            request: Analysis request containing contract code and vulnerabilities
            
        Returns:
            Analysis response with results
            
        Raises:
            ValueError: If input validation fails
            Exception: If analysis fails
        """
        start_time = time.time()
        
        try:
            # Validate input
            if not self.validate_contract_code(request.contract_code):
                raise ValueError("Invalid or empty smart contract code provided")
            
            if not request.vulnerabilities:
                raise ValueError("No vulnerability names provided for analysis")

            logger.info(f"Starting analysis for {len(request.vulnerabilities)} vulnerability types")

            # Convert vulnerability names to detailed reports for analysis
            vulnerability_reports = self.convert_vulnerability_names_to_reports(request.vulnerabilities)
            vulnerability_names = [vuln.name for vuln in request.vulnerabilities]
            
            # Perform analysis
            results = self.analyzer.analyze_vulnerabilities(vulnerability_reports, request.contract_code)
            
            # Convert results to output models
            output_results = self.convert_results_to_output(results, vulnerability_names)

            # Calculate statistics
            found_count = sum(1 for result in results if result.is_valid)
            not_found_count = len(results) - found_count

            processing_time = time.time() - start_time

            logger.info(f"Analysis completed in {processing_time:.2f}s. Found: {found_count}, Not Found: {not_found_count}")

            return AnalysisResponse(
                success=True,
                total_checked=len(results),
                vulnerabilities_found=found_count,
                vulnerabilities_not_found=not_found_count,
                results=output_results,
                processing_time_seconds=round(processing_time, 2)
            )
            
        except ValueError as e:
            logger.error(f"Validation error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            raise Exception(f"Analysis failed: {str(e)}")
    
    def check_deepseek_api_status(self) -> str:
        """Check if DeepSeek API is accessible."""
        try:
            # Simple test to check API connectivity
            from deepseek_client import DeepSeekClient
            client = DeepSeekClient()
            
            # Try a minimal request to test connectivity
            test_response = client.analyze_vulnerability(
                "Test connectivity", 
                "pragma solidity ^0.8.0; contract Test {}"
            )
            
            if test_response is not None:
                return "connected"
            else:
                return "disconnected"
                
        except Exception as e:
            logger.warning(f"DeepSeek API check failed: {str(e)}")
            return "error"
