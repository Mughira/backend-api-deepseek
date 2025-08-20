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
    
    def convert_input_to_vulnerability_reports(self, vulnerabilities: List[VulnerabilityInput]) -> List[VulnerabilityReport]:
        """Convert API input models to internal vulnerability report models."""
        reports = []
        for vuln in vulnerabilities:
            report = VulnerabilityReport(
                id=vuln.id,
                description=vuln.description,
                severity=vuln.severity.value,
                category=vuln.category,
                line_numbers=vuln.line_numbers or []
            )
            reports.append(report)
        return reports
    
    def convert_results_to_output(self, results: List[AnalysisResult]) -> List[AnalysisResultOutput]:
        """Convert internal analysis results to API output models."""
        outputs = []
        for result in results:
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
            
            output = AnalysisResultOutput(
                vulnerability_id=result.vulnerability_id,
                is_valid=result.is_valid,
                confidence=confidence,
                explanation=result.explanation,
                issue_code=result.issue_code,
                fixed_code=result.fixed_code,
                recommendations=result.recommendations or [],
                vulnerability_type=getattr(result, 'vulnerability_type', ''),
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
                raise ValueError("No vulnerabilities provided for analysis")
            
            logger.info(f"Starting analysis of {len(request.vulnerabilities)} vulnerabilities")
            
            # Convert input models to internal models
            vulnerability_reports = self.convert_input_to_vulnerability_reports(request.vulnerabilities)
            
            # Perform analysis
            results = self.analyzer.analyze_vulnerabilities(vulnerability_reports, request.contract_code)
            
            # Convert results to output models
            output_results = self.convert_results_to_output(results)
            
            # Calculate statistics
            valid_count = sum(1 for result in results if result.is_valid)
            invalid_count = len(results) - valid_count
            false_positive_rate = (invalid_count / len(results)) * 100 if results else 0
            
            processing_time = time.time() - start_time
            
            logger.info(f"Analysis completed in {processing_time:.2f}s. Valid: {valid_count}, Invalid: {invalid_count}")
            
            return AnalysisResponse(
                success=True,
                total_analyzed=len(results),
                valid_vulnerabilities=valid_count,
                invalid_vulnerabilities=invalid_count,
                false_positive_rate=round(false_positive_rate, 2),
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
