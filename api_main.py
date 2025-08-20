"""FastAPI application for Smart Contract Vulnerability Analyzer."""

import time
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from api_models import (
    AnalysisRequest, AnalysisResponse, ErrorResponse, HealthResponse
)
from api_service import VulnerabilityAnalysisService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global service instance
service = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global service
    logger.info("Starting Smart Contract Vulnerability Analyzer API...")
    
    # Initialize service
    service = VulnerabilityAnalysisService()
    logger.info("Service initialized successfully")
    
    yield
    
    logger.info("Shutting down Smart Contract Vulnerability Analyzer API...")


# Create FastAPI application
app = FastAPI(
    title="Smart Contract Vulnerability Analyzer API",
    description="API for analyzing smart contract vulnerabilities using DeepSeek AI",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom exception handler
@app.exception_handler(ValueError)
async def validation_exception_handler(request: Request, exc: ValueError):
    """Handle validation errors."""
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error=str(exc),
            error_code="VALIDATION_ERROR"
        ).dict()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error occurred",
            error_code="INTERNAL_ERROR",
            details={"message": str(exc)}
        ).dict()
    )


# Middleware for request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all requests."""
    start_time = time.time()
    
    # Log request
    logger.info(f"Request: {request.method} {request.url}")
    
    response = await call_next(request)
    
    # Log response
    process_time = time.time() - start_time
    logger.info(f"Response: {response.status_code} - {process_time:.2f}s")
    
    return response


@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Smart Contract Vulnerability Analyzer API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "analyze": "/analyze"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    global service
    
    if service is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    # Check DeepSeek API status
    api_status = service.check_deepseek_api_status()
    
    return HealthResponse(
        status="healthy" if api_status == "connected" else "degraded",
        version="1.0.0",
        uptime_seconds=round(service.get_uptime(), 2),
        deepseek_status=api_status
    )


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_vulnerabilities(request: AnalysisRequest):
    """
    Analyze smart contract for specific vulnerability types.

    This endpoint takes smart contract code and a list of vulnerability names to check for,
    then uses DeepSeek AI to determine which vulnerabilities exist in the code and provides
    issue code and fixed code for any vulnerabilities found.

    **Request Format:**
    - `contract_code`: Solidity smart contract source code
    - `vulnerabilities`: Array of vulnerability names to check for (e.g., "Reentrancy", "Access Control")

    **Response Format:**
    - Returns analysis results showing which vulnerabilities exist and which don't
    - Provides issue code and fixed code for vulnerabilities found
    - Includes confidence levels and security recommendations
    """
    global service
    
    if service is None:
        raise HTTPException(status_code=503, detail="Service not initialized")
    
    try:
        logger.info(f"Received analysis request to check for {len(request.vulnerabilities)} vulnerability types")

        # Perform analysis
        result = await service.analyze_vulnerabilities(request)

        logger.info(f"Analysis completed successfully. Found: {result.vulnerabilities_found}, Not Found: {result.vulnerabilities_not_found}")
        
        return result
        
    except ValueError as e:
        logger.warning(f"Validation error in analysis request: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/vulnerabilities/categories", response_model=list)
async def get_vulnerability_categories():
    """Get list of supported vulnerability categories."""
    from config import VULNERABILITY_CATEGORIES
    return VULNERABILITY_CATEGORIES


@app.get("/api-info", response_model=dict)
async def get_api_info():
    """Get detailed API information and usage examples."""
    return {
        "title": "Smart Contract Vulnerability Analyzer API",
        "version": "1.0.0",
        "description": "API for analyzing smart contract vulnerabilities using DeepSeek AI",
        "endpoints": {
            "POST /analyze": "Analyze vulnerabilities in smart contract code",
            "GET /health": "Check API health status",
            "GET /vulnerabilities/categories": "Get supported vulnerability categories",
            "GET /docs": "Interactive API documentation",
            "GET /redoc": "Alternative API documentation"
        },
        "example_request": {
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
        },
        "supported_formats": {
            "input": "JSON with contract_code and vulnerabilities array containing vulnerability names",
            "output": "JSON with analysis results showing which vulnerabilities exist, with issue code and fixed code"
        },
        "supported_vulnerability_types": [
            "Reentrancy", "Access Control", "Integer Overflow", "Unchecked External Calls",
            "Denial of Service", "Front Running", "Time Manipulation", "Short Address Attack",
            "Uninitialized Storage Pointers", "Delegatecall Injection", "Signature Malleability",
            "Gas Limit Issues", "Random Number Generation", "Logic Errors", "Tx.Origin",
            "Unchecked Return Values", "State Variable Default Visibility", "Floating Pragma",
            "Outdated Compiler Version", "Function Default Visibility", "Unprotected Ether Withdrawal",
            "Unprotected SELFDESTRUCT", "Assert Violation", "Deprecated Solidity Functions",
            "Centralization Risk", "Price Oracle Manipulation", "Flash Loan Attack", "MEV"
        ]
    }


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title="Smart Contract Vulnerability Analyzer API",
        version="1.0.0",
        description="""
        ## Smart Contract Vulnerability Analyzer API
        
        This API analyzes smart contract vulnerabilities using DeepSeek AI to determine:
        - Whether reported vulnerabilities actually exist in the code
        - Confidence level of the analysis
        - Specific code snippets showing issues
        - Fixed code snippets for confirmed vulnerabilities
        - Security recommendations
        
        ### Key Features:
        - **Vulnerability Validation**: Filters out false positives
        - **Code Analysis**: Provides specific issue and fixed code
        - **AI-Powered**: Uses DeepSeek AI for expert-level analysis
        - **Comprehensive Results**: Detailed explanations and recommendations
        
        ### Usage:
        1. Send POST request to `/analyze` with contract code and vulnerability reports
        2. Receive detailed analysis results with validation status
        3. Use the provided fixed code to address confirmed vulnerabilities
        """,
        routes=app.routes,
    )
    
    # Add custom tags
    openapi_schema["tags"] = [
        {
            "name": "Analysis",
            "description": "Vulnerability analysis operations"
        },
        {
            "name": "Health",
            "description": "Health check and status operations"
        },
        {
            "name": "Information",
            "description": "API information and metadata"
        }
    ]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting Smart Contract Vulnerability Analyzer API server...")
    
    uvicorn.run(
        "api_main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
