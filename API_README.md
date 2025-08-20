# Smart Contract Vulnerability Analyzer API

A REST API for analyzing smart contract vulnerabilities using DeepSeek AI. The API receives smart contract code and vulnerability reports, then returns detailed analysis results including validation status, issue code, and fixed code.

## 🚀 Quick Start

### Start API Server

```bash
# Using Docker (Recommended)
./docker-run.sh api

# Or with docker-compose
docker-compose up --build

# Or locally
python main.py --api
```

The API will be available at:
- **API Base URL**: `http://localhost:8000`
- **Interactive Docs**: `http://localhost:8000/docs`
- **Alternative Docs**: `http://localhost:8000/redoc`
- **Health Check**: `http://localhost:8000/health`

## 📡 API Endpoints

### POST /analyze
Analyze vulnerabilities in smart contract code.

**Request Body:**
```json
{
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
```

**Response:**
```json
{
  "success": true,
  "total_checked": 3,
  "vulnerabilities_found": 1,
  "vulnerabilities_not_found": 2,
  "processing_time_seconds": 2.5,
  "results": [
    {
      "vulnerability_name": "Reentrancy",
      "exists": true,
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
      "exists": false,
      "confidence": "high",
      "explanation": "No access control vulnerabilities found. Functions have appropriate visibility and access restrictions.",
      "issue_code": "",
      "fixed_code": "",
      "recommendations": [],
      "severity": null,
      "vulnerable_lines": null
    },
    {
      "vulnerability_name": "Integer Overflow",
      "exists": false,
      "confidence": "high",
      "explanation": "No integer overflow vulnerabilities found. Solidity 0.8.0+ has built-in overflow protection.",
      "issue_code": "",
      "fixed_code": "",
      "recommendations": [],
      "severity": null,
      "vulnerable_lines": null
    }
  ]
}
```

### GET /health
Check API health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime_seconds": 3600.5,
  "deepseek_status": "connected"
}
```

### GET /vulnerabilities/categories
Get supported vulnerability categories.

**Response:**
```json
[
  "Reentrancy",
  "Integer Overflow/Underflow",
  "Access Control",
  "Unchecked External Calls",
  "Denial of Service",
  "Front Running",
  "Time Manipulation",
  "Short Address Attack",
  "Uninitialized Storage Pointers",
  "Delegatecall Injection",
  "Signature Malleability",
  "Gas Limit Issues",
  "Random Number Generation",
  "Logic Errors"
]
```

## 💻 Using the API

### Python Client Example

```python
import requests

# API client
class VulnerabilityAnalyzerClient:
    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
    
    def analyze(self, contract_code, vulnerabilities):
        response = requests.post(
            f"{self.base_url}/analyze",
            json={
                "contract_code": contract_code,
                "vulnerabilities": vulnerabilities
            }
        )
        return response.json()

# Usage
client = VulnerabilityAnalyzerClient()

contract = """
pragma solidity ^0.8.0;
contract Example {
    mapping(address => uint256) public balances;
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount;
    }
}
"""

vulnerabilities = [
    {
        "id": "VULN-001",
        "description": "Reentrancy vulnerability in withdraw function",
        "severity": "critical",
        "category": "Reentrancy"
    }
]

result = client.analyze(contract, vulnerabilities)
print(f"Valid vulnerabilities: {result['valid_vulnerabilities']}")
```

### cURL Example

```bash
curl -X POST "http://localhost:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{
    "contract_code": "pragma solidity ^0.8.0;\ncontract Example {\n    mapping(address => uint256) public balances;\n    function withdraw(uint256 amount) public {\n        require(balances[msg.sender] >= amount);\n        (bool success, ) = msg.sender.call{value: amount}(\"\");\n        require(success);\n        balances[msg.sender] -= amount;\n    }\n}",
    "vulnerabilities": [
      {
        "id": "VULN-001",
        "description": "Reentrancy vulnerability in withdraw function",
        "severity": "critical",
        "category": "Reentrancy"
      }
    ]
  }'
```

### JavaScript/Node.js Example

```javascript
const axios = require('axios');

async function analyzeVulnerabilities() {
  try {
    const response = await axios.post('http://localhost:8000/analyze', {
      contract_code: `
        pragma solidity ^0.8.0;
        contract Example {
          mapping(address => uint256) public balances;
          function withdraw(uint256 amount) public {
            require(balances[msg.sender] >= amount);
            (bool success, ) = msg.sender.call{value: amount}("");
            require(success);
            balances[msg.sender] -= amount;
          }
        }
      `,
      vulnerabilities: [
        {
          id: "VULN-001",
          description: "Reentrancy vulnerability in withdraw function",
          severity: "critical",
          category: "Reentrancy"
        }
      ]
    });
    
    console.log('Analysis Results:', response.data);
  } catch (error) {
    console.error('Error:', error.response?.data || error.message);
  }
}

analyzeVulnerabilities();
```

## 🔧 Configuration

### Environment Variables

```bash
DEEPSEEK_API_KEY=sk-87457878984f4e6fa51eed224ee46f6f
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
MODEL_NAME=deepseek-chat
MAX_TOKENS=4000
TEMPERATURE=0.1
```

### Docker Environment

```yaml
# docker-compose.yml
environment:
  - DEEPSEEK_API_KEY=your-api-key
  - DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
  - MODEL_NAME=deepseek-chat
  - MAX_TOKENS=4000
  - TEMPERATURE=0.1
```

## 🧪 Testing

### Test API Endpoints

```bash
# Test with provided client
python api_client_example.py

# Test specific endpoints
python api_client_example.py test

# Using Docker
./docker-run.sh test-api
```

### Health Check

```bash
curl http://localhost:8000/health
```

## 📊 Response Format

### Success Response
- `success`: Boolean indicating if analysis was successful
- `total_analyzed`: Number of vulnerabilities analyzed
- `valid_vulnerabilities`: Number of confirmed vulnerabilities
- `invalid_vulnerabilities`: Number of false positives
- `false_positive_rate`: Percentage of false positives
- `processing_time_seconds`: Time taken for analysis
- `results`: Array of detailed analysis results

### Error Response
- `success`: Always false for errors
- `error`: Human-readable error message
- `error_code`: Machine-readable error code
- `details`: Additional error information (optional)

## 🚀 Deployment

### Production Deployment

```bash
# Build production image
docker build -t vulnerability-analyzer:prod .

# Run with production settings
docker run -d \
  --name vulnerability-analyzer \
  -p 8000:8000 \
  -e DEEPSEEK_API_KEY=your-production-key \
  --restart unless-stopped \
  vulnerability-analyzer:prod
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerability-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vulnerability-analyzer
  template:
    metadata:
      labels:
        app: vulnerability-analyzer
    spec:
      containers:
      - name: api
        image: vulnerability-analyzer:prod
        ports:
        - containerPort: 8000
        env:
        - name: DEEPSEEK_API_KEY
          valueFrom:
            secretKeyRef:
              name: api-secrets
              key: deepseek-api-key
---
apiVersion: v1
kind: Service
metadata:
  name: vulnerability-analyzer-service
spec:
  selector:
    app: vulnerability-analyzer
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

## 🔒 Security Considerations

1. **API Key Protection**: Store API keys securely using environment variables or secrets management
2. **Rate Limiting**: Implement rate limiting for production use
3. **Input Validation**: API includes comprehensive input validation
4. **CORS**: Configure CORS settings appropriately for your domain
5. **HTTPS**: Use HTTPS in production environments
6. **Authentication**: Consider adding authentication for production use

## 📈 Monitoring

### Health Checks
- Built-in health check endpoint at `/health`
- Docker health checks included
- Monitors DeepSeek API connectivity

### Logging
- Structured logging with timestamps
- Request/response logging
- Error tracking and reporting

### Metrics
- Processing time tracking
- Success/failure rates
- API usage statistics
