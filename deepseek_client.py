"""DeepSeek API client for smart contract vulnerability analysis."""

import requests
import json
from typing import Dict, Any, Optional
from config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, MODEL_NAME, MAX_TOKENS, TEMPERATURE


class DeepSeekClient:
    """Client for interacting with DeepSeek API."""
    
    def __init__(self):
        self.api_key = DEEPSEEK_API_KEY
        self.base_url = DEEPSEEK_BASE_URL
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def analyze_vulnerability(self, vulnerability_description: str, smart_contract_code: str) -> Optional[Dict[str, Any]]:
        """
        Analyze if a reported vulnerability is actually present in the smart contract code.
        
        Args:
            vulnerability_description: Description of the reported vulnerability
            smart_contract_code: The smart contract source code
            
        Returns:
            Dictionary containing analysis results or None if API call fails
        """
        prompt = self._create_analysis_prompt(vulnerability_description, smart_contract_code)
        
        payload = {
            "model": MODEL_NAME,
            "messages": [
                {
                    "role": "system",
                    "content": "You are an expert smart contract security auditor. Analyze the provided code and vulnerability report with extreme precision."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": MAX_TOKENS,
            "temperature": TEMPERATURE,
            "stream": False
        }
        
        try:
            response = requests.post(
                f"{self.base_url}/chat/completions",
                headers=self.headers,
                json=payload,
                timeout=60
            )
            response.raise_for_status()
            
            result = response.json()
            return self._parse_response(result)
            
        except requests.exceptions.RequestException as e:
            print(f"API request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Failed to parse API response: {e}")
            return None
    
    def _create_analysis_prompt(self, vulnerability_description: str, smart_contract_code: str) -> str:
        """Create a detailed prompt for vulnerability analysis."""
        # Extract vulnerability type from description
        vuln_type = vulnerability_description.split("Check for ")[1].split(" vulnerabilities")[0] if "Check for " in vulnerability_description else "unknown"

        return f"""
You are an expert smart contract security auditor. Analyze the following Solidity code to determine if it contains the specified vulnerability type.

VULNERABILITY TYPE TO CHECK: {vuln_type}

SMART CONTRACT CODE:
```solidity
{smart_contract_code}
```

ANALYSIS TASK:
{vulnerability_description}

Please provide your analysis in the following JSON format:
{{
    "vulnerability_exists": true/false,
    "confidence_level": "high/medium/low",
    "explanation": "Detailed explanation of your analysis and findings",
    "vulnerable_lines": [line_numbers_if_vulnerability_found],
    "severity": "critical/high/medium/low",
    "issue_code": "exact_code_snippet_showing_the_vulnerability",
    "fixed_code": "corrected_code_snippet_if_vulnerability_exists",
    "recommendations": ["specific", "actionable", "security", "recommendations"]
}}

ANALYSIS GUIDELINES:
1. Carefully examine the code for the specific vulnerability type mentioned
2. If the vulnerability exists, provide the exact vulnerable code and line numbers
3. If the vulnerability exists, provide a corrected version of the code
4. If the vulnerability does NOT exist, clearly state why it's not present
5. Be precise and avoid false positives - only report vulnerabilities that actually exist
6. Consider the specific patterns and characteristics of {vuln_type} vulnerabilities
7. Provide actionable recommendations for improvement

RESPOND ONLY WITH THE JSON - NO ADDITIONAL TEXT.
"""
    
    def _parse_response(self, response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse the API response and extract the analysis."""
        try:
            content = response["choices"][0]["message"]["content"]
            
            # Try to extract JSON from the response
            start_idx = content.find('{')
            end_idx = content.rfind('}') + 1
            
            if start_idx != -1 and end_idx != 0:
                json_str = content[start_idx:end_idx]
                return json.loads(json_str)
            else:
                # If no JSON found, return raw content
                return {"raw_response": content}
                
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            print(f"Failed to parse response: {e}")
            return {"error": "Failed to parse API response", "raw_response": str(response)}
