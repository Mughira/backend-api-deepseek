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
        return f"""
Please analyze the following smart contract code for the reported vulnerability.

REPORTED VULNERABILITY:
{vulnerability_description}

SMART CONTRACT CODE:
```solidity
{smart_contract_code}
```

Please provide your analysis in the following JSON format:
{{
    "vulnerability_exists": true/false,
    "confidence_level": "high/medium/low",
    "explanation": "Detailed explanation of your analysis",
    "vulnerable_lines": [line_numbers_if_applicable],
    "vulnerability_type": "specific_vulnerability_category",
    "severity": "critical/high/medium/low",
    "issue_code": "code_snippet_showing_the_issue",
    "fixed_code": "corrected_code_snippet_if_vulnerability_exists",
    "recommendations": ["list", "of", "security", "recommendations"]
}}

Focus on:
1. Whether the reported vulnerability actually exists in the code
2. Exact line numbers where issues occur
3. Provide fixed code only if vulnerability is confirmed
4. Be precise and avoid false positives
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
