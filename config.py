"""Configuration settings for the Smart Contract Vulnerability Analyzer."""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# DeepSeek API Configuration
DEEPSEEK_API_KEY = "sk-87457878984f4e6fa51eed224ee46f6f"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"

# Model configuration
MODEL_NAME = "deepseek-chat"
MAX_TOKENS = 4000
TEMPERATURE = 0.1  # Low temperature for more consistent analysis

# Vulnerability categories to check
VULNERABILITY_CATEGORIES = [
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
