# Smart Contract Vulnerability Analyzer

A Python application that analyzes smart contract vulnerabilities using the DeepSeek API. The application takes vulnerability reports and smart contract code, determines whether the vulnerabilities are valid, and provides issue code and fixed code for confirmed vulnerabilities.

## Features

- **Vulnerability Validation**: Determines if reported vulnerabilities actually exist in the code
- **False Positive Detection**: Identifies and filters out incorrect vulnerability reports
- **Code Analysis**: Provides specific code snippets showing issues
- **Automated Fixes**: Generates corrected code for confirmed vulnerabilities
- **Detailed Reporting**: Exports comprehensive analysis results
- **Interactive Mode**: User-friendly interface for manual input
- **Batch Processing**: Analyze multiple vulnerabilities at once

## Installation

### Option 1: Docker (Recommended)

1. Clone or download the project files
2. Build and run with Docker:

```bash
# Quick start with sample data
./docker-run.sh sample

# Interactive mode
./docker-run.sh interactive

# Or use docker-compose
docker-compose up --build
```

### Option 2: Local Python Installation

1. Clone or download the project files
2. Install required dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

The application uses the DeepSeek API with the provided API key. The configuration is set in `config.py`:

- API Key: `sk-87457878984f4e6fa51eed224ee46f6f`
- Model: `deepseek-chat`
- Base URL: `https://api.deepseek.com/v1`

## Usage

### Docker Usage (Recommended)

```bash
# Quick test with sample data
./docker-run.sh sample

# Interactive mode
./docker-run.sh interactive

# Analyze specific files (place them in ./input/ directory first)
./docker-run.sh analyze contract.sol vulnerabilities.json

# Run tests
./docker-run.sh test

# Using docker-compose
docker-compose up --build
```

### Local Python Usage

#### Interactive Mode (Recommended for beginners)

```bash
python main.py --interactive
```

This will guide you through:
1. Selecting a smart contract file
2. Choosing vulnerability input method (JSON file, sample data, or manual entry)
3. Running the analysis
4. Exporting results

#### Command Line Mode

```bash
python main.py --contract sample_contract.sol --vulnerabilities sample_vulnerabilities.json
```

#### Sample Data Mode (for testing)

```bash
python main.py --sample
```

### Command Line Options

- `--contract, -c`: Path to smart contract file (.sol)
- `--vulnerabilities, -v`: Path to vulnerabilities JSON file
- `--output, -o`: Output file for results (default: vulnerability_analysis_results.json)
- `--interactive, -i`: Run in interactive mode
- `--sample, -s`: Use sample data for testing

## Input Formats

### Smart Contract File
Standard Solidity (.sol) files are supported.

### Vulnerabilities JSON Format

```json
{
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "description": "Detailed description of the vulnerability",
      "severity": "critical|high|medium|low",
      "category": "Reentrancy|Access Control|etc.",
      "line_numbers": [1, 2, 3]
    }
  ]
}
```

## Output

The application provides:

1. **Console Output**: Real-time analysis with colored status indicators
2. **JSON Export**: Detailed results including:
   - Vulnerability validation status
   - Confidence levels
   - Explanations
   - Issue code snippets
   - Fixed code snippets
   - Security recommendations

### Sample Output

```
Analyzing vulnerability 1/3: VULN-001
Vulnerability ID: VULN-001
Status: VALID
Confidence: high
Explanation: Reentrancy vulnerability confirmed in withdraw function...
Issue Code: [vulnerable code snippet]
Fixed Code: [corrected code snippet]
Recommendations:
  • Use checks-effects-interactions pattern
  • Implement reentrancy guard
```

## Example Files

The project includes sample files for testing:

- `sample_contract.sol`: A vulnerable smart contract for testing
- `sample_vulnerabilities.json`: Sample vulnerability reports

## Vulnerability Categories Supported

- Reentrancy
- Integer Overflow/Underflow
- Access Control
- Unchecked External Calls
- Denial of Service
- Front Running
- Time Manipulation
- Short Address Attack
- Uninitialized Storage Pointers
- Delegatecall Injection
- Signature Malleability
- Gas Limit Issues
- Random Number Generation
- Logic Errors

## API Integration

The application uses the DeepSeek API for intelligent vulnerability analysis. The API provides:

- Expert-level smart contract security analysis
- Precise vulnerability detection
- Code-specific recommendations
- Automated fix generation

## Error Handling

The application includes comprehensive error handling for:
- API connection issues
- Invalid file formats
- Malformed JSON
- Missing files
- Network timeouts

## Contributing

To extend the application:

1. Add new vulnerability categories in `config.py`
2. Enhance the analysis prompt in `deepseek_client.py`
3. Add new output formats in `vulnerability_analyzer.py`
4. Extend the CLI interface in `main.py`

## License

This project is provided as-is for educational and research purposes.
