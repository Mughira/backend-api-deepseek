# Docker Usage Guide for Smart Contract Vulnerability Analyzer

This guide explains how to build and run the Smart Contract Vulnerability Analyzer using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose (usually included with Docker Desktop)

## Quick Start

### 1. Build and Run with Docker Compose (Recommended)

```bash
# Build and start the container
docker-compose up --build

# Run in detached mode
docker-compose up -d --build

# View logs
docker-compose logs -f vulnerability-analyzer
```

### 2. Build and Run with Docker Commands

```bash
# Build the image
docker build -t smart-contract-analyzer .

# Run interactively
docker run -it --rm smart-contract-analyzer

# Run with sample data
docker run --rm smart-contract-analyzer python main.py --sample
```

## Usage Modes

### Interactive Mode (Default)

```bash
# Using docker-compose
docker-compose run --rm vulnerability-analyzer

# Using docker directly
docker run -it --rm smart-contract-analyzer
```

### Sample Data Mode

```bash
# Using docker-compose
docker-compose run --rm vulnerability-analyzer python main.py --sample

# Using docker directly
docker run --rm smart-contract-analyzer python main.py --sample
```

### File Analysis Mode

First, create the required directories and place your files:

```bash
# Create directories
mkdir -p input output results

# Copy your files
cp your_contract.sol input/
cp your_vulnerabilities.json input/
```

Then run the analysis:

```bash
# Using docker-compose
docker-compose run --rm vulnerability-analyzer \
  python main.py --contract input/your_contract.sol --vulnerabilities input/your_vulnerabilities.json --output results/analysis_results.json

# Using docker directly
docker run --rm \
  -v $(pwd)/input:/app/input:ro \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/results:/app/results \
  smart-contract-analyzer \
  python main.py --contract input/your_contract.sol --vulnerabilities input/your_vulnerabilities.json --output results/analysis_results.json
```

## Volume Mounts

The Docker setup includes several volume mounts for easy file access:

- `./input:/app/input:ro` - Read-only input directory for contract files and vulnerability reports
- `./output:/app/output` - Output directory for temporary files
- `./results:/app/results` - Results directory for analysis outputs

## Environment Variables

You can customize the application behavior using environment variables:

```bash
# Create a custom .env file
cat > .env << EOF
DEEPSEEK_API_KEY=your-api-key-here
DEEPSEEK_BASE_URL=https://api.deepseek.com/v1
MODEL_NAME=deepseek-chat
MAX_TOKENS=4000
TEMPERATURE=0.1
EOF

# Run with custom environment
docker-compose --env-file .env up
```

## Development Mode

For development, you can mount the source code as a volume:

```bash
# Add to docker-compose.yml under volumes:
# - .:/app

# Or run directly:
docker run -it --rm \
  -v $(pwd):/app \
  -w /app \
  python:3.11-slim \
  bash -c "pip install -r requirements.txt && python main.py --sample"
```

## Running Tests

```bash
# Run the test suite
docker-compose run --rm vulnerability-analyzer python test_analyzer.py

# Or with docker directly
docker run --rm smart-contract-analyzer python test_analyzer.py
```

## Useful Docker Commands

### Container Management

```bash
# List running containers
docker-compose ps

# Stop all services
docker-compose down

# Remove containers and volumes
docker-compose down -v

# View container logs
docker-compose logs vulnerability-analyzer

# Execute commands in running container
docker-compose exec vulnerability-analyzer bash
```

### Image Management

```bash
# List images
docker images

# Remove the built image
docker rmi smart-contract-analyzer

# Rebuild without cache
docker-compose build --no-cache
```

### Cleanup

```bash
# Remove stopped containers, unused networks, images, and build cache
docker system prune -a

# Remove only unused containers and networks
docker system prune
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER input output results
   ```

2. **API Connection Issues**
   ```bash
   # Check if API key is correctly set
   docker-compose run --rm vulnerability-analyzer env | grep DEEPSEEK
   ```

3. **Out of Memory Errors**
   ```bash
   # Increase Docker memory limit in Docker Desktop settings
   # Or run with memory limit
   docker run --memory=2g --rm smart-contract-analyzer
   ```

4. **File Not Found Errors**
   ```bash
   # Ensure files are in the correct directories
   ls -la input/
   ls -la output/
   ls -la results/
   ```

### Debug Mode

```bash
# Run with debug output
docker-compose run --rm vulnerability-analyzer python -u main.py --sample

# Access container shell for debugging
docker-compose run --rm vulnerability-analyzer bash
```

## Production Deployment

For production deployment, consider:

1. **Security**: Use secrets management for API keys
2. **Scaling**: Use Docker Swarm or Kubernetes
3. **Monitoring**: Add health checks and logging
4. **Persistence**: Use named volumes for important data

Example production docker-compose.yml additions:

```yaml
services:
  vulnerability-analyzer:
    # ... existing config ...
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
    secrets:
      - deepseek_api_key
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

secrets:
  deepseek_api_key:
    external: true
```

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
name: Vulnerability Analysis
on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build and test
        run: |
          docker build -t analyzer .
          docker run --rm analyzer python test_analyzer.py
```
