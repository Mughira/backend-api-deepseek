#!/bin/bash

# Smart Contract Vulnerability Analyzer - Docker Runner Script
# This script provides easy commands to build and run the analyzer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
}

# Function to create necessary directories
setup_directories() {
    print_status "Creating necessary directories..."
    mkdir -p input output results
    print_success "Directories created: input/, output/, results/"
}

# Function to build the Docker image
build_image() {
    print_status "Building Docker image..."
    docker build -t smart-contract-analyzer .
    print_success "Docker image built successfully!"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    docker run --rm smart-contract-analyzer python test_analyzer.py
    print_success "Tests completed!"
}

# Function to run with sample data
run_sample() {
    print_status "Running analyzer with sample data..."
    docker run --rm smart-contract-analyzer python main.py --sample
    print_success "Sample analysis completed!"
}

# Function to run in interactive mode
run_interactive() {
    print_status "Starting interactive mode..."
    setup_directories
    docker run -it --rm \
        -v "$(pwd)/input:/app/input:ro" \
        -v "$(pwd)/output:/app/output" \
        -v "$(pwd)/results:/app/results" \
        smart-contract-analyzer
}

# Function to analyze specific files
run_analysis() {
    if [ $# -lt 2 ]; then
        print_error "Usage: $0 analyze <contract_file> <vulnerabilities_file> [output_file]"
        exit 1
    fi
    
    local contract_file="$1"
    local vuln_file="$2"
    local output_file="${3:-analysis_results.json}"
    
    # Check if files exist
    if [ ! -f "input/$contract_file" ]; then
        print_error "Contract file not found: input/$contract_file"
        exit 1
    fi
    
    if [ ! -f "input/$vuln_file" ]; then
        print_error "Vulnerabilities file not found: input/$vuln_file"
        exit 1
    fi
    
    print_status "Analyzing $contract_file with vulnerabilities from $vuln_file..."
    setup_directories
    
    docker run --rm \
        -v "$(pwd)/input:/app/input:ro" \
        -v "$(pwd)/output:/app/output" \
        -v "$(pwd)/results:/app/results" \
        smart-contract-analyzer \
        python main.py --contract "input/$contract_file" --vulnerabilities "input/$vuln_file" --output "results/$output_file"
    
    print_success "Analysis completed! Results saved to results/$output_file"
}

# Function to run with docker-compose
run_compose() {
    print_status "Starting with docker-compose..."
    setup_directories
    docker-compose up --build
}

# Function to clean up Docker resources
cleanup() {
    print_status "Cleaning up Docker resources..."
    
    # Stop and remove containers
    docker-compose down 2>/dev/null || true
    
    # Remove the image
    docker rmi smart-contract-analyzer 2>/dev/null || true
    
    # Clean up system
    docker system prune -f
    
    print_success "Cleanup completed!"
}

# Function to show usage
show_usage() {
    echo "Smart Contract Vulnerability Analyzer - Docker Runner"
    echo ""
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  build                           Build the Docker image"
    echo "  test                           Run tests"
    echo "  sample                         Run with sample data"
    echo "  interactive                    Run in interactive mode"
    echo "  analyze <contract> <vulns>     Analyze specific files"
    echo "  compose                        Run with docker-compose"
    echo "  cleanup                        Clean up Docker resources"
    echo "  help                           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 sample"
    echo "  $0 interactive"
    echo "  $0 analyze contract.sol vulnerabilities.json"
    echo "  $0 compose"
    echo ""
    echo "File locations:"
    echo "  Place input files in: ./input/"
    echo "  Results will be in: ./results/"
    echo "  Temporary files in: ./output/"
}

# Main script logic
main() {
    check_docker
    
    case "${1:-help}" in
        "build")
            build_image
            ;;
        "test")
            build_image
            run_tests
            ;;
        "sample")
            build_image
            run_sample
            ;;
        "interactive")
            build_image
            run_interactive
            ;;
        "analyze")
            build_image
            shift
            run_analysis "$@"
            ;;
        "compose")
            run_compose
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|"--help"|"-h")
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
