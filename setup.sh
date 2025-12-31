#!/bin/bash
# PayloadZer0 - KEV Threat Scanner Setup Script
# Automates installation and initial configuration

set -e

echo "=================================="
echo "PayloadZer0 - KEV Threat Scanner Setup"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Error: Do not run this script as root${NC}"
   exit 1
fi

# Check Python version
echo -e "${YELLOW}[1/6] Checking Python version...${NC}"
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check Go installation
echo -e "${YELLOW}[2/6] Checking Go installation...${NC}"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓ Go $GO_VERSION found${NC}"
else
    echo -e "${RED}✗ Go not found. Install from: https://golang.org/dl/${NC}"
    echo "After installing Go, run this script again."
    exit 1
fi

# Install/Check Nuclei
echo -e "${YELLOW}[3/6] Installing/Checking Nuclei...${NC}"
if command -v nuclei &> /dev/null; then
    NUCLEI_VERSION=$(nuclei -version 2>&1 | head -n 1)
    echo -e "${GREEN}✓ Nuclei already installed: $NUCLEI_VERSION${NC}"
else
    echo "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Add Go bin to PATH if needed
    if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin
    fi
    
    if command -v nuclei &> /dev/null; then
        echo -e "${GREEN}✓ Nuclei installed successfully${NC}"
    else
        echo -e "${RED}✗ Nuclei installation failed${NC}"
        echo "Please ensure $HOME/go/bin is in your PATH"
        exit 1
    fi
fi

# Install Python dependencies
echo -e "${YELLOW}[4/6] Installing Python dependencies...${NC}"
pip3 install -q -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Update Nuclei templates
echo -e "${YELLOW}[5/6] Updating Nuclei templates...${NC}"
nuclei -update-templates -silent
echo -e "${GREEN}✓ Nuclei templates updated${NC}"

# Create necessary directories
echo -e "${YELLOW}[6/6] Setting up directories...${NC}"
mkdir -p scan_results
mkdir -p logs

# Create hosts file if it doesn't exist
if [ ! -f "hosts.txt" ]; then
    cp hosts.txt.example hosts.txt
    echo -e "${YELLOW}⚠ Created hosts.txt from example - please edit with your targets${NC}"
fi

# Make script executable
chmod +x payloadZer0.py

echo ""
echo -e "${GREEN}=================================="
echo "Setup Complete!"
echo "==================================${NC}"
echo ""
echo "Next steps:"
echo ""
echo "1. Edit hosts.txt with your target hosts:"
echo "   nano hosts.txt"
echo ""
echo "2. (Optional) Set up Teams notifications:"
echo "   export TEAMS_WEBHOOK_URL='https://outlook.office.com/webhook/YOUR_URL'"
echo ""
echo "3. Run a test scan:"
echo "   python3 payloadZer0.py -t hosts.txt --force-scan"
echo ""
echo "4. Start continuous monitoring:"
echo "   python3 payloadZer0.py -t hosts.txt --continuous --interval 3600"
echo ""
echo "For more options, see: ./payloadZer0.py --help"
echo ""

# Test Nuclei and Python script
echo -e "${YELLOW}Running quick verification...${NC}"
if python3 -c "import requests; print('Python dependencies OK')"; then
    echo -e "${GREEN}✓ Python environment verified${NC}"
else
    echo -e "${RED}✗ Python environment issue detected${NC}"
fi

if nuclei -version > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Nuclei verified${NC}"
else
    echo -e "${RED}✗ Nuclei verification failed${NC}"
fi

echo ""
echo -e "${GREEN}All systems ready!${NC}"
