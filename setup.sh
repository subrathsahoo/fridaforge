#!/bin/bash

# VAPT Mobile Analyzer - Setup Script
# Author: Automated Security Tool
# Version: 1.0.0

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════╗"
echo "║        ⚔️  FRIDAFORGE SETUP  ⚔️                ║"
echo "║                                               ║"
echo "║  AI-Powered Mobile Security Analysis Tool     ║"
echo "║  Where Code Meets Bypasses                    ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running on Ubuntu/Debian
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    echo -e "${GREEN}✓ Detected OS: $OS${NC}"
else
    echo -e "${RED}✗ Unable to detect OS. This script is designed for Ubuntu/Debian.${NC}"
    exit 1
fi

# Check if running as root for system packages
if [ "$EUID" -eq 0 ]; then
    echo -e "${YELLOW}⚠ Running as root. This is acceptable for initial setup.${NC}"
fi

echo -e "\n${BLUE}[1/8] Checking system requirements...${NC}"

# Check Python 3.8+
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
    echo -e "${GREEN}✓ Python $PYTHON_VERSION installed${NC}"
else
    echo -e "${RED}✗ Python 3 not found${NC}"
    exit 1
fi

# Check Java (required for JADX and Apktool)
if command -v java &> /dev/null; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2)
    echo -e "${GREEN}✓ Java $JAVA_VERSION installed${NC}"
else
    echo -e "${YELLOW}⚠ Java not found. Installing OpenJDK...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y openjdk-17-jdk wget unzip
fi

echo -e "\n${BLUE}[2/8] Installing system dependencies...${NC}"
sudo apt-get update -qq
sudo apt-get install -y \
    python3-pip \
    python3-venv \
    wget \
    unzip \
    libmagic1 \
    mongodb \
    curl \
    git

echo -e "${GREEN}✓ System dependencies installed${NC}"

echo -e "\n${BLUE}[3/8] Setting up decompilation tools...${NC}"

# Install JADX
if [ ! -f "/opt/jadx/bin/jadx" ]; then
    echo "Installing JADX..."
    cd /opt
    sudo wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip
    sudo unzip -q jadx-1.5.1.zip -d jadx
    sudo rm jadx-1.5.1.zip
    sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    echo -e "${GREEN}✓ JADX installed${NC}"
else
    echo -e "${GREEN}✓ JADX already installed${NC}"
fi

# Install Apktool
if [ ! -f "/usr/local/bin/apktool" ]; then
    echo "Installing Apktool..."
    cd /opt
    sudo wget -q https://github.com/iBotPeaches/Apktool/releases/download/v2.10.0/apktool_2.10.0.jar
    sudo mv apktool_2.10.0.jar apktool.jar
    echo '#!/bin/bash' | sudo tee /usr/local/bin/apktool > /dev/null
    echo 'java -jar /opt/apktool.jar "$@"' | sudo tee -a /usr/local/bin/apktool > /dev/null
    sudo chmod +x /usr/local/bin/apktool
    echo -e "${GREEN}✓ Apktool installed${NC}"
else
    echo -e "${GREEN}✓ Apktool already installed${NC}"
fi

# Verify installations
jadx --version > /dev/null 2>&1 && echo -e "${GREEN}✓ JADX verified${NC}"
apktool --version > /dev/null 2>&1 && echo -e "${GREEN}✓ Apktool verified${NC}"

echo -e "\n${BLUE}[4/8] Setting up Python virtual environment...${NC}"
cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment exists${NC}"
fi

echo -e "\n${BLUE}[5/8] Installing Python dependencies...${NC}"
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "${GREEN}✓ Python dependencies installed${NC}"

echo -e "\n${BLUE}[6/8] Setting up MongoDB...${NC}"
sudo systemctl start mongodb || sudo service mongodb start
sudo systemctl enable mongodb || echo "MongoDB service enabled"
echo -e "${GREEN}✓ MongoDB started${NC}"

echo -e "\n${BLUE}[7/8] Creating necessary directories...${NC}"
mkdir -p uploads
mkdir -p temp
mkdir -p logs
mkdir -p database
echo -e "${GREEN}✓ Directories created${NC}"

echo -e "\n${BLUE}[8/8] Configuring environment...${NC}"
if [ ! -f ".env" ]; then
    cat > .env << EOF
# VAPT Mobile Analyzer Configuration
MONGO_URL=mongodb://localhost:27017
DB_NAME=vapt_mobile_analyzer
EMERGENT_LLM_KEY=sk-emergent-2A7FcC7D5433bFdC80
HOST=0.0.0.0
PORT=8000
UPLOAD_DIR=./uploads
TEMP_DIR=./temp
LOG_DIR=./logs
MAX_FILE_SIZE=1073741824
EOF
    echo -e "${GREEN}✓ Configuration file created${NC}"
else
    echo -e "${GREEN}✓ Configuration file exists${NC}"
fi

echo -e "\n${GREEN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║         ✅ FRIDAFORGE READY!  ⚔️               ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${YELLOW}🚀 Start FridaForge:${NC}"
echo -e "${BLUE}   ./run.sh${NC}"
echo ""
echo -e "${YELLOW}🌐 Open in browser:${NC}"
echo -e "${BLUE}   http://localhost:8000${NC}"
echo ""
echo -e "${YELLOW}📖 Get help:${NC}"
echo -e "${BLUE}   ./run.sh --help${NC}"
echo ""
echo -e "${GREEN}⚔️  Happy Security Testing!${NC}"
echo ""