#!/bin/bash

# VAPT Mobile Analyzer - Run Script
# Author: Automated Security Tool
# Version: 1.0.0

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

cd "$(dirname "$0")"

if [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
    echo -e "${BLUE}"
    echo "VAPT Mobile Analyzer - Usage"
    echo "============================="
    echo -e "${NC}"
    echo "./run.sh              - Start the analyzer"
    echo "./run.sh --dev        - Start in development mode with auto-reload"
    echo "./run.sh --stop       - Stop the analyzer"
    echo "./run.sh --status     - Check service status"
    echo "./run.sh --logs       - View logs"
    echo "./run.sh --help       - Show this help"
    exit 0
fi

if [ "$1" == "--stop" ]; then
    echo -e "${YELLOW}Stopping VAPT Mobile Analyzer...${NC}"
    pkill -f "uvicorn backend.server:app" || echo "No running instance found"
    exit 0
fi

if [ "$1" == "--status" ]; then
    if pgrep -f "uvicorn backend.server:app" > /dev/null; then
        echo -e "${GREEN}✓ VAPT Mobile Analyzer is running${NC}"
        echo -e "${BLUE}Access at: http://localhost:9090${NC}"
    else
        echo -e "${RED}✗ VAPT Mobile Analyzer is not running${NC}"
    fi
    exit 0
fi

if [ "$1" == "--logs" ]; then
    tail -f logs/app.log
    exit 0
fi

# Check if setup was run
if [ ! -d "venv" ]; then
    echo -e "${RED}✗ Setup not completed. Please run ./setup.sh first${NC}"
    exit 1
fi

# Check if MongoDB is running
if ! pgrep -x "mongod" > /dev/null; then
    echo -e "${YELLOW}⚠ MongoDB not running. Starting...${NC}"
    sudo systemctl start mongodb || sudo service mongodb start
    sleep 2
fi

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════╗"
echo "║        ⚔️  STARTING FRIDAFORGE  ⚔️             ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

source venv/bin/activate

# Load environment
if [ -f ".env" ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

if [ "$1" == "--dev" ]; then
    echo -e "${YELLOW}Starting in development mode...${NC}"
    cd backend && uvicorn server:app --host ${HOST:-127.0.0.1} --port ${PORT:-9090} --reload
else
    echo -e "${GREEN}Starting server...${NC}"
    echo -e "${BLUE}Access the web interface at: http://localhost:${PORT:-9090}${NC}"
    echo ""
    cd backend && uvicorn server:app --host ${HOST:-127.0.0.1} --port ${PORT:-9090} --log-level info
fi