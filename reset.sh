#!/bin/bash
# FridaForge - Complete Reset & Fresh Start

echo "🔄 Resetting FridaForge to fresh state..."

# Stop server
pkill -f "uvicorn backend.server:app" 2>/dev/null

# Clean temporary files
rm -rf uploads/* temp/* logs/*

# Reset MongoDB
mongo mongodb://localhost:27017/fridaforge --eval "db.dropDatabase()" 2>/dev/null
mongo mongodb://localhost:27017/mobile_security_db --eval "db.dropDatabase()" 2>/dev/null
mongo mongodb://localhost:27017/vapt_mobile_analyzer --eval "db.dropDatabase()" 2>/dev/null

# Clear browser cache instruction
echo ""
echo "✅ FridaForge reset complete!"
echo ""
echo "Next steps:"
echo "1. Clear your browser cache (Ctrl+Shift+Delete)"
echo "2. Run: ./run.sh"
echo "3. Open: http://localhost:9090"
echo "4. Upload a fresh APK"
echo ""
