#!/bin/bash

# Kill any existing server processes
pkill -9 -f "python3 server.py" 2>/dev/null
sleep 1

# Start the server with sudo for privileged ports
echo "🚀 Starting HotZone Pro Server (requires sudo for DNS/HTTP ports)..."
cd "$(dirname "$0")"
sudo python3 server.py