#!/bin/bash

echo "Starting troubleshooting for Kali Linux boot issues..."

# 1. Update and Upgrade the System
echo "Updating and upgrading the system..."
sudo apt update && sudo apt upgrade -y
if [ $? -ne 0 ]; then
    echo "Error: Failed to update and upgrade system."
fi

# 2. Check and Fix Broken Dependencies
echo "Fixing broken dependencies..."
sudo apt --fix-broken install -y
if [ $? -ne 0 ]; then
    echo "Error: Failed to fix broken dependencies."
fi

# 3. Reconfigure Light Display Manager
echo "Reconfiguring lightdm..."
sudo dpkg-reconfigure lightdm
if [ $? -ne 0 ]; then
    echo "Error: Failed to reconfigure lightdm."
fi

# 4. Check Disk Space
echo "Checking disk space..."
df -h
if [ $? -ne 0 ]; then
    echo "Error: Failed to check disk space."
fi

# 5. Reconfigure Xorg
echo "Reconfiguring Xorg server..."
sudo dpkg-reconfigure xserver-xorg
if [ $? -ne 0 ]; then
    echo "Error: Failed to reconfigure Xorg server."
fi

# 6. Install Missing Graphics Drivers
echo "Installing graphics drivers..."
sudo apt install -y xserver-xorg-video-all xserver-xorg-core
if [ $? -ne 0 ]; then
    echo "Error: Failed to install graphics drivers."
fi

# 7. Restart Display Manager
echo "Restarting lightdm service..."
sudo systemctl restart lightdm
if [ $? -ne 0 ]; then
    echo "Error: Failed to restart lightdm service."
fi

# 8. Check Kernel Logs for Errors
echo "Checking kernel logs for errors..."
sudo dmesg | grep -i error
if [ $? -ne 0 ]; then
    echo "Error: Failed to check kernel logs."
fi

# 9. Disable Plymouth Service (if causing issues)
echo "Disabling plymouth-quit service..."
sudo systemctl disable plymouth-quit.service
if [ $? -ne 0 ]; then
    echo "Error: Failed to disable plymouth-quit service."
fi

# 10. Verify System Logs
echo "Verifying system logs..."
sudo journalctl -b | grep -i error
if [ $? -ne 0 ]; then
    echo "Error: Failed to verify system logs."
fi

echo "All troubleshooting steps completed. Please reboot your system."
