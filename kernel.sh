#!/bin/bash

echo "Starting Kernel Diagnosis and Troubleshooting..."

# 1. Display Current Kernel Version
echo "Checking current kernel version..."
uname -r
echo "Kernel version check complete."

# 2. Check Installed Kernel Headers
echo "Checking installed kernel headers..."
dpkg --list | grep linux-headers
if [ $? -ne 0 ]; then
    echo "Warning: Kernel headers not found."
    echo "Attempting to install kernel headers..."
    sudo apt update && sudo apt install linux-headers-$(uname -r) build-essential -y
else
    echo "Kernel headers are installed."
fi

# 3. Check Disk Space
echo "Checking disk space..."
df -h | grep 'Filesystem\|/dev/sd'
if [ $? -ne 0 ]; then
    echo "Error: Unable to retrieve disk space. Ensure partitions are mounted correctly."
else
    echo "Disk space check complete."
fi

# 4. Rebuild Initramfs
echo "Rebuilding initramfs..."
sudo update-initramfs -u
if [ $? -ne 0 ]; then
    echo "Error: Failed to rebuild initramfs."
else
    echo "Initramfs rebuild successful."
fi

# 5. Check Kernel Modules
echo "Checking kernel modules..."
lsmod
echo "Kernel modules listed."

# 6. Verify GRUB Configuration
echo "Verifying GRUB configuration..."
sudo update-grub
if [ $? -ne 0 ]; then
    echo "Error: Failed to update GRUB configuration."
else
    echo "GRUB configuration updated."
fi

# 7. Inspect System Logs for Errors
echo "Checking system logs for kernel errors..."
sudo dmesg | grep -i error
sudo journalctl -k | grep -i error
echo "System log check complete."

# 8. Check for Broken Packages
echo "Checking for broken packages..."
sudo apt --fix-broken install -y
if [ $? -ne 0 ]; then
    echo "Error: Failed to fix broken packages."
else
    echo "Broken packages fixed successfully."
fi

# 9. Clean Up APT Cache
echo "Cleaning APT cache..."
sudo apt clean
echo "APT cache cleaned."

echo "Kernel diagnosis and troubleshooting completed. Please reboot your system if changes were made."
