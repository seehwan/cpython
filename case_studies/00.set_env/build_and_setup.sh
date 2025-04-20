#!/bin/bash

# Exit on any error
set -e

echo "Step 1: Building Python extensions..."
python3.14 setup.py build_ext --inplace
if [ $? -ne 0 ]; then
    echo "Error: Failed to build Python extensions"
    exit 1
fi

echo "Step 2: Copying .so files to ../run_dir..."
# Create run_dir if it doesn't exist
mkdir -p ../run_dir
cp *.so ../run_dir/
cp *.bin ../run_dir/
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy .so files"
    exit 1
fi

echo "Step 3: Copying AppArmor profile..."
sudo cp apparmor_profile_usr.local.bin.python3.14 /etc/apparmor.d/usr.local.bin.python3.14
if [ $? -ne 0 ]; then
    echo "Error: Failed to copy AppArmor profile"
    exit 1
fi

echo "Step 4: Reloading AppArmor profile..."
sudo apparmor_parser -r /etc/apparmor.d/usr.local.bin.python3.14
if [ $? -ne 0 ]; then
    echo "Error: Failed to reload AppArmor profile"
    exit 1
fi

echo "Step 5: Running security environment check..."
python3.14 00.check_security_env.py
if [ $? -ne 0 ]; then
    echo "Error: Security environment check failed"
    exit 1
fi

echo "It's ready to go!" 
