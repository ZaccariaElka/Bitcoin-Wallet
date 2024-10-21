@echo off
echo Installing requirements for the Bitcoin wallet generator

python.exe -m pip install -q --upgrade pip

pip install -q ecdsa base58

echo Requirements installed, If the script crashes, manually run "pip install ecdsa base58".
pause
