@echo off
echo Installing PyInstaller...
pip install pyinstaller

echo Building EXE...
pyinstaller --noconfirm --onedir --windowed --name "WinVolAuto" --add-data "resources;resources" --icon "resources/icon.ico" main.py

echo Build complete. Check dist/WinVolAuto folder.
pause
