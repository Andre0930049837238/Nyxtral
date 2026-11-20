@echo off
REM ============================================================
REM  Build script for Nyxtral (Windows)
REM  Run on Windows with Python 3.9+ installed
REM  (tick "Add Python to PATH" during installation)
REM ============================================================

echo.
echo === Installing dependencies (PyInstaller, reportlab, pywebview, tree-sitter) ===
pip install --upgrade pyinstaller reportlab pywebview tree-sitter tree-sitter-javascript tree-sitter-typescript tree-sitter-rust tree-sitter-c tree-sitter-cpp tree-sitter-go tree-sitter-kotlin tree-sitter-swift tree-sitter-java tree-sitter-c-sharp tree-sitter-php
if errorlevel 1 (
    echo.
    echo ERROR: dependency installation failed. Check your internet connection and that Python 3.9+ and pip are on PATH, then try again.
    pause
    exit /b 1
)

echo.
echo === Building the executable ===
if exist webui (
    echo webui folder found: building with the modern interface.
    pyinstaller --onefile --windowed --icon assets\icon.ico --collect-data reportlab --collect-all tree_sitter --collect-all tree_sitter_javascript --collect-all tree_sitter_typescript --collect-all tree_sitter_rust --collect-all tree_sitter_c --collect-all tree_sitter_cpp --collect-all tree_sitter_go --collect-all tree_sitter_kotlin --collect-all tree_sitter_swift --collect-all tree_sitter_java --collect-all tree_sitter_c_sharp --collect-all tree_sitter_php --add-data "webui;webui" --name Nyxtral main.py
) else (
    echo WARNING: webui folder not found. Building with the fallback Tkinter interface only.
    pyinstaller --onefile --windowed --icon assets\icon.ico --collect-data reportlab --collect-all tree_sitter --collect-all tree_sitter_javascript --collect-all tree_sitter_typescript --collect-all tree_sitter_rust --collect-all tree_sitter_c --collect-all tree_sitter_cpp --collect-all tree_sitter_go --collect-all tree_sitter_kotlin --collect-all tree_sitter_swift --collect-all tree_sitter_java --collect-all tree_sitter_c_sharp --collect-all tree_sitter_php --name Nyxtral main.py
)
if errorlevel 1 (
    echo.
    echo ERROR: the build failed. Read the PyInstaller messages above for the cause.
    pause
    exit /b 1
)

echo.
echo === Done! ===
echo The executable is located at: dist\Nyxtral.exe
echo.

REM --- Build the setup (Nyxtral-Setup.exe, with the program inside) ---
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" (
    echo Inno Setup not found: trying to install it with winget...
    winget install --id JRSoftware.InnoSetup -e --silent --accept-package-agreements --accept-source-agreements
    set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"
    if not exist "%ISCC%" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
)
if exist "%ISCC%" (
    echo === Building the setup with Inno Setup ===
    "%ISCC%" installer.iss
    if errorlevel 1 (
        echo ERROR: the setup build failed. Read the Inno Setup messages above.
    ) else (
        echo The setup is located at: installer_output\Nyxtral-Setup-<version>.exe
    )
) else (
    echo Could not install Inno Setup automatically. Install it from https://jrsoftware.org/isdl.php and run build.bat again.
)
echo.
echo If something fails to start, the error is saved in %%APPDATA%%\Nyxtral\crash.log (and scanner.log)
echo.
pause
