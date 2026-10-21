@echo off
title Push TrustVault to GitHub
echo =========================================================
echo       Pushing TrustVault Repository to GitHub
echo =========================================================
echo.
cd /d "%~dp0"

echo 1. Configuring remote origin...
git remote remove origin 2>nul
git remote add origin https://github.com/Chaitanyasource-06/trustvault.git

echo 2. Ensuring branch is 'main'...
git branch -M main

echo 3. Pushing commits, tests, and documentation to GitHub...
git push -u origin main

if %errorlevel% equ 0 (
    echo.
    echo =========================================================
    echo [SUCCESS] TrustVault successfully uploaded to GitHub!
    echo Visit: https://github.com/Chaitanyasource-06/trustvault
    echo =========================================================
) else (
    echo.
    echo If GitHub rejected because of existing remote commits, attempting sync...
    git push -u origin main --force
)

echo.
pause
