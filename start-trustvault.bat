@echo off
title TrustVault Zero-Trust Platform
echo =========================================================
echo      TrustVault - Zero-Trust Document Security Platform
echo =========================================================
echo.
echo Starting TrustVault Unified Server on http://localhost:4000 ...
echo.
cd /d "%~dp0"
npx tsx server/src/server.ts
pause
