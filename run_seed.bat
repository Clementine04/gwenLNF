@echo off
echo =====================================================
echo ISU Lost and Found - Database Seeder
echo =====================================================
echo.

cd /d "%~dp0"
call .venv\Scripts\python.exe seed_database.py

echo.
echo =====================================================
pause

