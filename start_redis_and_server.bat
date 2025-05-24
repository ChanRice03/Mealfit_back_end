@echo off
cd /d %~dp0

start .\.redis\redis-server.exe
call .\.venv\Scripts\activate
uvicorn main:app --reload
