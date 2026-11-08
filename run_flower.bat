@echo off
REM Flower + PyTorch + Opacus simulation (3 banks). Bank C label-flips from round 4. Result appears on the Results page.
REM First time only:  python -m venv .venv-flower  &&  .venv-flower\Scripts\pip install -r requirements-flower.txt --extra-index-url https://download.pytorch.org/whl/cpu
cd /d "%~dp0"
if exist .venv-flower\Scripts\python.exe (set PY=.venv-flower\Scripts\python.exe) else (set PY=python)
%PY% -m sentinel_flower.simulate --attack label_flip %*
pause
