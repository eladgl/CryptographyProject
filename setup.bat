@echo off
echo Setting up the project...

:: Configure environment variables
set PYENV_HOME=%USERPROFILE%\.pyenv
set PYENV_ROOT=%USERPROFILE%\.pyenv
set PATH=%PYENV_HOME%\pyenv-win\bin;%PYENV_HOME%\pyenv-win\shims;%PATH%

:: Install Python version with pyenv
pyenv install 3.11.5
pyenv local 3.11.5

:: Create virtual environment
python -m venv "%cd%\.venv"

:: Activate virtual environment
call "%cd%\.venv\Scripts\activate"

:: Install dependencies
pip install -r requirements.txt

echo Setup complete!
pause
