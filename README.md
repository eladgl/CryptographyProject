# CryptographyProject
Secure email exchange: encr-decr with BLOWFISH in CFB mode+secure delivery of the secrect key with RSA +  signature based on EC EL-GAMAL 


# Project Setup

## Prerequisites
- Python 3.11.5 (recommended via [pyenv](https://github.com/pyenv/pyenv))
- Git
- Environment variables for `pyenv`:
  - `PYENV_HOME`: Path to your pyenv installation.
  - `PYENV_ROOT`: Root directory of pyenv.
  - `PYENV`: Path to the pyenv shim for global Python management.

## Setup Instructions
###1. Clone the repository:
   '''bash
   git clone <repository-url>
   cd <project-folder>'''

###2. Install pyenv for Python version management:
'''
pip install pyenv-win --target %USERPROFILE%\\.pyenv
'''
If you run into an error with the above command use the folllowing instead (#303):
'''
pip install pyenv-win --target %USERPROFILE%\\.pyenv --no-user --upgrade
'''
See this for more information: https://github.com/pyenv-win/pyenv-win/blob/master/docs/installation.md#powershell
###3. Configure Environment Variables:

Add System Settings
- For windows It's a easy way to use PowerShell here

Adding PYENV, PYENV_HOME and PYENV_ROOT to your Environment Variables
'''
[System.Environment]::SetEnvironmentVariable('PYENV',$env:USERPROFILE + "\.pyenv\pyenv-win\","User")

[System.Environment]::SetEnvironmentVariable('PYENV_ROOT',$env:USERPROFILE + "\.pyenv\pyenv-win\","User")

[System.Environment]::SetEnvironmentVariable('PYENV_HOME',$env:USERPROFILE + "\.pyenv\pyenv-win\","User")
'''

Now adding the following paths to your USER PATH variable in order to access the pyenv command

'''
[System.Environment]::SetEnvironmentVariable('path', $env:USERPROFILE + "\.pyenv\pyenv-win\bin;" + $env:USERPROFILE + "\.pyenv\pyenv-win\shims;" + [System.Environment]::GetEnvironmentVariable('path', "User"),"User")
'''
If for some reason you cannot execute PowerShell command(likely on an organization managed device), type "environment variables for you account" in Windows search bar and open Environment Variables dialog. You will need create those 3 new variables in System Variables section (bottom half). Let's assume username is my_pc.

| Variable | Value |
| --------- | ------- |
|PYENV   | C:\Users\my_pc\.pyenv\pyenv-win\ |
|PYENV_HOME |	C:\Users\my_pc\.pyenv\pyenv-win\ |
|PYENV_ROOT |	C:\Users\my_pc\.pyenv\pyenv-win\ |

And add two more lines to user variable Path both in user profile and in system and add them to the top of the file.

C:\Users\my_pc\.pyenv\pyenv-win\bin
C:\Users\my_pc\.pyenv\pyenv-win\shims

-For macOS/Linux: Add the following to your .bashrc or .zshrc in project folder:
'''
export PYENV_HOME="$HOME/.pyenv"
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_HOME/bin:$PYENV_HOME/shims:$PATH"
'''
Then apply changes:
'''
source ~/.bashrc

'''

###4. Ensure the correct Python version:
'''
pyenv install 3.11.5
pyenv local 3.11.5
'''

###5. Create a virtual environment in current project directory:
'''
python -m venv "%cd%\.venv"
'''

###6. Activate the virtual environment:

- On macOS/Linux:
'''
source .venv/bin/activate
'''
- On Windows:
'''
.\.venv\Scripts\activate
'''

###7. Install dependencies:
'''
pip install -r requirements.txt
'''


##Notice foe windows users sometimes powershell blocks script activation, run:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass


There are also two run files for automation of the process, setup.bat file for windows and setup.sh for mac/Linux users. Run them in project director after cloning.

