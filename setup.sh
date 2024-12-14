#!/bin/bash
echo "Setting up the project..."

# Configure environment variables
export PYENV_HOME="$HOME/.pyenv"
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_HOME/bin:$PYENV_HOME/shims:$PATH"

# Install Python version with pyenv
pyenv install 3.11.5
pyenv local 3.11.5

# Create virtual environment
python -m venv ".venv"

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

echo "Setup complete!"
