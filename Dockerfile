# Use official Python base image
FROM python:3.10

# Set working directory
WORKDIR /app

# Copy only requirements first (for caching)
COPY requirements.txt .

# Set trusted hosts (optional, if you have network issues)
RUN pip config set global.trusted-host "pypi.org" && \
    pip config set global.trusted-host "files.pythonhosted.org"

# Upgrade pip and install dependencies
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy the rest of the app
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Run FastAPI
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]