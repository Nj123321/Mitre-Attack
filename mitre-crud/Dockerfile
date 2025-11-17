# Use a small Python base image
FROM python:3.13-slim

# Set the working directory inside the container
WORKDIR /app

# Copy only requirements first (better layer caching)
# COPY attack-stix-injestion/requirements.txt .

COPY . .

WORKDIR /app/mitre-crud

# Install dependencies (if you don’t have requirements.txt, we adjust)
RUN pip install --no-cache-dir -r requirements.txt || true

# CMD ["python", "scripts/parsing.py"]

# Command to run your Python program
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]