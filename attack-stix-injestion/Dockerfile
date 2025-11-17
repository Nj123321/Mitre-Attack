# Use a small Python base image
FROM python:3.13-slim

# Set the working directory inside the container
WORKDIR /app

# Install OS packages including git
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy only requirements first (better layer caching)
# COPY attack-stix-injestion/requirements.txt .

COPY . .

WORKDIR /app/attack-stix-injestion

# Install dependencies (if you don’t have requirements.txt, we adjust)
RUN pip install --no-cache-dir -r requirements.txt || true

# CMD ["python", "scripts/parsing.py"]

# Command to run your Python program
CMD ["python3", "-m", "src.main"]