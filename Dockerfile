# Dockerfile — AI SOC Analyst Backend
FROM python:3.11-slim

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Create required directories
RUN mkdir -p logs models data

# Generate sample logs if none exist
RUN python generate_sample_logs.py

# Run full pipeline to populate DB
RUN python db.py

# Expose API port
EXPOSE 8000

# Start FastAPI server
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000"]