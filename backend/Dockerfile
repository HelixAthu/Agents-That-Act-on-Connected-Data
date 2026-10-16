FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend application source and data
COPY backend/ ./backend/
COPY mcp_server/ ./mcp_server/
COPY seed/ ./seed/
COPY evals/ ./evals/
COPY replays/ ./replays/
COPY pyproject.toml .

ENV FALKORDB_HOST=falkordb \
    FALKORDB_PORT=6379 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

EXPOSE 8000

# Wait for FalkorDB, ensure initial graph seed, and start FastAPI
CMD ["sh", "-c", "python seed/seed_graph.py --reset && uvicorn backend.main:app --host 0.0.0.0 --port 8000"]
