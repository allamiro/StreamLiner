FROM python:3.11-slim

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

CMD ["python", "src/main.py", "--config", "examples/streamliner.ini"]
