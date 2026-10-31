FROM python:3.11-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 GRADIO_SERVER_NAME=0.0.0.0 GRADIO_SERVER_PORT=7860
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN python scripts/build_index.py
EXPOSE 7860
CMD ["python", "app.py"]
