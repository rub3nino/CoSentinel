FROM python:latest

WORKDIR /app
COPY requirements.txt app.py settings.py ./
RUN pip install --no-cache-dir -r requirements.txt

ENV FLASK_DEBUG=1
EXPOSE 8080

CMD ["python", "app.py"]
