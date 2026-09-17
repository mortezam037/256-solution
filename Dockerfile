FROM python:3.12-alpine
WORKDIR /app
COPY main.py /app/main.py
ENTRYPOINT ["python3","/app/main.py"]


