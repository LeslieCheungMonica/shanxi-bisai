FROM pytorch/pytorch:2.1.0-cuda12.1-cudnn8-runtime

RUN pip install modelscope

WORKDIR /app

COPY batch_vuln_detect.py .
COPY files/ ./files/

RUN mkdir -p output

CMD ["python", "batch_vuln_detect.py"]
