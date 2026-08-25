FROM python:3.10-slim

# Instalar dependencias del sistema necesarias para recovery-tool
RUN apt-get update && apt-get install -y \
    ca-certificates \
    chmod \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copiar archivos del proyecto
COPY . /app/

# Dar permisos de ejecución a la herramienta de Muun
RUN chmod +x /app/recovery-tool

# Instalar dependencias de Python
RUN pip install --no-cache-dir -r requirements.txt

# Ejecutar el scanner
CMD ["python", "auto_muun_scanner.py"]

