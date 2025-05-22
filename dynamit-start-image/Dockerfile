FROM python:3.13.3-alpine

# Install build deps, install Python packages, then remove build deps
RUN pip install --no-cache-dir kmedoids==0.5.3.1 numpy==2.2.5 python-libnmap==0.7.3 ruamel.yaml==0.18.10
RUN apk add --no-cache nmap nmap-scripts

COPY dist/ /dynamit-start/
WORKDIR /dynamit-start
CMD ["python3", "-u", "dynamit-start.py"]