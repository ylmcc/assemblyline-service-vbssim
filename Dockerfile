ARG branch=latest
ARG base=cccs/assemblyline-v4-service-base
FROM $base:$branch

ENV SERVICE_PATH=vbssim_service.vbssim_service.VBSSim

USER root
WORKDIR /opt/al_service
COPY vbssim_service vbssim_service
COPY service_manifest.yml .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

ARG version=4.7.4.stable1
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml
USER assemblyline
