FROM alpine:3.20 as base

ARG CLI_NAME="networkscan"
ARG TARGETARCH

RUN apk update && apk add bash jq libpcap-dev

# Setup Method Directory Structure
RUN \
  mkdir -p /opt/method/${CLI_NAME}/ && \
  mkdir -p /opt/method/${CLI_NAME}/var/data && \
  mkdir -p /opt/method/${CLI_NAME}/var/data/tmp && \
  mkdir -p /opt/method/${CLI_NAME}/var/conf && \
  mkdir -p /opt/method/${CLI_NAME}/var/log && \
  mkdir -p /opt/method/${CLI_NAME}/service/bin && \
  mkdir -p /mnt/output

COPY scripts/* /opt/method/${CLI_NAME}/service/bin/

FROM base as amd64
ARG CLI_NAME
COPY build/linux-amd64/${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

FROM base as arm64
ARG CLI_NAME
COPY build/linux-arm64/${CLI_NAME} /opt/method/${CLI_NAME}/service/bin/${CLI_NAME}

FROM ${TARGETARCH} as final
ARG CLI_NAME
RUN \
  adduser --disabled-password --gecos '' method && \
  chown -R method:method /opt/method/${CLI_NAME}/ && \
  chown -R method:method /mnt/output
USER method
WORKDIR /opt/method/${CLI_NAME}/
ENV PATH="/opt/method/${CLI_NAME}/service/bin:${PATH}"
