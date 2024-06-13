# Dockerfile used for the compilation of the statically compiled networkscan binary
FROM golang:1.22.4-alpine3.20 as base
ARG GORELEASER_VERSION="v2.0.1"
ARG CLI_NAME="networkscan"
ARG TARGETARCH

RUN apk add --no-cache git gcc build-base libpcap-dev bash wget && mkdir -p /app/${CLI_NAME}
WORKDIR /app/${CLI_NAME}

FROM base as amd64
ARG CLI_NAME
ARG GORELEASER_VERSION
RUN \
  wget https://github.com/goreleaser/goreleaser-pro/releases/download/${GORELEASER_VERSION}-pro/goreleaser-pro_Linux_x86_64.tar.gz && \
  tar -xvzf goreleaser-pro_Linux_x86_64.tar.gz && \
  mv goreleaser /usr/local/bin/goreleaser && \
  rm -rf goreleaser-pro_Linux_x86_64.tar.gz LICENSE.md README.md completions manpages

FROM base as arm64
ARG CLI_NAME
RUN \
  wget https://github.com/goreleaser/goreleaser-pro/releases/download/${GORELEASER_VERSION}-pro/goreleaser-pro_Linux_arm64.tar.gz && \
  tar -xvzf goreleaser-pro_Linux_arm64.tar.gz && \
  mv goreleaser /usr/local/bin/goreleaser && \
  rm -rf goreleaser-pro_Linux_arm64.tar.gz LICENSE.md README.md completions manpages
