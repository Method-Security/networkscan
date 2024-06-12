# Dockerfile used for the compilation of the statically compiled networkscan binary
FROM golang:1.22.4-alpine3.20 as builder
ARG CLI_NAME="networkscan"
ARG TARGETARCH

RUN apk add --no-cache git gcc build-base libpcap-dev bash && mkdir -p /app/${CLI_NAME}
RUN go install github.com/goreleaser/goreleaser/v2@latest
WORKDIR /app/${CLI_NAME}
COPY ./ ./
# RUN goreleaser releaser --snapshot --clean
