# Drop-in hotdesk desktop image with Valet bundled.
# Build from source (default):
#   docker build -f deploy/hotdesk/Dockerfile --build-arg BASE=hotdesk-desktop:<ver> -t hotdesk-desktop-valet:<ver> .
# Build from a published release instead:
#   docker build -f deploy/hotdesk/Dockerfile --build-arg BASE=... --build-arg VALET_SRC=release --build-arg VALET_VERSION=0.1.0 -t ... .
ARG BASE=hotdesk-desktop:latest
ARG VALET_VERSION=
ARG VALET_SRC=build

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# modernc.org/sqlite is pure Go — static binary, no cgo needed.
RUN CGO_ENABLED=0 go build -trimpath -o /out/valet .

FROM alpine:3.21 AS release
ARG VALET_VERSION
ARG TARGETARCH
RUN apk add --no-cache curl \
    && curl -fsSL "https://github.com/joalavedra/valet/releases/download/v${VALET_VERSION}/valet_${VALET_VERSION}_linux_${TARGETARCH}.tar.gz" \
       | tar -xz -C /tmp valet \
    && mkdir -p /out && mv /tmp/valet /out/valet && chmod 755 /out/valet

FROM ${BASE}
ARG VALET_SRC
USER root
COPY --from=${VALET_SRC} /out/valet /usr/local/bin/valet
COPY deploy/hotdesk/valet-start.sh /usr/local/bin/valet-start.sh
COPY deploy/hotdesk/supervisor.conf /tmp/valet-supervisor.conf
RUN chmod 755 /usr/local/bin/valet /usr/local/bin/valet-start.sh \
    && cat /tmp/valet-supervisor.conf >> /etc/supervisor/supervisord.conf \
    && rm /tmp/valet-supervisor.conf \
    && bash -n /usr/local/bin/valet-start.sh \
    && /usr/local/bin/valet --help >/dev/null
