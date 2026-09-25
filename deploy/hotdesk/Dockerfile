# Drop-in hotdesk desktop image with Valet bundled.
# Build: docker build -f deploy/hotdesk/Dockerfile --build-arg BASE=hotdesk-desktop:<ver> -t hotdesk-desktop-valet:<ver> .
ARG BASE=hotdesk-desktop:latest

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# modernc.org/sqlite is pure Go — static binary, no cgo needed.
RUN CGO_ENABLED=0 go build -trimpath -o /out/valet .

FROM ${BASE}
USER root
COPY --from=build /out/valet /usr/local/bin/valet
COPY deploy/hotdesk/valet-start.sh /usr/local/bin/valet-start.sh
COPY deploy/hotdesk/supervisor.conf /tmp/valet-supervisor.conf
RUN chmod 755 /usr/local/bin/valet /usr/local/bin/valet-start.sh \
    && cat /tmp/valet-supervisor.conf >> /etc/supervisor/supervisord.conf \
    && rm /tmp/valet-supervisor.conf \
    && bash -n /usr/local/bin/valet-start.sh \
    && /usr/local/bin/valet --help >/dev/null
