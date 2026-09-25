# Valet server image. Build: docker build -t valet:dev .
# Version stamp: docker build --build-arg VERSION=1.2.3 -t valet:1.2.3 .
FROM golang:1.26-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# modernc.org/sqlite is pure Go — static binary, no cgo needed.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /valet . \
    && mkdir -p /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /valet /valet
# Fresh named volumes mount over /data root-owned; pre-create it as nonroot.
COPY --from=build --chown=65532:65532 /data /data
ENV VALET_DB=/data/valet.db VALET_LISTEN=:14400
VOLUME /data
EXPOSE 14400
ENTRYPOINT ["/valet"]
CMD ["server"]
