FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/valet-demo ./demo

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/valet-demo /valet-demo
EXPOSE 8080
ENV DEMO_LISTEN=:8080
ENTRYPOINT ["/valet-demo"]
