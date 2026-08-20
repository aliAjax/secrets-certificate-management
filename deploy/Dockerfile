FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

FROM alpine:3.20
RUN adduser -D -H app
COPY --from=build /out/server /usr/local/bin/scp-server
COPY configs/config.yaml /etc/scp/config.yaml
COPY migrations /etc/scp/migrations
USER app
EXPOSE 8080 9090
ENTRYPOINT ["scp-server", "-config", "/etc/scp/config.yaml"]
