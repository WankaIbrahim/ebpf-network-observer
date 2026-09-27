FROM golang:1.25 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/observer ./cmd/observer

# Runtime stage
FROM alpine:3.20
COPY --from=build /out/observer /usr/local/bin/observer
EXPOSE 2112
ENTRYPOINT ["/usr/local/bin/observer"]