FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/plystra-auth ./cmd/plystra-auth

FROM alpine:3.22

RUN addgroup -S auth && adduser -S -G auth auth
COPY --from=build /out/plystra-auth /usr/local/bin/plystra-auth
USER auth
ENTRYPOINT ["/usr/local/bin/plystra-auth"]
