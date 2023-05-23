FROM golang:1.18.2-alpine3.14 AS builder
RUN apk add git
WORKDIR /build
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
# Build
COPY . .
RUN go build -o /build/mtlsauth .


FROM kong:3.3.0-alpine
USER root
COPY --from=builder /build/mtlsauth /usr/local/bin
USER kong
