FROM golang:1.24rc2-alpine as builder
RUN apk add git
WORKDIR /build
COPY go.mod .
COPY go.sum .
# Get dependancies - will also be cached if we won't change mod/sum
RUN go mod download
# Build
COPY . .
RUN go build -o /build/mtlsauth .


FROM kong:3.3.1-alpine
USER root
COPY --from=builder /build/mtlsauth /usr/local/bin
USER kong
