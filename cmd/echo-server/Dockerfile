FROM golang:1.22-alpine
RUN apk add --no-cache curl
WORKDIR /app
COPY . .
RUN go build -o echo-server ./cmd/echo-server
CMD ["./echo-server"]
