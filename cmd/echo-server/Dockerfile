FROM golang:1.22-alpine
WORKDIR /app
COPY . .
RUN go build -o echo-server ./cmd/echo-server
CMD ["./echo-server"]
