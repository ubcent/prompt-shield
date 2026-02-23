FROM golang:1.22-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o velar ./cmd/velar && go build -o velard ./cmd/velard

FROM alpine:3.20
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/velar ./velar
COPY --from=build /app/velard ./velard
COPY docker/velar-config.yaml /root/.velar/config.yaml
EXPOSE 8080
CMD ["./velard"]
