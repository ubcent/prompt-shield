FROM golang:1.22-alpine AS build
WORKDIR /app
COPY . .
RUN go build -o psd ./cmd/psd

FROM alpine:3.20
RUN apk add --no-cache curl
WORKDIR /app
COPY --from=build /app/psd ./psd
COPY docker/promptshield-config.yaml /root/.promptshield/config.yaml
EXPOSE 8080
CMD ["./psd"]
