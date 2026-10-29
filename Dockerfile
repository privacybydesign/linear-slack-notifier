FROM golang:1.26 AS builder

WORKDIR /app

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o linear-slack-notifier

FROM alpine:latest

# Run as an unprivileged user to limit the blast radius of a container compromise.
RUN addgroup -S notifier && adduser -S -G notifier notifier

COPY --from=builder /app/linear-slack-notifier /app/linear-slack-notifier

EXPOSE 8080

WORKDIR /app

USER notifier

ENTRYPOINT ["/app/linear-slack-notifier"]
