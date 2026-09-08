FROM alpine:3.21
WORKDIR /app
COPY . .
CMD ["sh", "-c", "echo tigergate-test-go"]
