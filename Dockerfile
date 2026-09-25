FROM golang:1.23-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app ./src/...

FROM alpine:3.21
COPY --from=build /out/app /usr/local/bin/app
CMD ["app"]
