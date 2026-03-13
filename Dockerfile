FROM golang:1.22-alpine AS build
WORKDIR /src
COPY server/ ./
RUN go build -o /latch-relay .

FROM alpine:3.20
COPY --from=build /latch-relay /usr/local/bin/latch-relay
EXPOSE 8081
ENTRYPOINT ["latch-relay"]
