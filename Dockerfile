FROM golang:1.22-alpine AS build
WORKDIR /src
COPY server/ ./
RUN go build -o /latch-relay .

FROM alpine:3.20
RUN adduser -D -u 1000 appuser
COPY --from=build /latch-relay /usr/local/bin/latch-relay
USER appuser
EXPOSE 8081
ENTRYPOINT ["latch-relay"]
