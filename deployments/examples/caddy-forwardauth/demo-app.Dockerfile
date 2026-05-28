FROM golang:1.22-alpine AS build

WORKDIR /src
COPY demo-app.go .
RUN go build -o /out/demo-app demo-app.go

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/demo-app /demo-app
EXPOSE 3000
ENTRYPOINT ["/demo-app"]

