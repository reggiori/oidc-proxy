FROM golang:1.17 as build
WORKDIR /go/src/app
COPY go.mod .
COPY go.sum .
RUN CGO_ENABLED=0 go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -a -o /go/bin/app .


FROM scratch
COPY --from=build /go/bin/app /usr/local/bin/app
ENTRYPOINT ["/usr/local/bin/app"]
