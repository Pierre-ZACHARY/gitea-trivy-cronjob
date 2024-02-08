FROM golang:1.22 AS BUILDER

# Set the working directory
WORKDIR /app

COPY . .

# build the go app ( go.mod / TrivyBot.go )
RUN go get -d -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .


FROM aquasec/trivy
RUN apk add git

COPY --from=builder /app/main /usr/local/bin/giteatrivybot

WORKDIR /app

ENTRYPOINT ["/bin/sh"]

