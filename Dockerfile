

FROM golang:alpine

ADD go.mod .

ADD go.sum .

RUN go mod download

COPY . .

RUN go build -o main main.go

CMD ["./main"]
