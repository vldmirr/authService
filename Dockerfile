FROM golang:latest

WORKDIR /app

COPY . .

RUN go build -buildvcs=false -o /authService .
RUN chmod +x /authService

EXPOSE 8000

CMD ["/authService"]
