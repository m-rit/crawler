# Use an official Golang runtime as a parent image
FROM golang:latest AS builder

# Set the working directory
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go application
RUN go build -o scan-app
EXPOSE 8080
## Command to run the application
CMD ["/app/scan-app"]
