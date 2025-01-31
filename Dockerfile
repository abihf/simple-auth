# Start with the official Golang image
FROM golang:1.23-alpine AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app with static linking
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Start a new stage from scratch
FROM scratch

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/main /app/main

# Default environment variables
ENV LISTEN_ADDR=":8081"
ENV COOKIE_NAME="simple-auth-session"
ENV COOKIE_SECRET="secret"
ENV AUTH_USER="admin"
ENV AUTH_PASSWORD="admin" 
ENV UPSTREAM_ADDR="localhost:8080"

# Command to run the executable
ENTRYPOINT ["/app/main"]