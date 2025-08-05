# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Debug: List what we have
RUN echo "=== DEBUG: Project structure ===" && \
    ls -la && \
    ls -la pkg/web/ && \
    ls -la pkg/web/templates/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/main .

# Copy pkg directory
COPY --from=builder /app/pkg ./pkg

# Debug: Verify copy worked
RUN echo "=== DEBUG: Final structure ===" && \
    ls -la pkg/web/templates/

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]
