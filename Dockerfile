# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Debug: List what we have
RUN echo "=== DEBUG: Listing project structure ===" && \
    find . -name "templates" -type d && \
    ls -la pkg/web/ && \
    ls -la pkg/web/templates/ 2>/dev/null || echo "templates not found during build"

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/api/main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/main .

# Debug: Check what we're copying
RUN echo "=== DEBUG: Before copying web assets ===" && ls -la /

# Copy entire pkg directory to ensure nothing is missed
COPY --from=builder /app/pkg ./pkg

# Debug: Verify copy worked
RUN echo "=== DEBUG: After copying ===" && \
    ls -la pkg/ && \
    ls -la pkg/web/ && \
    ls -la pkg/web/templates/ 2>/dev/null || echo "templates missing after copy"

# Copy configs if exists
COPY --from=builder /app/configs ./configs 2>/dev/null || echo "No configs found"

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"]
