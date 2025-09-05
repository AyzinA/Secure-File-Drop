FROM golang:1.23-alpine

# Install dependencies
RUN apk add --no-cache git gcc build-base musl-dev libc-dev

# Create non-root user
RUN adduser -D -u 1000 appuser

# Set working directory
WORKDIR /app
COPY go.* .
RUN go mod download

# Copy application code, templates, static files, and certs
COPY backend/*.go .
COPY backend/config/ config/
COPY backend/database/ database/
COPY backend/models/ models/
COPY backend/auth/ auth/
COPY backend/handlers/ handlers/
COPY backend/templates/ templates/
COPY backend/static/ static/
COPY certs ./certs

# Set CGO_ENABLED
ENV CGO_ENABLED=1

# Build the Go application
RUN go build -o main .

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run the application with SSL
CMD ["./main"]