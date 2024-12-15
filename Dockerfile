# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY . .

# Install build dependencies
RUN apk add --no-cache make git

# Build the binary
RUN make build

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata

# Copy binary and config
COPY --from=builder /app/bin/oauth2-device-proxy /bin/oauth2-device-proxy

# Create non-root user
RUN adduser -D -H -h /app device-proxy && \
    chown device-proxy:device-proxy /bin/oauth2-device-proxy

# Switch to non-root user
USER device-proxy

# Expose port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["/bin/oauth2-device-proxy"]