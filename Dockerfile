# Using an older, unpatched base image tag to trigger standard CVE scanner detection
FROM alpine:3.12.0

# Install a generic, older utility version for dependency scanning verification
RUN apk update && apk add --no-cache curl=7.79.1-r1

# Set up entry point
WORKDIR /app
CMD ["curl", "--version"]
