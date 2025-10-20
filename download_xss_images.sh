#!/bin/bash

# Confluence attachment URLs
# Format: https://innowise-group.atlassian.net/wiki/download/attachments/PAGE_ID/FILENAME

PAGE_ID="4037378654"
BASE_URL="https://innowise-group.atlassian.net/wiki/download/attachments/$PAGE_ID"
OUTPUT_DIR="public/pics/xss-lesson"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Download images
echo "Downloading XSS lesson images..."

# Image 1: Burp Collaborator diagram
curl -L -o "$OUTPUT_DIR/burp-collaborator-diagram.png" \
  "$BASE_URL/image-20251002-123758.png"

# Image 2: Alert example
curl -L -o "$OUTPUT_DIR/xss-alert-example.png" \
  "$BASE_URL/image-20251002-113651.png"

# Image 3: Blind XSS payload
curl -L -o "$OUTPUT_DIR/blind-xss-payload.jpg" \
  "$BASE_URL/photo_2025-10-02_14-43-29-20251002-124329.jpg"

# Image 4: Blind XSS result
curl -L -o "$OUTPUT_DIR/blind-xss-result.png" \
  "$BASE_URL/image-20251003-055849.png"

# Image 5: SVG XSS example
curl -L -o "$OUTPUT_DIR/svg-xss-example.jpg" \
  "$BASE_URL/photo_2025-10-02_13-33-13-20251002-113313.jpg"

echo "Download complete! Images saved to $OUTPUT_DIR"
