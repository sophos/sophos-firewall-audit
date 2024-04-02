# Use the official nginx image as base image
FROM nginx:latest

# Copy local html files to the container
COPY results_html /usr/share/nginx/html

# Copy SSL certificate and key to the container
COPY server.key /etc/nginx/ssl/server.key
COPY server.crt /etc/nginx/ssl/server.crt

# Remove default nginx configuration
RUN rm /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration file with HTTPS support
COPY nginx.conf /etc/nginx/conf.d/

# Expose port 80 for HTTP and port 8443 for HTTPS
EXPOSE 80
EXPOSE 8443

# Start nginx server
CMD ["nginx", "-g", "daemon off;"]