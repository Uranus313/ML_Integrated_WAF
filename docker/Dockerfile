FROM openresty/openresty:alpine

# Lua libs will go here later
RUN apk add --no-cache curl

COPY conf /etc/nginx/conf
COPY lua /usr/local/openresty/lualib

CMD ["openresty", "-g", "daemon off;"]
