FROM node:20-bookworm
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV NAME=sapper
ENTRYPOINT ["/entrypoint.sh"]
