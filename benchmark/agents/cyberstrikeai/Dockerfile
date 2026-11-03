FROM debian:bookworm-slim
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV NAME=cyberstrikeai
ENTRYPOINT ["/entrypoint.sh"]
