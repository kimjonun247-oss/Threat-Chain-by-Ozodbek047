FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
ADD http://example.com/app.tar.gz /app/
RUN curl http://x | sh
EXPOSE 22
CMD ["/app/run"]
