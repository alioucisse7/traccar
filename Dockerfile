FROM traccar/traccar:latest

# Remove the default server jar
RUN rm /opt/traccar/tracker-server.jar

# Copy our custom compiled jar (We will compile this in the build step below)
COPY ./target/tracker-server.jar /opt/traccar/tracker-server.jar

# Open all protocol ports
EXPOSE 8082 5000-5150 5000-5150/udp