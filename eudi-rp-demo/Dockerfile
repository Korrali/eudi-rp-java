FROM eclipse-temurin:21-jre AS runtime
WORKDIR /app
COPY target/eudi-rp-demo.jar app.jar
ENV EUDIRP_DEMO_DATA_DIR=/app/demo-data
ENV EUDIRP_DEMO_WALLET_MODE=mock
ENV EUDIRP_DEMO_BASE_URL=http://localhost:8080
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
