# - 1: build
FROM maven:3.9.7-eclipse-temurin-17 AS builder

WORKDIR /app

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests
# - 2: runtime
FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

ENV SPRING_PROFILES_ACTIVE=dev \
    CLIENT_ID=myclientid \
    REDIRECT_URI=http://localhost:5173/callback \
    REDIRECT_LOGOUT_URI=http://localhost:5173/ \
    JWT_DURATION=86400 \
    CORS_ALLOWED_ORIGIN=http://localhost:5173 \
    SERVER_PORT_AS=9000 \
    DB_URL=jdbc:postgresql://host.docker.internal:5432/auth-db \
    DB_USER=postgres \
    DB_PASS=1234567

COPY --from=builder /app/target/*.jar app.jar
EXPOSE 9000
ENTRYPOINT ["java","-jar","/app/app.jar"]
