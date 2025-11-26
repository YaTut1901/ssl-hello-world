FROM maven:3.9-eclipse-temurin-17 AS builder

WORKDIR /build

COPY pom.xml ./pom.xml
COPY src ./src

RUN mvn -B package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

COPY --from=builder /build/target/hello-server.jar app.jar

ENTRYPOINT ["java", "-jar", "app.jar"]
