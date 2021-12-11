FROM alpine:3.15

RUN apk --no-cache add maven git openjdk11-jdk

WORKDIR /app
RUN adduser -h /app -D user
USER user

RUN git clone --depth=1 https://github.com/veracode-research/rogue-jndi .
RUN mvn package

ENTRYPOINT ["java", "-jar", "target/RogueJndi-1.1.jar"]

EXPOSE 8000
EXPOSE 1389
