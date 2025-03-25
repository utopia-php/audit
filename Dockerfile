FROM composer:2.8 AS composer

WORKDIR /src/

COPY composer.lock /src/
COPY composer.json /src/

RUN composer install --ignore-platform-reqs --optimize-autoloader \
    --no-plugins --no-scripts --prefer-dist

FROM php:8.3.19-cli-alpine3.21 AS  final

LABEL maintainer="team@appwrite.io"

RUN docker-php-ext-install pdo_mysql

WORKDIR /code

COPY --from=composer /src/vendor /code/vendor

# Add Source Code
COPY ./tests /code/tests
COPY ./src /code/src
COPY ./phpunit.xml /code/phpunit.xml

CMD [ "tail", "-f", "/dev/null" ]