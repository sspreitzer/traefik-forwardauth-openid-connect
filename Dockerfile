FROM ruby:3

WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock config.ru app.rb ./
RUN bundle install

CMD ["puma", "-e", "production", "-p", "8080"]

EXPOSE 8080/tcp
