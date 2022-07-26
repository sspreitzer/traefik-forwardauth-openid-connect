FROM ruby:3

WORKDIR /usr/src/app

COPY Gemfile Gemfile.lock config.ru app.rb ./
RUN bundle install

ENV PORT=8080

CMD ["/bin/bash", "-c", "exec puma -e production -p ${PORT}"]

EXPOSE 8080/tcp
