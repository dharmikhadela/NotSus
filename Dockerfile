FROM python:3.8
LABEL authors="notsus"

ENV HOME /root
WORKDIR /app

RUN mkdir -p /app/logs

COPY . .

RUN pip3 install -r requirements.txt

RUN curl -o wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && \
    chmod +x wait-for-it.sh

EXPOSE 8000

CMD sh -c "./wait-for-it.sh mongo:27017 -- python3 -u server.py"
