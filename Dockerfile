FROM python:3.8
LABEL authors="notsus"

WORKDIR /app

#This is for creating a directory which will store the logs.
RUN mkdir -p /app/logs

COPY . .

RUN pip3 install -r requirements.txt

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

EXPOSE 8000

CMD /wait && python3 -u server.py
