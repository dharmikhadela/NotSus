FROM ubuntu:latest
LABEL authors="shane"

ENTRYPOINT ["top", "-b"]

ENV HOME /root
WORKDIR /root

COPY ./requirements.txt ./requirements.txt
COPY ./server.py ./server.py
COPY ./public ./public
COPY ./util ./util

RUN pip3 install -r requirements.txt && apt-get update && apt-get install -y ffmpeg
RUN pip install ffmpeg-python

EXPOSE 8000

ADD https://github.com/ufoscout/docker-compose-wait/releases/download/2.2.1/wait /wait
RUN chmod +x /wait

CMD /wait && python3 -u server.py

# docker compose -f docker-compose.db-only.yml up --build