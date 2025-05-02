FROM python:3.12
LABEL authors="notsus"

ENV HOME /root
WORKDIR /app

RUN touch logs.txt

COPY . .

RUN pip3 install -r requirements.txt

RUN curl -o wait-for-it.sh https://raw.githubusercontent.com/vishnubob/wait-for-it/master/wait-for-it.sh && \
    chmod +x wait-for-it.sh

EXPOSE 8000

CMD sh -c "./wait-for-it.sh mongo:27017 -- sh -c 'python3 -u app.py'"

