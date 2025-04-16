import logging
from logging.config import dictConfig
from flask import Flask

# Setting up logging details.
dictConfig({
    'version': 1,
    'formatters': {
        'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
        },
        'request': {
        'format': '[%(asctime)s] %(remote_addr)s requested %(url)s\n%(levelname)s in %(module)s: %(message)s',
        }
    },
    'handlers': {
    'file': {
        'class': 'logging.FileHandler',
        'filename': 'logs/app.log',
        'formatter': 'default',
        'level': 'INFO'
        },
    'console': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://sys.stdout',
        'formatter': 'default',
        'level': 'INFO'
        }
    },
    'root': {
        'level': 'INFO',
        'handlers': ['file', 'console']
    }

})

app = Flask(__name__)


#For logging and giving errors, use format: 
# app.logger.info() [Whatever you want to show as an error]
# abort(401) [The status code, if needed]

#Use this for development, if required.
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=8080, debug=True)
