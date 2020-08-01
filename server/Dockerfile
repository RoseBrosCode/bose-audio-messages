FROM python:3.8-slim-buster

# Setup gunicorn env vars
ENV GUNICORN_DIRECTORY=/gunicorn \
    GUNICORN_WORKERS=1 \
    GUNICORN_WORKER_CLASS=geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    GUNICORN_BACKLOG=2048 \
    GUNICORN_BIND=0.0.0.0:80 \
    APP_MODULE=main:app \
    APP_DIRECTORY=/server

# Setup gunicorn config
WORKDIR ${GUNICORN_DIRECTORY}
COPY gunicorn .

# Setup application
WORKDIR ${APP_DIRECTORY}

# Install dependencies
RUN pip install pipenv
COPY server/Pipfile* ./
RUN pipenv install --system --deploy

# Copy remaining source
COPY server .

# Run the server
CMD gunicorn --config ${GUNICORN_DIRECTORY}/gunicorn.conf.py --log-config ${GUNICORN_DIRECTORY}/logging.conf \
    --chdir ${APP_DIRECTORY} ${APP_MODULE}
