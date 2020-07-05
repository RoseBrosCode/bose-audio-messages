FROM python:3.8

RUN pip install pipenv

# Configure environment variables
ENV FLASK_APP=server.py

# ENV PYTHONPATH=$PYTHONPATH:/
# ENV APP_MODULE=service.main:APP
# ENV GUNICORN_WORKERS=4
# ENV GUNICORN_BIND=0.0.0.0:9090
# ENV GUNICORN_WORKER_CLASS=gevent

# Install dependencies
WORKDIR /server
COPY server/Pipfile* ./

# RUN apk add --no-cache ${PYTHON_BUILD_PACKAGES} \
#     && pipenv install --system --deploy\
#     && apk del ${PYTHON_BUILD_PACKAGES} \
#     && rm -rf /var/cache/apk/*

RUN pipenv install --system --deploy

# Copy remaining data
COPY server .
COPY client ./client

CMD [ "flask", "run", "--host=0.0.0.0"]
