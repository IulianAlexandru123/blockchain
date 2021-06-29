FROM python:3.9.1
ADD . /python-flask
WORKDIR /python-flask
RUN pip install cryptography
RUN pip install requests
RUN pip install -U flask-cors
RUN pip install -r requirements.txt
EXPOSE 5000
EXPOSE 4000
EXPOSE 3000
CMD flask run --host=0.0.0.0
