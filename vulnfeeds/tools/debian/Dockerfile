FROM gcr.io/oss-vdb/worker

RUN apt-get update
RUN apt-get install ca-certificates

RUN mkdir /src
WORKDIR /src

ENV PIP_NO_BINARY ""
RUN pip3 install pipenv==2021.5.29
COPY . /src

ENV LANG en_US.UTF-8
RUN cd debian_converter && pipenv sync

COPY run_* /src/
RUN chmod +x /src/run_*
