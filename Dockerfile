FROM ubuntu

RUN apt-get -y update
RUN apt-get -y install build-essential python3 python3-pip python2.7 python2.7-dev python python-setuptools git wget automake cmake gdb
WORKDIR /unicorefuzz
ADD requirements.txt ./
Add . ./
RUN ./setup.sh
