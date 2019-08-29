FROM ubuntu

RUN apt-get -y update
RUN apt-get -y install build-essential python3 python3-pip python2.7 python2.7-dev python python-setuptools git wget automake cmake gdb
WORKDIR /unicorefuzz
ADD setupaflpp.sh ./
RUN ./setupaflpp.sh
ADD requirements.txt ./
RUN pip3 install -r requirements.txt
RUN pip3 install --force-reinstall --ignore-installed --no-binary :all: keystone-engine
ADD setupdebug.sh ./
RUN ./setupdebug.sh
ADD . ./