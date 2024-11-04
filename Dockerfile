FROM ubuntu:latest

# https://docs.suricata.io/en/latest/quickstart.html#installation
RUN echo Y | apt-get update
RUN apt-get install -y software-properties-common iptables net-tools
RUN add-apt-repository ppa:oisf/suricata-stable
RUN echo Y | apt-get update
RUN apt-get install -y suricata
