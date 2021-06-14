FROM debian:unstable
RUN apt-get update && apt-get install -y libelf-dev
RUN apt-get install -y iputils-ping
RUN apt-get install -y iproute2
RUN apt-get install -y openssh-server
RUN ln -s /usr/lib/systemd/system/getty@.service /etc/systemd/system/getty.target.wants/getty@ttyS0.service
RUN echo "root:root" | chpasswd
