### Usage:
###   docker build -t ditto --build-arg UID=$(id -u) --build-arg GID=$(id -g) .
###   # Run docker either privileged or with --device=/dev/kvm to permit
###   # using kvm in the container.
###   docker run --privileged -it --name ditto -p 2222:22 ditto:latest

FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
# Set TZ and install tzdata early so 'requirements.sh' will not wait forever to prompt.
ENV TZ=Etc/UTC

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install -y git \
    python3 python3-pip \
    python3-venv sudo \
    tzdata locales \
    wget unzip vim

ARG UNAME=user
ARG UID=1000
ARG GID=1000
RUN set -x && groupadd -g ${GID} -o ${UNAME} && \
    useradd -u ${UID} -g ${GID} -G sudo -ms /bin/bash ${UNAME} && \
    echo "${UNAME} ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN addgroup kvm && usermod -a -G kvm ${UNAME}

RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environ && \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen && \
    echo "LANG=en_US.UTF-8" > /etc/locale.conf && \
    locale-gen en_US.UTF-8

USER ${UNAME}

RUN echo "export LANG=en_US.UTF-8" >> /home/${UNAME}/.bashrc
RUN echo "export LC_ALL=en_US.UTF-8" >> /home/${UNAME}/.bashrc

WORKDIR /home/${UNAME}
WORKDIR /home/${UNAME}/Ditto
RUN cd /home/${UNAME}/Ditto/ && wget https://zenodo.org/records/14098168/files/Ditto_Code.zip && unzip Ditto_Code.zip && rm Ditto_Code.zip
# Install Ditto python dependencies && system dependencies
RUN pip3 install -r requirements.txt && bash -ex core/scripts/requirements.sh

CMD ["bash"]
