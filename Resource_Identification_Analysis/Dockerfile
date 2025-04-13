FROM docker.io/library/golang:1.23.0
RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/kubernetes/kubernetes.git /kubernetes
WORKDIR /kubernetes
RUN git checkout v1.30.10
COPY ./main /main
WORKDIR /main
RUN go mod init main
RUN go env -w GOPROXY=https://goproxy.io,direct
RUN go mod tidy
CMD ["bash"]
