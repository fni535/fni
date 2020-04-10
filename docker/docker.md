yum update

yum install -y yum-utils device-mapper-persistent lvm2

sudo yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

yum install -y docker -ce

docker -v

从docker（https://hub.docker.com/）下载镜像慢：更新阿里云镜像加速器：

systemctl status

systemctl stop

systemctl restart

systemctl enable





查看镜像:docker images 

搜索镜像:docker search [images]

拉取镜像:docker pull [image]：[version]

删除镜像:docker rmi imageID    删除所有镜像：docker rmi ”docker images -q“

REPOSITORY（仓库）    TAG      IMAGE ID   CREATED  SIZE  OFFICIAL(是否官方)            AUTOMATED



 docker ps -a     

docker run -id --name c3 -v $pwd/data:/root/data2  centos:7 /bin/bash

docker run -it --name c1 centos:7 /bin/bash 

docker exec -t containerID /bin/bash

