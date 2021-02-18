# Building UPF docker image

## Building image

```shell
$ export OPENUPF_IMAGE_NAME=upf
$ sudo docker run -tid -e "LD_LIBRARY_PATH=/opt/upf/lib" -w "/opt/upf" -e "PATH=$PATH:/opt/upf/bin" --name ${OPENUPF_IMAGE_NAME} air5005/upu
$ sudo docker cp install/bin/ ${OPENUPF_IMAGE_NAME}:/opt/upf/bin
$ sudo docker cp install/lib/ ${OPENUPF_IMAGE_NAME}:/opt/upf/lib
$ sudo docker cp install/script/ ${OPENUPF_IMAGE_NAME}:/opt/upf/script
```

## Push to repository

```shell
$ UPF_CONT_ID=`sudo docker ps -a | grep ${OPENUPF_IMAGE_NAME} | awk 'NR==1{print $1}'`
$ sudo docker commit $UPF_CONT_ID registry.docker.com/${OPENUPF_IMAGE_NAME}:latest
$ sudo docker push registry.docker.com/${OPENUPF_IMAGE_NAME}
$ sudo docker rm -f ${OPENUPF_IMAGE_NAME}
```

## Remove residual docker

```shell
$ sudo docker rm -f ${OPENUPF_IMAGE_NAME}
```
