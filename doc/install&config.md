# Install

```shell
$ cd openupf/build
$ ./build.sh            # Compile and install
```

It is compiled and installed to `openupf/install` directory by default.
If you want to install to other paths, you need to copy it manually

# Config

All openupf related configurations are in [openupf-deploy-script](https://github.com/5GOpenUPF/openupf-deploy-script/deploy_upf/upf-configmap.yaml)

  - Currently, openupf only uses one network port to receive and forward N3|N6|N4|N9 packets, and distinguishes different services according to IP

  - In the configuration file of SMU, most of the functions of up featrues are supported. If not, it is indicated in the comments that it is not supported

  - There is a debug configuration in the configuration file of each unit, which controls the output granularity of the log. Normally, you only need to open MUST and ERR

  - When ueip in up featrues is enabled, [ueip] in SMU configuration file needs to be set to provide one or more assignable network segments

  - Most of the configuration data of FPU is transmitted when connecting to SMU


