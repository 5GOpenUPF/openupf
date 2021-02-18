# References

## What is the 5G User Plane Function (UPF)?

refer to [what-is-the-5g-upf](https://www.metaswitch.com/knowledge-center/reference/what-is-the-5g-user-plane-function-upf)

## Kubernetes configure CPU manager policy

Kubernetes needs to configure the CPU manager policy to be static

Refer to [kubernetes doc](https://kubernetes.io/docs/tasks/administer-cluster/cpu-management-policies/)

## Kubernetes configure device plugin

See [device-plugin](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/resource-management/device-plugin.md)

## SR-IOV Network device plugin for Kubernetes

[SR-IOV Network device plugin](https://github.com/k8snetworkplumbingwg/sriov-network-device-plugin)

[SR-IOV configuration](https://github.com/5GOpenUPF/openupf-deploy-script/sriov_configmap.yaml)

[SR-IOV CRD](https://github.com/5GOpenUPF/openupf-deploy-script/upf-dpdk-sriov.yaml)

## Using openupf command line tool

To run command-line tools of different units, you need to enter the corresponding pod first

After entering pod, you only need to execute cli <unit name>

Examples:

```shell
$ kubectl exec -ti -n upf upf-c-a-s7q97 -- bash
$ cli smu
```

Use `cli help` to see more
