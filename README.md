# OpenUPF

A 3GPP R16 compliant open source UPF.

Supports kubernetes and Docker based deployment. 

The software is mainly divided into three units: LBU (load balance unit), SMU (slow match unit) and FPU (fast pass unit).

OpenUPF uses [DPDK](https://github.com/DPDK/dpdk.git) to forward packets quickly combines.

## Network connection diagram

![Signaling data flow chart](/images/signal_flow_chart.png)

![Signaling data flow chart](/images/data_flow_chart.png)

## Summary

  - [Getting Started](#getting-started)
  - [Deployment](#deployment)
  - [Built With](#built-with)
  - [License](#license)
  - [Contact Us](#contact-us)

## Getting Started

### Prerequisites

Install dependency Library

```shell
$ cd openupf
$ sudo ./install/script/install-dep.sh  # Install compilation dependency
```

### Build
```shell
$ git clone https://github.com/5GOpenUPF/openupf.git
$ cd openupf/build
$ ./build.sh               # Compile binary to install directory
```

### Deploy

Refer to [Quick Start](http://www.panath.com.cn/en-us/docs/dir/demo3.html)

## Built With

  - [Contributor Covenant](https://www.contributor-covenant.org/) - Used
    for the Code of Conduct
  - [Creative Commons](https://creativecommons.org/) - Used to choose
    the license

## License

This project is licensed under the [Apache-2.0](LICENSE)
Creative Commons License - see the [LICENSE](LICENSE) file for
details

## Contribution

  - Open pull request with improvements
  - Discuss ideas in issues
  - Spread the word
  - Reach out with any feedback

## Supported By
   Copyright (c) 2021 ShenZhen Panath Technology Co., Ltd.

## Contact us
   * Webpage: [http://www.panath.com.cn](http://www.panath.com.cn)


