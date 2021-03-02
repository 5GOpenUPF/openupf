# OpenUPF

A 3GPP R16 compliant open source UPF.

The OpenUPF is an open source project for 5th generation (5G) mobile core networks User Plane Function. The goal of this project is to implement the User Plane Function (UPF) defined in 3GPP Release 16 (R16) and beyond. 

The software is mainly divided into three units: LBU (load balance unit), SMU (slow match unit) and FPU (fast pass unit).

OpenUPF uses [DPDK](https://github.com/DPDK/dpdk.git) to forward packets to acheive high througput.

## OpenUPF Architecture

![OpenUPF Architecture](/images/openupf_architecture.png)

## Features list

|**Supported**|**UP Function Features**                                                                              |
|:-------:|----------------------------------------------------------------------------------------------------------|
| **Y**   |(**BUCP**)Downlink Data Buffering in CP function is supported by the UP function.                         |
| **Y**   |(**DDND**)The buffering parameter 'Downlink Data Notification Delay' is supported by the UP function.     |
| **Y**   |(**DLBD**)The buffering parameter 'DL Buffering Duration' is supported by the UP function.                |
| **Y**   |(**TRST**)Traffic Steering is supported by the UP function.                                               |
| **Y**   |(**FTUP**)F-TEID allocation / release in the UP function is supported by the UP function.                 |
| **Y**   |(**PFDM**)The PFD Management procedure is supported by the UP function.                                   |
| **Y**   |(**HEEU**)Header Enrichment of Uplink traffic is supported by the UP function.                            |
| **Y**   |(**TREU**)Traffic Redirection Enforcement in the UP function is supported by the UP function.             |
| **Y**   |(**EMPU**)Sending of End Marker packets supported by the UP function.                                     |
| **Y**   |(**PDIU**)Support of PDI optimised signalling in UP function.                                             |
| **Y**   |(**UDBC**)Support of UL/DL Buffering Control.                                                             |
| **Y**   |(**QUOAC**)The UP function supports being provisioned with the Quota Action to apply when reaching quotas.|
|   N     |(**TRACE**)The UP function supports Trace.                                                                |
| **Y**   |(**FRRT**)The UP function supports Framed Routing.                                                        |
| **Y**   |(**PFDE**)The UP function supports a PFD Contents including a property with multiple values.              |
| **Y**   |(**EPFAR**)The UP function supports the Enhanced PFCP Association Release feature.                        |
| **Y**   |(**DPDRA**)The UP function supports Deferred PDR Activation or Deactivation.                              |
| **Y**   |(**ADPDP**)The UP function supports the Activation and Deactivation of Pre-defined PDRs.                  |
| **Y**   |(**UEIP**)The UPF supports allocating UE IP addresses or prefixes.                                        |
| **Y**   |(**SSET**)UPF support of PFCP sessions successively controlled by different SMFs of a same SMF Set.       |
|   N     |(**MNOP**)UPF supports measurement of number of packets which is instructed with the flag 'Measurement of Number of Packets' in a URR.|
|   N     |(**MTE**)UPF supports multiple instances of Traffic Endpoint IDs in a PDI.                                |
|   N     |(**BUNDL**)PFCP messages bunding is supported by the UP function.                                         |
|   N     |(**GCOM**)UPF support of 5G VN Group Communication.                                                       |
|   N     |(**MPAS**)UPF support for multiple PFCP associations to the SMFs in an SMF set.                           |
|   N     |(**RTTL**)The UP function supports redundant transmission at transport layer.                             |
|   N     |(**VTIME**)UPF support of quota validity time feature.                                                    |
|   N     |(**NORP**)UP function support of Number of Reports.                                                       |
|   N     |(**IPTV**)UPF support of IPTV service                                                                     |
|   N     |(**IP6PL**)UPF supports UE IPv6 address(es) allocation with IPv6 prefix length other than default /64 (including allocating /128 individual IPv6 addresses).|
|   N     |(**TSCU**)Time Sensitive Communication is supported by the UPF.                                           |
|   N     |(**MPTCP**)UPF support of MPTCP Proxy functionality.                                                      |
|   N     |(**ATSSS-LL**)UPF support of ATSSS-LLL steering functionality.                                            |
|   N     |(**QFQM**)UPF support of per QoS flow per UE QoS monitoring.                                              |
|   N     |(**GPQM**)UPF support of per GTP-U Path QoS monitoring.                                                   |
|   N     |(**MT-EDT**)SGW-U support of reporting the size of DL Data Packets.                                       |
|   N     |(**CIOT**)UPF support of CIoT feature, e.g. small data packet rate enforcement.                           |
|   N     |(**ETHAR**)UPF support of Ethernet PDU Session Anchor Relocation.                                         |

## Summary

  - [Getting Started](#getting-started)
  - [Built With](#built-with)
  - [License](#license)
  - [Contact Us](#contact-us)

## Getting Started

Refer to [Quick Start](http://www.openupf.net/openupf_dg.pdf)

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
   Copyright © 2021 Shenzhen Panath Technology Co., Ltd.

## Contact us
   * Webpage: [http://www.openupf.net](http://www.openupf.net)


