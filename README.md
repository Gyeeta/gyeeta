# Gyeeta Observability

<p align="center"><a href="https://gyeeta.io"><img src="https://pkg.gyeeta.workers.dev/gyeeta-96.png" alt="Gyeeta" width="96" /></a></p>


[***Gyeeta***](https://gyeeta.io) is a non intrusive, *100% Open Source (GPLv3)* and *Free* Infrastructure, Services and Process Level monitor (*Linux* only).  


## Key Observability Capabilities

- Monitor Hosts, Services, Processes at *Global* scale (scales to *tens of thousands* of hosts).
- Completely non-intrusive and uses a combination of eBPF and Kernel Statistics. No Application changes are needed. Gyeeta can monitor 
  both HTTP and non-HTTP based services and can provide statistics such as Queries/sec, Response Times, Network Throughputs, Service Network 
  Flows for any service (even proprietary or TLS encrypted).
- Monitor Kubernetes or any other Cluster orchestrators.
- Service Level Statistics such as Queries/sec, Response Times (Latency) and HTTP Errors (if HTTP based) with no manual inputs or integrations.
  Monitors binary / proprietary network protocol or non HTTP Service statistics as well.
- Query Global Aggregated Statistics from multiple servers using a single query either from Web UI or REST APIs.
- Self Learning Algorithms that can detect Anomalies, Contention or Degradation without any manual inputs. 
- Advanced Cluster, Service or Process Level Alerts using a powerful Web UI or REST APIs.
- Detect Process Level *CPU starvation, Virtual Memory or IO Bottlenecks*. 

[***Website***](https://gyeeta.io) | [***Documentation***](https://gyeeta.io/docs) | [***Youtube***](https://youtube.com/@gyeeta)

## License

Gyeeta is licensed under the [GNU General Public License v3.0 (GPLv3)](./LICENSE) open source license.

## Components in Gyeeta

*Gyeeta* consists of the following components :

- Host Monitor Agent (named `partha`) to be installed on each of the hosts which needs to be monitored

- A Central Server (named `shyama`) which serves as both an Aggregating Server and an Alert Manager

- One or more Intermediate Servers (named `madhava`) analyzing metrics from multiple monitored hosts (`partha`)

- A NodeJS Webserver which handles Web UI and REST API queries

- An Alert Agent which interacts with `shyama` AlertManager and executes the Alert Trigger Actions (Notifications)

- One or more Postgres DBs to be used as the datastore for `shyama` and `madhava` servers

The image below shows the high level overview of how the different components interact with each other :

![Gyeeta Architecture](https://gyeeta.io/img/gyeeta_arch.jpg)

## Install Options for Gyeeta components

Gyeeta components can be installed using any of the following methods :

- Bash Script based Installation and Configuration (Easiest install option)
- Kubernetes Helm Chart
- Docker Containers
- rpm / deb based native packages for dnf/yum, apt-get or zypper
- Manual Tar Package download and configure

Installing using either the Bash Script or Kubernetes Helm Charts are the easiest ways to deploy the various Gyeeta
components.

**Install instructions** are available at [Gyeeta Install Planning and Options](https://gyeeta.io/docs/installation/install_options)

**A Quick TL;DR Install of Gyeeta Server Components** can be found at [TL;DR Instructions](https://gyeeta.io/docs/installation/install_options)

## Supported Linux Distributions

| OS Distribution | Supported Versions |
| :-------------: | :-------------: |
| Ubuntu | 16 & higher |
| Debian | 9 & higher |
| RHEL, CentOS, Rocky Linux, Oracle Linux | 8 & higher |
| Amazon Linux 2 | All Versions |
| Amazon Linux | Year 2017+ |
| Google Container OS (COS) | Linux Kernel 4.14 & Higher |
| Fedora | 28 & higher |
| OpenSUSE, SUSE Linux | 15 & higher |

Other Linux distributions based on Debian/Ubuntu or RHEL are supported as long as the base Linux Kernel is 4.4+

Container Platforms such as Kubernetes or Docker Swarm are also supported using Helm Charts or Docker containers.


## Main Github Repositories for different Gyeeta Components

- [Partha Host Agent, Shyama Central Server and Madhava Intermediate Servers](https://github.com/gyeeta/gyeeta)
- [Node Webserver](https://github.com/gyeeta/nodewebserver)
- [Frontend React WebUI](https://github.com/gyeeta/frontend)
- [Alert Agent](https://github.com/gyeeta/alertaction)

## Info on this Repository

This repository provides the source for the Gyeeta Host Agents (*Partha*), *Shyama Central Server* and *Madhava Intermediate Server*.

Gyeeta uses C++ (C++17) as the programming language for these components. 

### Building the Components

We provide a Docker container for building this repo source.

```bash
docker pull ghcr.io/gyeeta/gyeeta-devel:latest
```

Note that the container is of 4 GB size. 

Users can run the container optionally passing a Volume mount for the git source.

To compile the source from within the container :

```bash
git clone https://github.com/Gyeeta/gyeeta.git
cd gyeeta
make ci
```
