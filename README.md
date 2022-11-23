# Gyeeta Observability

[![Gyeeta Logo](https://pkg.gyeeta.workers.dev/gyeeta-96.png)](https://gyeeta.io)

[**Gyeeta**](https://gyeeta.io) is a non intrusive, *100% Open Source (GPLv3)* and *Free* Infrastructure, Services and Process Level monitor (*Linux* only).  

## Salient Features

- Monitor Hosts, Services, Processes at *Global* scale (scales to *tens of thousands* of hosts).
- Completely non-intrusive and uses a combination of eBPF and Kernel Statistics. No Application changes are needed. Gyeeta can monitor 
  both HTTP and non-HTTP based services and can provide statistics such as Queries/sec, Response Times, Network Throughputs, Service Network 
  Flows for any service (even proprietary or TLS encrypted).
- Monitor Kubernetes or any other Cluster orchestrators.

## Key Observability Capabilities

1. Service Level Statistics such as Queries/sec, Response Times (Latency) and HTTP Errors (if HTTP based) with no manual inputs or integrations.
   Monitors binary / proprietary network protocol or non HTTP Service statistics as well.
2. Query Global Aggregated Statistics from multiple servers using a single query either from Web UI or REST APIs.
3. Self Learning Algorithms that can detect Anomalies, Contention or Degradation without any manual inputs. 
4. Advanced Cluster, Service or Process Level Alerts using a powerful Web UI or REST APIs.
5. Detect Process Level *CPU starvation, Virtual Memory or IO Bottlenecks*. 
6. Monitors all applications without any instrumentation or tapping irrespective of the programming language used.
7. Auto Detect Service Dependencies and Service Network Flows (Service Maps).

## Components in Gyeeta

*Gyeeta* consists of the following components :

- Host Monitor Agent (named [`partha`](#host-monitor-agent-partha)) to be installed on each of the hosts which needs to be monitored

- A Central Server (named [`shyama`](#central-server-shyama)) which serves as both an Aggregating Server and an Alert Manager

- One or more Intermediate Servers (named [`madhava`](#intermediate-server-madhava)) analyzing metrics from multiple monitored hosts (`partha`)

- A [NodeJS Webserver](#webserver) which handles Web UI and REST API queries

- An [Alert Agent](#alert-action-agent) which interacts with `shyama` AlertManager and executes the Alert Trigger Actions (Notifications)

- One or more [Postgres DBs](#postgres-database) to be used as the datastore for `shyama` and `madhava` servers

The image below shows the high level overview of how the different components interact with each other :

![Gyeeta Architecture](https://gyeeta.io/img/gyeeta_arch.jpg)

## Github Repositories for different Gyeeta Components

- [For Partha Host Agent, Shyama Central Server and Madhava Intermediate Servers](https://github.com/gyeeta/gyeeta)

