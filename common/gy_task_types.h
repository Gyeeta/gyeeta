//  SPDX-FileCopyrightText: 2022 Exact Solutions, Inc.
//  SPDX-License-Identifier: GPL-3.0-or-later

#pragma				once

#include			"gy_common_inc.h"
#include			"gy_misc.h"

namespace gyeeta {

namespace typeinfo {

//  Type of binary whether Interpreted or ByteCode instead of Machine code generation 
enum class BIN_TYPE : uint8_t
{
	BIN_MACHINE		= 0,

	BIN_JAVA,
	BIN_NODEJS,
	BIN_PYTHON,
	BIN_PERL,
	BIN_PHP,
	BIN_ERLANG,
	BIN_DENOJS,
	BIN_DASH,
	BIN_RUBY,
	BIN_SCALA,
	BIN_SH,
	BIN_BASH,

	BIN_UNKNOWN		= 255,
};	


static BIN_TYPE get_binary_type(const char *comm) noexcept
{
	switch (*comm) {
	
	case 'j' :
		if (0 == memcmp(comm, "java", 4 + 1)) {
			return BIN_TYPE::BIN_JAVA;
		}	
		break;

	case 'n' :
		if (0 == memcmp(comm, "node", 4 + 1)) {
			return BIN_TYPE::BIN_NODEJS;
		}	
		break;

	case 'p' :
		// Do not compare the entire name to account for versioned binaries
		if (0 == memcmp(comm, "python", 6)) {
			return BIN_TYPE::BIN_PYTHON;
		}	
		else if (0 == memcmp(comm, "perl", 4)) {
			return BIN_TYPE::BIN_PERL;
		}	
		else if (0 == memcmp(comm, "php", 3)) {
			return BIN_TYPE::BIN_PHP;
		}	
		break;

	case 'e' :
		if (0 == memcmp(comm, "erl", 3 + 1)) {
			return BIN_TYPE::BIN_ERLANG;
		}	
		break;
	
	case 'd' :
		if (0 == memcmp(comm, "deno", 4 + 1)) {
			return BIN_TYPE::BIN_DENOJS;
		}	
		else if (0 == memcmp(comm, "dash", 4 + 1)) {
			return BIN_TYPE::BIN_DASH;
		}	
		break;

	case 'r' :
		if (0 == memcmp(comm, "ruby", 4 + 1)) {
			return BIN_TYPE::BIN_RUBY;
		}	
		break;

	case 's' :
		if (0 == memcmp(comm, "scala", 5 + 1)) {
			return BIN_TYPE::BIN_SCALA;
		}	
		else if (0 == memcmp(comm, "sh", 2 + 1)) {
			return BIN_TYPE::BIN_SH;
		}	
		break;
	
	case 'b' :
		if (0 == memcmp(comm, "bash", 4 + 1)) {
			return BIN_TYPE::BIN_BASH;
		}	
		break;
	
	case '\0' :
		return BIN_TYPE::BIN_UNKNOWN;

	default :
		break;
	}	

	return BIN_TYPE::BIN_MACHINE;
};	

enum SVC_PORTS : uint16_t
{
	SVC_SSH				= 22,
	SVC_DNS				= 53,
	SVC_DNS_TLS			= 853,

	SVC_HTTP			= 80,
	SVC_HTTPS			= 443,
	SVC_HTTP_ALIAS			= 8080,
	SVC_HTTPS_ALIAS			= 8443,

	SVC_MYSQL			= 3306,
	SVC_MARIADB_REST		= 8989,

	SVC_POSTGRES			= 5432,

	SVC_CASSANDRA			= 9042,
	SVC_CASSANDRA_CLUST		= 7000,
	SVC_CASSANDRA_CLUST_TLS		= 7001,
	SVC_CASSANDRA_JMX		= 7199,

	SVC_ELASTICSEARCH_REST		= 9200,
	SVC_ELASTICSEARCH		= 9300,

	SVC_NEO4J_HTTP			= 7474,
	SVC_NEO4J_HTTPS			= 7473,
	SVC_NEO4J_BACKUP		= 6362,

	SVC_MONGODB			= 27017,
	SVC_MONGODB_SHARD		= 27018,
	SVC_MONGODB_CONFIG		= 27019,
	
	SVC_REDIS			= 6379,
	
	SVC_ORACLE			= 1521,

	SVC_MSSQL			= 1433,

	SVC_CONSUL_HTTP			= 8500,
	SVC_CONSUL_HTTPS		= 8501,
	SVC_CONSUL_GRPC			= 8502,
	SVC_CONSUL_LAN_SERF		= 8301,
	SVC_CONSUL_WAN_SERF		= 8302,
	SVC_CONSUL_SERVER_RPC		= 8300,
	
	SVC_ETCD_CLI			= 2379,
	SVC_ETCD_PEER			= 2380,

	SVC_KUBERNETES_MASTER		= 6443,
	
	SVC_MESOS_HTTP			= 5050,

	SVC_ZOOKEEPER_CLI		= 2181,
	SVC_ZOOKEEPER_FOLLOWER		= 2888,
	SVC_ZOOKEEPER_NODES		= 3888,

	SVC_KAFKA			= 9092,

	SVC_RABBITMQ			= 5672,
	SVC_RABBITMQ_TLS		= 5671,

	SVC_CEPH_MON			= 6789,
	SVC_CEPH_MON2			= 3300,
	SVC_CEPH_MGR			= 6800,

	SVC_COCKROACHDB			= 26257,

	SVC_PROMETHEUS			= 9090,
	SVC_GRAFANA			= 3000,
	SVC_INFLUXD			= 8086,

};	

// Will return true if port not likely to be HTTP. (HTTPS ports also returned true as HTTPS captures not supported)
static bool not_http_service(uint16_t port, const char *name, const char *cmdline) noexcept
{
	if (port < 1024 && port != SVC_HTTP) {
		return true;
	}

	switch (port) {

	case SVC_HTTP :	
	case SVC_HTTP_ALIAS :		
		return false;

	case SVC_HTTPS :
	case SVC_HTTPS_ALIAS :
		return true;

	case SVC_MYSQL :
		if (strstr(name, "mysql")) {
			return true;
		}
		break;

	case SVC_POSTGRES :
		if (strstr(name, "postgres")) {
			return true;
		}	
		break;

	case SVC_CASSANDRA :
	case SVC_CASSANDRA_CLUST :
	case SVC_CASSANDRA_CLUST_TLS :
		if ((strstr(name, "java")) && (strstr(cmdline, "cassandra"))) {
			return true;
		}	
		break;

	case SVC_CASSANDRA_JMX :
		if ((strstr(name, "java")) && (strstr(cmdline, "cassandra"))) {
			return false;
		}	
		break;

	case SVC_ELASTICSEARCH :
		if ((strstr(name, "java")) && (strstr(cmdline, "lasticsearch"))) {
			return true;
		}	
		break;

	case SVC_ELASTICSEARCH_REST :
		if ((strstr(name, "java")) && (strstr(cmdline, "lasticsearch"))) {
			return false;
		}	
		break;

	case SVC_NEO4J_HTTPS :
	case SVC_NEO4J_BACKUP :
		if ((strstr(name, "java")) && (strstr(cmdline, "neo4j"))) {
			return true;
		}	
		break;

	case SVC_NEO4J_HTTP :
		if ((strstr(name, "java")) && (strstr(cmdline, "neo4j"))) {
			return false;
		}	
		break;

	case SVC_MONGODB :
	case SVC_MONGODB_SHARD :
	case SVC_MONGODB_CONFIG :
		if (strstr(name, "mongo")) {
			return true;
		}	
		break;

	case SVC_REDIS :
		if (strstr(name, "redis-server")) {
			return true;
		}	
		break;

	case SVC_CONSUL_HTTPS :
	case SVC_CONSUL_LAN_SERF :
	case SVC_CONSUL_WAN_SERF :
	case SVC_CONSUL_SERVER_RPC :
		if (strstr(name, "consul")) {
			return true;
		}
		break;

	case SVC_CONSUL_HTTP :
		if (strstr(name, "consul")) {
			return false;
		}	
		break;

	case SVC_ZOOKEEPER_CLI :
	case SVC_ZOOKEEPER_FOLLOWER :
	case SVC_ZOOKEEPER_NODES :
		if ((strstr(name, "java")) && (strstr(cmdline, "zookeeper"))) {
			return true;
		}	
		break;

	case SVC_KAFKA :
		if (((strstr(name, "java")) || (strstr(name, "kafka"))) && (strstr(cmdline, "kafka"))) {
			return true;
		}
		break;

	case SVC_RABBITMQ :
	case SVC_RABBITMQ_TLS :
		if (strstr(name, "rabbitmq")) {
			return true;
		}	
		break;

	case SVC_CEPH_MON :
	case SVC_CEPH_MON2 :
	case SVC_CEPH_MGR :
		if (strstr(name, "ceph")) {
			return true;
		}	
		break;

	case SVC_COCKROACHDB :
		if (strstr(name, "cockroach")) {
			return true;
		}	
		break;

	case SVC_GRAFANA :
		if (strstr(name, "grafana")) {
			return false;
		}	
		break;

	case SVC_INFLUXD :
		if (strstr(name, "influxd")) {
			return false;
		}	
		break;


	default	:
		break;
	}	

	if (strstr(name, "mysql") && strstr(cmdline, "mysql")) {
		return true;
	}	
	else if (strstr(name, "redis-server") && strstr(cmdline, "redis-server")) {
		return true;
	}	
	else if (strstr(name, "postgres") && strstr(cmdline, "postgres")) {
		return true;
	}	
	else if (strstr(name, "mongo") && strstr(cmdline, "mongo")) {
		return true;
	}	
	else if (strstr(name, "rabbitmq") && strstr(cmdline, "rabbitmq")) {
		return true;
	}	
	else if (strstr(name, "cockroach") && strstr(cmdline, "cockroach")) {
		return true;
	}	
	else if (strstr(name, "ceph") && strstr(cmdline, "ceph")) {
		return true;
	}	

	return false;
}

static tribool ssl_enabled_listener(uint16_t port, const char *name, const char *cmdline) noexcept
{
	switch (port) {

	case SVC_HTTP :	
	case SVC_HTTP_ALIAS :		
		return false;

	case SVC_HTTPS :
	case SVC_HTTPS_ALIAS :
		return true;

	/*
	XXX TODO Add once SSL uprobe for Java, Go Binaries is supported...
	case SVC_CASSANDRA_CLUST_TLS :
		if ((strstr(name, "java")) && (strstr(cmdline, "cassandra"))) {
			return true;
		}	
		break;
	*/
	
	case SVC_CONSUL_HTTPS :
		if (strstr(name, "consul")) {
			return true;
		}
		break;

	case SVC_CONSUL_HTTP :
		if (strstr(name, "consul")) {
			return false;
		}	
		break;

	/*
	XXX TODO Add once these protocols parsing supported...
	case SVC_RABBITMQ :
		if (strstr(name, "rabbitmq")) {
			return false;
		}	
		break;

	case SVC_RABBITMQ_TLS :
		if (strstr(name, "rabbitmq")) {
			return true;
		}	
		break;
	*/

	default	:
		break;
	}	

	if (strstr(name, "mysql") && strstr(cmdline, "mysql")) {
		return indeterminate;
	}	
	else if (strstr(name, "redis-server") && strstr(cmdline, "redis-server")) {
		return indeterminate;
	}	
	else if (strstr(name, "postgres") && strstr(cmdline, "postgres")) {
		return indeterminate;
	}	
	else if (strstr(name, "mongo") && strstr(cmdline, "mongo")) {
		return indeterminate;
	}	
	/*
	else if (strstr(name, "rabbitmq") && strstr(cmdline, "rabbitmq")) {
		return indeterminate;
	}
	*/
	else if (strstr(name, "cockroach") && strstr(cmdline, "cockroach")) {
		return indeterminate;
	}	

	return false;
}	

/*
 * Returns true for listeners which can have both unencryoted and TLS encrypted payloads on same port.
 * Currently we just check a small subset of open source listeners
 */
static bool ssl_multiplexed_listener(uint16_t port, const char *name, const char *cmdline) noexcept
{
	return true == indeterminate(ssl_enabled_listener(port, name, cmdline));
}	

enum class SVC_TYPE : uint64_t
{
	WEB_SERVER		= 1 << 0,		// httpd[2], nginx, node, deno
	WEB_CACHING		= 1 << 1,		// varnishd, squid, haproxy, nginx, traefik, relayd
	SERVICE_MESH		= 1 << 2,		// linkerd, istio

	DATABASE		= 1 << 3,			
	DATA_CACHING		= 1 << 4,		// redis, memcached
	
	// TODO
};	

} // namespace typeinfo

} // namespace gyeeta


