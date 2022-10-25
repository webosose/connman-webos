/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2012  Intel Corporation. All rights reserved.
 *  Copyright (C) 2011	ProFUSION embedded systems
 *  Copyright (C) 2013 LG Electronics, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/if_bridge.h>

#include "connman.h"

#include <gdhcp/gdhcp.h>

#include <gdbus.h>

#ifndef DBUS_TYPE_UNIX_FD
#define DBUS_TYPE_UNIX_FD -1
#endif

#define BRIDGE_DNS		"8.8.8.8"
#define DEFAULT_MTU		1500

#define PRIVATE_NETWORK_PRIMARY_DNS		BRIDGE_DNS
#define PRIVATE_NETWORK_SECONDARY_DNS		"8.8.4.4"

#define P2P_DEFAULT_BLOCK		0xc0a83100 //192.168.49.x

static GDHCPServer *tethering_dhcp_server = NULL;
static struct connman_ippool *dhcp_ippool = NULL;

static char* bridge_name;

void __connman_p2p_go_set_bridge(char *bridge)
{
	bridge_name = g_strdup(bridge);
}

const char *__connman_p2p_go_get_bridge(void)
{
	return bridge_name;
}

static void dhcp_server_debug(const char *str, void *data)
{
	connman_info("%s: %s\n", (const char *) data, str);
}

static void dhcp_server_error(GDHCPServerError error)
{
	switch (error) {
	case G_DHCP_SERVER_ERROR_NONE:
		connman_error("OK");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_UNAVAILABLE:
		connman_error("Interface unavailable");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_IN_USE:
		connman_error("Interface in use");
		break;
	case G_DHCP_SERVER_ERROR_INTERFACE_DOWN:
		connman_error("Interface down");
		break;
	case G_DHCP_SERVER_ERROR_NOMEM:
		connman_error("No memory");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_INDEX:
		connman_error("Invalid index");
		break;
	case G_DHCP_SERVER_ERROR_INVALID_OPTION:
		connman_error("Invalid option");
		break;
	case G_DHCP_SERVER_ERROR_IP_ADDRESS_INVALID:
		connman_error("Invalid address");
		break;
	}
}

static GDHCPServer *dhcp_server_start(const char *bridge,
				const char *router, const char* subnet,
				const char *start_ip, const char *end_ip,
				unsigned int lease_time, const char *dns)
{
	GDHCPServerError error;
	GDHCPServer *dhcp_server;
	int index;

	DBG("");

	index = connman_inet_ifindex(bridge);
	if (index < 0)
		return NULL;

	dhcp_server = g_dhcp_server_new(G_DHCP_IPV4, index, &error);
	if (!dhcp_server) {
		dhcp_server_error(error);
		return NULL;
	}

	g_dhcp_server_set_debug(dhcp_server, dhcp_server_debug, "DHCP server");

	g_dhcp_server_set_lease_time(dhcp_server, lease_time);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_SUBNET, subnet);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_ROUTER, router);
	g_dhcp_server_set_option(dhcp_server, G_DHCP_DNS_SERVER, dns);
	g_dhcp_server_set_ip_range(dhcp_server, start_ip, end_ip);

	g_dhcp_server_start(dhcp_server);

	return dhcp_server;
}

static void dhcp_server_stop(GDHCPServer *server)
{
	if (!server)
		return;

	g_dhcp_server_unref(server);
}

int __connman_p2p_go_set_enabled(void)
{
	int index;
	int err;
	const char *gateway;
	const char *broadcast;
	const char *subnet_mask;
	const char *start_ip;
	const char *end_ip;
	const char *dns;

	index = connman_inet_ifindex(bridge_name);
	connman_info("p2pgo.c :  index = %d",index);

	dhcp_ippool = __connman_ippool_create_with_block(index, 2, 252,
						P2P_DEFAULT_BLOCK, NULL, NULL);

	if (!dhcp_ippool) {
		connman_error("Fail to create IP pool");
		__connman_bridge_remove(bridge_name);
	}

	gateway = __connman_ippool_get_gateway(dhcp_ippool);
	broadcast = __connman_ippool_get_broadcast(dhcp_ippool);
	subnet_mask = __connman_ippool_get_subnet_mask(dhcp_ippool);
	start_ip = __connman_ippool_get_start_ip(dhcp_ippool);
	end_ip = __connman_ippool_get_end_ip(dhcp_ippool);

	err = __connman_bridge_enable(bridge_name, gateway,
		connman_ipaddress_calc_netmask_len(subnet_mask), broadcast);
	if (err < 0 && err != -EALREADY) {
		__connman_ippool_unref(dhcp_ippool);
		__connman_bridge_remove(bridge_name);
	}

	dns = gateway;
	if (__connman_dnsproxy_add_listener(index) < 0) {
		connman_error("Can't add listener %s to DNS proxy",
								bridge_name);
		dns = BRIDGE_DNS;
	}

	tethering_dhcp_server = dhcp_server_start(bridge_name,
						gateway, subnet_mask,
						start_ip, end_ip,
						24 * 3600, dns);
	if (tethering_dhcp_server == NULL) {
		__connman_bridge_disable(bridge_name);
		__connman_ippool_unref(dhcp_ippool);
		__connman_bridge_remove(bridge_name);
	}

	DBG("p2p go dhcp started");
	return 0;
}

void __connman_p2p_go_set_disabled(void)
{
	int index;

	index = connman_inet_ifindex(bridge_name);
	if (index < 0)
		return;

	__connman_dnsproxy_remove_listener(index);

	__connman_nat_disable(bridge_name);

	dhcp_server_stop(tethering_dhcp_server);

	tethering_dhcp_server = NULL;

	__connman_bridge_disable(bridge_name);

	__connman_ippool_unref(dhcp_ippool);

	__connman_bridge_remove(bridge_name);

	DBG("p2p go stopped");
}

void __connman_p2p_go_tethering_set_enabled(void)
{
	unsigned char prefixlen;
	const char *subnet_mask;
	const char *start_ip;

	if (!dhcp_ippool)
		return;
	subnet_mask = __connman_ippool_get_subnet_mask(dhcp_ippool);
	start_ip = __connman_ippool_get_start_ip(dhcp_ippool);

	prefixlen =
		connman_ipaddress_calc_netmask_len(subnet_mask);
	__connman_nat_enable(bridge_name, start_ip, prefixlen);
}

void __connman_p2p_go_tethering_set_disabled(void)
{
	__connman_nat_disable(bridge_name);
}

const char* __connman_p2p_group_get_local_ip(void)
{
	if(dhcp_ippool) {
		const char *gateway = __connman_ippool_get_gateway(dhcp_ippool);
		return gateway;
	}

	return NULL;
}

void __connman_dhcpserver_append_gateway(DBusMessageIter* iter)
{
	const char* local_address = __connman_p2p_group_get_local_ip();
	if(local_address != NULL)
		connman_dbus_dict_append_basic(iter, "LocalAddress", DBUS_TYPE_STRING, &local_address);
}

int __connman_p2p_go_init(void)
{
	DBG("");
	return 0;
}

void __connman_p2p_set_dhcp_pool(struct connman_ippool *ippool)
{
	dhcp_ippool = ippool;
}

void __connman_p2p_go_cleanup(void)
{
	DBG("");
}
