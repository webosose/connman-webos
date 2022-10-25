/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2018-2021 LG Electronics, Inc.
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
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <gdbus.h>
#include <ctype.h>

#include "../include/sd.h"
#include <gsupplicant/gsupplicant.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static DBusMessage *sd_msg = NULL;

#define DISCOVER_SERVICE_FROM_ALL_PEERS "00:00:00:00:00:00"
#define UPNP_SERVICE "upnp"
#define BONJOUR_SERVICE "bonjour"

struct connman_service_discovery {
	GSupplicantInterface *interface;
	char *peer_service_prefix;
};

static struct connman_service_discovery *sd = NULL;

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter, value;
	const char *name;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	DBusMessage *reply;
	DBusMessageIter array, dict;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);
	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static void request_device_discovery()
{
	__connman_device_request_scan(CONNMAN_SERVICE_TYPE_P2P);
}

static void request_discover_service_callback(int result, GSupplicantInterface *interface,
								void *user_data, void* result_data)
{
	DBusMessage *reply;

	if(sd_msg == NULL)
		return;

	if(result < 0) {
		reply = __connman_error_failed(sd_msg, -result);
		if(reply != NULL)
			g_dbus_send_message(connection, reply);
	} else
		g_dbus_send_reply(connection, sd_msg,
								DBUS_TYPE_INT32, &result,
								DBUS_TYPE_INVALID);

	dbus_message_unref(sd_msg);
	sd_msg = NULL;
}

static DBusMessage *request_discover_upnp_service(DBusConnection *conn,
								DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter;
	const char *address, *description;
	dbus_int32_t version;
	GSupplicantP2PSDParams *sd_params;
	int err;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &address);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_INT32)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &version);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &description);

	sd_params = g_try_malloc0(sizeof(GSupplicantP2PSDParams));
	if(sd_params == NULL)
		return __connman_error_failed(msg, ENOMEM);

	if(g_str_equal(address, DISCOVER_SERVICE_FROM_ALL_PEERS) == FALSE) {
		const char *addr_no_colon;
		GString *str_peer_ident = g_string_new(NULL);
		char *peer_ident;
		struct connman_service *service;
		struct connman_network *network;
		const char *path;

		addr_no_colon = __connman_util_remove_colon_from_mac_addr(address);
		if(addr_no_colon == NULL) {
			g_string_free(str_peer_ident, TRUE);
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
                }

		g_string_append_printf(str_peer_ident, "%s_%s", sd->peer_service_prefix, addr_no_colon);
		g_free(addr_no_colon);

		peer_ident = g_string_free(str_peer_ident, FALSE);

		service = __connman_service_lookup_from_ident(peer_ident);
		if(service == NULL) {
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
		}

		network = __connman_service_get_network(service);
		path = connman_network_get_string(network, "Path");
		if(path == NULL) {
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
		}

		sd_params->peer = g_strdup(path);
	}
	sd_params->service_type = UPNP_SERVICE;
	sd_params->desc = g_strdup(description);
	sd_params->version = version;

	err = g_supplicant_interface_p2p_sd_request(sd->interface, sd_params,
												request_discover_service_callback, NULL);

	if(err == -EINPROGRESS) {
		sd_msg = dbus_message_ref(msg);

		request_device_discovery();
	} else {
		g_free(sd_params);
		return __connman_error_failed(msg, -err);
	}

	return NULL;
}

static DBusMessage *request_discover_bonjour_service(DBusConnection *conn,
								DBusMessage *msg, void *user_data)
{
	DBusMessageIter iter, iter_array;
	const char *address;
	unsigned char *query = NULL;
	int len = 0;
	GSupplicantP2PSDParams *sd_params;
	int err;

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &address);

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &iter_array);

	dbus_message_iter_get_fixed_array(&iter_array, &query, &len);

	sd_params = g_try_malloc0(sizeof(GSupplicantP2PSDParams));
	if(sd_params == NULL)
		return __connman_error_failed(msg, ENOMEM);

	if(g_str_equal(address, DISCOVER_SERVICE_FROM_ALL_PEERS) == FALSE) {
		const char *addr_no_colon;
		GString *str_peer_ident = g_string_new(NULL);
		char *peer_ident;
		struct connman_service *service;
		struct connman_network *network;
		const char *path;

		addr_no_colon = __connman_util_remove_colon_from_mac_addr(address);
		if(addr_no_colon == NULL) {
			g_string_free(str_peer_ident, TRUE);
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
                }

		g_string_append_printf(str_peer_ident, "%s_%s", sd->peer_service_prefix, addr_no_colon);
		g_free(addr_no_colon);

                peer_ident = g_string_free(str_peer_ident, FALSE);

		service = __connman_service_lookup_from_ident(peer_ident);
		if(service == NULL) {
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
		}

		network = __connman_service_get_network(service);
		path = connman_network_get_string(network, "Path");
		if(path == NULL) {
			g_free(sd_params);
			return __connman_error_invalid_arguments(msg);
		}

		sd_params->peer = g_strdup(path);
	}
	sd_params->query = query;
	sd_params->query_len = len;

	err = g_supplicant_interface_p2p_sd_request(sd->interface, sd_params,
												request_discover_service_callback, NULL);

	if(err == -EINPROGRESS) {
		sd_msg = dbus_message_ref(msg);

		request_device_discovery();
	} else {
		g_free(sd_params);
		return __connman_error_failed(msg, -err);
	}

	return NULL;
}

static const GDBusMethodTable sd_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("RequestDiscoverUPnPService",
			GDBUS_ARGS({ "address", "s" }, { "version", "i" }, { "description", "s" }),
			GDBUS_ARGS({ "reference", "i" }),
			request_discover_upnp_service) },
	{ GDBUS_ASYNC_METHOD("RequestDiscoverBonjourService",
			GDBUS_ARGS({ "address", "s" }, { "query", "ay" }),
			GDBUS_ARGS({ "reference", "i" }),
			request_discover_bonjour_service) },
	{},
};

static const GDBusSignalTable sd_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("DiscoveryResponse",
			GDBUS_ARGS({ "address", "s" }, { "reference", "i" }, { "tlv", "ay" })) },
	{ },
};

static void emit_sd_response(const char *dev_addr, int reference, unsigned char *tlv, int tlv_len)
{
	DBusMessage *signal;
	DBusMessageIter iter, array;

	signal = dbus_message_new_signal(CONNMAN_SD_PATH, CONNMAN_SD_INTERFACE, "DiscoveryResponse");
	if (signal == NULL)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &dev_addr);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_INT32, &reference);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &array);
	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE, &tlv, tlv_len);
	dbus_message_iter_close_container(&iter, &array);

	g_dbus_send_message(connection, signal);
}

void __connman_sd_response_from_p2p_peer(const char *peer_ident, int reference,
								unsigned char *tlv, int tlv_len)
{
	const char *dev_addr;

	dev_addr = __connman_util_insert_colon_to_mac_addr(peer_ident);

	emit_sd_response(dev_addr, reference, tlv, tlv_len);
	g_free(dev_addr);
}

void __connman_sd_init(GSupplicantInterface *interface, const char* dev_ident)
{
	connman_bool_t res;

	connection = connman_dbus_get_connection();

	sd = g_try_new0(struct connman_service_discovery, 1);
	if(sd == NULL)
		return;

	res = g_dbus_register_interface(connection, CONNMAN_SD_PATH, CONNMAN_SD_INTERFACE,
									sd_methods, sd_signals,
									NULL, NULL, NULL);

	if(res == FALSE) {
		g_free(sd);
		sd = NULL;
		return;
	}

	sd->interface = interface;
	sd->peer_service_prefix = g_strdup_printf("wifi_%s", dev_ident);
}

void __connman_sd_cleanup(void)
{
	if(connection != NULL)
		g_dbus_unregister_interface(connection, "/", CONNMAN_SD_INTERFACE);

	if(sd != NULL) {
		g_free(sd->peer_service_prefix);
		g_free(sd);
		sd = NULL;
	}
}
