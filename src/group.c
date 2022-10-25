/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2013-2019 LG Electronics, Inc.
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

#include <connman/storage.h>
#include <connman/setting.h>
#include <connman/agent.h>
#include "include/group.h"
#include <gsupplicant/gsupplicant.h>

#include "connman.h"

static DBusConnection *connection = NULL;
static GList *group_list = NULL;
static GHashTable *group_hash = NULL;

struct peer_cb_data {
	DBusMessageIter *iter;
	struct connman_group *group;
};

static struct connman_group *group_get(const char *identifier)
{
	struct connman_group *group;

	group = g_hash_table_lookup(group_hash, identifier);
	if (group) {
		return group;
	}

	group = g_try_new0(struct connman_group, 1);
	if (!group)
		return NULL;

	DBG("group %p", group);

	group->identifier = g_strdup(identifier);
	group->peer_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	group->peer_intf = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

	group_list = g_list_prepend(group_list, group);

	g_hash_table_insert(group_hash, group->identifier, group);

	return group;
}

static int set_tethering(struct connman_group *group,
		bool enabled)
{
	group->tethering = enabled;
	dbus_bool_t val = enabled;

	connman_dbus_property_changed_basic(group->path,
			CONNMAN_GROUP_INTERFACE, "Tethering",
			DBUS_TYPE_BOOLEAN,
			&val);

	if (enabled == TRUE) {
		__connman_p2p_go_tethering_set_enabled();
	} else {
		__connman_p2p_go_tethering_set_disabled();
	}

	return 0;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_group *group = user_data;
	DBusMessageIter iter, value;
	const char *name;
	int type;

	DBG("group %p", group);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	if (g_str_equal(name, "Tethering") == TRUE) {
		int err;
		bool tethering;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &tethering);

		if (group->tethering == tethering) {
			if (tethering == FALSE)
				return __connman_error_already_disabled(msg);
			else
				return __connman_error_already_enabled(msg);
		}

		err = set_tethering(group, tethering);
		if (err < 0)
			return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void append_properties(DBusMessageIter *dict, struct connman_group *group)
{
	dbus_bool_t val;
	struct connman_peer *connman_peer = NULL;

	if(group->name)
		connman_dbus_dict_append_basic(dict, "Name", DBUS_TYPE_STRING, &group->name);

	val = group->is_group_owner;
	connman_dbus_dict_append_basic(dict, "Owner", DBUS_TYPE_BOOLEAN, &val);

	if (group->is_group_owner)
		connman_dbus_dict_append_basic(dict, "Passphrase", DBUS_TYPE_STRING, &group->passphrase);
	else if (group->group_owner)
		connman_dbus_dict_append_basic(dict, "OwnerPath", DBUS_TYPE_OBJECT_PATH, &group->group_owner);

	val = group->is_persistent;
	connman_dbus_dict_append_basic(dict, "Persistent", DBUS_TYPE_BOOLEAN, &val);

	val = group->tethering;
	connman_dbus_dict_append_basic(dict, "Tethering", DBUS_TYPE_BOOLEAN, &val);

	connman_dbus_dict_append_basic(dict, "Freq", DBUS_TYPE_UINT32, &group->freq);

	if(group->is_group_owner)
		__connman_dhcpserver_append_gateway(dict);
	/*else {
		connman_peer = connman_peer_get_by_path(group->group_owner);
		if (connman_peer) {
			connman_peer_get_local_address(dict, connman_peer);
		}
	}*/
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_group *group = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("group %p", group);

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	dbus_message_iter_init_append(reply, &array);

	connman_dbus_dict_open(&array, &dict);
	append_properties(&dict, group);
	connman_dbus_dict_close(&array, &dict);

	return reply;
}

static void group_added_signal(struct connman_group *group)
{
	DBusMessage *signal;
	DBusMessageIter iter;
	DBusMessageIter dict;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GroupAdded");
	if (!signal)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&group->path);

	connman_dbus_dict_open(&iter, &dict);
	append_properties(&dict, group);
	connman_dbus_dict_close(&iter, &dict);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void group_removed_signal(struct connman_group *group)
{
	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GroupRemoved",
			DBUS_TYPE_OBJECT_PATH, &group->path,
			DBUS_TYPE_INVALID);
}

static void p2p_disconnect_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_group *group = user_data;

	DBG("group %p\n", group);
}

static DBusMessage *p2p_disconnect(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_group *group = user_data;
	int err = 0;

	DBG("group %p", group);

	err = g_supplicant_interface_p2p_group_disconnect(group->interface, p2p_disconnect_callback, group);

	if (err < 0) {
		if (err != -EINPROGRESS)
			return __connman_error_failed(msg, -err);
	}

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void p2p_invite_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	DBG("p2p invite callback %d\n", result);
}

static DBusMessage *p2p_invite(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_group *group = user_data;
	DBusMessageIter iter;
	const char *peer_path;
	char *peer_ident;
	GSupplicantP2PInviteParams *invite_params = NULL;
	struct connman_service *service;
	struct connman_network *network;
	struct connman_peer *connman_peer;
	GSupplicantPeer *gs_peer;

	DBG("group %p", group);

	if (dbus_message_iter_init(msg, &iter) == FALSE)
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &peer_path);

	connman_peer = connman_peer_get_by_path(peer_path);
	peer_ident = connman_peer_get_identifier(connman_peer);

	gs_peer = g_supplicant_interface_peer_lookup(group->orig_interface, peer_ident);

	if(!gs_peer || !g_supplicant_peer_get_path(gs_peer))
		return __connman_error_invalid_arguments(msg);

	invite_params = g_try_malloc0(sizeof(GSupplicantP2PInviteParams));
	if (!invite_params)
		return __connman_error_invalid_arguments(msg);

	invite_params->peer = g_strdup(g_supplicant_peer_get_path(gs_peer));

	g_supplicant_interface_p2p_invite(group->interface, invite_params, p2p_invite_callback, NULL);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void append_peer_struct(gpointer value, gpointer user_data)
{
	struct peer_cb_data *cbd = user_data;
	const char *peer_ident = value;
	const char *peer_path, *peer_dev_addr = NULL;
	DBusMessageIter entry, dict;
	struct connman_peer *connman_peer = NULL;

	DBG("peer_ident %s", peer_ident);

	dbus_message_iter_open_container(cbd->iter, DBUS_TYPE_STRUCT, NULL, &entry);

	peer_path = g_hash_table_lookup(cbd->group->peer_hash, peer_ident);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH, &peer_path);

	connman_peer = connman_peer_get_by_path(peer_path);
	if (connman_peer) {
		__connman_peer_get_properties_struct(&entry, connman_peer);
	} else {
		connman_dbus_dict_open(&entry, &dict);
		peer_dev_addr = __connman_util_insert_colon_to_mac_addr(peer_ident);
		connman_dbus_dict_append_basic(&dict, "DeviceAddress", DBUS_TYPE_STRING, &peer_dev_addr);
		connman_dbus_dict_close(&entry, &dict);
	}

	dbus_message_iter_close_container(cbd->iter, &entry);
	g_free(peer_dev_addr);
}

static void append_peer_structs(DBusMessageIter *iter, void *user_data)
{
	struct connman_group *group = user_data;
	struct peer_cb_data cbd;

	cbd.iter = iter;
	cbd.group = group;

	DBG("iter %p group %p", iter, group);

	g_slist_foreach(group->peer_list, append_peer_struct, &cbd);
}

static void append_peer_go(DBusMessageIter *iter, void *user_data)
{
	struct connman_group *group = user_data;
	const char *peer_ident, *peer_dev_addr = NULL;
	DBusMessageIter entry, dict;
	struct connman_peer *connman_peer;

	if(!group || !g_list_find(group_list, group) || !group->group_owner)
		return;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH, &group->group_owner);

	connman_peer = connman_peer_get_by_path(group->group_owner);
	if(connman_peer) {
		peer_ident = connman_peer_get_identifier(connman_peer);
		__connman_peer_get_properties_struct(&entry, connman_peer);
	} else {
		connman_dbus_dict_open(&entry, &dict);
		peer_ident = strrchr(group->group_owner, '_') + 1;
		peer_dev_addr = __connman_util_insert_colon_to_mac_addr(peer_ident);
		connman_dbus_dict_append_basic(&dict, "DeviceAddress", DBUS_TYPE_STRING, &peer_dev_addr);
		connman_dbus_dict_close(&entry, &dict);
	}

	dbus_message_iter_close_container(iter, &entry);
	g_free(peer_dev_addr);
}

static DBusMessage *get_peers(DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	struct connman_group *group = user_data;
	DBusMessage *reply;

	reply = dbus_message_new_method_return(msg);
	if (reply == NULL)
		return NULL;

	if(group->is_group_owner)
		__connman_dbus_append_objpath_dict_array(reply,
			append_peer_structs, group);
	else
		__connman_dbus_append_objpath_dict_array(reply,
			append_peer_go, group);

	return reply;
}

static const GDBusMethodTable group_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_METHOD("Disconnect",
			NULL, NULL, p2p_disconnect) },
	{ GDBUS_METHOD("Invite",
			GDBUS_ARGS({ "service_path", "s" }),
			NULL, p2p_invite) },
	{ GDBUS_METHOD("GetPeers",
			NULL, GDBUS_ARGS({ "peers", "a(oa{sv})" }),
			get_peers) },
	{},
};

static const GDBusSignalTable group_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ GDBUS_SIGNAL("PeerAdded",
			GDBUS_ARGS({ "path", "o" })) },
	{ GDBUS_SIGNAL("PeerRemoved",
			GDBUS_ARGS({ "path", "o" })) },
	{ },
};

const char* __connman_group_get_path(struct connman_group *group)
{
	if (group)
		return group->path;

	return NULL;
}

const char* __connman_group_get_identifier(struct connman_group *group)
{
	return group->identifier;
}

const char* __connman_group_get_group_owner(struct connman_group *group)
{
	if (group)
		return group->group_owner;

	return NULL;
}

int  __connman_group_get_list_length(struct connman_group *group)
{
	int length = 0;

	if (group->peer_list == NULL)
		return 0;

	length = g_slist_length(group->peer_list);

	return length;
}

bool __connman_group_is_autonomous(struct connman_group *group)
{
		return group->autonomous;
}

bool __connman_group_exist(void)
{
	if(!group_list || !group_list->data)
		return false;

	return true;
}

int __connman_group_accept_connection(struct connman_group *group, GSupplicantP2PWPSParams *wps_params)
{
	if(group == NULL)
		return -1;

	if(group->path == NULL)
		return -1;

	return g_supplicant_interface_p2p_wps_start(group->interface, wps_params, NULL, NULL);
}

void __connman_group_peer_failed(struct connman_group *group)
{
	g_supplicant_interface_p2p_group_disconnect(group->interface, NULL, NULL);
}

struct connman_group *__connman_group_lookup_from_ident(const char *identifier)
{
	return group_get(identifier);
}

static void append_dict_properties(DBusMessageIter *dict, void *user_data)
{
	struct connman_group *group = user_data;

	append_properties(dict, group);
}

static void append_struct_group(DBusMessageIter *iter,
		connman_dbus_append_cb_t function,
		struct connman_group *group)
{
	DBusMessageIter entry, dict;

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
							&group->path);

	connman_dbus_dict_open(&entry, &dict);
	if (function)
		function(&dict, group);
	connman_dbus_dict_close(&entry, &dict);

	dbus_message_iter_close_container(iter, &entry);
}

static void append_struct(gpointer value, gpointer user_data)
{
	struct connman_group *group = value;
	DBusMessageIter *iter = user_data;

	if (!group->path)
		return;

	append_struct_group(iter, append_dict_properties, group);
}

void __connman_group_list_struct(DBusMessageIter *iter)
{
	g_list_foreach(group_list, append_struct, iter);
}

static int group_register(struct connman_group *group)
{
	DBG("group %p", group);

	if (group->path != NULL)
		return -EALREADY;

	group->path = g_strdup_printf("%s/group/%s", CONNMAN_PATH,
						group->identifier);

	DBG("path %s", group->path);

	g_dbus_register_interface(connection, group->path,
								CONNMAN_GROUP_INTERFACE,
								group_methods, group_signals,
								NULL, group, NULL);

	if (!group->autonomous)
		__connman_p2p_set_dhcp_pool(NULL);
	group_added_signal(group);

	return 0;
}

static void interface_create_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_group *group = user_data;

	DBG("result %d ifname %s", result,
				g_supplicant_interface_get_ifname(interface));

	group->interface = interface;
}

void __connman_group_client_dhcp_ip_assigned(struct connman_group *group)
{
	dbus_bool_t dhcp_address = TRUE;

	connman_dbus_property_changed_basic(group->path,
			CONNMAN_GROUP_INTERFACE, "DHCPAddress", DBUS_TYPE_BOOLEAN,
			&dhcp_address);
}
struct connman_group* __connman_group_create(GSupplicantInterface *iface, const char *ifname, const char *ssid, const char *passphrase,
											bool go, bool persistent, const char *go_path, bool autonomous, int freq)
{
	struct connman_group *group;
	char *ident;
	int ssid_len = strlen(ssid);
	GString *name = g_string_sized_new(ssid_len * 2 + 1);
	int i=0;
	int ret=0;

	DBG("ssid : %s, len : %d\n", ssid, ssid_len);

	for(i=0; i<ssid_len; i++) {
		g_string_append_printf(name, "%02x", ssid[i]);
	}

	ident = g_string_free(name, FALSE);

	DBG("ident : %s\n", ident);

	group = group_get(ident);

	g_free(ident);
	ident = NULL;
	if (!group)
		return NULL;

	group->name = g_strdup(ssid);
	group->is_group_owner = go;
	if (go) {
		group->passphrase = g_strdup(passphrase);
	}
	group->is_persistent = persistent;
	group->group_owner = go_path;
	group->autonomous = autonomous;
	group->freq = freq;
	group->is_static_ip = false;
	group->orig_interface = iface;

	DBG("go path : %s\n", go_path);

	ret = group_register(group);

	if (ret == 0) {
		g_supplicant_interface_create(ifname, "nl80211", NULL, NULL, interface_create_callback, group);
	}

	return group;
}

void __connman_group_remove(GSupplicantInterface *interface)
{
	GList *list;
	struct connman_group *group = NULL;

	if(!group_list)
		return;

	for (list = group_list; list != NULL; list = list->next) {
		group = list->data;

		if (group->interface == interface) {
			break;
		}
	}

	if (group) {
		DBG("group removed\n");

		if(!connection)
			connection = connman_dbus_get_connection();

		DBG("group path : %s\n", group->path);
		__connman_p2p_set_dhcp_pool(NULL);

		if (group->path && strncmp(group->path, CONNMAN_PATH, strlen(CONNMAN_PATH)) == 0) {
			group_removed_signal(group);
			g_dbus_unregister_interface(connection, group->path, CONNMAN_GROUP_INTERFACE);
		}
		g_hash_table_remove(group_hash, group->identifier);
		group_list = g_list_remove(group_list, group);

		g_hash_table_destroy(group->peer_hash);
		g_hash_table_destroy(group->peer_intf);

		g_free(group->path);
		g_free(group->passphrase);
		g_free(group->peer_ip);
		g_free(group->identifier);
		g_free(group->name);
		g_free(group);
		group = NULL;
	}
}

void __connman_group_peer_joined(struct connman_group *group, const char *_peer_ident, char *intf_addr, const char *peer_path)
{
	const char *not_p2p_peer = "/";
	const char *sig = "pbc";

	DBG("group: %s, peer: %s peer_path: %s \n", group->name, _peer_ident, peer_path);

	//Peer list will be the owner.
	char* peer_ident = g_strdup(_peer_ident);

	if (peer_path) {
		g_hash_table_replace(group->peer_hash, peer_ident, g_strdup(peer_path));
		if(intf_addr != NULL && g_str_equal(peer_ident, intf_addr) == FALSE)
			g_hash_table_replace(group->peer_intf, peer_ident, intf_addr);
	} else {
		g_hash_table_replace(group->peer_hash, peer_ident, g_strdup(not_p2p_peer));
	}

	group->peer_list = g_slist_prepend(group->peer_list, peer_ident);

	if (peer_path) {
		g_dbus_emit_signal(connection, group->path, CONNMAN_GROUP_INTERFACE, "PeerAdded",
						DBUS_TYPE_OBJECT_PATH, &peer_path,
						DBUS_TYPE_INVALID);
		connman_dbus_property_changed_basic(peer_path, CONNMAN_PEER_INTERFACE,
						"PeerAdded", DBUS_TYPE_STRING, &sig);
	}
}

bool __connman_group_peer_disconnected(struct connman_group *group, char *peer_ident)
{
	char *peer_path = NULL;
	GSList* item;

	DBG("group %s\n", group->name);

	if (group->peer_hash)
		peer_path = g_hash_table_lookup(group->peer_hash, peer_ident);

	item = g_slist_find_custom(group->peer_list, peer_ident, (GCompareFunc)g_strcmp0);

	if (!item)
	{
		DBG("Internal error - Peer not found in list %s\n", peer_ident);
		return false;
	}

	if (peer_path && peer_ident) {
		g_hash_table_remove(group->peer_hash, peer_ident);
	}
	g_hash_table_remove(group->peer_intf, peer_ident);
	g_free(item->data);
	group->peer_list = g_slist_delete_link(group->peer_list, item);

	if(peer_path) {
		g_dbus_emit_signal(connection, group->path,
						CONNMAN_GROUP_INTERFACE, "PeerRemoved",
						DBUS_TYPE_OBJECT_PATH, &peer_path,
						DBUS_TYPE_INVALID);

		g_free(peer_path);
	}

	if(group->autonomous == false && group->peer_list == NULL)
		if (-EINPROGRESS == g_supplicant_interface_p2p_group_disconnect(group->interface, NULL, NULL))
			return true;

	return true;
}

void __connman_group_init(void)
{
	connection = connman_dbus_get_connection();

	if (group_hash != NULL){
		__connman_group_cleanup();
	}

	group_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
}

void __connman_group_cleanup(void)
{
	GList *list;

	if (!group_list){
		if (group_hash != NULL){
			g_hash_table_destroy(group_hash);
			group_hash = NULL;
		}
		return;
	}

	for (list = group_list; list != NULL; list = list->next) {

		struct connman_group *group = list->data;

		/*
		 * Checking if group->path == null is added to prevent connman crash [NCVTDEFFECT-2085]).
		 * You can check original code review in http://wall.lge.com:8110/#/c/80192/.
		 * For network module migration from drd4tv to emo, this patch will be taken as it is.
		 * For further investigation, PLAT-16133 is created for to find a better solution
		 * other than checking null.
		 */

		if (group && group->path && strstr(group->path, "group") != NULL) {
			group_removed_signal(group);

			if (group->interface) {
				g_supplicant_interface_p2p_group_disconnect(group->interface, NULL, NULL);
				g_dbus_unregister_interface(connection, group->path, CONNMAN_GROUP_INTERFACE);
			}
		}
	}

	list = group_list;
	group_list = NULL;
	g_list_free (list);

	g_hash_table_destroy(group_hash);
	group_hash = NULL;
}
