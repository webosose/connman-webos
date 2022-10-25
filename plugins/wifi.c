/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2014  Intel Corporation. All rights reserved.
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

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/wireless.h>

#include <connman/types.h>

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP	0x10000
#endif

#include <dbus/dbus.h>
#include <glib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/inet.h>
#include <connman/device.h>
#include <connman/rtnl.h>
#include <connman/technology.h>
#include <connman/service.h>
#include <connman/peer.h>
#include <connman/log.h>
#include <include/option.h>
#include <connman/storage.h>
#include <include/setting.h>
#include <connman/provision.h>
#include <connman/utsname.h>
#include <connman/machine.h>
#include <connman/tethering.h>

#include <gsupplicant/gsupplicant.h>

#include "src/connman.h"

#include "include/group.h"
#include "src/shared/util.h"

#define CLEANUP_TIMEOUT   8	/* in seconds */
#define INACTIVE_TIMEOUT  12	/* in seconds */
#define FAVORITE_MAXIMUM_RETRIES 2
#define WPS_CONNECT_TIMEOUT 120 /* in seconds */

#define BGSCAN_DEFAULT "simple:30:-65:300"
#define AUTOSCAN_EXPONENTIAL "exponential:3:300"
#define AUTOSCAN_SINGLE "single:3"
#define SCAN_MAX_DURATION 10
#define P2P_PERSISTENT_INFO		"P2PPersistentInfo"

#define P2P_FIND_TIMEOUT 30
#define P2P_CONNECTION_TIMEOUT 100
#define P2P_LISTEN_PERIOD 500
#define P2P_LISTEN_INTERVAL 2000
#define P2P_PERSISTENT_MAX_COUNT 20

#define ASSOC_STATUS_AUTH_TIMEOUT 16
#define ASSOC_STATUS_NO_CLIENT 17
#define LOAD_SHAPING_MAX_RETRIES 3

static char *p2p_go_identifier = NULL;
static char *p2p_group_if_prefix = "p2p-";
static char *p2p_group_ifname = NULL;
static int p2p_group_ifindex = -1;
static int pin_requested_ref = -1;
static int pbc_requested_ref = -1;
static int p2p_find_ref = -1;
static int p2p_listen_ref = -1;

struct p2p_listen_data params = { .period = P2P_LISTEN_PERIOD, .interval = P2P_LISTEN_INTERVAL };

static DBusConnection *connection;
static struct connman_technology *wifi_technology = NULL;
static struct connman_technology *p2p_technology = NULL;

extern bool block_auto_connect;

enum wifi_ap_capability{
	WIFI_AP_UNKNOWN 	= 0,
	WIFI_AP_SUPPORTED 	= 1,
	WIFI_AP_NOT_SUPPORTED 	= 2,
};

enum wifi_scanning_type {
	WIFI_SCANNING_UNKNOWN	= 0,
	WIFI_SCANNING_PASSIVE	= 1,
	WIFI_SCANNING_ACTIVE	= 2,
};

struct hidden_params {
	char ssid[32];
	unsigned int ssid_len;
	char *identity;
	char *anonymous_identity;
	char *subject_match;
	char *altsubject_match;
	char *domain_suffix_match;
	char *domain_match;
	char *passphrase;
	char *security;
	GSupplicantScanParams *scan_params;
	gpointer user_data;
};

/**
 * Used for autoscan "emulation".
 * Should be removed when wpa_s autoscan support will be by default.
 */
struct autoscan_params {
	int base;
	int limit;
	int interval;
	unsigned int timeout;
};

struct wifi_tethering_info {
	struct wifi_data *wifi;
	struct connman_technology *technology;
	char *ifname;
	GSupplicantSSID *ssid;
};

struct wifi_data {
	char *identifier;
	struct connman_device *device;
	struct connman_network *network;
	struct connman_network *pending_network;
	GSList *networks;
	GSupplicantInterface *interface;
	GSupplicantState state;
	bool connected;
	bool disconnecting;
	bool tethering;
	enum wifi_ap_capability ap_supported;
	bool bridged;
	bool interface_ready;
	const char *bridge;
	int index;
	unsigned flags;
	unsigned int watch;
	int retries;
	int load_shaping_retries;
	struct hidden_params *hidden;
	bool postpone_hidden;
	struct wifi_tethering_info *tethering_param;
	/**
	 * autoscan "emulation".
	 */
	struct autoscan_params *autoscan;
	enum wifi_scanning_type scanning_type;
	GSupplicantScanParams *scan_params;
	GSupplicantP2PDeviceConfigParams p2p_device_config;
	unsigned int p2p_find_timeout;
	unsigned int p2p_connection_timeout;
	struct connman_peer *pending_peer;
	GSList *peers;
	bool p2p_connecting;
	bool p2p_device;
	bool p2p_listen_suppressed;
	int servicing;
	int disconnect_code;
	int assoc_code;

	bool wps_active;
	GSupplicantSSID *wps_ssid;
	guint wps_timeout;
	bool wps_start_deferred;

	const char *generated_pin;
	const char *pin_requested_path;
	const char *invited_path;
	GSList *persistent_groups;
	GHashTable *persistent_peer_ssid;
};

struct wifi_network {
	unsigned int keymgmt;
};
struct wifi_cb_data {
	struct wifi_data *wifi;
	void *callback;
	void *user_data;
};

struct disconnect_data {
	struct wifi_data *wifi;
	struct connman_network *network;
};

static GList *iface_list = NULL;

static GList *pending_wifi_device = NULL;
static GList *p2p_iface_list = NULL;
static bool wfd_service_registered = false;

static DBusMessage *group_msg;
static bool create_group_flag = false;

static int peer_disconnect(struct connman_peer *peer);
static void p2p_group_finished(GSupplicantInterface *interface);
static void remove_peers(struct wifi_data *wifi);
static void start_autoscan(struct connman_device *device);
static gboolean p2p_find_stop(gpointer data);
static GSupplicantSSID *ssid_ap_init(const char *ssid, const char *passphrase);
static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled);
static int apply_p2p_listen_on_iface(gpointer data, gpointer user_data);
static void leave_p2p_listen_on_iface(gpointer data);
static int add_persistent_group_info(struct wifi_data *wifi);
static int p2p_persistent_info_load(GSupplicantInterface *interface,
		const char *persistent_dir, GSupplicantP2PPersistentGroup *persistent_group);

static void bss_foreach(gpointer key, gpointer value, gpointer user_data)
{
	GSupplicantBss *bss;
	const unsigned char *bssid;
	dbus_int16_t signal;
	dbus_uint16_t frequency;
	struct connman_network *network;

	if (!key || !value || !user_data)
		return;

	network = (struct connman_network *)user_data;
	bss = (GSupplicantBss *)value;
	bssid = g_supplicant_bss_get_bssid(bss);
	signal = g_supplicant_bss_get_signal(bss);
	frequency = g_supplicant_bss_get_frequency(bss);
	DBG("signal %d frequency %d",signal,frequency);

	connman_network_add_bss(network, bssid, signal, frequency);
}

static int p2p_tech_probe(struct connman_technology *technology)
{
	p2p_technology = technology;

	return 0;
}

static void p2p_tech_remove(struct connman_technology *technology)
{
	p2p_technology = NULL;
}

static const char *load_p2p_identifier()
{
	GKeyFile *keyfile = NULL;
	gchar *identifier = NULL;
	const char *p2p_identifier = NULL;

	keyfile = __connman_storage_load_global();
	if(!keyfile)
		return NULL;

	identifier = g_strdup_printf("%s", "WiFi");
	if (!identifier) {
		g_key_file_free(keyfile);
		return NULL;
	}

	p2p_identifier = g_key_file_get_string(keyfile, identifier, "P2PIdentifier", NULL);
	g_free(identifier);

	if(!p2p_identifier) {
		g_key_file_free(keyfile);
		return NULL;
	}

	if(strlen(p2p_identifier) > 32)
		p2p_identifier = NULL;

	g_key_file_free(keyfile);

	return p2p_identifier;
}

static void save_p2p_identifier(const char *p2p_identifier)
{
	GKeyFile *keyfile = NULL;
	gchar *identifier = NULL;

	keyfile = __connman_storage_load_global();
	if(!keyfile)
		return;

	identifier = g_strdup_printf("%s", "WiFi");
	if (!identifier) {
		g_key_file_free(keyfile);
		return;
	}

	g_key_file_set_string(keyfile, identifier, "P2PIdentifier", p2p_identifier);
	g_free(identifier);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);
}
static int tech_set_p2p_enable(struct connman_technology *technology, bool status)
{
	GList *list = NULL;
	int err = 0;
	struct connman_peer *connmanpeer;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;
		err = g_supplicant_interface_set_p2p_disabled(iface, !status);

		if (err == 0 && status) {
			if (connman_technology_get_p2p_listen(technology)) {
				err = apply_p2p_listen_on_iface(wifi, &params);
			}
			if(err == 0)
				g_supplicant_interface_get_p2p_device_config(iface, &wifi->p2p_device_config);
		} else if(err == 0 && !status) {
			if (connman_technology_get_p2p_listen(technology)) {
				leave_p2p_listen_on_iface(wifi);
			}
			if(__connman_peer_get_connected_exists()) {
				connman_technology_set_p2p(p2p_technology, false);
				connmanpeer = __connman_get_connected_peer();
				peer_disconnect(connmanpeer);
				p2p_group_finished(iface);
				remove_peers(wifi);
			}
		}
	}

	return err;
}
static int tech_set_p2p_identifier(struct connman_technology *technology, const char *p2p_identifier)
{
	GList *list = NULL;
	char *old_device_name = NULL;
	char *old_ssid_postfix = NULL;
	int err = -EOPNOTSUPP;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	if (is_technology_enabled(p2p_technology)) {
		for (list = iface_list; list; list = list->next) {
			struct wifi_data *wifi = list->data;
			GSupplicantInterface *iface = wifi->interface;

			if (!g_supplicant_interface_has_p2p(iface))
				continue;

			if (wifi->p2p_device_config.device_name)
				old_device_name = wifi->p2p_device_config.device_name;

			if (wifi->p2p_device_config.ssid_postfix)
				old_ssid_postfix = wifi->p2p_device_config.ssid_postfix;

			wifi->p2p_device_config.device_name = g_strdup(p2p_identifier);
			wifi->p2p_device_config.ssid_postfix = g_strdup_printf("-%s", p2p_identifier);

			err = g_supplicant_interface_set_p2p_device_configs(iface, &wifi->p2p_device_config, NULL);

			if(err < 0) {
				g_free(wifi->p2p_device_config.device_name);
				g_free(wifi->p2p_device_config.ssid_postfix);

				wifi->p2p_device_config.device_name = old_device_name;
				wifi->p2p_device_config.ssid_postfix = old_ssid_postfix;
			} else {
				connman_technology_set_p2p_identifier(technology, wifi->p2p_device_config.device_name);
				save_p2p_identifier(wifi->p2p_device_config.device_name);

				g_free(old_device_name);
				g_free(old_ssid_postfix);
			}
		}
	} else {
		connman_technology_set_p2p_identifier(technology, p2p_identifier);
		save_p2p_identifier(p2p_identifier);
		err = 0;
	}
	return err;
}
static int tech_set_p2p_persistent(struct connman_technology *technology, bool persistent_reconnect)
{
	GList *list = NULL;
	int err = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		wifi->p2p_device_config.persistent_reconnect = persistent_reconnect;

		err = g_supplicant_interface_set_p2p_device_configs(iface, &wifi->p2p_device_config, NULL);
	}

	return err;
}
static int listen_reg_class_by_channel(int channel)
{
	int listen_reg_class = 0;

	if (channel >= 1 && channel <= 13)
		listen_reg_class = 81;
	else if(channel == 14)
		listen_reg_class = 82;
	else if(channel >= 36 && channel <= 48)
		listen_reg_class = 115;
	else if(channel >= 52 && channel <= 64)
		listen_reg_class = 118;
	else if(channel >= 149 && channel <= 161)
		listen_reg_class = 124;
	else if(channel >= 165 && channel <= 169)
		listen_reg_class = 125;

	return listen_reg_class;
}
static int tech_set_p2p_listen_channel(struct connman_technology *technology, unsigned int listen_channel)
{
	GList *list = NULL;
	int err = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		DBG("listen channel %d", listen_channel);

		wifi->p2p_device_config.listen_reg_class = listen_reg_class_by_channel(listen_channel);
		wifi->p2p_device_config.listen_channel = listen_channel;

		err = g_supplicant_interface_set_p2p_device_configs(iface, &wifi->p2p_device_config, NULL);
	}

	return err;
}

static int tech_set_p2p_go_intent(struct connman_technology *technology, unsigned int go_intent)
{
	GList *list = NULL;
	int err = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!iface || !g_supplicant_interface_has_p2p(iface))
			continue;

		DBG("go intent value : %d", go_intent);

		wifi->p2p_device_config.go_intent = go_intent;

		err = g_supplicant_interface_set_p2p_device_configs(iface, &wifi->p2p_device_config, NULL);
	}

	return err;
}

static int set_p2p_listen_without_state_change(struct connman_technology *technology, bool enable)
{
	GList *list = NULL;
	int ret = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!iface || !g_supplicant_interface_has_p2p(iface))
			continue;

		if (enable) {
			if (!connman_technology_get_enable_p2p_listen(technology))
				return -EOPNOTSUPP;

			ret = apply_p2p_listen_on_iface(wifi, &params);
		}
		else
			leave_p2p_listen_on_iface(wifi);
	}

	return ret;
}


static int tech_set_p2p_listen(struct connman_technology *technology, bool enable)
{
	GList *list = NULL;
	int ret = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!iface || !g_supplicant_interface_has_p2p(iface))
			continue;

		if (p2p_find_ref == -1) {
			if (enable) {
				ret = apply_p2p_listen_on_iface(wifi, &params);
				if (!ret)
					connman_technology_set_p2p_listen(technology, true);
			} else {
				leave_p2p_listen_on_iface(wifi);
				connman_technology_set_p2p_listen(technology, false);
			}
		} else {
			if (enable)
				connman_technology_set_p2p_listen(technology, true);
			else {
				p2p_find_stop(wifi->device);
				start_autoscan(wifi->device);
			}
		}
	}

	return ret;
}

static int tech_set_p2p_listen_params(struct connman_technology *technology,
					int period, int interval)
{
	GList *list = NULL;
	struct wifi_data *wifi = NULL;
	bool params_changed = false;
	int ret = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	DBG("period %d interval %d", period, interval);

	if ((params.period != period) || (params.interval != interval)) {
		params_changed = true;
		params.period = period;
		params.interval = interval;
	}

	if (!connman_technology_get_enable_p2p_listen(technology))
		return 0;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		if (!wifi->interface ||
			!g_supplicant_interface_has_p2p(wifi->interface))
			continue;

		// Decrement the count if listen is already set
		if (wifi->servicing && params_changed)
			wifi->servicing--;

		ret = apply_p2p_listen_on_iface(wifi, &params);
		if (ret != 0)
			continue;
		if (!connman_technology_get_p2p_listen(p2p_technology))
			connman_technology_set_p2p_listen(p2p_technology, true);
	}

	return 0;
}

static void remove_persistent_groups_elements(GSupplicantP2PPersistentGroup *pg)
{
	if(pg->path)
		g_free(pg->path);
	if(pg->group_path)
		g_free(pg->group_path);
	if(pg->bssid)
		g_free(pg->bssid);
	if(pg->bssid_no_colon)
		g_free(pg->bssid_no_colon);
	if(pg->ssid)
		g_free(pg->ssid);
	if(pg->psk)
		g_free(pg->psk);

	g_free(pg);
	pg = NULL;
}

static void free_persistent_groups(gpointer data)
{
	struct GSupplicantP2PPersistentGroup *pg = data;

	if (pg != NULL)
		remove_persistent_groups_elements(pg);
}

static void p2p_persistent_group_added(GSupplicantInterface *interface, GSupplicantP2PPersistentGroup *persistent_group)
{
	struct wifi_data *wifi;
	wifi = g_supplicant_interface_get_data(interface);

	DBG("ssid %s", persistent_group->ssid);

	if(wifi == NULL)
		goto DONE;

	/* newly added persistent_group */
	if(persistent_group->psk != NULL){
		wifi->persistent_groups = g_slist_prepend(wifi->persistent_groups, persistent_group);
		DBG("new group ssid : %s\n", persistent_group->ssid);
		return;
	/* added by service file */
	} else if (persistent_group->bssid != NULL &&  persistent_group->ssid != NULL) {
		GSList *item;
		GSupplicantP2PPersistentGroup *exist_pg;

		item = wifi->persistent_groups;
		while(item != NULL) {
			exist_pg = item->data;
			if(g_str_equal(exist_pg->bssid, persistent_group->bssid) && g_str_equal(exist_pg->ssid, persistent_group->ssid)) {
				DBG("updating existing group: %s\n", persistent_group->ssid);
				if (exist_pg->path)
					g_free(exist_pg->path);
				exist_pg->path = g_strdup(persistent_group->path);

				if (exist_pg->bssid_no_colon)
					g_free(exist_pg->bssid_no_colon);
				exist_pg->bssid_no_colon = g_strdup(persistent_group->bssid_no_colon);
				break;
			}

			item = g_slist_next(item);
		}
	} else {
		DBG("Skipping group, need bssid and ssid!");
	}

DONE:
	free_persistent_groups(persistent_group);
}

static void p2p_persistent_group_removed(GSupplicantInterface *interface, const char *persistent_group_path)
{
	struct wifi_data *wifi;
	GSList *item;
	GSupplicantP2PPersistentGroup *exist_pg, *removed_pg = NULL;

	wifi = g_supplicant_interface_get_data(interface);

	DBG("persistent_group_path %s", persistent_group_path);

	if(wifi == NULL || wifi->persistent_groups == NULL || persistent_group_path == NULL)
		return;

	item = wifi->persistent_groups;
	while(item != NULL) {
		exist_pg = item->data;

		if(exist_pg->path && g_str_equal(exist_pg->path, persistent_group_path)) {
			removed_pg = exist_pg;
			break;
		}
		item = g_slist_next(item);
	}

	if(removed_pg != NULL){
		wifi->persistent_groups = g_slist_remove(wifi->persistent_groups, removed_pg);
		remove_persistent_groups_elements(removed_pg);
	}
}

static int tech_set_p2p_go(DBusMessage *msg, struct connman_technology *technology,
		const char *identifier, const char *passphrase) {
	GList *list;
	struct wifi_tethering_info *info;
	char p2p_ssid[P2P_MAX_SSID] = {0x00,};
	int err = 0;

	if (!p2p_technology)
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!iface || !g_supplicant_interface_has_p2p(iface))
			continue;

		if (connman_technology_get_p2p_listen(technology) == TRUE) {
			leave_p2p_listen_on_iface(wifi);
			connman_technology_set_p2p_listen(technology, false);
		} else {
			if (wifi->device)
				p2p_find_stop(wifi->device);
		}

		info = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (info == NULL )
			return -ENOMEM;

		info->wifi = wifi;
		info->technology = technology;

		if (identifier || passphrase) {
			snprintf(p2p_ssid, P2P_MAX_SSID, "%s%s", P2P_WILDCARD_SSID, identifier);
			info->ssid = ssid_ap_init(p2p_ssid, passphrase);

			err = g_supplicant_interface_p2p_persistent_group_add(iface,
					info->ssid, NULL, info);

		} else {
			err = g_supplicant_interface_p2p_group_add(iface, NULL,
					NULL, info);
		}

		group_msg = dbus_message_ref(msg);
		create_group_flag = true;
	}

	return -err;
}

static int p2p_remove_persistent_info(GSupplicantInterface *interface, const char *peer_ident)
{
	struct wifi_data *wifi;
	GSupplicantP2PPersistentGroup *persistent_group, *removing_pg;
	char persistent_info_name[28] = "p2p_persistent_";
	GSList *item;

	DBG("peer_ident %s", peer_ident);

	wifi = g_supplicant_interface_get_data(interface);

	if(wifi == NULL)
		return -ENOMEM;

	p2p_find_stop(wifi->device);

	removing_pg = g_try_malloc0(sizeof(GSupplicantP2PPersistentGroup));
	if(removing_pg == NULL)
		return -ENOMEM;

	strncat(persistent_info_name, peer_ident, strlen(peer_ident));

	p2p_persistent_info_load(interface, persistent_info_name, removing_pg);

	if(removing_pg->ssid == NULL) {
		g_free(removing_pg);
		return -EOPNOTSUPP;
	}

	item = wifi->persistent_groups;
	while(item != NULL) {
		persistent_group = item->data;

		if(persistent_group->ssid == NULL || persistent_group->bssid == NULL)
			continue;

		if(g_str_equal(persistent_group->ssid, removing_pg->ssid)
				&& g_str_equal(persistent_group->bssid, removing_pg->bssid)) {
			removing_pg->path = persistent_group->path;
			break;
		}
		item = g_slist_next(item);
	}

	if(removing_pg->path != NULL) {
		struct connman_network *network;

		g_supplicant_interface_p2p_remove_persistent_group(interface, removing_pg->path);
		g_hash_table_remove(wifi->persistent_peer_ssid, peer_ident);
		g_free(removing_pg);
		__connman_storage_remove_service(persistent_info_name);

		return 0;
	}

	g_free(removing_pg);

	return -EOPNOTSUPP;
}


static int tech_remove_persistent_info(struct connman_technology *technology, const char *identifier)
{
	GList *list;
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	const char *addr_no_colon;
	int err = 0;

	if (!is_technology_enabled(p2p_technology))
		return -EOPNOTSUPP;

	addr_no_colon = __connman_util_remove_colon_from_mac_addr(identifier);
	if(addr_no_colon == NULL)
		return -EINVAL;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;
		interface = wifi->interface;

		if (!interface || !g_supplicant_interface_has_p2p(interface))
			continue;

		err = p2p_remove_persistent_info(interface, addr_no_colon);
	}

	g_free(addr_no_colon);

	return err;
}

static int tech_remove_persistent_info_all(struct connman_technology *technology)
{
	GList *list;
	struct wifi_data *wifi = NULL;
	GSupplicantInterface *interface;
	gchar **persistents;
	char *peer_ident;
	struct connman_network *network;
	int i;

	if (!is_technology_enabled(p2p_technology))
		return -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;
		interface = wifi->interface;

		if (interface == NULL || !g_supplicant_interface_has_p2p(interface))
			continue;

		g_supplicant_interface_p2p_remove_all_persistent_groups(interface);
	}

	persistents = __connman_storage_get_p2p_persistents();
	for (i = 0; persistents && persistents[i]; i++) {
		DBG("loop : %s\n", persistents[i]);

		if (strncmp(persistents[i], "p2p_persistent_", 15) != 0)
			continue;

		__connman_storage_remove_service(persistents[i]);

	}

	if (wifi)
		g_hash_table_remove_all(wifi->persistent_peer_ssid);

	if (persistents)
		g_strfreev(persistents);
	return 1;
}
static struct connman_technology_driver p2p_tech_driver = {
	.name		= "p2p",
	.type		= CONNMAN_SERVICE_TYPE_P2P,
	.probe		= p2p_tech_probe,
	.remove		= p2p_tech_remove,
	.set_p2p_enable = tech_set_p2p_enable,
	.set_p2p_identifier = tech_set_p2p_identifier,
	.set_p2p_persistent = tech_set_p2p_persistent,
	.set_p2p_listen_channel = tech_set_p2p_listen_channel,
	.set_p2p_go_intent = tech_set_p2p_go_intent,
	.set_p2p_listen = tech_set_p2p_listen,
	.set_p2p_listen_params = tech_set_p2p_listen_params,
	.set_p2p_go = tech_set_p2p_go,
	.remove_persistent_info = tech_remove_persistent_info,
	.remove_persistent_info_all = tech_remove_persistent_info_all,
};

static bool is_p2p_connecting(void)
{
	GList *list;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;

		if (wifi->p2p_connecting)
			return true;
	}

	return false;
}

static void enable_auto_connect_block(bool block)
{
	DBG("block %d", block);
	if (block)
		block_auto_connect = true;
	else {
		block_auto_connect = false;
		__connman_service_auto_connect(CONNMAN_SERVICE_CONNECT_REASON_AUTO);
	}
}

static void add_pending_wifi_device(struct wifi_data *wifi)
{
	if (g_list_find(pending_wifi_device, wifi))
		return;

	pending_wifi_device = g_list_append(pending_wifi_device, wifi);
}

static struct wifi_data *get_pending_wifi_data(const char *ifname)
{
	GList *list;

	for (list = pending_wifi_device; list; list = list->next) {
		struct wifi_data *wifi;
		const char *dev_name;

		wifi = list->data;
		if (!wifi || !wifi->device)
			continue;

		dev_name = connman_device_get_string(wifi->device, "Interface");
		if (!g_strcmp0(ifname, dev_name)) {
			pending_wifi_device = g_list_delete_link(
						pending_wifi_device, list);
			return wifi;
		}
	}

	return NULL;
}

static void remove_pending_wifi_device(struct wifi_data *wifi)
{
	GList *link;

	link = g_list_find(pending_wifi_device, wifi);

	if (!link)
		return;

	pending_wifi_device = g_list_delete_link(pending_wifi_device, link);
}

static void peer_cancel_timeout(struct wifi_data *wifi)
{
	if (wifi->p2p_connection_timeout > 0)
		g_source_remove(wifi->p2p_connection_timeout);

	wifi->p2p_connection_timeout = 0;
	wifi->p2p_connecting = false;

	if (wifi->pending_peer) {
		connman_peer_unref(wifi->pending_peer);
		wifi->pending_peer = NULL;
	}
}

static gboolean peer_connect_timeout(gpointer data)
{
	struct wifi_data *wifi = data;

	DBG("");

	if (wifi->p2p_connecting) {
		enum connman_peer_state state = CONNMAN_PEER_STATE_FAILURE;
		GSupplicantPeer *gs_peer =
			g_supplicant_interface_peer_lookup(wifi->interface,
				connman_peer_get_identifier(wifi->pending_peer));

		if (g_supplicant_peer_has_requested_connection(gs_peer))
			state = CONNMAN_PEER_STATE_IDLE;

		connman_peer_set_state(wifi->pending_peer, state);
	}

	peer_cancel_timeout(wifi);

	return FALSE;
}

static void peer_connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;
	struct connman_peer *peer = wifi->pending_peer;

	DBG("peer %p - %d", peer, result);

	if (!peer)
		return;

	if (result < 0) {
		peer_connect_timeout(wifi);
		return;
	}

	connman_peer_set_state(peer, CONNMAN_PEER_STATE_ASSOCIATION);

	wifi->p2p_connection_timeout = g_timeout_add_seconds(
						P2P_CONNECTION_TIMEOUT,
						peer_connect_timeout, wifi);
}

static int peer_connect(struct connman_peer *peer,
			enum connman_peer_wps_method wps_method,
			const char *wps_pin)
{
	struct connman_device *device = connman_peer_get_device(peer);
	GSupplicantPeerParams *peer_params;
	GSupplicantPeer *gs_peer;
	struct wifi_data *wifi;
	bool pbc, pin;
	int ret;

	DBG("peer %p", peer);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi || !wifi->interface)
		return -ENODEV;

	if (wifi->p2p_connecting)
		return -EBUSY;

	gs_peer = g_supplicant_interface_peer_lookup(wifi->interface,
					connman_peer_get_identifier(peer));
	if (!gs_peer)
		return -EINVAL;

	pbc = g_supplicant_peer_is_wps_pbc(gs_peer);
	pin = g_supplicant_peer_is_wps_pin(gs_peer);

	switch (wps_method) {
	case CONNMAN_PEER_WPS_UNKNOWN:
		if ((pbc && pin) || pin)
			return -ENOKEY;
		break;
	case CONNMAN_PEER_WPS_PBC:
		if (!pbc)
			return -EINVAL;
		wps_pin = NULL;
		break;
	case CONNMAN_PEER_WPS_PIN:
		if (!pin || !wps_pin)
			return -EINVAL;
		break;
	}

	if (connman_technology_get_p2p_listen(p2p_technology)) {
		leave_p2p_listen_on_iface(wifi);
		connman_technology_set_p2p_listen(p2p_technology, false);
	}

	if(p2p_go_identifier != NULL) {
			struct connman_network *network;
			const char *wp_pin = NULL;

			struct connman_group * group = __connman_group_lookup_from_ident(p2p_go_identifier);
			const char *identifier = connman_peer_get_identifier(peer);

			network = connman_device_get_network(wifi->device, identifier);

			if(group != NULL) {
				GSupplicantP2PWPSParams *wps_params = NULL;

				wps_params = g_try_malloc0(sizeof(GSupplicantP2PWPSParams));
				if(wps_params == NULL)
					return -ENOMEM;

				if (network != NULL)
					wp_pin = connman_network_get_string(network, "WiFi.PinWPS");

				wps_params->role = "enrollee";
				if(wp_pin == NULL) {
					wps_params->type = "pbc";
					wps_params->p2p_dev_addr = identifier;
				} else {
					wps_params->type = "pin";
					wps_params->pin = wp_pin;
				}

				ret = __connman_group_accept_connection(group, wps_params);

				if(ret == -EINPROGRESS) {
					wifi->pending_peer = connman_peer_ref(peer);
					wifi->p2p_connecting = true;
				}

				return ret;
			} else
				return -ENOMEM;
	}

	peer_params = g_try_malloc0(sizeof(GSupplicantPeerParams));
	if (!peer_params)
		return -ENOMEM;

	peer_params->path = g_strdup(g_supplicant_peer_get_path(gs_peer));
	if (wps_pin)
		peer_params->wps_pin = g_strdup(wps_pin);

	peer_params->master = connman_peer_service_is_master();
	peer_params->authorize_only= FALSE;
	peer_params->join = FALSE;

	peer_params->go_intent = wifi->p2p_device_config.go_intent;
	if(connman_technology_get_p2p_persistent(p2p_technology))
		peer_params->persistent = TRUE;
	else
		peer_params->persistent = FALSE;

	const char* connman_peer_path = __connman_peer_get_path(peer);

	if (wifi->pin_requested_path && g_str_equal(wifi->pin_requested_path, connman_peer_path)
		&& wifi->generated_pin) {
		wps_method = CONNMAN_PEER_WPS_DISPLAY;
		wifi->pin_requested_path = NULL;
	} else if (wifi->invited_path && g_str_equal(wifi->invited_path, connman_peer_path)) {
		wps_method = CONNMAN_PEER_WPS_DISPLAY;
		peer_params->join = TRUE;
		wifi->invited_path = NULL;
	}

	peer_params->wps_method= g_strdup(connman_peer_wps_method2string(wps_method));

	ret = g_supplicant_interface_p2p_connect(wifi->interface, peer_params,
						peer_connect_callback, wifi);
	if (ret == -EINPROGRESS) {
		wifi->pending_peer = connman_peer_ref(peer);
		wifi->p2p_connecting = true;
	} else if (ret < 0) {
		g_free(peer_params->path);
		g_free(peer_params->wps_pin);
		g_free(peer_params->wps_method);
		g_free(peer_params);
	}

	return ret;
}

static void p2p_peers_refresh(struct wifi_data *wifi)
{
	GSupplicantInterface *interface = wifi->interface;
	int err;

	err = g_supplicant_interface_p2p_flush(interface, NULL, NULL);

	if (!connman_technology_get_enable_p2p_listen(p2p_technology))
		return;

	//Do not p2p find from webOS 4.5 platform, since there is no WiFi Direct menu
	// in settings, so no need to list the peers
	// if(err == -EINPROGRESS)
		//p2p_find(wifi->device);
	if (__connman_get_connected_peer() == NULL && wifi->servicing){
		leave_p2p_listen_on_iface(wifi);
	}

	err = apply_p2p_listen_on_iface(wifi, &params);
	if (err == 0)
		connman_technology_set_p2p_listen(p2p_technology, true);
}

static int peer_disconnect(struct connman_peer *peer)
{
	struct connman_device *device = connman_peer_get_device(peer);
	GSupplicantPeer *gs_peer;
	struct wifi_data *wifi;
	char* peer_path = NULL;
	int ret;

	DBG("peer %p", peer);

	if (!device)
		return -ENODEV;

	if (p2p_go_identifier) {
		struct connman_group *connman_group;
		bool autonomous;
		connman_group = __connman_group_lookup_from_ident(p2p_go_identifier);
		if (connman_group) {
			autonomous = __connman_group_is_autonomous(connman_group);
			if (autonomous)
				return -ENOTSUP;
		}
	}

	wifi = connman_device_get_data(device);
	if (!wifi)
		return -ENODEV;

	gs_peer = g_supplicant_interface_peer_lookup(wifi->interface,
					connman_peer_get_identifier(peer));
	if (!gs_peer)
		return -EINVAL;

	peer_path = g_strdup(g_supplicant_peer_get_path(gs_peer));

	ret = g_supplicant_interface_p2p_client_remove(wifi->interface, NULL, peer_path);
	g_free(peer_path);

	if (ret == -EINPROGRESS) {
		peer_cancel_timeout(wifi);
		wifi->p2p_device = false;
		__connman_peer_set_static_ip(peer, NULL);
	}

	if (!__connman_get_connected_peer())
		p2p_peers_refresh(wifi);

	return ret;
}
static gboolean timeout_p2p_listen_state(gpointer user_data)
{
	GSupplicantInterface *interface = user_data;

	p2p_listen_ref = -1;

	if (connman_technology_get_p2p_listen(p2p_technology) == false &&
			!__connman_peer_get_connected_exists())
		tech_set_p2p_listen(p2p_technology, true);

	return FALSE;
}
static void reject_peer_callback(int result, GSupplicantInterface *interface,
								void *user_data)
{
	struct connman_peer *peer= user_data;

	DBG("result %d supplicant interface %p peer %p",
			result, interface, peer);

	if (result < 0)
		return;

	/*
	 * Current wpa_supplicant does not supports to emit the signal which is
	 * P2P negotiation failure when calling RejectPeer().
	 * To do this, we should call dummy Connect() after RejectPeer().
	 */
	peer_connect(peer, CONNMAN_PEER_WPS_PBC, "");

	if (p2p_listen_ref != -1)
		g_source_remove(p2p_listen_ref);

	p2p_listen_ref = g_timeout_add(3000, timeout_p2p_listen_state, interface);
}
static int peer_reject(struct connman_peer *peer)
{
	struct connman_device *device = connman_peer_get_device(peer);
	GSupplicantPeerParams peer_params = {};
	GSupplicantPeer *gs_peer;
	struct wifi_data *wifi;
	int ret;

	DBG("peer %p", peer);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi)
		return -ENODEV;

	gs_peer = g_supplicant_interface_peer_lookup(wifi->interface,
					connman_peer_get_identifier(peer));
	if (!gs_peer)
		return -EINVAL;

	peer_params.path = g_strdup(g_supplicant_peer_get_path(gs_peer));

	ret = g_supplicant_interface_p2p_disconnect(wifi->interface,
							&peer_params);
	g_free(peer_params.path);

	if (ret == -EINPROGRESS) {
		peer_cancel_timeout(wifi);
		wifi->p2p_device = false;
	}

	return ret;
}

struct peer_service_registration {
	peer_service_registration_cb_t callback;
	void *user_data;
};

static bool is_service_wfd(const unsigned char *specs, int length)
{
	if (length < 9 || specs[0] != 0 || specs[1] != 0 || specs[2] != 6)
		return false;

	return true;
}

static void apply_p2p_listen_callback(int result, GSupplicantInterface *interface, void *user_data)
{
	struct wifi_data *wifi = user_data;

	if (result < 0) {
		connman_info("p2p extended listen set failed(%d)", result);
		wifi->servicing--;
	}
}
static int apply_p2p_listen_on_iface(gpointer data, gpointer user_data)
{
	int err = 0;
	struct wifi_data *wifi = data;
	struct p2p_listen_data* listenParams = user_data;

	if (!listenParams)
		return -EINVAL;

	if (!wifi->interface ||
			!g_supplicant_interface_has_p2p(wifi->interface))
		return -ENODEV;

	if (connman_setting_get_bool("SupportP2P0Interface") &&
		g_strcmp0(connman_device_get_string(wifi->device, "Interface"),
				connman_option_get_string("P2PDevice")) != 0)
		return -EOPNOTSUPP;

	if (__connman_group_exist())
		return -EALREADY;

	if (!wifi->servicing) {
		err = g_supplicant_interface_p2p_listen(wifi->interface,
				listenParams->period, listenParams->interval, apply_p2p_listen_callback, wifi);

		wifi->servicing++;
	}
	return err;
}

static void leave_p2p_listen_on_iface(gpointer data)
{
	struct wifi_data *wifi = data;
	if (!wifi->interface ||
			!g_supplicant_interface_has_p2p(wifi->interface))
		return;

	if (connman_setting_get_bool("SupportP2P0Interface") &&
		g_strcmp0(connman_device_get_string(wifi->device, "Interface"),
				connman_option_get_string("P2PDevice")) != 0)
		return;

	wifi->servicing--;
	if (!wifi->servicing || wifi->servicing < 0) {
		g_supplicant_interface_p2p_listen(wifi->interface, 0, 0, NULL, wifi);
		wifi->servicing = 0;
	}
}

static void register_wfd_service_cb(int result,
				GSupplicantInterface *iface, void *user_data)
{
	struct peer_service_registration *reg_data = user_data;

	DBG("");

	if (result == 0)
		g_list_foreach(iface_list, apply_p2p_listen_on_iface, NULL);

	if (reg_data && reg_data->callback) {
		reg_data->callback(result, reg_data->user_data);
		g_free(reg_data);
	}
}

static GSupplicantP2PServiceParams *fill_in_peer_service_params(
				const unsigned char *spec,
				int spec_length, const unsigned char *query,
				int query_length, int version)
{
	GSupplicantP2PServiceParams *params;

	params = g_try_malloc0(sizeof(GSupplicantP2PServiceParams));
	if (!params)
		return NULL;

	if (version > 0) {
		params->version = version;
		if (spec_length > 0) {
			params->service = g_malloc(spec_length);
			memcpy(params->service, spec, spec_length);
		}
	} else if (query_length > 0 && spec_length > 0) {
		params->query = g_malloc(query_length);
		memcpy(params->query, query, query_length);
		params->query_length = query_length;

		params->response = g_malloc(spec_length);
		memcpy(params->response, spec, spec_length);
		params->response_length = spec_length;
	} else {
		if (spec_length > 0) {
			params->wfd_ies = g_malloc(spec_length);
			memcpy(params->wfd_ies, spec, spec_length);
		}
		params->wfd_ies_length = spec_length;
	}

	return params;
}

static void free_peer_service_params(GSupplicantP2PServiceParams *params)
{
	if (!params)
		return;

	g_free(params->service);
	g_free(params->query);
	g_free(params->response);
	g_free(params->wfd_ies);

	g_free(params);
}

static int peer_register_wfd_service(const unsigned char *specification,
				int specification_length,
				peer_service_registration_cb_t callback,
				void *user_data)
{
	struct peer_service_registration *reg_data = NULL;
	static GSupplicantP2PServiceParams *params;
	int ret;

	DBG("");

	if (wfd_service_registered)
		return -EBUSY;

	params = fill_in_peer_service_params(specification,
					specification_length, NULL, 0, 0);
	if (!params)
		return -ENOMEM;

	reg_data = g_try_malloc0(sizeof(*reg_data));
	if (!reg_data) {
		ret = -ENOMEM;
		goto error;
	}

	reg_data->callback = callback;
	reg_data->user_data = user_data;

	ret = g_supplicant_set_widi_ies(params,
					register_wfd_service_cb, reg_data);
	if (ret < 0 && ret != -EINPROGRESS)
		goto error;

	wfd_service_registered = true;

	return ret;
error:
	free_peer_service_params(params);
	g_free(reg_data);

	return ret;
}

static void register_peer_service_cb(int result,
				GSupplicantInterface *iface, void *user_data)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct peer_service_registration *reg_data = user_data;

	DBG("");

	if (result == 0)
		apply_p2p_listen_on_iface(wifi, NULL);

	if (reg_data && reg_data->callback)
		reg_data->callback(result, reg_data->user_data);

	g_free(reg_data);
}

static int peer_register_service(const unsigned char *specification,
				int specification_length,
				const unsigned char *query,
				int query_length, int version,
				peer_service_registration_cb_t callback,
				void *user_data)
{
	struct peer_service_registration *reg_data = NULL;
	GSupplicantP2PServiceParams *params;
	bool found = false;
	int ret, ret_f;
	GList *list;

	DBG("");

	if (specification && !version && !query &&
			is_service_wfd(specification, specification_length)) {
		return peer_register_wfd_service(specification,
				specification_length, callback, user_data);
	}

	reg_data = g_try_malloc0(sizeof(*reg_data));
	if (!reg_data)
		return -ENOMEM;

	reg_data->callback = callback;
	reg_data->user_data = user_data;

	ret_f = -EOPNOTSUPP;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		params = fill_in_peer_service_params(specification,
						specification_length, query,
						query_length, version);
		if (!params) {
			ret_f = -ENOMEM;
			continue;
		}

		if (!found) {
			ret_f = g_supplicant_interface_p2p_add_service(iface,
				register_peer_service_cb, params, reg_data);
			if (ret_f == 0 || ret_f == -EINPROGRESS)
				found = true;
			ret = ret_f;
		} else
			ret = g_supplicant_interface_p2p_add_service(iface,
				register_peer_service_cb, params, NULL);
		if (ret != 0 && ret != -EINPROGRESS)
			free_peer_service_params(params);
	}

	if(ret_f != -EINPROGRESS && reg_data)
		g_free(reg_data);

	return ret_f;
}

static int peer_unregister_wfd_service(void)
{
	GSupplicantP2PServiceParams *params;
	GList *list;

	if (!wfd_service_registered)
		return -EALREADY;

	params = fill_in_peer_service_params(NULL, 0, NULL, 0, 0);
	if (!params)
		return -ENOMEM;

	wfd_service_registered = false;

	g_supplicant_set_widi_ies(params, NULL, NULL);



	return 0;
}

static int peer_unregister_service(const unsigned char *specification,
						int specification_length,
						const unsigned char *query,
						int query_length, int version)
{
	GSupplicantP2PServiceParams *params;
	bool wfd = false;
	GList *list;
	int ret;

	if (specification && !version && !query &&
			is_service_wfd(specification, specification_length)) {
		ret = peer_unregister_wfd_service();
		if (ret != 0 && ret != -EINPROGRESS)
			return ret;
		wfd = true;
	}

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *wifi = list->data;
		GSupplicantInterface *iface = wifi->interface;

		if (wfd)
			continue;

		if (!g_supplicant_interface_has_p2p(iface))
			continue;

		params = fill_in_peer_service_params(specification,
						specification_length, query,
						query_length, version);
		if (!params)
			continue;

		ret = g_supplicant_interface_p2p_del_service(iface, params);
		if (ret != 0 && ret != -EINPROGRESS)
			free_peer_service_params(params);

	}

	return 0;
}

static struct connman_peer_driver peer_driver = {
	.connect    = peer_connect,
	.disconnect = peer_disconnect,
	.register_service = peer_register_service,
	.unregister_service = peer_unregister_service,
	.reject = peer_reject,
};

static void handle_tethering(struct wifi_data *wifi)
{
	if (!wifi->tethering)
		return;

	if (!wifi->bridge)
		return;

	if (wifi->bridged)
		return;

	DBG("index %d bridge %s", wifi->index, wifi->bridge);

	if (connman_inet_add_to_bridge(wifi->index, wifi->bridge) < 0)
		return;

	wifi->bridged = true;
}

static void wifi_newlink(unsigned flags, unsigned change, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	if (!wifi)
		return;

	DBG("index %d flags %d change %d", wifi->index, flags, change);

	if ((wifi->flags & IFF_UP) != (flags & IFF_UP)) {
		if (flags & IFF_UP)
			DBG("interface up");
		else
			DBG("interface down");
	}

	if ((wifi->flags & IFF_LOWER_UP) != (flags & IFF_LOWER_UP)) {
		if (flags & IFF_LOWER_UP)
			DBG("carrier on");
		else
			DBG("carrier off");
	}

	if (flags & IFF_LOWER_UP)
		handle_tethering(wifi);

	wifi->flags = flags;
}

static int wifi_probe(struct connman_device *device)
{
	struct wifi_data *wifi;

	DBG("device %p", device);

	wifi = g_try_new0(struct wifi_data, 1);
	if (!wifi)
		return -ENOMEM;

	wifi->state = G_SUPPLICANT_STATE_INACTIVE;
	wifi->ap_supported = WIFI_AP_UNKNOWN;
	wifi->tethering_param = NULL;

	connman_device_set_data(device, wifi);
	wifi->device = connman_device_ref(device);

	wifi->index = connman_device_get_index(device);
	wifi->flags = 0;

	wifi->watch = connman_rtnl_add_newlink_watch(wifi->index,
							wifi_newlink, device);

	wifi->p2p_listen_suppressed = false;
	wifi->wps_active = FALSE;

	if (is_p2p_connecting())
		add_pending_wifi_device(wifi);
	else
		iface_list = g_list_append(iface_list, wifi);

	return 0;
}

static void remove_networks(struct connman_device *device,
				struct wifi_data *wifi)
{
	GSList *list;

	for (list = wifi->networks; list; list = list->next) {
		struct connman_network *network = list->data;

		g_free(connman_network_get_data(network));
		connman_device_remove_network(device, network);
		connman_network_unref(network);
	}

	g_slist_free(wifi->networks);
	wifi->networks = NULL;
}

static void remove_peers(struct wifi_data *wifi)
{
	GSList *list;

	for (list = wifi->peers; list; list = list->next) {
		struct connman_peer *peer = list->data;

		connman_peer_unregister(peer);
		connman_peer_unref(peer);
	}

	g_slist_free(wifi->peers);
	wifi->peers = NULL;
}

static void reset_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (!wifi || !wifi->autoscan)
		return;

	autoscan = wifi->autoscan;

	autoscan->interval = 0;

	if (autoscan->timeout == 0)
		return;

	g_source_remove(autoscan->timeout);
	autoscan->timeout = 0;

	connman_device_unref(device);
}

static void stop_autoscan(struct connman_device *device)
{
	const struct wifi_data *wifi = connman_device_get_data(device);

	if (!wifi || !wifi->autoscan)
		return;

	reset_autoscan(device);

	connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_WIFI, false);
}

static void check_p2p_technology(void)
{
	bool p2p_exists = false;
	GList *list;

	for (list = iface_list; list; list = list->next) {
		struct wifi_data *w = list->data;

		if (w && w->interface &&
				g_supplicant_interface_has_p2p(w->interface)) {
			p2p_exists = true;

			if (w->p2p_listen_suppressed == true ||
					connman_technology_get_p2p_listen(p2p_technology)) {
				leave_p2p_listen_on_iface(w);
				p2p_peers_refresh(w);
				if (w->p2p_listen_suppressed == true)
					w->p2p_listen_suppressed = false;
			}
		}
	}

	if (!p2p_exists) {
		connman_technology_driver_unregister(&p2p_tech_driver);
		connman_peer_driver_unregister(&peer_driver);
	}
}

static void wifi_remove(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return;

	stop_autoscan(device);

	if (g_list_find(p2p_iface_list, wifi))
		p2p_iface_list = g_list_remove(p2p_iface_list, wifi);
	else
		iface_list = g_list_remove(iface_list, wifi);

	check_p2p_technology();

	remove_pending_wifi_device(wifi);

	if (wifi->p2p_find_timeout) {
		g_source_remove(wifi->p2p_find_timeout);
		connman_device_unref(wifi->device);
	}

	if (wifi->p2p_connection_timeout)
		g_source_remove(wifi->p2p_connection_timeout);

	remove_networks(device, wifi);
	remove_peers(wifi);

	connman_device_set_powered(device, false);
	connman_device_set_data(device, NULL);
	connman_device_unref(wifi->device);
	connman_rtnl_remove_watch(wifi->watch);
	__connman_sd_cleanup();

	g_supplicant_interface_set_data(wifi->interface, NULL);

	g_supplicant_interface_cancel(wifi->interface);

	if (wifi->scan_params)
		g_supplicant_free_scan_params(wifi->scan_params);

	if(wifi->p2p_device_config.device_name)
	{
		g_free(wifi->p2p_device_config.device_name);
		wifi->p2p_device_config.device_name = NULL;
	}

	if(wifi->p2p_device_config.ssid_postfix)
	{
		g_free(wifi->p2p_device_config.ssid_postfix);
		wifi->p2p_device_config.ssid_postfix = NULL;
	}

	if(wifi->persistent_groups){
		g_slist_free_full(wifi->persistent_groups, free_persistent_groups);
		wifi->persistent_groups = NULL;
	}

	g_free(wifi->autoscan);
	g_free(wifi->identifier);
	g_free(wifi);
}

static bool is_duplicate(GSList *list, gchar *ssid, int ssid_len)
{
	GSList *iter;

	for (iter = list; iter; iter = g_slist_next(iter)) {
		struct scan_ssid *scan_ssid = iter->data;

		if (ssid_len == scan_ssid->ssid_len &&
				memcmp(ssid, scan_ssid->ssid, ssid_len) == 0)
			return true;
	}

	return false;
}

static int add_scan_param(gchar *hex_ssid, char *raw_ssid, int ssid_len,
			int freq, GSupplicantScanParams *scan_data,
			int driver_max_scan_ssids, char *ssid_name)
{
	unsigned int i;
	struct scan_ssid *scan_ssid;

	if ((driver_max_scan_ssids == 0 ||
			driver_max_scan_ssids > scan_data->num_ssids) &&
			(hex_ssid || raw_ssid)) {
		gchar *ssid;
		unsigned int j = 0, hex;

		if (hex_ssid) {
			size_t hex_ssid_len = strlen(hex_ssid);

			ssid = g_try_malloc0(hex_ssid_len / 2);
			if (!ssid)
				return -ENOMEM;

			for (i = 0; i < hex_ssid_len; i += 2) {
				sscanf(hex_ssid + i, "%02x", &hex);
				ssid[j++] = hex;
			}
		} else {
			ssid = raw_ssid;
			j = ssid_len;
		}

		/*
		 * If we have already added hidden AP to the list,
		 * then do not do it again. This might happen if you have
		 * used or are using multiple wifi cards, so in that case
		 * you might have multiple service files for same AP.
		 */
		if (is_duplicate(scan_data->ssids, ssid, j)) {
			if (hex_ssid)
				g_free(ssid);
			return 0;
		}

		scan_ssid = g_try_new(struct scan_ssid, 1);
		if (!scan_ssid) {
			if (hex_ssid)
				g_free(ssid);
			return -ENOMEM;
		}

		memcpy(scan_ssid->ssid, ssid, j);
		scan_ssid->ssid_len = j;
		scan_data->ssids = g_slist_prepend(scan_data->ssids,
								scan_ssid);

		scan_data->num_ssids++;

		DBG("SSID %s added to scanned list of %d entries", ssid_name,
							scan_data->num_ssids);

		if (hex_ssid)
			g_free(ssid);
	} else
		return -EINVAL;

	scan_data->ssids = g_slist_reverse(scan_data->ssids);

	if (!scan_data->freqs) {
		scan_data->freqs = g_try_malloc0(sizeof(uint16_t));
		if (!scan_data->freqs) {
			g_slist_free_full(scan_data->ssids, g_free);
			return -ENOMEM;
		}

		scan_data->num_freqs = 1;
		scan_data->freqs[0] = freq;
	} else {
		bool duplicate = false;

		/* Don't add duplicate entries */
		for (i = 0; i < scan_data->num_freqs; i++) {
			if (scan_data->freqs[i] == freq) {
				duplicate = true;
				break;
			}
		}

		if (!duplicate) {
			scan_data->num_freqs++;
			scan_data->freqs = g_try_realloc(scan_data->freqs,
				sizeof(uint16_t) * scan_data->num_freqs);
			if (!scan_data->freqs) {
				g_slist_free_full(scan_data->ssids, g_free);
				return -ENOMEM;
			}
			scan_data->freqs[scan_data->num_freqs - 1] = freq;
		}
	}

	return 1;
}

static int get_hidden_connections(GSupplicantScanParams *scan_data)
{
	struct connman_config_entry **entries;
	GKeyFile *keyfile;
	gchar **services;
	char *ssid, *name;
	int i, ret;
	bool value;
	int num_ssids = 0, add_param_failed = 0;

	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		value = g_key_file_get_boolean(keyfile,
					services[i], "Hidden", NULL);
		if (!value) {
			g_key_file_free(keyfile);
			continue;
		}

		value = g_key_file_get_boolean(keyfile,
					services[i], "Favorite", NULL);
		if (!value) {
			g_key_file_free(keyfile);
			continue;
		}

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		name = g_key_file_get_string(keyfile, services[i], "Name",
								NULL);

		ret = add_scan_param(ssid, NULL, 0, 0, scan_data, 0, name);
		if (ret < 0)
			add_param_failed++;
		else if (ret > 0)
			num_ssids++;

		g_free(ssid);
		g_free(name);
		g_key_file_free(keyfile);
	}

	/*
	 * Check if there are any hidden AP that needs to be provisioned.
	 */
	entries = connman_config_get_entries("wifi");
	for (i = 0; entries && entries[i]; i++) {
		int len;

		if (!entries[i]->hidden)
			continue;

		if (!entries[i]->ssid) {
			ssid = entries[i]->name;
			len = strlen(ssid);
		} else {
			ssid = entries[i]->ssid;
			len = entries[i]->ssid_len;
		}

		if (!ssid)
			continue;

		ret = add_scan_param(NULL, ssid, len, 0, scan_data, 0, ssid);
		if (ret < 0)
			add_param_failed++;
		else if (ret > 0)
			num_ssids++;
	}

	connman_config_free_entries(entries);

	if (add_param_failed > 0)
		DBG("Unable to scan %d out of %d SSIDs",
					add_param_failed, num_ssids);

	g_strfreev(services);

	return num_ssids;
}

static int get_hidden_connections_params(struct wifi_data *wifi,
					GSupplicantScanParams *scan_params)
{
	int driver_max_ssids, i;
	GSupplicantScanParams *orig_params;

	/*
	 * Scan hidden networks so that we can autoconnect to them.
	 * We will assume 1 as a default number of ssid to scan.
	 */
	driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
	if (driver_max_ssids == 0)
		driver_max_ssids = 1;

	DBG("max ssids %d", driver_max_ssids);

	if (!wifi->scan_params) {
		wifi->scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
		if (!wifi->scan_params)
			return 0;

		if (get_hidden_connections(wifi->scan_params) == 0) {
			g_supplicant_free_scan_params(wifi->scan_params);
			wifi->scan_params = NULL;

			return 0;
		}
	}

	orig_params = wifi->scan_params;

	/* Let's transfer driver_max_ssids params */
	for (i = 0; i < driver_max_ssids; i++) {
		struct scan_ssid *ssid;

		if (!wifi->scan_params->ssids)
			break;

		ssid = orig_params->ssids->data;
		orig_params->ssids = g_slist_remove(orig_params->ssids, ssid);
		scan_params->ssids = g_slist_prepend(scan_params->ssids, ssid);
	}

	if (i > 0) {
		scan_params->num_ssids = i;
		scan_params->ssids = g_slist_reverse(scan_params->ssids);

		if (orig_params->num_freqs <= 0)
			goto err;

		scan_params->freqs =
			g_malloc(sizeof(uint16_t) * orig_params->num_freqs);
		memcpy(scan_params->freqs, orig_params->freqs,
			sizeof(uint16_t) *orig_params->num_freqs);

		scan_params->num_freqs = orig_params->num_freqs;

	} else
		goto err;

	orig_params->num_ssids -= scan_params->num_ssids;

	return scan_params->num_ssids;

err:
	g_slist_free_full(scan_params->ssids, g_free);
	g_supplicant_free_scan_params(wifi->scan_params);
	wifi->scan_params = NULL;

	return 0;
}

static void p2p_stop_find(struct wifi_data *wifi)
{
	if(p2p_find_ref != -1) {
		g_source_remove(p2p_find_ref);
		p2p_find_ref = -1;
		g_supplicant_interface_p2p_stop_find(wifi->interface);

		if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
					g_strcmp0(connman_device_get_string(wifi->device, "Interface"),
							connman_option_get_string("P2PDevice")) == 0) {
			connman_device_set_scanning(wifi->device, CONNMAN_SERVICE_TYPE_P2P, false);
		}
		return;
	}

	g_supplicant_interface_p2p_stop_find(wifi->interface);
}


static int throw_wifi_scan(struct connman_device *device,
			GSupplicantInterfaceCallback callback)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	if (!wifi)
		return -ENODEV;

	DBG("device %p %p", device, wifi->interface);

	if (wifi->tethering)
		return -EBUSY;

	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI))
		return -EALREADY;

	connman_device_ref(device);

	ret = g_supplicant_interface_scan(wifi->interface, NULL,
						callback, device);
	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, true);
	} else
		connman_device_unref(device);

	return ret;
}

static void hidden_free(struct hidden_params *hidden)
{
	if (!hidden)
		return;

	if (hidden->scan_params)
		g_supplicant_free_scan_params(hidden->scan_params);
	g_free(hidden->identity);
	g_free(hidden->passphrase);
	g_free(hidden->security);
	g_free(hidden);
}

static void scan_callback(int result, GSupplicantInterface *interface,
						void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	bool scanning;

	DBG("result %d wifi %p", result, wifi);

	if (wifi) {
		if (wifi->hidden && !wifi->postpone_hidden) {
			connman_network_clear_hidden(wifi->hidden->user_data);
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}

		if (wifi->scan_params) {
			g_supplicant_free_scan_params(wifi->scan_params);
			wifi->scan_params = NULL;
		}
	}

	if (result < 0)
		connman_device_reset_scanning(device);

	/* User is connecting to a hidden AP, let's wait for finished event */
	if (wifi && wifi->hidden && wifi->postpone_hidden) {
		GSupplicantScanParams *scan_params;
		int ret;

		wifi->postpone_hidden = false;
		scan_params = wifi->hidden->scan_params;
		wifi->hidden->scan_params = NULL;

		reset_autoscan(device);

		ret = g_supplicant_interface_scan(wifi->interface, scan_params,
							scan_callback, device);
		if (ret == 0)
			return;

		/* On error, let's recall scan_callback, which will cleanup */
		return scan_callback(ret, interface, user_data);
	}

	scanning = connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI);

	if (scanning) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
	}

	if (result != -ENOLINK)
		start_autoscan(device);

	/*
	 * If we are here then we were scanning; however, if we are
	 * also mid-flight disabling the interface, then wifi_disable
	 * has already cleared the device scanning state and
	 * unreferenced the device, obviating the need to do it here.
	 */

	if (scanning)
		connman_device_unref(device);
}

static void scan_callback_hidden(int result,
			GSupplicantInterface *interface, void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params;
	int ret;

	DBG("result %d wifi %p", result, wifi);

	if (!wifi)
		goto out;

	/* User is trying to connect to a hidden AP */
	if (wifi->hidden && wifi->postpone_hidden)
		goto out;

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (!scan_params)
		goto out;

	if (get_hidden_connections_params(wifi, scan_params) > 0) {
		ret = g_supplicant_interface_scan(wifi->interface,
							scan_params,
							scan_callback_hidden,
							device);
		if (ret == 0)
			return;
	}

	g_supplicant_free_scan_params(scan_params);

out:
	scan_callback(result, interface, user_data);
}

static gboolean autoscan_timeout(gpointer data)
{
	struct connman_device *device = data;
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;
	int interval;

	if (!wifi)
		return FALSE;

	autoscan = wifi->autoscan;

	if (autoscan->interval <= 0) {
		interval = autoscan->base;
		goto set_interval;
	} else
		interval = autoscan->interval * autoscan->base;

	if (interval > autoscan->limit)
		interval = autoscan->limit;

	throw_wifi_scan(wifi->device, scan_callback_hidden);

	/*
	 * In case BackgroundScanning is disabled, interval will reach the
	 * limit exactly after the very first passive scanning. It allows
	 * to ensure at most one passive scan is performed in such cases.
	 */
	if (!connman_setting_get_bool("BackgroundScanning") &&
					interval == autoscan->limit) {
		g_source_remove(autoscan->timeout);
		autoscan->timeout = 0;

		connman_device_unref(device);

		return FALSE;
	}

set_interval:
	DBG("interval %d", interval);

	autoscan->interval = interval;

	autoscan->timeout = g_timeout_add_seconds(interval,
						autoscan_timeout, device);

	return FALSE;
}

static void start_autoscan(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct autoscan_params *autoscan;

	DBG("");

	if (!wifi)
		return;

	if (wifi->p2p_device)
		return;

	if (wifi->connected)
		return;

	autoscan = wifi->autoscan;
	if (!autoscan)
		return;

	if (autoscan->timeout > 0 || autoscan->interval > 0)
		return;

	connman_device_ref(device);

	autoscan_timeout(device);
}

static struct autoscan_params *parse_autoscan_params(const char *params)
{
	struct autoscan_params *autoscan;
	char **list_params;
	int limit;
	int base;

	DBG("");

	list_params = g_strsplit(params, ":", 0);
	if (list_params == 0)
		return NULL;

	if (!g_strcmp0(list_params[0], "exponential") &&
				g_strv_length(list_params) == 3) {
		base = atoi(list_params[1]);
		limit = atoi(list_params[2]);
	} else if (!g_strcmp0(list_params[0], "single") &&
				g_strv_length(list_params) == 2)
		base = limit = atoi(list_params[1]);
	else {
		g_strfreev(list_params);
		return NULL;
	}

	DBG("Setup %s autoscanning", list_params[0]);

	g_strfreev(list_params);

	autoscan = g_try_malloc0(sizeof(struct autoscan_params));
	if (!autoscan) {
		DBG("Could not allocate memory for autoscan");
		return NULL;
	}

	DBG("base %d - limit %d", base, limit);
	autoscan->base = base;
	autoscan->limit = limit;

	return autoscan;
}

static void setup_autoscan(struct wifi_data *wifi)
{
	/*
	 * If BackgroundScanning is enabled, setup exponential
	 * autoscanning if it has not been previously done.
	 */
	if (connman_setting_get_bool("BackgroundScanning")) {
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_EXPONENTIAL);
		return;
	}

	/*
	 * On the contrary, if BackgroundScanning is disabled, update autoscan
	 * parameters based on the type of scanning that is being performed.
	 */
	if (wifi->autoscan) {
		g_free(wifi->autoscan);
		wifi->autoscan = NULL;
	}

	switch (wifi->scanning_type) {
	case WIFI_SCANNING_PASSIVE:
		/* Do not setup autoscan. */
		break;
	case WIFI_SCANNING_ACTIVE:
		/* Setup one single passive scan after active. */
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_SINGLE);
		break;
	case WIFI_SCANNING_UNKNOWN:
		/* Setup autoscan in this case but we should never fall here. */
		wifi->autoscan = parse_autoscan_params(AUTOSCAN_SINGLE);
		break;
	}
}

static void finalize_interface_creation(struct wifi_data *wifi)
{
	DBG("interface is ready wifi %p tethering %d", wifi, wifi->tethering);

	if (!wifi->device) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, true);

	if (wifi->p2p_device)
		return;

	if (is_technology_enabled(wifi_technology)) {
		DBG("WiFi is enable, so enable p2p also");
		if (p2p_technology)
			connman_technology_set_p2p(p2p_technology, true);
	}
//	if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
//		g_strcmp0(g_supplicant_interface_get_ifname(wifi->interface),
//			connman_option_get_string("P2PDevice")) == 0) {
                int ret;

                DBG("interface type is p2p interface");
                ret = g_supplicant_interface_get_p2p_device_config(wifi->interface, &wifi->p2p_device_config);
                if (ret == 0) {
                        DBG("interface type is p2p device config");

                        wifi->persistent_peer_ssid = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
                        add_persistent_group_info(wifi);
                }

                __connman_group_init();

		__connman_sd_init(wifi->interface, connman_device_get_ident(wifi->device));
//	}

	if (!wifi->autoscan)
		setup_autoscan(wifi);

	start_autoscan(wifi->device);
}

static void interface_create_callback(int result,
					GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_data *wifi = user_data;
	char *bgscan_range_max;
	long value;

	DBG("result %d ifname %s, wifi %p", result,
				g_supplicant_interface_get_ifname(interface),
				wifi);

	if (result < 0 || !wifi)
		return;

	wifi->interface = interface;
	g_supplicant_interface_set_data(interface, wifi);

	if (g_supplicant_interface_get_ready(interface)) {
		wifi->interface_ready = true;
		finalize_interface_creation(wifi);
	}

	/*
	 * Set the BSS expiration age to match the long scanning
	 * interval to avoid the loss of unconnected networks between
	 * two scans.
	 */
	bgscan_range_max = strrchr(BGSCAN_DEFAULT, ':');
	if (!bgscan_range_max || strlen(bgscan_range_max) < 1)
		return;

	value = strtol(bgscan_range_max + 1, NULL, 10);
	if (value <= 0 || errno == ERANGE)
		return;

	if (g_supplicant_interface_set_bss_expiration_age(interface,
					value + SCAN_MAX_DURATION) < 0) {
		connman_warn("Failed to set bss expiration age");
	}
}

static int wifi_enable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int index;
	char *interface;
	const char *driver = connman_setting_get_string("wifi");
	int ret;

	DBG("device %p %p", device, wifi);

	index = connman_device_get_index(device);
	if (!wifi || index < 0)
		return -ENODEV;

	if (is_p2p_connecting())
		return -EINPROGRESS;

	interface = connman_inet_ifname(index);
	const char *wpas_config_file = connman_setting_get_string("WpaSupplicantConfigFile");
	ret = g_supplicant_interface_create(interface, driver, NULL, wpas_config_file,
						interface_create_callback,
							wifi);
	g_free(interface);

	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

static int wifi_disable(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return -ENODEV;

	wifi->connected = false;
	wifi->disconnecting = false;

	if (wifi->pending_network)
		wifi->pending_network = NULL;

	stop_autoscan(device);

	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_P2P)) {
		g_source_remove(wifi->p2p_find_timeout);
		wifi->p2p_find_timeout = 0;
		connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_P2P, false);
		connman_device_unref(wifi->device);
	}

	/* In case of a user scan, device is still referenced */
	if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI)) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, false);
		connman_device_unref(wifi->device);
	}

	remove_networks(device, wifi);
	remove_peers(wifi);

	ret = g_supplicant_interface_remove(wifi->interface, NULL, NULL);
	if (ret < 0)
		return ret;

	return -EINPROGRESS;
}

struct last_connected {
	struct timeval modified;
	gchar *ssid;
	int freq;
};

static gint sort_entry(gconstpointer a, gconstpointer b, gpointer user_data)
{
	struct timeval *aval = (struct timeval *)a;
	struct timeval *bval = (struct timeval *)b;

	/* Note that the sort order is descending */
	if (aval->tv_sec < bval->tv_sec)
		return 1;

	if (aval->tv_sec > bval->tv_sec)
		return -1;

	return 0;
}

static void free_entry(gpointer data)
{
	struct last_connected *entry = data;

	g_free(entry->ssid);
	g_free(entry);
}

static int get_latest_connections(int max_ssids,
				GSupplicantScanParams *scan_data)
{
	GSequenceIter *iter;
	GSequence *latest_list;
	struct last_connected *entry;
	GKeyFile *keyfile;
	struct timeval modified;
	gchar **services;
	gchar *str;
	char *ssid;
	int i, freq;
	int num_ssids = 0;

	latest_list = g_sequence_new(free_entry);
	if (!latest_list)
		return -ENOMEM;

	services = connman_storage_get_services();
	for (i = 0; services && services[i]; i++) {
		if (strncmp(services[i], "wifi_", 5) != 0)
			continue;

		keyfile = connman_storage_load_service(services[i]);
		if (!keyfile)
			continue;

		str = g_key_file_get_string(keyfile,
					services[i], "Favorite", NULL);
		if (!str || g_strcmp0(str, "true")) {
			g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "AutoConnect", NULL);
		if (!str || g_strcmp0(str, "true")) {
			g_free(str);
			g_key_file_free(keyfile);
			continue;
		}
		g_free(str);

		str = g_key_file_get_string(keyfile,
					services[i], "Modified", NULL);
		if (!str) {
			g_key_file_free(keyfile);
			continue;
		}
		util_iso8601_to_timeval(str, &modified);
		g_free(str);

		ssid = g_key_file_get_string(keyfile,
					services[i], "SSID", NULL);

		freq = g_key_file_get_integer(keyfile, services[i],
					"Frequency", NULL);
		if (freq) {
			entry = g_try_new(struct last_connected, 1);
			if (!entry) {
				g_sequence_free(latest_list);
				g_key_file_free(keyfile);
				g_free(ssid);
				return -ENOMEM;
			}

			entry->ssid = ssid;
			entry->modified = modified;
			entry->freq = freq;

			g_sequence_insert_sorted(latest_list, entry,
						sort_entry, NULL);
			num_ssids++;
		} else
			g_free(ssid);

		g_key_file_free(keyfile);
	}

	g_strfreev(services);

	num_ssids = num_ssids > max_ssids ? max_ssids : num_ssids;

	iter = g_sequence_get_begin_iter(latest_list);

	for (i = 0; i < num_ssids; i++) {
		entry = g_sequence_get(iter);

		DBG("ssid %s freq %d modified %lu", entry->ssid, entry->freq,
						entry->modified.tv_sec);

		add_scan_param(entry->ssid, NULL, 0, entry->freq, scan_data,
						max_ssids, entry->ssid);

		iter = g_sequence_iter_next(iter);
	}

	g_sequence_free(latest_list);
	return num_ssids;
}

static void wifi_update_scanner_type(struct wifi_data *wifi,
					enum wifi_scanning_type new_type)
{
	DBG("");

	if (!wifi || wifi->scanning_type == new_type)
		return;

	wifi->scanning_type = new_type;

	setup_autoscan(wifi);
}

static int wifi_scan_simple(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	reset_autoscan(device);

	/* Distinguish between devices performing passive and active scanning */
	if (wifi)
		wifi_update_scanner_type(wifi, WIFI_SCANNING_PASSIVE);

	return throw_wifi_scan(device, scan_callback_hidden);
}

static gboolean p2p_find_stop(gpointer data)
{
	struct connman_device *device = data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("");

	if (wifi) {
		wifi->p2p_find_timeout = 0;

		g_supplicant_interface_p2p_stop_find(wifi->interface);
		if (p2p_technology &&
				(wifi->p2p_listen_suppressed == true ||
				connman_technology_get_p2p_listen(p2p_technology))) {
			set_p2p_listen_without_state_change(p2p_technology, true);
			if (wifi->p2p_listen_suppressed)
				wifi->p2p_listen_suppressed = false;
		}
	}

	connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_P2P, false);

	connman_device_unref(device);
	start_autoscan(device);

	return FALSE;
}

static void p2p_find_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_device *device = user_data;
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("result %d wifi %p", result, wifi);

	if (!wifi)
		goto error;

	if (wifi->p2p_find_timeout) {
		g_source_remove(wifi->p2p_find_timeout);
		wifi->p2p_find_timeout = 0;
	}

	if (result)
		goto error;

	wifi->p2p_find_timeout = g_timeout_add_seconds(P2P_FIND_TIMEOUT,
							p2p_find_stop, device);
	if (!wifi->p2p_find_timeout)
		goto error;

	p2p_find_ref = -1;

	return;
error:
	p2p_find_ref = -1;
	p2p_find_stop(device);
}

static gboolean p2p_find_complete(gpointer argv)
{
	struct connman_device *device = argv;
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret = 0;

	if(!wifi) {
		p2p_find_ref = -1;
		return FALSE;
	}

	if (p2p_technology &&
			(wifi->p2p_listen_suppressed == true ||
			connman_technology_get_p2p_listen(p2p_technology))) {
		set_p2p_listen_without_state_change(p2p_technology, true);
		if (wifi->p2p_listen_suppressed)
			wifi->p2p_listen_suppressed = false;
	}

	p2p_find_ref = -1;

	return FALSE;
}

static int p2p_find(struct connman_device *device)
{
	struct wifi_data *wifi;
	int ret;

	DBG("");

	if (!p2p_technology)
		return -ENOTSUP;

	wifi = connman_device_get_data(device);

	if (!wifi || !wifi->interface)
		return -ENODEV;

	if (g_supplicant_interface_is_p2p_finding(wifi->interface))
		return -EALREADY;

	if (p2p_technology &&
		connman_technology_get_p2p_listen(p2p_technology)) {
		set_p2p_listen_without_state_change(p2p_technology, false);
		wifi->p2p_listen_suppressed = true;
	}

	reset_autoscan(device);
	connman_device_ref(device);

	ret = g_supplicant_interface_p2p_find(wifi->interface, NULL,
						p2p_find_callback, device);
	if (ret) {
		connman_device_unref(device);
		start_autoscan(device);
	} else {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_P2P, true);
		p2p_find_ref = g_timeout_add_seconds(wifi->p2p_find_timeout, p2p_find_complete, device);
	}

	return ret;
}

/*
 * Note that the hidden scan is only used when connecting to this specific
 * hidden AP first time. It is not used when system autoconnects to hidden AP.
 */
static int wifi_scan(struct connman_device *device,
			struct connman_device_scan_params *params)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantScanParams *scan_params = NULL;
	struct scan_ssid *scan_ssid;
	struct hidden_params *hidden;
	int ret;
	int driver_max_ssids = 0;
	bool do_hidden;
	bool scanning;

	if (!wifi)
		return -ENODEV;

	if (wifi->p2p_device)
		return -EBUSY;

	if (wifi->tethering)
		return -EBUSY;

	if (params->type == CONNMAN_SERVICE_TYPE_P2P) {
			if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
					g_strcmp0(connman_device_get_string(device, "Interface"),
								connman_option_get_string("P2PDevice")) != 0)
					return -ENOTSUP;

			if(p2p_find_ref != -1)
				return -EINPROGRESS;
			return p2p_find(device);
	}
 
	DBG("device %p wifi %p hidden ssid %s", device, wifi->interface,
		params->ssid);

	if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
				g_strcmp0(connman_device_get_string(device, "Interface"),
						connman_option_get_string("WiFiDevice")) != 0)
		return -ENOTSUP;

	scanning = connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_WIFI);
	if (!scanning && (!params->ssid || params->ssid_len == 0 || params->ssid_len > 32))
		p2p_stop_find(wifi);

	if (p2p_technology &&
		connman_technology_get_p2p_listen(p2p_technology)) {
		set_p2p_listen_without_state_change(p2p_technology, false);
		wifi->p2p_listen_suppressed = true;
	}


	if (!params->ssid || params->ssid_len == 0 || params->ssid_len > 32) {
		if (scanning)
			return -EALREADY;

		driver_max_ssids = g_supplicant_interface_get_max_scan_ssids(
							wifi->interface);
		DBG("max ssids %d", driver_max_ssids);
		if (driver_max_ssids == 0)
			return wifi_scan_simple(device);

		do_hidden = false;
	} else {
		if (scanning && wifi->hidden && wifi->postpone_hidden)
			return -EALREADY;

		do_hidden = true;
	}

	scan_params = g_try_malloc0(sizeof(GSupplicantScanParams));
	if (!scan_params)
		return -ENOMEM;

	if (do_hidden) {
		scan_ssid = g_try_new(struct scan_ssid, 1);
		if (!scan_ssid) {
			g_free(scan_params);
			return -ENOMEM;
		}

		memcpy(scan_ssid->ssid, params->ssid, params->ssid_len);
		scan_ssid->ssid_len = params->ssid_len;
		scan_params->ssids = g_slist_prepend(scan_params->ssids,
								scan_ssid);
		scan_params->num_ssids = 1;

		hidden = g_try_new0(struct hidden_params, 1);
		if (!hidden) {
			g_supplicant_free_scan_params(scan_params);
			return -ENOMEM;
		}

		if (wifi->hidden) {
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}

		memcpy(hidden->ssid, params->ssid, params->ssid_len);
		hidden->ssid_len = params->ssid_len;
		hidden->identity = g_strdup(params->identity);
		hidden->passphrase = g_strdup(params->passphrase);
		hidden->security = g_strdup(params->security);
		hidden->user_data = params->user_data;
		wifi->hidden = hidden;

		if (scanning) {
			/* Let's keep this active scan for later,
			 * when current scan will be over. */
			wifi->postpone_hidden = TRUE;
			hidden->scan_params = scan_params;

			return 0;
		}
	} else if (wifi->connected) {
		g_supplicant_free_scan_params(scan_params);
		return wifi_scan_simple(device);
	} else if (!params->force_full_scan) {
		ret = get_latest_connections(driver_max_ssids, scan_params);
		if (ret <= 0) {
			g_supplicant_free_scan_params(scan_params);
			return wifi_scan_simple(device);
		}
	}

	/* Distinguish between devices performing passive and active scanning */
	wifi_update_scanner_type(wifi, WIFI_SCANNING_ACTIVE);

	connman_device_ref(device);

	reset_autoscan(device);

	ret = g_supplicant_interface_scan(wifi->interface, scan_params,
						scan_callback, device);
	if (ret == 0) {
		connman_device_set_scanning(device,
				CONNMAN_SERVICE_TYPE_WIFI, true);
	} else {
		g_supplicant_free_scan_params(scan_params);
		connman_device_unref(device);

		if (do_hidden) {
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}
	}

	return ret;
}

static void wifi_stop_scan(enum connman_service_type type,
			struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("device %p wifi %p", device, wifi);

	if (!wifi)
		return;

	if (type == CONNMAN_SERVICE_TYPE_P2P) {
		if (connman_device_get_scanning(device, CONNMAN_SERVICE_TYPE_P2P)) {
			g_source_remove(wifi->p2p_find_timeout);
			p2p_find_stop(device);
		}
	}
}

static void wifi_regdom_callback(int result,
					const char *alpha2,
						void *user_data)
{
	struct connman_device *device = user_data;

	connman_device_regdom_notify(device, result, alpha2);

	connman_device_unref(device);
}

static int wifi_set_regdom(struct connman_device *device, const char *alpha2)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret;

	if (!wifi)
		return -EINVAL;

	connman_device_ref(device);

	ret = g_supplicant_interface_set_country(wifi->interface,
						wifi_regdom_callback,
							alpha2, device);
	if (ret != 0)
		connman_device_unref(device);

	return ret;
}

static gboolean start_wps_timeout(gpointer user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("");

	wifi->wps_timeout = 0;
	wifi->wps_active = FALSE;

	/* if we already assigned a network we have to remove it too */
	wifi->network = NULL;

	connman_technology_wps_failed_notify(wifi_technology);

	return FALSE;
}
static bool is_wifi_valid (struct wifi_data *wifi)
{
	GList *list;

	DBG("");

	if (wifi == NULL)
		return FALSE;

	for (list = iface_list; list; list = list->next) {
		if (list->data == wifi)
			return TRUE;
	}

	DBG("wifi %p not found", wifi);

	return FALSE;
}
static void cancel_wps_callback(int result, GSupplicantInterface *interface,
                            void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d", result);

	if (!is_wifi_valid(wifi))
		return;

	/* if we already assigned a network we have to remove it too */
	if (wifi->network) {
		connman_network_set_bool(wifi->network, "WiFi.UseWPS", FALSE);
		connman_network_set_connected(wifi->network, FALSE);
		wifi->network = NULL;
	}

	if (wifi->wps_timeout > 0) {
		g_source_remove(wifi->wps_timeout);
		wifi->wps_timeout = 0;
	}

	wifi->wps_active = FALSE;
	/* already freed within gsupplicant layer */
	wifi->wps_ssid = NULL;

	enable_auto_connect_block(FALSE);
}
static int cancel_wps(struct wifi_data *wifi)
{
	int ret;

	DBG("wifi %p", wifi);

	ret = g_supplicant_interface_wps_cancel(wifi->interface, cancel_wps_callback, wifi);
	if (ret == -EALREADY || ret == -EINPROGRESS)
		ret = 0;

	return ret;
}
static gboolean wps_timeout_cb(gpointer user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("");

	if (!is_wifi_valid(wifi))
		return FALSE;

	cancel_wps(wifi);

	connman_technology_wps_failed_notify(wifi_technology);

	return FALSE;
}
static void wps_start_callback(int result, GSupplicantInterface *interface,
                            void *user_data)
{
	struct wifi_data *wifi = user_data;

	DBG("result %d", result);

	if (result == 0)
		return;

	if (!is_wifi_valid(wifi))
		return;

	/* if we're at this place something went wrong an we have to clean up */
	if (wifi->wps_timeout > 0) {
		g_source_remove(wifi->wps_timeout);
		wifi->wps_timeout = 0;
	}

	wifi->wps_active = FALSE;

	connman_technology_wps_failed_notify(wifi_technology);
}
static int start_wps(struct wifi_data *wifi)
{
	int ret;

	connman_info("start wps connection");

	wifi->wps_timeout = g_timeout_add_seconds(WPS_CONNECT_TIMEOUT,
							wps_timeout_cb, wifi);

	ret = g_supplicant_interface_connect(wifi->interface, wifi->wps_ssid,
						wps_start_callback, wifi);
	if (ret == -EALREADY || ret == -EINPROGRESS)
		ret = 0;

	return ret;
}
static gboolean deferred_wps_start(struct wifi_data *wifi)
{
	DBG("WPS active %d", wifi->wps_active);

	if(wifi->wps_active == FALSE)
		return FALSE;

	if(wifi->wps_start_deferred) {
		wifi->network = NULL;
		start_wps(wifi);
		wifi->wps_start_deferred = FALSE;
		return TRUE;
	}

	return FALSE;
}
static int wifi_start_wps(struct connman_device *device, const char *pin)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	GSupplicantSSID *ssid;
	int ret=0;

	if (wifi->wps_active == TRUE)
		return -EINPROGRESS;

	DBG("");

	ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (ssid == NULL)
		return -ENOMEM;

	ssid->use_wps = TRUE;
	if(strlen(pin) == 0)
		ssid->pin_wps = NULL;
	else
		ssid->pin_wps = g_strdup(pin);

	wifi->wps_active = TRUE;
	wifi->wps_ssid = ssid;

	enable_auto_connect_block(TRUE);

	/* if we're still disconnecting wait until we're completely disconnected */
	if (wifi->disconnecting) {
		DBG("Defering WPS until disconnect is done");
		wifi->wps_start_deferred = TRUE;
		return 0;
	}

	/* This is ahead of what will happen if we have an associating network
	 * at this point. Once we issue the StartWPS command to wpa-supplicant
	 * the network will be disconnected and we will receive the interface
	 * state change signal. As we're in the middle of the WPS process we
	 * don't handle that there ... */
	if (wifi->network) {
		connman_network_set_connected(wifi->network, FALSE);
		connman_network_set_associating(wifi->network, FALSE);
		wifi->network = NULL;
	}

	return start_wps(wifi);
}
static int wifi_cancel_wps(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);

	DBG("");

	if (wifi->wps_active == FALSE)
		return 0;

	return cancel_wps(wifi);
}
static void cancel_p2p_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_device *device = user_data;

	DBG("result %d", result);

	if (!device)
		return;

	//Do not p2p find on webOS 4.5 platform
	//p2p_find(device);
}
static int wifi_cancel_p2p(struct connman_device *device)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	int ret = 0;

	if (!wifi || !wifi->device)
		return -EINVAL;

	DBG("");

	if (p2p_go_identifier != NULL) {
		/* disconnect the group only if there are no existing connected peers */
			struct connman_group *group = __connman_group_lookup_from_ident(p2p_go_identifier);

			if (group != NULL) {

				if (__connman_group_get_list_length(group) == 0)
					__connman_group_peer_failed(group);

				return 0;
			}
	}

	ret = g_supplicant_interface_p2p_cancel(wifi->interface, cancel_p2p_callback, wifi->device);
	if (ret == -EALREADY || ret == -EINPROGRESS) {
		ret = 0;

		connman_peer_state_change_by_cancelled();
	}

	return ret;
}
static void signal_info_cb(int result, GSupplicantInterface *interface, void *user_data)
{
	struct wifi_cb_data *data = user_data;
	connman_device_request_signal_info_cb cb = data->callback;
	unsigned int value;

	if (result < 0)
		goto done;

	value = g_supplicant_interface_get_rssi(interface);
	connman_device_set_integer(data->wifi->device, "WiFi.RSSI", value);

	value = g_supplicant_interface_get_link_speed(interface);
	connman_device_set_integer(data->wifi->device, "WiFi.LinkSpeed", value);

	value = g_supplicant_interface_get_frequency(interface);
	connman_device_set_integer(data->wifi->device, "WiFi.Frequency", value);

	value = g_supplicant_interface_get_noise(interface);
	connman_device_set_integer(data->wifi->device, "WiFi.Noise", value);

done:
	cb(data->wifi->device, data->user_data);

	g_free(data);
}
static int wifi_get_signal_info(struct connman_device *device, connman_device_request_signal_info_cb cb, void *user_data)
{
	struct wifi_data *wifi = connman_device_get_data(device);
	struct wifi_cb_data *data;

	if (!wifi)
		return -EINVAL;

	data = g_new0(struct wifi_cb_data, 1);
	if (!data)
		return -ENOMEM;

	data->callback = cb;
	data->user_data = user_data;
	data->wifi = wifi;

	return g_supplicant_interface_update_signal_info(wifi->interface, signal_info_cb, data);
}
static struct connman_device_driver wifi_ng_driver = {
	.name		= "wifi",
	.type		= CONNMAN_DEVICE_TYPE_WIFI,
	.priority	= CONNMAN_DEVICE_PRIORITY_LOW,
	.probe		= wifi_probe,
	.remove		= wifi_remove,
	.enable		= wifi_enable,
	.disable	= wifi_disable,
	.scan		= wifi_scan,
	.stop_scan	= wifi_stop_scan,
	.set_regdom	= wifi_set_regdom,
	.start_wps	= wifi_start_wps,
	.cancel_wps	= wifi_cancel_wps,
	.cancel_p2p	= wifi_cancel_p2p,
	.get_signal_info = wifi_get_signal_info,
};

static void system_ready(void)
{
	DBG("");

	if (connman_device_driver_register(&wifi_ng_driver) < 0)
		connman_error("Failed to register WiFi driver");
}

static void system_killed(void)
{
	DBG("");

	connman_device_driver_unregister(&wifi_ng_driver);
}

static int network_probe(struct connman_network *network)
{
	DBG("network %p", network);

	return 0;
}

static int network_connect(struct connman_network *network);

static gboolean perform_deferred_connect_after_disconnect(struct wifi_data *wifi)
{
	if (wifi->pending_network != NULL) {
		network_connect(wifi->pending_network);
		wifi->pending_network = NULL;
		return TRUE;
	}

	if (deferred_wps_start(wifi)) {
		return TRUE;
	}

	return FALSE;
}

static void network_remove(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (!wifi)
		return;

	if (wifi->network != network)
		return;
	else {
		wifi->disconnecting = FALSE;
		perform_deferred_connect_after_disconnect(wifi);
	}

	wifi->network = NULL;
}

static void connect_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct connman_network *network = user_data;

	DBG("network %p result %d", network, result);

	if (result == -ENOKEY) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_INVALID_KEY);
	} else if (result < 0) {
		connman_network_set_error(network,
					CONNMAN_NETWORK_ERROR_CONFIGURE_FAIL);
	}

	connman_network_unref(network);
}

static GSupplicantSecurity network_security(const char *security)
{
	if (g_str_equal(security, "none"))
		return G_SUPPLICANT_SECURITY_NONE;
	else if (g_str_equal(security, "wep"))
		return G_SUPPLICANT_SECURITY_WEP;
	else if (g_str_equal(security, "psk"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "wpa"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "rsn"))
		return G_SUPPLICANT_SECURITY_PSK;
	else if (g_str_equal(security, "ieee8021x"))
		return G_SUPPLICANT_SECURITY_IEEE8021X;

	return G_SUPPLICANT_SECURITY_UNKNOWN;
}

static void ssid_init(GSupplicantSSID *ssid, struct connman_network *network)
{
	struct wifi_network *network_data = connman_network_get_data(network);
	const char *security;

	memset(ssid, 0, sizeof(*ssid));
	ssid->mode = G_SUPPLICANT_MODE_INFRA;
	ssid->ssid = connman_network_get_blob(network, "WiFi.SSID",
						&ssid->ssid_len);
	ssid->scan_ssid = 1;
	security = connman_network_get_string(network, "WiFi.Security");
	ssid->security = network_security(security);
	
	ssid->passphrase = connman_network_get_string(network,
						"WiFi.Passphrase");

	ssid->eap = connman_network_get_string(network, "WiFi.EAP");

	/*
	 * If our private key password is unset,
	 * we use the supplied passphrase. That is needed
	 * for PEAP where 2 passphrases (identity and client
	 * cert may have to be provided.
	 */
	if (!connman_network_get_string(network, "WiFi.PrivateKeyPassphrase"))
		connman_network_set_string(network,
						"WiFi.PrivateKeyPassphrase",
						ssid->passphrase);
	/* We must have an identity for both PEAP and TLS */
	ssid->identity = connman_network_get_string(network, "WiFi.Identity");

	/* Use agent provided identity as a fallback */
	if (!ssid->identity || strlen(ssid->identity) == 0)
		ssid->identity = connman_network_get_string(network,
							"WiFi.AgentIdentity");

	ssid->anonymous_identity = connman_network_get_string(network,
						"WiFi.AnonymousIdentity");
	ssid->ca_cert_path = connman_network_get_string(network,
							"WiFi.CACertFile");
	ssid->subject_match = connman_network_get_string(network,
							"WiFi.SubjectMatch");
	ssid->altsubject_match = connman_network_get_string(network,
							"WiFi.AltSubjectMatch");
	ssid->domain_suffix_match = connman_network_get_string(network,
							"WiFi.DomainSuffixMatch");
	ssid->domain_match = connman_network_get_string(network,
							"WiFi.DomainMatch");
	ssid->client_cert_path = connman_network_get_string(network,
							"WiFi.ClientCertFile");
	ssid->private_key_path = connman_network_get_string(network,
							"WiFi.PrivateKeyFile");
	ssid->private_key_passphrase = connman_network_get_string(network,
						"WiFi.PrivateKeyPassphrase");
	ssid->phase2_auth = connman_network_get_string(network, "WiFi.Phase2");

	ssid->use_wps = connman_network_get_bool(network, "WiFi.UseWPS");
	ssid->pin_wps = connman_network_get_string(network, "WiFi.PinWPS");

	if (connman_setting_get_bool("BackgroundScanning"))
		ssid->bgscan = BGSCAN_DEFAULT;
}

static int network_connect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct wifi_data *wifi;
	GSupplicantInterface *interface;
	GSupplicantSSID *ssid;

	DBG("network %p", network);

	if (!device)
		return -ENODEV;

	wifi = connman_device_get_data(device);
	if (!wifi)
		return -ENODEV;

	if (wifi->wps_active)
		return -EINPROGRESS;

	ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (!ssid)
		return -ENOMEM;

	interface = wifi->interface;

	p2p_stop_find(wifi);
	ssid_init(ssid, network);

	if (wifi->disconnecting) {
		wifi->pending_network = network;
		g_free(ssid);
	} else {
		wifi->network = connman_network_ref(network);
		wifi->retries = 0;

		if (p2p_technology && is_technology_enabled(p2p_technology) &&
			connman_technology_get_p2p_listen(p2p_technology) == true) {
			set_p2p_listen_without_state_change(p2p_technology, false);

			wifi->p2p_listen_suppressed = true;
			if (p2p_find_ref == -1)
				g_supplicant_interface_p2p_stop_find(wifi->interface);
		}
		return g_supplicant_interface_connect(interface, ssid,
						connect_callback, network);
	}

	return -EINPROGRESS;
}

static void disconnect_callback(int result, GSupplicantInterface *interface,
								void *user_data)
{
	struct disconnect_data *dd = user_data;
	struct connman_network *network = dd->network;
	struct wifi_data *wifi = dd->wifi;

	g_free(dd);

	DBG("result %d supplicant interface %p wifi %p networks: current %p "
		"pending %p disconnected %p", result, interface, wifi,
		wifi->network, wifi->pending_network, network);

	if (result == -ECONNABORTED) {
		DBG("wifi interface no longer available");
		return;
	}

	if (g_slist_find(wifi->networks, network))
		connman_network_set_connected(network, false);

	wifi->disconnecting = false;

	if (network != wifi->network) {
		if (network == wifi->pending_network)
			wifi->pending_network = NULL;
		DBG("current wifi network has changed since disconnection");
		return;
	}

	wifi->network = NULL;

	wifi->disconnecting = false;
	wifi->connected = false;

	if (perform_deferred_connect_after_disconnect(wifi) == FALSE)
	{
		start_autoscan(wifi->device);
	}

	start_autoscan(wifi->device);
}

static int network_disconnect(struct connman_network *network)
{
	struct connman_device *device = connman_network_get_device(network);
	struct disconnect_data *dd;
	struct wifi_data *wifi;
	int err;

	DBG("network %p", network);

	wifi = connman_device_get_data(device);
	if (!wifi || !wifi->interface)
		return -ENODEV;

	connman_network_set_associating(network, false);

	if (wifi->disconnecting)
		return -EALREADY;

	wifi->disconnecting = true;

	dd = g_malloc0(sizeof(*dd));
	dd->wifi = wifi;
	dd->network = network;

	err = g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, dd);
	if (err < 0) {
		wifi->disconnecting = false;
		g_free(dd);
	}

	return err;
}

static struct connman_network_driver network_driver = {
	.name		= "wifi",
	.type		= CONNMAN_NETWORK_TYPE_WIFI,
	.priority	= CONNMAN_NETWORK_PRIORITY_LOW,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
};

static void interface_added(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	const char *driver = g_supplicant_interface_get_driver(interface);
	struct wifi_data *wifi;

	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi) {
		wifi = get_pending_wifi_data(ifname);
		if (!wifi)
			return;

		wifi->interface = interface;
		g_supplicant_interface_set_data(interface, wifi);
		p2p_iface_list = g_list_append(p2p_iface_list, wifi);
		wifi->p2p_device = true;
	}

	DBG("ifname %s driver %s wifi %p tethering %d",
			ifname, driver, wifi, wifi->tethering);

	if (!wifi->device) {
		connman_error("WiFi device not set");
		return;
	}

	connman_device_set_powered(wifi->device, true);
}

static bool is_idle(struct wifi_data *wifi)
{
	DBG("state %d", wifi->state);

	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
		return true;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return false;
	}

	return false;
}

static bool is_idle_wps(GSupplicantInterface *interface,
						struct wifi_data *wifi)
{
	/* First, let's check if WPS processing did not went wrong */
	if (g_supplicant_interface_get_wps_state(interface) ==
		G_SUPPLICANT_WPS_STATE_FAIL)
		return false;

	/* Unlike normal connection, being associated while processing wps
	 * actually means that we are idling. */
	switch (wifi->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
		return true;
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		return false;
	}

	return false;
}

static bool handle_wps_completion(GSupplicantInterface *interface,
					struct connman_network *network,
					struct connman_device *device,
					struct wifi_data *wifi)
{
	bool wps;

	wps = connman_network_get_bool(network, "WiFi.UseWPS");
	if (wps) {
		const unsigned char *ssid, *wps_ssid;
		unsigned int ssid_len, wps_ssid_len;
		struct disconnect_data *dd;
		const char *wps_key;

		if (wifi->wps_active == FALSE) {
			/* Checking if we got associated with requested
			 * network */
			ssid = connman_network_get_blob(network, "WiFi.SSID",
							&ssid_len);

		wps_ssid = g_supplicant_interface_get_wps_ssid(
			interface, &wps_ssid_len);

		if (!wps_ssid || wps_ssid_len != ssid_len ||
				memcmp(ssid, wps_ssid, ssid_len) != 0) {
			dd = g_malloc0(sizeof(*dd));
			dd->wifi = wifi;
			dd->network = network;

			connman_network_set_associating(network, false);
			g_supplicant_interface_disconnect(wifi->interface,
						disconnect_callback, dd);
			return false;
		}
		}

		wps_key = g_supplicant_interface_get_wps_key(interface);
		connman_network_set_string(network, "WiFi.Passphrase",
					wps_key);

		connman_network_set_string(network, "WiFi.PinWPS", NULL);
	}

	return true;
}

static bool handle_assoc_status_code(GSupplicantInterface *interface,
                                     struct wifi_data *wifi)
{
	if (wifi->state == G_SUPPLICANT_STATE_ASSOCIATING &&
			wifi->assoc_code == ASSOC_STATUS_NO_CLIENT &&
			wifi->load_shaping_retries < LOAD_SHAPING_MAX_RETRIES) {
		wifi->load_shaping_retries ++;
		return TRUE;
	}
	wifi->load_shaping_retries = 0;
	return FALSE;
}

static bool handle_4way_handshake_failure(GSupplicantInterface *interface,
					struct connman_network *network,
					struct wifi_data *wifi)
{
	struct connman_service *service;

	if ((wifi->state != G_SUPPLICANT_STATE_4WAY_HANDSHAKE) &&
			!((wifi->state == G_SUPPLICANT_STATE_ASSOCIATING) &&
				(wifi->assoc_code == ASSOC_STATUS_AUTH_TIMEOUT)))
		return false;

	if (wifi->connected)
		return false;

	service = connman_service_lookup_from_network(network);
	if (!service)
		return false;

	wifi->retries++;

	if (connman_service_get_favorite(service)) {
		if (wifi->retries < FAVORITE_MAXIMUM_RETRIES)
			return true;
	}

	wifi->retries = 0;
	connman_network_set_error(network, CONNMAN_NETWORK_ERROR_INVALID_KEY);

	return false;
}

static void wps_state(GSupplicantInterface *interface)
{
	struct wifi_data *wifi;
	GSupplicantWpsState state = g_supplicant_interface_get_wps_state(interface);
	const char *wps_ssid, *ssid;
	unsigned int wps_ssid_len, ssid_len;
	GSList *list;
	struct connman_network *found_network = NULL;

	wifi = g_supplicant_interface_get_data(interface);

	if(wifi==NULL)
		return;

	if (wifi->wps_active == FALSE)
		return;

	wps_ssid = g_supplicant_interface_get_wps_ssid(interface, &wps_ssid_len);

	DBG("wifi %p wps state %d ssid %s", wifi, state, wps_ssid);

	g_source_remove(wifi->wps_timeout);
	wifi->wps_timeout = 0;

	switch (state) {
	case G_SUPPLICANT_WPS_STATE_UNKNOWN:
		return;
	case G_SUPPLICANT_WPS_STATE_FAIL:
	wifi->wps_active = FALSE;
	connman_technology_wps_failed_notify(wifi_technology);
	return;
	}

	for (list = wifi->networks; list != NULL; list = list->next) {
		struct connman_network *network = list->data;

		ssid = connman_network_get_blob(network, "WiFi.SSID", &ssid_len);

		if (ssid != NULL && wps_ssid_len == ssid_len &&
		    memcmp(ssid, wps_ssid, ssid_len) == 0) {
			DBG("found network %s", ssid);
			connman_network_set_bool(network, "WiFi.UseWPS", TRUE);
			found_network = network;
			break;
		}
	}

	if (found_network == NULL) {
		DBG("didn't found a network for ssid %s", wps_ssid);
		g_supplicant_interface_disconnect(wifi->interface,
		disconnect_callback, wifi);
		return;
	}

	/* we've found the correct network so we connect as normal
	 * in our connection process */
	wifi->network = found_network;
}

static void interface_state(GSupplicantInterface *interface)
{
	struct connman_network *network;
	struct connman_device *device;
	struct wifi_data *wifi;
	GSupplicantState state = g_supplicant_interface_get_state(interface);
	bool wps;
	GSList *list;
	bool old_connected;
	const char *wps_ssid, *ssid;
	unsigned int wps_ssid_len, ssid_len;

	wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p interface state %d", wifi, state);

	if (!wifi)
		return;

	device = wifi->device;
	if (!device)
		return;

	if (state == G_SUPPLICANT_STATE_COMPLETED) {
		if (wifi->tethering_param) {
			g_free(wifi->tethering_param->ssid);
			g_free(wifi->tethering_param);
			wifi->tethering_param = NULL;
		}

		if (wifi->tethering)
			stop_autoscan(device);
	}

	if (g_supplicant_interface_get_ready(interface) &&
					!wifi->interface_ready) {
		wifi->interface_ready = true;
		finalize_interface_creation(wifi);
	}

	network = wifi->network;
	if (!network)
		return;

	wps_ssid = g_supplicant_interface_get_wps_ssid(interface, &wps_ssid_len);
	if (!network && wifi->wps_active && wps_ssid_len) {
		for (list = wifi->networks; list != NULL; list = list->next) {
			struct connman_network *connected_network = list->data;

			ssid = connman_network_get_blob(connected_network, "WiFi.SSID", &ssid_len);
			if (ssid != NULL && wps_ssid_len == ssid_len &&
				memcmp(ssid, wps_ssid, ssid_len) == 0) {
				DBG("found network %s", ssid);
				connman_network_set_bool(connected_network, "WiFi.UseWPS", TRUE);
				wifi->network = connected_network;
				network = wifi->network;
				break;
			}
		}
	}

	switch (state) {
	case G_SUPPLICANT_STATE_SCANNING:
		if (wifi->connected)
			connman_network_set_connected(network, false);

		break;

	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
		stop_autoscan(device);

		connman_device_set_scanning(device, CONNMAN_SERVICE_TYPE_WIFI,FALSE);
		if (!wifi->connected)
			connman_network_set_associating(network, true);

		break;

	case G_SUPPLICANT_STATE_COMPLETED:
		/* though it should be already stopped: */
		stop_autoscan(device);

		connman_device_set_scanning(device,CONNMAN_SERVICE_TYPE_WIFI,FALSE);
		if (!handle_wps_completion(interface, network, device, wifi))
			break;

		connman_network_set_connected(network, true);

		wifi->disconnect_code = 0;
		wifi->assoc_code = 0;
		wifi->load_shaping_retries = 0;
		wifi->wps_active = FALSE;
		break;

	case G_SUPPLICANT_STATE_DISCONNECTED:
		/*
		 * If we're in one of the idle modes, we have
		 * not started association yet and thus setting
		 * those ones to FALSE could cancel an association
		 * in progress.
		 */
		wps = connman_network_get_bool(network, "WiFi.UseWPS");
		if (wps)
			if (is_idle_wps(interface, wifi))
				break;

		if (is_idle(wifi))
			break;

		if (handle_assoc_status_code(interface, wifi))
			break;

		/* If previous state was 4way-handshake, then
		 * it's either: psk was incorrect and thus we retry
		 * or if we reach the maximum retries we declare the
		 * psk as wrong */
		if (handle_4way_handshake_failure(interface,
						network, wifi))
			break;

		/* See table 8-36 Reason codes in IEEE Std 802.11 */
		switch (wifi->disconnect_code) {
		case 6: /* Class 2 frame received from nonauthenticated STA */
			connman_network_set_error(network,
						CONNMAN_NETWORK_ERROR_BLOCKED);
			break;

		default:
			break;
		}

		if (network != wifi->pending_network) {
			connman_network_set_connected(network, false);
			connman_network_set_associating(network, false);
		}
		wifi->disconnecting = false;

		if (!deferred_wps_start(wifi))
		{
			/* Set connected to false to allow autoscan to start. */
			wifi->connected = FALSE;
		    start_autoscan(device);
		}

		break;

	case G_SUPPLICANT_STATE_INACTIVE:
		connman_network_set_associating(network, false);
		start_autoscan(device);

		break;

	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		break;
	}

	old_connected = wifi->connected;
	wifi->state = state;

	/* Saving wpa_s state policy:
	 * If connected and if the state changes are roaming related:
	 * --> We stay connected
	 * If completed
	 * --> We are connected
	 * All other case:
	 * --> We are not connected
	 * */
	switch (state) {
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		if (wifi->connected)
			connman_warn("Probably roaming right now!"
						" Staying connected...");
		break;
	case G_SUPPLICANT_STATE_SCANNING:
		wifi->connected = false;

		if (old_connected)
			start_autoscan(device);
		break;
	case G_SUPPLICANT_STATE_COMPLETED:
		wifi->connected = true;
		break;
	default:
		wifi->connected = false;
		break;
	}

	DBG("DONE");
}

static void interface_removed(GSupplicantInterface *interface)
{
	const char *ifname = g_supplicant_interface_get_ifname(interface);
	struct wifi_data *wifi;
	int err;

	DBG("ifname %s", ifname);
	GSList *list;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;
		GSupplicantInterface *p2p_interface = wifi->interface;

		if (!p2p_interface || !g_supplicant_interface_has_p2p(p2p_interface))
			continue;

		if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
				g_strcmp0(g_supplicant_interface_get_ifname(p2p_interface),
					connman_option_get_string("P2PDevice")) != 0)
			continue;

		if (connman_technology_get_p2p_listen(p2p_technology) == false &&
				!__connman_peer_get_connected_exists()) {
			if (!connman_technology_get_enable_p2p_listen(p2p_technology))
				break;
			err = apply_p2p_listen_on_iface(wifi, &params);
			if (err == 0)
				connman_technology_set_p2p_listen(p2p_technology, true);
		}
	}

	wifi = g_supplicant_interface_get_data(interface);

	if (wifi)
		wifi->interface = NULL;

	if (wifi && wifi->tethering)
		return;

	if (!wifi || !wifi->device) {
		DBG("wifi interface already removed");
		return;
	}

	connman_device_set_powered(wifi->device, false);

	check_p2p_technology();
}

static void set_device_type(const char *type, char dev_type[17])
{
	const char *oui = "0050F204";
	const char *category = "0001";
	const char *sub_category = "0000";

	if (!g_strcmp0(type, "handset")) {
		category = "000A";
		sub_category = "0005";
	} else if (!g_strcmp0(type, "vm") || !g_strcmp0(type, "container"))
		sub_category = "0001";
	else if (!g_strcmp0(type, "server"))
		sub_category = "0002";
	else if (!g_strcmp0(type, "laptop"))
		sub_category = "0005";
	else if (!g_strcmp0(type, "desktop"))
		sub_category = "0006";
	else if (!g_strcmp0(type, "tablet"))
		sub_category = "0009";
	else if (!g_strcmp0(type, "watch"))
		category = "00FF";

	snprintf(dev_type, 17, "%s%s%s", category, oui, sub_category);
}

static void p2ps_prov_start(GSupplicantInterface *interface,  GSupplicantPeer *peer, GSupplicantP2PSProvisionSignalParams* params)
{
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (connman_network == NULL)
		return;

	//wfds_on_p2ps_prov_start(connman_network, params);
}

static void p2ps_prov_done(GSupplicantInterface *interface,  GSupplicantPeer *peer, GSupplicantP2PSProvisionSignalParams* params)
{
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (connman_network == NULL)
		return;

	//wfds_on_p2ps_prov_done(connman_network, params);
}

static GSupplicantSSID *ssid_persistent_init(GSupplicantP2PPersistentGroup *persistent_group, int go)
{
	GSupplicantSSID *p_ssid;

	p_ssid = g_try_malloc0(sizeof(GSupplicantSSID));
	if (p_ssid == NULL)
		return NULL;

	if(go == 1)
		p_ssid->mode = G_SUPPLICANT_MODE_MASTER;
	else
		p_ssid->mode = G_SUPPLICANT_MODE_UNKNOWN;
	p_ssid->ssid = g_strdup(persistent_group->ssid);
	p_ssid->ssid_len = strlen(persistent_group->ssid);
	p_ssid->scan_ssid = 0;
	p_ssid->bssid = g_strdup(persistent_group->bssid);
	p_ssid->passphrase= g_strdup(persistent_group->psk);

	p_ssid->security = G_SUPPLICANT_SECURITY_PSK;
	p_ssid->protocol = G_SUPPLICANT_PROTO_RSN;
	p_ssid->pairwise_cipher = G_SUPPLICANT_PAIRWISE_CCMP;
	p_ssid->group_cipher = G_SUPPLICANT_GROUP_CCMP;

	return p_ssid;
}

static int p2p_persistent_info_load(GSupplicantInterface *interface, const char *persistent_dir, GSupplicantP2PPersistentGroup *persistent_group)
{
	GKeyFile *keyfile;
	const char *ssid=NULL, *bssid=NULL, *psk=NULL, *role=NULL, *mac_address=NULL;
	int ret = -1;
	unsigned long long connectedtime=0;

	keyfile = __connman_storage_open_service(persistent_dir);
	if(keyfile == NULL)
		return -EIO;

	ssid = g_key_file_get_string(keyfile, P2P_PERSISTENT_INFO, "SSID", NULL);
	bssid = g_key_file_get_string(keyfile, P2P_PERSISTENT_INFO, "BSSID", NULL);
	psk = g_key_file_get_string(keyfile, P2P_PERSISTENT_INFO, "PSK", NULL);
	role = g_key_file_get_string(keyfile, P2P_PERSISTENT_INFO, "Role", NULL);
	mac_address = g_key_file_get_string(keyfile, P2P_PERSISTENT_INFO, "MAC", NULL);
	connectedtime = g_key_file_get_uint64(keyfile, P2P_PERSISTENT_INFO, "ConnectedTime", NULL);

	g_key_file_free(keyfile);

	if (mac_address) {
		struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
		if (wifi) {
			char * p2p_ident = __connman_util_insert_colon_to_mac_addr(connman_device_get_ident(wifi->device));
			if (strncmp(mac_address, p2p_ident, 17) != 0) {
				// P2P MAC address changed, so removing this p2p service
				__connman_storage_remove_service(persistent_dir);
				g_free(p2p_ident);
				goto cleanup;
			}
			g_free(p2p_ident);
		}
	}

	if(ssid != NULL && bssid != NULL && psk != NULL) {
		DBG("ssid : %s bssid : %s psk : %s connectedtime : %llu\n", ssid, bssid, psk, connectedtime);

		persistent_group->interface = interface;
		persistent_group->ssid = g_strdup(ssid);
		persistent_group->bssid = g_strdup(bssid);
		persistent_group->psk = g_strdup(psk);
		persistent_group->connected_time = connectedtime;

		if(g_str_equal(role, "GO")) {
			persistent_group->go = TRUE;
			ret = 1;
		} else if(g_str_equal(role, "Client")) {
			persistent_group->go = FALSE;
			ret = 0;
		} else
			ret = -1;
	}

cleanup:
	g_free(mac_address);
	g_free(role);
	g_free(psk);
	g_free(bssid);
	g_free(ssid);
	return ret;
}

static void ssid_persistent_free(GSupplicantSSID *p_ssid)
{
	if (p_ssid == NULL)
		return;

	if (p_ssid->ssid)
		g_free(p_ssid->ssid);
	if (p_ssid->bssid)
		g_free(p_ssid->bssid);
	if (p_ssid->passphrase)
		g_free(p_ssid->passphrase);

	g_free(p_ssid);
	p_ssid = NULL;
}


static int add_persistent_group_info(struct wifi_data *wifi)
{
	GSupplicantInterface *interface;
	gchar **persistents;
	GSupplicantP2PPersistentGroup *persistent_group;
	int go;
	char *peer;
	int i;

	if(wifi == NULL)
		return -ENOMEM;

	interface = wifi->interface;

	if(interface == NULL)
		return -ENOMEM;

	persistents = __connman_storage_get_p2p_persistents();
        if (!persistents)
            return -ENOMEM;

	for (i = 0; persistents && persistents[i]; i++) {
		persistent_group = g_try_malloc0(sizeof(GSupplicantP2PPersistentGroup));
		if(persistent_group == NULL) {
			g_strfreev(persistents);
			return -ENOMEM;
		}

		if (strncmp(persistents[i], "p2p_persistent_", 15) != 0) {
			g_free(persistent_group);
			continue;
		}

		go = p2p_persistent_info_load(interface, persistents[i], persistent_group);
		if(go < 0) {
			g_free(persistent_group);
			continue;
		}
		else {
			GSupplicantSSID *p_ssid = ssid_persistent_init(persistent_group, go);

			if(p_ssid == NULL) {
				g_free(persistent_group);
				continue;
			}

			wifi->persistent_groups = g_slist_prepend(wifi->persistent_groups, persistent_group);

			g_supplicant_interface_p2p_add_persistent_group(interface, p_ssid, &go);

			peer = strrchr(persistents[i], '_') + 1;
			g_hash_table_replace(wifi->persistent_peer_ssid, peer, persistent_group->ssid);
			ssid_persistent_free(p_ssid);
		}
	}
        g_strfreev(persistents);
	return 1;
}
static void p2p_support(GSupplicantInterface *interface)
{
	char dev_type[17] = {};
	const char *hostname;

	DBG("");

	if (!interface)
		return;

	if (!g_supplicant_interface_has_p2p(interface))
		return;

	if (connman_technology_driver_register(&p2p_tech_driver) < 0) {
		DBG("Could not register P2P technology driver");
		return;
	}

	hostname = connman_utsname_get_hostname();
	if (!hostname)
		hostname = "ConnMan";

	set_device_type(connman_machine_get_type(), dev_type);
	g_supplicant_interface_set_p2p_device_config(interface,
							hostname, dev_type);
	connman_peer_driver_register(&peer_driver);
}

static void p2p_device_config_loaded(GSupplicantInterface *interface)
{
	struct wifi_data *wifi = NULL;
	char dev_type[17] = {};
	char hostname[HOST_NAME_MAX+1] = {0};
	const char *p2p_identifier;
	char *old_device_name = NULL, *old_ssid_postfix = NULL;
	int result;

	wifi = g_supplicant_interface_get_data(interface);

	if (!wifi)
		return;

	p2p_identifier = load_p2p_identifier();
	if (wifi->p2p_device_config.device_name)
		old_device_name = wifi->p2p_device_config.device_name;

	if (wifi->p2p_device_config.ssid_postfix)
		old_ssid_postfix = wifi->p2p_device_config.ssid_postfix;

	if (!p2p_identifier) {
		if (gethostname(hostname, HOST_NAME_MAX) < 0)
			return;

		wifi->p2p_device_config.device_name = g_strdup(hostname);
	}
	else
		wifi->p2p_device_config.device_name = g_strdup(p2p_identifier);

	if (wifi->p2p_device_config.device_name) {
		/* we have to add a hyphen here as wpa-supplicant just adds the postifx to the
		 * automatically created SSID */
		wifi->p2p_device_config.ssid_postfix = g_strdup_printf("-%s", wifi->p2p_device_config.device_name);
	}

	/**
	 * TV icon type listed as Laptop. Reason is the machine type related interface org.freedesktop.hostname1
	 * is not used ,commenting the below source ,using the type from wpa_supplicant as it is
	 */
	/*	set_device_type(connman_machine_get_type(), dev_type);
	 dev_type_str2bin(dev_type, wifi->p2p_device_config.pri_dev_type);*/

	result = g_supplicant_interface_set_p2p_device_configs(interface, &wifi->p2p_device_config, NULL);
	if (result < 0) {
		g_free(wifi->p2p_device_config.device_name);
		g_free(wifi->p2p_device_config.ssid_postfix);
		wifi->p2p_device_config.device_name = old_device_name;
		wifi->p2p_device_config.ssid_postfix = old_ssid_postfix;
	}

	connman_technology_set_p2p_identifier(p2p_technology, wifi->p2p_device_config.device_name);
	if (old_device_name != wifi->p2p_device_config.device_name)
		g_free(old_device_name);
	if (old_ssid_postfix != wifi->p2p_device_config.ssid_postfix)
		g_free(old_ssid_postfix);

    g_free(p2p_identifier);
}

static void scan_started(GSupplicantInterface *interface)
{
	DBG("");
}

static void scan_finished(GSupplicantInterface *interface)
{
	DBG("");
}

static void ap_create_fail(GSupplicantInterface *interface)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	int ret;

	if ((wifi->tethering) && (wifi->tethering_param)) {
		DBG("%s create AP fail \n",
				g_supplicant_interface_get_ifname(wifi->interface));

		connman_inet_remove_from_bridge(wifi->index, wifi->bridge);
		wifi->ap_supported = WIFI_AP_NOT_SUPPORTED;
		wifi->tethering = false;

		ret = tech_set_tethering(wifi->tethering_param->technology,
				wifi->tethering_param->ssid->ssid,
				wifi->tethering_param->ssid->passphrase,
				wifi->bridge, true);

		if ((ret == -EOPNOTSUPP) && (wifi_technology)) {
			connman_technology_tethering_notify(wifi_technology,false);
		}

		g_free(wifi->tethering_param->ssid);
		g_free(wifi->tethering_param);
		wifi->tethering_param = NULL;
	}
}

static unsigned char calculate_strength(GSupplicantNetwork *supplicant_network)
{
	unsigned char strength;

	strength = 120 + g_supplicant_network_get_signal(supplicant_network);
	if (strength > 100)
		strength = 100;

	return strength;
}

static unsigned char calculate_peer_strength(GSupplicantPeer *peer)
{
	unsigned char strength;

	strength = 120 + g_supplicant_peer_get_level(peer);
	if (strength > 100)
		strength = 100;

	return strength;
}

static void network_added(GSupplicantNetwork *supplicant_network)
{
	struct connman_network *network;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct wifi_network *network_data;
	const char *name, *identifier, *security, *group, *mode;
	const unsigned char *ssid;
	unsigned int ssid_len;
	bool wps;
	bool wps_pbc;
	bool wps_ready;
	bool wps_advertizing;
	GHashTable *bss_table;

	mode = g_supplicant_network_get_mode(supplicant_network);
	identifier = g_supplicant_network_get_identifier(supplicant_network);

	DBG("%s", identifier);

	if (!g_strcmp0(mode, "adhoc"))
		return;

	interface = g_supplicant_network_get_interface(supplicant_network);
	wifi = g_supplicant_interface_get_data(interface);
	name = g_supplicant_network_get_name(supplicant_network);
	security = g_supplicant_network_get_security(supplicant_network);
	group = g_supplicant_network_get_identifier(supplicant_network);
	wps = g_supplicant_network_get_wps(supplicant_network);
	wps_pbc = g_supplicant_network_is_wps_pbc(supplicant_network);
	wps_ready = g_supplicant_network_is_wps_active(supplicant_network);
	wps_advertizing = g_supplicant_network_is_wps_advertizing(
							supplicant_network);
	bss_table = g_supplicant_network_get_bss_table(supplicant_network);

	if (!wifi)
		return;

	ssid = g_supplicant_network_get_ssid(supplicant_network, &ssid_len);

	network = connman_device_get_network(wifi->device, identifier);

	if (!network) {
		network = connman_network_create(identifier,
						CONNMAN_NETWORK_TYPE_WIFI);
		if (!network)
			return;

		connman_network_set_index(network, wifi->index);

		if (connman_device_add_network(wifi->device, network) < 0) {
			connman_network_unref(network);
			return;
		}

		wifi->networks = g_slist_prepend(wifi->networks, network);

		network_data = g_new0(struct wifi_network, 1);
		connman_network_set_data(network, network_data);
	}

	network_data = connman_network_get_data(network);
	network_data->keymgmt =
		g_supplicant_network_get_keymgmt(supplicant_network);

	if (name && name[0] != '\0')
		connman_network_set_name(network, name);

	connman_network_set_blob(network, "WiFi.SSID",
						ssid, ssid_len);
	connman_network_set_string(network, "WiFi.Security", security);
	connman_network_set_strength(network,
				calculate_strength(supplicant_network));
	connman_network_set_bool(network, "WiFi.WPS", wps);
	connman_network_set_bool(network, "WiFi.WPSAdvertising",
				wps_advertizing);

	if (wps) {
		/* Is AP advertizing for WPS association?
		 * If so, we decide to use WPS by default */
		if (wps_ready && wps_pbc &&
						wps_advertizing)
			connman_network_set_bool(network, "WiFi.UseWPS", true);
	}

	connman_network_set_frequency(network,
			g_supplicant_network_get_frequency(supplicant_network));

	connman_network_set_available(network, true);
	connman_network_set_string(network, "WiFi.Mode", mode);

	if (ssid)
		connman_network_set_group(network, group);

	if (wifi->hidden && ssid) {
		if (!g_strcmp0(wifi->hidden->security, security) &&
				wifi->hidden->ssid_len == ssid_len &&
				!memcmp(wifi->hidden->ssid, ssid, ssid_len)) {
			connman_network_connect_hidden(network,
					wifi->hidden->identity,
					wifi->hidden->passphrase,
					wifi->hidden->user_data);
			wifi->hidden->user_data = NULL;
			hidden_free(wifi->hidden);
			wifi->hidden = NULL;
		}
	}

	connman_network_set_address(network, g_supplicant_network_get_bssid(supplicant_network), 6);

	if (bss_table)
		g_hash_table_foreach(bss_table, bss_foreach, network);
}

static void network_removed(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);

	DBG("name %s", name);

	if (!wifi)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	wifi->networks = g_slist_remove(wifi->networks, connman_network);

	g_free(connman_network_get_data(connman_network));
	connman_device_remove_network(wifi->device, connman_network);
	connman_network_unref(connman_network);
}

static void network_changed(GSupplicantNetwork *network, const char *property)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	const char *name, *identifier;
	struct connman_network *connman_network;
	bool update_needed;
	GHashTable *bss_table;

	if (p2p_find_ref != -1)
		return;

	interface = g_supplicant_network_get_interface(network);
	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_network_get_identifier(network);
	name = g_supplicant_network_get_name(network);
	bss_table = g_supplicant_network_get_bss_table(network);

	DBG("name %s", name);

	if (!wifi)
		return;

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	connman_network_set_address(connman_network, g_supplicant_network_get_bssid(network), 6);

	if (bss_table)
		g_hash_table_foreach(bss_table, bss_foreach, connman_network);

	if (g_str_equal(property, "WPSCapabilities")) {
		bool wps;
		bool wps_pbc;
		bool wps_ready;
		bool wps_advertizing;

		wps = g_supplicant_network_get_wps(network);
		wps_pbc = g_supplicant_network_is_wps_pbc(network);
		wps_ready = g_supplicant_network_is_wps_active(network);
		wps_advertizing =
			g_supplicant_network_is_wps_advertizing(network);

		connman_network_set_bool(connman_network, "WiFi.WPS", wps);
		connman_network_set_bool(connman_network,
				"WiFi.WPSAdvertising", wps_advertizing);

		if (wps) {
			/*
			 * Is AP advertizing for WPS association?
			 * If so, we decide to use WPS by default
			 */
			if (wps_ready && wps_pbc && wps_advertizing)
				connman_network_set_bool(connman_network,
							"WiFi.UseWPS", true);
		}

		update_needed = true;
	} else if (g_str_equal(property, "Signal")) {
		connman_network_set_strength(connman_network,
					calculate_strength(network));
		update_needed = true;
	} else
		update_needed = false;

	if (update_needed)
		connman_network_update(connman_network);
}

static void network_associated(GSupplicantNetwork *network)
{
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct connman_network *connman_network;
	const char *identifier;

	DBG("");

	interface = g_supplicant_network_get_interface(network);
	if (!interface)
		return;

	wifi = g_supplicant_interface_get_data(interface);
	if (!wifi)
		return;

	/* P2P networks must not be treated as WiFi networks */
	if (wifi->p2p_connecting || wifi->p2p_device)
		return;

	identifier = g_supplicant_network_get_identifier(network);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	if (wifi->network) {
		if (wifi->network == connman_network)
			return;

		/*
		 * This should never happen, we got associated with
		 * a network different than the one we were expecting.
		 */
		DBG("Associated to %p while expecting %p",
					connman_network, wifi->network);

		connman_network_set_associating(wifi->network, false);
	}

	DBG("Reconnecting to previous network %p from wpa_s", connman_network);

	wifi->network = connman_network_ref(connman_network);
	wifi->retries = 0;

	/*
	 * Interface state changes callback (interface_state) is always
	 * called before network_associated callback thus we need to call
	 * interface_state again in order to process the new state now that
	 * we have the network properly set.
	 */
	interface_state(interface);
}

static void sta_authorized(GSupplicantInterface *interface,
					const char *addr)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p station %s authorized", wifi, addr);

	if (!wifi || !wifi->tethering)
		return;

	__connman_tethering_client_register(addr);
}

static void sta_deauthorized(GSupplicantInterface *interface,
					const char *addr)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	DBG("wifi %p station %s deauthorized", wifi, addr);

	if (!wifi || !wifi->tethering)
		return;

	__connman_tethering_client_unregister(addr);
}

static void station_added(const char *mac)
{
	int stacount = 0;
	connman_technology_tethering_add_station(CONNMAN_SERVICE_TYPE_WIFI, mac);

	stacount = __connman_tethering_sta_count();
	__connman_technology_sta_count_changed(CONNMAN_SERVICE_TYPE_WIFI, stacount);
}

static void station_removed(const char *mac)
{
	int stacount = 0;

	connman_technology_tethering_remove_station(mac);

	stacount = __connman_tethering_sta_count();
	__connman_technology_sta_count_changed(CONNMAN_SERVICE_TYPE_WIFI, stacount);
}

static void p2p_sd_asp_response(GSupplicantInterface *interface, GSupplicantPeer *peer,
								unsigned char transaction_id,
								unsigned int advertisement_id,
								unsigned char service_status,
								dbus_uint16_t config_method,
								const char* service_name,
								const char* service_info)
{
	/*
	wfds_on_service_discovery_response(peer,
										transaction_id,
										advertisement_id,
										service_status,
										config_method,
										service_name,
										service_info);
	*/
}

static void p2p_sd_response(GSupplicantInterface *interface, GSupplicantPeer *peer,
				int indicator, unsigned char *tlv, int tlv_len)
{
	struct wifi_data *wifi;
	const char *identifier;

	if (p2p_technology == NULL)
		return;

	wifi = g_supplicant_interface_get_data(interface);

	identifier =  strrchr(g_supplicant_peer_get_path(peer), '/') + 1;

	__connman_sd_response_from_p2p_peer(identifier, indicator, tlv, tlv_len);
}

static void apply_peer_services(GSupplicantPeer *peer,
				struct connman_peer *connman_peer)
{
	const unsigned char *data;
	int length;

	DBG("");

	connman_peer_reset_services(connman_peer);

	data = g_supplicant_peer_get_widi_ies(peer, &length);
	if (data) {
		connman_peer_add_service(connman_peer,
			CONNMAN_PEER_SERVICE_WIFI_DISPLAY, data, length);
	}
}

static void peer_found(GSupplicantPeer *peer)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_peer *connman_peer;

	struct connman_network *connman_network;

	const char *identifier, *name, *path, *pri_dev_type;;
	dbus_uint16_t config_methods;
	int ret;

	identifier = g_supplicant_peer_get_identifier(peer);
	name = g_supplicant_peer_get_name(peer);

	path = g_supplicant_peer_get_path(peer);
	config_methods = g_supplicant_peer_get_config_methods(peer);
	pri_dev_type = g_supplicant_peer_get_pri_dev_type(peer);

	DBG("ident: %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);

	if (connman_network == NULL) {
		DBG("creating new network");
		connman_network = connman_network_create(identifier, CONNMAN_NETWORK_TYPE_WIFI);
		if (connman_network == NULL)
			return;

		connman_network_set_index(connman_network, wifi->index);

		connman_network_set_name(connman_network, name);
		connman_network_set_string(connman_network, "Path", path);
		connman_network_set_p2p_network(connman_network, TRUE);
		if (connman_device_add_network(wifi->device, connman_network) < 0) {
			connman_network_unref(connman_network);
			return;
		}

		wifi->networks = g_slist_prepend(wifi->networks, connman_network);
	} else {
		DBG("network already exists, just update it");

		connman_network_set_name(connman_network, name);
		__connman_service_update_from_network(connman_network);
	}

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (connman_peer)
		return;

	connman_peer = connman_peer_create(identifier);
	connman_peer_set_name(connman_peer, name);
	connman_peer_set_device(connman_peer, wifi->device);
	connman_peer_set_strength(connman_peer, calculate_peer_strength(peer));
	connman_peer_set_config_methods(connman_peer, config_methods);
	connman_peer_set_pri_dev_type(connman_peer, pri_dev_type);

	apply_peer_services(peer, connman_peer);

	ret = connman_peer_register(connman_peer);
	if (ret < 0 && ret != -EALREADY)
		connman_peer_unref(connman_peer);
	else
		wifi->peers = g_slist_prepend(wifi->peers, connman_peer);
}

static void peer_lost(GSupplicantPeer *peer)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_peer *connman_peer;
	const char *identifier;
	struct connman_network *connman_network;

	if (!wifi)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	if (!identifier)
		return;

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	connman_network = connman_device_get_network(wifi->device, identifier);

	if (connman_peer) {
		if (wifi->p2p_connecting &&
				wifi->pending_peer == connman_peer) {
			peer_connect_timeout(wifi);
		}
		connman_peer_unregister(connman_peer);
		connman_peer_unref(connman_peer);
	}

	if (connman_network) {
		wifi->networks = g_slist_remove(wifi->networks, connman_network);

		connman_device_remove_network(wifi->device, connman_network);
		connman_network_unref(connman_network);
	}

	wifi->peers = g_slist_remove(wifi->peers, connman_peer);
}

GSList * __connman_service_connected_peer_list(struct wifi_data *wifi)
{
	GSList *list;
	GSList *connected_peers = NULL;
	int cnt = 0;

	for (list = wifi->peers; list; list = list->next)
	{
		struct connman_peer *peer = list->data;
		if (peer == NULL)
			continue;

		if (connman_peer_get_state(peer) == CONNMAN_PEER_STATE_READY)
			connected_peers = g_slist_prepend(connected_peers, peer);
	}
	return connected_peers;
}

static char * p2p_persistent_info_find_oldest(const char *identifier, GList * connected_p2pList, struct wifi_data *wifi)
{
	gchar **persistents = NULL;
	int i = 0;
	char *peer_ident = NULL;
	char *oldest_identifier = NULL;
	guint64 oldest_time = 0;
	GList *list;
	char *connected_identifier = NULL;
	connman_bool_t same = 0;

	persistents = __connman_storage_get_p2p_persistents();
	for (i = 0; persistents && persistents[i]; i++)
	{
		if (strncmp(persistents[i], "p2p_persistent_", 15) != 0)
			continue;

		peer_ident = strrchr(persistents[i], '_') + 1;

		if (!strcmp(peer_ident, identifier))
			continue;

		for (list = connected_p2pList; list != NULL; list = list->next)
		{
			struct connman_peer *peer = list->data;
			if (peer == NULL)
				continue;

			if (connman_peer_get_state(peer) == CONNMAN_PEER_STATE_READY)
				connected_identifier = connman_peer_get_identifier(peer);

			if (connected_identifier && !strcmp(peer_ident, connected_identifier))
			{
				same = 1;
				break;
			}
		}

		if (same)
		{
			same = 0;
			continue;
		}

		GKeyFile *keyfile = NULL;
		keyfile =  __connman_storage_open_service(persistents[i]);
		guint64 last_connected = 0;
		last_connected = g_key_file_get_uint64(keyfile, P2P_PERSISTENT_INFO, "ConnectedTime", NULL);

		if (last_connected == 0){
			struct timeval now;
			unsigned long current_time = 0;
			if (!gettimeofday(&now, NULL))
				current_time = now.tv_sec;

			g_key_file_set_uint64(keyfile, P2P_PERSISTENT_INFO, "ConnectedTime", current_time);

			g_key_file_free(keyfile);
			continue;
		}

		if (oldest_time == 0 || oldest_time > last_connected)
		{
			oldest_time = last_connected;
			if (oldest_identifier != NULL)
			{
				g_free(oldest_identifier);
				oldest_identifier = NULL;
			}
			oldest_identifier = g_strdup(peer_ident);
		}

		g_key_file_free(keyfile);
	}

	if (persistents != NULL)
		g_strfreev(persistents);

	return oldest_identifier;
}
static void p2p_persistent_info_remove_oldest(const char *identifier, struct wifi_data *wifi)
{
	char *oldest_identifier = NULL;
	GList *connected_p2p_list = NULL;
	char persistent_info_name[28] = "p2p_persistent_";

	connected_p2p_list = __connman_service_connected_peer_list(wifi);

	oldest_identifier = p2p_persistent_info_find_oldest(identifier, connected_p2p_list, wifi);

	if (oldest_identifier == NULL)
		return;

	strncat(persistent_info_name, oldest_identifier, strlen(oldest_identifier));

	g_hash_table_remove(wifi->persistent_peer_ssid, oldest_identifier);
	__connman_storage_remove_service(persistent_info_name);

	g_free(oldest_identifier);
	g_slist_free(connected_p2p_list);
}
static void p2p_persistent_info_save(const char *identifier, GSupplicantP2PPersistentGroup *persistent_group)
{
	char persistent_info_name[28] = "p2p_persistent_";
	strncat(persistent_info_name, identifier, strlen(identifier));
	int count = 0;

	if(persistent_group == NULL) {
		return;
	} else {
		GKeyFile *keyfile;
		char * mac_address=NULL;

		if(persistent_group->psk == NULL)
			return;

		keyfile = __connman_storage_open_service(persistent_info_name);
		if (keyfile == NULL)
			return;

		g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "SSID", persistent_group->ssid);
		g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "BSSID", persistent_group->bssid);
		g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "PSK", persistent_group->psk);

		struct wifi_data *wifi = g_supplicant_interface_get_data(persistent_group->interface);
		if (wifi) {
			mac_address = __connman_util_insert_colon_to_mac_addr(connman_device_get_ident(wifi->device));
			if (mac_address)
				g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "MAC", mac_address);
		}

		if(persistent_group->go == TRUE)
			g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "Role", "GO");
		else
			g_key_file_set_string(keyfile, P2P_PERSISTENT_INFO, "Role", "Client");

		struct timeval now;
		unsigned long connected_time = 0;
		if (!gettimeofday(&now, NULL))
			connected_time = now.tv_sec;

		persistent_group->connected_time = connected_time;
		g_key_file_set_uint64(keyfile, P2P_PERSISTENT_INFO, "ConnectedTime", persistent_group->connected_time);

		__connman_storage_save_service(keyfile, persistent_info_name);

		g_free(mac_address);
		count = __connman_storage_get_p2p_persistents_count();
		if (wifi && count > P2P_PERSISTENT_MAX_COUNT)
			p2p_persistent_info_remove_oldest(identifier, wifi);

		g_key_file_free(keyfile);
	}
}
static void p2p_go_neg_failed(GSupplicantInterface *interface, struct connman_peer *peer, int status)
{
	struct wifi_data *wifi;
	const char *identifier, *path;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = connman_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	p2p_peers_refresh(wifi);

	// TODO: will consider with other WFDS changes
//	wfds_on_go_neg_failed(connman_network, status);

	path = __connman_peer_get_path(peer);

	if(!path)
		return;

	connman_dbus_property_changed_basic(path, CONNMAN_PEER_INTERFACE,
					"P2PGONegFailed", DBUS_TYPE_INT32, &status);

}

static void peer_dhcp_address_update()
{
	struct connman_group *group;

	group = __connman_group_lookup_from_ident(p2p_go_identifier);
	if (group == NULL)
		return;

	__connman_group_client_dhcp_ip_assigned(group);
}
static void peer_changed(GSupplicantPeer *peer, GSupplicantPeerState state)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	enum connman_peer_state p_state = CONNMAN_PEER_STATE_UNKNOWN;
	struct connman_peer *connman_peer;
	struct connman_group *connman_group;
	const char *identifier;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	if (!wifi)
		return;

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	switch (state) {
	case G_SUPPLICANT_PEER_SERVICES_CHANGED:
		apply_peer_services(peer, connman_peer);
		connman_peer_services_changed(connman_peer);
		return;
	case G_SUPPLICANT_PEER_GROUP_CHANGED:
		if (!g_supplicant_peer_is_in_a_group(peer))
			p_state = CONNMAN_PEER_STATE_IDLE;
		else
			p_state = CONNMAN_PEER_STATE_CONFIGURATION;
		break;
	case G_SUPPLICANT_PEER_GROUP_STARTED:
		break;
	case G_SUPPLICANT_PEER_GROUP_FINISHED:
		p_state = CONNMAN_PEER_STATE_IDLE;
		break;
	case G_SUPPLICANT_PEER_GROUP_JOINED:
		connman_peer_set_iface_address(connman_peer,
				g_supplicant_peer_get_iface_address(peer));

		if (p2p_go_identifier) {
			GSupplicantP2PPersistentGroup *persistent_group;
			GSupplicantGroup *group;
			struct connman_network *network;
			char *ipaddress = g_supplicant_peer_get_ip_address(peer);

			const char *identifier = connman_peer_get_identifier(connman_peer);

			network = connman_device_get_network(wifi->device, identifier);

			connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_ASSOCIATION);
			connman_peer_set_as_go(connman_peer, false);
			connman_group = __connman_group_lookup_from_ident(p2p_go_identifier);
			group = g_supplicant_get_group(__connman_group_get_group_owner(connman_group));

			if (connman_group->autonomous)
				__connman_peer_set_autonomous_group(connman_peer, true);

			if (group) {
				persistent_group = g_supplicant_interface_get_p2p_persistent_group(iface, group);
				if(persistent_group != NULL) {
					persistent_group->go = TRUE;
					p2p_persistent_info_save(identifier, persistent_group);
				}
			}

			if (ipaddress != NULL){
				connman_group->is_static_ip = true;
				connman_group->peer_ip = g_strdup(ipaddress);
				//p_state = CONNMAN_PEER_STATE_CONFIGURATION;

				__connman_peer_set_static_ip(connman_peer, ipaddress);
			}
			p_state = CONNMAN_PEER_STATE_CONFIGURATION;
//			if (network)
//				wfds_on_p2p_peer_joined(network, group);

//			if (network && connman_group->is_static_ip)
//				wfds_on_p2p_group_peer_static_ip_added(network, connman_group->peer_ip);

			__connman_group_peer_joined(connman_group, identifier,
					g_supplicant_peer_get_iface_address(peer), __connman_peer_get_path(connman_peer));
		} else {
			connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_ASSOCIATION);
			connman_peer_set_as_go(connman_peer, true);

			p_state = CONNMAN_PEER_STATE_CONFIGURATION;
		}
		break;
	case G_SUPPLICANT_PEER_GROUP_DISCONNECTED:
		if (p2p_go_identifier) {
			connman_group = __connman_group_lookup_from_ident(p2p_go_identifier);
			if (__connman_group_peer_disconnected(connman_group, identifier)) {
				peer_cancel_timeout(wifi);
				wifi->p2p_device = false;
				__connman_peer_set_static_ip(connman_peer, NULL);
			}
		}
		p_state = CONNMAN_PEER_STATE_IDLE;
		break;
	case G_SUPPLICANT_PEER_GROUP_FAILED:
		if (g_supplicant_peer_has_requested_connection(peer))
			p_state = CONNMAN_PEER_STATE_IDLE;
		else
			p_state = CONNMAN_PEER_STATE_FAILURE;

		p2p_go_neg_failed(iface, connman_peer,  g_supplicant_peer_get_failure_status(peer));
		break;
	}

	if (p_state == CONNMAN_PEER_STATE_CONFIGURATION ||
					p_state == CONNMAN_PEER_STATE_FAILURE) {
		if (wifi->p2p_connecting
				&& connman_peer == wifi->pending_peer)
			peer_cancel_timeout(wifi);
		else
			p_state = CONNMAN_PEER_STATE_UNKNOWN;
	}

	if (p_state == CONNMAN_PEER_STATE_UNKNOWN)
		return;

	if (p_state == CONNMAN_PEER_STATE_CONFIGURATION) {
		GSupplicantInterface *g_iface;
		struct wifi_data *g_wifi;
		bool is_client = false;

		g_iface = g_supplicant_peer_get_group_interface(peer);
		if (!g_iface)
			return;

		g_wifi = g_supplicant_interface_get_data(g_iface);
		if (!g_wifi)
			return;

		is_client = g_supplicant_peer_is_client(peer);
		connman_peer_set_as_master(connman_peer, !is_client);

		if (!is_client)
			connman_peer_dhcpclient_cb(connman_peer, peer_dhcp_address_update);
		else
			connman_peer_dhcpclient_cb(connman_peer, NULL);

		connman_peer_set_sub_device(connman_peer, g_wifi->device);

		/*
		 * If wpa_supplicant didn't create a dedicated p2p-group
		 * interface then mark this interface as p2p_device to avoid
		 * scan and auto-scan are launched on it while P2P is connected.
		 */
		if (!g_list_find(p2p_iface_list, g_wifi))
			wifi->p2p_device = true;
	}

	connman_peer_set_state(connman_peer, p_state);
}

static void peer_request(GSupplicantPeer *peer, int dev_passwd_id)
{
	GSupplicantInterface *iface = g_supplicant_peer_get_interface(peer);
	struct wifi_data *wifi = g_supplicant_interface_get_data(iface);
	struct connman_network *connman_network;
	struct connman_peer *connman_peer;
	const char *identifier, *name, *path;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	name = g_supplicant_peer_get_name(peer);
	path = g_supplicant_peer_get_path(peer);
      connman_network = connman_device_get_network(wifi->device, identifier);

      if (connman_network == NULL) {
		DBG("creating new network");
		connman_network = connman_network_create(identifier, CONNMAN_NETWORK_TYPE_WIFI);
		if (connman_network == NULL)
			return;

		connman_network_set_index(connman_network, wifi->index);

             connman_network_set_name(connman_network, name);
		connman_network_set_string(connman_network, "Path", path);

	      if (connman_device_add_network(wifi->device, connman_network) < 0) {
			connman_network_unref(connman_network);
			return;
		}

		wifi->networks = g_slist_prepend(wifi->networks, connman_network);
	}  else	{
		DBG("network already exists, just update it");

	      connman_network_set_name(connman_network, name);

		__connman_service_update_from_network(connman_network);
	}

//	wfds_on_go_neg_requested(connman_network, dev_passwd_id);

	connman_peer_request_connection(connman_peer, dev_passwd_id);
}

static void debug(const char *str)
{
	if (getenv("CONNMAN_SUPPLICANT_DEBUG"))
		connman_debug("%s", str);
}

static void disconnect_reasoncode(GSupplicantInterface *interface,
				int reasoncode)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	if (wifi != NULL) {
		wifi->disconnect_code = reasoncode;
	}
}

static void assoc_status_code(GSupplicantInterface *interface, int status_code)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);

	if (wifi != NULL) {
		wifi->assoc_code = status_code;
	}
}

static void p2p_group_started(GSupplicantGroup *group)
{
	struct wifi_data *wifi;
	GSList *item;
	GSupplicantP2PPersistentGroup *persistent_group;
	struct connman_group *connman_group = NULL;
	struct connman_peer *connman_peer_go = NULL;
	const char* go_path = NULL;

	GSupplicantInterface *iface = g_supplicant_group_get_orig_interface(group);

	wifi = g_supplicant_interface_get_data(iface);

	if (!wifi)
		return;

	const char* bssid_no_colon = g_supplicant_group_get_bssid_no_colon(group);
	const char *ssid = g_supplicant_group_get_ssid(group);
	const char *passphrase = g_supplicant_group_get_passphrase(group);

	struct connman_peer *peer = connman_peer_get(wifi->device, bssid_no_colon);
	if (peer)
		go_path = __connman_peer_get_path(peer);
	else
		go_path = g_supplicant_group_get_object_path(group);

	/* persistent check */
	item = wifi->persistent_groups;
	while(item != NULL) {
		persistent_group = item->data;

		if (persistent_group->ssid == NULL || persistent_group->bssid_no_colon == NULL ||  bssid_no_colon == NULL) {
			item = g_slist_next(item);
			continue;
		}

		if(g_str_equal(persistent_group->bssid_no_colon, bssid_no_colon)){
			if (!g_str_equal(persistent_group->ssid, ssid) || !g_str_equal(persistent_group->psk, passphrase)){
				if (persistent_group->ssid)
					g_free(persistent_group->ssid);
				persistent_group->ssid = g_strdup(ssid);

				if (passphrase && strcmp(passphrase, "") && persistent_group->psk) {
					g_free(persistent_group->psk);
					persistent_group->psk = g_strdup(passphrase);
				}
			}
			g_supplicant_interface_set_p2p_persistent_group(iface, group, persistent_group);
			break;
		}

		item = g_slist_next(item);
	}
	bool is_group_owner = false;
	if (g_supplicant_group_get_role(group) == G_SUPPLICANT_GROUP_ROLE_GO) {
		is_group_owner = true;

		__connman_p2p_go_set_bridge(p2p_group_ifname);

		//If autonomous group then only start the DHCP server
		if (create_group_flag)
			__connman_p2p_go_set_enabled();
	}

	int freq = g_supplicant_group_get_frequency(group);
	bool persistent = g_supplicant_group_get_persistent(group);

	connman_group = __connman_group_create(iface, p2p_group_ifname, ssid, passphrase,
					is_group_owner, persistent, go_path, create_group_flag, freq);

	const char *connman_group_path = __connman_group_get_path(connman_group);

	if (is_group_owner) {
		p2p_go_identifier = g_strdup(__connman_group_get_identifier(connman_group));
	} else {
		persistent_group = g_supplicant_interface_get_p2p_persistent_group(iface, group);
		if(persistent_group != NULL) {
			persistent_group->go = FALSE;
			p2p_persistent_info_save(persistent_group->bssid_no_colon, persistent_group);
		}
		char *ip_addr = g_supplicant_group_get_ip_addr(group);
		char *ip_mask = g_supplicant_group_get_ip_mask(group);
		char *go_ip_addr = g_supplicant_group_get_go_ip_addr(group);

		if (ip_addr) {
			__connman_peer_set_static_ip(peer, go_ip_addr);
			if (connman_peer_set_ipaddress(peer, ip_addr, ip_mask, go_ip_addr) < 0)
				connman_warn("Setting static IP for Peer failed");
		}

		GSupplicantPeer *supplicant_peer = g_supplicant_interface_peer_lookup(iface, bssid_no_colon);
		if (supplicant_peer) {
			peer_changed(supplicant_peer, G_SUPPLICANT_PEER_GROUP_JOINED);
		}
	}

	if (is_group_owner && create_group_flag) {
		g_dbus_send_reply(connection, group_msg,
						DBUS_TYPE_OBJECT_PATH, &connman_group_path,
						DBUS_TYPE_INVALID);

		create_group_flag = FALSE;
		dbus_message_unref(group_msg);
	}
}

static void p2p_find_group_stop(struct wifi_data *wifi)
{
	if (wifi) {
		wifi->p2p_find_timeout = 0;
		g_supplicant_interface_p2p_stop_find(wifi->interface);
	}
}

static void p2p_group_finished(GSupplicantInterface *interface)
{
	GList *list;
	struct wifi_data *wifi;
	GSupplicantInterface *not_group_interface;

	DBG("");

	if (p2p_go_identifier) {
		struct connman_group *connman_group = __connman_group_lookup_from_ident(p2p_go_identifier);
		if (connman_group->autonomous)
			__connman_p2p_go_set_disabled();

		g_free(p2p_go_identifier);
		p2p_go_identifier = NULL;
	}

	__connman_group_remove(interface);

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;
		not_group_interface = wifi->interface;

		if (!not_group_interface ||
			!g_supplicant_interface_has_p2p(wifi->interface))
			continue;

		p2p_find_group_stop(wifi);
		if (wifi->p2p_listen_suppressed == true ||
				connman_technology_get_p2p_listen(p2p_technology)) {
			leave_p2p_listen_on_iface(wifi);
			p2p_peers_refresh(wifi);
			if (wifi->p2p_listen_suppressed == true)
				wifi->p2p_listen_suppressed = false;
		}
	}

	if (p2p_group_ifname) {
		g_free(p2p_group_ifname);
		p2p_group_ifname = NULL;
	}
}
static gboolean p2p_pbc_requested(gpointer argv)
{
	pbc_requested_ref = -1;

	return FALSE;
}

static void p2p_invitation_result(GSupplicantInterface *interface, int status)
{
	struct wifi_data *wifi;

	wifi = g_supplicant_interface_get_data(interface);

	if (!wifi)
		return;

	DBG("status %i", status);

	__connman_technology_p2p_invitation_result(p2p_technology, status);
}

static void p2p_invitation_received(GSupplicantInterface *interface,
				GSupplicantPeer *peer, const char *go_dev_addr, bool persistent)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	struct connman_peer *connman_peer;
	const char *identifier, *path;
	const char *go_dev_addr_colon;

	if (!wifi || !wifi->device)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	go_dev_addr_colon = __connman_util_insert_colon_to_mac_addr(go_dev_addr);
	path = __connman_peer_get_path(connman_peer);

	if (!path) {
		g_free(go_dev_addr_colon);
		return;
	}

	if (!persistent) {
		connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_IDLE);

		/* Invitation received from GO */
		if (g_str_equal(identifier, go_dev_addr)) {
			wifi->invited_path = __connman_peer_get_path(connman_peer);
		/* Sometimes there is only src address in InvitationReceived signal without GO device address */
		} else if (g_str_equal(go_dev_addr, "000000000000")) {
			wifi->invited_path = __connman_peer_get_path(connman_peer);
			g_free(go_dev_addr_colon);
			go_dev_addr_colon = __connman_util_insert_colon_to_mac_addr(identifier);
		} else {
			struct connman_network *network_go = connman_device_get_network(wifi->device, go_dev_addr);

			if (network_go) {
				struct connman_service *service_go;

				wifi->invited_path = connman_network_get_string(network_go, "Path");
			}
		}

		connman_peer_invitation_request(path, "P2PInvitationReceived", go_dev_addr_colon);

	} else {
		p2p_find_stop(wifi->device);
		if (connman_technology_get_p2p_listen(p2p_technology) == true &&
			connman_peer_get_state(connman_peer) == CONNMAN_PEER_STATE_READY) {//already changed to listen off
			leave_p2p_listen_on_iface(wifi);
			connman_technology_set_p2p_listen(p2p_technology, false);
		}

		connman_peer_invitation_request(path, "P2PPersistentReceived", go_dev_addr_colon);
	}
}

static void p2p_prov_disc_requested_pbc(GSupplicantInterface *interface,
					GSupplicantPeer *peer)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	struct connman_peer *connman_peer;
	const char *identifier, *path;
	const char *sig = "pbc";

	if (!wifi || !wifi->device)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	/** Throttle pbc requested messages */
	if (pbc_requested_ref != -1) {
		g_source_remove(pbc_requested_ref);
		pbc_requested_ref = g_timeout_add_seconds(2, p2p_pbc_requested, NULL);
		return;
	}

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;
	if (connman_peer_get_state(connman_peer) != CONNMAN_PEER_STATE_ASSOCIATION)
	{
	connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_IDLE);
	connman_peer_set_as_master(connman_peer, false);
	}
	path = __connman_peer_get_path(connman_peer);

	if (path && p2p_go_identifier) {
		connman_dbus_property_changed_basic(path,
					CONNMAN_PEER_INTERFACE,
					"P2PProvDiscRequestedPBC",
					DBUS_TYPE_STRING, &sig);

		pbc_requested_ref = g_timeout_add_seconds(2, p2p_pbc_requested, NULL);
	}
}

static void p2p_prov_disc_requested_enter_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	struct connman_peer *connman_peer;
	struct connman_network *connman_network;
	const char *identifier, *path;
	const char *sig = "keypad";

	if (!wifi || !wifi->device)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

//	wfds_on_p2p_pin_requested(connman_network, NULL);

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_IDLE);
	connman_peer_set_as_master(connman_peer, false);

	path = __connman_peer_get_path(connman_peer);

	if (p2p_go_identifier) {
		connman_dbus_property_changed_basic(path,
					CONNMAN_PEER_INTERFACE,
					"P2PProvDiscRequestedEnterPin",
					DBUS_TYPE_STRING, &sig);
	}
}

static gboolean p2p_pin_requested(gpointer argv)
{
	pin_requested_ref = -1;

	return FALSE;
}

static void p2p_prov_disc_requested_display_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, const char *pin)
{
	struct wifi_data *wifi = g_supplicant_interface_get_data(interface);
	struct connman_peer *connman_peer;
	struct connman_network *connman_network;
	const char *identifier, *path;
	const char *sig = "keypad";

	if (!wifi || !wifi->device)
		return;

	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("ident: %s", identifier);

	/** Throttle pin requested messages */
	if (pin_requested_ref != -1) {
		g_source_remove(pin_requested_ref);
		pin_requested_ref = g_timeout_add_seconds(2, p2p_pin_requested, NULL);
		return;
	}

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

	connman_peer = connman_peer_get(wifi->device, identifier);
	if (!connman_peer)
		return;

	connman_peer_set_state(connman_peer, CONNMAN_PEER_STATE_IDLE);
	connman_peer_set_as_master(connman_peer, false);
	path = __connman_peer_get_path(connman_peer);

	wifi->generated_pin = pin;
	wifi->pin_requested_path = connman_network_get_string(connman_network, "Path");

//	wfds_on_p2p_pin_requested(connman_network, pin);

	if (p2p_go_identifier || __connman_group_exist() == FALSE) {
		connman_dbus_property_changed_basic(path,
					CONNMAN_PEER_INTERFACE,
					"P2PProvDiscRequestedDisplayPin",
					DBUS_TYPE_STRING, &pin);

		pin_requested_ref = g_timeout_add_seconds(2, p2p_pin_requested, NULL);
	}
}

static void p2p_prov_disc_response_enter_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer)
{
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

//	wfds_on_p2p_pin_response(connman_network, NULL);
}

static void p2p_prov_disc_response_display_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, const char *pin)
{
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

//	wfds_on_p2p_pin_response(connman_network, pin);
}

static void p2p_prov_disc_fail(GSupplicantInterface *interface,
					GSupplicantPeer *peer, int status)
{
	struct wifi_data *wifi;
	const char *identifier;
	struct connman_network *connman_network;

	wifi = g_supplicant_interface_get_data(interface);
	identifier = g_supplicant_peer_get_identifier(peer);

	DBG("identifier %s", identifier);

	connman_network = connman_device_get_network(wifi->device, identifier);
	if (!connman_network)
		return;

//	wfds_on_p2p_prov_failed(connman_network, status);
}

static const GSupplicantCallbacks callbacks = {
	.system_ready		= system_ready,
	.system_killed		= system_killed,
	.interface_added	= interface_added,
	.interface_state	= interface_state,
	.interface_removed	= interface_removed,
	.p2p_support		= p2p_support,
	.p2p_device_config_loaded = p2p_device_config_loaded,
	.scan_started		= scan_started,
	.scan_finished		= scan_finished,
	.ap_create_fail		= ap_create_fail,
	.network_added		= network_added,
	.network_removed	= network_removed,
	.network_changed	= network_changed,
	.network_associated	= network_associated,
	.station_added          = station_added,
	.station_removed        = station_removed,
	.sta_authorized		= sta_authorized,
	.sta_deauthorized	= sta_deauthorized,
	.peer_found		= peer_found,
	.peer_lost		= peer_lost,
	.peer_changed		= peer_changed,
	.peer_request		= peer_request,
	.p2p_sd_response = p2p_sd_response,
	.p2p_sd_asp_response = p2p_sd_asp_response,
	.wps_state		= wps_state,
	.debug			= debug,
	.disconnect_reasoncode  = disconnect_reasoncode,
	.assoc_status_code      = assoc_status_code,
	.p2p_group_started		= p2p_group_started,
	.p2p_group_finished		= p2p_group_finished,
	.p2ps_prov_start = p2ps_prov_start,
	.p2ps_prov_done = p2ps_prov_done,
	.p2p_persistent_group_added = p2p_persistent_group_added,
	.p2p_persistent_group_removed = p2p_persistent_group_removed,
	.p2p_prov_disc_requested_pbc = p2p_prov_disc_requested_pbc,
	.p2p_prov_disc_requested_enter_pin = p2p_prov_disc_requested_enter_pin,
	.p2p_prov_disc_requested_display_pin = p2p_prov_disc_requested_display_pin,
	.p2p_prov_disc_response_enter_pin = p2p_prov_disc_response_enter_pin,
	.p2p_prov_disc_response_display_pin = p2p_prov_disc_response_display_pin,
	.p2p_prov_disc_fail = p2p_prov_disc_fail,

	.p2p_invitation_result = p2p_invitation_result,
	.p2p_invitation_received = p2p_invitation_received,
};


static int tech_probe(struct connman_technology *technology)
{
	wifi_technology = technology;

	return 0;
}

static void tech_remove(struct connman_technology *technology)
{
	wifi_technology = NULL;
}

static GSupplicantSSID *ssid_ap_init(const char *ssid, const char *passphrase)
{
    struct connman_technology *technology;
	GSupplicantSSID *ap;
	int freq;
	bool ret;

	ap = g_try_malloc0(sizeof(GSupplicantSSID));
	if (!ap)
		return NULL;

	ret = connman_technology_get_wifi_tethering(technology,
						&ssid, &passphrase,
						&freq);
	if (ret == false)
		return NULL;

	ap->mode = G_SUPPLICANT_MODE_MASTER;
	ap->ssid = ssid;
	ap->ssid_len = strlen(ssid);
	ap->scan_ssid = 0;
	if (freq)
		ap->freq = freq;
	else
		ap->freq = 2412;

	if (!passphrase || strlen(passphrase) == 0) {
		ap->security = G_SUPPLICANT_SECURITY_NONE;
		ap->passphrase = NULL;
	} else {
	       ap->security = G_SUPPLICANT_SECURITY_PSK;
	       ap->protocol = G_SUPPLICANT_PROTO_RSN;
	       ap->pairwise_cipher = G_SUPPLICANT_PAIRWISE_CCMP;
	       ap->group_cipher = G_SUPPLICANT_GROUP_CCMP;
	       ap->passphrase = passphrase;
	}

	return ap;
}

static void ap_start_callback(int result, GSupplicantInterface *interface,
							void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d index %d bridge %s",
		result, info->wifi->index, info->wifi->bridge);

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			connman_technology_tethering_notify(info->technology, false);
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;
		}
	}

	g_free(info->ifname);
	g_free(info);
}

static void ap_create_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;

	DBG("result %d ifname %s", result,
				g_supplicant_interface_get_ifname(interface));

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		connman_inet_remove_from_bridge(info->wifi->index,
							info->wifi->bridge);

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			connman_technology_tethering_notify(info->technology, false);
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;

		}

		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
		return;
	}

	info->wifi->interface = interface;
	g_supplicant_interface_set_data(interface, info->wifi);

	if (g_supplicant_interface_set_apscan(interface, 2) < 0)
		connman_error("Failed to set interface ap_scan property");

	g_supplicant_interface_connect(interface, info->ssid,
						ap_start_callback, info);
}

static void sta_remove_callback(int result,
				GSupplicantInterface *interface,
					void *user_data)
{
	struct wifi_tethering_info *info = user_data;
	const char *driver = connman_setting_get_string("wifi");

	DBG("ifname %s result %d ", info->ifname, result);

	if ((result < 0) || (info->wifi->ap_supported != WIFI_AP_SUPPORTED)) {
		info->wifi->tethering = false;
		connman_technology_tethering_notify(info->technology, false);

		if (info->wifi->ap_supported == WIFI_AP_SUPPORTED) {
			g_free(info->wifi->tethering_param->ssid);
			g_free(info->wifi->tethering_param);
			info->wifi->tethering_param = NULL;
		}

		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
		return;
	}

	info->wifi->interface = NULL;

	g_supplicant_interface_create(info->ifname, driver, info->wifi->bridge, NULL,
						ap_create_callback,
							info);
}

static int enable_wifi_tethering(struct connman_technology *technology,
				const char *bridge, const char *identifier,
				const char *passphrase, bool available)
{
	GList *list;
	GSupplicantInterface *interface;
	struct wifi_data *wifi;
	struct wifi_tethering_info *info;
	const char *ifname;
	unsigned int mode;
	int err, berr = 0;

	for (list = iface_list; list; list = list->next) {
		wifi = list->data;

		DBG("wifi %p network %p pending_network %p", wifi,
			wifi->network, wifi->pending_network);

		interface = wifi->interface;

		if (!interface)
			continue;

		ifname = g_supplicant_interface_get_ifname(wifi->interface);
		if (!ifname)
			continue;

		if (wifi->ap_supported == WIFI_AP_NOT_SUPPORTED) {
			DBG("%s does not support AP mode (detected)", ifname);
			continue;
		}

		mode = g_supplicant_interface_get_mode(interface);
		if ((mode & G_SUPPLICANT_CAPABILITY_MODE_AP) == 0) {
			wifi->ap_supported = WIFI_AP_NOT_SUPPORTED;
			DBG("%s does not support AP mode (capability)", ifname);
			continue;
		}

		if (wifi->network && available)
			continue;

		info = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (!info)
			return -ENOMEM;

		wifi->tethering_param = g_try_malloc0(sizeof(struct wifi_tethering_info));
		if (!wifi->tethering_param) {
			g_free(info);
			return -ENOMEM;
		}

		info->wifi = wifi;
		info->technology = technology;
		info->wifi->bridge = bridge;
		info->ssid = ssid_ap_init(identifier, passphrase);
		if (!info->ssid)
			goto failed;

		info->ifname = g_strdup(ifname);

		wifi->tethering_param->technology = technology;
		wifi->tethering_param->ssid = ssid_ap_init(identifier, passphrase);
		if (!wifi->tethering_param->ssid)
			goto failed;

		info->wifi->tethering = true;
		info->wifi->ap_supported = WIFI_AP_SUPPORTED;

		berr = connman_technology_tethering_notify(technology, true);
		if (berr < 0)
			goto failed;

		err = g_supplicant_interface_remove(interface,
						sta_remove_callback,
							info);
		if (err >= 0) {
			DBG("tethering wifi %p ifname %s", wifi, ifname);
			return 0;
		}

	failed:
		g_free(info->ifname);
		g_free(info->ssid);
		g_free(info);
		g_free(wifi->tethering_param);
		wifi->tethering_param = NULL;

		/*
		 * Remove bridge if it was correctly created but remove
		 * operation failed. Instead, if bridge creation failed then
		 * break out and do not try again on another interface,
		 * bridge set-up does not depend on it.
		 */
		if (berr == 0)
			connman_technology_tethering_notify(technology, false);
		else
			break;
	}

	return -EOPNOTSUPP;
}

static int tech_set_tethering(struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled)
{
	GList *list;
	struct wifi_data *wifi;
	int err;

	DBG("");

	if (!enabled) {
		for (list = iface_list; list; list = list->next) {
			wifi = list->data;

			if (wifi->tethering) {
				wifi->tethering = false;

				connman_inet_remove_from_bridge(wifi->index,
									bridge);
				wifi->bridged = false;
			}
		}

		connman_technology_tethering_notify(technology, false);

		return 0;
	}

	DBG("trying tethering for available devices");
	err = enable_wifi_tethering(technology, bridge, identifier, passphrase,
				true);

	if (err < 0) {
		DBG("trying tethering for any device");
		err = enable_wifi_tethering(technology, bridge, identifier,
					passphrase, false);
	}

	return err;
}

static void regdom_callback(int result, const char *alpha2, void *user_data)
{
	DBG("");

	if (!wifi_technology)
		return;

	if (result != 0)
		alpha2 = NULL;

	connman_technology_regdom_notify(wifi_technology, alpha2);
}

static int tech_set_regdom(struct connman_technology *technology, const char *alpha2)
{
	return g_supplicant_set_country(alpha2, regdom_callback, NULL);
}

static void tech_add_interface(struct connman_technology *technology,
			int index, const char *name, const char *ident)
{
	DBG("index %d name %s ident %s", index, name, ident);

	if(p2p_group_if_prefix && g_str_has_prefix(name, p2p_group_if_prefix)) {
		if (p2p_group_ifname) {
			g_free(p2p_group_ifname);
			p2p_group_ifname = NULL;
		}
		p2p_group_ifname = g_strdup(name);
		p2p_group_ifindex = index;
	}
}

static struct connman_technology_driver tech_driver = {
	.name		= "wifi",
	.type		= CONNMAN_SERVICE_TYPE_WIFI,
	.probe		= tech_probe,
	.remove		= tech_remove,
	.set_tethering	= tech_set_tethering,
	.set_regdom	= tech_set_regdom,
	.add_interface = tech_add_interface,
};

static int wifi_init(void)
{
	int err;

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		return err;

	err = g_supplicant_register(&callbacks);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		g_supplicant_unregister(&callbacks);
		connman_network_driver_unregister(&network_driver);
		return err;
	}

	return 0;
}




static enum connman_peer_wps_method p2psconnect_mode_to_wpa_method(int mode){

 /*
  always be in sync with p2p_connect_mode
		typedef enum _p2p_connect_mode {
			P2P_CONNECT_DISPLAY = 1,
			P2P_CONNECT_KEYPAD = 5,
			P2P_CONNECT_P2PS = 8
		} p2p_connect_mode;

 */
   enum  connman_peer_wps_method wps_method=CONNMAN_PEER_WPS_UNKNOWN;

	switch(mode){
       case 1:
                wps_method=CONNMAN_PEER_WPS_DISPLAY;
		break;
	case 5:
                 wps_method=CONNMAN_PEER_WPS_KEYBOARD;
		break;
	case 8:
                 wps_method=CONNMAN_PEER_WPS_P2PS;
		break;

	}
	return wps_method;

}



/** WFDS calls into wifi.c */
int wfds_p2p_wifi_connect(struct connman_network* network, int mode, const char* pin, gboolean persistent)
{
	struct connman_peer *connman_peer;
	connman_peer = connman_peer_get(connman_network_get_device(network), connman_network_get_identifier(network));

	return  peer_connect(connman_peer, p2psconnect_mode_to_wpa_method(mode), pin);

}

int wfds_p2p_wifi_disconnect(struct connman_network* network, GSupplicantP2PGroup* group)
{
	g_supplicant_interface_p2p_group_disconnect(group->group_interface, NULL, NULL);

	return 0;
}

int wfds_p2p_wifi_extended_listen(gboolean enabled)
{
	if (enabled)
	{
		tech_set_p2p_listen_params(wifi_technology, 450, 500);
	}

	int err = tech_set_p2p_listen(wifi_technology, enabled);

	if (err == -EINPROGRESS)
		err = 0;

	return err;
}

static void wifi_exit(void)
{
	DBG();

	connman_technology_driver_unregister(&tech_driver);

	g_supplicant_unregister(&callbacks);

	connman_network_driver_unregister(&network_driver);
}

CONNMAN_PLUGIN_DEFINE(wifi, "WiFi interface plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, wifi_init, wifi_exit)
