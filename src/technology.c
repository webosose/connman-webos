/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
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
#include <string.h>

#include <gdbus.h>

#include "connman.h"

static DBusConnection *connection;

static GSList *technology_list = NULL;

/*
 * List of devices with no technology associated with them either because of
 * no compiled in support or the driver is not yet loaded.
*/
static GSList *techless_device_list = NULL;
static GHashTable *rfkill_list;

static bool global_offlinemode;

struct connman_rfkill {
	unsigned int index;
	enum connman_service_type type;
	bool softblock;
	bool hardblock;
};

struct connman_technology {
	int refcount;
	enum connman_service_type type;
	char *path;
	GSList *device_list;
	bool enabled;
	char *regdom;
	bool connected;

	bool tethering;
	bool tethering_persistent; /* Tells the save status, needed
					      * as offline mode might set
					      * tethering OFF.
					      */
	char *tethering_ident;
	char *tethering_passphrase;
	int tethering_freq;
	char *tethering_ipaddress;
	unsigned int tethering_channel;

	int period;
	int interval;
	bool enable_p2p_listen_persistent;	/* Save the tech p2p listen state by p2p/setstate API */
	bool p2p_listen;
	unsigned int p2p_listen_channel;

	char *p2p_identifier;
	bool p2p_persistent;
	bool enable_persistent; /* Save the tech state */

	GSList *driver_list;

	DBusMessage *pending_reply;
	guint pending_timeout;

	GSList *scan_pending;
	GSList *iface_prop_pending;

	bool rfkill_driven;
	bool softblocked;
	bool hardblocked;
	bool dbus_registered;
};

static GSList *driver_list = NULL;

static int technology_enabled(struct connman_technology *technology);
static int technology_disabled(struct connman_technology *technology);
static int set_p2p_enable(struct connman_technology *technology, bool status);

static gint compare_priority(gconstpointer a, gconstpointer b)
{
	const struct connman_technology_driver *driver1 = a;
	const struct connman_technology_driver *driver2 = b;

	return driver2->priority - driver1->priority;
}

static void rfkill_check(gpointer key, gpointer value, gpointer user_data)
{
	struct connman_rfkill *rfkill = value;
	enum connman_service_type type = GPOINTER_TO_INT(user_data);

	/* Calling _technology_add_rfkill will update the tech. */
	if (rfkill->type == type)
		__connman_technology_add_rfkill(rfkill->index, type,
				rfkill->softblock, rfkill->hardblock);
}

bool
connman_technology_is_tethering_allowed(enum connman_service_type type)
{
	static char *allowed_default[] = { "wifi", "bluetooth", "gadget",
					   NULL };
	const char *type_str = __connman_service_type2string(type);
	char **allowed;
	int i;

	if (!type_str)
		return false;

	allowed = connman_setting_get_string_list("TetheringTechnologies");
	if (!allowed)
		allowed = allowed_default;

	for (i = 0; allowed[i]; i++) {
		if (g_strcmp0(allowed[i], type_str) == 0)
			return true;
	}

	return false;
}

static const char *get_name(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
		break;
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "Gadget";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "Wired";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "WiFi";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "Bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "Cellular";
	case CONNMAN_SERVICE_TYPE_P2P:
		return "P2P";
	}

	return NULL;
}

static void technology_save(struct connman_technology *technology)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	gchar *identifier;
	const char *name = get_name(technology->type);

	DBG("technology %p type %d name %s", technology, technology->type,
									name);

	if (!name || (technology->type == CONNMAN_SERVICE_TYPE_P2P))
		return;

	keyfile = __connman_storage_load_global();
	if (!keyfile)
		keyfile = g_key_file_new();

	identifier = g_strdup_printf("%s", name);
	if (!identifier)
		goto done;

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
			g_key_file_set_boolean(keyfile, "WiFi", "P2PListen",
						technology->enable_p2p_listen_persistent);
		goto done;
	}

	// Update only if a WiFi Enable key is present and new value is ture
	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI) {
		g_key_file_get_boolean(keyfile, identifier, "Enable", &error);
		if (error == NULL) {
			g_key_file_set_boolean(keyfile, identifier, "Enable",
						technology->enable_persistent);
		} else if (error && technology->enable_persistent) {
			g_key_file_set_boolean(keyfile, identifier, "Enable",
						technology->enable_persistent);
			g_clear_error(&error);
		}
	} else {
		g_key_file_set_boolean(keyfile, identifier, "Enable",
					technology->enable_persistent);
	}

	g_key_file_set_boolean(keyfile, identifier, "Tethering",
				technology->tethering_persistent);

	if (technology->tethering_ident)
		g_key_file_set_string(keyfile, identifier,
					"Tethering.Identifier",
					technology->tethering_ident);

	if (technology->tethering_passphrase) {
		char *enc = g_strescape(technology->tethering_passphrase, NULL);
		g_key_file_set_string(keyfile, identifier,
					"Tethering.Passphrase", enc);
		g_free(enc);
	}

	if (technology->tethering_channel)
		g_key_file_set_integer(keyfile, identifier,
					"Tethering.Channel",
					technology->tethering_channel);

	if (technology->tethering_ipaddress)
		g_key_file_set_string(keyfile, identifier,
					"Tethering.IP",
					technology->tethering_ipaddress);

done:
	g_free(identifier);

	__connman_storage_save_global(keyfile);

	g_key_file_free(keyfile);
}

static void tethering_changed(struct connman_technology *technology)
{
	dbus_bool_t tethering = technology->tethering;

	connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE, "Tethering",
						DBUS_TYPE_BOOLEAN, &tethering);

	technology_save(technology);
}

int connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled)
{
	int err;
	const char *ip;

	DBG("technology %p enabled %u", technology, enabled);

	if (technology->tethering == enabled)
		return -EALREADY;

	ip = technology->tethering_ipaddress;

	if (enabled) {
		if (!ip || strlen(ip) == 0)
			err = __connman_tethering_set_enabled();
		else
			err = __connman_tethering_set_enabled_with_ip(ip);

		if (err < 0)
			return err;
	} else
		__connman_tethering_set_disabled();

	technology->tethering = enabled;
	tethering_changed(technology);

	return 0;
}

static int set_tethering(struct connman_technology *technology,
				bool enabled)
{
	int result = -EOPNOTSUPP;
	int err;
	const char *ident, *passphrase, *bridge;
	GSList *tech_drivers;

	ident = technology->tethering_ident;
	passphrase = technology->tethering_passphrase;

	__sync_synchronize();
	if (!technology->enabled)
		return -EACCES;

	bridge = __connman_tethering_get_bridge();
	if (!bridge)
		return -EOPNOTSUPP;

	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI && !ident)
		return -EINVAL;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_tethering)
			continue;

		err = driver->set_tethering(technology, ident, passphrase,
				bridge, enabled);

		if (result == -EINPROGRESS)
			continue;

		if (err == -EINPROGRESS || err == 0)
			result = err;
	}

	return result;
}

void connman_technology_regdom_notify(struct connman_technology *technology,
							const char *alpha2)
{
	DBG("");

	if (!alpha2)
		connman_error("Failed to set regulatory domain");
	else
		DBG("Regulatory domain set to %s", alpha2);

	g_free(technology->regdom);
	technology->regdom = g_strdup(alpha2);
}

static int set_regdom_by_device(struct connman_technology *technology,
							const char *alpha2)
{
	GSList *list;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_set_regdom(device, alpha2) != 0)
			return -ENOTSUP;
	}

	return 0;
}

int connman_technology_set_regdom(const char *alpha2)
{
	GSList *list, *tech_drivers;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (set_regdom_by_device(technology, alpha2) != 0) {

			for (tech_drivers = technology->driver_list;
			     tech_drivers;
			     tech_drivers = g_slist_next(tech_drivers)) {

				struct connman_technology_driver *driver =
					tech_drivers->data;

				if (driver->set_regdom)
					driver->set_regdom(technology, alpha2);
			}
		}
	}

	return 0;
}

static struct connman_technology *technology_find(enum connman_service_type type)
{
	GSList *list;

	DBG("type %d", type);

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (technology->type == type)
			return technology;
	}

	return NULL;
}

enum connman_service_type connman_technology_get_type
				(struct connman_technology *technology)
{
	if (!technology)
		return CONNMAN_SERVICE_TYPE_UNKNOWN;

	return technology->type;
}

bool connman_technology_get_wifi_tethering(const char **ssid,
							const char **psk)
{
	bool force = true;

    struct connman_technology *technology;
	if (!ssid || !psk)
		return false;

	*ssid = *psk = NULL;

	/* Workaround for the neard plugin */
	if (!technology) {
		technology = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
		force = false;
	}

	if (!technology)
		return false;

	if (!force && !technology->tethering)
		return false;

	*ssid = technology->tethering_ident;
	*psk = technology->tethering_passphrase;
	//*freq = technology->tethering_freq;

	return true;
}

unsigned int connman_technology_get_wifi_tethering_channel(void)
{
	struct connman_technology *technology;

	technology = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
	if (!technology)
		return 0;

	return technology->tethering_channel;
}

static void free_rfkill(gpointer data)
{
	struct connman_rfkill *rfkill = data;

	g_free(rfkill);
}

static void technology_load(struct connman_technology *technology)
{
	GKeyFile *keyfile;
	gchar *identifier;
	GError *error = NULL;
	bool enable, need_saving = false;
	char *enc;

	DBG("technology %p", technology);

	keyfile = __connman_storage_load_global();
	/* Fallback on disabling technology if file not found. */
	if (!keyfile) {
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET || technology->type == CONNMAN_SERVICE_TYPE_WIFI)
			/* We enable ethernet by default */
			technology->enable_persistent = true;
		else
			technology->enable_persistent = false;

		if (technology->type == CONNMAN_SERVICE_TYPE_P2P)
			technology->enable_p2p_listen_persistent = true;

		return;
	}

	identifier = g_strdup_printf("%s", get_name(technology->type));
	if (!identifier)
		goto done;

	enable = g_key_file_get_boolean(keyfile, identifier, "Enable", &error);
	if (!error)
		technology->enable_persistent = enable;
	else {
		if (technology->type == CONNMAN_SERVICE_TYPE_ETHERNET)
			technology->enable_persistent = true;
		else
			technology->enable_persistent = false;

		need_saving = true;
		g_clear_error(&error);
			if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
				enable = g_key_file_get_boolean(keyfile, "WiFi", "P2PListen", &error);
				if (!error)
					technology->enable_p2p_listen_persistent = enable;
				else {
					technology->enable_p2p_listen_persistent = true;
					g_clear_error(&error);
				}
			}
	}

	enable = g_key_file_get_boolean(keyfile, identifier,
					"Tethering", &error);
	if (!error)
		technology->tethering_persistent = enable;
	else {
		need_saving = true;
		g_clear_error(&error);
	}

	if (need_saving)
		technology_save(technology);

	technology->tethering_ident = g_key_file_get_string(keyfile,
				identifier, "Tethering.Identifier", NULL);

	enc = g_key_file_get_string(keyfile,
				identifier, "Tethering.Passphrase", NULL);
	if (enc)
		technology->tethering_passphrase = g_strcompress(enc);

	technology->tethering_channel = g_key_file_get_integer(keyfile,
				identifier, "Tethering.Channel", NULL);

	technology->tethering_ipaddress = g_key_file_get_string(keyfile,
				identifier, "Tethering.IP", NULL);
done:
	g_free(identifier);

	g_key_file_free(keyfile);
}

bool __connman_technology_get_offlinemode(void)
{
	return global_offlinemode;
}

static void connman_technology_save_offlinemode(void)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	bool offlinemode;

	keyfile = __connman_storage_load_global();

	if (!keyfile) {
		keyfile = g_key_file_new();
		g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);

		__connman_storage_save_global(keyfile);
	}
	else {
		offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);

		if (error || offlinemode != global_offlinemode) {
			g_key_file_set_boolean(keyfile, "global",
					"OfflineMode", global_offlinemode);
			if (error)
				g_clear_error(&error);

			__connman_storage_save_global(keyfile);
		}
	}

	g_key_file_free(keyfile);
}

static bool connman_technology_load_offlinemode(void)
{
	GKeyFile *keyfile;
	GError *error = NULL;
	bool offlinemode;

	/* If there is a error, we enable offlinemode */
	keyfile = __connman_storage_load_global();
	if (!keyfile)
		return false;

	offlinemode = g_key_file_get_boolean(keyfile, "global",
						"OfflineMode", &error);
	if (error) {
		offlinemode = false;
		g_clear_error(&error);
	}

	g_key_file_free(keyfile);

	return offlinemode;
}

static void append_interfaces(DBusMessageIter *iter, void *user_data)
{
	struct connman_technology *technology = user_data;
	GSList *list;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;
		const char *iface = connman_device_get_interface(device);

		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &iface);
	}
}

static void interface_changed(struct connman_technology *technology)
{
	DBG("interface_changed for path  %s", technology->path);
	connman_dbus_property_changed_array(technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE,
						"Interfaces",
						DBUS_TYPE_STRING,
						append_interfaces, technology);
}

void connman_technology_interface_changed(struct connman_technology *technology)
{
	interface_changed(technology);
}

static void append_p2plistenparams(DBusMessageIter *iter, void *user_data)
{
	struct connman_technology *technology = user_data;

	if (!technology)
		return;

	connman_dbus_dict_append_basic(iter, "Period",
					DBUS_TYPE_INT32, &technology->period);

	connman_dbus_dict_append_basic(iter, "Interval",
					DBUS_TYPE_INT32, &technology->interval);
}

static void append_properties(DBusMessageIter *iter,
		struct connman_technology *technology)
{
	DBusMessageIter dict;
	dbus_bool_t val;
	const char *str;

	connman_dbus_dict_open(iter, &dict);

	str = get_name(technology->type);
	if (str)
		connman_dbus_dict_append_basic(&dict, "Name",
						DBUS_TYPE_STRING, &str);

	str = __connman_service_type2string(technology->type);
	if (str)
		connman_dbus_dict_append_basic(&dict, "Type",
						DBUS_TYPE_STRING, &str);

	__sync_synchronize();
	val = technology->enabled;
	connman_dbus_dict_append_basic(&dict, "Powered",
					DBUS_TYPE_BOOLEAN,
					&val);

	val = technology->connected;
	connman_dbus_dict_append_basic(&dict, "Connected",
					DBUS_TYPE_BOOLEAN,
					&val);

	val = technology->tethering;
	connman_dbus_dict_append_basic(&dict, "Tethering",
					DBUS_TYPE_BOOLEAN,
					&val);

	connman_dbus_dict_append_array(&dict, "Interfaces",
					DBUS_TYPE_STRING,
					append_interfaces,
					technology);

	if (technology->tethering_ident)
		connman_dbus_dict_append_basic(&dict, "TetheringIdentifier",
					DBUS_TYPE_STRING,
					&technology->tethering_ident);

	if (technology->tethering_passphrase)
		connman_dbus_dict_append_basic(&dict, "TetheringPassphrase",
					DBUS_TYPE_STRING,
					&technology->tethering_passphrase);

	if (technology->tethering_ipaddress)
		connman_dbus_dict_append_basic(&dict, "TetheringIPAddress",
					DBUS_TYPE_STRING,
					&technology->tethering_ipaddress);

	if (technology->tethering_channel)
		connman_dbus_dict_append_basic(&dict, "TetheringChannel",
					DBUS_TYPE_UINT32,
					&technology->tethering_channel);

	if(technology->p2p_identifier)
		connman_dbus_dict_append_basic(&dict, "P2PIdentifier",
					DBUS_TYPE_STRING,
					&technology->p2p_identifier);

	val = technology->p2p_persistent;
	connman_dbus_dict_append_basic(&dict, "P2PPersistent",
					DBUS_TYPE_BOOLEAN,
					&val);

	connman_dbus_dict_append_dict(&dict, "P2PListenParams",
					append_p2plistenparams, technology);

	connman_dbus_dict_append_basic(&dict, "P2PListenChannel",
					DBUS_TYPE_UINT32,
					&technology->p2p_listen_channel);

	val = technology->p2p_listen;
	connman_dbus_dict_append_basic(&dict, "P2PListen",
					DBUS_TYPE_BOOLEAN,
					&val);

	connman_dbus_dict_close(iter, &dict);
}

static void technology_added_signal(struct connman_technology *technology)
{
	DBusMessage *signal;
	DBusMessageIter iter;

	signal = dbus_message_new_signal(CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyAdded");
	if (!signal)
		return;

	dbus_message_iter_init_append(signal, &iter);
	dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
							&technology->path);
	append_properties(&iter, technology);

	dbus_connection_send(connection, signal, NULL);
	dbus_message_unref(signal);
}

static void technology_removed_signal(struct connman_technology *technology)
{
	g_dbus_emit_signal(connection, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "TechnologyRemoved",
			DBUS_TYPE_OBJECT_PATH, &technology->path,
			DBUS_TYPE_INVALID);
}

static DBusMessage *get_properties(DBusConnection *conn,
					DBusMessage *message, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;
	DBusMessageIter iter;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;

	dbus_message_iter_init_append(reply, &iter);
	append_properties(&iter, technology);

	return reply;
}

void __connman_technology_list_struct(DBusMessageIter *array)
{
	GSList *list;
	DBusMessageIter entry;

	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (!technology->path ||
				(technology->rfkill_driven &&
				 technology->hardblocked))
			continue;

		dbus_message_iter_open_container(array, DBUS_TYPE_STRUCT,
				NULL, &entry);
		dbus_message_iter_append_basic(&entry, DBUS_TYPE_OBJECT_PATH,
				&technology->path);
		append_properties(&entry, technology);
		dbus_message_iter_close_container(array, &entry);
	}
}

static gboolean technology_pending_reply(gpointer user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessage *reply;

	/* Power request timed out, send ETIMEDOUT. */
	if (technology->pending_reply) {
		reply = __connman_error_failed(technology->pending_reply, ETIMEDOUT);
		if (reply)
			g_dbus_send_message(connection, reply);

		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;
		technology->pending_timeout = 0;
	}

	return FALSE;
}

static int technology_affect_devices(struct connman_technology *technology,
						bool enable_device)
{
	int err = 0, err_dev;
	GSList *list;

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		if (enable_device)
			__connman_technology_enabled(technology->type);
		else
			__connman_technology_disabled(technology->type);
		return 0;
	}

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (enable_device)
			err_dev = __connman_device_enable(device);
		else
			err_dev = __connman_device_disable(device);

		if (err_dev < 0 && err_dev != -EALREADY)
			err = err_dev;
	}

	return err;
}

static void powered_changed(struct connman_technology *technology)
{
	dbus_bool_t enabled;

	if (!technology->dbus_registered)
		return;

	if (technology->pending_reply) {
		g_dbus_send_reply(connection,
				technology->pending_reply, DBUS_TYPE_INVALID);
		dbus_message_unref(technology->pending_reply);
		technology->pending_reply = NULL;

		g_source_remove(technology->pending_timeout);
		technology->pending_timeout = 0;
	}

	__sync_synchronize();
	enabled = technology->enabled;
	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Powered",
			DBUS_TYPE_BOOLEAN, &enabled);
}

static void enable_tethering(struct connman_technology *technology)
{
	int ret;

	if (!connman_setting_get_bool("PersistentTetheringMode"))
		return;

	ret = set_tethering(technology, true);
	if (ret < 0 && ret != -EALREADY)
		DBG("Cannot enable tethering yet for %s (%d/%s)",
			get_name(technology->type),
			-ret, strerror(-ret));
}

static int technology_enabled(struct connman_technology *technology)
{
	__sync_synchronize();
	if (technology->enabled)
		return -EALREADY;

	struct connman_technology *p2p;
	if (technology->type == CONNMAN_SERVICE_TYPE_WIFI) {
		
		p2p = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (p2p && !p2p->enabled && p2p->enable_persistent){
			technology_enabled(p2p);
		}
	}

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		p2p = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (p2p){
			(void)set_p2p_enable(p2p,true);
		}
	}

	technology->enabled = true;
	if (technology->tethering_persistent)
		enable_tethering(technology);

	powered_changed(technology);

	return 0;
}

static int technology_enable(struct connman_technology *technology)
{
	int err = 0;
	int err_dev;

	DBG("technology %p enable", technology);

	__sync_synchronize();

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		struct connman_technology *wifi;

		wifi = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
		if (wifi && wifi->enabled)
			return technology_enabled(technology);
		return 0;
	}

	if (technology->enabled)
		return -EALREADY;

	if (technology->pending_reply)
		return -EBUSY;

	if (connman_setting_get_bool("PersistentTetheringMode")	&&
					technology->tethering)
		set_tethering(technology, true);

	if (technology->rfkill_driven)
		err = __connman_rfkill_block(technology->type, false);

	err_dev = technology_affect_devices(technology, true);

	if (!technology->rfkill_driven)
		err = err_dev;

	return err;
}

static int technology_disabled(struct connman_technology *technology)
{
	__sync_synchronize();
	if (!technology->enabled)
		return -EALREADY;

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		(void)set_p2p_enable(technology,false);
	}

	technology->enabled = false;

	powered_changed(technology);

	return 0;
}

static int technology_disable(struct connman_technology *technology)
{
	int err;

	DBG("technology %p disable", technology);

	__sync_synchronize();

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P) {
		technology->enable_persistent = false;
		__connman_device_stop_scan(CONNMAN_SERVICE_TYPE_P2P);
		//__connman_peer_disconnect_all();
		return technology_disabled(technology);
	} else if (technology->type == CONNMAN_SERVICE_TYPE_WIFI) {
		struct connman_technology *p2p;

		p2p = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (p2p && p2p->enabled) {
			p2p->enable_persistent = true;
			technology_disabled(p2p);
		}
	}

	if (!technology->enabled)
		return -EALREADY;

	if (technology->pending_reply)
		return -EBUSY;

	if (technology->tethering)
		set_tethering(technology, false);

	err = technology_affect_devices(technology, false);

	if (technology->rfkill_driven)
		err = __connman_rfkill_block(technology->type, true);

	return err;
}

static int remove_persistent_info(struct connman_technology *technology,
													const char *identifier)
{
	int result = -EOPNOTSUPP;
	GSList *tech_drivers;

	__sync_synchronize();
	if (technology->enabled == FALSE)
		return -EACCES;

	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
		tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (driver == NULL || driver->remove_persistent_info == NULL)
			continue;

		result = driver->remove_persistent_info(technology, identifier);
	}

	return result;
}

static int remove_persistent_info_all(struct connman_technology *technology)
{
	int result = -EOPNOTSUPP;
	GSList *tech_drivers;

	__sync_synchronize();
	if (technology->enabled == FALSE)
		return -EACCES;

	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
		tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (driver == NULL || driver->remove_persistent_info_all == NULL)
			continue;

		result = driver->remove_persistent_info_all(technology);
	}

	return result;
}

static DBusMessage *set_powered(struct connman_technology *technology,
				DBusMessage *msg, bool powered)
{
	DBusMessage *reply = NULL;
	int err = 0;

	if (technology->rfkill_driven && technology->hardblocked) {
		err = -EACCES;
		goto make_reply;
	}

	if (powered)
		err = technology_enable(technology);
	else
		err = technology_disable(technology);

	if (err != -EBUSY) {
		technology->enable_persistent = powered;
		technology_save(technology);
	}

make_reply:
	if (err == -EINPROGRESS) {
		technology->pending_reply = dbus_message_ref(msg);
		technology->pending_timeout = g_timeout_add_seconds(10,
					technology_pending_reply, technology);
	} else if (err == -EALREADY) {
		if (powered)
			reply = __connman_error_already_enabled(msg);
		else
			reply = __connman_error_already_disabled(msg);
	} else if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}
bool connman_technology_get_enable_p2p_listen(struct connman_technology *technology)
{
	return technology->enable_p2p_listen_persistent;
}
bool connman_technology_get_p2p_listen(struct connman_technology *technology)
{
	return technology->p2p_listen;
}

void connman_technology_set_p2p_listen(struct connman_technology *technology, bool enabled)
{
	dbus_bool_t listen_enabled;

	if (enabled == technology->p2p_listen)
		return;

	technology->p2p_listen = enabled;
	listen_enabled = enabled;

	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE,
			"P2PListen",
			DBUS_TYPE_BOOLEAN,
			&listen_enabled);
}

void __connman_technology_p2p_invitation_result(struct connman_technology *technology, int status)
{
	if(technology->type != CONNMAN_SERVICE_TYPE_P2P)
		return;

	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "P2PInvitationResult",
			DBUS_TYPE_INT32, &status);
}

static DBusMessage *set_p2p_listen(struct connman_technology *technology,
				DBusMessage *msg, bool enable)
{
	DBusMessage *reply = NULL;
	int err = 0;
	GSList *tech_drivers = NULL;

	__sync_synchronize();
	if (!technology->enabled) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	if (technology->p2p_listen && enable)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_listen)
			continue;

		err = driver->set_p2p_listen(technology, enable);
		if (!err) {
			technology->enable_p2p_listen_persistent = enable;
			technology_save(technology);
		}
	}

make_reply:
	if (err == -EINPROGRESS)
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
	else if (err == -EALREADY) {
		if (enable)
			reply = __connman_error_already_enabled(msg);
		else
			reply = __connman_error_already_disabled(msg);
	} else if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}
void connman_technology_set_p2p_listen_params(struct connman_technology *technology,
						int period, int interval)
{
	if (!technology)
		return;

	technology->period = period;
	technology->interval = interval;
}
unsigned int connman_technology_get_p2p_listen_channel(struct connman_technology *technology)
{
	return technology->p2p_listen_channel;
}
void connman_technology_set_p2p_listen_channel(struct connman_technology *technology,
						unsigned int listen_channel)
{
	if (!connman_technology_get_p2p_listen(technology))
		return;

	if (connman_technology_get_p2p_listen_channel(technology) != listen_channel)
	{
		technology->p2p_listen_channel = listen_channel;
		connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE,
				"P2PListenChannel",
				DBUS_TYPE_UINT32,
				&technology->p2p_listen_channel);
	}
}

bool connman_technology_get_p2p_persistent(struct connman_technology *technology)
{
	return technology->p2p_persistent;
}

void connman_technology_set_p2p_persistent(struct connman_technology *technology, bool enabled)
{
	GSList *tech_drivers;
	int err = 0;
	dbus_bool_t persistent_enabled;

	if (technology->p2p_persistent == enabled)
		return;

	technology->p2p_persistent = enabled;

	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
		tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_persistent)
			continue;

		err = driver->set_p2p_persistent(technology, enabled);
		if (err < 0)
			connman_error("Failed to set P2P persistent state");
	}

	persistent_enabled = technology->p2p_persistent;
	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE,
			"P2PPersistent",
			DBUS_TYPE_BOOLEAN,
			&persistent_enabled);
}

static DBusMessage *set_p2p_persistent(struct connman_technology *technology,
													DBusMessage *msg, bool enabled)
{
	DBusMessage *reply = NULL;
	int err = 0;
	GSList *tech_drivers = NULL;
	dbus_bool_t persistent_enabled;

	__sync_synchronize();

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P || !technology->enabled) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	if(technology->p2p_persistent == enabled)
		return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	technology->p2p_persistent = enabled;

	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
	     tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (driver == NULL || driver->set_p2p_persistent == NULL)
			continue;

		err = driver->set_p2p_persistent(technology, enabled);
	}
make_reply:
	if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else {
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

		persistent_enabled = technology->p2p_persistent;
		connman_dbus_property_changed_basic(technology->path,
				CONNMAN_TECHNOLOGY_INTERFACE,
				"P2PPersistent",
				DBUS_TYPE_BOOLEAN,
				&persistent_enabled);
	}

	return reply;
}

void connman_technology_set_p2p_identifier(struct connman_technology *technology, const char *p2p_identifier)
{

	if (technology->p2p_identifier) {
		g_free(technology->p2p_identifier);
		technology->p2p_identifier = NULL;
	}

	if(p2p_identifier == NULL)
		return;

	technology->p2p_identifier = g_strdup(p2p_identifier);

	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE,
			"P2PIdentifier",
			DBUS_TYPE_STRING,
			&technology->p2p_identifier);
}

static int set_p2p_identifier(struct connman_technology *technology,
											const char *p2p_identifier)
{
	int result = -EOPNOTSUPP;
	int err = 0;
	GSList *tech_drivers = NULL;

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
		return -EINVAL;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_identifier)
			continue;

		err = driver->set_p2p_identifier(technology, p2p_identifier);

		if (result == -EINPROGRESS)
			continue;

		if (err == -EINPROGRESS || err == 0) {
			result = err;
			continue;
		}
	}

	return result;
}
static DBusMessage *set_p2p_listen_params(struct connman_technology *technology,
				DBusMessage *msg, DBusMessageIter *array)
{
	DBusMessage *reply = NULL;
	int err = 0;
	GSList *tech_drivers = NULL;
	int period = 0, interval = 0;
	DBusMessageIter dict;

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return NULL;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;
		int type;

		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return NULL;

		dbus_message_iter_get_basic(&entry, &key);
		dbus_message_iter_next(&entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return NULL;

		dbus_message_iter_recurse(&entry, &value);

		type = dbus_message_iter_get_arg_type(&value);

		if (g_str_equal(key, "Period")) {
			if (type != DBUS_TYPE_INT32)
				return NULL;

			dbus_message_iter_get_basic(&value, &period);
		} else if (g_str_equal(key, "Interval")) {
			if (type != DBUS_TYPE_INT32)
				return NULL;

			dbus_message_iter_get_basic(&value, &interval);
		}

		dbus_message_iter_next(&dict);
	}

	for (tech_drivers = technology->driver_list; tech_drivers;
			tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_listen_params)
			continue;

		err = driver->set_p2p_listen_params(technology, period, interval);

		if (err == 0)
			connman_technology_set_p2p_listen_params(technology, period, interval);
	}

	if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}
static DBusMessage *set_p2p_listen_channel(struct connman_technology *technology,
													DBusMessage *msg, unsigned int listen_channel)
{
	DBusMessage *reply = NULL;
	int err = 0;
	GSList *tech_drivers = NULL;

	__sync_synchronize();
	if (!technology->enabled) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P) {
		err = -EINVAL;
		goto make_reply;
	}

	for (tech_drivers = technology->driver_list; tech_drivers;
			tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver|| !driver->set_p2p_listen_channel)
			continue;

		err = driver->set_p2p_listen_channel(technology, listen_channel);

		if (err == 0)
			connman_technology_set_p2p_listen_channel(technology, listen_channel);
	}
make_reply:
	if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}
static DBusMessage *set_p2p_go_intent(struct connman_technology *technology,
				   DBusMessage *msg, unsigned int go_intent)
{
	DBusMessage *reply = NULL;
	int err = 0;
	GSList *tech_drivers = NULL;

	__sync_synchronize();
	if (!technology->enabled) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P) {
		err = -EOPNOTSUPP;
		goto make_reply;
	}

	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
			tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_go_intent)
			continue;

		err = driver->set_p2p_go_intent(technology, go_intent);
	}

make_reply:
	if (err < 0)
		reply = __connman_error_failed(msg, -err);
	else
		reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);

	return reply;
}

static int set_p2p_enable(struct connman_technology *technology,
				 bool status)
{
	int err = 0;
	GSList *tech_drivers = NULL;

	__sync_synchronize();
	if (technology->type != CONNMAN_SERVICE_TYPE_P2P) {
		return -EOPNOTSUPP;
	}


	for (tech_drivers = technology->driver_list; tech_drivers != NULL;
			tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_enable)
			continue;

		err = driver->set_p2p_enable(technology, status);
		return err;
	}

	return err;
}

void connman_technology_set_p2p(struct connman_technology *technology, bool enabled)
{
	dbus_bool_t p2p_enabled;
	DBG("Set p2p enable..enter");

	if (!technology) {
		DBG("Set p2p enable..tech null");
		return;
	}

	if (enabled == technology->enabled)
		return;

	technology->enabled = enabled;
	p2p_enabled = enabled;

	powered_changed(technology);

	connman_dbus_property_changed_basic(technology->path,
		CONNMAN_TECHNOLOGY_INTERFACE,
		"P2P",
		DBUS_TYPE_BOOLEAN,
		&p2p_enabled);
}

bool is_technology_enabled(struct connman_technology *technology)
{
	return technology == NULL ? false : technology->enabled;
}

static DBusMessage *set_property(DBusConnection *conn,
					DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	DBusMessageIter iter, value;
	const char *name;
	int type, err;

	DBG("conn %p", conn);

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &name);
	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_recurse(&iter, &value);

	type = dbus_message_iter_get_arg_type(&value);

	DBG("property %s", name);

	if (g_str_equal(name, "Tethering")) {
		dbus_bool_t tethering;
		int err;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (!connman_technology_is_tethering_allowed(technology->type)) {
			DBG("%s tethering not allowed by config file",
				__connman_service_type2string(technology->type));
			return __connman_error_not_supported(msg);
		}

		dbus_message_iter_get_basic(&value, &tethering);

		if (technology->tethering == tethering) {
			if (!tethering)
				return __connman_error_already_disabled(msg);
			else
				return __connman_error_already_enabled(msg);
		}

		err = set_tethering(technology, tethering);
		if (err < 0)
			return __connman_error_failed(msg, -err);

		technology->tethering_persistent = tethering;

		technology_save(technology);

	} else if (g_str_equal(name, "TetheringIdentifier")) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		if (strlen(str) < 1 || strlen(str) > 32)
			return __connman_error_invalid_arguments(msg);

		if (g_strcmp0(technology->tethering_ident, str) != 0) {
			g_free(technology->tethering_ident);
			technology->tethering_ident = g_strdup(str);
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
						CONNMAN_TECHNOLOGY_INTERFACE,
						"TetheringIdentifier",
						DBUS_TYPE_STRING,
						&technology->tethering_ident);
		}
	} else if (g_str_equal(name, "TetheringPassphrase")) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		/* Allow empty passphrases for setting up an AP with open
		 * security type */

		if (strlen(str) == 0) {
			g_free(technology->tethering_passphrase);
			technology->tethering_passphrase = NULL;
		}
		else {
			err = __connman_service_check_passphrase(CONNMAN_SERVICE_SECURITY_PSK,
								str);
			if (err < 0)
				return __connman_error_passphrase_required(msg);
		}

		if (g_strcmp0(technology->tethering_passphrase, str) != 0) {
			g_free(technology->tethering_passphrase);
			technology->tethering_passphrase = g_strdup(str);
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					"TetheringPassphrase",
					DBUS_TYPE_STRING,
					&technology->tethering_passphrase);
		}
	} else if (g_str_equal(name, "TetheringChannel")) {
		dbus_uint32_t channel;

		if (type != DBUS_TYPE_UINT32)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &channel);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		if (channel == 0 || channel > 13)
			return __connman_error_invalid_arguments(msg);

		if (technology->tethering_channel != channel) {

			technology->tethering_channel = channel;
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					"TetheringChannel",
					DBUS_TYPE_UINT32,
					&technology->tethering_channel);
		}
	} else if (g_str_equal(name, "TetheringIPAddress")) {
		const char *str;

		dbus_message_iter_get_basic(&value, &str);

		if (technology->type != CONNMAN_SERVICE_TYPE_WIFI)
			return __connman_error_not_supported(msg);

		if (strlen(str) == 0) {
				g_free(technology->tethering_ipaddress);
				technology->tethering_ipaddress = NULL;
		}
		if (g_strcmp0(technology->tethering_ipaddress, str) != 0) {
			g_free(technology->tethering_ipaddress);
			technology->tethering_ipaddress = g_strdup(str);
			technology_save(technology);

			connman_dbus_property_changed_basic(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					"TetheringIPAddress",
					DBUS_TYPE_STRING,
					&technology->tethering_ipaddress);
		}
	} else if (g_str_equal(name, "P2PListen")) {
		bool enable;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		dbus_message_iter_get_basic(&value, &enable);

		return set_p2p_listen(technology, msg, enable);
	} else if (g_str_equal(name, "P2PPersistent")) {
		bool enable;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		dbus_message_iter_get_basic(&value, &enable);

		return set_p2p_persistent(technology, msg, enable);
	} else if (g_str_equal(name, "P2PIdentifier")) {
		int err;
		const char *p2p_identifier;

		if (type != DBUS_TYPE_STRING)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &p2p_identifier);

		if(strlen(p2p_identifier) > 32)
			return __connman_error_invalid_arguments(msg);

		err = set_p2p_identifier(technology, p2p_identifier);
		if (err < 0)
			return __connman_error_failed(msg, -err);
	} else if (g_str_equal(name, "P2PListenParams")) {
		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		return set_p2p_listen_params(technology, msg, &value);
	} else if (g_str_equal(name, "P2PListenChannel")) {
		dbus_uint32_t listen_channel;

		if (type != DBUS_TYPE_UINT32)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &listen_channel);

		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		return set_p2p_listen_channel(technology, msg, listen_channel);
	} else if (g_str_equal(name, "P2PGOIntent")) {
		dbus_uint32_t go_intent;

		if (type != DBUS_TYPE_UINT32)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &go_intent);

		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		return set_p2p_go_intent(technology, msg, go_intent);
	} else if (g_str_equal(name, "Powered")) {
		dbus_bool_t enable;

		if (type != DBUS_TYPE_BOOLEAN)
			return __connman_error_invalid_arguments(msg);

		dbus_message_iter_get_basic(&value, &enable);

		return set_powered(technology, msg, enable);
	}	else if (g_str_equal(name, "RemovePersistentInfo") == TRUE) {
		const char *identifier;
		int res;

		dbus_message_iter_get_basic(&value, &identifier);

		if (technology->type != CONNMAN_SERVICE_TYPE_P2P)
			return __connman_error_not_supported(msg);

		if (!strncmp(identifier, "all", 3))
			res = remove_persistent_info_all(technology);
		else if (strlen(identifier) != 17)
			return __connman_error_invalid_arguments(msg);
		else
			res = remove_persistent_info(technology, identifier);

		if (res < 0)
			return __connman_error_failed(msg, -res);
	} else
		return __connman_error_invalid_property(msg);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void reply_scan_pending(struct connman_technology *technology, int err)
{
	DBusMessage *reply;

	DBG("technology %p err %d", technology, err);

	while (technology->scan_pending) {
		DBusMessage *msg = technology->scan_pending->data;

		DBG("reply to %s", dbus_message_get_sender(msg));

		if (err == 0)
			reply = g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
		else
			reply = __connman_error_failed(msg, -err);
		g_dbus_send_message(connection, reply);
		dbus_message_unref(msg);

		technology->scan_pending =
			g_slist_delete_link(technology->scan_pending,
					technology->scan_pending);
	}
}

void __connman_technology_scan_started(struct connman_device *device)
{
	DBG("device %p", device);
}

void __connman_technology_scan_stopped(struct connman_device *device,
					enum connman_service_type type)
{
	int count = 0;
	struct connman_technology *technology;
	GSList *list;

	technology = technology_find(type);

	DBG("technology %p device %p", technology, device);

	if (!technology)
		return;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *other_device = list->data;

		if (device == other_device)
			continue;

		if (connman_device_get_scanning(other_device, type))
			count += 1;
	}

	if (count == 0)
		reply_scan_pending(technology, 0);
}

void __connman_technology_notify_regdom_by_device(struct connman_device *device,
						int result, const char *alpha2)
{
	bool regdom_set = false;
	struct connman_technology *technology;
	enum connman_service_type type;
	GSList *tech_drivers;

	type = __connman_device_get_service_type(device);
	technology = technology_find(type);

	if (!technology)
		return;

	if (result < 0) {

		for (tech_drivers = technology->driver_list;
		     tech_drivers;
		     tech_drivers = g_slist_next(tech_drivers)) {
			struct connman_technology_driver *driver =
				tech_drivers->data;

			if (driver->set_regdom) {
				driver->set_regdom(technology, alpha2);
				regdom_set = true;
			}

		}

		if (!regdom_set)
			alpha2 = NULL;
	}

	connman_technology_regdom_notify(technology, alpha2);
}

int __connman_technology_set_p2p_go(DBusMessage *msg, const char *ident, const char *passphrase)
{
	struct connman_technology *technology;
	GSList *tech_drivers;
	int result = 0;
	int err;

	technology = technology_find(CONNMAN_SERVICE_TYPE_P2P);

	DBG("technology %p", technology);

	if (!technology)
		return -EINVAL;

	if (strlen(ident) < 1 || strlen(passphrase) < 1){
		ident = NULL;
		passphrase = NULL;
	}

	for (tech_drivers = technology->driver_list; tech_drivers;
			tech_drivers = g_slist_next(tech_drivers)) {
		struct connman_technology_driver *driver = tech_drivers->data;

		if (!driver || !driver->set_p2p_go)
			continue;

		err = driver->set_p2p_go(msg, technology, ident, passphrase);

		if (result == -EINPROGRESS)
			continue;

		if (err == -EINPROGRESS || err == 0) {
			result = err;
			continue;
		}
	}

	return 0;
}

static DBusMessage *scan(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	int err;

	DBG("technology %p request from %s", technology,
			dbus_message_get_sender(msg));

	if (technology->type == CONNMAN_SERVICE_TYPE_P2P &&
				!technology->enabled)
		return __connman_error_permission_denied(msg);

	dbus_message_ref(msg);
	technology->scan_pending =
		g_slist_prepend(technology->scan_pending, msg);

	err = __connman_device_request_scan_full(technology->type);
	if (err < 0)
		reply_scan_pending(technology, err);

	return NULL;
}
void connman_technology_wps_failed_notify(struct connman_technology *technology)
{
	g_dbus_emit_signal(connection, technology->path,
		CONNMAN_TECHNOLOGY_INTERFACE, "WPSFailed",
		DBUS_TYPE_INVALID);
}
static DBusMessage *cancel_p2p(DBusConnection *conn, DBusMessage *msg, void *data)
{
	struct connman_technology *technology = data;
	int err;

	if (technology->type != CONNMAN_SERVICE_TYPE_P2P &&
				!technology->enabled)
		return __connman_error_failed(msg, EOPNOTSUPP);

	err = __connman_device_request_cancel_p2p(technology->type);
	if (err < 0)
		return __connman_error_failed(msg, -err);

	return g_dbus_create_reply(msg, DBUS_TYPE_INVALID);
}

static void reply_interface_properties(struct connman_device *device, void *user_data)
{
	DBusMessage *msg = user_data;
	DBusMessage *reply;
	DBusMessageIter iter, dict;

	reply = dbus_message_new_method_return(msg);
	if (!reply) {
		reply = __connman_error_failed(msg, ENOMEM);
		g_dbus_send_message(connection, reply);
		dbus_message_unref(msg);
		return;
	}

	dbus_message_iter_init_append(reply, &iter);

	connman_dbus_dict_open(&iter, &dict);

	if (connman_device_get_type(device) == CONNMAN_DEVICE_TYPE_WIFI) {
		uint32_t value = 0;

		value = connman_device_get_integer(device, "WiFi.RSSI");
		connman_dbus_dict_append_basic(&dict, "WiFi.RSSI",
								DBUS_TYPE_UINT32, &value);

		value = connman_device_get_integer(device, "WiFi.LinkSpeed");
		connman_dbus_dict_append_basic(&dict, "WiFi.LinkSpeed",
								DBUS_TYPE_UINT32, &value);

		value = connman_device_get_integer(device, "WiFi.Frequency");
		connman_dbus_dict_append_basic(&dict, "WiFi.Frequency",
								DBUS_TYPE_UINT32, &value);

		value = connman_device_get_integer(device, "WiFi.Noise");
		connman_dbus_dict_append_basic(&dict, "WiFi.Noise",
								DBUS_TYPE_UINT32, &value);
	}

	connman_dbus_dict_close(&iter, &dict);

	g_dbus_send_message(connection, reply);

	dbus_message_unref(msg);
}
static DBusMessage *get_interface_properties(DBusConnection *conn,
					DBusMessage *msg, void *user_data)
{
	struct connman_technology *technology = user_data;
	DBusMessageIter iter;
	GSList *list;
	char *interface = NULL;

	if (!dbus_message_iter_init(msg, &iter))
		return __connman_error_invalid_arguments(msg);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING)
		return __connman_error_invalid_arguments(msg);

	dbus_message_iter_get_basic(&iter, &interface);

	if (!interface)
		return __connman_error_invalid_arguments(msg);

	struct connman_device *device = NULL;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *current_device = list->data;
		const char *iface = connman_device_get_interface(current_device);

		if (g_strcmp0(iface, interface) == 0) {
			device = current_device;
			break;
		}
	}

	if (!device)
		return __connman_error_invalid_arguments(msg);

	dbus_message_ref(msg);

	connman_device_request_signal_info(device, reply_interface_properties, msg);

	return NULL;
}
static const GDBusMethodTable technology_methods[] = {
	{ GDBUS_DEPRECATED_METHOD("GetProperties",
			NULL, GDBUS_ARGS({ "properties", "a{sv}" }),
			get_properties) },
	{ GDBUS_ASYNC_METHOD("SetProperty",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" }),
			NULL, set_property) },
	{ GDBUS_ASYNC_METHOD("Scan", NULL, NULL, scan) },
	{ GDBUS_METHOD("CancelP2P", NULL, NULL, cancel_p2p) },
	{ GDBUS_ASYNC_METHOD("GetInterfaceProperties",
			GDBUS_ARGS({ "interface", "s" }),
			GDBUS_ARGS({ "properties", "a{sv}"}),
			get_interface_properties) },
	{ },
};

static const GDBusSignalTable technology_signals[] = {
	{ GDBUS_SIGNAL("PropertyChanged",
			GDBUS_ARGS({ "name", "s" }, { "value", "v" })) },
	{ },
};

static bool technology_dbus_register(struct connman_technology *technology)
{
	if (technology->dbus_registered ||
				(technology->rfkill_driven &&
				 technology->hardblocked))
		return true;

	if (!g_dbus_register_interface(connection, technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE,
					technology_methods, technology_signals,
					NULL, technology, NULL)) {
		connman_error("Failed to register %s", technology->path);
		return false;
	}

	technology_added_signal(technology);
	technology->dbus_registered = true;

	return true;
}

static void technology_dbus_unregister(struct connman_technology *technology)
{
	if (!technology->dbus_registered)
		return;

	technology_removed_signal(technology);
	g_dbus_unregister_interface(connection, technology->path,
		CONNMAN_TECHNOLOGY_INTERFACE);

	technology->dbus_registered = false;
}

static void technology_put(struct connman_technology *technology)
{
	DBG("technology %p", technology);

	if (__sync_sub_and_fetch(&technology->refcount, 1) > 0)
		return;

	reply_scan_pending(technology, -EINTR);

	while (technology->driver_list) {
		struct connman_technology_driver *driver;

		driver = technology->driver_list->data;

		if (driver->remove)
			driver->remove(technology);

		technology->driver_list =
			g_slist_delete_link(technology->driver_list,
					technology->driver_list);
	}

	technology_list = g_slist_remove(technology_list, technology);

	technology_dbus_unregister(technology);

	g_slist_free(technology->device_list);

    if (technology->pending_reply) {
        dbus_message_unref(technology->pending_reply);
        technology->pending_reply = NULL;
        g_source_remove(technology->pending_timeout);
        technology->pending_timeout = 0;
    }

	g_free(technology->path);
	g_free(technology->regdom);
	g_free(technology->tethering_ident);
	g_free(technology->tethering_passphrase);
	g_free(technology->tethering_ipaddress);
	g_free(technology->p2p_identifier);
	g_free(technology);
}

static struct connman_technology *technology_get(enum connman_service_type type)
{
	GSList *tech_drivers = NULL;
	struct connman_technology_driver *driver;
	struct connman_technology *technology;
	const char *str;
	GSList *list;

	DBG("type %d", type);

	str = __connman_service_type2string(type);
	if (!str)
		return NULL;

	technology = technology_find(type);
	if (technology) {
		if (type != CONNMAN_SERVICE_TYPE_P2P)
			__sync_fetch_and_add(&technology->refcount, 1);
		return technology;
	}

	/* First check if we have a driver for this technology type */
	for (list = driver_list; list; list = list->next) {
		driver = list->data;

		if (driver->type == type) {
			DBG("technology %p driver %p", technology, driver);
			tech_drivers = g_slist_append(tech_drivers, driver);
		}
	}

	if (!tech_drivers) {
		DBG("No matching drivers found for %s.",
				__connman_service_type2string(type));
		return NULL;
	}

	technology = g_try_new0(struct connman_technology, 1);
	if (!technology)
		return NULL;

	technology->refcount = 1;
	technology->type = type;
	technology->path = g_strdup_printf("%s/technology/%s",
							CONNMAN_PATH, str);

	technology_load(technology);
	technology_list = g_slist_prepend(technology_list, technology);
	technology->driver_list = tech_drivers;

	for (list = tech_drivers; list; list = list->next) {
		driver = list->data;

		if (driver->probe && driver->probe(technology) < 0)
			DBG("Driver probe failed for technology %p",
					technology);
	}

	if (!technology_dbus_register(technology)) {
		technology_put(technology);
		return NULL;
	}

	if (type == CONNMAN_SERVICE_TYPE_P2P) {
		struct connman_technology *wifi;
		bool enable;

		enable = technology->enable_persistent;

		wifi = technology_find(CONNMAN_SERVICE_TYPE_WIFI);
		if (enable && wifi)
			enable = wifi->enabled;

		technology_affect_devices(technology, enable);
	}

	DBG("technology %p %s", technology, get_name(technology->type));

	return technology;
}

int connman_technology_driver_register(struct connman_technology_driver *driver)
{
	GSList *list;
	struct connman_device *device;
	enum connman_service_type type;

	for (list = driver_list; list; list = list->next) {
		if (list->data == driver)
			goto exist;
	}

	DBG("Registering %s driver", driver->name);

	driver_list = g_slist_insert_sorted(driver_list, driver,
							compare_priority);

	/*
	 * Check for technology less devices if this driver
	 * can service any of them.
	*/
	for (list = techless_device_list; list; list = list->next) {
		device = list->data;

		type = __connman_device_get_service_type(device);
		if (type != driver->type)
			continue;

		techless_device_list = g_slist_remove(techless_device_list,
								device);

		__connman_technology_add_device(device);
	}

	/* Check for orphaned rfkill switches. */
	g_hash_table_foreach(rfkill_list, rfkill_check,
					GINT_TO_POINTER(driver->type));

exist:
	if (driver->type == CONNMAN_SERVICE_TYPE_P2P) {
		if (!technology_get(CONNMAN_SERVICE_TYPE_P2P))
			return -ENOMEM;
	}

	return 0;
}

void connman_technology_driver_unregister(struct connman_technology_driver *driver)
{
	GSList *list, *tech_drivers;
	struct connman_technology *technology;
	struct connman_technology_driver *current;

	DBG("Unregistering driver %p name %s", driver, driver->name);

	for (list = technology_list; list; list = list->next) {
		technology = list->data;

		for (tech_drivers = technology->driver_list; tech_drivers;
				tech_drivers = g_slist_next(tech_drivers)) {
			current = tech_drivers->data;
			if (driver != current)
				continue;

			if (driver->remove)
				driver->remove(technology);

			technology->driver_list =
				g_slist_remove(technology->driver_list,
								driver);
			break;
		}
	}

	driver_list = g_slist_remove(driver_list, driver);

	if (driver->type == CONNMAN_SERVICE_TYPE_P2P) {
		technology = technology_find(CONNMAN_SERVICE_TYPE_P2P);
		if (technology)
			technology_put(technology);
	}
}

void __connman_technology_add_interface(enum connman_service_type type,
				int index, const char *ident)
{
	struct connman_technology *technology;
	GSList *tech_drivers;
	struct connman_technology_driver *driver;
	char *name;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	}

	name = connman_inet_ifname(index);
	connman_info("Adding interface %s [ %s ]", name,
				__connman_service_type2string(type));

	technology = technology_find(type);

	if (!technology)
		goto out;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		driver = tech_drivers->data;

		if (driver->add_interface)
			driver->add_interface(technology, index, name, ident);
	}

	/*
	 * At this point we can try to enable tethering automatically as
	 * now the interfaces are set properly.
	 */
	if (technology->tethering_persistent)
		enable_tethering(technology);

out:
	g_free(name);
}

void __connman_technology_remove_interface(enum connman_service_type type,
				int index, const char *ident)
{
	struct connman_technology *technology;
	GSList *tech_drivers;
	struct connman_technology_driver *driver;
	char *name;

	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return;
	case CONNMAN_SERVICE_TYPE_ETHERNET:
	case CONNMAN_SERVICE_TYPE_WIFI:
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
	case CONNMAN_SERVICE_TYPE_CELLULAR:
	case CONNMAN_SERVICE_TYPE_GPS:
	case CONNMAN_SERVICE_TYPE_VPN:
	case CONNMAN_SERVICE_TYPE_GADGET:
	case CONNMAN_SERVICE_TYPE_P2P:
		break;
	}

	name = connman_inet_ifname(index);
	connman_info("Remove interface %s [ %s ] index %d", name,
				__connman_service_type2string(type), index);
	g_free(name);

	technology = technology_find(type);

	if (!technology)
		return;

	for (tech_drivers = technology->driver_list; tech_drivers;
	     tech_drivers = g_slist_next(tech_drivers)) {
		driver = tech_drivers->data;

		if (driver->remove_interface)
			driver->remove_interface(technology, index);
	}
}

int __connman_technology_add_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	type = __connman_device_get_service_type(device);

	DBG("device %p type %s", device, get_name(type));

	technology = technology_get(type);
	if (!technology) {
		/*
		 * Since no driver can be found for this device at the moment we
		 * add it to the techless device list.
		*/
		techless_device_list = g_slist_prepend(techless_device_list,
								device);

		return -ENXIO;
	}

	__sync_synchronize();
	if (technology->rfkill_driven) {
		if (technology->enabled)
			__connman_device_enable(device);
		else
			__connman_device_disable(device);

		goto done;
	}

	if (technology->enable_persistent &&
					!global_offlinemode) {
		int err = __connman_device_enable(device);
		/*
		 * connman_technology_add_device() calls __connman_device_enable()
		 * but since the device is already enabled, the call does not
		 * propagate through to connman_technology_enabled via
		 * connman_device_set_powered.
		 */
		if (err == -EALREADY)
			__connman_technology_enabled(type);
	}
	/* if technology persistent state is offline */
	if (!technology->enable_persistent)
		__connman_device_disable(device);

done:
	if (connman_setting_get_bool("SupportP2P0Interface") == TRUE &&
					g_strcmp0(connman_device_get_string(device, "Interface"),
						connman_option_get_string("WiFiDevice")) == 0)
		technology->device_list = g_slist_append(technology->device_list,
								device);
	else
		technology->device_list = g_slist_prepend(technology->device_list,
								device);

	return 0;
}

int __connman_technology_remove_device(struct connman_device *device)
{
	struct connman_technology *technology;
	enum connman_service_type type;

	DBG("device %p", device);

	type = __connman_device_get_service_type(device);

	technology = technology_find(type);
	if (!technology) {
		techless_device_list = g_slist_remove(techless_device_list,
								device);
		return -ENXIO;
	}

	technology->device_list = g_slist_remove(technology->device_list,
								device);

	if (technology->tethering)
		set_tethering(technology, false);

	technology_put(technology);

	return 0;
}

int __connman_technology_enabled(enum connman_service_type type)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	DBG("technology %p type %s rfkill %d enabled %d", technology,
		get_name(type), technology->rfkill_driven,
		technology->enabled);

	if (technology->rfkill_driven) {
		if (technology->tethering_persistent)
			enable_tethering(technology);
		return 0;
	}

	return technology_enabled(technology);
}

int __connman_technology_disabled(enum connman_service_type type)
{
	struct connman_technology *technology;
	GSList *list;

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	if (technology->rfkill_driven)
		return 0;

	for (list = technology->device_list; list; list = list->next) {
		struct connman_device *device = list->data;

		if (connman_device_get_powered(device))
			return 0;
	}

	return technology_disabled(technology);
}

int __connman_technology_set_offlinemode(bool offlinemode)
{
	GSList *list;
	int err = -EINVAL, enabled_tech_count = 0;

	if (global_offlinemode == offlinemode)
		return 0;

	DBG("offlinemode %s", offlinemode ? "On" : "Off");

	/*
	 * This is a bit tricky. When you set offlinemode, there is no
	 * way to differentiate between attempting offline mode and
	 * resuming offlinemode from last saved profile. We need that
	 * information in rfkill_update, otherwise it falls back on the
	 * technology's persistent state. Hence we set the offline mode here
	 * but save it & call the notifier only if it is successful.
	 */

	global_offlinemode = offlinemode;

	/* Traverse technology list, enable/disable each technology. */
	for (list = technology_list; list; list = list->next) {
		struct connman_technology *technology = list->data;

		if (offlinemode)
			err = technology_disable(technology);
		else {
			if (technology->hardblocked)
				continue;

			if (technology->enable_persistent) {
				err = technology_enable(technology);
				enabled_tech_count++;
			}
		}
	}

	if (err == 0 || err == -EINPROGRESS || err == -EALREADY ||
			(err == -EINVAL && enabled_tech_count == 0)) {
		connman_technology_save_offlinemode();
		__connman_notifier_offlinemode(offlinemode);
	} else
		global_offlinemode = connman_technology_load_offlinemode();

	return err;
}

void __connman_technology_set_connected(enum connman_service_type type,
		bool connected)
{
	struct connman_technology *technology;
	dbus_bool_t val;

	technology = technology_find(type);
	if (!technology)
		return;

	DBG("technology %p connected %d", technology, connected);

	technology->connected = connected;

	val = connected;
	connman_dbus_property_changed_basic(technology->path,
			CONNMAN_TECHNOLOGY_INTERFACE, "Connected",
			DBUS_TYPE_BOOLEAN, &val);
}

static bool technology_apply_rfkill_change(struct connman_technology *technology,
						bool softblock,
						bool hardblock,
						bool new_rfkill)
{
	bool hardblock_changed = false;
	bool apply = true;
	GList *start, *list;

	DBG("technology %p --> %d/%d vs %d/%d",
			technology, softblock, hardblock,
			technology->softblocked, technology->hardblocked);

	if (technology->hardblocked == hardblock)
		goto softblock_change;

	if (!(new_rfkill && !hardblock)) {
		start = g_hash_table_get_values(rfkill_list);

		for (list = start; list; list = list->next) {
			struct connman_rfkill *rfkill = list->data;

			if (rfkill->type != technology->type)
				continue;

			if (rfkill->hardblock != hardblock)
				apply = false;
		}

		g_list_free(start);
	}

	if (!apply)
		goto softblock_change;

	technology->hardblocked = hardblock;
	hardblock_changed = true;

softblock_change:
	if (!apply && technology->softblocked != softblock)
		apply = true;

	if (!apply)
		return technology->hardblocked;

	technology->softblocked = softblock;

	if (technology->hardblocked ||
					technology->softblocked) {
		if (technology_disabled(technology) != -EALREADY)
			technology_affect_devices(technology, false);
	} else if (!technology->hardblocked &&
					!technology->softblocked) {
		if (technology_enabled(technology) != -EALREADY)
			technology_affect_devices(technology, true);
	}

	if (hardblock_changed) {
		if (technology->hardblocked) {
			DBG("%s is switched off.", get_name(technology->type));
			technology_dbus_unregister(technology);
		} else {
			DBG("%s is switched on.", get_name(technology->type));
			technology_dbus_register(technology);

			if (global_offlinemode)
				__connman_rfkill_block(technology->type, true);
		}
	}

	return technology->hardblocked;
}

int __connman_technology_add_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u type %d soft %u hard %u", index, type,
							softblock, hardblock);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (rfkill)
		goto done;

	rfkill = g_try_new0(struct connman_rfkill, 1);
	if (!rfkill)
		return -ENOMEM;

	rfkill->index = index;
	rfkill->type = type;
	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	g_hash_table_insert(rfkill_list, GINT_TO_POINTER(index), rfkill);

done:
	technology = technology_get(type);
	/* If there is no driver for this type, ignore it. */
	if (!technology)
		return -ENXIO;

	technology->rfkill_driven = true;

	/* If hardblocked, there is no need to handle softblocked state */
	if (technology_apply_rfkill_change(technology,
				softblock, hardblock, true))
		return 0;

	if (global_offlinemode)
		return 0;

	/*
	 * Depending on softblocked state we unblock/block according to
	 * offlinemode and persistente state.
	 */
	if (technology->softblocked &&
				technology->enable_persistent)
		return __connman_rfkill_block(type, false);
	else if (!technology->softblocked &&
				!technology->enable_persistent)
		return __connman_rfkill_block(type, true);

	return 0;
}

int __connman_technology_update_rfkill(unsigned int index,
					enum connman_service_type type,
						bool softblock,
						bool hardblock)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u soft %u hard %u", index, softblock, hardblock);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (!rfkill)
		return -ENXIO;

	if (rfkill->softblock == softblock &&
				rfkill->hardblock == hardblock)
		return 0;

	rfkill->softblock = softblock;
	rfkill->hardblock = hardblock;

	technology = technology_find(type);
	/* If there is no driver for this type, ignore it. */
	if (!technology)
		return -ENXIO;

	technology_apply_rfkill_change(technology, softblock, hardblock,
								false);

	if (technology->hardblocked)
		DBG("%s hardblocked", get_name(technology->type));
	else
		DBG("%s is%s softblocked", get_name(technology->type),
			technology->softblocked ? "" : " not");

	return 0;
}

int __connman_technology_remove_rfkill(unsigned int index,
					enum connman_service_type type)
{
	struct connman_technology *technology;
	struct connman_rfkill *rfkill;

	DBG("index %u", index);

	rfkill = g_hash_table_lookup(rfkill_list, GINT_TO_POINTER(index));
	if (!rfkill)
		return -ENXIO;

	g_hash_table_remove(rfkill_list, GINT_TO_POINTER(index));

	technology = technology_find(type);
	if (!technology)
		return -ENXIO;

	technology_apply_rfkill_change(technology,
		technology->softblocked, !technology->hardblocked, false);

	technology_put(technology);

	return 0;
}

int __connman_technology_init(void)
{
	DBG("");

	connection = connman_dbus_get_connection();

	rfkill_list = g_hash_table_new_full(g_direct_hash, g_direct_equal,
							NULL, free_rfkill);

	global_offlinemode = connman_technology_load_offlinemode();

	/* This will create settings file if it is missing */
	connman_technology_save_offlinemode();

	return 0;
}

void __connman_technology_cleanup(void)
{
	DBG("");

	while (technology_list) {
		struct connman_technology *technology = technology_list->data;
		technology_list = g_slist_remove(technology_list, technology);
		technology_put(technology);
	}

	g_hash_table_destroy(rfkill_list);

	dbus_connection_unref(connection);
}

static void append_station_mac(DBusMessageIter *iter, void *user_data)
{
	GHashTable *sta_hash = __connman_tethering_get_sta_hash();

	if (sta_hash == NULL)
		return;

	GHashTableIter iterator;
	gpointer key, value;
	g_hash_table_iter_init (&iterator, sta_hash);

	struct connman_station_info *info_found;

	while (g_hash_table_iter_next (&iterator, &key, &value))
	{
		info_found = value;
		const char* temp = info_found->mac;
		dbus_message_iter_append_basic(iter,
						DBUS_TYPE_STRING, &temp);
	}
}

void __connman_technology_sta_count_changed(enum connman_service_type type, int stacount)
{
	struct connman_technology *technology;

	technology = technology_find(type);
	if (technology == NULL)
		return;

	connman_dbus_property_changed_basic(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE, "StaCount",
					DBUS_TYPE_INT32, &stacount);

	connman_dbus_property_changed_array(technology->path,
					CONNMAN_TECHNOLOGY_INTERFACE, "StationMac",
					DBUS_TYPE_STRING, append_station_mac, NULL);
}
