/*
 *
 *  WPA supplicant library with GLib integration
 *
 *  Copyright (C) 2012-2013  Intel Corporation. All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <syslog.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <glib.h>
#include <gdbus.h>

#include "dbus.h"
#include "gsupplicant.h"

#define IEEE80211_CAP_ESS	0x0001
#define IEEE80211_CAP_IBSS	0x0002
#define IEEE80211_CAP_PRIVACY	0x0010

#define BSS_UNKNOWN_STRENGTH    -90

#define WPAS_P2P_WPS_PIN_LENGTH		8
#define MAX_P2P_SSID_LEN			32

static DBusConnection *connection;

static const GSupplicantCallbacks *callbacks_pointer;

static dbus_bool_t system_available = FALSE;
static dbus_bool_t system_ready = FALSE;

static dbus_int32_t debug_level;
static dbus_bool_t debug_timestamp = FALSE;
static dbus_bool_t debug_showkeys = FALSE;

static const char *debug_strings[] = {
	"msgdump", "debug", "info", "warning", "error", NULL
};

static unsigned int eap_methods;

struct strvalmap {
	const char *str;
	unsigned int val;
};

static struct strvalmap eap_method_map[] = {
	{ "MD5",	G_SUPPLICANT_EAP_METHOD_MD5	},
	{ "TLS",	G_SUPPLICANT_EAP_METHOD_TLS	},
	{ "MSCHAPV2",	G_SUPPLICANT_EAP_METHOD_MSCHAPV2	},
	{ "PEAP",	G_SUPPLICANT_EAP_METHOD_PEAP	},
	{ "TTLS",	G_SUPPLICANT_EAP_METHOD_TTLS	},
	{ "GTC",	G_SUPPLICANT_EAP_METHOD_GTC	},
	{ "OTP",	G_SUPPLICANT_EAP_METHOD_OTP	},
	{ "LEAP",	G_SUPPLICANT_EAP_METHOD_LEAP	},
	{ "WSC",	G_SUPPLICANT_EAP_METHOD_WSC	},
	{ }
};

static struct strvalmap keymgmt_map[] = {
	{ "none",		G_SUPPLICANT_KEYMGMT_NONE		},
	{ "ieee8021x",		G_SUPPLICANT_KEYMGMT_IEEE8021X	},
	{ "wpa-none",		G_SUPPLICANT_KEYMGMT_WPA_NONE	},
	{ "wpa-psk",		G_SUPPLICANT_KEYMGMT_WPA_PSK	},
	{ "wpa-psk-sha256",	G_SUPPLICANT_KEYMGMT_WPA_PSK_256	},
	{ "wpa-ft-psk",		G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	},
	{ "wpa-ft-eap",		G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	},
	{ "wpa-eap",		G_SUPPLICANT_KEYMGMT_WPA_EAP	},
	{ "wpa-eap-sha256",	G_SUPPLICANT_KEYMGMT_WPA_EAP_256	},
	{ "wps",		G_SUPPLICANT_KEYMGMT_WPS		},
	{ "sae",		G_SUPPLICANT_KEYMGMT_SAE		},
	{ }
};

static struct strvalmap authalg_capa_map[] = {
	{ "open",	G_SUPPLICANT_CAPABILITY_AUTHALG_OPEN	},
	{ "shared",	G_SUPPLICANT_CAPABILITY_AUTHALG_SHARED	},
	{ "leap",	G_SUPPLICANT_CAPABILITY_AUTHALG_LEAP	},
	{ }
};

static struct strvalmap proto_capa_map[] = {
	{ "wpa",	G_SUPPLICANT_CAPABILITY_PROTO_WPA		},
	{ "rsn",	G_SUPPLICANT_CAPABILITY_PROTO_RSN		},
	{ }
};

static struct strvalmap group_map[] = {
	{ "wep40",	G_SUPPLICANT_GROUP_WEP40	},
	{ "wep104",	G_SUPPLICANT_GROUP_WEP104	},
	{ "tkip",	G_SUPPLICANT_GROUP_TKIP	},
	{ "ccmp",	G_SUPPLICANT_GROUP_CCMP	},
	{ }
};

static struct strvalmap pairwise_map[] = {
	{ "none",	G_SUPPLICANT_PAIRWISE_NONE	},
	{ "tkip",	G_SUPPLICANT_PAIRWISE_TKIP	},
	{ "ccmp",	G_SUPPLICANT_PAIRWISE_CCMP	},
	{ }
};

static struct strvalmap scan_capa_map[] = {
	{ "active",	G_SUPPLICANT_CAPABILITY_SCAN_ACTIVE	},
	{ "passive",	G_SUPPLICANT_CAPABILITY_SCAN_PASSIVE	},
	{ "ssid",	G_SUPPLICANT_CAPABILITY_SCAN_SSID		},
	{ }
};

static struct strvalmap mode_capa_map[] = {
	{ "infrastructure",	G_SUPPLICANT_CAPABILITY_MODE_INFRA	},
	{ "ad-hoc",		G_SUPPLICANT_CAPABILITY_MODE_IBSS	},
	{ "ap",			G_SUPPLICANT_CAPABILITY_MODE_AP		},
	{ "p2p", 		G_SUPPLICANT_CAPABILITY_MODE_P2P	},
	{ }
};

static GHashTable *interface_table;
static GHashTable *bss_mapping;
static GHashTable *peer_mapping;
static GHashTable *group_mapping;
static GHashTable *pending_peer_connection;
static GHashTable *config_file_table;
static GHashTable *intf_addr_mapping;
static GHashTable *dev_addr_mapping;
static GSList *p2p_network_list;
static GHashTable *p2p_peer_table;

typedef void (*g_supplicant_p2p_prov_dics_signal_func) (GSupplicantInterface *interface,
				GSupplicantPeer* peer, void* params);

struct _GSupplicantWpsCredentials {
	unsigned char ssid[32];
	unsigned int ssid_len;
	char *key;
};

struct added_network_information {
	char * ssid;
	GSupplicantSecurity security;
	char * passphrase;
	char * private_passphrase;
};

struct _GSupplicantInterface {
	char *path;
	char *network_path;
	unsigned int keymgmt_capa;
	unsigned int authalg_capa;
	unsigned int proto_capa;
	unsigned int group_capa;
	unsigned int pairwise_capa;
	unsigned int scan_capa;
	unsigned int mode_capa;
	unsigned int max_scan_ssids;
	unsigned int rssi;
	unsigned int link_speed;
	unsigned int frequency;
	unsigned int noise;
	bool p2p_support;
	bool p2p_finding;
	bool ap_create_in_progress;
	dbus_bool_t ready;
	GSupplicantState state;
	dbus_bool_t scanning;
	GSupplicantInterfaceCallback scan_callback;
	void *scan_data;
	int apscan;
	char *ifname;
	char *driver;
	char *bridge;
	struct _GSupplicantWpsCredentials wps_cred;
	GSupplicantWpsState wps_state;
	GHashTable *network_table;
	GHashTable *peer_table;
	GHashTable *group_table;
	GHashTable *bss_mapping;
	GHashTable *p2p_peer_path_to_network;
	GHashTable *p2p_group_path_to_group;
	void *data;
	const char *pending_peer_path;
	GSupplicantNetwork *current_network;
	struct added_network_information network_info;

	unsigned char p2p_device_address[6];

};

struct g_supplicant_bss {
	GSupplicantInterface *interface;
	char *path;
	unsigned char bssid[6];
	unsigned char ssid[32];
	unsigned int ssid_len;
	dbus_uint16_t frequency;
	dbus_uint32_t maxrate;
	dbus_int16_t signal;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	dbus_bool_t rsn_selected;
	unsigned int wpa_keymgmt;
	unsigned int wpa_pairwise;
	unsigned int wpa_group;
	unsigned int rsn_keymgmt;
	unsigned int rsn_pairwise;
	unsigned int rsn_group;
	unsigned int keymgmt;
	dbus_bool_t privacy;
	dbus_bool_t psk;
	dbus_bool_t ieee8021x;
	unsigned int wps_capabilities;
};

struct _GSupplicantP2PNetwork {
	GSupplicantInterface *interface;
	int found_ref;
	char *path;
	char *identifier; /* Device address in string 112233445566 format */
	char *group;
	char *name;
	unsigned char p2p_device_addr[6]; /* Device address in binary format */
	uint8_t pri_dev_type[8];
	uint8_t dev_capab;
	uint8_t group_capab;
	dbus_uint16_t config_methods;
	dbus_int32_t level;
	int wfd_dev_type;
	int wfd_session_avail;
	int wfd_cp_support;
	unsigned int wfd_rtsp_port;
	GSupplicantP2PService* asp_services;
	int asp_services_len;
	GHashTable *peer_table;
	connman_bool_t removed;
};

struct _GSupplicantNetwork {
	GSupplicantInterface *interface;
	char *path;
	char *group;
	char *name;
	unsigned char ssid[32];
	unsigned int ssid_len;
	dbus_int16_t signal;
	dbus_uint16_t frequency;
	struct g_supplicant_bss *best_bss;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	dbus_bool_t wps;
	unsigned int wps_capabilities;
	GHashTable *bss_table;
	GHashTable *config_table;
	unsigned int keymgmt;
};

struct _GSupplicantPeer {
	GSupplicantInterface *interface;
	char *path;
	unsigned char device_address[ETH_ALEN];
	unsigned char iface_address[ETH_ALEN];
	char *name;
	unsigned char *widi_ies;
	char *ip_addr;
	int widi_ies_length;
	char *identifier;
	dbus_uint16_t config_methods;
	unsigned int wps_capabilities;
	GSList *groups;
	const GSupplicantInterface *current_group_iface;
	bool connection_requested;
	dbus_int32_t level;

	GSupplicantP2PService* asp_services;
	int asp_services_len;
	int status;
	int found_pending_signal_timeout_ref;

	char *pri_dev_type;
	GSList* pending_signals; // List of ordered signals pending dispatch when peer properties are fetched and network is created
	GSList* pending_invitation_signals;
};

struct _GSupplicantRequestedPeer {
	char *requested_p2p_dev_addr;
	char *requested_path;
	char *requested_ip_addr;
	bool requested_is_ip_present;
	struct peer_device_data *found_p2p_network;
};

struct _GSupplicantGroup {
	GSupplicantInterface *interface;
	GSupplicantInterface *orig_interface;
	char *path;
	int role;
	GSList *members;
	char *ssid;
	char *passphrase;
	char *bssid_no_colon;
	bool persistent;
	int frequency;
	char *ip_addr;
	char *ip_mask;
	char *go_ip_addr;
	char *psk;
	GSupplicantP2PPersistentGroup *persistent_group;
};

struct _GSupplicantP2PInterface {
	char *path;
	GSupplicantP2PDeviceConfigParams *p2p_device_config_param;
};

struct interface_data {
	GSupplicantInterface *interface;
	char *path; /* Interface path cannot be taken from interface (above) as
		     * it might have been freed already.
		     */
	GSupplicantInterfaceCallback callback;
	void *user_data;
	bool network_remove_in_progress;
	GSupplicantSSID *ssid;
};

struct interface_create_data {
	char *ifname;
	char *driver;
	char *bridge;
	const char *config_file;
	const char *country_code;
	GSupplicantInterface *interface;
	char *interface_path;
	GSupplicantInterfaceCallback callback;
	void *user_data;
	unsigned char get_interface_timer_count;
};

struct interface_connect_data {
	GSupplicantInterface *interface;
	char *path;
	GSupplicantInterfaceCallback callback;
	void *user_data;
	union {
		GSupplicantSSID *ssid;
		GSupplicantPeerParams *peer;
	};
};

struct interface_wps_connect_data {
	GSupplicantInterface *interface;
	char *path;
	GSupplicantInterfaceCallback callback;
	GSupplicantSSID *ssid;
	void *user_data;
};

struct interface_scan_data {
	GSupplicantInterface *interface;
	char *path;
	GSupplicantInterfaceCallback callback;
	GSupplicantScanParams *scan_params;
	void *user_data;
};

struct interface_reject_data {
	GSupplicantInterface *interface;
	char *path;
	GSupplicantInterfaceCallback callback;
	void *user_data;
	GSupplicantPeerParams *peer;
};

struct interface_p2p_device_config {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PDeviceConfigParams *p2p_device_config_params;
	void *user_data;
};

typedef void (*g_supplicant_p2p_network_signal_func) (GSupplicantInterface *interface, GSupplicantPeer *peer, GSupplicantP2PSProvisionSignalParams* params);
typedef void (*g_supplicant_p2p_network_signal_free_func) (void* params);

struct g_supplicant_p2p_peer_signal {
	g_supplicant_p2p_network_signal_func dispatch_function;
	g_supplicant_p2p_network_signal_free_func free_function; // function to use for freeing the params
	void* callback_params;
};

struct g_supplicant_p2p_inv_recv_info {
	GSupplicantInterface *interface;
	const char *p2p_go_dev_addr;
	const char *src_addr;
	connman_bool_t persistent;
	unsigned char get_invitation_timer_count;
};

static int inv_recv_ref = -1;
static int scan_callback_ref;

static int network_remove(struct interface_data *data);
static gboolean get_interface_retry(void* user_data);

static inline void debug(const char *format, ...)
{
	char str[256];
	va_list ap;

	if (!callbacks_pointer || !callbacks_pointer->debug)
		return;

	va_start(ap, format);

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		callbacks_pointer->debug(str);

	va_end(ap);
}

#define SUPPLICANT_DBG(fmt, arg...) \
	debug("%s:%s() " fmt, __FILE__, __FUNCTION__ , ## arg);

static GSupplicantMode string2mode(const char *mode)
{
	if (!mode)
		return G_SUPPLICANT_MODE_UNKNOWN;

	if (g_str_equal(mode, "infrastructure"))
		return G_SUPPLICANT_MODE_INFRA;
	else if (g_str_equal(mode, "ad-hoc"))
		return G_SUPPLICANT_MODE_IBSS;

	return G_SUPPLICANT_MODE_UNKNOWN;
}

static const char *mode2string(GSupplicantMode mode)
{
	switch (mode) {
	case G_SUPPLICANT_MODE_UNKNOWN:
		break;
	case G_SUPPLICANT_MODE_INFRA:
		return "managed";
	case G_SUPPLICANT_MODE_IBSS:
		return "adhoc";
	case G_SUPPLICANT_MODE_MASTER:
		return "ap";
	}

	return NULL;
}

static const char *security2string(GSupplicantSecurity security)
{
	switch (security) {
	case G_SUPPLICANT_SECURITY_UNKNOWN:
		break;
	case G_SUPPLICANT_SECURITY_NONE:
		return "none";
	case G_SUPPLICANT_SECURITY_WEP:
		return "wep";
	case G_SUPPLICANT_SECURITY_PSK:
		return "psk";
	case G_SUPPLICANT_SECURITY_IEEE8021X:
		return "ieee8021x";
	}

	return NULL;
}

static GSupplicantState string2state(const char *state)
{
	if (!state)
		return G_SUPPLICANT_STATE_UNKNOWN;

	if (g_str_equal(state, "unknown"))
		return G_SUPPLICANT_STATE_UNKNOWN;
	else if (g_str_equal(state, "interface_disabled"))
		return G_SUPPLICANT_STATE_DISABLED;
	else if (g_str_equal(state, "disconnected"))
		return G_SUPPLICANT_STATE_DISCONNECTED;
	else if (g_str_equal(state, "inactive"))
		return G_SUPPLICANT_STATE_INACTIVE;
	else if (g_str_equal(state, "scanning"))
		return G_SUPPLICANT_STATE_SCANNING;
	else if (g_str_equal(state, "authenticating"))
		return G_SUPPLICANT_STATE_AUTHENTICATING;
	else if (g_str_equal(state, "associating"))
		return G_SUPPLICANT_STATE_ASSOCIATING;
	else if (g_str_equal(state, "associated"))
		return G_SUPPLICANT_STATE_ASSOCIATED;
	else if (g_str_equal(state, "group_handshake"))
		return G_SUPPLICANT_STATE_GROUP_HANDSHAKE;
	else if (g_str_equal(state, "4way_handshake"))
		return G_SUPPLICANT_STATE_4WAY_HANDSHAKE;
	else if (g_str_equal(state, "completed"))
		return G_SUPPLICANT_STATE_COMPLETED;

	return G_SUPPLICANT_STATE_UNKNOWN;
}

static bool compare_network_parameters(GSupplicantInterface *interface,
				GSupplicantSSID *ssid)
{
	if (memcmp(interface->network_info.ssid, ssid->ssid, ssid->ssid_len))
		return FALSE;

	if (interface->network_info.security != ssid->security)
		return FALSE;

	if (interface->network_info.passphrase &&
			g_strcmp0(interface->network_info.passphrase,
				ssid->passphrase) != 0) {
		return FALSE;
	}

	if (interface->network_info.private_passphrase &&
			g_strcmp0(interface->network_info.private_passphrase,
				ssid->private_key_passphrase) != 0) {
		return FALSE;
	}

	return TRUE;
}

static void remove_network_information(GSupplicantInterface * interface)
{
	g_free(interface->network_info.ssid);
	g_free(interface->network_info.passphrase);
	g_free(interface->network_info.private_passphrase);
	interface->network_info.ssid = NULL;
	interface->network_info.passphrase = NULL;
	interface->network_info.private_passphrase = NULL;
}

static int store_network_information(GSupplicantInterface * interface,
				GSupplicantSSID *ssid)
{
	interface->network_info.ssid = g_malloc(ssid->ssid_len + 1);
	if (interface->network_info.ssid != NULL) {
		memcpy(interface->network_info.ssid, ssid->ssid,
			ssid->ssid_len);
		interface->network_info.ssid[ssid->ssid_len] = '\0';
	} else {
		return -ENOMEM;
	}

	interface->network_info.security = ssid->security;

	if ((ssid->security == G_SUPPLICANT_SECURITY_WEP ||
		ssid->security == G_SUPPLICANT_SECURITY_PSK ||
		ssid->security == G_SUPPLICANT_SECURITY_NONE) &&
		ssid->passphrase) {
		interface->network_info.passphrase = g_strdup(ssid->passphrase);
	}

	if (ssid->security == G_SUPPLICANT_SECURITY_IEEE8021X &&
			ssid->private_key_passphrase) {
		interface->network_info.private_passphrase =
			g_strdup(ssid->private_key_passphrase);
	}

	return 0;
}

static void callback_system_ready(void)
{
	if (system_ready)
		return;

	system_ready = TRUE;

	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->system_ready)
		return;

	callbacks_pointer->system_ready();
}

static void callback_system_killed(void)
{
	system_ready = FALSE;

	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->system_killed)
		return;

	callbacks_pointer->system_killed();
}

static void callback_interface_added(GSupplicantInterface *interface)
{
	SUPPLICANT_DBG("");

	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->interface_added)
		return;

	callbacks_pointer->interface_added(interface);
}

static void callback_interface_state(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->interface_state)
		return;

	callbacks_pointer->interface_state(interface);
}

static void callback_interface_removed(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->interface_removed)
		return;

	callbacks_pointer->interface_removed(interface);
}

static void callback_p2p_support(GSupplicantInterface *interface)
{
	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return;

	if (callbacks_pointer && callbacks_pointer->p2p_support)
		callbacks_pointer->p2p_support(interface);
}

static void callback_p2p_device_config_loaded(GSupplicantInterface *interface)
{
	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return;

	if (callbacks_pointer && callbacks_pointer->p2p_device_config_loaded)
		callbacks_pointer->p2p_device_config_loaded(interface);
}

static void callback_scan_started(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->scan_started)
		return;

	callbacks_pointer->scan_started(interface);
}

static void callback_ap_create_fail(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->ap_create_fail)
		return;

	callbacks_pointer->ap_create_fail(interface);
}

static void callback_scan_finished(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->scan_finished)
		return;

	callbacks_pointer->scan_finished(interface);
}

static void callback_network_added(GSupplicantNetwork *network)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->network_added)
		return;

	callbacks_pointer->network_added(network);
}

static void callback_network_removed(GSupplicantNetwork *network)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->network_removed)
		return;

	callbacks_pointer->network_removed(network);
}

static void callback_network_changed(GSupplicantNetwork *network,
					const char *property)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->network_changed)
		return;

	callbacks_pointer->network_changed(network, property);
}

static void callback_network_associated(GSupplicantNetwork *network)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->network_associated)
		return;

	callbacks_pointer->network_associated(network);
}

static void callback_sta_authorized(GSupplicantInterface *interface,
					const char *addr)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->sta_authorized)
		return;

	callbacks_pointer->sta_authorized(interface, addr);
}

static void callback_sta_deauthorized(GSupplicantInterface *interface,
					const char *addr)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->sta_deauthorized)
		return;

	callbacks_pointer->sta_deauthorized(interface, addr);
}

static void callback_peer_found(GSupplicantPeer *peer)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->peer_found)
		return;

	callbacks_pointer->peer_found(peer);
}

static void callback_peer_lost(GSupplicantPeer *peer)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->peer_lost)
		return;

	callbacks_pointer->peer_lost(peer);
}

static void callback_peer_changed(GSupplicantPeer *peer,
						GSupplicantPeerState state)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->peer_changed)
		return;

	callbacks_pointer->peer_changed(peer, state);
}

static void callback_p2p_group_started(GSupplicantGroup *group)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_group_started)
		return;

	callbacks_pointer->p2p_group_started(group);
}

static void callback_p2p_group_finished(GSupplicantInterface *interface)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_group_finished)
		return;

	callbacks_pointer->p2p_group_finished(interface);
}

static void callback_p2ps_prov_start(GSupplicantInterface *interface, GSupplicantPeer *peer,
                                       GSupplicantP2PSProvisionSignalParams* params)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2ps_prov_start == NULL)
		return;

	callbacks_pointer->p2ps_prov_start(interface,peer, params);
}

static void callback_p2ps_prov_done(GSupplicantInterface *interface, GSupplicantPeer *peer,
                                    GSupplicantP2PSProvisionSignalParams* params)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2ps_prov_done == NULL)
		return;

	callbacks_pointer->p2ps_prov_done(interface,peer, params);
}

static void callback_p2p_prov_disc_requested_pbc(GSupplicantInterface *interface,
					GSupplicantPeer *peer, void * data)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_requested_pbc)
		return;

	callbacks_pointer->p2p_prov_disc_requested_pbc(interface, peer);
}

static void callback_p2p_prov_disc_requested_enter_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, void * data)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_requested_enter_pin)
		return;

	callbacks_pointer->p2p_prov_disc_requested_enter_pin(interface, peer);
}

static void callback_p2p_prov_disc_requested_display_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, const char *pin)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_requested_display_pin)
		return;

	callbacks_pointer->p2p_prov_disc_requested_display_pin(interface, peer, pin);
}

static void callback_p2p_prov_disc_response_enter_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, void * data)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_requested_enter_pin)
		return;

	callbacks_pointer->p2p_prov_disc_response_enter_pin(interface, peer);
}

static void callback_p2p_prov_disc_response_display_pin(GSupplicantInterface *interface,
					GSupplicantPeer *peer, const char *pin)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_requested_display_pin)
		return;

	callbacks_pointer->p2p_prov_disc_response_display_pin(interface, peer, pin);
}

static void callback_p2p_prov_disc_fail(GSupplicantInterface *interface,
					GSupplicantPeer *peer, const char *pin)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_prov_disc_fail)
		return;

	callbacks_pointer->p2p_prov_disc_fail(interface, peer, pin);
}

GSupplicantInterface *g_supplicant_group_get_interface(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->interface;
}

GSupplicantInterface *g_supplicant_group_get_orig_interface(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->orig_interface;
}

char *g_supplicant_group_get_bssid_no_colon(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->bssid_no_colon;
}

char *g_supplicant_group_get_object_path(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->path;
}

char *g_supplicant_group_get_ssid(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->ssid;
}

char *g_supplicant_group_get_passphrase(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->passphrase;
}

int g_supplicant_group_get_frequency(GSupplicantGroup *group)
{
	if(!group)
		return 0;

	return group->frequency;
}

int g_supplicant_group_get_role(GSupplicantGroup *group)
{
	if(!group)
		return 0;

	return group->role;
}

bool g_supplicant_group_get_persistent(GSupplicantGroup *group)
{
	if(!group)
		return false;

	return group->persistent;
}

char *g_supplicant_group_get_ip_addr(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->ip_addr;
}

char *g_supplicant_group_get_ip_mask(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->ip_mask;
}

char *g_supplicant_group_get_go_ip_addr(GSupplicantGroup *group)
{
	if(!group)
		return NULL;

	return group->go_ip_addr;
}

static void callback_peer_request(GSupplicantPeer *peer, int dev_passwd_id)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->peer_request)
		return;

	peer->connection_requested = true;

	callbacks_pointer->peer_request(peer, dev_passwd_id);
}

static void callback_disconnect_reason_code(GSupplicantInterface *interface,
					int reason_code)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->disconnect_reasoncode)
		return;

	if (reason_code != 0)
		callbacks_pointer->disconnect_reasoncode(interface,
							reason_code);
}


static void callback_p2p_persistent_group_added(GSupplicantInterface *interface, GSupplicantP2PPersistentGroup *group)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2p_persistent_group_added == NULL)
		return;

	callbacks_pointer->p2p_persistent_group_added(interface, group);
}
static void callback_p2p_persistent_group_removed(GSupplicantInterface *interface, const char *persistent_group_path)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2p_persistent_group_removed == NULL)
		return;

	callbacks_pointer->p2p_persistent_group_removed(interface, persistent_group_path);
}
static void callback_p2p_sd_response(GSupplicantInterface *interface, GSupplicantPeer *peer,
											int indicator, unsigned char *tlv, int tlv_len)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2p_sd_response == NULL)
		return;

	callbacks_pointer->p2p_sd_response(interface, peer, indicator, tlv, tlv_len);
}

static void callback_assoc_status_code(GSupplicantInterface *interface,
				int status_code)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->assoc_status_code)
		return;

	callbacks_pointer->assoc_status_code(interface, status_code);

}

static void remove_group(gpointer data)
{
	GSupplicantGroup *group = data;

	if (group->members)
		g_slist_free_full(group->members, g_free);

	g_free(group->path);
	g_free(group->bssid_no_colon);
	g_free(group->ip_addr);
	g_free(group->ip_mask);
	g_free(group->go_ip_addr);
	g_free(group->ssid);
	g_free(group->psk);
	g_free(group->passphrase);
	g_free(group);
}

static void callback_wps_state(GSupplicantInterface *interface)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->wps_state == NULL)
		return;

	callbacks_pointer->wps_state(interface);
}

static void remove_interface(gpointer data)
{
	GSupplicantInterface *interface = data;

	g_hash_table_destroy(interface->bss_mapping);
	g_hash_table_destroy(interface->network_table);
	g_hash_table_destroy(interface->peer_table);
	g_hash_table_destroy(interface->group_table);
	if (interface->p2p_peer_path_to_network) {
		g_hash_table_destroy(interface->p2p_peer_path_to_network);
		interface->p2p_peer_path_to_network = NULL;
	}

	if (interface->p2p_group_path_to_group) {
		g_hash_table_destroy(interface->p2p_group_path_to_group);
		interface->p2p_group_path_to_group = NULL;
	}

	if (interface->scan_callback) {
		SUPPLICANT_DBG("call interface %p callback %p scanning %d",
				interface, interface->scan_callback,
				interface->scanning);

		interface->scan_callback(-EIO, interface, interface->scan_data);
                interface->scan_callback = NULL;
                interface->scan_data = NULL;

		if (interface->scanning) {
			interface->scanning = FALSE;
			callback_scan_finished(interface);
		}
	}

	callback_interface_removed(interface);

	g_free(interface->wps_cred.key);
	g_free(interface->path);
	g_free(interface->network_path);
	g_free(interface->ifname);
	g_free(interface->driver);
	g_free(interface->bridge);
	remove_network_information(interface);
	g_free(interface);
}

static void remove_network(gpointer data)
{
	GSupplicantNetwork *network = data;

	g_hash_table_destroy(network->bss_table);

	callback_network_removed(network);

	g_hash_table_destroy(network->config_table);

	g_free(network->path);
	g_free(network->group);
	g_free(network->name);
	g_free(network);
}

static void remove_bss(gpointer data)
{
	struct g_supplicant_bss *bss = data;

	supplicant_dbus_property_call_cancel_all(bss);

	g_free(bss->path);
	g_free(bss);
}

static void remove_peer(gpointer data)
{
	GSupplicantPeer *peer = data;

	SUPPLICANT_DBG("peer %p", peer);
	callback_peer_lost(peer);

	if (peer->groups)
		g_slist_free_full(peer->groups, g_free);

	if (peer_mapping)
		g_hash_table_remove(peer_mapping, peer->path);

	if (pending_peer_connection)
		g_hash_table_remove(pending_peer_connection, peer->path);

	if (p2p_peer_table)
		g_hash_table_remove(p2p_peer_table, peer->path);

	if (peer->found_pending_signal_timeout_ref > 0){
		g_source_remove(peer->found_pending_signal_timeout_ref);
		peer->found_pending_signal_timeout_ref = 0;
	}

	g_free(peer->path);
	g_free(peer->name);
	g_free(peer->identifier);
	g_free(peer->widi_ies);
	g_free(peer->pri_dev_type);
	g_free(peer->ip_addr);

	g_free(peer);
}

static void debug_strvalmap(const char *label, struct strvalmap *map,
							unsigned int val)
{
	int i;

	for (i = 0; map[i].str; i++) {
		if (val & map[i].val)
			SUPPLICANT_DBG("%s: %s", label, map[i].str);
	}
}

static void interface_capability_keymgmt(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; keymgmt_map[i].str; i++)
		if (strcmp(str, keymgmt_map[i].str) == 0) {
			interface->keymgmt_capa |= keymgmt_map[i].val;
			break;
		}
}

static void interface_capability_authalg(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; authalg_capa_map[i].str; i++)
		if (strcmp(str, authalg_capa_map[i].str) == 0) {
			interface->authalg_capa |= authalg_capa_map[i].val;
			break;
		}
}

static void interface_capability_proto(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; proto_capa_map[i].str; i++)
		if (strcmp(str, proto_capa_map[i].str) == 0) {
			interface->proto_capa |= proto_capa_map[i].val;
			break;
		}
}

static void interface_capability_pairwise(DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; pairwise_map[i].str; i++)
		if (strcmp(str, pairwise_map[i].str) == 0) {
			interface->pairwise_capa |= pairwise_map[i].val;
			break;
		}
}

static void interface_capability_group(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; group_map[i].str; i++)
		if (strcmp(str, group_map[i].str) == 0) {
			interface->group_capa |= group_map[i].val;
			break;
		}
}

static void interface_capability_scan(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; scan_capa_map[i].str; i++)
		if (strcmp(str, scan_capa_map[i].str) == 0) {
			interface->scan_capa |= scan_capa_map[i].val;
			break;
		}
}

static void interface_capability_mode(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; mode_capa_map[i].str; i++)
		if (strcmp(str, mode_capa_map[i].str) == 0) {
			interface->mode_capa |= mode_capa_map[i].val;
			break;
		}
}

static void interface_capability(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (!key)
		return;

	if (g_strcmp0(key, "KeyMgmt") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_keymgmt, interface);
	else if (g_strcmp0(key, "AuthAlg") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_authalg, interface);
	else if (g_strcmp0(key, "Protocol") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_proto, interface);
	else if (g_strcmp0(key, "Pairwise") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_pairwise, interface);
	else if (g_strcmp0(key, "Group") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_group, interface);
	else if (g_strcmp0(key, "Scan") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_scan, interface);
	else if (g_strcmp0(key, "Modes") == 0)
		supplicant_dbus_array_foreach(iter,
				interface_capability_mode, interface);
	else if (g_strcmp0(key, "MaxScanSSID") == 0) {
		dbus_int32_t max_scan_ssid;

		dbus_message_iter_get_basic(iter, &max_scan_ssid);
		if (max_scan_ssid < 2)
			max_scan_ssid = 0;
		interface->max_scan_ssids = max_scan_ssid;

	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void set_bss_expiration_age(DBusMessageIter *iter, void *user_data)
{
	unsigned int bss_expiration_age = GPOINTER_TO_UINT(user_data);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32,
				&bss_expiration_age);
}

int g_supplicant_interface_set_bss_expiration_age(GSupplicantInterface *interface,
					unsigned int bss_expiration_age)
{
       return supplicant_dbus_property_set(interface->path,
				       SUPPLICANT_INTERFACE ".Interface",
				       "BSSExpireAge", DBUS_TYPE_UINT32_AS_STRING,
				       set_bss_expiration_age, NULL,
				       GUINT_TO_POINTER(bss_expiration_age), NULL);
}

struct set_apscan_data
{
	unsigned int ap_scan;
	GSupplicantInterface *interface;
};

static void set_apscan(DBusMessageIter *iter, void *user_data)
{
	struct set_apscan_data *data = user_data;
	unsigned int ap_scan = data->ap_scan;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT32, &ap_scan);
}

static void set_apscan_complete(const char *error,
		DBusMessageIter *iter, void *user_data)
{
	struct set_apscan_data *data = user_data;
	GSupplicantInterface *interface = data->interface;

	if (error) {
		interface->ap_create_in_progress = false;
		SUPPLICANT_DBG("Set AP scan error %s", error);
		goto error;
	}

	interface->ap_create_in_progress = true;
error:
	dbus_free(data);
}

int g_supplicant_interface_set_apscan(GSupplicantInterface *interface,
							unsigned int ap_scan)
{
	struct set_apscan_data *data;
	int ret;

	data = dbus_malloc0(sizeof(*data));

	if (!data)
		return -ENOMEM;

	data->ap_scan = ap_scan;
	data->interface = interface;

	ret = supplicant_dbus_property_set(interface->path,
			SUPPLICANT_INTERFACE ".Interface",
			"ApScan", DBUS_TYPE_UINT32_AS_STRING,
			set_apscan, set_apscan_complete, data, NULL);
	if (ret < 0)
		dbus_free(data);

	return ret;
}

void g_supplicant_interface_set_data(GSupplicantInterface *interface,
								void *data)
{
	if (!interface)
		return;

	interface->data = data;

	if (!data)
		interface->scan_callback = NULL;
}

void *g_supplicant_interface_get_data(GSupplicantInterface *interface)
{
	if (!interface)
		return NULL;

	return interface->data;
}

const char *g_supplicant_interface_get_ifname(GSupplicantInterface *interface)
{
	if (!interface)
		return NULL;

	return interface->ifname;
}

const char *g_supplicant_interface_get_driver(GSupplicantInterface *interface)
{
	if (!interface)
		return NULL;

	return interface->driver;
}

GSupplicantState g_supplicant_interface_get_state(
					GSupplicantInterface *interface)
{
	if (!interface)
		return G_SUPPLICANT_STATE_UNKNOWN;

	return interface->state;
}

const char *g_supplicant_interface_get_wps_key(GSupplicantInterface *interface)
{
	if (!interface)
		return NULL;

	return (const char *)interface->wps_cred.key;
}

const void *g_supplicant_interface_get_wps_ssid(GSupplicantInterface *interface,
							unsigned int *ssid_len)
{
	if (!ssid_len)
		return NULL;

	if (!interface || interface->wps_cred.ssid_len == 0) {
		*ssid_len = 0;
		return NULL;
	}

	*ssid_len = interface->wps_cred.ssid_len;
	return interface->wps_cred.ssid;
}

GSupplicantWpsState g_supplicant_interface_get_wps_state(
					GSupplicantInterface *interface)
{
	if (!interface)
		return G_SUPPLICANT_WPS_STATE_UNKNOWN;

	return interface->wps_state;
}

unsigned int g_supplicant_interface_get_mode(GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->mode_capa;
}

unsigned int g_supplicant_interface_get_max_scan_ssids(
				GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->max_scan_ssids;
}

unsigned int g_supplicant_interface_get_rssi(GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->rssi;
}
unsigned int g_supplicant_interface_get_link_speed(GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->link_speed;
}

unsigned int g_supplicant_interface_get_frequency(GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->frequency;
}

unsigned int g_supplicant_interface_get_noise(GSupplicantInterface *interface)
{
	if (!interface)
		return 0;

	return interface->noise;
}

void g_supplicant_interface_set_p2p_persistent_group(GSupplicantInterface *interface, GSupplicantGroup *group, GSupplicantP2PPersistentGroup *persistent_group)
{
	group->persistent_group = persistent_group;
	g_hash_table_replace(interface->p2p_group_path_to_group, group->path, group);
}

GSupplicantP2PPersistentGroup* g_supplicant_interface_get_p2p_persistent_group(GSupplicantInterface *interface, GSupplicantGroup *group)
{
	if (!group)
		return NULL;

	return group->persistent_group;
}
static void set_network_enabled(DBusMessageIter *iter, void *user_data)
{
	dbus_bool_t enable = *(dbus_bool_t *)user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &enable);
}

int g_supplicant_interface_enable_selected_network(GSupplicantInterface *interface,
							dbus_bool_t enable)
{
	if (!interface)
		return -1;

	if (!interface->network_path)
		return -1;

	SUPPLICANT_DBG(" ");
	return supplicant_dbus_property_set(interface->network_path,
				SUPPLICANT_INTERFACE ".Network",
				"Enabled", DBUS_TYPE_BOOLEAN_AS_STRING,
				set_network_enabled, NULL, &enable, NULL);
}

dbus_bool_t g_supplicant_interface_get_ready(GSupplicantInterface *interface)
{
	if (!interface)
		return FALSE;

	return interface->ready;
}

GSupplicantInterface *g_supplicant_network_get_interface(
					GSupplicantNetwork *network)
{
	if (!network)
		return NULL;

	return network->interface;
}

const char *g_supplicant_network_get_name(GSupplicantNetwork *network)
{
	if (!network || !network->name)
		return "";

	return network->name;
}

const char *g_supplicant_network_get_identifier(GSupplicantNetwork *network)
{
	if (!network || !network->group)
		return "";

	return network->group;
}

const char *g_supplicant_network_get_path(GSupplicantNetwork *network)
{
	if (!network || !network->path)
		return NULL;

	return network->path;
}

const char *g_supplicant_network_get_mode(GSupplicantNetwork *network)
{
	if (!network)
		return G_SUPPLICANT_MODE_UNKNOWN;

	return mode2string(network->mode);
}

const char *g_supplicant_network_get_security(GSupplicantNetwork *network)
{
	if (!network)
		return NULL;

	return security2string(network->security);
}

const void *g_supplicant_network_get_ssid(GSupplicantNetwork *network,
						unsigned int *ssid_len)
{
	if (!network) {
		*ssid_len = 0;
		return NULL;
	}

	*ssid_len = network->ssid_len;
	return network->ssid;
}

dbus_int16_t g_supplicant_network_get_signal(GSupplicantNetwork *network)
{
	if (!network)
		return 0;

	return network->signal;
}

dbus_uint16_t g_supplicant_network_get_frequency(GSupplicantNetwork *network)
{
	if (!network)
		return 0;

	return network->frequency;
}

dbus_bool_t g_supplicant_network_get_wps(GSupplicantNetwork *network)
{
	if (!network)
		return FALSE;

	return network->wps;
}

dbus_bool_t g_supplicant_network_is_wps_active(GSupplicantNetwork *network)
{
	if (!network)
		return FALSE;

	if (network->wps_capabilities & G_SUPPLICANT_WPS_CONFIGURED)
		return TRUE;

	return FALSE;
}

dbus_bool_t g_supplicant_network_is_wps_pbc(GSupplicantNetwork *network)
{
	if (!network)
		return FALSE;

	if (network->wps_capabilities & G_SUPPLICANT_WPS_PBC)
		return TRUE;

	return FALSE;
}

dbus_bool_t g_supplicant_network_is_wps_advertizing(GSupplicantNetwork *network)
{
	if (!network)
		return FALSE;

	if (network->wps_capabilities & G_SUPPLICANT_WPS_REGISTRAR)
		return TRUE;

	return FALSE;
}

const unsigned char *g_supplicant_network_get_bssid(GSupplicantNetwork *network)
{
	if (!network || !network->best_bss)
		return NULL;

	return network->best_bss->bssid;
}
GHashTable *g_supplicant_network_get_bss_table(GSupplicantNetwork *network)
{
	if (!network)
		return NULL;

	return network->bss_table;
}

const unsigned char *g_supplicant_bss_get_bssid(GSupplicantBss *bss)
{
	if (!bss)
		return NULL;

	return bss->bssid;
}

dbus_int16_t g_supplicant_bss_get_signal(GSupplicantBss *bss)
{
	if (!bss)
		return 0;

	return bss->signal;
}

dbus_uint16_t g_supplicant_bss_get_frequency(GSupplicantBss *bss)
{
	if (!bss)
		return 0;

	return bss->frequency;
}

GSupplicantInterface *g_supplicant_peer_get_interface(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->interface;
}

const char *g_supplicant_peer_get_path(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->path;
}

dbus_uint16_t g_supplicant_peer_get_config_methods(GSupplicantPeer *peer)
{
	if (!peer)
		return 0;

	return peer->config_methods;
}

const char *g_supplicant_peer_get_identifier(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->identifier;
}

const void *g_supplicant_peer_get_device_address(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->device_address;
}

const void *g_supplicant_peer_get_iface_address(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->iface_address;
}

const char *g_supplicant_peer_get_ip_address(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->ip_addr;
}
const char *g_supplicant_peer_get_name(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->name;
}

const unsigned char *g_supplicant_peer_get_widi_ies(GSupplicantPeer *peer,
								int *length)
{
	if (!peer || !length)
		return NULL;

	*length = peer->widi_ies_length;
	return peer->widi_ies;
}
dbus_int32_t g_supplicant_peer_get_level(GSupplicantPeer *peer)
{
	if (!peer)
		return 0;

	return peer->level;
}
const char *g_supplicant_peer_get_pri_dev_type(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return peer->pri_dev_type;
}

int g_supplicant_peer_get_failure_status(GSupplicantPeer *peer)
{
	if (!peer)
		return 0;

	return peer->status;
}

bool g_supplicant_peer_is_wps_pbc(GSupplicantPeer *peer)
{
	if (!peer)
		return false;

	if (peer->wps_capabilities & G_SUPPLICANT_WPS_PBC)
		return true;

	return false;
}

bool g_supplicant_peer_is_wps_pin(GSupplicantPeer *peer)
{
	if (!peer)
		return false;

	if (peer->wps_capabilities & G_SUPPLICANT_WPS_PIN)
		return true;

	return false;
}

bool g_supplicant_peer_is_in_a_group(GSupplicantPeer *peer)
{
	if (!peer || !peer->groups)
		return false;

	return true;
}

GSupplicantInterface *g_supplicant_peer_get_group_interface(GSupplicantPeer *peer)
{
	if (!peer)
		return NULL;

	return (GSupplicantInterface *) peer->current_group_iface;
}

bool g_supplicant_peer_is_client(GSupplicantPeer *peer)
{
	GSupplicantGroup *group;
	GSList *list;

	if (!peer)
		return false;

	for (list = peer->groups; list; list = list->next) {
		const char *path = list->data;

		group = g_hash_table_lookup(group_mapping, path);
		if (!group)
			continue;

		if (group->role != G_SUPPLICANT_GROUP_ROLE_CLIENT ||
				group->orig_interface != peer->interface)
			continue;

		if (group->interface == peer->current_group_iface)
			return true;
	}

	return false;
}

bool g_supplicant_peer_has_requested_connection(GSupplicantPeer *peer)
{
	if (!peer)
		return false;

	return peer->connection_requested;
}

unsigned int g_supplicant_network_get_keymgmt(GSupplicantNetwork *network)
{
	if (!network)
		return 0;

	return network->keymgmt;
}

static void merge_network(GSupplicantNetwork *network)
{
	GString *str;
	const char *ssid, *mode, *key_mgmt;
	unsigned int i, ssid_len;
	char *group;

	ssid = g_hash_table_lookup(network->config_table, "ssid");
	mode = g_hash_table_lookup(network->config_table, "mode");
	key_mgmt = g_hash_table_lookup(network->config_table, "key_mgmt");

	SUPPLICANT_DBG("ssid %s mode %s", ssid, mode);

	if (ssid)
		ssid_len = strlen(ssid);
	else
		ssid_len = 0;

	str = g_string_sized_new((ssid_len * 2) + 24);
	if (!str)
		return;

	for (i = 0; i < ssid_len; i++)
		g_string_append_printf(str, "%02x", ssid[i]);

	if (g_strcmp0(mode, "0") == 0)
		g_string_append_printf(str, "_managed");
	else if (g_strcmp0(mode, "1") == 0)
		g_string_append_printf(str, "_adhoc");

	if ((g_strcmp0(key_mgmt, "WPA-PSK") == 0) ||
	    (g_strcmp0(key_mgmt, "SAE") == 0))
		g_string_append_printf(str, "_psk");

	group = g_string_free(str, FALSE);

	SUPPLICANT_DBG("%s", group);

	g_free(group);

	g_hash_table_destroy(network->config_table);

	g_free(network->path);
	g_free(network);
}

static void network_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantNetwork *network = user_data;

	if (!network->interface)
		return;

	if (!key) {
		merge_network(network);
		return;
	}

	if (g_strcmp0(key, "Enabled") == 0) {
		dbus_bool_t enabled = FALSE;

		dbus_message_iter_get_basic(iter, &enabled);
	} else if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str) {
			g_hash_table_replace(network->config_table,
						g_strdup(key), g_strdup(str));
		}
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void interface_network_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	const char *path = NULL;

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	network = g_try_new0(GSupplicantNetwork, 1);
	if (!network)
		return;

	network->interface = interface;
	network->path = g_strdup(path);

	network->config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, network_property,
								network);
		network_property(NULL, NULL, network);
		return;
	}

	supplicant_dbus_property_get_all(path,
				SUPPLICANT_INTERFACE ".Network",
					network_property, network, NULL);
}

static void interface_network_removed(DBusMessageIter *iter, void *user_data)
{
	SUPPLICANT_DBG("");
}

static char *create_name(unsigned char *ssid, int ssid_len)
{
	GString *string;
	const gchar *remainder, *invalid;
	int valid_bytes, remaining_bytes;

	if (ssid_len < 1 || ssid[0] == '\0')
		return g_strdup("");

	string = NULL;
	remainder = (const gchar *)ssid;
	remaining_bytes = ssid_len;

	while (remaining_bytes != 0) {
		if (g_utf8_validate(remainder, remaining_bytes,
					&invalid)) {
			break;
		}

		valid_bytes = invalid - remainder;

		if (!string)
			string = g_string_sized_new(remaining_bytes);

		g_string_append_len(string, remainder, valid_bytes);

		/* append U+FFFD REPLACEMENT CHARACTER */
		g_string_append(string, "\357\277\275");

		remaining_bytes -= valid_bytes + 1;
		remainder = invalid + 1;
	}

	if (!string)
		return g_strndup((const gchar *)ssid, ssid_len + 1);

	g_string_append(string, remainder);

	return g_string_free(string, FALSE);
}

static char *create_group(struct g_supplicant_bss *bss)
{
	GString *str;
	unsigned int i;
	const char *mode, *security;

	str = g_string_sized_new((bss->ssid_len * 2) + 24);
	if (!str)
		return NULL;

	if (bss->ssid_len > 0 && bss->ssid[0] != '\0') {
		for (i = 0; i < bss->ssid_len; i++)
			g_string_append_printf(str, "%02x", bss->ssid[i]);
	} else
		g_string_append_printf(str, "hidden");

	mode = mode2string(bss->mode);
	if (mode)
		g_string_append_printf(str, "_%s", mode);

	security = security2string(bss->security);
	if (security)
		g_string_append_printf(str, "_%s", security);

	return g_string_free(str, FALSE);
}

static int add_or_replace_bss_to_network(struct g_supplicant_bss *bss)
{
	GSupplicantInterface *interface = bss->interface;
	GSupplicantNetwork *network;
	char *group;
	bool is_new_network;

	group = create_group(bss);
	SUPPLICANT_DBG("New group created: %s", group);

	if (!group)
		return -ENOMEM;

	network = g_hash_table_lookup(interface->network_table, group);
	if (network) {
		g_free(group);
		SUPPLICANT_DBG("Network %s already exist", network->name);
		is_new_network = false;

		goto done;
	}

	is_new_network = true;

	network = g_try_new0(GSupplicantNetwork, 1);
	if (!network) {
		g_free(group);
		return -ENOMEM;
	}

	network->interface = interface;
	if (!network->path)
		network->path = g_strdup(bss->path);
	network->group = group;
	network->name = create_name(bss->ssid, bss->ssid_len);
	network->mode = bss->mode;
	network->security = bss->security;
	network->keymgmt = bss->keymgmt;
	network->ssid_len = bss->ssid_len;
	memcpy(network->ssid, bss->ssid, bss->ssid_len);
	network->signal = bss->signal;
	network->frequency = bss->frequency;
	network->best_bss = bss;

	if ((bss->keymgmt & G_SUPPLICANT_KEYMGMT_WPS) != 0) {
		network->wps = TRUE;
		network->wps_capabilities = bss->wps_capabilities;
	}

	SUPPLICANT_DBG("New network %s created", network->name);

	network->bss_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, remove_bss);

	network->config_table = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, g_free);

	g_hash_table_replace(interface->network_table,
						network->group, network);

	callback_network_added(network);

done:
	/* We update network's WPS properties if only bss provides WPS. */
	if ((bss->keymgmt & G_SUPPLICANT_KEYMGMT_WPS) != 0) {
		network->wps = TRUE;
		network->wps_capabilities = bss->wps_capabilities;

		if (!is_new_network)
			callback_network_changed(network, "WPSCapabilities");
	}

	/*
	 * Do not change best BSS if we are connected. It will be done through
	 * CurrentBSS property in case of misalignment with wpa_s or roaming.
	 */
	if (network != interface->current_network &&
				bss->signal > network->signal) {
		network->signal = bss->signal;
		network->best_bss = bss;
		callback_network_changed(network, "Signal");
	}

	g_hash_table_replace(interface->bss_mapping, bss->path, network);
	g_hash_table_replace(network->bss_table, bss->path, bss);

	g_hash_table_replace(bss_mapping, bss->path, interface);

	return 0;
}

static void bss_rates(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	dbus_uint32_t rate = 0;

	dbus_message_iter_get_basic(iter, &rate);
	if (rate == 0)
		return;

	if (rate > bss->maxrate)
		bss->maxrate = rate;
}

static void bss_keymgmt(DBusMessageIter *iter, void *user_data)
{
	unsigned int *keymgmt = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; keymgmt_map[i].str; i++)
		if (strcmp(str, keymgmt_map[i].str) == 0) {
			SUPPLICANT_DBG("Keymgmt: %s", str);
			*keymgmt |= keymgmt_map[i].val;
			break;
		}
}

static void bss_group(DBusMessageIter *iter, void *user_data)
{
	unsigned int *group = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; group_map[i].str; i++)
		if (strcmp(str, group_map[i].str) == 0) {
			SUPPLICANT_DBG("Group: %s", str);
			*group |= group_map[i].val;
			break;
		}
}

static void bss_pairwise(DBusMessageIter *iter, void *user_data)
{
	unsigned int *pairwise = user_data;
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; pairwise_map[i].str; i++)
		if (strcmp(str, pairwise_map[i].str) == 0) {
			SUPPLICANT_DBG("Pairwise: %s", str);
			*pairwise |= pairwise_map[i].val;
			break;
		}
}

static void bss_wpa(const char *key, DBusMessageIter *iter,
			void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	unsigned int value = 0;

	SUPPLICANT_DBG("Key: %s", key);

	if (g_strcmp0(key, "KeyMgmt") == 0) {
		supplicant_dbus_array_foreach(iter, bss_keymgmt, &value);

		if (bss->rsn_selected)
			bss->rsn_keymgmt = value;
		else
			bss->wpa_keymgmt = value;
	} else if (g_strcmp0(key, "Group") == 0) {
		supplicant_dbus_array_foreach(iter, bss_group, &value);

		if (bss->rsn_selected)
			bss->rsn_group = value;
		else
			bss->wpa_group = value;
	} else if (g_strcmp0(key, "Pairwise") == 0) {
		supplicant_dbus_array_foreach(iter, bss_pairwise, &value);

		if (bss->rsn_selected)
			bss->rsn_pairwise = value;
		else
			bss->wpa_pairwise = value;
	}
}

static unsigned int get_tlv(unsigned char *ie, unsigned int ie_size,
							unsigned int type)
{
	unsigned int len = 0;

	while (len + 4 < ie_size) {
		unsigned int hi = ie[len];
		unsigned int lo = ie[len + 1];
		unsigned int tmp_type = (hi << 8) + lo;
		unsigned int v_len = 0;

		/* hi and lo are used to recreate an unsigned int
		 * based on 2 8bits length unsigned int. */

		hi = ie[len + 2];
		lo = ie[len + 3];
		v_len = (hi << 8) + lo;

		if (tmp_type == type) {
			unsigned int ret_value = 0;
			unsigned char *value = (unsigned char *)&ret_value;

			SUPPLICANT_DBG("IE: match type 0x%x", type);

			/* Verifying length relevance */
			if (v_len > sizeof(unsigned int) ||
				len + 4 + v_len > ie_size)
				break;

			memcpy(value, ie + len + 4, v_len);

			SUPPLICANT_DBG("returning 0x%x", ret_value);
			return ret_value;
		}

		len += v_len + 4;
	}

	SUPPLICANT_DBG("returning 0");
	return 0;
}

static void bss_process_ies(DBusMessageIter *iter, void *user_data)
{
	struct g_supplicant_bss *bss = user_data;
	const unsigned char WPS_OUI[] = { 0x00, 0x50, 0xf2, 0x04 };
	unsigned char *ie, *ie_end;
	DBusMessageIter array;
	unsigned int value;
	int ie_len;

#define WMM_WPA1_WPS_INFO 221
#define WPS_INFO_MIN_LEN  6
#define WPS_VERSION_TLV   0x104A
#define WPS_STATE_TLV     0x1044
#define WPS_METHODS_TLV   0x1012
#define WPS_REGISTRAR_TLV 0x1041
#define WPS_VERSION       0x10
#define WPS_PBC           0x04
#define WPS_PIN           0x00
#define WPS_CONFIGURED    0x02

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

	if (!ie || ie_len < 2)
		return;

	bss->wps_capabilities = 0;
	bss->keymgmt = 0;

	for (ie_end = ie + ie_len; ie < ie_end && ie + ie[1] + 1 <= ie_end;
							ie += ie[1] + 2) {

		if (ie[0] != WMM_WPA1_WPS_INFO || ie[1] < WPS_INFO_MIN_LEN ||
			memcmp(ie+2, WPS_OUI, sizeof(WPS_OUI)) != 0)
			continue;

		SUPPLICANT_DBG("IE: match WPS_OUI");

		value = get_tlv(&ie[6], ie[1], WPS_STATE_TLV);
		if (get_tlv(&ie[6], ie[1], WPS_VERSION_TLV) == WPS_VERSION &&
								value != 0) {
			bss->keymgmt |= G_SUPPLICANT_KEYMGMT_WPS;

			if (value == WPS_CONFIGURED)
				bss->wps_capabilities |=
					G_SUPPLICANT_WPS_CONFIGURED;
		}

		value = get_tlv(&ie[6], ie[1], WPS_METHODS_TLV);
		if (value != 0) {
			if (GUINT16_FROM_BE(value) == WPS_PBC)
				bss->wps_capabilities |= G_SUPPLICANT_WPS_PBC;
			if (GUINT16_FROM_BE(value) == WPS_PIN)
				bss->wps_capabilities |= G_SUPPLICANT_WPS_PIN;
		} else
			bss->wps_capabilities |=
				G_SUPPLICANT_WPS_PBC | G_SUPPLICANT_WPS_PIN;

		/* If the AP sends this it means it's advertizing
		 * as a registrar and the WPS process is launched
		 * on its side */
		if (get_tlv(&ie[6], ie[1], WPS_REGISTRAR_TLV) != 0)
			bss->wps_capabilities |= G_SUPPLICANT_WPS_REGISTRAR;

		SUPPLICANT_DBG("WPS Methods 0x%x", bss->wps_capabilities);
	}
}

static void bss_compute_security(struct g_supplicant_bss *bss)
{
	/*
	 * Combining RSN and WPA keymgmt
	 * We combine it since parsing IEs might have set something for WPS. */
	bss->keymgmt |= bss->rsn_keymgmt | bss->wpa_keymgmt;

	bss->ieee8021x = FALSE;
	bss->psk = FALSE;

	if (bss->keymgmt &
			(G_SUPPLICANT_KEYMGMT_WPA_EAP |
				G_SUPPLICANT_KEYMGMT_WPA_FT_EAP |
				G_SUPPLICANT_KEYMGMT_WPA_EAP_256))
		bss->ieee8021x = TRUE;

	if (bss->keymgmt &
			(G_SUPPLICANT_KEYMGMT_WPA_PSK |
				G_SUPPLICANT_KEYMGMT_WPA_FT_PSK |
				G_SUPPLICANT_KEYMGMT_WPA_PSK_256))
		bss->psk = TRUE;

	if (bss->ieee8021x)
		bss->security = G_SUPPLICANT_SECURITY_IEEE8021X;
	else if (bss->psk)
		bss->security = G_SUPPLICANT_SECURITY_PSK;
	else if (bss->privacy)
		bss->security = G_SUPPLICANT_SECURITY_WEP;
	else
		bss->security = G_SUPPLICANT_SECURITY_NONE;
}


static void bss_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct g_supplicant_bss *bss = user_data;

	if (!bss->interface)
		return;

	SUPPLICANT_DBG("key %s", key);

	if (!key)
		return;

	if (g_strcmp0(key, "BSSID") == 0) {
		DBusMessageIter array;
		unsigned char *addr;
		int addr_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &addr, &addr_len);

		if (addr_len == 6)
			memcpy(bss->bssid, addr, addr_len);
	} else if (g_strcmp0(key, "SSID") == 0) {
		DBusMessageIter array;
		unsigned char *ssid;
		int ssid_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

		if (ssid_len > 0 && ssid_len < 33) {
			memcpy(bss->ssid, ssid, ssid_len);
			bss->ssid_len = ssid_len;
		} else {
			memset(bss->ssid, 0, sizeof(bss->ssid));
			bss->ssid_len = 0;
		}
	} else if (g_strcmp0(key, "Capabilities") == 0) {
		dbus_uint16_t capabilities = 0x0000;

		dbus_message_iter_get_basic(iter, &capabilities);

		if (capabilities & IEEE80211_CAP_ESS)
			bss->mode = G_SUPPLICANT_MODE_INFRA;
		else if (capabilities & IEEE80211_CAP_IBSS)
			bss->mode = G_SUPPLICANT_MODE_IBSS;

		if (capabilities & IEEE80211_CAP_PRIVACY)
			bss->privacy = TRUE;
	} else if (g_strcmp0(key, "Mode") == 0) {
		const char *mode = NULL;

		dbus_message_iter_get_basic(iter, &mode);
		bss->mode = string2mode(mode);
	} else if (g_strcmp0(key, "Frequency") == 0) {
		dbus_uint16_t frequency = 0;

		dbus_message_iter_get_basic(iter, &frequency);
		bss->frequency = frequency;
	} else if (g_strcmp0(key, "Signal") == 0) {
		dbus_int16_t signal = 0;

		dbus_message_iter_get_basic(iter, &signal);

		bss->signal = signal;
		if (!bss->signal)
			bss->signal = BSS_UNKNOWN_STRENGTH;

	} else if (g_strcmp0(key, "Level") == 0) {
		dbus_int32_t level = 0;

		dbus_message_iter_get_basic(iter, &level);
	} else if (g_strcmp0(key, "Rates") == 0) {
		supplicant_dbus_array_foreach(iter, bss_rates, bss);
	} else if (g_strcmp0(key, "MaxRate") == 0) {
		dbus_uint32_t maxrate = 0;

		dbus_message_iter_get_basic(iter, &maxrate);
		if (maxrate != 0)
			bss->maxrate = maxrate;
	} else if (g_strcmp0(key, "Privacy") == 0) {
		dbus_bool_t privacy = FALSE;

		dbus_message_iter_get_basic(iter, &privacy);
		bss->privacy = privacy;
	} else if (g_strcmp0(key, "RSN") == 0) {
		bss->rsn_selected = TRUE;

		supplicant_dbus_property_foreach(iter, bss_wpa, bss);
	} else if (g_strcmp0(key, "WPA") == 0) {
		bss->rsn_selected = FALSE;

		supplicant_dbus_property_foreach(iter, bss_wpa, bss);
	} else if (g_strcmp0(key, "IEs") == 0)
		bss_process_ies(iter, bss);
	else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static struct g_supplicant_bss *interface_bss_added(DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	struct g_supplicant_bss *bss;
	const char *path = NULL;

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		return NULL;

	if (g_strcmp0(path, "/") == 0)
		return NULL;

	SUPPLICANT_DBG("%s", path);

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network) {
		bss = g_hash_table_lookup(network->bss_table, path);
		if (bss)
			return NULL;
	}

	bss = g_try_new0(struct g_supplicant_bss, 1);
	if (!bss)
		return NULL;

	bss->interface = interface;
	bss->path = g_strdup(path);
	bss->signal = BSS_UNKNOWN_STRENGTH;

	return bss;
}

static void interface_bss_added_with_keys(DBusMessageIter *iter,
						void *user_data)
{
	struct g_supplicant_bss *bss;
	GSupplicantInterface *interface = user_data;

	SUPPLICANT_DBG("");

	if (!g_strcmp0(interface->ifname, "p2p0"))
		return;

	bss = interface_bss_added(iter, user_data);
	if (!bss)
		return;

	dbus_message_iter_next(iter);

	if (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_INVALID) {
		g_free(bss);
		return;
	}

	supplicant_dbus_property_foreach(iter, bss_property, bss);

	bss_compute_security(bss);
	if (add_or_replace_bss_to_network(bss) < 0)
		SUPPLICANT_DBG("add_or_replace_bss_to_network failed");
}

static void interface_bss_added_without_keys(DBusMessageIter *iter,
						void *user_data)
{
	struct g_supplicant_bss *bss;
	GSupplicantInterface *interface = user_data;

	SUPPLICANT_DBG("");

	if (!g_strcmp0(interface->ifname, "p2p0"))
		return;

	bss = interface_bss_added(iter, user_data);
	if (!bss)
		return;

	supplicant_dbus_property_get_all(bss->path,
					SUPPLICANT_INTERFACE ".BSS",
					bss_property, bss, bss);

	bss_compute_security(bss);
	if (add_or_replace_bss_to_network(bss) < 0)
			SUPPLICANT_DBG("add_or_replace_bss_to_network failed");
}

static void update_signal(gpointer key, gpointer value,
						gpointer user_data)
{
	struct g_supplicant_bss *bss = value;
	GSupplicantNetwork *network = user_data;

	if (bss->signal > network->signal) {
		network->signal = bss->signal;
		network->best_bss = bss;
	}
}

static void update_network_signal(GSupplicantNetwork *network)
{
	if (g_hash_table_size(network->bss_table) <= 1 && network->best_bss)
		return;

	g_hash_table_foreach(network->bss_table,
				update_signal, network);

	SUPPLICANT_DBG("New network signal %d", network->signal);
}

static void interface_current_bss(GSupplicantInterface *interface,
						DBusMessageIter *iter)
{
	GSupplicantNetwork *network;
	struct g_supplicant_bss *bss;
	const char *path;

	dbus_message_iter_get_basic(iter, &path);
	if (g_strcmp0(path, "/") == 0) {
		interface->current_network = NULL;
		return;
	}

	interface_bss_added_without_keys(iter, interface);

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (!network)
		return;

	bss = g_hash_table_lookup(network->bss_table, path);
	if (!bss)
		return;

	interface->current_network = network;

	if (bss != network->best_bss) {
		/*
		 * This is the case where either wpa_s got associated
		 * to a BSS different than the one ConnMan considers
		 * the best, or we are roaming.
		 */
		SUPPLICANT_DBG("Update best BSS for %s", network->name);

		network->best_bss = bss;

		if (network->signal != bss->signal) {
			SUPPLICANT_DBG("New network signal %d dBm",
						bss->signal);

			network->signal = bss->signal;
			callback_network_changed(network, "Signal");
		}
	}

	/*
	 * wpa_s could notify about CurrentBSS in any state once
	 * it got associated. It is not sure such notification will
	 * arrive together with transition to ASSOCIATED state.
	 * In fact, for networks with security WEP or OPEN, it
	 * always arrives together with transition to COMPLETED.
	 */
	switch (interface->state) {
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
		return;
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
	case G_SUPPLICANT_STATE_COMPLETED:
		callback_network_associated(network);
		break;
	}
}

static void interface_bss_removed(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	struct g_supplicant_bss *bss = NULL;
	const char *path = NULL;
	bool is_current_network_bss = false;

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (!network)
		return;

	bss = g_hash_table_lookup(network->bss_table, path);
	if (network->best_bss == bss) {
		network->best_bss = NULL;
		network->signal = BSS_UNKNOWN_STRENGTH;
		is_current_network_bss = true;
	}

	g_hash_table_remove(bss_mapping, path);

	g_hash_table_remove(interface->bss_mapping, path);
	g_hash_table_remove(network->bss_table, path);

	update_network_signal(network);

	if (g_hash_table_size(network->bss_table) == 0) {
		g_hash_table_remove(interface->network_table, network->group);
	} else {
		if (is_current_network_bss && network->best_bss)
			callback_network_changed(network, "");
	}
}

static void set_config_methods(DBusMessageIter *iter, void *user_data)
{
	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, user_data);
}

static void wps_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (!interface)
		return;

	SUPPLICANT_DBG("key: %s", key);

	if (g_strcmp0(key, "ConfigMethods") == 0) {
		const char *config_methods = "push_button", *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str && strlen(str) > 0) {
			/* It was already set at wpa_s level, don't modify it. */
			SUPPLICANT_DBG("%s", str);
			return;
		}

		supplicant_dbus_property_set(interface->path,
			SUPPLICANT_INTERFACE ".Interface.WPS",
			"ConfigMethods", DBUS_TYPE_STRING_AS_STRING,
			set_config_methods, NULL, &config_methods, NULL);

		SUPPLICANT_DBG("No value. Set %s", config_methods);
	}

}

static void interface_signal_info(const char *key, DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (g_strcmp0(key, "RSSI") == 0) {
		dbus_int32_t rssi = 0;
		dbus_message_iter_get_basic(iter, &rssi);

		interface->rssi = rssi;

	} else if (g_strcmp0(key, "LinkSpeed") == 0) {
		dbus_int32_t link_speed = 0;
		dbus_message_iter_get_basic(iter, &link_speed);

		interface->link_speed = link_speed;

	} else if (g_strcmp0(key, "Frequency") == 0) {
		dbus_int32_t frequency = 0;
		dbus_message_iter_get_basic(iter, &frequency);

		interface->frequency = frequency;

	} else if (g_strcmp0(key, "Noise") == 0) {
		dbus_int32_t noise = 0;
		dbus_message_iter_get_basic(iter, &noise);

		interface->noise = noise;
	}
}
static void interface_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (!interface)
		return;

	SUPPLICANT_DBG("%s", key);

	if (!key) {
		debug_strvalmap("KeyMgmt capability", keymgmt_map,
						interface->keymgmt_capa);
		debug_strvalmap("AuthAlg capability", authalg_capa_map,
						interface->authalg_capa);
		debug_strvalmap("Protocol capability", proto_capa_map,
						interface->proto_capa);
		debug_strvalmap("Pairwise capability", pairwise_map,
						interface->pairwise_capa);
		debug_strvalmap("Group capability", group_map,
						interface->group_capa);
		debug_strvalmap("Scan capability", scan_capa_map,
						interface->scan_capa);
		debug_strvalmap("Mode capability", mode_capa_map,
						interface->mode_capa);

		supplicant_dbus_property_get_all(interface->path,
				SUPPLICANT_INTERFACE ".Interface.WPS",
				wps_property, interface, interface);

		if (interface->ready)
			callback_interface_added(interface);

		return;
	}

	if (g_strcmp0(key, "Capabilities") == 0) {
		supplicant_dbus_property_foreach(iter, interface_capability,
								interface);
		if (interface->mode_capa & G_SUPPLICANT_CAPABILITY_MODE_P2P)
			interface->p2p_support = true;
	} else if (g_strcmp0(key, "State") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str)
			if (string2state(str) != interface->state) {
				interface->state = string2state(str);
				callback_interface_state(interface);
			}

		if (interface->ap_create_in_progress) {
			if (interface->state == G_SUPPLICANT_STATE_DISCONNECTED)
				callback_ap_create_fail(interface);

			interface->ap_create_in_progress = false;
		}

		if (interface->state == G_SUPPLICANT_STATE_DISABLED)
			interface->ready = FALSE;
		else
			interface->ready = TRUE;

		SUPPLICANT_DBG("state %s (%d)", str, interface->state);
	} else if (g_strcmp0(key, "Scanning") == 0) {
		dbus_bool_t scanning = FALSE;

		dbus_message_iter_get_basic(iter, &scanning);
		interface->scanning = scanning;

		if (interface->ready) {
			if (interface->scanning)
				callback_scan_started(interface);
			else
				callback_scan_finished(interface);
		}
	} else if (g_strcmp0(key, "ApScan") == 0) {
		int apscan = 1;

		dbus_message_iter_get_basic(iter, &apscan);
		interface->apscan = apscan;
	} else if (g_strcmp0(key, "Ifname") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str) {
			g_free(interface->ifname);
			interface->ifname = g_strdup(str);
		}
	} else if (g_strcmp0(key, "Driver") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str) {
			g_free(interface->driver);
			interface->driver = g_strdup(str);
		}
	} else if (g_strcmp0(key, "BridgeIfname") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str) {
			g_free(interface->bridge);
			interface->bridge = g_strdup(str);
		}
	} else if (g_strcmp0(key, "ConfigFile") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str && strlen(str) > 0 && interface->ifname) {
			SUPPLICANT_DBG("New {%s, %s}", interface->ifname, str);
			g_hash_table_replace(config_file_table,
				g_strdup(interface->ifname), g_strdup(str));
		}
	} else if (g_strcmp0(key, "CurrentBSS") == 0) {
		interface_bss_added_without_keys(iter, interface);
	} else if (g_strcmp0(key, "CurrentNetwork") == 0) {
		interface_network_added(iter, interface);
	} else if (g_strcmp0(key, "BSSs") == 0) {
		supplicant_dbus_array_foreach(iter,
					interface_bss_added_without_keys,
					interface);
	} else if (g_strcmp0(key, "Blobs") == 0) {
		/* Nothing */
	} else if (g_strcmp0(key, "Networks") == 0) {
		supplicant_dbus_array_foreach(iter, interface_network_added,
								interface);
	} else if (g_strcmp0(key, "SignalInfo") == 0) {
		supplicant_dbus_property_foreach(iter, interface_signal_info,
                                                               interface);
	} else if (g_strcmp0(key, "DisconnectReason") == 0) {
		int reason_code;
		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
			dbus_message_iter_get_basic(iter, &reason_code);
			callback_disconnect_reason_code(interface, reason_code);
		}
	} else if (g_strcmp0(key, "AssocStatusCode") == 0) {
		int status_code;
		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
			dbus_message_iter_get_basic(iter, &status_code);
			callback_assoc_status_code(interface, status_code);
		}
	} else {
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
	}
}

static void scan_network_update(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantNetwork *network;
	char *path;

	if (!iter)
		return;

	dbus_message_iter_get_basic(iter, &path);

	if (!path)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	/* Update the network details based on scan BSS data */
	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (network)
		callback_network_added(network);
}

static void scan_bss_data(const char *key, DBusMessageIter *iter,
				void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (iter)
		supplicant_dbus_array_foreach(iter, scan_network_update,
						interface);

	if (interface->scan_callback)
		interface->scan_callback(0, interface, interface->scan_data);

	interface->scan_callback = NULL;
	interface->scan_data = NULL;
}

static GSupplicantInterface *interface_alloc(const char *path)
{
	GSupplicantInterface *interface;

	interface = g_try_new0(GSupplicantInterface, 1);
	if (!interface)
		return NULL;

	interface->path = g_strdup(path);

	interface->network_table = g_hash_table_new_full(g_str_hash,
					g_str_equal, NULL, remove_network);
	interface->peer_table = g_hash_table_new_full(g_str_hash,
					g_str_equal, NULL, remove_peer);
	interface->group_table = g_hash_table_new_full(g_str_hash,
					g_str_equal, NULL, remove_group);
	interface->bss_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	interface->p2p_peer_path_to_network = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	interface->p2p_group_path_to_group = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);

	g_hash_table_replace(interface_table, interface->path, interface);

	return interface;
}

static void interface_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface;
	const char *path = NULL;
	bool properties_appended = GPOINTER_TO_UINT(user_data);

	SUPPLICANT_DBG("");

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface)
		return;

	interface = interface_alloc(path);
	if (!interface)
		return;

	if (!properties_appended) {
		supplicant_dbus_property_get_all(path,
						SUPPLICANT_INTERFACE ".Interface",
						interface_property, interface,
						interface);
		return;
	}

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, interface_property,
								interface);
		interface_property(NULL, NULL, interface);
	}
}

static void interface_removed(DBusMessageIter *iter, void *user_data)
{
	const char *path = NULL;
	GSupplicantInterface *interface = user_data;

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	g_supplicant_interface_cancel(interface);

	g_hash_table_remove(interface_table, path);
}

static void eap_method(DBusMessageIter *iter, void *user_data)
{
	const char *str = NULL;
	int i;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	for (i = 0; eap_method_map[i].str; i++)
		if (strcmp(str, eap_method_map[i].str) == 0) {
			eap_methods |= eap_method_map[i].val;
			break;
		}
}

static void service_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	if (!key) {
		callback_system_ready();
		return;
	}

	if (g_strcmp0(key, "DebugLevel") == 0) {
		const char *str = NULL;
		int i;

		dbus_message_iter_get_basic(iter, &str);
		for (i = 0; debug_strings[i]; i++)
			if (g_strcmp0(debug_strings[i], str) == 0) {
				debug_level = i;
				break;
			}
		SUPPLICANT_DBG("Debug level %d", debug_level);
	} else if (g_strcmp0(key, "DebugTimestamp") == 0) {
		dbus_message_iter_get_basic(iter, &debug_timestamp);
		SUPPLICANT_DBG("Debug timestamp %u", debug_timestamp);
	} else if (g_strcmp0(key, "DebugShowKeys") == 0) {
		dbus_message_iter_get_basic(iter, &debug_showkeys);
		SUPPLICANT_DBG("Debug show keys %u", debug_showkeys);
	} else if (g_strcmp0(key, "Interfaces") == 0) {
		supplicant_dbus_array_foreach(iter, interface_added, NULL);
	} else if (g_strcmp0(key, "EapMethods") == 0) {
		supplicant_dbus_array_foreach(iter, eap_method, NULL);
		debug_strvalmap("EAP method", eap_method_map, eap_methods);
	} else if (g_strcmp0(key, "Country") == 0) {
		const char *country = NULL;

		dbus_message_iter_get_basic(iter, &country);
		SUPPLICANT_DBG("Country %s", country);
	} else
		SUPPLICANT_DBG("key %s type %c",
				key, dbus_message_iter_get_arg_type(iter));
}

static void signal_name_owner_changed(const char *path, DBusMessageIter *iter)
{
	const char *name = NULL, *old = NULL, *new = NULL;

	SUPPLICANT_DBG("");

	if (g_strcmp0(path, DBUS_PATH_DBUS) != 0)
		return;

	dbus_message_iter_get_basic(iter, &name);
	if (!name)
		return;

	if (g_strcmp0(name, SUPPLICANT_SERVICE) != 0)
		return;

	dbus_message_iter_next(iter);
	dbus_message_iter_get_basic(iter, &old);
	dbus_message_iter_next(iter);
	dbus_message_iter_get_basic(iter, &new);

	if (!old || !new)
		return;

	if (strlen(old) > 0 && strlen(new) == 0) {
		system_available = FALSE;
		g_hash_table_remove_all(bss_mapping);
		g_hash_table_remove_all(peer_mapping);
		g_hash_table_remove_all(group_mapping);
		g_hash_table_remove_all(config_file_table);
		g_hash_table_remove_all(interface_table);
		g_hash_table_remove_all(p2p_peer_table);
		callback_system_killed();
	}

	if (strlen(new) > 0 && strlen(old) == 0) {
		system_available = TRUE;
		supplicant_dbus_property_get_all(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						service_property, NULL, NULL);
	}
}

static void signal_properties_changed(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("");

	if (g_strcmp0(path, SUPPLICANT_PATH) != 0)
		return;

	supplicant_dbus_property_foreach(iter, service_property, NULL);
}

static void signal_interface_added(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("path %s %s", path, SUPPLICANT_PATH);

	if (g_strcmp0(path, SUPPLICANT_PATH) == 0)
		interface_added(iter, GUINT_TO_POINTER(true));
}

static void signal_interface_removed(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("");

	if (g_strcmp0(path, SUPPLICANT_PATH) == 0)
		interface_removed(iter, NULL);
}

static void signal_interface_changed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, interface_property, interface);
}

static void signal_scan_done(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	dbus_bool_t success = FALSE;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &success);

	if (interface->scanning) {
		callback_scan_finished(interface);
		interface->scanning = FALSE;
	}

	/*
	 * If scan is unsuccessful return -EIO else get the scanned BSSs
	 * and update the network details accordingly
	 */
	if (!success) {
		if (interface->scan_callback)
			interface->scan_callback(-EIO, interface,
						interface->scan_data);

		interface->scan_callback = NULL;
		interface->scan_data = NULL;

		return;
	}

	supplicant_dbus_property_get(path, SUPPLICANT_INTERFACE ".Interface",
				"BSSs", scan_bss_data, interface, interface);
}

static void signal_bss_added(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_bss_added_with_keys(iter, interface);
}

static void signal_bss_removed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_bss_removed(iter, interface);
}

static void signal_network_added(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_network_added(iter, interface);
}

static void signal_network_removed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_network_removed(iter, interface);
}

static void signal_sta_authorized(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *addr = NULL;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &addr);
	if (!addr)
		return;

	callback_sta_authorized(interface, addr);
}

static void signal_sta_deauthorized(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *addr = NULL;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &addr);
	if (!addr)
		return;

	callback_sta_deauthorized(interface, addr);
}

static void signal_bss_changed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	GSupplicantNetwork *network;
	GSupplicantSecurity old_security;
	unsigned int old_wps_capabilities;
	struct g_supplicant_bss *bss;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(bss_mapping, path);
	if (!interface)
		return;

	network = g_hash_table_lookup(interface->bss_mapping, path);
	if (!network)
		return;

	bss = g_hash_table_lookup(network->bss_table, path);
	if (!bss)
		return;

	supplicant_dbus_property_foreach(iter, bss_property, bss);

	old_security = network->security;
	bss_compute_security(bss);

	if (old_security != bss->security) {
		struct g_supplicant_bss *new_bss;

		SUPPLICANT_DBG("New network security for %s with path %s",
			       bss->ssid, bss->path);

		/*
		 * Security change policy:
		 * - We first copy the current bss into a new one with
		 *   its own pointer (path)
		 * - Clear the old bss pointer and remove the network completely
		 *   if there are no more BSSs in the bss table.
		 * - The new bss will be added either to an existing network
		 *   or an additional network will be created
		 */

		new_bss = g_try_new0(struct g_supplicant_bss, 1);
		if (!new_bss)
			return;

		memcpy(new_bss, bss, sizeof(struct g_supplicant_bss));
		new_bss->path = g_strdup(bss->path);

		if (network->best_bss == bss) {
			network->best_bss = NULL;
			network->signal = BSS_UNKNOWN_STRENGTH;
		}

		g_hash_table_remove(bss_mapping, path);

		g_hash_table_remove(interface->bss_mapping, path);
		g_hash_table_remove(network->bss_table, path);

		update_network_signal(network);

		if (g_hash_table_size(network->bss_table) == 0)
			g_hash_table_remove(interface->network_table,
					    network->group);

		if (add_or_replace_bss_to_network(new_bss) < 0) {
			/*
			 * Prevent a memory leak on failure in
			 * add_or_replace_bss_to_network
			 */
			SUPPLICANT_DBG("Failed to add bss %s to network table",
				       new_bss->path);
			g_free(new_bss->path);
			g_free(new_bss);
		}

		return;
	}

	old_wps_capabilities = network->wps_capabilities;

	if (old_wps_capabilities != bss->wps_capabilities) {
		network->wps_capabilities = bss->wps_capabilities;
		callback_network_changed(network, "WPSCapabilities");
	}

	/* Consider only property changes of the connected BSS */
	if (network == interface->current_network && bss != network->best_bss)
		return;

	if (bss->signal == network->signal)
		return;

	/*
	 * If the new signal is lower than the SSID signal, we need
	 * to check for the new maximum.
	 */
	if (bss->signal < network->signal) {
		if (bss != network->best_bss)
			return;
		network->signal = bss->signal;
		update_network_signal(network);
	} else {
		network->signal = bss->signal;
		network->best_bss = bss;
	}

	SUPPLICANT_DBG("New network signal for %s %d dBm", network->ssid,
			network->signal);

	callback_network_changed(network, "Signal");
}

static void wps_credentials(const char *key, DBusMessageIter *iter,
			void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (!key)
		return;

	SUPPLICANT_DBG("key %s", key);

	if (g_strcmp0(key, "Key") == 0) {
		DBusMessageIter array;
		unsigned char *key_val;
		int key_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &key_val, &key_len);

		g_free(interface->wps_cred.key);
		interface->wps_cred.key = g_try_malloc0(
						sizeof(char) * key_len + 1);

		if (!interface->wps_cred.key)
			return;

		memcpy(interface->wps_cred.key, key_val,
						sizeof(char) * key_len);

		SUPPLICANT_DBG("WPS key present");
	} else if (g_strcmp0(key, "SSID") == 0) {
		DBusMessageIter array;
		unsigned char *ssid;
		int ssid_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

		if (ssid_len > 0 && ssid_len < 33) {
			memcpy(interface->wps_cred.ssid, ssid, ssid_len);
			interface->wps_cred.ssid_len = ssid_len;
		} else {
			memset(interface->wps_cred.ssid, 0, 32);
			interface->wps_cred.ssid_len = 0;
		}
	}
}

static void signal_wps_credentials(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, wps_credentials, interface);
}

static void wps_event_args(const char *key, DBusMessageIter *iter,
			void *user_data)
{
	GSupplicantInterface *interface = user_data;

	if (!key || !interface)
		return;

	SUPPLICANT_DBG("Arg Key %s", key);
}

static void signal_wps_event(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *name = NULL;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &name);

	SUPPLICANT_DBG("Name: %s", name);

	if (g_strcmp0(name, "success") == 0)
		interface->wps_state = G_SUPPLICANT_WPS_STATE_SUCCESS;
	else if (g_strcmp0(name, "fail") == 0)
		interface->wps_state = G_SUPPLICANT_WPS_STATE_FAIL;
	else
		interface->wps_state = G_SUPPLICANT_WPS_STATE_UNKNOWN;

	if (!dbus_message_iter_has_next(iter))
		return;

	dbus_message_iter_next(iter);

	supplicant_dbus_property_foreach(iter, wps_event_args, interface);

	callback_wps_state(interface);
}

static void signal_station_connected(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *sta_mac = NULL;

	SUPPLICANT_DBG("path %s %s", path, SUPPLICANT_PATH);

	if (callbacks_pointer->station_added == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	dbus_message_iter_get_basic(iter, &sta_mac);
	if (sta_mac == NULL)
		return;

	SUPPLICANT_DBG("New station %s connected", sta_mac);
	callbacks_pointer->station_added(sta_mac);
}

static void signal_station_disconnected(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *sta_mac = NULL;

	SUPPLICANT_DBG("path %s %s", path, SUPPLICANT_PATH);

	if (callbacks_pointer->station_removed == NULL)
		return;

	if (g_strcmp0(path, "/") == 0)
		return;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	dbus_message_iter_get_basic(iter, &sta_mac);
	if (sta_mac == NULL)
		return;

	SUPPLICANT_DBG("Station %s disconnected", sta_mac);
	callbacks_pointer->station_removed(sta_mac);
}

static void create_peer_identifier(GSupplicantPeer *peer)
{
	const unsigned char test[ETH_ALEN] = {};

	if (!peer)
		return;

	if (!memcmp(peer->device_address, test, ETH_ALEN)) {
		peer->identifier = g_strdup(peer->name);
		return;
	}

	peer->identifier = g_malloc0(19);
	snprintf(peer->identifier, 19, "%02x%02x%02x%02x%02x%02x",
						peer->device_address[0],
						peer->device_address[1],
						peer->device_address[2],
						peer->device_address[3],
						peer->device_address[4],
						peer->device_address[5]);
}

struct peer_property_data {
	GSupplicantPeer *peer;
	GSList *old_groups;
	bool groups_changed;
	bool services_changed;
};
struct peer_device_data {
	char *path;
	char *identifier; /* Device address in string 112233445566 format */
	unsigned char p2p_device_addr[6]; /* Device address in binary format */
};


static void peer_groups_relation(DBusMessageIter *iter, void *user_data)
{
	struct peer_property_data *data = user_data;
	GSupplicantPeer *peer = data->peer;
	GSupplicantGroup *group;
	const char *str = NULL;
	GSList *elem;

	dbus_message_iter_get_basic(iter, &str);
	if (!str)
		return;

	group = g_hash_table_lookup(group_mapping, str);
	if (!group)
		return;

	elem = g_slist_find_custom(data->old_groups, str, (GCompareFunc)g_strcmp0);
	if (elem) {
		data->old_groups = g_slist_remove_link(data->old_groups, elem);
		peer->groups = g_slist_concat(elem, peer->groups);
	} else {
		peer->groups = g_slist_prepend(peer->groups, g_strdup(str));
		data->groups_changed = true;
	}
}

static void string_to_byte(const char *src, unsigned char *dest)
{
	int len = strlen(src);
	int i=0;
	unsigned char t = 0;

	for(i=0; i<len; i++) {
		if (src[i] >= '0' && src[i] <= '9')
			t = src[i] - '0';
		if (src[i] >= 'a' && src[i] <= 'f')
			t = src[i] - 'a' + 10;
		if (src[i] >= 'A' && src[i] <= 'F')
			t = src[i] - 'A' + 10;

		if(i%2 == 0)
			dest[i/2] = (t << 4);
		else
			dest[i/2] |= t;
	}
}
static gboolean p2p_network_fire_signals(GSupplicantPeer * peer)
{
	if (!peer)
		return FALSE;

	peer->found_pending_signal_timeout_ref = 0;

	while (peer->pending_signals != NULL)
	{
		struct g_supplicant_p2p_peer_signal* signal = peer->pending_signals->data;

		SUPPLICANT_DBG("Firing delayed signal for peer %s", peer->path);

		signal->dispatch_function(peer->interface, peer, signal->callback_params);
		signal->free_function(signal->callback_params);

		peer->pending_signals = g_slist_remove(peer->pending_signals, signal);
		g_free(signal);
	}
	return FALSE;
}
static void p2p_pending_invitation_fire_signals(GSupplicantPeer * peer)
{
	while (peer->pending_invitation_signals != NULL)
	{
		struct g_supplicant_p2p_peer_signal* signal = peer->pending_invitation_signals->data;

		SUPPLICANT_DBG("Firing delayed signal for peer %s", peer->path);

		signal->dispatch_function(peer->interface, peer, signal->callback_params);
		signal->free_function(signal->callback_params);

		peer->pending_invitation_signals = g_slist_remove(peer->pending_invitation_signals, signal);
		g_free(signal);
	}
}
static void peer_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	GSupplicantPeer *pending_peer;
	struct peer_property_data *data = user_data;
	GSupplicantPeer *peer = data->peer;
	int dev_passwd_id = 0;
	GSupplicantInterface *interface = peer->interface;

	SUPPLICANT_DBG("key: %s", key);

	if (!peer->interface)
		return;

	if (!key) {
		if (g_hash_table_lookup(p2p_peer_table, peer->path) == NULL)
			return;

		if (peer->name) {
			struct peer_device_data *p2p_data;

			p2p_data = g_try_new0(struct peer_device_data, 1);
			if (p2p_data == NULL) {
				return;
			}

			if (p2p_data->path == NULL) {
				char *id = strrchr(peer->path, '/') + 1;
				p2p_data->identifier = g_strdup(id);
				p2p_data->path = g_strdup(peer->path);
				string_to_byte(p2p_data->identifier, p2p_data->p2p_device_addr);
			}
			p2p_network_list = g_slist_prepend(p2p_network_list, p2p_data);
			g_hash_table_replace(interface->p2p_peer_path_to_network, peer->path, p2p_data);

			create_peer_identifier(peer);
			callback_peer_found(peer);
			pending_peer = g_hash_table_lookup(
					pending_peer_connection, peer->path);

			if (pending_peer && pending_peer == peer) {
				callback_peer_request(peer, dev_passwd_id);
				g_hash_table_remove(pending_peer_connection,
						peer->path);
			}

			p2p_pending_invitation_fire_signals(peer);
			peer->found_pending_signal_timeout_ref = g_timeout_add(500, p2p_network_fire_signals, peer);

			dbus_free(data);
		}

		return;
	}

	if (g_strcmp0(key, "DeviceAddress") == 0) {
		unsigned char *dev_addr;
		DBusMessageIter array;
		int len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &dev_addr, &len);

		if (len == ETH_ALEN)
			memcpy(peer->device_address, dev_addr, len);
	} else if (g_strcmp0(key, "DeviceName") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (str)
			peer->name = g_strdup(str);
	} else if (g_strcmp0(key, "config_method") == 0) {
		uint16_t wps_config;

		dbus_message_iter_get_basic(iter, &wps_config);
		peer->config_methods = wps_config;

		if (wps_config & G_SUPPLICANT_WPS_CONFIG_PBC)
			peer->wps_capabilities |= G_SUPPLICANT_WPS_PBC;
		if (wps_config & ~G_SUPPLICANT_WPS_CONFIG_PBC)
			peer->wps_capabilities |= G_SUPPLICANT_WPS_PIN;
	} else if (g_strcmp0(key, "Groups") == 0) {
		data->old_groups = peer->groups;
		peer->groups = NULL;

		supplicant_dbus_array_foreach(iter,
						peer_groups_relation, data);
		if (g_slist_length(data->old_groups) > 0) {
			g_slist_free_full(data->old_groups, g_free);
			data->groups_changed = true;
		}

	} else if (g_strcmp0(key, "p2ps_instance") == 0) {
		DBusMessageIter array;
		int len = 0;

		if (peer->asp_services != NULL)
		{
			g_free(peer->asp_services);
			peer->asp_services = NULL;
			peer->asp_services_len = 0;
		}

		//get the array size
		dbus_message_iter_recurse(iter, &array);
		while (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_INVALID) {
			len ++;
			dbus_message_iter_next(&array);
		}

		if (len > 0)
		{
			int pos = 0;
			peer->asp_services_len = len;
			peer->asp_services = g_new0(GSupplicantP2PService, len);

			dbus_message_iter_recurse(iter, &array);

			while (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_INVALID) {
				DBusMessageIter item;
				const char* service_name = NULL;
				dbus_message_iter_recurse(&array, &item);
				dbus_message_iter_get_basic(&item, &(peer->asp_services[pos].advertisement_id));
				dbus_message_iter_next(&item);
				dbus_message_iter_get_basic(&item, &service_name);
				(void)g_strlcpy(peer->asp_services[pos].service_name, service_name, 256);

				pos ++;
				dbus_message_iter_next(&array);
			}
		}

	} else if (g_strcmp0(key, "IEs") == 0) {
		DBusMessageIter array;
		unsigned char *ie;
		int ie_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);

		if (!ie || ie_len < 2)
			return;

		if (peer->widi_ies) {
			if (memcmp(peer->widi_ies, ie, ie_len) == 0)
				return;

			g_free(peer->widi_ies);
			peer->widi_ies_length = 0;
		}

		peer->widi_ies = g_malloc0(ie_len * sizeof(unsigned char));

		memcpy(peer->widi_ies, ie, ie_len);
		peer->widi_ies_length = ie_len;
		data->services_changed = true;
	} else if (g_strcmp0(key, "level") == 0) {
		dbus_int32_t level = 0;

		dbus_message_iter_get_basic(iter, &level);
		peer->level = level;
	} else if (g_strcmp0(key, "PrimaryDeviceType") == 0) {
		DBusMessageIter array;
		unsigned char *device_type;
		int type_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &device_type, &type_len);

		if (type_len == 8) {
			peer->pri_dev_type = g_malloc0(type_len*2+1);
			__connman_util_byte_to_string(device_type, peer->pri_dev_type, type_len);
		} else {
			SUPPLICANT_DBG("strange device type\n");
		}
	}
}

static void signal_peer_found(const char *path, DBusMessageIter *iter)
{
	struct peer_property_data *property_data;
	GSupplicantInterface *interface;
	const char *obj_path = NULL;
	GSupplicantPeer *peer;
	int ret;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &obj_path);
	if (!obj_path || g_strcmp0(obj_path, "/") == 0)
		return;

	peer = g_hash_table_lookup(interface->peer_table, obj_path);
	if (peer)
		return;

	peer = g_try_new0(GSupplicantPeer, 1);
	if (!peer)
		return;

	peer->interface = interface;
	peer->path = g_strdup(obj_path);
	g_hash_table_insert(interface->peer_table, peer->path, peer);
	g_hash_table_replace(peer_mapping, peer->path, interface);
	g_hash_table_replace(p2p_peer_table, g_strdup(peer->path), peer);

	property_data = dbus_malloc0(sizeof(struct peer_property_data));

	if(!property_data)
		return;

	property_data->peer = peer;

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INVALID) {
		supplicant_dbus_property_foreach(iter, peer_property,
							property_data);
		peer_property(NULL, NULL, property_data);
		return;
	}

	ret=supplicant_dbus_property_get_all(obj_path,
					SUPPLICANT_INTERFACE ".Peer",
					peer_property, property_data, NULL);

	if(ret<0)
		dbus_free(property_data);
}

static void signal_peer_lost(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	const char *obj_path = NULL;
	GSupplicantPeer *peer;
	struct peer_device_data *p2p_data;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &obj_path);
	if (!obj_path || g_strcmp0(obj_path, "/") == 0)
		return;

	peer = g_hash_table_lookup(interface->peer_table, obj_path);
	if (!peer)
		return;

	if (interface->p2p_peer_path_to_network) {
	p2p_data = g_hash_table_lookup(interface->p2p_peer_path_to_network, obj_path);
		if (p2p_data == NULL) {
			g_hash_table_remove(interface->peer_table, obj_path);
			return;
		}

	g_hash_table_remove(interface->p2p_peer_path_to_network, obj_path);
	p2p_network_list = g_slist_remove(p2p_network_list, p2p_data);

	g_free(p2p_data->identifier);
	g_free(p2p_data->path);
	g_free(p2p_data);
	}

	g_hash_table_remove(interface->peer_table, obj_path);
}

static void signal_peer_changed(const char *path, DBusMessageIter *iter)
{
	struct peer_property_data *property_data;
	GSupplicantInterface *interface;
	GSupplicantPeer *peer;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(peer_mapping, path);
	if (!interface)
		return;

	peer = g_hash_table_lookup(interface->peer_table, path);
	if (!peer) {
		g_hash_table_remove(peer_mapping, path);
		return;
	}

	property_data = dbus_malloc0(sizeof(struct peer_property_data));
	if(!property_data)
		return;

	property_data->peer = peer;

	supplicant_dbus_property_foreach(iter, peer_property, property_data);
	if (property_data->services_changed)
		callback_peer_changed(peer, G_SUPPLICANT_PEER_SERVICES_CHANGED);

	if (property_data->groups_changed)
		callback_peer_changed(peer, G_SUPPLICANT_PEER_GROUP_CHANGED);

	dbus_free(property_data);

	if (!g_supplicant_peer_is_in_a_group(peer))
		peer->connection_requested = false;
}

static void remove_colon(char *str)
{
	int len = strlen(str);
	int i=0;
	int j=0;

	for(i=0; i<len; i++) {
		if(str[i] == ':') {
			for(j=i; j<len-1; j++) {
				str[j] = str[j+1];
			}
			len--;
			i--;
		}
	}
	str[len] = '\0';
}

struct group_sig_data {
	const char *peer_obj_path;
	unsigned char iface_address[ETH_ALEN];
	char dev_addr_buf[13];
	const char *interface_obj_path;
	const char *group_obj_path;
	int role;
	bool persistent;
	int status;
	char *ip_addr;
	char *ip_mask;
	char *go_ip_addr;
	int freq;
};

static void group_sig_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct group_sig_data *data = user_data;
	char *group_bssid_no_colon = NULL;
	int addr_len;

	if (!key)
		return;

	if (g_strcmp0(key, "peer_interface_addr") == 0) {
		unsigned char *dev_addr;
		DBusMessageIter array;
		int len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &dev_addr, &len);

		if (len == ETH_ALEN)
			memcpy(data->iface_address, dev_addr, len);
	} else if (g_strcmp0(key, "role") == 0 || g_strcmp0(key, "role_go") == 0) {
		const char *str = NULL;

		dbus_message_iter_get_basic(iter, &str);
		if (g_strcmp0(str, "GO") == 0)
			data->role = G_SUPPLICANT_GROUP_ROLE_GO;
		else
			data->role = G_SUPPLICANT_GROUP_ROLE_CLIENT;
	} else if (g_strcmp0(key, "peer_object") == 0)
		dbus_message_iter_get_basic(iter, &data->peer_obj_path);
	else if (g_strcmp0(key, "interface_object") == 0)
		dbus_message_iter_get_basic(iter, &data->interface_obj_path);
	else if (g_strcmp0(key, "group_object") == 0)
		dbus_message_iter_get_basic(iter, &data->group_obj_path);
	else if (g_strcmp0(key, "persistent") == 0)
		dbus_message_iter_get_basic(iter, &data->persistent);
	else if(g_str_equal(key, "go_dev_addr")) {
			DBusMessageIter array;
			dbus_message_iter_recurse(iter, &array);
			dbus_message_iter_get_fixed_array(&array, &group_bssid_no_colon, &addr_len);

			if (addr_len != 6) {
				//Do not set the bbsid_no_colon unless we have the correct length
				SUPPLICANT_DBG("group->bssid_no_colon: Error: array length expected to be 6, was %i", addr_len);
			} else {
				__connman_util_byte_to_string(group_bssid_no_colon, data->dev_addr_buf, addr_len);
			}
	} else if (g_strcmp0(key, "status") == 0)
		dbus_message_iter_get_basic(iter, &data->status);
	else if(g_str_equal(key, "IpAddr")) {
			DBusMessageIter array;
			char *ip_addr;
			dbus_message_iter_recurse(iter, &array);
			dbus_message_iter_get_fixed_array(&array, &ip_addr, &addr_len);

			data->ip_addr = __connman_util_ipaddr_binary_to_string(ip_addr);
			SUPPLICANT_DBG("ip_addr : %s\n", data->ip_addr);
	} else if(g_str_equal(key, "IpAddrMask")) {
			DBusMessageIter array;
			char *ip_mask;
			dbus_message_iter_recurse(iter, &array);
			dbus_message_iter_get_fixed_array(&array, &ip_mask, &addr_len);

			data->ip_mask = __connman_util_ipaddr_binary_to_string(ip_mask);
			SUPPLICANT_DBG("ip_mask : %s\n", data->ip_mask);
	} else if(g_str_equal(key, "IpAddrGo")) {
			DBusMessageIter array;
			char *go_ip_addr;
			dbus_message_iter_recurse(iter, &array);
			dbus_message_iter_get_fixed_array(&array, &go_ip_addr, &addr_len);

			data->go_ip_addr = __connman_util_ipaddr_binary_to_string(go_ip_addr);
			SUPPLICANT_DBG("go_ip_addr : %s\n", data->go_ip_addr);
	} else if(g_str_equal(key, "freq")) {
			dbus_message_iter_get_basic(iter, &data->freq);
			SUPPLICANT_DBG("freq : %d\n", data->freq);
	}
}

static void signal_group_success(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	struct group_sig_data data = {};
	GSupplicantPeer *peer;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, group_sig_property, &data);
	if (!data.peer_obj_path)
		return;

	peer = g_hash_table_lookup(interface->peer_table, data.peer_obj_path);
	if (!peer)
		return;

	memcpy(peer->iface_address, data.iface_address, ETH_ALEN);
	interface->pending_peer_path = peer->path;
}

static void signal_group_failure(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	struct group_sig_data data = {};
	GSupplicantPeer *peer;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, group_sig_property, &data);
	if (!data.peer_obj_path)
		return;

	peer = g_hash_table_lookup(interface->peer_table, data.peer_obj_path);
	if (!peer)
		return;

	peer->status = data.status;

	callback_peer_changed(peer, G_SUPPLICANT_PEER_GROUP_FAILED);
	peer->connection_requested = false;
}

static void p2p_group_property(const char *key, DBusMessageIter *iter,
												void *user_data)
{
	GSupplicantGroup *group = user_data;

	SUPPLICANT_DBG("key %s", key);

	if (!key) {
		callback_p2p_group_started(group);
		return;
	}

	if (!iter)
		return;

	if (g_strcmp0(key, "SSID") == 0) {
		DBusMessageIter array;
		char *ssid;
		int ssid_len;

		dbus_message_iter_recurse(iter, &array);
		dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

		if (ssid_len > 0 && ssid_len < 33) {
			group->ssid = g_strndup(ssid, ssid_len);
		}
	} else if (g_strcmp0(key, "Passphrase") == 0) {
		char *passphrase;

		dbus_message_iter_get_basic(iter, &passphrase);
		group->passphrase = g_strdup(passphrase);
	} else if (g_strcmp0(key, "Frequency") == 0) {
		dbus_uint16_t frequency = 0;

		dbus_message_iter_get_basic(iter, &frequency);
		group->frequency = frequency;
	}
}

static void p2p_group_ssid_property(const char *key, DBusMessageIter *iter,
										void *user_data)
{
	GSupplicantGroup *group = user_data;
	char *ssid;
	int len = 0;
	DBusMessageIter iter_array;
	GSupplicantPeer *peer = NULL;

	if(iter == NULL)
		return;

	dbus_message_iter_recurse(iter, &iter_array);

	dbus_message_iter_get_fixed_array(&iter_array, &ssid, &len);

	if(len >= MAX_P2P_SSID_LEN)
		len = MAX_P2P_SSID_LEN - 1;

	group->ssid = g_strndup(ssid, len);
	callback_p2p_group_started(group);
}

static void p2p_group_psk_property(const char *key, DBusMessageIter *iter,
										void *user_data)
{
	GSupplicantGroup *group = user_data;
	int len = 0;
	unsigned char *psk;
	char psk_s[65];
	DBusMessageIter iter_array;

	if(iter == NULL)
		return;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
	{
		SUPPLICANT_DBG("not array %d\n", dbus_message_iter_get_arg_type(iter));
		return;
	}

	dbus_message_iter_recurse(iter, &iter_array);

	dbus_message_iter_get_fixed_array(&iter_array, &psk, &len);
	__connman_util_byte_to_string(psk, psk_s, len);
	group->psk = g_strdup(psk_s);
	SUPPLICANT_DBG("psk : %s\n", group->psk);
}

static void p2p_group_passphrase_property(const char *key, DBusMessageIter *iter,
												void *user_data)
{
	GSupplicantGroup *group = user_data;
	char *passphrase;

	if(iter == NULL)
		return;

	dbus_message_iter_get_basic(iter, &passphrase);
	group->passphrase = g_strdup(passphrase);

	SUPPLICANT_DBG("passphrase : %s\n", group->passphrase);

}

static void interface_p2p_group_started(GSupplicantGroup *group) {

	if (!group->path)
		return;

	supplicant_dbus_property_get(group->path, SUPPLICANT_INTERFACE ".Group",
							"PSK", p2p_group_psk_property, group, NULL);

	supplicant_dbus_property_get(group->path, SUPPLICANT_INTERFACE ".Group",
							"Passphrase", p2p_group_passphrase_property, group, NULL);

	supplicant_dbus_property_get(group->path, SUPPLICANT_INTERFACE ".Group",
							"SSID", p2p_group_ssid_property, group, NULL);
}

static void signal_group_started(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface, *g_interface;
	struct group_sig_data data = {0,};
	GSupplicantGroup *group;
	GSupplicantPeer *peer = NULL;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, group_sig_property, &data);
	if (!data.interface_obj_path || !data.group_obj_path)
		return;

	if (interface->pending_peer_path) {
		peer = g_hash_table_lookup(interface->peer_table,
							interface->pending_peer_path);
		interface->pending_peer_path = NULL;
		if (!peer)
			return;
	}

	g_interface = g_hash_table_lookup(interface_table,
						data.interface_obj_path);
	if (!g_interface)
		return;

	group = g_hash_table_lookup(interface->group_table,
						data.group_obj_path);
	if (group)
		return;

	group = g_try_new0(GSupplicantGroup, 1);
	if (!group)
		return;

	group->interface = g_interface;
	group->orig_interface = interface;
	group->path = g_strdup(data.group_obj_path);
	group->role = data.role;
	group->persistent = data.persistent;
	group->bssid_no_colon = g_strdup(data.dev_addr_buf);
	group->ip_addr = g_strdup(data.ip_addr);
	group->ip_mask= g_strdup(data.ip_mask);
	group->go_ip_addr = g_strdup(data.go_ip_addr);
	group->frequency = data.freq;

	g_hash_table_insert(interface->group_table, group->path, group);
	g_hash_table_replace(group_mapping, group->path, group);

	if (!peer) {
		peer = g_supplicant_interface_peer_lookup(group->orig_interface, group->bssid_no_colon);
	}

	if (peer) {
		peer->current_group_iface = g_interface;
		callback_peer_changed(peer, G_SUPPLICANT_PEER_GROUP_STARTED);
	}

	interface_p2p_group_started(group);
}

static void remove_peer_group_interface(GHashTable *group_table,
				const char* path)
{
	GSupplicantGroup *group;
	GHashTableIter iter;
	gpointer value, key;

	if (!group_table)
		return;

	group = g_hash_table_lookup(group_table, path);

	if (!group || !group->orig_interface)
		return;

	g_hash_table_iter_init(&iter, group->orig_interface->peer_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GSupplicantPeer *peer = value;

		if (peer->current_group_iface == group->interface)
			peer->current_group_iface = NULL;
	}
}

static void remove_peer_peertable(GSupplicantInterface *interface)
{
	GHashTableIter iter;
	gpointer value, key;

	g_hash_table_iter_init(&iter, interface->peer_table);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		GSupplicantPeer *peer = value;
		char *peer_path = key;
		struct peer_device_data *p2p_data = NULL;

		if (g_hash_table_lookup(p2p_peer_table, peer_path))
		{
			if (interface->p2p_peer_path_to_network) {
				p2p_data = g_hash_table_lookup(interface->p2p_peer_path_to_network, peer_path);
				if (p2p_data == NULL) {
					g_hash_table_iter_remove(&iter);
					continue;
				}

				g_hash_table_remove(interface->p2p_peer_path_to_network, peer_path);
				p2p_network_list = g_slist_remove(p2p_network_list, p2p_data);

				g_free(p2p_data->identifier);
				g_free(p2p_data->path);
				g_free(p2p_data);
			}

			g_hash_table_iter_remove(&iter);
		}
	}
}

static void signal_group_finished(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	struct group_sig_data data = {};

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	supplicant_dbus_property_foreach(iter, group_sig_property, &data);
	if (!data.interface_obj_path || !data.group_obj_path)
		return;

	remove_peer_group_interface(interface->group_table, data.group_obj_path);

	g_hash_table_remove(group_mapping, data.group_obj_path);

	g_hash_table_remove(interface->group_table, data.group_obj_path);

	callback_p2p_group_finished(interface);
	remove_peer_peertable(interface);
}

static void signal_group_request(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	GSupplicantPeer *peer;
	const char *obj_path;
	dbus_uint16_t dev_passwd_id = 0;

	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	dbus_message_iter_get_basic(iter, &obj_path);
	if (!obj_path || !g_strcmp0(obj_path, "/"))
		return;

	peer = g_hash_table_lookup(interface->peer_table, obj_path);
	if (!peer)
		return;

	dbus_message_iter_next(iter);

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_UINT16) {
		SUPPLICANT_DBG("not uint 16\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &dev_passwd_id);

	/*
	 * Peer has been previously found and property set,
	 * otherwise, defer connection to when peer property
	 * is set.
	 */
	if (peer->identifier)
		callback_peer_request(peer, dev_passwd_id);
	else
		g_hash_table_replace(pending_peer_connection, peer->path, peer);
}

static void callback_p2p_invitation_result(GSupplicantInterface *interface, int status)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_invitation_result)
		return;

	callbacks_pointer->p2p_invitation_result(interface, status);
}
static void interface_p2p_invitation_result(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	DBusMessageIter dict, entry, value;
	char *key;
	int status = 0;

	SUPPLICANT_DBG("interface_p2p_invitation_result");

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		SUPPLICANT_DBG("not array\n");
		return;
	}

	dbus_message_iter_recurse(iter, &dict);
	if(dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY) {
		SUPPLICANT_DBG("not dict\n");
		return;
	}

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "status")) {
		SUPPLICANT_DBG("not status\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_get_basic(&value, &status);
	SUPPLICANT_DBG("status : %d\n", status);

	callback_p2p_invitation_result(interface, status);
}
static void signal_invitation_result(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal invitation result");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_invitation_result(iter, interface);
}
static void callback_p2p_invitation_received(GSupplicantInterface *interface, GSupplicantPeer *peer, const char *go_dev_addr, bool persistent)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_invitation_received)
		return;

	callbacks_pointer->p2p_invitation_received(interface, peer, go_dev_addr, persistent);
}
static void callback_p2p_pending_invitation_received(GSupplicantInterface *interface, GSupplicantPeer *peer, void * data)
{
	if (!callbacks_pointer)
		return;

	if (!callbacks_pointer->p2p_invitation_received)
		return;

	struct g_supplicant_p2p_inv_recv_info *inv_recv = data;
	callbacks_pointer->p2p_invitation_received(interface, peer, inv_recv->p2p_go_dev_addr, inv_recv->persistent);
}

static gboolean add_pending_invitation_for_peer(gpointer argv)
{
	struct g_supplicant_p2p_inv_recv_info *inv_recv = argv;
	GSupplicantInterface *interface = inv_recv->interface;

	GSupplicantPeer *peer = g_supplicant_interface_peer_lookup(interface, inv_recv->src_addr);

	if (!peer && inv_recv->get_invitation_timer_count < 10) {
			inv_recv_ref = g_timeout_add(100, add_pending_invitation_for_peer, inv_recv);
			inv_recv->get_invitation_timer_count++;
			return FALSE;
	}
	else if (peer)//Send the signal later
	{
		if (peer->path) {
			SUPPLICANT_DBG("Added signal to list print path %s" , peer->path);
			struct peer_device_data *p2p_data = g_hash_table_lookup(interface->p2p_peer_path_to_network, peer->path);

			if (!p2p_data && inv_recv->get_invitation_timer_count < 10) {
				inv_recv_ref = g_timeout_add(100, add_pending_invitation_for_peer, inv_recv);
				inv_recv->get_invitation_timer_count++;
				return FALSE;
			}

			if (p2p_data && p2p_data->path && (strcmp(peer->path, p2p_data->path) == 0)) {
				SUPPLICANT_DBG("Added signal to list print p2p_data->path  %s" , p2p_data->path);
				callback_p2p_invitation_received(interface, peer, inv_recv->p2p_go_dev_addr, inv_recv->persistent);
				goto done;
			}
		}

		struct g_supplicant_p2p_peer_signal* signal = g_try_new0(struct g_supplicant_p2p_peer_signal, 1);
		if(signal == NULL)
		{
			goto done;
		}

		signal->callback_params = (void *)inv_recv;
		signal->free_function = g_free;
		signal->dispatch_function = callback_p2p_pending_invitation_received;
		peer->pending_invitation_signals = g_slist_append(peer->pending_invitation_signals, signal);

		SUPPLICANT_DBG("Added signal to list");
		return FALSE;
	}

done:
	g_free(inv_recv);
	inv_recv_ref = -1;
	return FALSE;
}
static void interface_p2p_invitation_received(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	DBusMessageIter dict, entry, value, array;
	char *key;
	int status;
	int addr_len = 6;
	unsigned char *bssid, *go_dev_addr, *src_addr;
	char go_dev_addr_str[13], src_addr_str[13];
	char *p_go_dev_addr, *p_src_addr;

	SUPPLICANT_DBG("interface_p2p_invitation_received");

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		SUPPLICANT_DBG("not array\n");
		return;
	}

	dbus_message_iter_recurse(iter, &dict);
	if(dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY) {
		SUPPLICANT_DBG("not dict\n");
		return;
	}

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "status")) {
		SUPPLICANT_DBG("not status\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_get_basic(&value, &status);
	SUPPLICANT_DBG("status : %d\n", status);
/*
	if (status == 0) //Persistent group reinvoke case
		g_supplicant_interface_p2p_listen(interface, 0, 0);
	else
*/
	if (status != 0 && status != 1)
		return;

	dbus_message_iter_next(&dict);

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "sa")) {
		SUPPLICANT_DBG("not sa\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_recurse(&value, &array);

	dbus_message_iter_get_fixed_array(&array, &src_addr, &addr_len);

	dbus_message_iter_next(&dict);

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);

	if(!g_str_equal(key, "go_dev_addr")) {
		SUPPLICANT_DBG("not go_dev_addr\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_recurse(&value, &array);

	dbus_message_iter_get_fixed_array(&array, &go_dev_addr, &addr_len);

	dbus_message_iter_next(&dict);

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "bssid")) {
		if(status == 0)
			goto go_next; //BSSID is not exist at persistent go case
		SUPPLICANT_DBG("not bssid\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_recurse(&value, &array);

	dbus_message_iter_get_fixed_array(&array, &bssid, &addr_len);

go_next:

	__connman_util_byte_to_string(go_dev_addr, go_dev_addr_str, 6);
	p_go_dev_addr = g_strdup(go_dev_addr_str);

	__connman_util_byte_to_string(src_addr, src_addr_str, 6);
	p_src_addr = g_strdup(src_addr_str);

	if (inv_recv_ref != -1) {
		g_free(p_src_addr);
		g_free(p_go_dev_addr);
		return;
	}

	struct g_supplicant_p2p_inv_recv_info *inv_recv = g_try_new0(struct g_supplicant_p2p_inv_recv_info, 1);
	if (!inv_recv) {
		g_free(p_src_addr);
		g_free(p_go_dev_addr);
		return;
	}

	inv_recv->interface = interface;
	inv_recv->p2p_go_dev_addr = p_go_dev_addr;
	inv_recv->src_addr = p_src_addr;
	inv_recv->persistent = !status;

	inv_recv_ref = g_timeout_add(100, add_pending_invitation_for_peer, inv_recv);

	return;
}

static void signal_invitation_received(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal invitation received");

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_invitation_received(iter, interface);
}

static void empty_free_function(void* ptr)
{
	// Does nothing
}
static void fire_p2p_signal_when_network_present(GSupplicantInterface *interface,
                                                 const char* path,
                                                 g_supplicant_p2p_network_signal_func signal_func,
                                                 g_supplicant_p2p_network_signal_free_func free_func,
                                                 void* signal_params)
{
	struct peer_device_data *p2p_data;


	p2p_data = g_hash_table_lookup(interface->p2p_peer_path_to_network, path);

	if (free_func == NULL)
	{
		free_func = empty_free_function;
	}

	if(p2p_data != NULL)
	{
		//Send signal right away
		GSupplicantPeer *peer;
		peer = g_hash_table_lookup(interface->peer_table, p2p_data->path);

		signal_func(interface, peer, signal_params);
		free_func(signal_params);
	}
	else //Send the signal later
	{
		GSupplicantPeer *peer;
		SUPPLICANT_DBG("network not present, delaying signal dispatch");

		peer = g_hash_table_lookup(interface->peer_table, path);

		if (peer == NULL)
		{
			free_func(signal_params);
			SUPPLICANT_DBG("failed - no peer for path %s", path);
			return;
		}

		struct g_supplicant_p2p_peer_signal* signal = g_try_new0(struct g_supplicant_p2p_peer_signal, 1);
		if(signal == NULL)
		{
			free_func(signal_params);
			return;
		}

		signal->callback_params = signal_params;
		signal->free_function = free_func;
		signal->dispatch_function = signal_func;
		peer->pending_signals = g_slist_append(peer->pending_signals, signal);

		SUPPLICANT_DBG("Added signal to list");

	}
}
static void interface_p2p_prov_disc_request_or_response(DBusMessageIter *iter,
					void *user_data, bool is_request, char *wps_method)
{
	GSupplicantInterface *interface = user_data;
	char *path, *pin = NULL;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH) {
		SUPPLICANT_DBG("not object path\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &path);

	if (g_str_equal(wps_method, "disp_pin")) {
		dbus_message_iter_next(iter);

		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
			SUPPLICANT_DBG("not string\n");
			return;
		}

		dbus_message_iter_get_basic(iter, &pin);

		if (!pin || strlen(pin) != WPAS_P2P_WPS_PIN_LENGTH) {
			SUPPLICANT_DBG("strange\n");
			return;
		}
	}

	g_supplicant_p2p_prov_dics_signal_func callback_method = NULL;

	if (is_request) {
		if (g_str_equal(wps_method, "pbc"))
			callback_method = callback_p2p_prov_disc_requested_pbc;
		else if (g_str_equal(wps_method, "enter_pin"))
			callback_method = callback_p2p_prov_disc_requested_enter_pin;
		else if (g_str_equal(wps_method, "disp_pin"))
			callback_method = callback_p2p_prov_disc_requested_display_pin;
	}
	else {
		if (g_str_equal(wps_method, "enter_pin"))
			callback_method = callback_p2p_prov_disc_response_enter_pin;
		else if (g_str_equal(wps_method, "disp_pin"))
			callback_method = callback_p2p_prov_disc_response_display_pin;
	}

	if (callback_method)
	{
		pin = g_strdup(pin);
		fire_p2p_signal_when_network_present(interface,
		                                     path,
		                                     callback_method,
		                                     g_free,
		                                     (void *)pin);
	}
}

static void signal_prov_disc_requested_pbc(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_request_or_response(iter, interface, true, "pbc");
}

static void signal_prov_disc_requested_enter_pin(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_request_or_response(iter, interface, true, "enter_pin");
}

static void signal_prov_disc_requested_disp_pin(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_request_or_response(iter, interface, true, "disp_pin");
}

static void signal_prov_disc_response_enter_pin(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_request_or_response(iter, interface, false, "enter_pin");
}

static void signal_prov_disc_response_disp_pin(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_request_or_response(iter, interface, false, "disp_pin");
}

static void interface_p2p_prov_disc_fail(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	GSupplicantPeer *peer;
	const char *path;
	int status;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH) {
		SUPPLICANT_DBG("not object path\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &path);

	dbus_message_iter_next(iter);

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_INT32) {
		SUPPLICANT_DBG("not int32\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &status);

	peer = g_hash_table_lookup(interface->peer_table, path);

	if (!peer)
		return;

	callback_p2p_prov_disc_fail(interface, peer, status);
}
static void signal_prov_disc_fail(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface)
		return;

	interface_p2p_prov_disc_fail(iter, interface);
}
static void p2p_persistent_group_property_by_added(const char *key, DBusMessageIter *iter, void *user_data)
{
	GSupplicantP2PPersistentGroup *persistent_group = user_data;

	if(persistent_group == NULL){
		return;
	}

	if (key == NULL) {
		callback_p2p_persistent_group_added(persistent_group->interface, persistent_group);
		return;
	}

	if(g_strcmp0(key, "bssid") == 0) {
		char *bssid;
		dbus_message_iter_get_basic(iter, &bssid);
		persistent_group->bssid = g_strdup(bssid);
		remove_colon(bssid);
		persistent_group->bssid_no_colon = g_strdup(bssid);
		SUPPLICANT_DBG("bssid : %s\n", persistent_group->bssid);
	} else if(g_strcmp0(key, "binary-ssid") == 0) {
		/*
		 * In persistent case, when p2p-SSID is in Korean,
		 * connman cannot save the persistent information in connman config file.
		 * It changes string to byte array in Korean SSID which is encoded EUC-KR.
		 */
		const char *ssid;
		int len = 0;
		DBusMessageIter iter_array;
		dbus_message_iter_recurse(iter, &iter_array);

		dbus_message_iter_get_fixed_array(&iter_array, &ssid, &len);

		if(len >= MAX_P2P_SSID_LEN)
			len = MAX_P2P_SSID_LEN - 1;

		persistent_group->ssid = g_strndup(ssid, len);
		SUPPLICANT_DBG("ssid : %s\n", persistent_group->ssid);
	} else if(g_strcmp0(key, "psk") == 0) {
		const char *psk;
		dbus_message_iter_get_basic(iter, &psk);
		persistent_group->psk = g_strdup(psk);
		SUPPLICANT_DBG("psk : %s\n", persistent_group->psk);
	}
}
static void interface_persistent_group_added(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	char *pg_path;
	int ret;
	GSupplicantP2PPersistentGroup *persistent_group;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH) {
		SUPPLICANT_DBG("not object path\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &pg_path);

	/* signal data parsed if needed */

	persistent_group = g_try_new0(GSupplicantP2PPersistentGroup, 1);
	if (persistent_group == NULL){
		return;
	}

	persistent_group->interface = interface;
	persistent_group->path = g_strdup(pg_path);

	ret=supplicant_dbus_property_get_all(persistent_group->path,
					SUPPLICANT_INTERFACE ".PersistentGroup",
					p2p_persistent_group_property_by_added, persistent_group, NULL);
	if(ret<0) {
		g_free(persistent_group);
	}
}
static void signal_persistent_group_added(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal persistent group added");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_persistent_group_added(iter, interface);
}
static void interface_persistent_group_removed(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	char *pg_path;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_OBJECT_PATH) {
		SUPPLICANT_DBG("not object path\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &pg_path);

	callback_p2p_persistent_group_removed(interface, pg_path);
}
static void signal_persistent_group_removed(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal persistent group removed");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_persistent_group_removed(iter, interface);
}
static void interface_p2p_sd_response(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	DBusMessageIter dict, entry, value, array;
	char *key;
	char *peer_path;
	dbus_uint16_t indicator;
	int tlv_len = 0;
	unsigned char *tlv;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY) {
		SUPPLICANT_DBG("not array\n");
		return;
	}

	dbus_message_iter_recurse(iter, &dict);
	if(dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY) {
		SUPPLICANT_DBG("not dict\n");
		return;
	}

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "peer_object")) {
		SUPPLICANT_DBG("not peer_object\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_get_basic(&value, &peer_path);
	SUPPLICANT_DBG("peer_path : %s\n", peer_path);

	dbus_message_iter_next(&dict);

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "update_indicator")) {
		SUPPLICANT_DBG("not update_indicator\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_get_basic(&value, &indicator);
	SUPPLICANT_DBG("indicator : %d\n", indicator);

	dbus_message_iter_next(&dict);

	dbus_message_iter_recurse(&dict, &entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(&entry, &key);
	SUPPLICANT_DBG("key : %s\n", key);
	if(!g_str_equal(key, "tlvs")) {
		SUPPLICANT_DBG("not tlvs\n");
		return;
	}

	dbus_message_iter_next(&entry);
	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		SUPPLICANT_DBG("not variant\n");
		return;
	}

	dbus_message_iter_recurse(&entry, &value);
	dbus_message_iter_recurse(&value, &array);

	dbus_message_iter_get_fixed_array(&array, &tlv, &tlv_len);

	GSupplicantPeer *peer;
	peer = g_hash_table_lookup(interface->peer_table, peer_path);
	if (!peer)
	   return;

	callback_p2p_sd_response(interface, peer, indicator, tlv, tlv_len);
}
static void signal_sd_response(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal service discovery response");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_p2p_sd_response(iter, interface);
}
static void callback_p2p_sd_asp_response(GSupplicantInterface *interface, GSupplicantPeer *peer,
										 unsigned char transaction_id,
										 unsigned int advertisement_id,
										 unsigned char service_status,
										 dbus_uint16_t config_method,
										 const char* service_name,
										 const char* service_info)
{
	if (callbacks_pointer == NULL)
		return;

	if (callbacks_pointer->p2p_sd_asp_response == NULL)
		return;

	callbacks_pointer->p2p_sd_asp_response(interface, peer,
									   transaction_id,
									   advertisement_id,
									   service_status,
									   config_method,
									   service_name,
									   service_info);
}
static void interface_p2p_sd_asp_response(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *peer_path;
	unsigned char transaction_id;
	unsigned int advertisement_id;
	unsigned char service_status;
	dbus_uint16_t config_method;
	const char* service_name = NULL;
	const char* service_info = NULL;

	if (!dbus_message_get_args_from_array_of_sv(iter,
												DBUS_TYPE_OBJECT_PATH, "peer_object", &peer_path, true,
												DBUS_TYPE_BYTE, "service_transaction_id", &transaction_id, true,
												DBUS_TYPE_UINT32, "adv_id", &advertisement_id, true,
												DBUS_TYPE_BYTE, "service_status", &service_status, true,
												DBUS_TYPE_UINT16, "config_method", &config_method, true,
												DBUS_TYPE_STRING, "service_name", &service_name, true,
												DBUS_TYPE_STRING, "service_info", &service_info, false,
												DBUS_TYPE_INVALID)) {
		SUPPLICANT_DBG("could not parse DBUS message\n");
		return;
	}


	GSupplicantPeer *peer;
	peer = g_hash_table_lookup(interface->peer_table, peer_path);
	if (!peer)
	   return;

	callback_p2p_sd_asp_response(interface, peer,
								 transaction_id,
								 advertisement_id,
								 service_status,
								 config_method,
								 service_name,
								 service_info);
}

static void signal_sd_asp_response(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	SUPPLICANT_DBG("signal service discovery ASP response");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_p2p_sd_asp_response(iter, interface);
}
static void interface_p2ps_prov_done(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *path;
	GSupplicantP2PSProvisionSignalParams* params;
	const char* service_mac = "";
	const char* session_mac = "";
	const char* group_mac = "";

	params = g_try_new0(GSupplicantP2PSProvisionSignalParams, 1);
	if(params == NULL)
		return;

	if (!dbus_message_get_args_from_array_of_sv(iter,
												DBUS_TYPE_OBJECT_PATH, "peer_object", &path, true,
												DBUS_TYPE_UINT32, "adv_id", &params->advertisement_id, true,
												DBUS_TYPE_STRING, "adv_mac", &service_mac, true,
												DBUS_TYPE_UINT32, "session_id", &params->session_id, true,
												DBUS_TYPE_STRING, "session_mac", &session_mac, true,
												DBUS_TYPE_UINT32, "status", &params->status, true,
												DBUS_TYPE_UINT32, "connection_capability", &params->connection_capability, true,
												DBUS_TYPE_UINT32, "passwd_id", &params->password_id, true,
												DBUS_TYPE_UINT32, "persist", &params->persist, false,
												DBUS_TYPE_STRING, "group_mac", &group_mac, false,
												//DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, "feature_capability", &feature_capability_array, &feature_capability_len,
												DBUS_TYPE_INVALID)) {
		SUPPLICANT_DBG("could not parse DBUS message\n");
		g_free(params);
		return;
	}

	(void)g_strlcpy(params->session_mac, session_mac, 18);
	(void)g_strlcpy(params->service_mac, service_mac, 18);
	(void)g_strlcpy(params->group_mac, group_mac, 18);

	GSupplicantPeer *peer;
	peer = g_hash_table_lookup(interface->peer_table, path);
	if (!peer) {
	   g_free(params);
	   return;
	}

	fire_p2p_signal_when_network_present(interface,
	                                     path,
	                                     (g_supplicant_p2p_network_signal_func)callback_p2ps_prov_done,
	                                     g_free,
	                                     params);
	//callback_p2ps_prov_done(interface, peer, params);
}
static void interface_p2ps_prov_start(DBusMessageIter *iter, void *user_data)
{
	GSupplicantInterface *interface = user_data;
	const char *path;
	GSupplicantP2PSProvisionSignalParams* params;
	const char* service_mac = "";
	const char* session_mac = "";
	const char* session_info = "";

	params = g_try_new0(GSupplicantP2PSProvisionSignalParams, 1);
	if(params == NULL)
		return;

	SUPPLICANT_DBG("");

	if (!dbus_message_get_args_from_array_of_sv(iter,
												DBUS_TYPE_OBJECT_PATH, "peer_object", &path, true,
												DBUS_TYPE_UINT32, "adv_id", &params->advertisement_id, true,
												DBUS_TYPE_STRING, "adv_mac", &service_mac, true,
												DBUS_TYPE_UINT32, "session_id", &params->session_id, true,
												DBUS_TYPE_STRING, "session_mac", &session_mac, true,
												DBUS_TYPE_UINT32, "connection_capability", &params->connection_capability, true,
												DBUS_TYPE_UINT32, "passwd_id", &params->password_id, false,
												DBUS_TYPE_STRING, "session_info", &session_info, false,
												//TODO: get feature_cap
												//DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, "feature_capability", &feature_capability_array, &feature_capability_len,
												DBUS_TYPE_INVALID)) {
		SUPPLICANT_DBG("could not parse DBUS message\n");
		g_free(params);
		return;
	}

	(void)g_strlcpy(params->session_mac, session_mac, 18);
	(void)g_strlcpy(params->service_mac, service_mac, 18);
	(void)g_strlcpy(params->session_info, session_info, 150);

	SUPPLICANT_DBG("");
	GSupplicantPeer *peer;
	peer = g_hash_table_lookup(interface->peer_table, path);
	if (!peer) {
	   g_free(params);
	   return;
	}

	fire_p2p_signal_when_network_present(interface,
	                                     path,
	                                     (g_supplicant_p2p_network_signal_func)callback_p2ps_prov_start,
	                                     g_free,
	                                     params);
}
static void signal_p2ps_prov_start(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;
	SUPPLICANT_DBG("");

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_p2ps_prov_start(iter, interface);
}

static void signal_p2ps_prov_done(const char *path, DBusMessageIter *iter)
{
	GSupplicantInterface *interface;

	interface = g_hash_table_lookup(interface_table, path);
	if (interface == NULL)
		return;

	interface_p2ps_prov_done(iter, interface);
}
static void extract_peer_with_ip(const char *path, DBusMessageIter *iter, connman_bool_t joined, bool is_ip_present);

static void signal_group_peer_joined(const char *path, DBusMessageIter *iter)
{
	//const char *peer_path = NULL;
	extract_peer_with_ip(path, iter, TRUE, false);
}
static gboolean peer_joined_with_ip(gpointer data)
{
	GSupplicantPeer *peer = data;

	callback_peer_changed(peer, G_SUPPLICANT_PEER_GROUP_JOINED);

	return FALSE;
}
static bool find_p2p_network(GSupplicantRequestedPeer *requested_peer)
{
	GSList *item;
	struct peer_device_data *p2p_network=NULL;
	unsigned char p2p_dev_addr_byte[6] = {0,};
	int i;
	bool same = false;

	if (requested_peer == NULL)
		return false;

	string_to_byte(requested_peer->requested_p2p_dev_addr, p2p_dev_addr_byte);

	item = p2p_network_list;

	while(item) {
		p2p_network = item->data;
		same = true;
		for(i = 0; i < 6; i++) {
			if(p2p_network->p2p_device_addr[i] != p2p_dev_addr_byte[i]) {
				same = false;
				break;
			}
		}

		if(same)
			break;

		item = g_slist_next(item);
		p2p_network = NULL;
	}

	requested_peer->found_p2p_network = p2p_network;

	return same;
}
static gboolean requested_peer_joined_with_ip(gpointer data)
{
	GSupplicantRequestedPeer *requested_peer = data;

	GSupplicantGroup *group;
	GSupplicantInterface *interface;
	GSupplicantPeer *peer;
	struct peer_device_data *p2p_network=NULL;

	if (requested_peer == NULL)
			return FALSE;

	group = g_hash_table_lookup(group_mapping, requested_peer->requested_path);
	if (!group)
		goto error;

	if (requested_peer->found_p2p_network == NULL){
		if(!find_p2p_network(requested_peer))
			goto error;
	}

	p2p_network = requested_peer->found_p2p_network;

	interface = g_hash_table_lookup(peer_mapping, p2p_network->path);
	if (!interface)
		goto error;

	peer = g_hash_table_lookup(interface->peer_table, p2p_network->path);
	if (!peer) {
		g_hash_table_remove(peer_mapping, requested_peer->requested_path);
		goto error;
	}

	peer->current_group_iface = group->interface;
	if (requested_peer->requested_is_ip_present) {
		peer->ip_addr = g_strdup(requested_peer->requested_ip_addr);
	}
	group->members = g_slist_prepend(group->members, g_strdup(p2p_network->path));

	g_timeout_add(300, peer_joined_with_ip, peer);

error:
	g_free(requested_peer->requested_p2p_dev_addr);
	g_free(requested_peer->requested_path);
	g_free(requested_peer->requested_ip_addr);
	requested_peer->found_p2p_network = NULL;

	g_free(requested_peer);
	requested_peer = NULL;

	return FALSE;
}
GSupplicantGroup *g_supplicant_get_group(const char *path)
{
	GSupplicantGroup *group;

	if (!path)
		return NULL;

	group = g_hash_table_lookup(group_mapping, path);
	if (!group)
		return NULL;

	return group;
}
static void extract_peer_with_ip(const char *path, DBusMessageIter *iter, connman_bool_t joined, bool is_ip_present)
{
	GSupplicantGroup *group;
	GSupplicantPeer *peer;
	GSupplicantRequestedPeer *requested_peer;
	const char *peer_path;
	const char *ip_addr;
	char *intf_addr, *pintf_addr;
	char *p2p_dev_addr = NULL;
	char *dev_addr = NULL;
	unsigned char intf_addr_byte[6];

	group = g_hash_table_lookup(group_mapping, path);
	if (!group)
		return;

	dbus_message_iter_get_basic(iter, &peer_path);
	if (!peer_path)
		return;

	if (is_ip_present) {
		dbus_message_iter_next(iter);
		if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
			SUPPLICANT_DBG("not string\n");
			return;
		}
		dbus_message_iter_get_basic(iter, &ip_addr);
	}

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &p2p_dev_addr);
	if (!p2p_dev_addr)
		return;

	requested_peer = g_try_new0(GSupplicantRequestedPeer, 1);
	if (requested_peer == NULL)
		return;

	if (is_ip_present)
		requested_peer->requested_ip_addr = g_strdup(ip_addr);

	requested_peer->requested_path = g_strdup(path);
	requested_peer->requested_p2p_dev_addr = g_strdup(p2p_dev_addr);
	requested_peer->requested_is_ip_present = is_ip_present;

	intf_addr = strrchr(peer_path, '/') + 1;

	if(joined == TRUE) {
		pintf_addr = g_strdup(intf_addr);
		g_hash_table_replace(intf_addr_mapping, g_strdup(peer_path), pintf_addr);
	} else {
		pintf_addr = g_hash_table_lookup(intf_addr_mapping, peer_path);

		if(pintf_addr == NULL)
			goto error;
	}

	dev_addr = g_hash_table_lookup(dev_addr_mapping, pintf_addr);
	if(!dev_addr) {
		g_hash_table_replace(dev_addr_mapping, g_strdup(pintf_addr), g_strdup(p2p_dev_addr));
	}

	if (find_p2p_network(requested_peer))
		(void)requested_peer_joined_with_ip(requested_peer);
	else
		g_timeout_add(200, requested_peer_joined_with_ip, requested_peer);

	return;

error:
	g_free(requested_peer->requested_path);
	g_free(requested_peer->requested_p2p_dev_addr);
	g_free(requested_peer->requested_ip_addr);
	requested_peer->found_p2p_network = NULL;

	g_free(requested_peer);
	requested_peer = NULL;
}
static void signal_peer_joined_with_ip(const char *path, DBusMessageIter *iter)
{
	SUPPLICANT_DBG("signal peer joined with ip");

	extract_peer_with_ip(path, iter, TRUE, true);
}

GSupplicantP2PNetwork* g_supplicant_find_network_from_intf_address(const char* pintf_addr, const char* p2p_dev_addr)
{
	struct peer_device_data *p2p_network = NULL;
	unsigned char intf_addr_byte[6];
	unsigned char p2p_dev_addr_byte[6] = {0};
	GSList *item;
	int i;
	bool same;

	string_to_byte(pintf_addr, intf_addr_byte);
	string_to_byte(p2p_dev_addr, p2p_dev_addr_byte);

	item = p2p_network_list;

	while(item) {
		p2p_network = item->data;
		same = true;

		for(i = 0; i < 6; i++) {
			if(p2p_network->p2p_device_addr[i] != p2p_dev_addr_byte[i]) {
				same = false;
				break;
			}
		}
		if(same)
			break;

		item = g_slist_next(item);
		p2p_network = NULL;
	}

	return p2p_network;
}

/* @pintf_addr: interface mac address in the form of 0012233445a */
const char * g_supplicant_peer_identifier_from_intf_address(const char* pintf_addr)
{
	struct peer_device_data *p2p_network = NULL;
	unsigned char intf_addr_byte[6];
	unsigned char p2p_dev_addr_byte[6] = {0};
	GSList *item;
	int i;
	bool same;
	GSupplicantPeer *peer = NULL;
	GSupplicantInterface *interface;
	char *p2p_dev_addr = NULL;

	p2p_dev_addr = g_hash_table_lookup(dev_addr_mapping, pintf_addr);
	if(!p2p_dev_addr)
		return peer;

	string_to_byte(p2p_dev_addr, p2p_dev_addr_byte);
	string_to_byte(pintf_addr, intf_addr_byte);

	item = p2p_network_list;

	while(item) {
		p2p_network = item->data;
		same = true;

		for(i = 0; i < 6; i++) {
			if(p2p_network->p2p_device_addr[i] != p2p_dev_addr_byte[i]) {
				same = false;
				break;
			}
		}

		if(same)
			break;

		item = g_slist_next(item);
		p2p_network = NULL;
	}

	if(p2p_network == NULL)
		return peer;

	interface = g_hash_table_lookup(peer_mapping, p2p_network->path);
	if (!interface)
		return peer;

	peer = g_hash_table_lookup(interface->peer_table, p2p_network->path);

	return g_supplicant_peer_get_identifier(peer);
}

static void signal_group_peer_disconnected(const char *path, DBusMessageIter *iter)
{
	const char *peer_path = NULL;
	GSupplicantInterface *interface;
	GSupplicantGroup *group;
	GSupplicantPeer *peer;
	struct peer_device_data *p2p_network = NULL;
	char  *pintf_addr;
	char *p2p_dev_addr = NULL;

	GSList *elem;

	SUPPLICANT_DBG("");

	group = g_hash_table_lookup(group_mapping, path);
	if (!group)
		return;

	dbus_message_iter_get_basic(iter, &peer_path);
	if (!peer_path)
		return;

	dbus_message_iter_next(iter);
	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
		SUPPLICANT_DBG("not string\n");
		return;
	}

	dbus_message_iter_get_basic(iter, &p2p_dev_addr);
	if (!p2p_dev_addr)
		return;

	pintf_addr = g_hash_table_lookup(intf_addr_mapping, peer_path);
	if (pintf_addr == NULL)
		return;

	p2p_network = g_supplicant_find_network_from_intf_address(pintf_addr, p2p_dev_addr);

	if (p2p_network == NULL)
		return;

	g_hash_table_remove(dev_addr_mapping, pintf_addr);

	for (elem = group->members; elem; elem = elem->next) {
		if (!g_strcmp0(elem->data, p2p_network->path))
			break;
	}

	if (!elem)
		return;

	g_free(elem->data);
	group->members = g_slist_delete_link(group->members, elem);

	interface = g_hash_table_lookup(peer_mapping, p2p_network->path);
	if (!interface)
		return;

	peer = g_hash_table_lookup(interface->peer_table, p2p_network->path);
	if (!peer)
		return;

	callback_peer_changed(peer, G_SUPPLICANT_PEER_GROUP_DISCONNECTED);
	peer->connection_requested = false;
}

static struct {
	const char *interface;
	const char *member;
	void (*function) (const char *path, DBusMessageIter *iter);
} signal_map[] = {
	{ DBUS_INTERFACE_DBUS,  "NameOwnerChanged",  signal_name_owner_changed },

	{ SUPPLICANT_INTERFACE, "PropertiesChanged", signal_properties_changed },
	{ SUPPLICANT_INTERFACE, "InterfaceAdded",    signal_interface_added    },
	{ SUPPLICANT_INTERFACE, "InterfaceCreated",  signal_interface_added    },
	{ SUPPLICANT_INTERFACE, "InterfaceRemoved",  signal_interface_removed  },

	{ SUPPLICANT_INTERFACE ".Interface", "PropertiesChanged", signal_interface_changed },
	{ SUPPLICANT_INTERFACE ".Interface", "ScanDone",          signal_scan_done         },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSAdded",          signal_bss_added         },
	{ SUPPLICANT_INTERFACE ".Interface", "BSSRemoved",        signal_bss_removed       },
	{ SUPPLICANT_INTERFACE ".Interface", "NetworkAdded",      signal_network_added     },
	{ SUPPLICANT_INTERFACE ".Interface", "NetworkRemoved",    signal_network_removed   },
	{ SUPPLICANT_INTERFACE ".Interface", "StaAuthorized",     signal_sta_authorized    },
	{ SUPPLICANT_INTERFACE ".Interface", "StaDeauthorized",   signal_sta_deauthorized  },

	{ SUPPLICANT_INTERFACE ".Interface", "StaAuthorized",     signal_station_connected   },
	{ SUPPLICANT_INTERFACE ".Interface", "StaDeauthorized",   signal_station_disconnected },

	{ SUPPLICANT_INTERFACE ".BSS", "PropertiesChanged", signal_bss_changed   },

	{ SUPPLICANT_INTERFACE ".Interface.WPS", "Credentials", signal_wps_credentials },
	{ SUPPLICANT_INTERFACE ".Interface.WPS", "Event",       signal_wps_event       },

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "DeviceFound", signal_peer_found },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "DeviceLost",  signal_peer_lost  },

	{ SUPPLICANT_INTERFACE ".Peer", "PropertiesChanged", signal_peer_changed },

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "GONegotiationSuccess", signal_group_success },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "GONegotiationFailure", signal_group_failure },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "PersistentGroupAdded", signal_persistent_group_added	},
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "PersistentGroupRemoved", signal_persistent_group_removed	},
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "GroupStarted", signal_group_started },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "GroupFinished", signal_group_finished },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "GONegotiationRequest", signal_group_request },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ServiceDiscoveryResponse", signal_sd_response	},
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ServiceDiscoveryASPResponse", signal_sd_asp_response	},

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "P2PSProvisionStart", signal_p2ps_prov_start	},
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "P2PSProvisionDone",	 signal_p2ps_prov_done	},

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryPBCRequest",	signal_prov_disc_requested_pbc },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryRequestEnterPin",	signal_prov_disc_requested_enter_pin },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryRequestDisplayPin",	signal_prov_disc_requested_disp_pin },

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryResponseEnterPin",	signal_prov_disc_response_enter_pin },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryResponseDisplayPin",	signal_prov_disc_response_disp_pin },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ProvisionDiscoveryFailure",	signal_prov_disc_fail },

	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "InvitationResult", signal_invitation_result },
	{ SUPPLICANT_INTERFACE ".Interface.P2PDevice", "InvitationReceived", signal_invitation_received	},
	{ SUPPLICANT_INTERFACE ".Group", "PeerJoined", signal_group_peer_joined },
	{ SUPPLICANT_INTERFACE ".Group", "PeerJoinedWithIP", signal_peer_joined_with_ip },
	{ SUPPLICANT_INTERFACE ".Group", "PeerDisconnected", signal_group_peer_disconnected },

	{ }
};

static DBusHandlerResult g_supplicant_filter(DBusConnection *conn,
					DBusMessage *message, void *data)
{
	DBusMessageIter iter;
	const char *path;
	int i;

	path = dbus_message_get_path(message);
	if (!path)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_message_iter_init(message, &iter))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	for (i = 0; signal_map[i].interface; i++) {
		if (!dbus_message_has_interface(message, signal_map[i].interface))
			continue;

		if (!dbus_message_has_member(message, signal_map[i].member))
			continue;

		signal_map[i].function(path, &iter);
		break;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

struct interface_p2p_invite_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PInviteParams *p2p_invite_params;
	void *user_data;
};

static void interface_p2p_invite_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_invite_data *data = user_data;

	supplicant_dbus_dict_open(iter, &dict);

	if (data && data->p2p_invite_params) {
		GSupplicantP2PInviteParams* params = data->p2p_invite_params;

		supplicant_dbus_dict_append_basic(&dict, "peer",
					DBUS_TYPE_OBJECT_PATH, &params->peer);

		if(params->persistent_group)
			supplicant_dbus_dict_append_basic(&dict, "persistent_group_object",
					DBUS_TYPE_OBJECT_PATH, &params->persistent_group);
	}

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_invite_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_invite_data *data = user_data;
	int err = 0;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}
int g_supplicant_interface_p2p_invite(GSupplicantInterface *interface,
				GSupplicantP2PInviteParams *invite_data,
				GSupplicantInterfaceCallback callback, void *user_data)
{
	struct interface_p2p_invite_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;
	data->p2p_invite_params = invite_data;

	SUPPLICANT_DBG("interface->path : %s\n", interface->path);

	ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice",
					"Invite",
					interface_p2p_invite_params,
					interface_p2p_invite_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

void g_supplicant_interface_cancel(GSupplicantInterface *interface)
{
	if (!interface)
		return;

	SUPPLICANT_DBG("Cancelling any pending DBus calls");
	supplicant_dbus_method_call_cancel_all(interface);
	supplicant_dbus_property_call_cancel_all(interface);
}

struct supplicant_regdom {
	GSupplicantCountryCallback callback;
	const char *alpha2;
	const void *user_data;
};

static void country_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct supplicant_regdom *regdom = user_data;
	int result = 0;

	SUPPLICANT_DBG("Country setting result");

	if (!user_data)
		return;

	if (error) {
		SUPPLICANT_DBG("Country setting failure %s", error);
		result = -EINVAL;
	}

	if (regdom->callback)
		regdom->callback(result, regdom->alpha2,
					(void *) regdom->user_data);

	g_free(regdom);
}

static void country_params(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_regdom *regdom = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING,
							&regdom->alpha2);
}

int g_supplicant_set_country(const char *alpha2,
				GSupplicantCountryCallback callback,
					const void *user_data)
{
	struct supplicant_regdom *regdom;
	int ret;

	SUPPLICANT_DBG("Country setting %s", alpha2);

	if (!system_available)
		return -EFAULT;

	regdom = dbus_malloc0(sizeof(*regdom));
	if (!regdom)
		return -ENOMEM;

	regdom->callback = callback;
	regdom->alpha2 = alpha2;
	regdom->user_data = user_data;

	ret =  supplicant_dbus_property_set(SUPPLICANT_PATH, SUPPLICANT_INTERFACE,
					"Country", DBUS_TYPE_STRING_AS_STRING,
					country_params, country_result,
					regdom, NULL);
	if (ret < 0) {
		dbus_free(regdom);
		SUPPLICANT_DBG("Unable to set Country configuration");
	}
	return ret;
}

int g_supplicant_interface_set_country(GSupplicantInterface *interface,
					GSupplicantCountryCallback callback,
							const char *alpha2,
							void *user_data)
{
	struct supplicant_regdom *regdom;
	int ret;

	if (!interface)
		return -EINVAL;
	regdom = dbus_malloc0(sizeof(*regdom));
	if (!regdom)
		return -ENOMEM;

	regdom->callback = callback;
	regdom->alpha2 = alpha2;
	regdom->user_data = user_data;

	ret =  supplicant_dbus_property_set(interface->path,
				SUPPLICANT_INTERFACE ".Interface",
				"Country", DBUS_TYPE_STRING_AS_STRING,
				country_params, country_result,
					regdom, NULL);
	if (ret < 0) {
		dbus_free(regdom);
		SUPPLICANT_DBG("Unable to set Country configuration");
	}

	return ret;
}

bool g_supplicant_interface_has_p2p(GSupplicantInterface *interface)
{
	if (!interface)
		return false;

	return interface->p2p_support;
}

struct supplicant_p2p_dev_config {
	char *device_name;
	char *dev_type;
};

static void p2p_device_config_result(const char *error,
					DBusMessageIter *iter, void *user_data)
{
	struct supplicant_p2p_dev_config *config = user_data;

	if (error)
		SUPPLICANT_DBG("Unable to set P2P Device configuration: %s",
									error);

	g_free(config->device_name);
	g_free(config->dev_type);
	dbus_free(config);
}

int dev_type_str2bin(const char *type, unsigned char dev_type[8])
{
	int length, pos, end;
	char b[3] = {};
	char *e = NULL;

	end = strlen(type);
	for (length = pos = 0; type[pos] != '\0' && length < 8; length++) {
		if (pos+2 > end)
			return 0;

		b[0] = type[pos];
		b[1] = type[pos+1];

		dev_type[length] = strtol(b, &e, 16);
		if (e && *e != '\0')
			return 0;

		pos += 2;
	}

	return 8;
}

static void p2p_device_config_params(DBusMessageIter *iter, void *user_data)
{
	struct supplicant_p2p_dev_config *config = user_data;
	DBusMessageIter dict;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "DeviceName",
				DBUS_TYPE_STRING, &config->device_name);

	if (config->dev_type) {
		unsigned char dev_type[8] = {}, *type;
		int len;

		len = dev_type_str2bin(config->dev_type, dev_type);
		if (len) {
			type = dev_type;
			supplicant_dbus_dict_append_fixed_array(&dict,
					"PrimaryDeviceType",
					DBUS_TYPE_BYTE, &type, len);
		}
	}

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_set_p2p_device_config(GSupplicantInterface *interface,
					const char *device_name,
					const char *primary_dev_type)
{
	struct supplicant_p2p_dev_config *config;
	int ret;

	SUPPLICANT_DBG("P2P Device settings %s/%s",
					device_name, primary_dev_type);

	config = dbus_malloc0(sizeof(*config));
	if (!config)
		return -ENOMEM;

	config->device_name = g_strdup(device_name);
	config->dev_type = g_strdup(primary_dev_type);

	ret = supplicant_dbus_property_set(interface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"P2PDeviceConfig",
				DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
				p2p_device_config_params,
				p2p_device_config_result, config, NULL);
	if (ret < 0) {
		g_free(config->device_name);
		g_free(config->dev_type);
		dbus_free(config);
		SUPPLICANT_DBG("Unable to set P2P Device configuration");
	}

	return ret;
}

static void p2p_device_config_property_update(DBusMessageIter *iter, void *user_data)
{
	GSupplicantP2PDeviceConfigParams *p2p_device_config = user_data;
	DBusMessageIter iter_dict, iter_dict_entry;
	char *key = NULL;

	dbus_message_iter_recurse(iter, &iter_dict);
	dbus_message_iter_get_basic(&iter_dict, &key);

	dbus_message_iter_next(&iter_dict);
	dbus_message_iter_recurse(&iter_dict, &iter_dict_entry);

	if (!key)
		return;

	if (g_strcmp0(key, "DeviceName") == 0) {
		char *name = NULL;

		dbus_message_iter_get_basic(&iter_dict_entry, &name);

		if(p2p_device_config->device_name != NULL){
			g_free(p2p_device_config->device_name);
			p2p_device_config->device_name = NULL;
		}

		p2p_device_config->device_name = g_strdup(name);

		SUPPLICANT_DBG("device_name : %s\n", p2p_device_config->device_name);
	} else if (g_strcmp0(key, "PrimaryDeviceType") == 0) {
		DBusMessageIter array;
		unsigned char *device_type = NULL;
		int type_len = 0;
		int i=0;

		dbus_message_iter_recurse(&iter_dict_entry, &array);
		dbus_message_iter_get_fixed_array(&array, &device_type, &type_len);

		if(type_len == 8) {
			for(i=0; i<type_len; i++)
				p2p_device_config->pri_dev_type[i] = device_type[i];
		} else {
			SUPPLICANT_DBG("strange device type\n");
		}
	} else if (g_strcmp0(key, "GOIntent") == 0) {
		dbus_uint32_t go_intent;

		dbus_message_iter_get_basic(&iter_dict_entry, &go_intent);
		p2p_device_config->go_intent = go_intent;
		SUPPLICANT_DBG("go_intent : %d\n", p2p_device_config->go_intent);
	} else if (g_strcmp0(key, "PersistentReconnect") == 0) {
		dbus_bool_t persistent_reconnect;

		dbus_message_iter_get_basic(&iter_dict_entry, &persistent_reconnect);
		p2p_device_config->persistent_reconnect = persistent_reconnect;
		SUPPLICANT_DBG("persistent_reconnect : %d\n", p2p_device_config->persistent_reconnect);
	} else if (g_strcmp0(key, "ListenRegClass") == 0) {
		dbus_uint32_t listen_reg_class;

		dbus_message_iter_get_basic(&iter_dict_entry, &listen_reg_class);
		p2p_device_config->listen_reg_class = listen_reg_class;
		SUPPLICANT_DBG("listen_reg_class : %d\n", p2p_device_config->listen_reg_class);
	} else if (g_strcmp0(key, "ListenChannel") == 0) {
		dbus_uint32_t listen_channel;

		dbus_message_iter_get_basic(&iter_dict_entry, &listen_channel);
		p2p_device_config->listen_channel = listen_channel;
	} else if (g_strcmp0(key, "OperRegClass") == 0) {
		dbus_uint32_t oper_reg_class;

		dbus_message_iter_get_basic(&iter_dict_entry, &oper_reg_class);
		p2p_device_config->oper_reg_class = oper_reg_class;
	} else if (g_strcmp0(key, "OperChannel") == 0) {
		dbus_uint32_t oper_channel;

		dbus_message_iter_get_basic(&iter_dict_entry, &oper_channel);
		p2p_device_config->oper_channel = oper_channel;
	} else if (g_strcmp0(key, "SsidPostfix") == 0) {
		char *ssid_postfix = NULL;

		dbus_message_iter_get_basic(&iter_dict_entry, &ssid_postfix);

		if(p2p_device_config->ssid_postfix != NULL){
			g_free(p2p_device_config->ssid_postfix);
			p2p_device_config->ssid_postfix = NULL;
		}

		p2p_device_config->ssid_postfix = g_strdup(ssid_postfix);
	} else if (g_strcmp0(key, "IntraBss") == 0) {
		dbus_bool_t intra_bss;

		dbus_message_iter_get_basic(&iter_dict_entry, &intra_bss);
		p2p_device_config->intra_bss = intra_bss;
	} else if (g_strcmp0(key, "GroupIdle") == 0) {
		dbus_uint32_t group_idle;

		dbus_message_iter_get_basic(&iter_dict_entry, &group_idle);
		p2p_device_config->group_idle = group_idle;
	} else if (g_strcmp0(key, "disassoc_low_ack") == 0) {
		dbus_uint32_t disassoc_low_ack;

		dbus_message_iter_get_basic(&iter_dict_entry, &disassoc_low_ack);
		p2p_device_config->disassoc_low_ack = disassoc_low_ack;
	} else
		SUPPLICANT_DBG("key %s type %c",
					key, dbus_message_iter_get_arg_type(&iter_dict_entry));
}

static void p2p_device_config_property(const char *key, DBusMessageIter *iter,
					void *user_data)
{
	GSupplicantInterface *interface;
	GSupplicantP2PInterface *p2p_device_interface = user_data;
	GSupplicantP2PDeviceConfigParams *p2p_device_config = p2p_device_interface->p2p_device_config_param;;

	GSupplicantInterface *check_interface = NULL;

	if (key){
		check_interface = g_hash_table_lookup(interface_table, key);
		if (check_interface == NULL)
			return;

		struct wifi_data *check_wifi = g_supplicant_interface_get_data(check_interface);
		if (check_wifi == NULL)
			return;
	}

	if (p2p_device_config->interface->path == NULL)
		return;

	interface = g_hash_table_lookup(interface_table, p2p_device_config->interface->path);
	if (interface == NULL || interface != p2p_device_config->interface) {
		g_free(p2p_device_interface->path);
		g_free(p2p_device_interface);
		return;
	}

	if (iter)
		supplicant_dbus_array_foreach(iter, p2p_device_config_property_update, p2p_device_config);

	callback_p2p_device_config_loaded(p2p_device_config->interface);

	g_free(p2p_device_interface->path);
	g_free(p2p_device_interface);
}
int g_supplicant_interface_get_p2p_device_config(GSupplicantInterface *interface,
					GSupplicantP2PDeviceConfigParams *p2p_device_config_data)
{
	GSupplicantP2PInterface *p2p_device_interface = NULL;
	int ret;

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	p2p_device_interface = g_try_malloc0(sizeof(GSupplicantP2PInterface));
	if(!p2p_device_interface)
		return -ENOMEM;

	p2p_device_interface->path = g_strdup(interface->path);
	p2p_device_interface->p2p_device_config_param = p2p_device_config_data;
	p2p_device_interface->p2p_device_config_param->interface = interface;

	ret = supplicant_dbus_property_get(interface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"P2PDeviceConfig",
				p2p_device_config_property,
				p2p_device_interface,
				NULL);

	if (ret < 0) {
		g_free(p2p_device_interface->path);
		g_free(p2p_device_interface);
		SUPPLICANT_DBG("Unable to get P2P Device configuration");
	}

	return ret;
}
static void interface_set_p2p_device_config_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_device_config *config = user_data;
	GSupplicantP2PDeviceConfigParams *config_params = config->p2p_device_config_params;
	DBusMessageIter dict;
	uint8_t *pri_dev_type = config_params->pri_dev_type;
	uint8_t pri_dev_type_check[8] = {0,};

	supplicant_dbus_dict_open(iter, &dict);

	if(config_params->device_name)
		supplicant_dbus_dict_append_basic(&dict, "DeviceName", DBUS_TYPE_STRING, &config_params->device_name);

	if(memcmp(&pri_dev_type_check[0], pri_dev_type, 8) != 0)
		supplicant_dbus_dict_append_fixed_array(&dict, "PrimaryDeviceType", DBUS_TYPE_BYTE, &pri_dev_type, 8);

	if(config_params->go_intent != 0)
		supplicant_dbus_dict_append_basic(&dict, "GOIntent", DBUS_TYPE_UINT32, &config_params->go_intent);

	supplicant_dbus_dict_append_basic(&dict, "PersistentReconnect", DBUS_TYPE_BOOLEAN, &config_params->persistent_reconnect);

	if(config_params->listen_reg_class != 0)
		supplicant_dbus_dict_append_basic(&dict, "ListenRegClass", DBUS_TYPE_UINT32, &config_params->listen_reg_class);

	if(config_params->listen_channel != 0)
		supplicant_dbus_dict_append_basic(&dict, "ListenChannel", DBUS_TYPE_UINT32, &config_params->listen_channel);

	if(config_params->oper_reg_class != 0)
		supplicant_dbus_dict_append_basic(&dict, "OperRegClass", DBUS_TYPE_UINT32, &config_params->oper_reg_class);

	if(config_params->oper_channel != 0)
		supplicant_dbus_dict_append_basic(&dict, "OperChannel", DBUS_TYPE_UINT32, &config_params->oper_channel);

	if(config_params->ssid_postfix)
		supplicant_dbus_dict_append_basic(&dict, "SsidPostfix", DBUS_TYPE_STRING, &config_params->ssid_postfix);

	supplicant_dbus_dict_append_basic(&dict, "IntraBss", DBUS_TYPE_BOOLEAN, &config_params->intra_bss);

	if(config_params->group_idle != 0)
		supplicant_dbus_dict_append_basic(&dict, "GroupIdle", DBUS_TYPE_UINT32, &config_params->group_idle);

	if(config_params->disassoc_low_ack != 0)
		supplicant_dbus_dict_append_basic(&dict, "disassoc_low_ack", DBUS_TYPE_UINT32, &config_params->disassoc_low_ack);

	supplicant_dbus_dict_close(iter, &dict);
}
static void interface_set_p2p_device_config_result(const char *error,
												DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_device_config *config = user_data;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
	}

	dbus_free(config);
}
int g_supplicant_interface_set_p2p_device_configs(GSupplicantInterface *interface,
												GSupplicantP2PDeviceConfigParams *p2p_device_config_data,
												void *user_data)
{
	struct interface_p2p_device_config *config = NULL;
	int ret;

	if (!interface)
		return -EINVAL;

	config = dbus_malloc0(sizeof(*config));
	if (!config)
		return -ENOMEM;

	config->interface = interface;
	config->user_data = user_data;
	config->p2p_device_config_params = p2p_device_config_data;

	ret = supplicant_dbus_property_set(interface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"P2PDeviceConfig", DBUS_TYPE_ARRAY_AS_STRING
				DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
				DBUS_TYPE_STRING_AS_STRING
				DBUS_TYPE_VARIANT_AS_STRING
				DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
				interface_set_p2p_device_config_params,
				interface_set_p2p_device_config_result, config, NULL);

	if (ret < 0) {
		dbus_free(config);
		SUPPLICANT_DBG("Unable to set P2P Device configuration");
	}

	return ret;
}

static void set_p2p_disabled(DBusMessageIter *iter, void *user_data)
{
	dbus_bool_t enable = *(dbus_bool_t *)user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &enable);
}

int g_supplicant_interface_set_p2p_disabled(GSupplicantInterface *interface,
							dbus_bool_t disabled)
{
	GSupplicantInterface *check_interface = NULL;
	if (interface == NULL || interface->path == NULL)
		return -EINVAL;

	check_interface = g_hash_table_lookup(interface_table, interface->path);
	if (check_interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	SUPPLICANT_DBG("disabled %d", disabled);

	return supplicant_dbus_property_set(interface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"P2PDisabled", DBUS_TYPE_BOOLEAN_AS_STRING,
				set_p2p_disabled, NULL, &disabled, NULL);
}
static gboolean peer_lookup_by_identifier(gpointer key, gpointer value,
							gpointer user_data)
{
	const GSupplicantPeer *peer = value;
	const char *identifier = user_data;

	if (!g_strcmp0(identifier, peer->identifier))
		return TRUE;

	return FALSE;
}

GSupplicantPeer *g_supplicant_interface_peer_lookup(GSupplicantInterface *interface,
							const char *identifier)
{
	GSupplicantPeer *peer;

	peer = g_hash_table_find(interface->peer_table,
					peer_lookup_by_identifier,
					(void *) identifier);
	return peer;
}

static void interface_create_data_free(struct interface_create_data *data)
{
	g_free(data->ifname);
	g_free(data->driver);
	g_free(data->bridge);
	if (data->config_file)
		g_free(data->config_file);
	if (data->interface_path)
		g_free(data->interface_path);
	dbus_free(data);
}

static bool interface_exists(GSupplicantInterface *interface,
				const char *path)
{
	GSupplicantInterface *tmp;

	tmp = g_hash_table_lookup(interface_table, path);
	if (tmp && tmp == interface)
		return true;

	return false;
}

static void interface_create_property(const char *key, DBusMessageIter *iter,
							void *user_data)
{
	struct interface_create_data *data = user_data;
	GSupplicantInterface *interface = data->interface;

	if (!key) {
		if (data->callback && interface_exists(data->interface, data->interface_path)) {
			data->callback(0, data->interface, data->user_data);
			callback_p2p_support(interface);
		}

		interface_create_data_free(data);
	}

	interface_property(key, iter, interface);
}

static void interface_create_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	const char *path = NULL;
	int err;

	SUPPLICANT_DBG("");

	if (error) {
		g_warning("error %s", error);
		err = -EIO;
		goto done;
	}

	dbus_message_iter_get_basic(iter, &path);
	if (!path) {
		err = -EINVAL;
		goto done;
	}
	data->interface_path = g_strdup(path);

	if (!system_available) {
		err = -EFAULT;
		goto done;
	}

	data->interface = g_hash_table_lookup(interface_table, path);
	if (!data->interface) {
		data->interface = interface_alloc(path);
		if (!data->interface) {
			err = -ENOMEM;
			goto done;
		}
	}

	err = supplicant_dbus_property_get_all(path,
					SUPPLICANT_INTERFACE ".Interface",
					interface_create_property, data,
					NULL);
	if (err == 0)
		return;

done:
	if (data->callback)
		data->callback(err, NULL, data->user_data);

	interface_create_data_free(data);
}

static void interface_create_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	DBusMessageIter dict;
	char *config_file = NULL;

	SUPPLICANT_DBG("");

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "Ifname",
					DBUS_TYPE_STRING, &data->ifname);

	if (data->driver)
		supplicant_dbus_dict_append_basic(&dict, "Driver",
					DBUS_TYPE_STRING, &data->driver);

	if (data->bridge)
		supplicant_dbus_dict_append_basic(&dict, "BridgeIfname",
					DBUS_TYPE_STRING, &data->bridge);

	config_file = g_hash_table_lookup(config_file_table, data->ifname);
	if (!config_file && data->config_file)
		config_file = data->config_file;

	if (config_file) {
		SUPPLICANT_DBG("[%s] ConfigFile %s", data->ifname, config_file);

		supplicant_dbus_dict_append_basic(&dict, "ConfigFile",
					DBUS_TYPE_STRING, &config_file);
	}

    if (data->config_file != NULL)
            supplicant_dbus_dict_append_basic(&dict, "ConfigFile",
                                    DBUS_TYPE_STRING, &data->config_file);


	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_get_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;
	GSupplicantInterface *interface;
	const char *path = NULL;
	int err;

	SUPPLICANT_DBG("");

	if (error) {
		SUPPLICANT_DBG("Interface not created yet");

		if ( (g_str_has_prefix(data->ifname, "p2p-wlan0-") == TRUE) && data->get_interface_timer_count < 10)
		{
			g_timeout_add(50, get_interface_retry, data);
			data->get_interface_timer_count++;
			return;
		}
		goto create;
	}

	dbus_message_iter_get_basic(iter, &path);
	if (!path || (strlen(path) == 0)) {
		err = -EINVAL;
		goto done;
	}

	interface = g_hash_table_lookup(interface_table, path);
	if (!interface) {
		err = -ENOENT;
		goto done;
	}

	if (data->callback) {
		data->callback(0, interface, data->user_data);
		callback_p2p_support(interface);
	}

	interface_create_data_free(data);

	return;

create:
	if (!system_available) {
		err = -EFAULT;
		goto done;
	}

	SUPPLICANT_DBG("Creating interface");

	err = supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"CreateInterface",
						interface_create_params,
						interface_create_result, data,
						NULL);
	if (err == 0)
		return;

done:
	if (data->callback)
		data->callback(err, NULL, data->user_data);

	interface_create_data_free(data);
}

static void interface_get_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_create_data *data = user_data;

	SUPPLICANT_DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &data->ifname);
}

static gboolean get_interface_retry(void* user_data)
{
	supplicant_dbus_method_call(SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE,
					"GetInterface",
					interface_get_params,
					interface_get_result, user_data,
					NULL);
	return FALSE;
}

int g_supplicant_interface_create(const char *ifname, const char *driver,
					const char *bridge, const char *config_file,
					GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_create_data *data;
	int ret;

	SUPPLICANT_DBG("ifname %s", ifname);

	if (!ifname)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->ifname = g_strdup(ifname);
	data->driver = g_strdup(driver);
	data->bridge = g_strdup(bridge);
	data->config_file = g_strdup(config_file);
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"GetInterface",
						interface_get_params,
						interface_get_result, data,
						NULL);
	if (ret < 0)
		interface_create_data_free(data);

	return ret;
}

static void interface_remove_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err;

	if (error) {
		err = -EIO;
		SUPPLICANT_DBG("error: %s", error);
		goto done;
	}

	if (!system_available) {
		err = -EFAULT;
		goto done;
	}

	/*
	 * The gsupplicant interface is already freed by the InterfaceRemoved
	 * signal callback. Simply invoke the interface_data callback.
	 */
	err = 0;

done:
	g_free(data->path);

	if (data->callback)
		data->callback(err, NULL, data->user_data);

	dbus_free(data);
}


static void interface_remove_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&data->interface->path);
}


int g_supplicant_interface_remove(GSupplicantInterface *interface,
			GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_data *data;
	int ret;

	if (!interface || !(interface->path))
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	g_supplicant_interface_cancel(interface);

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						"RemoveInterface",
						interface_remove_params,
						interface_remove_result, data,
						NULL);
	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
	}
	return ret;
}

static void interface_scan_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_scan_data *data = user_data;
	int err = 0;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	/* A non ready interface cannot send/receive anything */
	if (interface_exists(data->interface, data->path)) {
		if (!data->interface->ready)
			err = -ENOLINK;
	}

	g_free(data->path);

	if (err != 0) {
		if (data->callback)
			data->callback(err, data->interface, data->user_data);
	} else {
		data->interface->scan_callback = data->callback;
		data->interface->scan_data = data->user_data;
	}

	if (data->scan_params)
		g_supplicant_free_scan_params(data->scan_params);

	dbus_free(data);
}

static void add_scan_frequency(DBusMessageIter *iter, unsigned int freq)
{
	DBusMessageIter data;
	unsigned int width = 0; /* Not used by wpa_supplicant atm */

	dbus_message_iter_open_container(iter, DBUS_TYPE_STRUCT, NULL, &data);

	dbus_message_iter_append_basic(&data, DBUS_TYPE_UINT32, &freq);
	dbus_message_iter_append_basic(&data, DBUS_TYPE_UINT32, &width);

	dbus_message_iter_close_container(iter, &data);
}

static void add_scan_frequencies(DBusMessageIter *iter,
						void *user_data)
{
	GSupplicantScanParams *scan_data = user_data;
	unsigned int freq;
	int i;

	for (i = 0; i < scan_data->num_freqs; i++) {
		freq = scan_data->freqs[i];
		if (!freq)
			break;

		add_scan_frequency(iter, freq);
	}
}

static void append_ssid(DBusMessageIter *iter,
			const void *ssid, unsigned int len)
{
	DBusMessageIter array;

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
	DBUS_TYPE_BYTE_AS_STRING, &array);

	dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
								&ssid, len);
	dbus_message_iter_close_container(iter, &array);
}

static void append_ssids(DBusMessageIter *iter, void *user_data)
{
	GSupplicantScanParams *scan_data = user_data;
	GSList *list;

	for (list = scan_data->ssids; list; list = list->next) {
		struct scan_ssid *scan_ssid = list->data;

		append_ssid(iter, scan_ssid->ssid, scan_ssid->ssid_len);
	}
}

static void supplicant_add_scan_frequency(DBusMessageIter *dict,
		supplicant_dbus_array_function function,
					void *user_data)
{
	GSupplicantScanParams *scan_params = user_data;
	DBusMessageIter entry, value, array;
	const char *key = "Channels";

	if (scan_params->freqs && scan_params->freqs[0] != 0) {
		dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY,
						NULL, &entry);

		dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

		dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_UINT32_AS_STRING
					DBUS_TYPE_UINT32_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&value);

		dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_STRUCT_BEGIN_CHAR_AS_STRING
					DBUS_TYPE_UINT32_AS_STRING
					DBUS_TYPE_UINT32_AS_STRING
					DBUS_STRUCT_END_CHAR_AS_STRING,
					&array);

		if (function)
			function(&array, user_data);

		dbus_message_iter_close_container(&value, &array);
		dbus_message_iter_close_container(&entry, &value);
		dbus_message_iter_close_container(dict, &entry);
	}
}

static void interface_scan_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	const char *type = "passive";
	struct interface_scan_data *data = user_data;

	supplicant_dbus_dict_open(iter, &dict);

	if (data && data->scan_params) {
		type = "active";

		supplicant_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &type);


		if (data->scan_params->ssids) {
			supplicant_dbus_dict_append_array(&dict, "SSIDs",
							DBUS_TYPE_STRING,
							append_ssids,
							data->scan_params);
		}
		supplicant_add_scan_frequency(&dict, add_scan_frequencies,
						data->scan_params);
	} else
		supplicant_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &type);

	supplicant_dbus_dict_close(iter, &dict);
}

static int interface_ready_to_scan(GSupplicantInterface *interface)
{
	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	if (interface->scanning)
		return -EALREADY;

	switch (interface->state) {
	case G_SUPPLICANT_STATE_AUTHENTICATING:
	case G_SUPPLICANT_STATE_ASSOCIATING:
	case G_SUPPLICANT_STATE_ASSOCIATED:
	case G_SUPPLICANT_STATE_4WAY_HANDSHAKE:
	case G_SUPPLICANT_STATE_GROUP_HANDSHAKE:
		return -EBUSY;
	case G_SUPPLICANT_STATE_UNKNOWN:
	case G_SUPPLICANT_STATE_DISABLED:
	case G_SUPPLICANT_STATE_DISCONNECTED:
	case G_SUPPLICANT_STATE_INACTIVE:
	case G_SUPPLICANT_STATE_SCANNING:
	case G_SUPPLICANT_STATE_COMPLETED:
		break;
	}

	return 0;
}

int g_supplicant_interface_scan(GSupplicantInterface *interface,
				GSupplicantScanParams *scan_data,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_scan_data *data;
	int ret;

	ret = interface_ready_to_scan(interface);
	if (ret)
		return ret;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->user_data = user_data;
	data->scan_params = scan_data;

        interface->scan_callback = callback;
        interface->scan_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "Scan",
			interface_scan_params, interface_scan_result, data,
			interface);

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
	}

	return ret;
}

static int parse_supplicant_error(DBusMessageIter *iter)
{
	int err = -ECONNABORTED;
	char *key;

	if (!iter)
		return err;

	/* If the given passphrase is malformed wpa_s returns
	 * "invalid message format" but this error should be interpreted as
	 * invalid-key.
	 */
	while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
		dbus_message_iter_get_basic(iter, &key);
		if (strncmp(key, "psk", 3) == 0 ||
				strncmp(key, "wep_key", 7) == 0 ||
				strcmp(key, "invalid message format") == 0) {
			err = -ENOKEY;
			break;
		}
		dbus_message_iter_next(iter);
	}

	return err;
}

static void interface_select_network_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	int err;

	SUPPLICANT_DBG("");

	err = 0;
	if (error) {
		SUPPLICANT_DBG("SelectNetwork error %s", error);
		err = parse_supplicant_error(iter);
	}

	g_free(data->path);

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data->ssid);
	dbus_free(data);
}

static void interface_select_network_params(DBusMessageIter *iter,
							void *user_data)
{
	struct interface_connect_data *data = user_data;
	GSupplicantInterface *interface = data->interface;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
					&interface->network_path);
}

static void interface_add_network_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	GSupplicantInterface *interface = data->interface;
	const char *path;
	int err;

	if (error)
		goto error;

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		goto error;

	SUPPLICANT_DBG("PATH: %s", path);

	if (interface->network_path)
		g_free(interface->network_path);
	interface->network_path = g_strdup(path);

	store_network_information(interface, data->ssid);

	supplicant_dbus_method_call(data->interface->path,
			SUPPLICANT_INTERFACE ".Interface", "SelectNetwork",
			interface_select_network_params,
			interface_select_network_result, data,
			interface);

	return;

error:
	SUPPLICANT_DBG("AddNetwork error %s", error);

	if (interface_exists(data->interface, data->interface->path)) {
		err = parse_supplicant_error(iter);
		if (data->callback)
			data->callback(err, data->interface, data->user_data);

		g_free(interface->network_path);
		interface->network_path = NULL;
	}

	g_free(data->path);
	g_free(data->ssid);
	g_free(data);
}

static void add_network_security_none(DBusMessageIter *dict)
{
	const char *auth_alg = "OPEN";

	supplicant_dbus_dict_append_basic(dict, "auth_alg",
					DBUS_TYPE_STRING, &auth_alg);
}

static void add_network_security_wep(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	const char *auth_alg = "OPEN SHARED";
	dbus_uint32_t key_index = 0;

	supplicant_dbus_dict_append_basic(dict, "auth_alg",
					DBUS_TYPE_STRING, &auth_alg);

	if (ssid->passphrase) {
		int size = strlen(ssid->passphrase);
		if (size == 10 || size == 26) {
			unsigned char *key = g_try_malloc(13);
			char tmp[3];
			int i;

			memset(tmp, 0, sizeof(tmp));
			if (!key)
				size = 0;

			for (i = 0; i < size / 2; i++) {
				memcpy(tmp, ssid->passphrase + (i * 2), 2);
				key[i] = (unsigned char) strtol(tmp, NULL, 16);
			}

			supplicant_dbus_dict_append_fixed_array(dict,
							"wep_key0",
							DBUS_TYPE_BYTE,
							&key, size / 2);
			g_free(key);
		} else if (size == 5 || size == 13) {
			unsigned char *key = g_try_malloc(13);
			int i;

			if (!key)
				size = 0;

			for (i = 0; i < size; i++)
				key[i] = (unsigned char) ssid->passphrase[i];

			supplicant_dbus_dict_append_fixed_array(dict,
								"wep_key0",
								DBUS_TYPE_BYTE,
								&key, size);
			g_free(key);
		} else
			supplicant_dbus_dict_append_basic(dict,
							"wep_key0",
							DBUS_TYPE_STRING,
							&ssid->passphrase);

		supplicant_dbus_dict_append_basic(dict, "wep_tx_keyidx",
					DBUS_TYPE_UINT32, &key_index);
	}
}

static dbus_bool_t is_psk_raw_key(const char *psk)
{
	int i;

	/* A raw key is always 64 bytes length... */
	if (strlen(psk) != 64)
		return FALSE;

	/* ... and its content is in hex representation */
	for (i = 0; i < 64; i++)
		if (!isxdigit((unsigned char) psk[i]))
			return FALSE;

	return TRUE;
}

static unsigned char hexchar2bin(char c)
{
	if ((c >= '0') && (c <= '9'))
		return c - '0';
	else if ((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;
	else
		return c;
}

static void hexstring2bin(const char *string, unsigned char *data,
				size_t data_len)
{
	size_t i;

	for (i = 0; i < data_len; i++)
		data[i] = (hexchar2bin(string[i * 2 + 0]) << 4 |
			   hexchar2bin(string[i * 2 + 1]) << 0);
}

static void add_network_security_psk(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	if (ssid->passphrase && strlen(ssid->passphrase) > 0) {
		const char *key = "psk";

		if (is_psk_raw_key(ssid->passphrase)) {
			unsigned char data[32];
			unsigned char *datap = data;

			/* The above pointer alias is required by D-Bus because
			 * with D-Bus and GCC, non-heap-allocated arrays cannot
			 * be passed directly by their base pointer. */

			hexstring2bin(ssid->passphrase, datap, sizeof(data));

			supplicant_dbus_dict_append_fixed_array(dict,
							key, DBUS_TYPE_BYTE,
							&datap, sizeof(data));
		} else
			supplicant_dbus_dict_append_basic(dict,
							key, DBUS_TYPE_STRING,
							&ssid->passphrase);
	}
}

static void add_network_security_tls(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	/*
	 * For TLS, we at least need:
	 *              The client certificate
	 *              The client private key file
	 *              The client private key file password
	 *
	 * The Authority certificate is optional.
	 */
	if (!ssid->client_cert_path)
		return;

	if (!ssid->private_key_path)
		return;

	if (!ssid->private_key_passphrase)
		return;

	if (ssid->ca_cert_path)
		supplicant_dbus_dict_append_basic(dict, "ca_cert",
					DBUS_TYPE_STRING, &ssid->ca_cert_path);

	supplicant_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING,
						&ssid->private_key_path);
	supplicant_dbus_dict_append_basic(dict, "private_key_passwd",
						DBUS_TYPE_STRING,
						&ssid->private_key_passphrase);
	supplicant_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING,
						&ssid->client_cert_path);
}

static void add_network_security_peap(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	char *phase2_auth;

	/*
	 * For PEAP/TTLS, we at least need
	 *              The authority certificate
	 *              The 2nd phase authentication method
	 *              The 2nd phase passphrase
	 *
	 * The Client certificate is optional although strongly recommended
	 * When setting it, we need in addition
	 *              The Client private key file
	 *              The Client private key file password
	 */
	if (!ssid->passphrase)
		return;

	if (!ssid->phase2_auth)
		return;

	if (ssid->client_cert_path) {
		if (!ssid->private_key_path)
			return;

		if (!ssid->private_key_passphrase)
			return;

		supplicant_dbus_dict_append_basic(dict, "client_cert",
						DBUS_TYPE_STRING,
						&ssid->client_cert_path);

		supplicant_dbus_dict_append_basic(dict, "private_key",
						DBUS_TYPE_STRING,
						&ssid->private_key_path);

		supplicant_dbus_dict_append_basic(dict, "private_key_passwd",
						DBUS_TYPE_STRING,
						&ssid->private_key_passphrase);

	}

	if(g_strcmp0(ssid->phase2_auth, "GTC") == 0 && g_strcmp0(ssid->eap, "ttls") == 0)
		phase2_auth = g_strdup_printf("autheap=%s", ssid->phase2_auth);
	else if (g_str_has_prefix(ssid->phase2_auth, "EAP-")) {
		phase2_auth = g_strdup_printf("autheap=%s",
					ssid->phase2_auth + strlen("EAP-"));
	} else
		phase2_auth = g_strdup_printf("auth=%s", ssid->phase2_auth);

	supplicant_dbus_dict_append_basic(dict, "password",
						DBUS_TYPE_STRING,
						&ssid->passphrase);

	if (ssid->ca_cert_path)
		supplicant_dbus_dict_append_basic(dict, "ca_cert",
						DBUS_TYPE_STRING,
						&ssid->ca_cert_path);

	supplicant_dbus_dict_append_basic(dict, "phase2",
						DBUS_TYPE_STRING,
						&phase2_auth);

	g_free(phase2_auth);
}

static void add_network_security_eap(DBusMessageIter *dict,
					GSupplicantSSID *ssid)
{
	char *eap_value;

	if (!ssid->eap || !ssid->identity)
		return;

	if (g_strcmp0(ssid->eap, "tls") == 0) {
		add_network_security_tls(dict, ssid);
	} else if (g_strcmp0(ssid->eap, "peap") == 0 ||
				g_strcmp0(ssid->eap, "ttls") == 0) {
		add_network_security_peap(dict, ssid);
	} else
		return;

	eap_value = g_ascii_strup(ssid->eap, -1);

	supplicant_dbus_dict_append_basic(dict, "eap",
						DBUS_TYPE_STRING,
						&eap_value);
	supplicant_dbus_dict_append_basic(dict, "identity",
						DBUS_TYPE_STRING,
						&ssid->identity);
	if(ssid->anonymous_identity)
		supplicant_dbus_dict_append_basic(dict, "anonymous_identity",
						     DBUS_TYPE_STRING,
						     &ssid->anonymous_identity);

	if(ssid->subject_match)
		supplicant_dbus_dict_append_basic(dict, "subject_match",
						     DBUS_TYPE_STRING,
						     &ssid->subject_match);

	if(ssid->altsubject_match)
		supplicant_dbus_dict_append_basic(dict, "altsubject_match",
						     DBUS_TYPE_STRING,
						     &ssid->altsubject_match);

	if(ssid->domain_suffix_match)
		supplicant_dbus_dict_append_basic(dict, "domain_suffix_match",
						     DBUS_TYPE_STRING,
						     &ssid->domain_suffix_match);

	if(ssid->domain_match)
		supplicant_dbus_dict_append_basic(dict, "domain_match",
						     DBUS_TYPE_STRING,
						     &ssid->domain_match);

	g_free(eap_value);
}

static void add_network_security_ciphers(DBusMessageIter *dict,
						GSupplicantSSID *ssid)
{
	unsigned int p_cipher, g_cipher, i;
	char *pairwise, *group;
	char *pair_ciphers[4];
	char *group_ciphers[5];

	p_cipher = ssid->pairwise_cipher;
	g_cipher = ssid->group_cipher;

	if (p_cipher == 0 && g_cipher == 0)
		return;

	i = 0;

	if (p_cipher & G_SUPPLICANT_PAIRWISE_CCMP)
		pair_ciphers[i++] = "CCMP";

	if (p_cipher & G_SUPPLICANT_PAIRWISE_TKIP)
		pair_ciphers[i++] = "TKIP";

	if (p_cipher & G_SUPPLICANT_PAIRWISE_NONE)
		pair_ciphers[i++] = "NONE";

	pair_ciphers[i] = NULL;

	i = 0;

	if (g_cipher & G_SUPPLICANT_GROUP_CCMP)
		group_ciphers[i++] = "CCMP";

	if (g_cipher & G_SUPPLICANT_GROUP_TKIP)
		group_ciphers[i++] = "TKIP";

	if (g_cipher & G_SUPPLICANT_GROUP_WEP104)
		group_ciphers[i++] = "WEP104";

	if (g_cipher & G_SUPPLICANT_GROUP_WEP40)
		group_ciphers[i++] = "WEP40";

	group_ciphers[i] = NULL;

	pairwise = g_strjoinv(" ", pair_ciphers);
	group = g_strjoinv(" ", group_ciphers);

	SUPPLICANT_DBG("cipher %s %s", pairwise, group);

	supplicant_dbus_dict_append_basic(dict, "pairwise",
						DBUS_TYPE_STRING,
						&pairwise);
	supplicant_dbus_dict_append_basic(dict, "group",
						DBUS_TYPE_STRING,
						&group);

	g_free(pairwise);
	g_free(group);
}

static void add_network_security_proto(DBusMessageIter *dict,
						GSupplicantSSID *ssid)
{
	unsigned int protocol, i;
	char *proto;
	char *protos[3];

	protocol = ssid->protocol;

	if (protocol == 0)
		return;

	i = 0;

	if (protocol & G_SUPPLICANT_PROTO_RSN)
		protos[i++] = "RSN";

	if (protocol & G_SUPPLICANT_PROTO_WPA)
		protos[i++] = "WPA";

	protos[i] = NULL;

	proto = g_strjoinv(" ", protos);

	SUPPLICANT_DBG("proto %s", proto);

	supplicant_dbus_dict_append_basic(dict, "proto",
						DBUS_TYPE_STRING,
						&proto);

	g_free(proto);
}

static void add_network_ieee80211w(DBusMessageIter *dict, GSupplicantSSID *ssid,
				   GSupplicantMfpOptions ieee80211w)
{
	supplicant_dbus_dict_append_basic(dict, "ieee80211w", DBUS_TYPE_UINT32,
					  &ieee80211w);
}

static void add_network_security(DBusMessageIter *dict, GSupplicantSSID *ssid)
{
	GSupplicantMfpOptions ieee80211w;
	char *key_mgmt;

	switch (ssid->security) {
	case G_SUPPLICANT_SECURITY_NONE:
		key_mgmt = "NONE";
		add_network_security_none(dict);
		add_network_security_ciphers(dict, ssid);
		break;
	case G_SUPPLICANT_SECURITY_UNKNOWN:
	case G_SUPPLICANT_SECURITY_WEP:
		key_mgmt = "NONE";
		add_network_security_wep(dict, ssid);
		add_network_security_ciphers(dict, ssid);
		break;
	case G_SUPPLICANT_SECURITY_PSK:
			key_mgmt = "WPA-PSK";
		add_network_security_psk(dict, ssid);
		add_network_security_ciphers(dict, ssid);
		add_network_security_proto(dict, ssid);
		break;
	case G_SUPPLICANT_SECURITY_IEEE8021X:
		key_mgmt = "WPA-EAP";
		add_network_security_eap(dict, ssid);
		add_network_security_ciphers(dict, ssid);
		add_network_security_proto(dict, ssid);
		break;
	}

	supplicant_dbus_dict_append_basic(dict, "key_mgmt",
				DBUS_TYPE_STRING, &key_mgmt);
}

static void add_network_mode(DBusMessageIter *dict, GSupplicantSSID *ssid)
{
	dbus_uint32_t mode;

	switch (ssid->mode) {
	case G_SUPPLICANT_MODE_UNKNOWN:
	case G_SUPPLICANT_MODE_INFRA:
		mode = 0;
		break;
	case G_SUPPLICANT_MODE_IBSS:
		mode = 1;
		break;
	case G_SUPPLICANT_MODE_MASTER:
		mode = 2;
		break;
	}

	supplicant_dbus_dict_append_basic(dict, "mode",
				DBUS_TYPE_UINT32, &mode);
}

static void interface_add_network_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_connect_data *data = user_data;
	GSupplicantSSID *ssid = data->ssid;

	supplicant_dbus_dict_open(iter, &dict);

	if (ssid->scan_ssid)
		supplicant_dbus_dict_append_basic(&dict, "scan_ssid",
					 DBUS_TYPE_UINT32, &ssid->scan_ssid);

	if (ssid->freq)
		supplicant_dbus_dict_append_basic(&dict, "frequency",
					 DBUS_TYPE_UINT32, &ssid->freq);

	if (ssid->bgscan)
		supplicant_dbus_dict_append_basic(&dict, "bgscan",
					DBUS_TYPE_STRING, &ssid->bgscan);

	add_network_mode(&dict, ssid);

	add_network_security(&dict, ssid);

	supplicant_dbus_dict_append_fixed_array(&dict, "ssid",
					DBUS_TYPE_BYTE, &ssid->ssid,
						ssid->ssid_len);

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_wps_start_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	int err;

	SUPPLICANT_DBG("");

	err = 0;
	if (error) {
		SUPPLICANT_DBG("error: %s", error);
		err = parse_supplicant_error(iter);
	}

	if(data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data->path);
	g_free(data->ssid);
	dbus_free(data);
}

static void interface_add_wps_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	GSupplicantSSID *ssid = data->ssid;
	const char *role = "enrollee", *type;
	DBusMessageIter dict;

	SUPPLICANT_DBG("");

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "Role",
						DBUS_TYPE_STRING, &role);

	type = "pbc";
	if (ssid->pin_wps) {
		type = "pin";
		supplicant_dbus_dict_append_basic(&dict, "Pin",
					DBUS_TYPE_STRING, &ssid->pin_wps);
	}

	supplicant_dbus_dict_append_basic(&dict, "Type",
					DBUS_TYPE_STRING, &type);

	supplicant_dbus_dict_close(iter, &dict);
}

static void wps_start(const char *error, DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;

	SUPPLICANT_DBG("");

	if (error) {
		SUPPLICANT_DBG("error: %s", error);
		g_free(data->path);
		g_free(data->ssid);
		dbus_free(data);
		return;
	}

	supplicant_dbus_method_call(data->interface->path,
			SUPPLICANT_INTERFACE ".Interface.WPS", "Start",
			interface_add_wps_params,
			interface_wps_start_result, data, NULL);
}

static void wps_process_credentials(DBusMessageIter *iter, void *user_data)
{
	dbus_bool_t credentials = TRUE;

	SUPPLICANT_DBG("");

	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &credentials);
}


int g_supplicant_interface_connect(GSupplicantInterface *interface,
				GSupplicantSSID *ssid,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_connect_data *data;
	struct interface_data *intf_data;
	int ret = 0;

	SUPPLICANT_DBG("");

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	/* TODO: Check if we're already connected and switch */

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->ssid = ssid;
	data->user_data = user_data;

	if (ssid->use_wps) {
		g_free(interface->wps_cred.key);
		memset(&interface->wps_cred, 0,
				sizeof(struct _GSupplicantWpsCredentials));

		ret = supplicant_dbus_property_set(interface->path,
			SUPPLICANT_INTERFACE ".Interface.WPS",
			"ProcessCredentials", DBUS_TYPE_BOOLEAN_AS_STRING,
			wps_process_credentials, wps_start, data, interface);
	} else {
		/* By the time there is a request for connect and the network
		 * path is not NULL it means that connman has not removed the
		 * previous network pointer. This can happen in the case AP
		 * deauthenticated client and connman does not remove the
		 * previously connected network pointer. This causes supplicant
		 * to reallocate the memory for struct wpa_ssid again even if it
		 * is the same SSID. This causes memory usage of wpa_supplicnat
		 * to go high. The idea here is that if the previously connected
		 * network is not removed at the time of next connection attempt
		 * check if the network path is not NULL. In case it is non-NULL
		 * first remove the network and then once removal is successful, add
		 * the network.
		 */

		if (interface->network_path != NULL) {
			g_free(data->path);
			dbus_free(data);

			/*
			 * If this add network is for the same network for
			 * which wpa_supplicant already has a profile then do
			 * not need to add another profile. Only if the
			 * profile that needs to get added is different from
			 * what is there in wpa_s delete the current one. A
			 * network is identified by its SSID, security_type
			 * and passphrase (private passphrase in case security
			 * type is 802.11x).
			 */
			if (compare_network_parameters(interface, ssid)) {
				return -EALREADY;
			}

			intf_data = dbus_malloc0(sizeof(*intf_data));
			if (!intf_data)
				return -ENOMEM;

			intf_data->interface = interface;
			intf_data->path = g_strdup(interface->path);
			intf_data->callback = callback;
			intf_data->ssid = ssid;
			intf_data->user_data = user_data;
			intf_data->network_remove_in_progress = TRUE;
			network_remove(intf_data);
		} else {
			ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface", "AddNetwork",
					interface_add_network_params,
					interface_add_network_result, data,
					interface);
		}
        }

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_wps_cancel_result(const char *error,
		DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;

	SUPPLICANT_DBG("");

	if (error != NULL) {
		SUPPLICANT_DBG("error: %s", error);
		err = parse_supplicant_error(iter);
	}

	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

int g_supplicant_interface_wps_cancel(GSupplicantInterface *interface,
		GSupplicantInterfaceCallback callback,
			void *user_data)
{
	struct interface_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
		SUPPLICANT_INTERFACE ".Interface.WPS", "Cancel",
		NULL,
		interface_wps_cancel_result, data, interface);

	if (ret < 0) {
		g_free(data);
		return ret;
	}

	return -EINPROGRESS;
}
static void network_remove_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	struct interface_connect_data *connect_data;
	int result = 0;

	SUPPLICANT_DBG("");

	if (error) {
		result = -EIO;
		SUPPLICANT_DBG("error: %s", error);

		if (g_strcmp0("org.freedesktop.DBus.Error.UnknownMethod",
						error) == 0)
			result = -ECONNABORTED;
	}

	g_free(data->interface->network_path);
	data->interface->network_path = NULL;

	remove_network_information(data->interface);

	if (data->network_remove_in_progress == TRUE) {
		data->network_remove_in_progress = FALSE;
		connect_data = dbus_malloc0(sizeof(*connect_data));
		if (!connect_data)
			return;

		connect_data->interface = data->interface;
		connect_data->path = g_strdup(data->path);
		connect_data->callback = data->callback;
		connect_data->ssid = data->ssid;
		connect_data->user_data = data->user_data;

		supplicant_dbus_method_call(data->interface->path,
			SUPPLICANT_INTERFACE ".Interface", "AddNetwork",
			interface_add_network_params,
			interface_add_network_result, connect_data,
			connect_data->interface);
	} else {
		if (data->callback)
			data->callback(result, data->interface, data->user_data);
	}
	g_free(data->path);
	dbus_free(data);
}

static void network_remove_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	const char *path = data->interface->network_path;

	SUPPLICANT_DBG("path %s", path);

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

static int network_remove(struct interface_data *data)
{
	GSupplicantInterface *interface = data->interface;

	SUPPLICANT_DBG("");

	return supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "RemoveNetwork",
			network_remove_params, network_remove_result, data,
			interface);
}

static void interface_disconnect_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int result = 0;

	SUPPLICANT_DBG("");

	if (error) {
		result = -EIO;
		SUPPLICANT_DBG("error: %s", error);

		if (g_strcmp0("org.freedesktop.DBus.Error.UnknownMethod",
						error) == 0)
			result = -ECONNABORTED;
	}

	/* If we are disconnecting from previous WPS successful
	 * association. i.e.: it did not went through AddNetwork,
	 * and interface->network_path was never set. */
	if (!data->interface->network_path) {
		if (data->callback)
			data->callback(result, data->interface,
							data->user_data);

		g_free(data->path);
		dbus_free(data);
		return;
	}

	if (result < 0 && data->callback) {
		data->callback(result, data->interface, data->user_data);
		data->callback = NULL;
	}

	if (result != -ECONNABORTED) {
		if (network_remove(data) < 0) {
			g_free(data->path);
			dbus_free(data);
		}
	} else {
		g_free(data->path);
		dbus_free(data);
	}
}

int g_supplicant_interface_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface", "Disconnect",
			NULL, interface_disconnect_result, data,
			interface);

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
	}

	return ret;
}

struct interface_p2p_find_data {
	GSupplicantInterface *interface;
	char *path;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PFindParams *p2p_find_params;
	void *user_data;
};

static void interface_p2p_find_result(const char *error,
					DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_find_data *data = user_data;
	int err = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}
	if (interface_exists(data->interface, data->path)) {
		if (!data->interface->ready)
			err = -ENOLINK;
		if (!err) {
			data->interface->p2p_finding = true;
		}
	}

	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	g_free(data->path);
	dbus_free(data);
}

static void interface_p2p_find_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_find_data *data = user_data;
	int timeout = 0;
	char *disc_type = "social";

	supplicant_dbus_dict_open(iter, &dict);

	if (data && data->p2p_find_params) {
		GSupplicantP2PFindParams* params = data->p2p_find_params;
		supplicant_dbus_dict_append_basic(&dict, "Timeout",
												DBUS_TYPE_INT32, &params->timeout);

		if(params->disc_type == G_SUPPLICANT_P2P_FIND_START_WITH_FULL) {
			disc_type = "start_with_full";
		}
		else if(params->disc_type == G_SUPPLICANT_P2P_FIND_PROGRESSIVE) {
			disc_type = "progressive";
		}
		else {
			disc_type = "social";
		}

		supplicant_dbus_dict_append_basic(&dict, "DiscoveryType",
											DBUS_TYPE_STRING, &disc_type);

		if (params->frequency != 0)
			supplicant_dbus_dict_append_basic(&dict, "Frequency",
											  DBUS_TYPE_INT32, &params->frequency);

		if (params->seek_array != NULL){

			DBusMessageIter entry;
			DBusMessageIter value;
			DBusMessageIter array;
			const char** seek = params->seek_array;
			const char* key = "Seek";

			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
			dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);

			dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
											 DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING, &value);
			dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &array);

			// Append items from null terminated array
			while(*seek)
			{
				dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, seek);
				seek++;
			}

			dbus_message_iter_close_container(&value, &array);
			dbus_message_iter_close_container(&entry, &value);

			dbus_message_iter_close_container(&dict, &entry);
		}
	} else
		supplicant_dbus_dict_append_basic(&dict, "Timeout",
					DBUS_TYPE_INT32, &timeout);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_find(GSupplicantInterface *interface,
				GSupplicantP2PFindParams *find_data,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_p2p_find_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->user_data = user_data;
	data->p2p_find_params = find_data;

	ret = supplicant_dbus_method_call(interface->path,
										SUPPLICANT_INTERFACE ".Interface.P2PDevice", "Find",
										interface_p2p_find_params, interface_p2p_find_result, data, NULL);

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
	}

	return ret;
}

bool g_supplicant_interface_is_p2p_finding(GSupplicantInterface *interface)
{
	if (!interface)
		return false;

	return interface->p2p_finding;
}

int g_supplicant_interface_p2p_stop_find(GSupplicantInterface *interface)
{
	if (!interface->p2p_finding)
		return 0;

	SUPPLICANT_DBG("");

	interface->p2p_finding = false;

	return supplicant_dbus_method_call(interface->path,
		SUPPLICANT_INTERFACE ".Interface.P2PDevice", "StopFind",
		NULL, NULL, NULL, NULL);
}

static void interface_p2p_connect_result(const char *error,
					DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	int err = 0;

	SUPPLICANT_DBG("");

	if (error) {
		SUPPLICANT_DBG("error: %s", error);
		err = parse_supplicant_error(iter);
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data->path);
	g_free(data->peer->wps_pin);
	g_free(data->peer->wps_method);
	g_free(data->peer->path);
	g_free(data->peer);
	g_free(data);
}

static void interface_p2p_connect_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	const char *wps = data->peer->wps_method?data->peer->wps_method:"pbc";
	DBusMessageIter dict;
	int go_intent = 7;

	SUPPLICANT_DBG("");

	supplicant_dbus_dict_open(iter, &dict);

	if (data->peer->master)
		go_intent = 15;

	if (data->peer->wps_method==NULL && data->peer->wps_pin)
		wps = "pin";

	supplicant_dbus_dict_append_basic(&dict, "peer",
				DBUS_TYPE_OBJECT_PATH, &data->peer->path);
	supplicant_dbus_dict_append_basic(&dict, "wps_method",
				DBUS_TYPE_STRING, &wps);
	if (data->peer->wps_pin) {
		supplicant_dbus_dict_append_basic(&dict, "pin",
				DBUS_TYPE_STRING, &data->peer->wps_pin);
	}

	supplicant_dbus_dict_append_basic(&dict, "persistent",
				DBUS_TYPE_BOOLEAN, &data->peer->persistent);

	if (data->peer->go_intent)
		go_intent = data->peer->go_intent;

	supplicant_dbus_dict_append_basic(&dict, "go_intent",
				DBUS_TYPE_INT32, &go_intent);

	supplicant_dbus_dict_append_basic(&dict, "join",
				DBUS_TYPE_BOOLEAN, &data->peer->join);

	supplicant_dbus_dict_append_basic(&dict, "authorize_only",
				DBUS_TYPE_BOOLEAN, &data->peer->authorize_only);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_connect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params,
					GSupplicantInterfaceCallback callback,
					void *user_data)
{
	struct interface_connect_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->peer = peer_params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
		SUPPLICANT_INTERFACE ".Interface.P2PDevice", "Connect",
		interface_p2p_connect_params, interface_p2p_connect_result,
		data, interface);
	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

int g_supplicant_interface_p2p_disconnect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params)
{
	GSupplicantPeer *peer;
	int count = 0;
	GSList *list;

	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return -ENOTSUP;

	peer = g_hash_table_lookup(interface->peer_table, peer_params->path);
	if (!peer)
		return -ENODEV;

	for (list = peer->groups; list; list = list->next, count++) {
		const char *group_obj_path = list->data;
		GSupplicantInterface *g_interface;
		GSupplicantGroup *group;

		group = g_hash_table_lookup(group_mapping, group_obj_path);
		if (!group || !group->interface)
			continue;

		g_interface = group->interface;
		supplicant_dbus_method_call(g_interface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"Disconnect", NULL, NULL, NULL, g_interface);
	}

	if (count == 0 && peer->current_group_iface) {
		supplicant_dbus_method_call(peer->current_group_iface->path,
				SUPPLICANT_INTERFACE ".Interface.P2PDevice",
				"Disconnect", NULL, NULL, NULL,
				peer->current_group_iface->path);
	}

	peer->current_group_iface = NULL;

	return -EINPROGRESS;
}

static void interface_p2p_disconnect_result(const char *error,
													DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}
int g_supplicant_interface_p2p_group_disconnect(GSupplicantInterface *interface,
													GSupplicantInterfaceCallback callback,
													void *user_data)
{
	struct interface_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	SUPPLICANT_DBG("interface->path : %s\n", interface->path);

	ret = supplicant_dbus_method_call(interface->path,
									SUPPLICANT_INTERFACE ".Interface.P2PDevice",
									"Disconnect", NULL,
									interface_p2p_disconnect_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_p2p_client_remove_result(const char *error,
							DBusMessageIter *iter, void *user_data)
{
	if (error) {
		SUPPLICANT_DBG("error %s", error);
	}
}

static void interface_p2p_client_remove_params(DBusMessageIter *iter, void *user_data)
{
	char* peer_path = user_data;
	DBusMessageIter dict;

	supplicant_dbus_dict_open(iter, &dict);
	supplicant_dbus_dict_append_basic(&dict, "peer",
					DBUS_TYPE_OBJECT_PATH, &peer_path);
	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_client_remove(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
					char* peer_path)
{
	int ret;

	if (!interface)
		return -EINVAL;

	SUPPLICANT_DBG("interface->path : %s\n", interface->path);

	ret = supplicant_dbus_method_call(interface->path,
									SUPPLICANT_INTERFACE ".Interface.P2PDevice",
									"RemoveClient", interface_p2p_client_remove_params,
									interface_p2p_client_remove_result, (void*) peer_path, NULL);

	if (ret < 0) {
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_p2p_cancel_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;

	SUPPLICANT_DBG("");

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data->path);
	dbus_free(data);
}

int g_supplicant_interface_p2p_cancel(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				void *user_data)
{
	struct interface_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface.P2PDevice", "Cancel",
			NULL, interface_p2p_cancel_result, data, NULL);

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_p2p_flush_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}
int g_supplicant_interface_p2p_flush(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				void *user_data)
{
	struct interface_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice", "Flush",
					NULL, interface_p2p_flush_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}
static void interface_p2p_reject_peer_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_reject_data *data = user_data;
	int err = 0;

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

static void interface_p2p_reject_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_reject_data *data = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&data->peer->path);
}

int g_supplicant_interface_p2p_reject(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params,
					GSupplicantInterfaceCallback callback,
					void *user_data)
{
	struct interface_reject_data* data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface || !peer_params || !peer_params->path)
		return -EINVAL;

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->path = g_strdup(interface->path);
	data->peer = peer_params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface.P2PDevice", "RejectPeer",
			interface_p2p_reject_params, interface_p2p_reject_peer_result, data, NULL);

	if (ret < 0) {
		g_free(data->path);
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

struct interface_p2p_sd_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PSDParams *p2p_sd_params;
	void *user_data;
};
static void interface_p2p_sd_request_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_sd_data *data = user_data;

	supplicant_dbus_dict_open(iter, &dict);

	if (data && data->p2p_sd_params) {
		GSupplicantP2PSDParams* params = data->p2p_sd_params;

		if(params->peer)
			supplicant_dbus_dict_append_basic(&dict, "peer_object",
												DBUS_TYPE_OBJECT_PATH, &params->peer);

		if(params->service_type)
			supplicant_dbus_dict_append_basic(&dict, "service_type",
												DBUS_TYPE_STRING, &params->service_type);

		if(params->version > 0)
			supplicant_dbus_dict_append_basic(&dict, "version",
												DBUS_TYPE_INT32, &params->version);

		if(params->desc)
			supplicant_dbus_dict_append_basic(&dict, "service",
												DBUS_TYPE_STRING, &params->desc);

		if(params->query_len > 0)
			supplicant_dbus_dict_append_fixed_array(&dict, "tlv",
														DBUS_TYPE_BYTE, &params->query, params->query_len);
		if(params->service_info != NULL)
			supplicant_dbus_dict_append_basic(&dict, "service_info",
												DBUS_TYPE_STRING, &params->service_info);
		if(params->service_transaction_id != 0)
			supplicant_dbus_dict_append_basic(&dict, "service_transaction_id",
												DBUS_TYPE_BYTE, &params->service_transaction_id);
	}

	supplicant_dbus_dict_close(iter, &dict);
}
static void interface_p2p_sd_request_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_sd_data *data = user_data;
	int err = 0;
	dbus_uint64_t ref = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback != NULL)
	{
		if(err == 0) {
			dbus_message_iter_get_basic(iter, &ref);
			((GSupplicantInterfaceCallbackWithData)data->callback)(0, data->interface, data->user_data, &ref);
		} else {
			((GSupplicantInterfaceCallbackWithData)data->callback)(err, data->interface, data->user_data, NULL);
		}
	}

	dbus_free(data);
}
int g_supplicant_interface_p2p_sd_request(GSupplicantInterface *interface,
				GSupplicantP2PSDParams *sd_data,
				GSupplicantInterfaceCallbackWithData callback,
				void *user_data)
{
	struct interface_p2p_sd_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = (GSupplicantInterfaceCallback) callback;
	data->user_data = user_data;
	data->p2p_sd_params = sd_data;

	ret = supplicant_dbus_method_call(interface->path,
										SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ServiceDiscoveryRequest",
										interface_p2p_sd_request_params, interface_p2p_sd_request_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}
static void interface_p2p_sd_cancel_request_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_sd_data *data = user_data;
	int err = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback != NULL)
	{
		data->callback(err, data->interface, data->user_data);
	}

	dbus_free(data);
}

static void interface_p2p_sd_cancel_request_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_sd_data *data = user_data;
	if (data && data->p2p_sd_params) {
		uint64_t *request_id = (uint64_t*)data->p2p_sd_params;
		dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT64, request_id);
	}
}

int g_supplicant_interface_p2p_sd_cancel_request(GSupplicantInterface *interface,
				dbus_uint64_t request_id,
				GSupplicantInterfaceCallback callback,
				void *user_data)
{
	struct interface_p2p_sd_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;
	data->p2p_sd_params = (void*)&request_id;

	ret = supplicant_dbus_method_call(interface->path,
									  SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ServiceDiscoveryCancelRequest",
									  interface_p2p_sd_cancel_request_params, interface_p2p_sd_cancel_request_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

struct p2p_service_data {
	bool registration;
	GSupplicantInterface *interface;
	GSupplicantP2PServiceParams *service;
	GSupplicantInterfaceCallback callback;
	void *user_data;
};

static void interface_p2p_service_result(const char *error,
					DBusMessageIter *iter, void *user_data)
{
	struct p2p_service_data *data = user_data;
	int result = 0;

	SUPPLICANT_DBG("%s result - %s", data->registration ?
				"Registration" : "Deletion",
				error ? error : "Success");
	if (error)
		result = -EINVAL;

	if (data->callback)
		data->callback(result, data->interface, data->user_data);

	g_free(data->service->query);
	g_free(data->service->response);
	g_free(data->service->service);
	g_free(data->service->wfd_ies);
	g_free(data->service);
	dbus_free(data);
}

static void interface_p2p_service_params(DBusMessageIter *iter,
							void *user_data)
{
	struct p2p_service_data *data = user_data;
	GSupplicantP2PServiceParams *service;
	DBusMessageIter dict;
	const char *type;

	SUPPLICANT_DBG("");

	service = data->service;

	supplicant_dbus_dict_open(iter, &dict);

	if (service->query && service->response) {
		type = "bonjour";
		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);
		supplicant_dbus_dict_append_fixed_array(&dict, "query",
					DBUS_TYPE_BYTE, &service->query,
					service->query_length);
		supplicant_dbus_dict_append_fixed_array(&dict, "response",
					DBUS_TYPE_BYTE, &service->response,
					service->response_length);
	} else if (service->version && service->service) {
		type = "upnp";
		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);
		supplicant_dbus_dict_append_basic(&dict, "version",
					DBUS_TYPE_INT32, &service->version);
		supplicant_dbus_dict_append_basic(&dict, "service",
					DBUS_TYPE_STRING, &service->service);
	} else if (service->adv_id > 0) {
		type = "asp";

		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);

		if (service->service)
			supplicant_dbus_dict_append_basic(&dict, "service",
					DBUS_TYPE_STRING, &service->service);

		if(service->adv_id != 0)
			supplicant_dbus_dict_append_basic(&dict, "adv_id",
			             DBUS_TYPE_UINT32, &service->adv_id);

		supplicant_dbus_dict_append_basic(&dict, "auto_accept",
		                                  DBUS_TYPE_UINT32, &service->auto_accept);

		supplicant_dbus_dict_append_basic(&dict, "service_state",
		                                  DBUS_TYPE_BYTE, &service->service_state);

		supplicant_dbus_dict_append_basic(&dict, "config_method",
		                                  DBUS_TYPE_UINT16, &service->config_method);

		if(service->service_info)
			supplicant_dbus_dict_append_basic(&dict, "service_info",
							DBUS_TYPE_STRING, &service->service_info);
	}
	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_delete_service_params(DBusMessageIter *iter,
							void *user_data)
{
	struct p2p_service_data *data = user_data;
	GSupplicantP2PServiceParams *service;
	DBusMessageIter dict;
	const char *type;

	SUPPLICANT_DBG("");

	service = data->service;

	supplicant_dbus_dict_open(iter, &dict);

	if (service->query && service->response) {
		type = "bonjour";
		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);
		supplicant_dbus_dict_append_fixed_array(&dict, "query",
					DBUS_TYPE_BYTE, &service->query,
					service->query_length);
		supplicant_dbus_dict_append_fixed_array(&dict, "response",
					DBUS_TYPE_BYTE, &service->response,
					service->response_length);
	} else if (service->version && service->service) {
		type = "upnp";
		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);
		supplicant_dbus_dict_append_basic(&dict, "version",
					DBUS_TYPE_INT32, &service->version);
		supplicant_dbus_dict_append_basic(&dict, "service",
					DBUS_TYPE_STRING, &service->service);
	} else if (service->adv_id > 0) {
		type = "asp";

		supplicant_dbus_dict_append_basic(&dict, "service_type",
						DBUS_TYPE_STRING, &type);

		if (service->service)
			supplicant_dbus_dict_append_basic(&dict, "service",
					DBUS_TYPE_STRING, &service->service);

		if(service->adv_id != 0)
			supplicant_dbus_dict_append_basic(&dict, "adv_id",
			             DBUS_TYPE_UINT32, &service->adv_id);

		supplicant_dbus_dict_append_basic(&dict, "auto_accept",
		                                  DBUS_TYPE_UINT32, &service->auto_accept);

		supplicant_dbus_dict_append_basic(&dict, "service_state",
		                                  DBUS_TYPE_BYTE, &service->service_state);

		supplicant_dbus_dict_append_basic(&dict, "config_method",
		                                  DBUS_TYPE_UINT16, &service->config_method);

		if(service->service_info)
			supplicant_dbus_dict_append_basic(&dict, "service_info",
							DBUS_TYPE_STRING, &service->service_info);
	}
	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_add_service(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				GSupplicantP2PServiceParams *p2p_service_params,
				void *user_data)
{
	struct p2p_service_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->registration = true;
	data->interface = interface;
	data->service = p2p_service_params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
		SUPPLICANT_INTERFACE ".Interface.P2PDevice", "AddService",
		interface_p2p_service_params, interface_p2p_service_result,
		data, interface);
	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

int g_supplicant_interface_p2p_del_service(GSupplicantInterface *interface,
				GSupplicantP2PServiceParams *p2p_service_params)
{
	struct p2p_service_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->service = p2p_service_params;

	ret = supplicant_dbus_method_call(interface->path,
		SUPPLICANT_INTERFACE ".Interface.P2PDevice", "DeleteService",
		interface_p2p_delete_service_params, interface_p2p_service_result,
		data, interface);
	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

struct interface_p2p_group_add_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PGroupAddParams *p2p_group_add_params;
	void *user_data;
};

static void interface_p2p_group_add_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_group_add_data *data = user_data;

	supplicant_dbus_dict_open(iter, &dict);


	if (data && data->p2p_group_add_params) {
		GSupplicantP2PGroupAddParams* params = data->p2p_group_add_params;

		if(params->persistent == TRUE) {
			supplicant_dbus_dict_append_basic(&dict, "persistent",
												DBUS_TYPE_BOOLEAN, &params->persistent);
		}

		if(params->persistent_group_object != NULL)	{
			supplicant_dbus_dict_append_basic(&dict, "persistent_group_object",
												DBUS_TYPE_OBJECT_PATH, &params->persistent_group_object);
		}

		if(params->frequency >= 0) {
			supplicant_dbus_dict_append_basic(&dict, "frequency",
												DBUS_TYPE_INT32, &params->frequency);
		}
	}

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_group_add_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_group_add_data *data = user_data;
	int err = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

int g_supplicant_interface_p2p_group_add(GSupplicantInterface *interface,
				GSupplicantP2PGroupAddParams *group_data,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_p2p_group_add_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;
	data->p2p_group_add_params = group_data;

	ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice",
					"GroupAdd",
					interface_p2p_group_add_params, interface_p2p_group_add_result,
					data, NULL);

	if (ret < 0)
		dbus_free(data);

	return ret;
}

struct interface_p2p_wps_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantP2PWPSParams *p2p_wps_params;
	void *user_data;
};

static void interface_p2p_wps_start_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_wps_connect_data *data = user_data;
	int err;

	SUPPLICANT_DBG("");

	err = 0;
	if (error != NULL) {
		SUPPLICANT_DBG("error: %s", error);
		err = parse_supplicant_error(iter);
	}

	if (error != NULL) {
		if (data->callback != NULL)
			data->callback(err, data->interface, data->user_data);
	}

	g_free(data->ssid);
	dbus_free(data);
}

static void interface_p2p_wps_start(DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_wps_data *data = user_data;
	GSupplicantP2PWPSParams *params = data->p2p_wps_params;

	DBusMessageIter dict;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "Role",
											DBUS_TYPE_STRING, &params->role);

	supplicant_dbus_dict_append_basic(&dict, "Type",
											DBUS_TYPE_STRING, &params->type);

	if (params->pin != NULL) {
		supplicant_dbus_dict_append_basic(&dict, "Pin",
												DBUS_TYPE_STRING, &params->pin);
	}

	if(params->p2p_dev_addr != NULL) {
		unsigned char *dev_addr = g_try_malloc(6);
		string_to_byte(params->p2p_dev_addr, dev_addr);
		supplicant_dbus_dict_append_fixed_array(&dict, "P2PDeviceAddress", DBUS_TYPE_BYTE, &dev_addr, 6);
		g_free(dev_addr);
	}

	supplicant_dbus_dict_close(iter, &dict);
}


int g_supplicant_interface_p2p_wps_start(GSupplicantInterface *interface,
													GSupplicantP2PWPSParams *wps_data,
													GSupplicantInterfaceCallback callback,
													void *user_data)
{
	struct interface_p2p_wps_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;
	data->p2p_wps_params = wps_data;

	SUPPLICANT_DBG("interface->path : %s\n", interface->path);

	ret = supplicant_dbus_method_call(interface->path,
										SUPPLICANT_INTERFACE ".Interface.WPS", "Start",
										interface_p2p_wps_start, interface_p2p_wps_start_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

struct interface_p2p_persistent_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	GSupplicantSSID *ssid;
	void *user_data;
};

static void interface_p2p_remove_persistent_group_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_persistent_data *data = user_data;
	const char *path = data->user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH, &path);
}

int g_supplicant_interface_p2p_remove_persistent_group(GSupplicantInterface *interface,
																		void *user_data)
{
	struct interface_p2p_persistent_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
										SUPPLICANT_INTERFACE ".Interface.P2PDevice", "RemovePersistentGroup",
										interface_p2p_remove_persistent_group_params,
										NULL, data, NULL);
	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

static void remove_quote(char *str)
{
	int len = strlen(str);
	int i=0;

	for(i=0; i<len-2; i++) {
		str[i] = str[i+1];
	}
	str[len-2] = '\0';
}

int g_supplicant_interface_p2p_remove_all_persistent_groups(GSupplicantInterface *interface)
{
	int ret;

	if (interface == NULL)
		return -EINVAL;

	SUPPLICANT_DBG("interface path : %s", interface->path);

	if (system_available == FALSE)
		return -EFAULT;

	ret = supplicant_dbus_method_call(interface->path,
						SUPPLICANT_INTERFACE ".Interface.P2PDevice",
						"RemoveAllPersistentGroups",
						NULL, NULL, NULL, NULL);
	if (ret < 0) {
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_p2p_add_persistent_group_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_group_add_data *data = user_data;
	int err = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

static void interface_p2p_add_persistent_group_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_persistent_data *data = user_data;
	GSupplicantSSID *ssid = data->ssid;
	dbus_uint32_t disabled=2;
	const char *auth_alg = "OPEN";

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "mode", DBUS_TYPE_UINT32, &ssid->mode);

	supplicant_dbus_dict_append_basic(&dict, "disabled", DBUS_TYPE_UINT32, &disabled);

	supplicant_dbus_dict_append_basic(&dict, "auth_alg", DBUS_TYPE_STRING, &auth_alg);

	supplicant_dbus_dict_append_basic(&dict, "bssid", DBUS_TYPE_STRING, &ssid->bssid);

	supplicant_dbus_dict_append_fixed_array(&dict, "ssid",
						DBUS_TYPE_BYTE, &ssid->ssid, ssid->ssid_len);

	if(ssid->passphrase != NULL && ssid->passphrase[0] == '\"') {
		char *passphrase = g_strdup(ssid->passphrase);
		remove_quote(passphrase);
		g_free(ssid->passphrase);
		ssid->passphrase = passphrase;
	}

	add_network_security(&dict, ssid);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_add_persistent_group(GSupplicantInterface *interface,
							GSupplicantSSID *ssid, void *user_data)
{
	struct interface_p2p_persistent_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->ssid = ssid;
	data->user_data = user_data;
	data->callback = NULL;

	ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice", "AddPersistentGroup",
					interface_p2p_add_persistent_group_params,
					interface_p2p_add_persistent_group_result, data, NULL);
	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

static void interface_p2p_persistent_group_add_params(DBusMessageIter *iter,
							void *user_data)
{
	DBusMessageIter dict;
	struct interface_connect_data *data = user_data;
	GSupplicantInterface *interface = data->interface;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "persistent_group_object",
						DBUS_TYPE_OBJECT_PATH, &interface->network_path);

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_persistent_group_add_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	int err;

	err = 0;
	if (error) {
		SUPPLICANT_DBG("Group add error %s", error);
		err = parse_supplicant_error(iter);
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

static void interface_p2p_persistent_group_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_connect_data *data = user_data;
	GSupplicantInterface *interface = data->interface;
	const char *path = NULL;
	int err;

	if (error)
		goto error;

	dbus_message_iter_get_basic(iter, &path);
	if (!path)
		goto error;

	g_free(interface->network_path);
	interface->network_path = g_strdup(path);

	SUPPLICANT_DBG("data->interface->path : %s\n", data->interface->path);

	supplicant_dbus_method_call(data->interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice",
					"GroupAdd",
					interface_p2p_persistent_group_add_params,
					interface_p2p_persistent_group_add_result,
					data, NULL);
	return;

	error:
		SUPPLICANT_DBG("GroupAdd error %s", error);
		err = parse_supplicant_error(iter);
		if (data->callback)
			data->callback(err, data->interface, data->user_data);

		g_free(interface->network_path);
		interface->network_path = NULL;
		g_free(data);
}

static void interface_p2p_persistent_group_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_connect_data *data = user_data;
	GSupplicantSSID *ssid = data->ssid;
	dbus_uint32_t mode = 3;
	dbus_uint32_t disabled = 2;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "mode", DBUS_TYPE_UINT32, &mode);
	supplicant_dbus_dict_append_basic(&dict, "disabled",
						DBUS_TYPE_UINT32, &disabled);

	add_network_security(&dict, ssid);

	//The data structure is set up as a byte buffer, however
	//SSID->SSID is created by ssid_ap_init - it is a null terminated string.
	supplicant_dbus_dict_append_basic(&dict, "ssid",
					DBUS_TYPE_STRING,
					&(ssid->ssid));

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_persistent_group_add(GSupplicantInterface *interface,
				GSupplicantSSID *ssid,
				GSupplicantInterfaceCallback callback,
							void *user_data)
{
	struct interface_connect_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->ssid = ssid;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
					SUPPLICANT_INTERFACE ".Interface.P2PDevice",
					"AddPersistentGroup",
					interface_p2p_persistent_group_params,
					interface_p2p_persistent_group_result,
					data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

int g_supplicant_interface_p2p_replace_service(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				GSupplicantP2PServiceParams *p2p_service_params,
				void *user_data)
{
      struct p2p_service_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->registration = true;
	data->interface = interface;
	data->service = p2p_service_params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
										SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ReplaceService",
										interface_p2p_service_params, interface_p2p_service_result,
		                                                   data, interface);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

struct interface_p2p_asp_provision_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	void *params; //Either request or response params
	void *user_data;
};

static void interface_p2p_asp_provision_result(const char *error,
											 DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_asp_provision_data *data = user_data;
	int err = 0;

	if (error != NULL) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback != NULL)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}

static void interface_p2p_asp_provision_request_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_asp_provision_data *data = user_data;
	GSupplicantP2PASPProvisionRequestParams* params = data->params;

	supplicant_dbus_dict_open(iter, &dict);

	if(params->peer)
		supplicant_dbus_dict_append_basic(&dict, "peer",
										  DBUS_TYPE_OBJECT_PATH, &params->peer);
	if(params->config_method)
		supplicant_dbus_dict_append_basic(&dict, "config_method",
										  DBUS_TYPE_UINT16, &params->config_method);
	if(params->advertisement_id)
		supplicant_dbus_dict_append_basic(&dict, "adv_id",
										  DBUS_TYPE_UINT32, &params->advertisement_id);
	if(params->service_mac)
		supplicant_dbus_dict_append_basic(&dict, "adv_mac",
										  DBUS_TYPE_STRING, &params->service_mac);
	if(params->role)
		supplicant_dbus_dict_append_basic(&dict, "role",
										  DBUS_TYPE_BYTE, &params->role);
	if(params->session_id)
		supplicant_dbus_dict_append_basic(&dict, "session_id",
										  DBUS_TYPE_UINT32, &params->session_id);
	if(params->session_mac)
		supplicant_dbus_dict_append_basic(&dict, "session_mac",
										  DBUS_TYPE_STRING, &params->session_mac);
	if(params->service_info)
		supplicant_dbus_dict_append_basic(&dict, "service_info",
										  DBUS_TYPE_STRING, &params->service_info);

	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_asp_provision_response_params(DBusMessageIter *iter, void *user_data)
{
	DBusMessageIter dict;
	struct interface_p2p_asp_provision_data *data = user_data;
	GSupplicantP2PASPProvisionResponseParams* params = data->params;

	supplicant_dbus_dict_open(iter, &dict);

	if(params->peer)
		supplicant_dbus_dict_append_basic(&dict, "peer",
										  DBUS_TYPE_OBJECT_PATH, &params->peer);
	if(params->advertisement_id)
		supplicant_dbus_dict_append_basic(&dict, "adv_id",
										  DBUS_TYPE_UINT32, &params->advertisement_id);
	if(params->service_mac)
		supplicant_dbus_dict_append_basic(&dict, "adv_mac",
										  DBUS_TYPE_STRING, &params->service_mac);
	supplicant_dbus_dict_append_basic(&dict, "status",
	                                  DBUS_TYPE_INT32, &params->status);
	supplicant_dbus_dict_append_basic(&dict, "role",
										  DBUS_TYPE_BYTE, &params->role);
	if(params->session_id)
		supplicant_dbus_dict_append_basic(&dict, "session_id",
										  DBUS_TYPE_UINT32, &params->session_id);
	if(params->session_mac)
		supplicant_dbus_dict_append_basic(&dict, "session_mac",
										  DBUS_TYPE_STRING, &params->session_mac);

	supplicant_dbus_dict_close(iter, &dict);
}

int g_supplicant_interface_p2p_asp_provision_request(GSupplicantInterface *interface,
													 GSupplicantP2PASPProvisionRequestParams *params,
													 GSupplicantInterfaceCallback callback,
													 void *user_data)
{
	struct interface_p2p_asp_provision_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->params = params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
									  SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ASPProvisionRequest",
									  interface_p2p_asp_provision_request_params, interface_p2p_asp_provision_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}

int g_supplicant_interface_p2p_asp_provision_response(GSupplicantInterface *interface,
                                                      GSupplicantP2PASPProvisionResponseParams *params,
													 GSupplicantInterfaceCallback callback,
													 void *user_data)
{
	struct interface_p2p_asp_provision_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->params = params;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_method_call(interface->path,
									  SUPPLICANT_INTERFACE ".Interface.P2PDevice", "ASPProvisionResponse",
									  interface_p2p_asp_provision_response_params, interface_p2p_asp_provision_result, data, NULL);

	if (ret < 0) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}
static void p2p_dev_address_update_cb(const char *key,
                                  DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;
	unsigned char *mac_bin;
	int mac_bin_len = 0;
	DBusMessageIter array;

	if (iter == NULL)
		return;

	dbus_message_iter_recurse(iter, &array);
	dbus_message_iter_get_fixed_array(&array, &mac_bin, &mac_bin_len);

	if (mac_bin_len == 6) {
		memcpy(data->interface->p2p_device_address, mac_bin, mac_bin_len);
		err = 0;
	}
	else {
		err = -1;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data);
}
int g_supplicant_interface_p2p_read_device_address(GSupplicantInterface *interface,
                                                   GSupplicantInterfaceCallback callback, void *user_data)
{
	struct interface_data *data;
	int ret;

	if (interface == NULL)
		return -EINVAL;

	if (system_available == FALSE)
		return -EINVAL;

	data = dbus_malloc0(sizeof(*data));
	if (data == NULL)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_property_get(interface->path,
	                                    SUPPLICANT_INTERFACE ".Interface.P2PDevice",
	                                    "DeviceAddress",
	                                    p2p_dev_address_update_cb, data, NULL);

	if (ret < 0)
		dbus_free(data);

	return ret;
}
const unsigned char *g_supplicant_interface_p2p_get_device_address(GSupplicantInterface *interface)
{
	return interface->p2p_device_address;
}
struct interface_p2p_listen_data {
	GSupplicantInterface *interface;
	GSupplicantInterfaceCallback callback;
	void *user_data;
	int period;
	int interval;
};

static void interface_p2p_listen_params(DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_listen_data *data = user_data;
	DBusMessageIter dict;

	supplicant_dbus_dict_open(iter, &dict);

	supplicant_dbus_dict_append_basic(&dict, "period",
					DBUS_TYPE_INT32, &data->period);
	supplicant_dbus_dict_append_basic(&dict, "interval",
					DBUS_TYPE_INT32, &data->interval);
	supplicant_dbus_dict_close(iter, &dict);
}

static void interface_p2p_listen_result(const char *error,
				DBusMessageIter *iter, void *user_data)
{
	struct interface_p2p_listen_data *data = user_data;
	int err = 0;

	SUPPLICANT_DBG("");

	if (error) {
		SUPPLICANT_DBG("error %s", error);
		err = -EIO;
	}

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	dbus_free(data);
}
int g_supplicant_interface_p2p_listen(GSupplicantInterface *interface,
						int period, int interval, GSupplicantInterfaceCallback callback,
						void *user_data)
{
	struct interface_p2p_listen_data *data;
	int ret=0;

	SUPPLICANT_DBG("");

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	if (!interface->p2p_support)
		return -ENOTSUP;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->period = period;
	data->interval = interval;
	data->user_data = user_data;

	ret=supplicant_dbus_method_call(interface->path,
			SUPPLICANT_INTERFACE ".Interface.P2PDevice",
			"ExtendedListen", interface_p2p_listen_params,
			interface_p2p_listen_result, data, NULL);
	if(ret<0)
		dbus_free(data);
	return ret;
}

static void widi_ies_params(DBusMessageIter *iter, void *user_data)
{
	struct p2p_service_data *data = user_data;
	GSupplicantP2PServiceParams *service = data->service;
	DBusMessageIter array;

	SUPPLICANT_DBG("%p - %d", service->wfd_ies, service->wfd_ies_length);

	dbus_message_iter_open_container(iter, DBUS_TYPE_ARRAY,
					DBUS_TYPE_BYTE_AS_STRING, &array);

	if (service->wfd_ies && service->wfd_ies_length > 0) {
		dbus_message_iter_append_fixed_array(&array, DBUS_TYPE_BYTE,
				&service->wfd_ies, service->wfd_ies_length);
	}

	dbus_message_iter_close_container(iter, &array);
}

int g_supplicant_set_widi_ies(GSupplicantP2PServiceParams *p2p_service_params,
					GSupplicantInterfaceCallback callback,
					void *user_data)
{
	struct p2p_service_data *data;
	int ret;

	SUPPLICANT_DBG("");

	if (!system_available)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->service = p2p_service_params;
	data->callback = callback;
	data->user_data = user_data;

	if (p2p_service_params->wfd_ies)
		data->registration = true;

	ret = supplicant_dbus_property_set(SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE, "WFDIEs",
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_TYPE_BYTE_AS_STRING,
					widi_ies_params,
					interface_p2p_service_result,
					data, NULL);
	if (ret < 0 && ret != -EINPROGRESS) {
		dbus_free(data);
		return ret;
	}

	return -EINPROGRESS;
}


static const char *g_supplicant_rule0 = "type=signal,"
					"path=" DBUS_PATH_DBUS ","
					"sender=" DBUS_SERVICE_DBUS ","
					"interface=" DBUS_INTERFACE_DBUS ","
					"member=NameOwnerChanged,"
					"arg0=" SUPPLICANT_SERVICE;
static const char *g_supplicant_rule1 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE;
static const char *g_supplicant_rule2 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface";
static const char *g_supplicant_rule3 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Interface.WPS";
static const char *g_supplicant_rule4 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".BSS";
static const char *g_supplicant_rule5 = "type=signal,"
			"interface=" SUPPLICANT_INTERFACE ".Network";
static const char *g_supplicant_rule6 = "type=signal,"
		"interface=" SUPPLICANT_INTERFACE ".Interface.P2PDevice";
static const char *g_supplicant_rule7 = "type=signal,"
		"interface=" SUPPLICANT_INTERFACE ".Peer";
static const char *g_supplicant_rule8 = "type=signal,"
		"interface=" SUPPLICANT_INTERFACE ".Group";

static void invoke_introspect_method(void)
{
	DBusMessage *message;

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE,
					SUPPLICANT_PATH,
					DBUS_INTERFACE_INTROSPECTABLE,
					"Introspect");

	if (!message)
		return;

	dbus_message_set_no_reply(message, TRUE);
	dbus_connection_send(connection, message, NULL);
	dbus_message_unref(message);
}

int g_supplicant_register(const GSupplicantCallbacks *callbacks)
{
	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (!connection)
		return -EIO;

	if (!dbus_connection_add_filter(connection, g_supplicant_filter,
						NULL, NULL)) {
		dbus_connection_unref(connection);
		connection = NULL;
		return -EIO;
	}

	callbacks_pointer = callbacks;
	eap_methods = 0;

	interface_table = g_hash_table_new_full(g_str_hash, g_str_equal,
						NULL, remove_interface);

	bss_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
	peer_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
	group_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
	pending_peer_connection = g_hash_table_new_full(g_str_hash, g_str_equal,
								NULL, NULL);
	config_file_table = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, g_free);
	intf_addr_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, NULL);
	dev_addr_mapping = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, g_free);
	p2p_peer_table = g_hash_table_new_full(g_str_hash, g_str_equal,
								g_free, NULL);

	supplicant_dbus_setup(connection);

	dbus_bus_add_match(connection, g_supplicant_rule0, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule1, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule2, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule3, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule4, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule5, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule6, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule7, NULL);
	dbus_bus_add_match(connection, g_supplicant_rule8, NULL);
	dbus_connection_flush(connection);

	if (dbus_bus_name_has_owner(connection,
					SUPPLICANT_SERVICE, NULL)) {
		system_available = TRUE;
		supplicant_dbus_property_get_all(SUPPLICANT_PATH,
						SUPPLICANT_INTERFACE,
						service_property, NULL, NULL);
	} else
		invoke_introspect_method();

	return 0;
}

static void unregister_interface_remove_params(DBusMessageIter *iter,
						void *user_data)
{
	const char *path = user_data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_OBJECT_PATH,
							&path);
}


static void unregister_remove_interface(gpointer key, gpointer value,
						gpointer user_data)
{
	GSupplicantInterface *interface = value;

	supplicant_dbus_method_call(SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE,
					"RemoveInterface",
					unregister_interface_remove_params,
					NULL, interface->path, NULL);
}

void g_supplicant_unregister(const GSupplicantCallbacks *callbacks)
{
	SUPPLICANT_DBG("");

	if (connection) {
		dbus_bus_remove_match(connection, g_supplicant_rule8, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule7, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule6, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule5, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule4, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule3, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule2, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule1, NULL);
		dbus_bus_remove_match(connection, g_supplicant_rule0, NULL);
		dbus_connection_flush(connection);

		dbus_connection_remove_filter(connection,
						g_supplicant_filter, NULL);
	}

	if (config_file_table) {
		g_hash_table_destroy(config_file_table);
		config_file_table = NULL;
	}

	if (bss_mapping) {
		g_hash_table_destroy(bss_mapping);
		bss_mapping = NULL;
	}

	if (peer_mapping) {
		g_hash_table_destroy(peer_mapping);
		peer_mapping = NULL;
	}

	if (group_mapping) {
		g_hash_table_destroy(group_mapping);
		group_mapping = NULL;
	}

	if (interface_table) {
		g_hash_table_foreach(interface_table,
					unregister_remove_interface, NULL);
		g_hash_table_destroy(interface_table);
		interface_table = NULL;
	}

	if (system_available)
		callback_system_killed();

	if (connection) {
		dbus_connection_unref(connection);
		connection = NULL;
	}

	if (intf_addr_mapping){
		g_hash_table_destroy(intf_addr_mapping);
		intf_addr_mapping = NULL;
	}
	if (p2p_peer_table != NULL){
		g_hash_table_destroy(p2p_peer_table);
		p2p_peer_table = NULL;
	}

	callbacks_pointer = NULL;
	eap_methods = 0;
}
static void signal_info_update_cb(const char *key,
                               DBusMessageIter *iter, void *user_data)
{
	struct interface_data *data = user_data;
	int err = 0;

	supplicant_dbus_property_foreach(iter, interface_signal_info,
						data->interface);

	if (data->callback)
		data->callback(err, data->interface, data->user_data);

	g_free(data);
}

int g_supplicant_interface_update_signal_info(GSupplicantInterface *interface,
                    GSupplicantInterfaceCallback callback, void *user_data)
{
	struct interface_data *data;
	int ret;

	if (!interface)
		return -EINVAL;

	if (!system_available)
		return -EFAULT;

	data = dbus_malloc0(sizeof(*data));
	if (!data)
		return -ENOMEM;

	data->interface = interface;
	data->callback = callback;
	data->user_data = user_data;

	ret = supplicant_dbus_property_get(interface->path,
						SUPPLICANT_INTERFACE ".Interface", "SignalInfo",
						signal_info_update_cb, data, NULL);

	if (ret < 0)
		dbus_free(data);

	return ret;
}
