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
#ifndef __G_SUPPLICANT_H
#define __G_SUPPLICANT_H

#ifdef __cplusplus
extern "C" {
#endif

#define G_SUPPLICANT_EAP_METHOD_MD5	(1 << 0)
#define G_SUPPLICANT_EAP_METHOD_TLS	(1 << 1)
#define G_SUPPLICANT_EAP_METHOD_MSCHAPV2	(1 << 2)
#define G_SUPPLICANT_EAP_METHOD_PEAP	(1 << 3)
#define G_SUPPLICANT_EAP_METHOD_TTLS	(1 << 4)
#define G_SUPPLICANT_EAP_METHOD_GTC	(1 << 5)
#define G_SUPPLICANT_EAP_METHOD_OTP	(1 << 6)
#define G_SUPPLICANT_EAP_METHOD_LEAP	(1 << 7)
#define G_SUPPLICANT_EAP_METHOD_WSC	(1 << 8)

#define G_SUPPLICANT_CAPABILITY_AUTHALG_OPEN	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_SHARED	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_AUTHALG_LEAP	(1 << 2)

#define G_SUPPLICANT_CAPABILITY_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_CAPABILITY_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_CAPABILITY_SCAN_ACTIVE	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_SCAN_PASSIVE	(1 << 1)
#define G_SUPPLICANT_CAPABILITY_SCAN_SSID		(1 << 2)

#define G_SUPPLICANT_CAPABILITY_MODE_INFRA	(1 << 0)
#define G_SUPPLICANT_CAPABILITY_MODE_IBSS		(1 << 1)
#define G_SUPPLICANT_CAPABILITY_MODE_AP		(1 << 2)
#define G_SUPPLICANT_CAPABILITY_MODE_P2P	(1 << 3)

#define G_SUPPLICANT_KEYMGMT_NONE		(1 << 0)
#define G_SUPPLICANT_KEYMGMT_IEEE8021X	(1 << 1)
#define G_SUPPLICANT_KEYMGMT_WPA_NONE	(1 << 2)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK	(1 << 3)
#define G_SUPPLICANT_KEYMGMT_WPA_PSK_256	(1 << 4)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_PSK	(1 << 5)
#define G_SUPPLICANT_KEYMGMT_WPA_FT_EAP	(1 << 6)
#define G_SUPPLICANT_KEYMGMT_WPA_EAP	(1 << 7)
#define G_SUPPLICANT_KEYMGMT_WPA_EAP_256	(1 << 8)
#define G_SUPPLICANT_KEYMGMT_WPS		(1 << 9)
#define G_SUPPLICANT_KEYMGMT_SAE		(1 << 10)

#define G_SUPPLICANT_PROTO_WPA		(1 << 0)
#define G_SUPPLICANT_PROTO_RSN		(1 << 1)

#define G_SUPPLICANT_GROUP_WEP40		(1 << 0)
#define G_SUPPLICANT_GROUP_WEP104		(1 << 1)
#define G_SUPPLICANT_GROUP_TKIP		(1 << 2)
#define G_SUPPLICANT_GROUP_CCMP		(1 << 3)

#define G_SUPPLICANT_PAIRWISE_NONE	(1 << 0)
#define G_SUPPLICANT_PAIRWISE_TKIP	(1 << 1)
#define G_SUPPLICANT_PAIRWISE_CCMP	(1 << 2)

#define G_SUPPLICANT_WPS_CONFIGURED     (1 << 0)
#define G_SUPPLICANT_WPS_PBC            (1 << 1)
#define G_SUPPLICANT_WPS_PIN            (1 << 2)
#define G_SUPPLICANT_WPS_REGISTRAR      (1 << 3)

#define G_SUPPLICANT_WPS_CONFIG_PBC	0x0080

#define G_SUPPLICANT_GROUP_ROLE_CLIENT	(1 << 0)
#define G_SUPPLICANT_GROUP_ROLE_GO      (1 << 1)

typedef enum {
	G_SUPPLICANT_MODE_UNKNOWN,
	G_SUPPLICANT_MODE_INFRA,
	G_SUPPLICANT_MODE_IBSS,
	G_SUPPLICANT_MODE_MASTER,
} GSupplicantMode;

typedef enum {
	G_SUPPLICANT_SECURITY_UNKNOWN,
	G_SUPPLICANT_SECURITY_NONE,
	G_SUPPLICANT_SECURITY_WEP,
	G_SUPPLICANT_SECURITY_PSK,
	G_SUPPLICANT_SECURITY_IEEE8021X,
} GSupplicantSecurity;

typedef enum {
	G_SUPPLICANT_STATE_UNKNOWN,
	G_SUPPLICANT_STATE_DISABLED,
	G_SUPPLICANT_STATE_DISCONNECTED,
	G_SUPPLICANT_STATE_INACTIVE,
	G_SUPPLICANT_STATE_SCANNING,
	G_SUPPLICANT_STATE_AUTHENTICATING,
	G_SUPPLICANT_STATE_ASSOCIATING,
	G_SUPPLICANT_STATE_ASSOCIATED,
	G_SUPPLICANT_STATE_4WAY_HANDSHAKE,
	G_SUPPLICANT_STATE_GROUP_HANDSHAKE,
	G_SUPPLICANT_STATE_COMPLETED,
} GSupplicantState;

typedef enum {
	G_SUPPLICANT_WPS_STATE_UNKNOWN,
	G_SUPPLICANT_WPS_STATE_SUCCESS,
	G_SUPPLICANT_WPS_STATE_FAIL,
} GSupplicantWpsState;

typedef enum {
	G_SUPPLICANT_PEER_SERVICES_CHANGED,
	G_SUPPLICANT_PEER_GROUP_CHANGED,
	G_SUPPLICANT_PEER_GROUP_STARTED,
	G_SUPPLICANT_PEER_GROUP_FINISHED,
	G_SUPPLICANT_PEER_GROUP_JOINED,
	G_SUPPLICANT_PEER_GROUP_DISCONNECTED,
	G_SUPPLICANT_PEER_GROUP_FAILED,
} GSupplicantPeerState;

typedef enum {
	G_SUPPLICANT_MFP_NONE,
	G_SUPPLICANT_MFP_OPTIONAL,
	G_SUPPLICANT_MFP_REQUIRED,
} GSupplicantMfpOptions;

struct _GSupplicantSSID {
	const void *ssid;
	unsigned int ssid_len;
	unsigned int scan_ssid;
	GSupplicantMode mode;
	GSupplicantSecurity security;
	unsigned int protocol;
	unsigned int pairwise_cipher;
	unsigned int group_cipher;
	unsigned int freq;
	const char *eap;
	const char *passphrase;
	const char *identity;
	const char *anonymous_identity;
	const char *ca_cert_path;
	const char *subject_match;
	const char *altsubject_match;
	const char *domain_suffix_match;
	const char *domain_match;
	const char *client_cert_path;
	const char *private_key_path;
	const char *private_key_passphrase;
	const char *phase2_auth;
	dbus_bool_t use_wps;
	const char *pin_wps;
	const char *bgscan;
	const char *bssid;
};

typedef struct _GSupplicantSSID GSupplicantSSID;

struct scan_ssid {
	unsigned char ssid[32];
	uint8_t ssid_len;
};

struct _GSupplicantScanParams {
	GSList *ssids;

	uint8_t num_ssids;

	uint8_t num_freqs;
	uint16_t *freqs;
};

typedef struct _GSupplicantScanParams GSupplicantScanParams;

struct _GSupplicantPeerParams {
	bool master;
	char *wps_method;
	char *wps_pin;
	char *path;

	dbus_bool_t persistent;
	dbus_bool_t join;
	dbus_bool_t authorize_only;
	dbus_int32_t frequency;
	dbus_int32_t go_intent;
};

typedef struct _GSupplicantPeerParams GSupplicantPeerParams;

struct _GSupplicantP2PServiceParams {
	int version;
	char *service;
	unsigned char *query;
	int query_length;
	unsigned char *response;
	int response_length;
	unsigned char *wfd_ies;
	int wfd_ies_length;

	const char *service_info;
	dbus_uint32_t auto_accept;
	dbus_uint32_t adv_id;
	uint8_t service_state;
	dbus_uint16_t config_method;
};

typedef struct _GSupplicantP2PServiceParams GSupplicantP2PServiceParams;

typedef enum
{
	G_SUPPLICANT_P2P_FIND_START_WITH_FULL,
	G_SUPPLICANT_P2P_FIND_ONLY_SOCIAL,
	G_SUPPLICANT_P2P_FIND_PROGRESSIVE
} GSupplicantP2PFindType;


struct _GSupplicantP2PSDParams {
	const char *peer;
	const char *service_type;
	dbus_int32_t version;
	const char *desc;
	const char *service_info;
	unsigned char service_transaction_id;
	unsigned char *query;
	int query_len;
	unsigned char *response;
	dbus_uint32_t auto_accept;
	dbus_uint32_t adv_id;
	uint8_t service_state;
	dbus_uint16_t config_method;
	int response_len;
};
typedef struct _GSupplicantP2PSDParams GSupplicantP2PSDParams;


typedef struct _GSupplicantP2PASPProvisionRequestParams {
	const char *peer;
	uint16_t config_method;
	uint32_t advertisement_id;
	const char *service_mac;
	uint8_t role;
	uint32_t session_id;
	const char *session_mac;
	const char *service_info;
} GSupplicantP2PASPProvisionRequestParams;

typedef struct _GSupplicantP2PASPProvisionResponseParams {
	const char *peer;
	uint32_t advertisement_id;
	const char *service_mac;
	int32_t status;
	uint8_t role;
	uint32_t session_id;
	const char *session_mac;
} GSupplicantP2PASPProvisionResponseParams;

typedef struct _GSupplicantP2PSProvisionSignalParams {
	//Common
	uint32_t advertisement_id;
	char service_mac[18];
	uint32_t session_id;
	char session_mac[18];
	uint32_t connection_capability;
	uint32_t password_id;
	uint16_t feature_capability;

	//Start only
	char session_info[150]; // up to 144 bytes

	//Done only
	uint32_t status;
	uint32_t persist;
	char group_mac[18];
} GSupplicantP2PSProvisionSignalParams;

struct _GSupplicantP2PGroupAddParams {
	dbus_bool_t persistent;
	const char *persistent_group_object;
	dbus_int32_t frequency;
};

typedef struct _GSupplicantP2PGroupAddParams GSupplicantP2PGroupAddParams;

/* global API */
typedef void (*GSupplicantCountryCallback) (int result,
						const char *alpha2,
							void *user_data);

int g_supplicant_set_country(const char *alpha2,
				GSupplicantCountryCallback callback,
						const void *user_data);

/* Interface API */
struct _GSupplicantInterface;
struct _GSupplicantPeer;
struct _GSupplicantP2PInterface;

typedef struct _GSupplicantInterface GSupplicantInterface;
typedef struct _GSupplicantPeer GSupplicantPeer;
typedef struct _GSupplicantP2PInterface GSupplicantP2PInterface;
typedef struct _GSupplicantRequestedPeer GSupplicantRequestedPeer;

struct _GSupplicantP2PDeviceConfigParams {
	GSupplicantInterface *interface;
	char *device_name;
	unsigned char pri_dev_type[8];
	dbus_uint32_t go_intent;
	int persistent_reconnect;
	dbus_uint32_t listen_reg_class;
	dbus_uint32_t listen_channel;
	dbus_uint32_t oper_reg_class;
	dbus_uint32_t oper_channel;
	char *ssid_postfix;
	int intra_bss;
	dbus_uint32_t group_idle;
	dbus_uint32_t disassoc_low_ack;
	const void *user_data;
};

typedef int		connman_bool_t;

struct _GSupplicantP2PPersistentGroup {
	GSupplicantInterface *interface;
	char *path;
	char *group_path;
	char *bssid;
	char *bssid_no_colon;
	char *ssid;
	char *psk;
	connman_bool_t go;
	unsigned long long connected_time;
};
typedef struct _GSupplicantP2PPersistentGroup GSupplicantP2PPersistentGroup;

struct _GSupplicantP2PGroup {
	GSupplicantInterface *interface;
	GSupplicantInterface *group_interface;
	char *path;
	char *ssid;
	char *bssid_no_colon;
	char *passphrase;
	char *psk;
	char *role;
	char *ip_addr;
	char *ip_mask;
	char *go_ip_addr;
	int persistent;
	int freq;
	GSupplicantP2PPersistentGroup *persistent_group;
};

typedef struct _GSupplicantP2PGroup GSupplicantP2PGroup;

/* ASP service advertised by the peer.*/
struct _GSupplicantP2PService {
	dbus_uint32_t advertisement_id;
	char service_name[256];
};

typedef struct _GSupplicantP2PService GSupplicantP2PService;

struct _GSupplicantP2PWPSParams {
	const char *role;
	const char *type;
	const char *p2p_dev_addr;
	const char *pin;
};
typedef struct _GSupplicantP2PWPSParams GSupplicantP2PWPSParams;

struct _GSupplicantP2PFindParams {
	dbus_int32_t timeout;
	int disc_type;
	const char** seek_array;
	int frequency;
};

typedef struct _GSupplicantP2PFindParams GSupplicantP2PFindParams;

typedef struct _GSupplicantP2PDeviceConfigParams GSupplicantP2PDeviceConfigParams;
struct p2p_listen_data {
	int period;
	int interval;
};

struct _GSupplicantP2PInviteParams {
	const char *peer;
	const char *persistent_group;
};

typedef struct _GSupplicantP2PInviteParams GSupplicantP2PInviteParams;

typedef void (*GSupplicantInterfaceCallback) (int result,
					GSupplicantInterface *interface,
							void *user_data);

void g_supplicant_interface_cancel(GSupplicantInterface *interface);

int g_supplicant_interface_create(const char *ifname, const char *driver,
					const char *bridge, const char *config_file,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_remove(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);
int g_supplicant_interface_scan(GSupplicantInterface *interface,
					GSupplicantScanParams *scan_data,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_p2p_find(GSupplicantInterface *interface,
				GSupplicantP2PFindParams *find_data,
				GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_p2p_stop_find(GSupplicantInterface *interface);

int g_supplicant_interface_p2p_connect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params,
					GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_p2p_disconnect(GSupplicantInterface *interface,
					GSupplicantPeerParams *peer_params);

int g_supplicant_interface_p2p_group_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_p2p_persistent_group_add(GSupplicantInterface *interface,
					GSupplicantSSID *ssid, GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_p2p_group_add(GSupplicantInterface *interface,
				GSupplicantP2PGroupAddParams *group_data,
				GSupplicantInterfaceCallback callback,
				void *user_data);

int g_supplicant_interface_p2p_listen(GSupplicantInterface *interface,
						int period, int interval,
						GSupplicantInterfaceCallback callback,
						void *user_data);

int g_supplicant_interface_p2p_add_service(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback,
				GSupplicantP2PServiceParams *p2p_service_params,
				void *user_data);

typedef void (*GSupplicantInterfaceCallbackWithData) (int result,
					GSupplicantInterface *interface,
							void *user_data, void* data);
int g_supplicant_interface_p2p_wps_start(GSupplicantInterface *interface,
													GSupplicantP2PWPSParams *wps_data,
													GSupplicantInterfaceCallback callback,
													void *user_data);
int g_supplicant_interface_p2p_del_service(GSupplicantInterface *interface,
				GSupplicantP2PServiceParams *p2p_service_params);
int g_supplicant_interface_p2p_flush(GSupplicantInterface *interface,
				GSupplicantInterfaceCallback callback, void *user_data);
int g_supplicant_interface_p2p_invite(GSupplicantInterface *interface,
				GSupplicantP2PInviteParams *invite_data,
				GSupplicantInterfaceCallback callback, void *user_data);

int g_supplicant_set_widi_ies(GSupplicantP2PServiceParams *p2p_service_params,
					GSupplicantInterfaceCallback callback,
					void *user_data);

int g_supplicant_interface_connect(GSupplicantInterface *interface,
					GSupplicantSSID *ssid,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_disconnect(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback,
							void *user_data);

int g_supplicant_interface_set_bss_expiration_age(GSupplicantInterface *interface,
					unsigned int bss_expiration_age);

int g_supplicant_interface_set_apscan(GSupplicantInterface *interface,
							unsigned int ap_scan);

void g_supplicant_interface_set_data(GSupplicantInterface *interface,
								void *data);
void *g_supplicant_interface_get_data(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_ifname(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_driver(GSupplicantInterface *interface);
GSupplicantState g_supplicant_interface_get_state(GSupplicantInterface *interface);
const char *g_supplicant_interface_get_wps_key(GSupplicantInterface *interface);
const void *g_supplicant_interface_get_wps_ssid(GSupplicantInterface *interface,
							unsigned int *ssid_len);
GSupplicantWpsState g_supplicant_interface_get_wps_state(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_mode(GSupplicantInterface *interface);
dbus_bool_t g_supplicant_interface_get_ready(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_max_scan_ssids(
					GSupplicantInterface *interface);

int g_supplicant_interface_enable_selected_network(GSupplicantInterface *interface,
							dbus_bool_t enable);
int g_supplicant_interface_set_country(GSupplicantInterface *interface,
					GSupplicantCountryCallback callback,
							const char *alpha2,
							void *user_data);
bool g_supplicant_interface_has_p2p(GSupplicantInterface *interface);
int g_supplicant_interface_set_p2p_device_config(GSupplicantInterface *interface,
						const char *device_name,
						const char *primary_dev_type);
int g_supplicant_interface_set_p2p_device_configs(GSupplicantInterface *interface,
						GSupplicantP2PDeviceConfigParams *p2p_device_config_data,
						void *user_data);
int g_supplicant_interface_get_p2p_device_config(GSupplicantInterface *interface,
						GSupplicantP2PDeviceConfigParams *p2p_device_config);
int g_supplicant_interface_set_p2p_disabled(GSupplicantInterface *interface,
						dbus_bool_t disabled);
GSupplicantPeer *g_supplicant_interface_peer_lookup(GSupplicantInterface *interface,
						const char *identifier);
bool g_supplicant_interface_is_p2p_finding(GSupplicantInterface *interface);

int g_supplicant_interface_update_signal_info(GSupplicantInterface *interface,
					GSupplicantInterfaceCallback callback, void *user_data);

unsigned int g_supplicant_interface_get_rssi(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_link_speed(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_frequency(GSupplicantInterface *interface);
unsigned int g_supplicant_interface_get_noise(GSupplicantInterface *interface);

/* Network and Peer API */
struct _GSupplicantNetwork;
struct _GSupplicantGroup;

struct _GSupplicantP2PNetwork;
typedef struct _GSupplicantP2PNetwork GSupplicantP2PNetwork;

typedef struct _GSupplicantNetwork GSupplicantNetwork;
typedef struct _GSupplicantGroup GSupplicantGroup;

GSupplicantInterface *g_supplicant_network_get_interface(GSupplicantNetwork *network);
const char *g_supplicant_network_get_name(GSupplicantNetwork *network);
const char *g_supplicant_network_get_identifier(GSupplicantNetwork *network);
const char *g_supplicant_network_get_path(GSupplicantNetwork *network);
const void *g_supplicant_network_get_ssid(GSupplicantNetwork *network,
							unsigned int *ssid_len);
const char *g_supplicant_network_get_mode(GSupplicantNetwork *network);
const char *g_supplicant_network_get_security(GSupplicantNetwork *network);
dbus_int16_t g_supplicant_network_get_signal(GSupplicantNetwork *network);
dbus_uint16_t g_supplicant_network_get_frequency(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_get_wps(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_active(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_pbc(GSupplicantNetwork *network);
dbus_bool_t g_supplicant_network_is_wps_advertizing(GSupplicantNetwork *network);

const unsigned char *g_supplicant_network_get_bssid(GSupplicantNetwork *network);
GHashTable *g_supplicant_network_get_bss_table(GSupplicantNetwork *network);

struct g_supplicant_bss;

typedef struct g_supplicant_bss GSupplicantBss;

const unsigned char *g_supplicant_bss_get_bssid(GSupplicantBss *bss);
dbus_int16_t g_supplicant_bss_get_signal(GSupplicantBss *bss);
dbus_uint16_t g_supplicant_bss_get_frequency(GSupplicantBss *bss);

GSupplicantInterface *g_supplicant_peer_get_interface(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_path(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_identifier(GSupplicantPeer *peer);
const void *g_supplicant_peer_get_device_address(GSupplicantPeer *peer);
const void *g_supplicant_peer_get_iface_address(GSupplicantPeer *peer);
const char *g_supplicant_peer_get_name(GSupplicantPeer *peer);
const unsigned char *g_supplicant_peer_get_widi_ies(GSupplicantPeer *peer,
								int *length);
bool g_supplicant_peer_is_wps_pbc(GSupplicantPeer *peer);
bool g_supplicant_peer_is_wps_pin(GSupplicantPeer *peer);
bool g_supplicant_peer_is_in_a_group(GSupplicantPeer *peer);
GSupplicantInterface *g_supplicant_peer_get_group_interface(GSupplicantPeer *peer);
bool g_supplicant_peer_is_client(GSupplicantPeer *peer);
bool g_supplicant_peer_has_requested_connection(GSupplicantPeer *peer);

GSupplicantP2PNetwork* g_supplicant_find_network_from_intf_address(const char* pintf_addr, const char* p2p_dev_addr);
const char *g_supplicant_peer_identifier_from_intf_address(const char* pintf_addr);
const char *g_supplicant_peer_wfds_get_identifier(GSupplicantPeer *peer);
int g_supplicant_peer_wfds_get_asp_services(GSupplicantPeer *peer, GSupplicantP2PService** services);
const char *g_supplicant_peer_wfds_get_peer_name(GSupplicantPeer *peer);
char *g_supplicant_group_get_ssid(GSupplicantGroup *group);
unsigned int g_supplicant_network_get_keymgmt(GSupplicantNetwork *network);

struct _GSupplicantCallbacks {
	void (*system_ready) (void);
	void (*system_killed) (void);
	void (*interface_added) (GSupplicantInterface *interface);
	void (*interface_state) (GSupplicantInterface *interface);
	void (*interface_removed) (GSupplicantInterface *interface);
	void (*p2p_support) (GSupplicantInterface *interface);
	void (*p2p_device_config_loaded) (GSupplicantInterface *interface);
	void (*scan_started) (GSupplicantInterface *interface);
	void (*scan_finished) (GSupplicantInterface *interface);
	void (*ap_create_fail) (GSupplicantInterface *interface);
	void (*network_added) (GSupplicantNetwork *network);
	void (*network_removed) (GSupplicantNetwork *network);
	void (*network_changed) (GSupplicantNetwork *network,
					const char *property);
	void (*network_associated) (GSupplicantNetwork *network);
	void (*station_added) (const char *mac);
	void (*station_removed) (const char *mac);
	void (*sta_authorized) (GSupplicantInterface *interface,
					const char *addr);
	void (*sta_deauthorized) (GSupplicantInterface *interface,
					const char *addr);
	void (*peer_found) (GSupplicantPeer *peer);
	void (*peer_lost) (GSupplicantPeer *peer);
	void (*peer_changed) (GSupplicantPeer *peer,
					GSupplicantPeerState state);
	void (*peer_request) (GSupplicantPeer *peer, int dev_passwd_id);
	void (*p2p_sd_response) (GSupplicantInterface *interface, GSupplicantPeer *peer, int indicator, unsigned char *tlv, int tlv_len);
	void (*p2p_sd_asp_response) (GSupplicantInterface *interface,  GSupplicantPeer *peer, unsigned char transaction_id, unsigned int advertisment_id, unsigned char service_status, dbus_uint16_t config_method, const char* service_name, const char* service_info);
	void (*wps_state)(GSupplicantInterface *interface);
	void (*debug) (const char *str);
	void (*disconnect_reasoncode)(GSupplicantInterface *interface,
				int reasoncode);
	void (*assoc_status_code)(GSupplicantInterface *interface,
				int reasoncode);
	void (*p2p_group_started)(GSupplicantGroup *group);
	void (*p2p_group_finished)(GSupplicantInterface *interface);
	void (*p2ps_prov_start) (GSupplicantInterface *interface,  GSupplicantPeer *peer, GSupplicantP2PSProvisionSignalParams* params);
	void (*p2ps_prov_done) (GSupplicantInterface *interface,  GSupplicantPeer *peer, GSupplicantP2PSProvisionSignalParams* params);

	void (*p2p_persistent_group_added) (GSupplicantInterface *interface, GSupplicantP2PPersistentGroup *persistent_group);
	void (*p2p_persistent_group_removed) (GSupplicantInterface *interface, const char *persistent_group_path);
	void (*p2p_prov_disc_requested_pbc) (GSupplicantInterface *interface, GSupplicantPeer *peer);
	void (*p2p_prov_disc_requested_enter_pin) (GSupplicantInterface *interface, GSupplicantPeer *peer);
	void (*p2p_prov_disc_requested_display_pin) (GSupplicantInterface *interface, GSupplicantPeer *peer, const char *pin);
	void (*p2p_prov_disc_response_enter_pin) (GSupplicantInterface *interface, GSupplicantPeer *peer);
	void (*p2p_prov_disc_response_display_pin) (GSupplicantInterface *interface, GSupplicantPeer *peer, const char *pin);
	void (*p2p_prov_disc_fail) (GSupplicantInterface *interface, GSupplicantPeer *peer, int status);

	void (*p2p_invitation_result)(GSupplicantInterface *interface, int status);
	void (*p2p_invitation_received) (GSupplicantInterface *interface, GSupplicantP2PNetwork *p2p_network, const char *go_dev_addr, connman_bool_t persistent);
};

typedef struct _GSupplicantCallbacks GSupplicantCallbacks;

int g_supplicant_register(const GSupplicantCallbacks *callbacks);
void g_supplicant_unregister(const GSupplicantCallbacks *callbacks);

static inline
void g_supplicant_free_scan_params(GSupplicantScanParams *scan_params)
{
	g_slist_free_full(scan_params->ssids, g_free);
	g_free(scan_params->freqs);
	g_free(scan_params);
}

#ifdef __cplusplus
}
#endif

#endif /* __G_SUPPLICANT_H */
