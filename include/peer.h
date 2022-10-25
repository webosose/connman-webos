/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2014  Intel Corporation. All rights reserved.
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

#ifndef __CONNMAN_PEER_H
#define __CONNMAN_PEER_H

#ifdef __cplusplus
extern "C" {
#endif

enum connman_peer_state {
	CONNMAN_PEER_STATE_UNKNOWN       = 0,
	CONNMAN_PEER_STATE_IDLE          = 1,
	CONNMAN_PEER_STATE_ASSOCIATION   = 2,
	CONNMAN_PEER_STATE_CONFIGURATION = 3,
	CONNMAN_PEER_STATE_READY         = 4,
	CONNMAN_PEER_STATE_DISCONNECT    = 5,
	CONNMAN_PEER_STATE_FAILURE       = 6,
};

enum connman_peer_wps_method {
	CONNMAN_PEER_WPS_UNKNOWN         = 0,
	CONNMAN_PEER_WPS_PBC             = 1,
	CONNMAN_PEER_WPS_PIN             = 2,
	CONNMAN_PEER_WPS_DISPLAY            = 3,
	CONNMAN_PEER_WPS_KEYBOARD         = 4,
	CONNMAN_PEER_WPS_P2PS                 = 5
};

enum connman_peer_service_type {
	CONNMAN_PEER_SERVICE_UNKNOWN      = 0,
	CONNMAN_PEER_SERVICE_WIFI_DISPLAY = 1,
};

struct connman_peer;

struct connman_peer *connman_peer_create(const char *identifier);

#define connman_peer_ref(peer) \
	connman_peer_ref_debug(peer, __FILE__, __LINE__, __func__)

#define connman_peer_unref(peer) \
	connman_peer_unref_debug(peer, __FILE__, __LINE__, __func__)

struct connman_peer *connman_peer_ref_debug(struct connman_peer *peer,
			const char *file, int line, const char *caller);
void connman_peer_unref_debug(struct connman_peer *peer,
			const char *file, int line, const char *caller);

const char *connman_peer_get_identifier(struct connman_peer *peer);
void connman_peer_set_name(struct connman_peer *peer, const char *name);
void connman_peer_set_iface_address(struct connman_peer *peer,
					const unsigned char *iface_address);
void connman_peer_set_device(struct connman_peer *peer,
				struct connman_device *device);
int connman_peer_set_ipaddress(struct connman_peer *peer,
				const char *address, const char *netmask, const char *gateway);
struct connman_device *connman_peer_get_device(struct connman_peer *peer);
void connman_peer_set_sub_device(struct connman_peer *peer,
					struct connman_device *device);
void connman_peer_set_as_master(struct connman_peer *peer, bool master);
void connman_peer_set_as_go(struct connman_peer *peer, bool go);
int connman_peer_set_state(struct connman_peer *peer,
					enum connman_peer_state new_state);
enum connman_peer_state connman_peer_get_state(struct connman_peer *peer);
void connman_peer_state_change_by_cancelled(void);
void connman_peer_request_connection(struct connman_peer *peer, int dev_passwd_id);
void connman_peer_invitation_request(const char* peer_path,
					const char* signal, const char* go_dev_addr);
void connman_peer_reset_services(struct connman_peer *peer);
void connman_peer_add_service(struct connman_peer *peer,
				enum connman_peer_service_type type,
				const unsigned char *data, int data_length);
void connman_peer_services_changed(struct connman_peer *peer);

int connman_peer_register(struct connman_peer *peer);
void connman_peer_unregister(struct connman_peer *peer);

struct connman_peer *connman_peer_get(struct connman_device *device,
						const char *identifier);
struct connman_peer *connman_peer_get_by_path(const char *path);
void connman_peer_get_local_address(gpointer user_data, DBusMessageIter *iter);

void __connman_peer_get_properties_struct(DBusMessageIter *iter, gpointer user_data);

typedef void (* peer_service_registration_cb_t) (int result, void *user_data);

struct connman_peer_driver {
	int (*connect) (struct connman_peer *peer,
			enum connman_peer_wps_method wps_method,
			const char *wps_pin);
	int (*disconnect) (struct connman_peer *peer);
	int (*register_service) (const unsigned char *specification,
				int specification_length,
				const unsigned char *query,
				int query_length, int version,
				peer_service_registration_cb_t callback,
				void *user_data);
	int (*unregister_service) (const unsigned char *specification,
					int specification_length,
					const unsigned char *query,
					int query_length, int version);
	int (*reject) (struct connman_peer *peer);
};

int connman_peer_driver_register(struct connman_peer_driver *driver);
void connman_peer_driver_unregister(struct connman_peer_driver *driver);

bool connman_peer_service_is_master(void);
const char *connman_peer_wps_method2string(enum connman_peer_wps_method method);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_PEER_H */
