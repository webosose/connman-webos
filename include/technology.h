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

#ifndef __CONNMAN_TECHNOLOGY_H
#define __CONNMAN_TECHNOLOGY_H

#include <connman/service.h>
#include <gdbus.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SECTION:technology
 * @title: technology premitives
 * @short_description: Functions for handling technology details
 */

struct connman_technology;

int connman_technology_tethering_notify(struct connman_technology *technology,
							bool enabled);
void connman_technology_interface_changed(struct connman_technology *technology);
int connman_technology_add_station(enum connman_service_type type, const char *mac);
int connman_technology_remove_station(char *mac);
int connman_technology_set_regdom(const char *alpha2);
void connman_technology_regdom_notify(struct connman_technology *technology,
							const char *alpha2);

enum connman_service_type connman_technology_get_type
				(struct connman_technology *technology);
bool connman_technology_get_wifi_tethering(const char **ssid,
							const char **psk);
unsigned int connman_technology_get_wifi_tethering_channel(void);
bool connman_technology_is_tethering_allowed(enum connman_service_type type);
bool is_technology_enabled(struct connman_technology *technology);

void connman_technology_set_p2p(struct connman_technology *technology, bool enabled);
void connman_technology_set_p2p_identifier(struct connman_technology *technology,
							const char *p2p_identifier);
bool connman_technology_get_enable_p2p_listen(struct connman_technology *technology);
bool connman_technology_get_p2p_listen(struct connman_technology *technology);
void connman_technology_set_p2p_listen(struct connman_technology *technology,
							bool enabled);
void __connman_technology_p2p_invitation_result(struct connman_technology *technology,
							int status);
void connman_technology_set_p2p_listen_params(struct connman_technology *technology,
						int period, int interval);
unsigned int connman_technology_get_p2p_listen_channel(struct connman_technology *technology);
void connman_technology_set_p2p_listen_channel(struct connman_technology *technology,
									unsigned int listen_channel);
void connman_technology_wps_failed_notify(struct connman_technology *technology);
bool connman_technology_get_p2p_persistent(struct connman_technology *technology);
void connman_technology_set_p2p_persistent(struct connman_technology *technology, bool enabled);

struct connman_technology_driver {
	const char *name;
	enum connman_service_type type;
	int priority;
	int (*probe) (struct connman_technology *technology);
	void (*remove) (struct connman_technology *technology);
	void (*add_interface) (struct connman_technology *technology,
						int index, const char *name,
							const char *ident);
	void (*remove_interface) (struct connman_technology *technology,
								int index);
	int (*set_p2p_enable) (struct connman_technology *technology,
								bool status);
	int (*set_tethering) (struct connman_technology *technology,
				const char *identifier, const char *passphrase,
				const char *bridge, bool enabled);
	int (*set_regdom) (struct connman_technology *technology,
						const char *alpha2);
	int (*set_p2p_identifier) (struct connman_technology *technology,
						const char *p2p_identifier);
	int (*set_p2p_persistent) (struct connman_technology *technology,
						bool persistent_reconnect);
	int (*set_p2p_listen_channel) (struct connman_technology *technology,
						unsigned int listen_channel);
	int (*set_p2p_go_intent) (struct connman_technology *technology,
						unsigned int go_intent);
	int (*set_p2p_listen) (struct connman_technology *technology,
						bool enable);
	int (*set_p2p_listen_params) (struct connman_technology *technology,
						int period, int interval);
	int (*set_p2p_go) (DBusMessage *msg, struct connman_technology *technology,
						const char *identifier, const char *passphrase);
	int (*remove_persistent_info) (struct connman_technology *technology,
						const char *identifier);
	int (*remove_persistent_info_all) (struct connman_technology *technology);
};

int connman_technology_driver_register(struct connman_technology_driver *driver);
void connman_technology_driver_unregister(struct connman_technology_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_TECHNOLOGY_H */
