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
int connman_technology_set_regdom(const char *alpha2);
void connman_technology_regdom_notify(struct connman_technology *technology,
							const char *alpha2);

enum connman_service_type connman_technology_get_type
				(struct connman_technology *technology);

bool connman_technology_get_wifi_tethering(const struct connman_technology *technology,
					const char **ssid, const char **psk, int *freq);

bool connman_technology_is_tethering_allowed(enum connman_service_type type);
bool connman_technology_get_p2p_listen(struct connman_technology *technology);
void connman_technology_set_p2p_listen(struct connman_technology *technology,
							bool enabled);
unsigned int connman_technology_get_p2p_listen_channel(struct connman_technology *technology);
void connman_technology_set_p2p_listen_channel(struct connman_technology *technology,
									unsigned int listen_channel);

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
	int (*set_tethering) (struct connman_technology *technology,
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
};

int connman_technology_driver_register(struct connman_technology_driver *driver);
void connman_technology_driver_unregister(struct connman_technology_driver *driver);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_TECHNOLOGY_H */
