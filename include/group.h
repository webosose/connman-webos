#ifndef __CONNMAN_GROUP_H
#define __CONNMAN_GROUP_H

#include <gsupplicant/gsupplicant.h>

#ifdef __cplusplus
extern "C" {
#endif


struct connman_group {
	int refcount;
	char *identifier;
	char *path;
	GSupplicantInterface *interface;
	GSupplicantInterface *orig_interface;

	char *name;
	char *passphrase;
	char *peer_ip;
	bool is_group_owner;
	bool is_persistent;
	bool tethering;
	bool autonomous;
	int freq;
	bool is_static_ip;

	const char *group_owner;
	GSList *peer_list;
	GHashTable *peer_hash;
	GHashTable *peer_intf;
};

#define connman_group_ref(group) \
	connman_group_ref_debug(group, __FILE__, __LINE__, __func__)

#define connman_group_unref(group) \
	connman_group_unref_debug(group, __FILE__, __LINE__, __func__)

#define P2P_WILDCARD_SSID "DIRECT-"
#define P2P_WILDCARD_SSID_LEN 7
#define P2P_MAX_SSID 32

struct connman_group *__connman_group();
const char* __connman_group_get_path(struct connman_group *group);
const char* __connman_group_get_identifier(struct connman_group *group);
const char* __connman_group_get_group_owner(struct connman_group *group);
int  __connman_group_get_list_length(struct connman_group *group);
bool __connman_group_is_autonomous(struct connman_group *group);

int __connman_group_accept_connection(struct connman_group *group, GSupplicantP2PWPSParams *wps_params);

bool __connman_group_exist(void);
void __connman_group_peer_failed(struct connman_group *group);

struct connman_group *__connman_group_lookup_from_ident(const char *identifier);

void __connman_group_list_struct(DBusMessageIter *iter);

struct connman_group* __connman_group_create(GSupplicantInterface *iface, const char *ifname, const char *ssid, const char *passphrase,
														bool go, bool persistent, const char *go_path, bool autonomous, int freq);
void __connman_group_remove(GSupplicantInterface *interface);
void __connman_group_peer_joined(struct connman_group *group, const char *_peer_ident, char *intf_addr, const char *peer_path);
bool __connman_group_peer_disconnected(struct connman_group *group, char *peer_ident);
void __connman_group_client_dhcp_ip_assigned(struct connman_group *group);

void __connman_group_init(void);
void __connman_group_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_GROUP_H */
