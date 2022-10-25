#ifndef __CONNMAN_SD_H
#define __CONNMAN_SD_H

#include <connman/types.h>
#include <stdbool.h>
#include <gsupplicant/gsupplicant.h>

#ifdef __cplusplus
extern "C" {
#endif


struct connman_service_discovery;

void __connman_sd_init(GSupplicantInterface *interface, const char *dev_ident);
void __connman_sd_cleanup(void);

void __connman_sd_response_from_p2p_peer(const char *peer_ident, int reference,
								unsigned char *tlv, int tlv_len);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_SD_H */
