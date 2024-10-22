/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2024  Intel Corporation. All rights reserved.
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include <ctype.h>
#include "connman.h"

#define URANDOM "/dev/urandom"

static int f = -1;

int __connman_util_get_random(uint64_t *val)
{
	int r;

	if (!val)
		return -EINVAL;

	r = read(f, val, sizeof(uint64_t));
	if (r < 0) {
		r = -errno;
		connman_warn_once("Could not read from "URANDOM);
		*val = random();
	} else if (r != sizeof(uint64_t)) {
		r = -EIO;
		connman_warn_once("Short read from "URANDOM);
		*val = random();
	}

	return r;
}

int __connman_util_init(void)
{
	int r = 0;

	if (f >= 0)
		return 0;

	f = open(URANDOM, O_RDONLY);
	if (f < 0) {
		r = -errno;
		connman_warn("Could not open "URANDOM);
		srandom(time(NULL));
	} else {
		uint64_t val;

		r = __connman_util_get_random(&val);
		if (r < 0)
			srandom(time(NULL));
		else
			srandom(val);
	}

	return r;
}

void __connman_util_cleanup(void)
{
	if (f >= 0)
		close(f);

	f = -1;
}

/**
 * Return a random delay in range of zero to secs*1000 milli seconds.
 */
unsigned int __connman_util_random_delay_ms(unsigned int secs)
{
       uint64_t rand;

       __connman_util_get_random(&rand);
       return rand % (secs * 1000);
}

char *__connman_util_insert_colon_to_mac_addr(const char *mac_addr)
{
	char *result = g_try_malloc(18);
	int i;

	if (!mac_addr || strlen(mac_addr) < 12) {
		g_free(result);
		return NULL;
	}

	for (i=0; i<6; i++) {
		result[i*3] = mac_addr[i*2];
		result[i*3+1] = mac_addr[i*2+1];
	}

	result[2] = ':';
	result[5] = ':';
	result[8] = ':';
	result[11] = ':';
	result[14] = ':';
	result[17] = '\0';

	DBG("before: %s, after: %s", mac_addr, result);

	return result;
}

char *__connman_util_remove_colon_from_mac_addr(const char *mac_addr)
{
	char *result;
	int i=0;

	if(mac_addr == NULL || strlen(mac_addr) != 17)
		return NULL;

	result = g_try_malloc(13);
	if(result == NULL)
		return NULL;

	for(i=0; i<6; i++) {
		result[i*2] = mac_addr[i*3];
		result[i*2+1] = mac_addr[i*3+1];
	}
	result[12] = '\0';

	return result;
}


void __connman_util_byte_to_string(unsigned char *src, char *dest, int len)
{
	int i=0;

	for(i=0; i<len; i++) {
		snprintf(&dest[i*2], 3, "%02x", src[i]);
	}

	dest[len*2] = '\0';
}

char *__connman_util_mac_binary_to_string(const unsigned char binmac[6]){
	return g_strdup_printf("%02x:%02x:%02x:%02x:%02x:%02x",
	                       binmac[0], binmac[1], binmac[2],
	                       binmac[3], binmac[4], binmac[5]);
}

char *__connman_util_mac_binary_to_string_no_colon(const unsigned char binmac[6]){
	return g_strdup_printf("%02x%02x%02x%02x%02x%02x",
	                       binmac[0], binmac[1], binmac[2],
	                       binmac[3], binmac[4], binmac[5]);
}

char *__connman_util_ipaddr_binary_to_string(const unsigned char addr[4]){
	return g_strdup_printf("%u.%u.%u.%u",
	                       addr[0], addr[1], addr[2], addr[3]);
}

static unsigned char char_to_hex_value(char c)
{
	c = toupper(c);

	if (c >= 'A')
		return c - 'A' + 10;
	else
		return c - '0';
}

static unsigned char char2_to_hex_value(const char c[2])
{
	return char_to_hex_value(c[0]) * 16 + char_to_hex_value(c[1]);
}

void __connman_util_mac_string_to_binary(const char* mac_string, unsigned char binmac[6])
{
	if (mac_string == NULL || strlen(mac_string) != 17)
		return;

	binmac[0] = char2_to_hex_value(mac_string);
	binmac[1] = char2_to_hex_value(mac_string+3);
	binmac[2] = char2_to_hex_value(mac_string+6);
	binmac[3] = char2_to_hex_value(mac_string+9);
	binmac[4] = char2_to_hex_value(mac_string+12);
	binmac[5] = char2_to_hex_value(mac_string+15);
}
