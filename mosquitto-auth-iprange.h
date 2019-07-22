#pragma once

#ifndef MOSQUITTO_AUTH_IPRANGE_H
#define MOSQUITTO_AUTH_IPRANGE_H

/* This comes from mosquitto_broker.h, which is not shipped in
 * any Ubuntu .deb, so we'll just copy it */
const char *mosquitto_client_address(const struct mosquitto *client);
void mosquitto_log_printf(int level, const char *fmt, ...);

#endif
