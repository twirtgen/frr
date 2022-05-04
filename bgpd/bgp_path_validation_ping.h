//
// Created by thomas on 4/05/22.
//

#ifndef FRR_DATAPLANE_BGP_PATH_VALIDATION_PING_H
#define FRR_DATAPLANE_BGP_PATH_VALIDATION_PING_H

#include <netinet/in.h>

/**
 * Send an ICMP packet and wait for the response.
 * @param ping_addr sockaddr structure
 * @param timeout_us the time in microseconds to wait the response
 * @param retries number of retries
 * @return  0 if the address is pingable
 *         -1 if error or not pingable
 */
int send_ping(struct sockaddr_in *ping_addr, int timeout_us, int retries);

#endif // FRR_DATAPLANE_BGP_PATH_VALIDATION_PING_H
