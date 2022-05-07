//
// Created by thomas on 26/04/22.
//

#ifndef FRR_DATAPLANE_BGP_PATH_VALIDATION_H
#define FRR_DATAPLANE_BGP_PATH_VALIDATION_H


#include "lib/thread.h"

enum path_validation_states {
	PATH_VALIDATION_NOT_BEING_USED,
	PATH_VALIDATION_VALID,
	PATH_VALIDATION_PENDING,
	PATH_VALIDATION_INVALID,
	PATH_VALIDATION_NOT_REQUESTED,
};


int bgp_path_validation_init(struct thread_master *master);

void bgp_path_validation_run(void);

#endif // FRR_DATAPLANE_BGP_PATH_VALIDATION_H
