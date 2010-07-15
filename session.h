#ifndef _ASMP_SES
#define _ASMP_SES

#include "asmp.h"

int asmp_request(struct asmp_cfg *cfg, uint8_t cmd, uint32_t len, const uint8_t *data);

#endif
