#ifndef __AIDP__H
#define __AIDP__H

#define AIDP_DISCOVER_REQUEST             0x01
#define AIDP_TEST_IP_REQUEST              0x02
#define AIDP_SET_IP_REQUEST               0x03
#define AIDP_DISCOVER_REPLY               0x81

struct aidp_disc_info {
   uint8_t model;
   uint8_t mac[6];
   uint8_t ip[4];
   uint8_t mask[4];
   uint8_t gw[4];
};

#endif /* __AIDP__H */
