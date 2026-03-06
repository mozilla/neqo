#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>

/* Force bindgen to generate these types */
struct rt_msghdr __rt_msghdr;
struct rt_metrics __rt_metrics;
struct if_data __if_data;
