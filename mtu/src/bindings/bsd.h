#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
#include <net/if.h>

/* Force bindgen to generate these types. Bindgen only emits Rust types for C
 * types it sees actually used in the translation unit; including the headers
 * alone is not enough. These dummy variable declarations cause bindgen to emit
 * the corresponding Rust types. The variables are never used at runtime. */
struct rt_msghdr __rt_msghdr;
struct rt_metrics __rt_metrics;
struct if_data __if_data;
