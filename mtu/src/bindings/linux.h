#include <linux/rtnetlink.h>

/* Force bindgen to generate these types. Bindgen only emits Rust types for C
 * types it sees actually used in the translation unit; including the headers
 * alone is not enough. These dummy variable declarations cause bindgen to emit
 * the corresponding Rust types. The variables are never used at runtime. */
struct nlmsghdr __nlmsghdr;
struct rtattr __rtattr;
struct rtmsg __rtmsg;
struct ifinfomsg __ifinfomsg;
