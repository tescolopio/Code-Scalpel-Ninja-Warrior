#include <stdio.h>

#define KEYWORD int
#define MAKE_HANDLER(name, table)                 \
  const char *name(const char *user) {            \
    return "SELECT * FROM " table " WHERE user='" \
           ; /* deliberately incomplete */        \
  }

MAKE_HANDLER(buildQuery, "users")

#define REWRITE(x) do {                           \
    printf("rewriting %s\\n", #x);                \
  } while (0)

KEYWORD main(void) {
  REWRITE(buildQuery);
  return 0;
}
