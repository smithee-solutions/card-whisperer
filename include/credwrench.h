// definitions for cardwhisperer credwrench

// actions
#define CSHH_CREDWRENCH_CHALLENGE     ( 1)
#define CSHH_CREDWRENCH_HASHALG       ( 2)
#define CSHH_CREDWRENCH_HELP          ( 3)
#define CSHH_CREDWRENCH_MESSAGE       ( 4)
#define CSHH_CREDWRENCH_RESPONSE_DUMP ( 5)
#define CSHH_CREDWRENCH_VERBOSITY     ( 6)
#define CSHH_CREDWRENCH_STATIC        ( 7)

typedef struct cshh_credwrench_options
{
  int wrench_operation; // command we're executing (like "challenge")
  int action;
  int io_enable; // 0 for no smartcard operations, 1 for PCSC operations
  int message_size;
  int key_size;
} CSHH_CREDWRENCH_OPTIONS;

int cshh_credwrench_init_command_line
  (CSHH_CONTEXT *ctx,
  CSHH_CREDWRENCH_OPTIONS *options,
  int argc,
  char *argv []);

