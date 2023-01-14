/* Many parts of this proof-of-concept use the following example as a template:
 *
 * https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/samples/landlock/sandboxer.c
 *
 * Other information about landlock was found here:
 *
 * https://docs.kernel.org/userspace-api/landlock.html
*/

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/landlock.h>
#include <linux/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <unistd.h>

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *const attr,
      const size_t size, const __u32 flags)
{
  return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
            const enum landlock_rule_type rule_type,
            const void *const rule_attr,
            const __u32 flags)
{
  return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type, rule_attr,
           flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
           const __u32 flags)
{
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

#define LANDLOCK_ABI_LAST 3

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER      (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE   (1ULL << 14)
#endif

#define ACCESS_FILE ( \
  LANDLOCK_ACCESS_FS_EXECUTE | \
  LANDLOCK_ACCESS_FS_WRITE_FILE | \
  LANDLOCK_ACCESS_FS_READ_FILE)

#define ACCESS_FS_ROUGHLY_READ ( \
  LANDLOCK_ACCESS_FS_EXECUTE | \
  LANDLOCK_ACCESS_FS_READ_FILE | \
  LANDLOCK_ACCESS_FS_READ_DIR)

#define ACCESS_FS_ROUGHLY_WRITE ( \
  LANDLOCK_ACCESS_FS_WRITE_FILE | \
  LANDLOCK_ACCESS_FS_REMOVE_DIR | \
  LANDLOCK_ACCESS_FS_REMOVE_FILE | \
  LANDLOCK_ACCESS_FS_MAKE_CHAR | \
  LANDLOCK_ACCESS_FS_MAKE_DIR | \
  LANDLOCK_ACCESS_FS_MAKE_REG | \
  LANDLOCK_ACCESS_FS_MAKE_SOCK | \
  LANDLOCK_ACCESS_FS_MAKE_FIFO | \
  LANDLOCK_ACCESS_FS_MAKE_BLOCK | \
  LANDLOCK_ACCESS_FS_MAKE_SYM | \
  LANDLOCK_ACCESS_FS_REFER | \
  LANDLOCK_ACCESS_FS_TRUNCATE)

int apply_landlock_rule(const int ruleset_fd, const char* path, __u64 access) {
  struct landlock_path_beneath_attr beneath_attr;

  // Try to open file and apply landlock rule
  beneath_attr.parent_fd = open(path, O_PATH | O_CLOEXEC);
  if (beneath_attr.parent_fd < 0) {
    fprintf(stderr, "Failed to open file %s: %i\n", path, errno);
    return 1;
  }

  // Get file stat to determine what permissions to set
  struct stat statbuf;
  if (fstat(beneath_attr.parent_fd, &statbuf)) {
    fprintf(stderr, "Failed to get stat for file %s: %i\n", path, errno);
    close(beneath_attr.parent_fd);
    return 1;
  }

  // Set permissions depending on whether it's a file or a directory
  beneath_attr.allowed_access = access;
  if (!S_ISDIR(statbuf.st_mode)) {
    beneath_attr.allowed_access &= ACCESS_FILE;
  }

  // Add ruleset for this device file
  if (landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &beneath_attr, 0)) {
    fprintf(stderr, "Failed to add ruleset to file %s: %i\n", path, errno);
    close(beneath_attr.parent_fd);
    return 1;
  }
  close(beneath_attr.parent_fd);

  return 0;
}

void usage() {
    fprintf(stderr, "SimpleJail v0.1.0\n");
    fprintf(stderr, "Usage: sjail [OPTIONS] ALLOWED_FILES ... -c COMMAND [ARGS ...]\n");
    fprintf(stderr, "  Make sure that the '-c' flag is included before the sub-command\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -v  Print debug statements\n");
}

int main(int argc, char* argv[], char* const* const envp) {
  // Exit if there are not enough arguments to parse
  if (argc < 4) {
    usage();
    return 1;
  }

  // Search for flags
  int command_flag_found = 0;
  int verbose = 0;
  for (int i = 0; i < argc - 1; ++i) {
    if (command_flag_found == 0 && strncmp(argv[i], "-c", 2) == 0) {
      command_flag_found = 1;
    }
    if (verbose == 0 && strncmp(argv[i], "-v", 2) == 0) {
      verbose = i;
    }
  }

  // Exit if there is no '-c' flag (excluding the last argument)
  if (command_flag_found == 0) {
    usage();
    return 1;
  }

  // Ensure landlock is supported
  int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (abi < 0) {
    const int err = errno;

    perror("Failed to check Landlock compatibility");
    switch (err) {
    case ENOSYS:
      fprintf(stderr,
          "Hint: Landlock is not supported by the current kernel. "
          "To support it, build the kernel with "
          "CONFIG_SECURITY_LANDLOCK=y and prepend "
          "\"landlock,\" to the content of CONFIG_LSM.\n");
      break;
    case EOPNOTSUPP:
      fprintf(stderr,
          "Hint: Landlock is currently disabled. "
          "It can be enabled in the kernel configuration by "
          "prepending \"landlock,\" to the content of CONFIG_LSM, "
          "or at boot time by setting the same content to the "
          "\"lsm\" kernel parameter.\n");
      break;
    }
    return 1;
  }
  if (verbose) {
    printf("Landlock ABI version: %i\n", abi);
  }

  // Set up ruleset struct
  struct landlock_ruleset_attr ruleset_attr = {
    .handled_access_fs = ACCESS_FS_ROUGHLY_READ | ACCESS_FS_ROUGHLY_WRITE
  };
  int rough_read = ACCESS_FS_ROUGHLY_READ;
  int rough_write = ACCESS_FS_ROUGHLY_WRITE;

  // Disable features that are not supported
  switch (abi) {
  case 1:
    /* Removes LANDLOCK_ACCESS_FS_REFER for ABI < 2 */
    ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
    __attribute__((fallthrough));
  case 2:
    /* Removes LANDLOCK_ACCESS_FS_TRUNCATE for ABI < 3 */
    ruleset_attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;
    if (verbose) {
      fprintf(stderr,
        "Hint: You should update the running kernel "
        "to leverage Landlock features "
        "provided by ABI version %d (instead of %d).\n",
        LANDLOCK_ABI_LAST, abi);
    }
    __attribute__((fallthrough));
  case LANDLOCK_ABI_LAST:
    break;
  default:
    if (verbose) {
      fprintf(stderr,
        "Hint: You should update this program "
        "to leverage Landlock features "
        "provided by ABI version %d (instead of %d).\n",
        abi, LANDLOCK_ABI_LAST);
    }
  }
  rough_read &= ruleset_attr.handled_access_fs;
  rough_write &= ruleset_attr.handled_access_fs;

  // Create ruleset for landlock
  int ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
  if (ruleset_fd < 0) {
    perror("Failed to create a ruleset");
    return 1;
  }

  // Restrict privileges of this thread and its children
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("Failed to fully restrict privileges with prctl");
    close(ruleset_fd);
    return 1;
  }

  // Restrict entire file system to read only
  if (apply_landlock_rule(ruleset_fd, "/", rough_read) != 0) {
    close(ruleset_fd);
    return 1;
  }

  // Loop through each command line argument until the '-c' flag
  int sub_cmd_start = 0;
  for (int i = 1; i < argc - 1; ++i) {
    if (strncmp(argv[i], "-c", 2) == 0) {
      // Record where the sub-command starts
      sub_cmd_start = i + 1;
      break;
    } else if (i == verbose) {
      continue;
    }

    // Allow writes only to devices marked as allowed
    const char* path = argv[i];
    if (verbose) {
      printf("Allowing writes to %s\n", path);
    }
    apply_landlock_rule(ruleset_fd, path, rough_write | rough_read);
  }

  // Restrict this thread to the landlock rules that were just created
  if (landlock_restrict_self(ruleset_fd, 0)) {
    perror("Failed to enforce ruleset");
    close(ruleset_fd);
    return 1;
  }
  close(ruleset_fd);

  // Run the sub-command with the previous landlock restrictions applied
  const char* sub_cmd = argv[sub_cmd_start];
  if (verbose) {
    printf("Running %s\n", sub_cmd);
  }
  execve(sub_cmd, &argv[sub_cmd_start], envp);

  // This shouldn't run if the sub-command ran properly
  fprintf(stderr, "Failed to execute %s: %i\n", sub_cmd, errno);
  return 1;
}
