/*
 * mr-peercred-gate (R43-P2-4): run by systemd for each accepted connection on /run/mr-piv/sign.sock
 * (Accept=yes, StandardInput=socket). Checks SO_PEERCRED on fd 0: the peer uid must equal argv[1]
 * (mr-signer's uid). On success it execs argv[2..] (mr-piv-sign --stdio) with the socket still on fd 0/1;
 * otherwise it exits 77 without reading a byte. No libraries beyond libc; no environment is used.
 * Build: cc -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -o mr-peercred-gate peercred-gate.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 3) { fprintf(stderr, "usage: mr-peercred-gate <uid> <cmd> [args...]\n"); return 64; }
  char *end = NULL;
  errno = 0;
  unsigned long want = strtoul(argv[1], &end, 10);
  if (errno || !end || *end || argv[1][0] == '\0' || argv[1][0] == '-') { fprintf(stderr, "bad uid\n"); return 64; }
  struct ucred cr;
  socklen_t len = sizeof cr;
  memset(&cr, 0, sizeof cr);
  if (getsockopt(0, SOL_SOCKET, SO_PEERCRED, &cr, &len) != 0 || len != sizeof cr) { fprintf(stderr, "no peer credentials\n"); return 77; }
  if ((unsigned long)cr.uid != want) { fprintf(stderr, "peer uid %lu refused\n", (unsigned long)cr.uid); return 77; }
  execv(argv[2], &argv[2]);
  fprintf(stderr, "exec failed\n");
  return 71;
}
