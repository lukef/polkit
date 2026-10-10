/* An in-process stand-in for pam_fprintd, for the concurrent-stack suite.
 *
 *   auth required /path/pam_test_finger.so trace=FILE delay_ms=N result=0|1 [grandchild] [prompt]
 *
 * Records its uid, pid, parent and dumpability to FILE, optionally forks a
 * grandchild that sleeps (staying in the caller's process group, unlike
 * pam_exec, which calls setsid), optionally asks the conversation something,
 * sleeps, and returns success or failure.
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/prctl.h>

static void
trace (const char *path, const char *fmt, ...)
{
  FILE *f;
  va_list ap;

  if (path == NULL || (f = fopen (path, "a")) == NULL)
    return;
  va_start (ap, fmt);
  vfprintf (f, fmt, ap);
  va_end (ap);
  fputc ('\n', f);
  fclose (f);
}

int
pam_sm_authenticate (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  const char *path = NULL;
  long delay_ms = 0;
  int result = 0, grandchild = 0, prompt = 0, i;
  long faildelay_ms = 0;
  char sigign[32] = "?", sigblk[32] = "?";
  struct timespec ts;

  (void) flags;
  for (i = 0; i < argc; i++)
    {
      if (strncmp (argv[i], "trace=", 6) == 0)
        path = argv[i] + 6;
      else if (strncmp (argv[i], "delay_ms=", 9) == 0)
        delay_ms = atol (argv[i] + 9);
      else if (strncmp (argv[i], "result=", 7) == 0)
        result = atoi (argv[i] + 7);
      else if (strcmp (argv[i], "grandchild") == 0)
        grandchild = 1;
      else if (strcmp (argv[i], "prompt") == 0)
        prompt = 1;
      else if (strncmp (argv[i], "faildelay_ms=", 13) == 0)
        faildelay_ms = atol (argv[i] + 13);
    }

  /* Inherited signal state, as the kernel sees it. */
  {
    FILE *status = fopen ("/proc/self/status", "r");
    char line[256];

    while (status != NULL && fgets (line, sizeof line, status) != NULL)
      {
        if (strncmp (line, "SigIgn:", 7) == 0)
          sscanf (line + 7, "%31s", sigign);
        else if (strncmp (line, "SigBlk:", 7) == 0)
          sscanf (line + 7, "%31s", sigblk);
      }
    if (status != NULL)
      fclose (status);
  }

  /* As pam_unix does after a wrong password, but before asking anything. */
  if (faildelay_ms > 0)
    pam_fail_delay (pamh, (unsigned int) (faildelay_ms * 1000));

  trace (path, "start uid=%d euid=%d pid=%d ppid=%d pgid=%d dumpable=%d sigign=%s sigblk=%s",
         (int) getuid (), (int) geteuid (), (int) getpid (), (int) getppid (),
         (int) getpgrp (), prctl (PR_GET_DUMPABLE, 0, 0, 0, 0), sigign, sigblk);

  if (grandchild)
    {
      pid_t pid = fork ();
      if (pid == 0)
        {
          execl ("/bin/sleep", "sleep", "300", (char *) NULL);
          _exit (127);
        }
      trace (path, "grandchild %d", (int) pid);
    }

  if (prompt)
    {
      char *resp = NULL;
      int rc = pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &resp, "finger module asks: ");
      trace (path, "prompt rc=%d", rc);
      free (resp);
      if (rc != PAM_SUCCESS)
        return PAM_AUTH_ERR;
    }

  ts.tv_sec = delay_ms / 1000;
  ts.tv_nsec = (delay_ms % 1000) * 1000000L;
  while (nanosleep (&ts, &ts) != 0)
    ;

  trace (path, "finish result=%d", result);
  return result == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}

int
pam_sm_setcred (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  (void) pamh; (void) flags; (void) argc; (void) argv;
  return PAM_SUCCESS;
}
