/*
 * Copyright (C) 2008, 2010 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General
 * Public License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330,
 * Boston, MA 02111-1307, USA.
 *
 * Author: David Zeuthen <davidz@redhat.com>
 */

#include "polkitagenthelperprivate.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <time.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#ifdef __FreeBSD__
#include <sys/procctl.h>
#endif
#include <security/pam_appl.h>

#include <polkit/polkit.h>

#ifndef SO_PEERPIDFD
#  if defined(__parisc__)
#    define SO_PEERPIDFD 0x404B
#  elif defined(__sparc__)
#    define SO_PEERPIDFD 0x0056
#  elif defined(__linux__)
#    define SO_PEERPIDFD 77
#  endif
#endif

/* The stack that talks to the agent, as before. */
#define PAM_SERVICE_NAME "polkit-1"

/* Optional. Runs alongside PAM_SERVICE_NAME for factors that take time rather
 * than input (fingerprint, smartcard), with a conversation that answers
 * nothing. Without this file the helper behaves exactly as before.
 */
#define PAM_SERVICE_NAME_CONCURRENT "polkit-1-concurrent"

/* Linux-PAM reads both, preferring /etc. */
static const char *pam_service_directories[] = { "/etc/pam.d", "/usr/lib/pam.d" };

/* Single byte written back by the concurrent child to report its verdict. */
#define CONCURRENT_VERDICT_SUCCESS 'y'

/* Lets the conversation stop waiting for the agent once the concurrent stack wins. */
typedef struct
{
  int verdict_fd;             /* read end of the child's pipe, -1 once done */
  gboolean concurrent_won;
} ConversationData;

/* The concurrent child's process group while the race runs, else 0. */
static volatile sig_atomic_t concurrent_group;

/* Signals that can end the helper mid-race. Agents cancel with SIGTERM, and
 * an agent that has gone raises SIGPIPE; either would otherwise orphan the
 * concurrent child, still holding the reader.
 */
static const int ending_signals[] = { SIGHUP, SIGINT, SIGPIPE, SIGQUIT, SIGTERM };

static int conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data);
static int null_conversation_function (int n, const struct pam_message **msg, struct pam_response **resp,
                                       void *data);

static void
send_to_helper (const gchar *str1,
                const gchar *str2)
{
  char *escaped;
  char *tmp2;
  size_t len2;

  tmp2 = g_strdup(str2);
  g_assert (tmp2 != NULL);
  len2 = strlen(tmp2);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s ' to stdout\n", str1);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s ", str1);

  if (len2 > 0 && tmp2[len2 - 1] == '\n')
    tmp2[len2 - 1] = '\0';
  escaped = g_strescape (tmp2, NULL);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing `%s' to stdout\n", escaped);
#endif /* PAH_DEBUG */
  fprintf (stdout, "%s", escaped);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: writing newline to stdout\n");
#endif /* PAH_DEBUG */
  fputc ('\n', stdout);
#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: flushing stdout\n");
#endif /* PAH_DEBUG */
  fflush (stdout);

  g_free (escaped);
  g_free (tmp2);
}

/* A won race fails the password stack on purpose, and libpam would then sleep
 * out the delay a module requested as if a password had been wrong. Skip it
 * for that case only; real failures sleep exactly what libpam would have.
 *
 * PAM_FAIL_DELAY is Linux-PAM's; OpenPAM imposes no delay of its own.
 */
#ifdef PAM_FAIL_DELAY
static void
fail_delay (int retval, unsigned usec, void *appdata)
{
  ConversationData *conversation_data = appdata;
  struct timespec remaining;

  if (conversation_data != NULL && conversation_data->concurrent_won)
    return;

  if (retval == PAM_SUCCESS || usec == 0)
    return;

  remaining.tv_sec = usec / 1000000;
  remaining.tv_nsec = (long) (usec % 1000000) * 1000;
  while (nanosleep (&remaining, &remaining) != 0 && errno == EINTR)
    ;
}
#endif /* PAM_FAIL_DELAY */

/* Authenticates @user_to_auth, checks the account unless @authenticate_only,
 * and confirms PAM authenticated that user. Both stacks go through here.
 */
static gboolean
authenticate_with_pam (const char *service,
                       const char *user_to_auth,
                       struct pam_conv *conversation,
                       gboolean authenticate_only)
{
  pam_handle_t *pam_h = NULL;
  const void *authed_user;
  gboolean authenticated = FALSE;
  int rc;

  rc = pam_start (service, user_to_auth, conversation, &pam_h);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_start failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  rc = pam_set_item (pam_h, PAM_RUSER, user_to_auth);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_set_item failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

#ifdef PAM_FAIL_DELAY
  /* See fail_delay. */
  rc = pam_set_item (pam_h, PAM_FAIL_DELAY, (const void *) fail_delay);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_set_item failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }
#endif

  /* is user really user? */
  rc = pam_authenticate (pam_h, 0);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_authenticate failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  /* permitted access? (For the concurrent stack: run_concurrent_account_check.) */
  if (!authenticate_only)
    {
      rc = pam_acct_mgmt (pam_h, 0);
      if (rc != PAM_SUCCESS)
        {
          fprintf (stderr, "polkit-agent-helper-1: pam_acct_mgmt failed: %s\n", pam_strerror (pam_h, rc));
          goto out;
        }
    }

  /* did we auth the right user? */
  rc = pam_get_item (pam_h, PAM_USER, &authed_user);
  if (rc != PAM_SUCCESS)
    {
      fprintf (stderr, "polkit-agent-helper-1: pam_get_item failed: %s\n", pam_strerror (pam_h, rc));
      goto out;
    }

  if (strcmp (authed_user, user_to_auth) != 0)
    {
      fprintf (stderr,
               "polkit-agent-helper-1: Tried to auth user '%s' but we got auth for user '%s' instead",
               user_to_auth, (const char *) authed_user);
      goto out;
    }

  authenticated = TRUE;

out:
  if (pam_h != NULL)
    pam_end (pam_h, rc);
  return authenticated;
}

/* Keeps debuggers out of this process. Returns FALSE where that is not
 * possible, and the concurrent stack then does not run.
 */
static gboolean
forbid_tracing (void)
{
#if defined(__linux__)
  return prctl (PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
#elif defined(__FreeBSD__)
  int disable = PROC_TRACE_CTL_DISABLE;

  return procctl (P_PID, getpid (), PROC_TRACE_CTL, &disable) == 0;
#else
  errno = ENOSYS;
  return FALSE;
#endif
}

/* Drops the concurrent child to @user_to_auth for good, before any module runs.
 *
 * As root, pam_fprintd asks fprintd to verify another user, which needs a
 * polkit authorization (setusername, auth_admin_keep) that only the agent
 * waiting on this very request could grant. As the user, verify is allowed.
 *
 * The drop cannot be undone and the process is non-dumpable: the child may
 * share the invoking user's uid, and must not be traceable into reporting
 * success. The account phase needs root, so it runs in the parent.
 */

static gboolean
become_user_for_good (const char *user_to_auth)
{
  struct passwd *pw = getpwnam (user_to_auth);
  uid_t ruid, euid, suid;
  gid_t rgid, egid, sgid;

  if (pw == NULL || pw->pw_uid == 0)
    {
      syslog (LOG_NOTICE, "no non-root user '%s' for %s", user_to_auth, PAM_SERVICE_NAME_CONCURRENT);
      return FALSE;
    }

  if (!forbid_tracing ())
    {
      syslog (LOG_NOTICE, "could not protect %s from tracing: %m", PAM_SERVICE_NAME_CONCURRENT);
      return FALSE;
    }

  if (initgroups (pw->pw_name, pw->pw_gid) != 0
      || setresgid (pw->pw_gid, pw->pw_gid, pw->pw_gid) != 0
      || setresuid (pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
    {
      syslog (LOG_NOTICE, "could not enter user context for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      return FALSE;
    }

  /* On Linux, setresuid resets dumpability to fs.suid_dumpable; set it again. */
  if (!forbid_tracing ()
      || getresuid (&ruid, &euid, &suid) != 0 || getresgid (&rgid, &egid, &sgid) != 0
      || ruid != pw->pw_uid || euid != pw->pw_uid || suid != pw->pw_uid
      || rgid != pw->pw_gid || egid != pw->pw_gid || sgid != pw->pw_gid
      || setuid (0) == 0 || seteuid (0) == 0)
    {
      syslog (LOG_NOTICE, "retained capabilities in user context for %s", PAM_SERVICE_NAME_CONCURRENT);
      return FALSE;
    }

  return TRUE;
}

/* The account phase of a concurrent win, as root in the parent, with
 * PAM_SERVICE_NAME_CONCURRENT's account rules.
 */
static gboolean
run_concurrent_account_check (const char *user_to_auth)
{
  struct pam_conv conversation = { null_conversation_function, NULL };
  pam_handle_t *pam_h = NULL;
  const void *checked_user = NULL;
  gboolean permitted = FALSE;
  int rc;

  rc = pam_start (PAM_SERVICE_NAME_CONCURRENT, user_to_auth, &conversation, &pam_h);
  if (rc == PAM_SUCCESS)
    rc = pam_set_item (pam_h, PAM_RUSER, user_to_auth);
  if (rc == PAM_SUCCESS)
    rc = pam_acct_mgmt (pam_h, 0);
  if (rc == PAM_SUCCESS)
    rc = pam_get_item (pam_h, PAM_USER, &checked_user);
  if (rc == PAM_SUCCESS && checked_user != NULL && strcmp (checked_user, user_to_auth) == 0)
    permitted = TRUE;
  else
    syslog (LOG_NOTICE, "concurrent PAM account check failed for '%s': %s",
            user_to_auth, pam_strerror (pam_h, rc));

  if (pam_h != NULL)
    pam_end (pam_h, rc);
  return permitted;
}

static gboolean
pam_service_exists (const char *service)
{
  gsize i;

  for (i = 0; i < G_N_ELEMENTS (pam_service_directories); i++)
    {
      char *path;
      gboolean found;

      path = g_build_filename (pam_service_directories[i], service, NULL);
      found = g_file_test (path, G_FILE_TEST_IS_REGULAR);
      g_free (path);

      if (found)
        return TRUE;
    }

  return FALSE;
}

/* Takes the concurrent stack down with the helper, then dies of the same
 * signal. Only async-signal-safe calls.
 */
static void
end_with_concurrent_stack (int signal_number)
{
  pid_t group = (pid_t) concurrent_group;

  if (group > 0)
    kill (-group, SIGKILL);

  signal (signal_number, SIG_DFL);
  raise (signal_number);
}

static gboolean
catch_ending_signals (void)
{
  struct sigaction action;
  gsize i;

  memset (&action, 0, sizeof action);
  action.sa_handler = end_with_concurrent_stack;
  sigemptyset (&action.sa_mask);
  for (i = 0; i < G_N_ELEMENTS (ending_signals); i++)
    sigaddset (&action.sa_mask, ending_signals[i]);

  for (i = 0; i < G_N_ELEMENTS (ending_signals); i++)
    if (sigaction (ending_signals[i], &action, NULL) != 0)
      return FALSE;

  return TRUE;
}

/* Kills this process when @parent dies, SIGKILL included. Set after the
 * credential change, which clears it on Linux. Best effort.
 */
static void
die_with_parent (pid_t parent)
{
#if defined(__linux__)
  if (prctl (PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0)
    syslog (LOG_NOTICE, "could not tie %s to the helper: %m", PAM_SERVICE_NAME_CONCURRENT);
#elif defined(__FreeBSD__)
  int signal_number = SIGKILL;

  if (procctl (P_PID, 0, PROC_PDEATHSIG_CTL, &signal_number) != 0)
    syslog (LOG_NOTICE, "could not tie %s to the helper: %m", PAM_SERVICE_NAME_CONCURRENT);
#endif

  /* The parent may have gone before the setting took. */
  if (getppid () != parent)
    _exit (1);
}

/* Forks a child running PAM_SERVICE_NAME_CONCURRENT and returns the read end of
 * its verdict pipe, or -1 if that stack is not configured.
 *
 * A process rather than a thread: PAM is not thread-safe, and a wedged module
 * must be killable. The child never touches the agent's stdin or stdout, so
 * the agent protocol is unchanged.
 */
static int
start_concurrent_authentication (const char *user_to_auth,
                                 pid_t *out_child)
{
  struct pam_conv conversation;
  int pipe_fds[2];
  pid_t parent = getpid ();
  pid_t child;
  int devnull;
  char verdict;

  *out_child = -1;

  if (!pam_service_exists (PAM_SERVICE_NAME_CONCURRENT))
    return -1;

  /* Before the fork, so no child can outlive a cancelled request. */
  if (!catch_ending_signals ())
    {
      syslog (LOG_NOTICE, "could not catch signals for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      return -1;
    }

  /* Close-on-exec: nothing either stack executes may see the verdict pipe. */
  if (pipe2 (pipe_fds, O_CLOEXEC) != 0)
    {
      syslog (LOG_NOTICE, "could not create pipe for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      return -1;
    }

  child = fork ();
  if (child < 0)
    {
      syslog (LOG_NOTICE, "could not fork for %s: %m", PAM_SERVICE_NAME_CONCURRENT);
      close (pipe_fds[0]);
      close (pipe_fds[1]);
      return -1;
    }

  if (child > 0)
    {
      close (pipe_fds[1]);
      /* Also done in the child; whichever runs first wins. */
      setpgid (child, child);
      concurrent_group = child;
      *out_child = child;
      return pipe_fds[0];
    }

  /* Child. Keep the concurrent stack off the agent's descriptors. */
  close (pipe_fds[0]);

  /* Its own process group, so losing the race also kills anything it started. */
  setpgid (0, 0);

  devnull = open ("/dev/null", O_RDWR);
  if (devnull >= 0)
    {
      dup2 (devnull, STDIN_FILENO);
      dup2 (devnull, STDOUT_FILENO);
      if (devnull > STDERR_FILENO)
        close (devnull);
    }

  conversation.conv = null_conversation_function;
  conversation.appdata_ptr = NULL;

  if (!become_user_for_good (user_to_auth))
    {
      verdict = 'n';
      if (write (pipe_fds[1], &verdict, 1) != 1)
        _exit (1);
      _exit (1);
    }

  die_with_parent (parent);

  /* The previous request's child, killed mid-verify, can hold the reader for
   * a moment longer, so this one fails with "already claimed". A failure
   * within a second cannot be a finger being refused: retry it, boundedly.
   */
  {
    int attempt;

    for (attempt = 0; ; attempt++)
      {
        struct timespec begin, end;
        long took_ms;

        clock_gettime (CLOCK_MONOTONIC, &begin);
        verdict = authenticate_with_pam (PAM_SERVICE_NAME_CONCURRENT, user_to_auth,
                                         &conversation, TRUE /* authenticate only */)
                  ? CONCURRENT_VERDICT_SUCCESS : 'n';
        clock_gettime (CLOCK_MONOTONIC, &end);

        took_ms = (end.tv_sec - begin.tv_sec) * 1000
                + (end.tv_nsec - begin.tv_nsec) / 1000000;

        if (verdict == CONCURRENT_VERDICT_SUCCESS || took_ms > 1000 || attempt >= 5)
          break;

        {
          struct timespec pause = { 0, 300 * 1000 * 1000 };
          while (nanosleep (&pause, &pause) != 0 && errno == EINTR)
            ;
        }
      }
  }

  /* A short write or a dead parent both mean nobody is listening any more. */
  if (write (pipe_fds[1], &verdict, 1) != 1)
    _exit (1);

  _exit (verdict == CONCURRENT_VERDICT_SUCCESS ? 0 : 1);
}

static void
stop_concurrent_authentication (pid_t child,
                                int verdict_fd)
{
  if (verdict_fd >= 0)
    close (verdict_fd);

  if (child <= 0)
    return;

  concurrent_group = 0;

  /* SIGKILL: a module may have installed its own SIGTERM handler. */
  if (kill (-child, SIGKILL) != 0 && errno == ESRCH)
    kill (child, SIGKILL);
  while (waitpid (child, NULL, 0) < 0 && errno == EINTR)
    ;
}

static gboolean
reset_signal_state (void)
{
  struct sigaction defaults;
  sigset_t nothing;
  int signal_number;

  memset (&defaults, 0, sizeof defaults);
  defaults.sa_handler = SIG_DFL;
  sigemptyset (&defaults.sa_mask);

  for (signal_number = 1; signal_number < NSIG; signal_number++)
    {
      if (signal_number == SIGKILL || signal_number == SIGSTOP)
        continue;
      /* Reserved numbers (glibc's) refuse with EINVAL. */
      if (sigaction (signal_number, &defaults, NULL) != 0 && errno != EINVAL)
        return FALSE;
    }

  sigemptyset (&nothing);
  return sigprocmask (SIG_SETMASK, &nothing, NULL) == 0;
}

int
main (int argc, char *argv[])
{
  int rc;
  int pidfd = -1;
  int uid = -1;
  int errval = 1;
  const char *user_to_auth;
  char *user_to_auth_free = NULL;
  char *cookie = NULL;
  struct pam_conv pam_conversation;
  ConversationData conversation_data = { -1, FALSE };
  pid_t concurrent_child = -1;

  rc = 0;

  /* Dispositions and the mask are inherited from the invoker. An ignored
   * SIGCHLD would let the concurrent child reap itself, and the kill that ends
   * the race could then hit a reused pid.
   */
  if (!reset_signal_state ())
    {
      fprintf (stderr, "polkit-agent-helper-1: could not install helper signal handlers\n");
      goto error;
    }

  char *lang = getenv("LANG");
  char *language = getenv("LANGUAGE");
  char *lc_messages = getenv("LC_MESSAGES");

  /* clear the entire environment to avoid attacks using with libraries honoring environment variables */
  if (_polkit_clearenv () != 0)
    goto error;

  /* set a minimal environment */
  setenv ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);

  if(lang)
      setenv("LANG",lang,0);
  if(language)
      setenv("LANGUAGE",language,0);
  if(lc_messages)
      setenv("LC_MESSAGES",lc_messages,0);

  /* check that we are setuid root */
  if (geteuid () != 0)
    {
      gchar *s;

      fprintf (stderr, "polkit-agent-helper-1: needs to be setuid root\n");

      /* Special-case a very common error triggered in jhbuild setups */
      s = g_strdup_printf ("Incorrect permissions on %s (needs to be setuid root)", argv[0]);
      send_to_helper ("PAM_ERROR_MSG", s);
      g_free (s);
      goto error;
    }

  openlog ("polkit-agent-helper-1", LOG_CONS | LOG_PID, LOG_AUTHPRIV);

  /* check for correct invocation */
  if (!(argc == 2 || argc == 3))
    {
      syslog (LOG_NOTICE, "inappropriate use of helper, wrong number of arguments [uid=%d]", getuid ());
      fprintf (stderr, "polkit-agent-helper-1: wrong number of arguments. This incident has been logged.\n");
      goto error;
    }

#ifdef SO_PEERPIDFD
  /* We are socket activated and the socket has been set up as stdio/stdout, read user from it */
  if (argv[1] != NULL && strcmp (argv[1], "--socket-activated") == 0)
    {
      socklen_t socklen = sizeof(int);
#ifdef SO_PEERCRED
      struct ucred ucred;
#endif

      user_to_auth_free = read_cookie (argc, argv);
      if (!user_to_auth_free)
        goto error;
      user_to_auth = user_to_auth_free;

      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERPIDFD, &pidfd, &socklen);
      if (rc < 0)
        {
          if (errno == ENOPROTOOPT || errno == ENODATA)
            {
              syslog (LOG_ERR, "Pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper");
              fprintf (stderr, "polkit-agent-helper-1: pidfd not supported on this platform, disable polkit-agent-helper.socket and use setuid helper.\n");
            }
          if (errno == EINVAL)
            {
              syslog (LOG_ERR, "Caller already exited, unable to get pidfd");
              fprintf (stderr, "polkit-agent-helper-1: caller already exited, unable to get pidfd.\n");
            }

          goto error;
        }

#ifdef SO_PEERCRED
      socklen = sizeof(ucred);
      rc = getsockopt(STDIN_FILENO, SOL_SOCKET, SO_PEERCRED, &ucred, &socklen);
#else
      rc = -1;
#endif
      if (rc < 0)
        {
          syslog (LOG_ERR, "Unable to get credentials from socket");
          fprintf (stderr, "polkit-agent-helper-1: unable to get credentials from socket.\n");
          goto error;
        }

#ifdef SO_PEERCRED
      uid = ucred.uid;
#endif
    }
  else
#endif
    user_to_auth = argv[1];

  cookie = read_cookie (argc, argv);
  if (!cookie)
    goto error;

  if (getuid () != 0)
    {
      /* check we're running with a non-tty stdin */
      if (isatty (STDIN_FILENO) != 0)
        {
          syslog (LOG_NOTICE, "inappropriate use of helper, stdin is a tty [uid=%d]", getuid ());
          fprintf (stderr, "polkit-agent-helper-1: inappropriate use of helper, stdin is a tty. This incident has been logged.\n");
          goto error;
        }
    }

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: user to auth is '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

  pam_conversation.conv        = conversation_function;
  pam_conversation.appdata_ptr = &conversation_data;

  /* PAM conversations are serial, so a factor that needs no input runs as a
   * second stack beside the one that talks to the agent.
   */
  conversation_data.verdict_fd = start_concurrent_authentication (user_to_auth, &concurrent_child);

  if (!authenticate_with_pam (PAM_SERVICE_NAME, user_to_auth, &pam_conversation, FALSE) &&
      !(conversation_data.concurrent_won && run_concurrent_account_check (user_to_auth)))
    {
      /* if run via systemd socket, failed authentication won't taint the system using SuccessExitStatus=2*/
      errval = 2;
      goto error;
    }

  stop_concurrent_authentication (concurrent_child, conversation_data.verdict_fd);
  concurrent_child = -1;
  conversation_data.verdict_fd = -1;

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully authenticated user '%s'.\n", user_to_auth);
#endif /* PAH_DEBUG */

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  /* now send a D-Bus message to the PolicyKit daemon that
   * includes a) the cookie; b) the user we authenticated;
   * c) the pidfd and uid of the caller, if socket-activated
   */
  if (!send_dbus_message (cookie, user_to_auth, pidfd, uid))
    {
#ifdef PAH_DEBUG
      fprintf (stderr, "polkit-agent-helper-1: error sending D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */
      goto error;
    }

  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);

#ifdef PAH_DEBUG
  fprintf (stderr, "polkit-agent-helper-1: successfully sent D-Bus message to PolicyKit daemon\n");
#endif /* PAH_DEBUG */

  fprintf (stdout, "SUCCESS\n");
  flush_and_wait();
  return 0;

error:
  free (cookie);
  free (user_to_auth_free);
  if (pidfd >= 0)
    close (pidfd);
  stop_concurrent_authentication (concurrent_child, conversation_data.verdict_fd);

  fprintf (stdout, "FAILURE\n");
  flush_and_wait();
  return errval;
}

static int
conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  char buf[PAM_MAX_RESP_SIZE];
  int i;

  ConversationData *conversation_data = data;

  /* The concurrent stack has won. A module that shrugs off the aborted prompt
   * would pass the stack to the next one, which would ask the agent for a
   * password nobody will give; refuse every further prompt instead.
   */
  if (conversation_data != NULL && conversation_data->concurrent_won)
    return PAM_CONV_ERR;

  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return PAM_CONV_ERR;

  if ((aresp = calloc(n, sizeof *aresp)) == NULL)
    return PAM_BUF_ERR;

  for (i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;
      switch (msg[i]->msg_style)
        {

        case PAM_PROMPT_ECHO_OFF:
          send_to_helper ("PAM_PROMPT_ECHO_OFF", msg[i]->msg);
          goto conv1;

        case PAM_PROMPT_ECHO_ON:
          send_to_helper ("PAM_PROMPT_ECHO_ON", msg[i]->msg);

        conv1:
          /* Wait for the agent, or for the concurrent stack's verdict. */
          for (;;)
            {
              gboolean concurrent_ready = FALSE;
              int verdict_fd = conversation_data != NULL ? conversation_data->verdict_fd : -1;
              char verdict;

              int line = read_line_from_agent (buf, sizeof buf, verdict_fd, &concurrent_ready);

              if (line == 1)
                break;

              if (!concurrent_ready)
                {
                  syslog (LOG_NOTICE, "no answer from the agent: %s",
                          line == 0 ? "it closed the connection" : strerror (errno));
                  goto error;
                }

              /* Success ends the request. Failure leaves this prompt the only way
               * through: stop watching and keep waiting.
               */
              if (read (verdict_fd, &verdict, 1) == 1 && verdict == CONCURRENT_VERDICT_SUCCESS)
                {
                  conversation_data->concurrent_won = TRUE;
                  goto error;
                }

              close (verdict_fd);
              conversation_data->verdict_fd = -1;
            }

          aresp[i].resp = strdup (buf);
          explicit_bzero (buf, sizeof buf);
          if (aresp[i].resp == NULL)
            {
              syslog (LOG_NOTICE, "out of memory holding the agent's answer");
              goto error;
            }
          break;

        case PAM_ERROR_MSG:
          send_to_helper ("PAM_ERROR_MSG", msg[i]->msg);
          break;

        case PAM_TEXT_INFO:
          send_to_helper ("PAM_TEXT_INFO", msg[i]->msg);
          break;

        default:
          syslog (LOG_NOTICE, "the stack asked something this helper cannot relay "
                  "(message style %d)", msg[i]->msg_style);
          goto error;
        }
    }

  *resp = aresp;
  return PAM_SUCCESS;

error:

  for (i = 0; i < n; ++i)
    {
      if (aresp[i].resp != NULL) {
        memset (aresp[i].resp, 0, strlen(aresp[i].resp));
        free (aresp[i].resp);
      }
    }
  memset (aresp, 0, n * sizeof *aresp);
  free (aresp);
  *resp = NULL;
  return PAM_CONV_ERR;
}

/* The concurrent stack's conversation. Nothing can be answered, so a module
 * that prompts simply loses the race.
 */
static int
null_conversation_function (int n, const struct pam_message **msg, struct pam_response **resp, void *data)
{
  struct pam_response *aresp;
  int i;

  (void)data;
  if (n <= 0 || n > PAM_MAX_NUM_MSG)
    return PAM_CONV_ERR;

  if ((aresp = calloc (n, sizeof *aresp)) == NULL)
    return PAM_BUF_ERR;

  for (i = 0; i < n; ++i)
    {
      aresp[i].resp_retcode = 0;
      aresp[i].resp = NULL;

      switch (msg[i]->msg_style)
        {
        case PAM_ERROR_MSG:
        case PAM_TEXT_INFO:
          /* Dropped: they belong to no conversation the agent can see. */
          break;

        default:
          free (aresp);
          *resp = NULL;
          return PAM_CONV_ERR;
        }
    }

  *resp = aresp;
  return PAM_SUCCESS;
}
