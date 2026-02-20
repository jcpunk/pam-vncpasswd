/**
 * pam/pam_entry.c - PAM module entry points
 *
 * Thin glue layer bridging the PAM API to the core logic in auth.c.
 * Extracts username and password from the PAM handle, then calls
 * authenticate_vnc_user().
 *
 * PAM headers are pulled in via auth.h.
 *
 * ALL SIX pam_sm_* ENTRY POINTS ARE REQUIRED.  Linux-PAM resolves them by
 * symbol name at dlopen time based on which service types appear in
 * /etc/pam.d/.  A missing symbol causes dlsym failure and breaks the entire
 * auth stack.  The "pam_sm_*" defines above tell pam_modules.h to declare the
 * corresponding prototypes, omitting them for unused types would produce
 * implicit-declaration warnings, the stubs themselves must still exist.
 *
 * Recommended PAM stack configuration for VNC password file with fallback
 * to pam_unix.so, etc:
 *
 * ----
 * auth [success=done authinfo_unavail=ignore default=die] \
 * pam_fnal_vncpasswd.so
 * auth sufficient pam_unix.so
 * ----
 *
 * authinfo_unavail=ignore: skip to the next module when the user has no VNC
 * password file, allowing the next module(s) (pam_unix) to handle the attempt.
 *
 * success=done: short-circuit the stack on successful VNC authentication;
 * pam_unix is not consulted.
 *
 * default=die: any other failure (PAM_AUTH_ERR, PAM_USER_UNKNOWN, etc.)
 * terminates the stack immediately without falling through to pam_unix.
 * This prevents an attacker from deliberately triggering an error condition
 * to bypass a VNC password that is present.
 *
 * Do NOT use 'sufficient' in place of the bracket syntax: sufficient treats
 * PAM_AUTHINFO_UNAVAIL as failure and will not fall through to pam_unix.
 */

#include <syslog.h>

#include "auth.h"
#include "autoconf.h"
#include "syscall_ops.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  const char *username = NULL;
  const char *authtok = NULL;
  struct pam_args args = make_pam_args();

  (void)flags;

  parse_pam_args(argc, argv, &args);

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get username");
    return PAM_AUTH_ERR;
  }

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS ||
      !authtok) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get password");
    return PAM_AUTH_ERR;
  }

  return authenticate_vnc_user(&syscall_ops_default, pamh, username, authtok,
                               args.debug);
}

/*
 * This module manages no credentials.
 *
 * PAM_IGNORE tells the PAM stack that setcred is not applicable here,
 * which is correct and avoids interfering with stacked modules that
 * inspect setcred return values.
 *
 * PAM_PERM_DENIED tells the PAM stack that a permissions error prevents
 * changing the password.
 *
 * PAM_SUCCESS would falsely signal behavior we don't support.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  (void)flags;
  (void)argc;
  (void)argv;
  /*
   * Password changes are not supported; use fnal-vncpasswd instead.
   * Log at INFO so administrators understand why the operation was denied.
   */
  pam_syslog(pamh, LOG_INFO,
             "pam_fnal_vncpasswd: password changes not supported via PAM; "
             "use fnal-vncpasswd to set the VNC password");
  return PAM_PERM_DENIED;
}

/*
 * This module does not implement anything other than the password
 * authentication. Attempts to put this in other elements of the PAM stack
 * will return an error indicating that the requested PAM elements are not
 * implemented.
 */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_SERVICE_ERR;
}
