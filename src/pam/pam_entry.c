/**
 * pam_entry.c - PAM module entry points
 *
 * Thin glue layer bridging the PAM API to the core logic in auth.c.
 * Extracts username and password from the PAM handle, then calls
 * authenticate_vnc_user().
 *
 * PAM headers are pulled in via auth.h.  Tests do not compile this file;
 * they call authenticate_vnc_user() directly.
 *
 * ALL SIX pam_sm_* ENTRY POINTS ARE REQUIRED.  Linux-PAM resolves them by
 * symbol name at dlopen time based on which service types appear in
 * /etc/pam.d/.  A missing symbol causes dlsym failure and breaks the entire
 * auth stack.  The PAM_SM_* defines above tell pam_modules.h to declare the
 * corresponding prototypes; omitting them for unused types would produce
 * implicit-declaration warnings while the stubs themselves must still exist.
 */

#include <syslog.h>

#include "auth.h"
#include "autoconf.h"
#include "syscall_ops.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  const char *username = NULL;
  const char *authtok = NULL;
  struct pam_args args;

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

  return authenticate_vnc_user(&syscall_ops_default, username, authtok,
                               args.nullok);
}

/*
 * This module manages no credentials.  PAM_IGNORE tells the PAM stack that
 * setcred is not applicable here, which is correct and avoids interfering
 * with stacked modules that inspect setcred return values.
 * PAM_SUCCESS would falsely signal that credentials were established.
 */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  (void)pamh;
  (void)flags;
  (void)argc;
  (void)argv;
  return PAM_IGNORE;
}

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
