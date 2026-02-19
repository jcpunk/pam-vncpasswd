/**
 * pam_entry.c - PAM module entry points
 *
 * Thin wrappers around authenticate_vnc_user() that bridge the PAM API
 * to the core logic in pam_fnal_vncpasswd.c.
 *
 * WHY SEPARATE FROM pam_fnal_vncpasswd.c:
 * The core authentication logic (pam_fnal_vncpasswd.c) has no PAM dependency,
 * making it fully testable via the syscall_ops mock pattern. This file
 * contains only the PAM glue: extract username/password from the PAM
 * handle and call authenticate_vnc_user().
 *
 * PAM headers are expected to be present in the build environment (RHEL10).
 * Tests do not compile this file; they test authenticate_vnc_user() directly.
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "autoconf.h"
#include "pam_fnal_vncpasswd.h"
#include "syscall_ops.h"

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  const char *username = NULL;
  const char *authtok = NULL;
  struct pam_args args;

  (void)flags;

  parse_pam_args(argc, argv, &args);

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get username");
    return PAM_AUTH_ERR;
  }

  if (pam_get_authtok(pamh, PAM_AUTHTOK, &authtok, NULL) != PAM_SUCCESS
      || !authtok) {
    pam_syslog(pamh, LOG_ERR, "pam_fnal_vncpasswd: could not get password");
    return PAM_AUTH_ERR;
  }

  return authenticate_vnc_user(&syscall_ops_default, username, authtok,
                               args.file, args.nullok);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
                              int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
                                 int argc, const char **argv) {
  (void)pamh; (void)flags; (void)argc; (void)argv;
  return PAM_SUCCESS;
}
