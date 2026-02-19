Name:		pam-vncpasswd
Version:	0.1.0
Release:	1%{?dist}

# Only the test_framework is CC-PDDC; everything else is BSD-3-Clause
License:	BSD-3-Clause and CC-PDDC

URL:		https://github.com/jcpunk/%{name}
Source0:	%{url}/archive/refs/tags/%{version}.tar.gz

BuildRequires:	cmake >= 3.11
BuildRequires:	coreutils git
BuildRequires:	gcc lcov
BuildRequires:	pam-devel
BuildRequires:	libxcrypt-devel
BuildRequires:	(rubygem-asciidoctor or asciidoc)

Requires:	libxcrypt

Summary:	PAM module for VNC password file authentication
%description
pam-vncpasswd is a PAM module that authenticates users against a per-user
VNC password file (~/.config/vnc/fnal_vncpasswd) using proper crypt(3) hashing.

It is designed for environments where VNC servers (such as Weston + NeatVNC
on RHEL10) need password authentication for users whose primary credentials
are Kerberos tickets with no local password hash.

The module supports yescrypt (the default on modern RHEL/Fedora), SHA-512,
SHA-256, and bcrypt, reading the algorithm and cost parameters from
/etc/login.defs at runtime.

Unlike TigerVNC's built-in password handling, pam_fnal_vncpasswd uses proper
crypt(3) hashing. For yescrypt, the cost is controlled by YESCRYPT_COST_FACTOR
in /etc/login.defs (not SHA_CRYPT_MAX_ROUNDS, which is for SHA-crypt only).

%prep
%autosetup

%build
%cmake -Wdev -Wdeprecated   \
       -DVERSION=%{version} \
       -DBUILD_TESTING=ON
%cmake_build

%install
%cmake_install

%check
%ctest

%files
%defattr(0644,root,root,0755)
%license LICENSE
%doc %{_mandir}
%attr(0755,root,root) %{_bindir}/fnal-vncpasswd
%attr(0755,root,root) %{_libdir}/security/pam_fnal_vncpasswd.so
%dir %{_datadir}/pam-vncpasswd
%{_datadir}/pam-vncpasswd/


%changelog
* Thu Feb 19 2026 Fermi Forward Discovery Group <fnal-systems@fnal.gov> - 0.1.0
- Initial release
- yescrypt support (default on RHEL10): uses YESCRYPT_COST_FACTOR from
  login.defs, not SHA_CRYPT_MAX_ROUNDS
- SHA-512, SHA-256, bcrypt support
- TOCTOU-safe file validation (O_NOFOLLOW + fstat)
- Constant-time password comparison
- Atomic password file writes (mkstemp + rename)
