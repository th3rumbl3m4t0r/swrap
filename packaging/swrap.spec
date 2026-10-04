# swrap: audited SSH jump host (AAA). Builds offline from the source tarball and a tarball of the
# vendored crates (packaging/make-sources.sh makes both). The package only installs files; the
# system setup (users, vault, sshd/PAM, units, SELinux module, firewall) stays with
# `swrap-install core` on core and `swedge deploy <label>` (from core) on edge.

%global debug_package %{nil}

Name:           swrap
Version:        0.2.0
Release:        1%{?dist}
Summary:        Audited SSH jump host: recorded sessions, vault-held keys, fleet jobs, AI workbench
License:        GPL-3.0-or-later
URL:            https://github.com/th3rumbl3m4t0r/swrap
Source0:        %{name}-%{version}.tar.gz
Source1:        %{name}-%{version}-vendor.tar.gz
ExclusiveArch:  x86_64 aarch64

BuildRequires:  cargo >= 1.85
BuildRequires:  rust >= 1.85
BuildRequires:  gcc

Requires:       openssh-server
Requires:       openssh-clients
Requires:       git-core
Requires:       nftables
Requires:       tar
Requires:       gzip
Requires:       bubblewrap
Requires:       audit
Requires:       policycoreutils
Requires:       policycoreutils-python-utils
Requires:       selinux-policy-devel
Requires:       make
Recommends:     fail2ban

%description
swrap is an AAA jump host for SSH. Every session (sw, shell, SFTP, fleet jobs, swai) is recorded
in a signed, crash-safe format; host keys live in an encrypted vault and are used through a
per-session filtering agent; grants are role based and time bound; a public edge node relays
logins to the on-prem core over a single link. Web playback and search on core.

After installing: `swrap-install core` (core node); edge nodes are installed from core with
`swedge deploy <label>`. The AI harnesses (Claude Code, opencode) are not part of this package
(`swai` docs).

%prep
%autosetup -n %{name}-%{version} -a 1
mkdir -p .cargo
cat > .cargo/config.toml <<'CFG'
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"
CFG

%build
cargo build --release --locked --offline

%check
cargo test --release --locked --offline --workspace -q

%install
install -d %{buildroot}%{_libexecdir}/swrap
for b in swrapd swrap swrap-shell swrap-pam-unlock swrec swrap-web; do
    install -m 0755 target/release/$b %{buildroot}%{_libexecdir}/swrap/$b
done
ln -s swrap %{buildroot}%{_libexecdir}/swrap/sftp-dispatch
install -d %{buildroot}%{_bindir}
for l in swrap sw swai swls swlog swcat swplay swsearch swupdate swinv swr swx swpasswd swunlock \
         swadm swadd swenroll swdel swuser swrotate swcrypto swfw swedge swrap-install; do
    ln -s ../libexec/swrap/swrap %{buildroot}%{_bindir}/$l
done
ln -s ../libexec/swrap/swrec %{buildroot}%{_bindir}/swrec
install -d %{buildroot}%{_datadir}/swrap/selinux
install -m 0644 crates/swrap-cli/selinux/swrap.te crates/swrap-cli/selinux/swrap.fc %{buildroot}%{_datadir}/swrap/selinux/

%post
if [ "$1" -eq 1 ]; then
    echo "swrap installed: run 'swrap-install core' on the core node (edge: 'swedge deploy <label>' from core)."
fi

%files
%doc README.md docs/aaa.md
%dir %{_libexecdir}/swrap
%{_libexecdir}/swrap/swrapd
%{_libexecdir}/swrap/swrap
%{_libexecdir}/swrap/swrap-shell
%{_libexecdir}/swrap/swrap-pam-unlock
%{_libexecdir}/swrap/swrec
%{_libexecdir}/swrap/swrap-web
%{_libexecdir}/swrap/sftp-dispatch
%{_bindir}/sw*
%{_bindir}/swrap-install
%{_datadir}/swrap

%changelog
* Sun Oct 04 2026 th3rumbl3m4t0r <th3rumbl3m4t0r@users.noreply.github.com> - 0.2.0-1
- swai (AI workbench) handoffs, limits, Proxmox reset, chat view; swuser / swrotate; SELinux
  rules for core; edge state mirror, SFTP and fleet output through edge; x11 look; UTC default

* Sat Oct 03 2026 th3rumbl3m4t0r <th3rumbl3m4t0r@users.noreply.github.com> - 0.1.0-1
- First package: core and edge binaries, command links, SELinux module sources, docs.
