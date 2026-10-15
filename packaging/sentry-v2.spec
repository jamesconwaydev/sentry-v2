%global upstream_version 0.1.0
%global selinuxtype targeted
%global modulename sentry_v2

# The unit tests need python3-pytest, which EL10 only ships in CRB/EPEL.
%bcond_with tests

Name:           sentry-v2
Version:        %{upstream_version}
Release:        1%{?dist}
Summary:        Correlates PSI, journal failures and SELinux denials, with reversible remediation

License:        AGPL-3.0-or-later
URL:            https://github.com/jamesconwaydev/sentry-v2
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  pyproject-rpm-macros
BuildRequires:  systemd-rpm-macros
BuildRequires:  selinux-policy-devel
BuildRequires:  bzip2
%if %{with tests}
BuildRequires:  python3-pytest
%endif

Requires:       python3 >= 3.12
Requires:       python3-systemd
Requires:       python3-dbus
Recommends:     (%{name}-selinux if selinux-policy-%{selinuxtype})

%description
Sentry-v2 watches cgroup v2 pressure, unit failures in the journal and
SELinux AVC denials, ties them together into incidents and writes a
diagnostic bundle for each. Policies can throttle or freeze a unit for a
fixed time through systemd and always roll the change back. Every policy
and the daemon itself start in dry-run, and the service is not enabled
on install.

%package selinux
Summary:        SELinux policy module for sentry-v2
Requires:       %{name} = %{version}-%{release}
Requires:       selinux-policy-%{selinuxtype}
Requires(post): selinux-policy-%{selinuxtype}
Requires(post): policycoreutils
# semanage, for the metrics port label.
Requires(post): policycoreutils-python-utils
Requires(postun): policycoreutils-python-utils
%{?selinux_requires}

%description selinux
Confines the sentry-v2 daemon in the sentry_v2_t domain.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel
%make_build -C packaging/selinux -f %{_datadir}/selinux/devel/Makefile %{modulename}.pp
bzip2 -9 packaging/selinux/%{modulename}.pp

%install
%pyproject_install
%pyproject_save_files -l sentry_v2

install -Dpm 0644 packaging/sentry-v2.service %{buildroot}%{_unitdir}/sentry-v2.service
install -Dpm 0644 packaging/90-sentry-v2.preset %{buildroot}%{_presetdir}/90-sentry-v2.preset
install -Dpm 0644 packaging/sentry-v2.sysusers %{buildroot}%{_sysusersdir}/sentry-v2.conf
install -Dpm 0644 packaging/sentry-v2.tmpfiles %{buildroot}%{_tmpfilesdir}/sentry-v2.conf
install -Dpm 0644 packaging/examples/sentry-v2.toml %{buildroot}%{_sysconfdir}/sentry-v2/sentry-v2.toml
install -d -m 0755 %{buildroot}%{_sysconfdir}/sentry-v2/policies.d
install -pm 0644 packaging/examples/policies.d/*.toml %{buildroot}%{_sysconfdir}/sentry-v2/policies.d/
install -d -m 0700 %{buildroot}%{_sharedstatedir}/sentry-v2
install -d -m 0750 %{buildroot}/run/sentry-v2

install -Dpm 0644 packaging/selinux/%{modulename}.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
install -Dpm 0644 packaging/selinux/%{modulename}.if \
    %{buildroot}%{_datadir}/selinux/devel/include/distributed/%{modulename}.if

%check
# sentry_v2.daemon is the console script's target and doesn't exist yet;
# drop the exclusion when it lands.
%pyproject_check_import -e sentry_v2.daemon
%if %{with tests}
%pytest -m 'not integration'
%endif

# rpm >= 4.19 creates the groups from the sysusers.d file before install.

%post
%systemd_post sentry-v2.service

%preun
%systemd_preun sentry-v2.service

%postun
%systemd_postun_with_restart sentry-v2.service

%pre selinux
%selinux_relabel_pre -s %{selinuxtype}

%preun selinux
if [ $1 -eq 0 ]; then
    %selinux_relabel_pre -s %{selinuxtype}
fi

%post selinux
%selinux_modules_install -s %{selinuxtype} %{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
# -a fails if the port is already labelled (an upgrade), so fall back to -m.
semanage port -a -t sentry_v2_metrics_port_t -p tcp 9787 2>/dev/null \
    || semanage port -m -t sentry_v2_metrics_port_t -p tcp 9787 || :

%postun selinux
if [ $1 -eq 0 ]; then
    # The port record refers to the module's type, so it goes first.
    semanage port -d -t sentry_v2_metrics_port_t -p tcp 9787 || :
    %selinux_modules_uninstall -s %{selinuxtype} %{modulename}
    %selinux_relabel_post -s %{selinuxtype}
fi

%posttrans selinux
%selinux_relabel_post -s %{selinuxtype}

%files -f %{pyproject_files}
%doc README.md
%{_bindir}/sentry-v2
%{_bindir}/sentry-v2ctl
%{_unitdir}/sentry-v2.service
%{_presetdir}/90-sentry-v2.preset
%{_sysusersdir}/sentry-v2.conf
%{_tmpfilesdir}/sentry-v2.conf
%dir %{_sysconfdir}/sentry-v2
%dir %{_sysconfdir}/sentry-v2/policies.d
%config(noreplace) %{_sysconfdir}/sentry-v2/sentry-v2.toml
%config(noreplace) %{_sysconfdir}/sentry-v2/policies.d/*.toml
%dir %attr(0700,root,sentry-v2) %{_sharedstatedir}/sentry-v2
%ghost %dir %attr(0750,root,sentry-v2) /run/sentry-v2

%files selinux
%{_datadir}/selinux/packages/%{selinuxtype}/%{modulename}.pp.bz2
%{_datadir}/selinux/devel/include/distributed/%{modulename}.if
%ghost %verify(not md5 size mode mtime) %{_sharedstatedir}/selinux/%{selinuxtype}/active/modules/200/%{modulename}

%changelog
* Wed Oct 14 2026 James Conway <148910373+jamesconwaydev@users.noreply.github.com> - 0.1.0-1
- First package
