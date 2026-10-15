%global upstream_version 0.1.0

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
%if %{with tests}
BuildRequires:  python3-pytest
%endif

Requires:       python3 >= 3.12
Requires:       python3-systemd
Requires:       python3-dbus

%description
Sentry-v2 watches cgroup v2 pressure, unit failures in the journal and
SELinux AVC denials, ties them together into incidents and writes a
diagnostic bundle for each. Policies can throttle or freeze a unit for a
fixed time through systemd and always roll the change back. Every policy
and the daemon itself start in dry-run, and the service is not enabled
on install.

%prep
%autosetup -n %{name}-%{version}

%generate_buildrequires
%pyproject_buildrequires

%build
%pyproject_wheel

%install
%pyproject_install
%pyproject_save_files sentry_v2

install -Dpm 0644 packaging/sentry-v2.service %{buildroot}%{_unitdir}/sentry-v2.service
install -Dpm 0644 packaging/90-sentry-v2.preset %{buildroot}%{_presetdir}/90-sentry-v2.preset
install -Dpm 0644 packaging/sentry-v2.sysusers %{buildroot}%{_sysusersdir}/sentry-v2.conf
install -Dpm 0644 packaging/sentry-v2.tmpfiles %{buildroot}%{_tmpfilesdir}/sentry-v2.conf
install -Dpm 0644 packaging/examples/sentry-v2.toml %{buildroot}%{_sysconfdir}/sentry-v2/sentry-v2.toml
install -d -m 0755 %{buildroot}%{_sysconfdir}/sentry-v2/policies.d
install -pm 0644 packaging/examples/policies.d/*.toml %{buildroot}%{_sysconfdir}/sentry-v2/policies.d/
install -d -m 0700 %{buildroot}%{_sharedstatedir}/sentry-v2
install -d -m 0750 %{buildroot}/run/sentry-v2


%check
%pyproject_check_import -e sentry_v2.daemon -e sentry_v2.cli
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

%files -f %{pyproject_files}
%license LICENSE
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
%dir %attr(0700,root,root) %{_sharedstatedir}/sentry-v2
%ghost %dir %attr(0750,root,sentry-v2) /run/sentry-v2

%changelog
* Wed Oct 14 2026 James Conway <148910373+jamesconwaydev@users.noreply.github.com> - 0.1.0-1
- First package
