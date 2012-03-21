Summary:	network configuration infrastructure
Name:		wicked
Version:	0.0.0
Release:	12.mge
Source0:	%{name}-%{version}.tar.bz2
Group:		Networking
License:	GPL v2
Buildroot:	%{_tmppath}/%{name}%{version}-buildroot/

%if 0%{?suse_version} > 1110
BuildRequires:	libiw-devel libnl-devel dbus-1-devel
%else
BuildRequires:	wireless-tools libnl-devel dbus-1-devel
%endif

%if 0%{?suse_version:1}
PreReq:         %fillup_prereq %insserv_prereq
%endif

%description
wicked is a network configuration infrastructure incorporating a number
of existing frameworks into a unified architecture, providing a REST
interface to network configuration.

%prep
rm -rf $RPM_BUILD_ROOT
%setup

%build
export CFLAGS="$RPM_OPT_FLAGS"
make

%install
%makeinstall DESTDIR=${RPM_BUILD_ROOT}
make install-files DESTDIR=${RPM_BUILD_ROOT}
#
install -d -m 755 ${RPM_BUILD_ROOT}/etc/init.d
install -d -m 755 ${RPM_BUILD_ROOT}/usr/sbin
install -m 750 etc/wickedd.init ${RPM_BUILD_ROOT}/etc/init.d/wickedd
ln -s ../../etc/init.d/wickedd  ${RPM_BUILD_ROOT}/usr/sbin/rcwickedd

%post
%{fillup_and_insserv wickedd}

%preun
%stop_on_removal wickedd

%postun
%restart_on_update wickedd
%insserv_cleanup

## BASE

%files
%defattr (-,root,root)
%doc ANNOUNCE COPYING README TODO samples
/sbin/wickedd
/sbin/dhcp4-supplicant
/sbin/auto4-supplicant
/etc/init.d/wickedd
/usr/sbin/rcwickedd
%dir /etc/wicked
%dir /etc/wicked/schema
%dir /var/run/wicked
%config(noreplace) /etc/wicked/*.xml
/etc/wicked/schema/*.xml
%{_mandir}/man7/*
%{_mandir}/man8/*

## CLI

%package cli
License:        GPL v2
Group:          Networking
Summary:        network configuration infrastructure - cli
Requires:       %name = %{version}

%description cli
wicked is a network configuration infrastructure incorporating a number
of existing frameworks into a unified architecture, providing a REST
interface to network configuration.
This package provides the CLI.

%files cli
%defattr (-,root,root)
/sbin/wicked

## CHANGELOG

%changelog
* Thu Nov 25 2010 Matthias Eckermann <mge@novell.com>
- update to git version as of Thu Nov 25 16:16:13 CET 2010
* Mon Oct 18 2010 Matthias Eckermann <mge@novell.com>
- update to git version as of Thu Oct 14 13:25:15 2010 +0200
* Thu Sep  2 2010 Matthias Eckermann <mge@novell.com>
- initial SPEC file

