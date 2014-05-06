%if ! (0%{?fedora} > 12 || 0%{?rhel} > 5)
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}
%endif

Name:           python-txmilter
Version:        0.0.1
Release:        1%{?dist}
Summary:        Twisted library for the milter protocol
Group:          Development/Libraries
License:        MIT
URL:            https://github.com/flaviogrossi/txmilter-cyclone
Source0:        %{name}-%{version}.tar.gz

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch
BuildRequires:  python-devel
BuildRequires:  python-setuptools

Requires:       python
Requires:       python-twisted

%description
Twisted library for the milter protocol.

%prep
%setup

%build
%{__python} setup.py build

%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install --skip-build --root $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%dir %{python_sitelib}/txmilter/
%{python_sitelib}/txmilter/*
%{python_sitelib}/txmilter*egg-info

%changelog
* Tue May 6 2014 Flavio Grossi <flaviogrossi@gmail.com>
- first rpm release.
