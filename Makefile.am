
CLEANFILES			= *~
DISTCLEANFILES			= wicked.pc
MAINTAINERCLEANFILES		= Makefile.in aclocal.m4 config.guess config.*   \
				  configure depcomp install-sh ltmain.sh missing \
				  $(DIST_ARCHIVES) $(PACKAGE)-*.tar.bz2

SUBDIRS				= include src util schema client server nanny \
				  autoip4 dhcp4 dhcp6 etc extensions man doc testing


pkgconfig_DATA			= wicked.pc

wicked_doc_data			= README TODO COPYING ANNOUNCE		\
				  $(wildcard ChangeLog)

EXTRA_DIST			= VERSION wicked.pc.in wicked-rpmlintrc	\
				  wicked.spec.in wicked.spec samples	\
				  $(wicked_doc_data)

custom_rpmbuild_opts		= $(CUSTOM_RPMBUILD_OPTS)
rpmbuild_opts			= $(custom_rpmbuild_opts) -ta --define "snapshot $$(date +%Y%m%d%H%M%S)"


# Build test RPMs, no checks
rpmbuild: dist-bzip2
	rpmbuild $(rpmbuild_opts) $(distdir).tar.bz2

# Build source package with all checks enabled (unlike 'make dist')
package: all check distcheck show-commit-state

# Build rpm test package with all checks enabled
rpmpackage: package
	rpmbuild $(rpmbuild_opts) $(distdir).tar.bz2

dist-hook: VERSION $(distdir)/wicked.spec $(distdir)/ChangeLog

$(distdir)/wicked.spec: wicked.spec
	@cp $< $@

$(distdir)/ChangeLog: check-git-tool
	@if  [ -d $(top_srcdir)/.git ]; then \
	  LANG=C git log -- $(top_srcdir) > $(distdir)/ChangeLog ; \
	fi

show-commit-state: check-git-tool
	@if  [ -d $(top_srcdir)/.git ]; then \
	  cd $(top_srcdir) && \
	  LC_ALL=C git status 2>&1 | \
	  grep -qsE 'Untracked|to be committed|not staged for commit' && { \
	    echo -e "##\n## *** NOTE: There are uncommitted changes:\n##" ; \
	    git status 2>&1 || : ; \
	  } || : ; \
	fi

check-git-tool:
	@if ! git --version &>/dev/null ; then \
	  echo 'ERROR: Unable to find the '\'git\'' version control client!'; \
	  echo '       Please install git (git-core) and try again.'        ; \
	  exit 1 ; \
	fi >&2

# vim: ai
