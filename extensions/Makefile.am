
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(BUILT_SOURCES)
EXTRA_DIST			= $(scripts) $(templates)

wicked_extensions_SCRIPTS	= $(scripts) $(BUILT_SOURCES)

scripts				= \
	ibft			\
	netconfig		\
	redfish-config

if nbft
scripts				+= nbft
else
EXTRA_DIST			+= nbft
endif

BUILT_SOURCES			= \
	dispatch		\
	firewall		\
	hostname

templates			= \
	$(BUILT_SOURCES:=.sh)

substitute_vars			= \
	$(AM_V_GEN)sed							\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"			\
	-e "s|[@]wicked_statedir[@]|$(wicked_statedir)|g"		\
	-e "s|[@]wicked_scriptsdir[@]|$(wicked_scriptsdir)|g"		\
	-e "s|[@]compat_scriptsdir[@]|$(compat_scriptsdir)|g"		\
	-e "s|[@]system_scriptsdir[@]|$(system_scriptsdir)|g"

%: %.sh $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@ && chmod +x $@

check-local: $(wicked_extensions_SCRIPTS)
	@for i in $(scripts) ; \
	do \
		bash -n $(srcdir)/$$i \
			&& printf 'extensions/%-30s %s\n' $$i "Syntax OK" \
			|| exit 1 ; \
	done
	@for i in $(BUILT_SOURCES) ; \
	do \
		bash -n $(builddir)/$$i \
			&& printf 'extensions/%-30s %s\n' $$i "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
