
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

templatepp			= $(top_srcdir)/util/templatepp.gawk
substitute_vars			= \
	$(AM_V_GEN)$(AWK) -f $(templatepp) --			\
	-V wicked_sbindir='$(wicked_sbindir)'			\
	-V wicked_statedir='$(wicked_statedir)'			\
	-V wicked_scriptsdir='$(wicked_scriptsdir)'		\
	-V compat_scriptsdir='$(compat_scriptsdir)'		\
	-V system_scriptsdir='$(system_scriptsdir)'

%: %.sh $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) -i $< -o $@.tmp && mv $@.tmp $@ && chmod +x $@

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
