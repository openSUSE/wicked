
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
EXTRA_DIST			= $(wicked_extensions_SCRIPTS)

wicked_extensions_SCRIPTS	= \
	dispatch	\
	firewall	\
	hostname	\
	ibft		\
	netconfig	\
	redfish-config

if nbft
wicked_extensions_SCRIPTS	+= nbft
else
EXTRA_DIST			+= nbft
endif


check-local:
	@for i in $(wicked_extensions_SCRIPTS) ; \
	do \
		bash -n $(srcdir)/$$i \
			&& printf 'extensions/%-30s %s\n' $$i "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
