
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in

wicked_extensions_SCRIPTS	= \
	dispatch	\
	firewall	\
	hostname	\
	ibft		\
	nbft		\
	netconfig	\
	redfish-config

EXTRA_DIST			= $(wicked_extensions_SCRIPTS)

check-local:
	@for i in $(wicked_extensions_SCRIPTS) ; \
	do \
		bash -n $(srcdir)/$$i \
			&& printf 'extensions/%-30s %s\n' $$i "Syntax OK" \
			|| exit 1 ; \
	done

# vim: ai
