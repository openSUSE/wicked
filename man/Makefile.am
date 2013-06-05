
CLEANFILES			= *~
MAINTAINERCLEANFILES		= Makefile.in
DISTCLEANFILES			= $(man_MANS)
BUILT_SOURCES			= $(man_MANS)
EXTRA_DIST			= $(templates)

man_MANS			= \
	wicked-config.5		\
	wicked.7		\
	wicked.8		\
	wickedd.8

templates			= $(man_MANS:=.in)

substitute_vars			= \
	$(AM_V_GEN)sed						\
	-e "s|[@]wicked_piddir[@]|$(wicked_piddir)|g"		\
	-e "s|[@]wicked_sbindir[@]|$(wicked_sbindir)|g"		\
	-e "s|[@]wicked_statedir[@]|$(wicked_statedir)|g"	\
	-e "s|[@]wicked_storedir[@]|$(wicked_storedir)|g"	\
	-e "s|[@]wicked_schemadir[@]|$(wicked_schemadir)|g"	\
	-e "s|[@]wicked_configdir[@]|$(wicked_configdir)|g"	\
	-e "s|[@]wicked_supplicantdir[@]|$(wicked_supplicantdir)|g"\
	-e "s|[@]wicked_extensionsdir[@]|$(wicked_extensionsdir)|g"

wicked%: wicked%.in $(top_builddir)/config.status
	@echo "substituting variables in $< > $@"
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

# vim: ai
