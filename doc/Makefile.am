
CLEANFILES			= *~ schema.xml
MAINTAINERCLEANFILES		= Makefile.in
EXTRA_DIST			= schema.xml.in $(wicked_doc_data)

schema: schema/dbus.html

schema/%.html: schema.xml $(top_builddir)/schema/constants.xml
	@rm -f $(@D)/*
	@$(MKDIR_P) $(@D)
	$(top_builddir)/util/schema2html --outdir $(@D) --config $<

$(top_builddir)/schema/constants.xml:
	cd $(top_builddir)/schema && $(MAKE) constants.xml

$(top_builddir)/util/schema2html: $(top_builddir)/src/libwicked.la
	cd $(top_builddir)/util && $(MAKE) schema2html

substitute_vars		=	\
	$(AM_V_GEN)sed		\
	-e "s|[@]schemadir[@]|$(top_builddir)/schema|g"

schema.xml: schema.xml.in
	@rm -f $@ $@.tmp
	@$(substitute_vars) < $< > $@.tmp && mv $@.tmp $@

wicked_doc_data	= \
	FAQ.txt WhyWicked.txt

# vim: ai
