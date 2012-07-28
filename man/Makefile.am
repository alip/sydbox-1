CLEANFILES= \
	    sydbox.1 \
	    sydbox.html
EXTRA_DIST= \
	    sydbox.xml

if HAVE_XSLTPROC
XSLTPROC_FLAGS= \
		--encoding "'UTF-8'" \
		--nonet \
		--param funcsynopsis.style "'ansi'"

sydbox.1: sydbox.xml
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<

sydbox.html: sydbox.xml
	$(AM_V_GEN)
	$(AM_V_at)$(XSLTPROC) -o $@ $(XSLTPROC_FLAGS) http://docbook.sourceforge.net/release/xsl/current/xhtml-1_1/docbook.xsl $<

dist_man_MANS= \
	       sydbox.1
dist_html_DATA= \
		sydbox.html

upload-html: sydbox.html
	rsync --progress -avze ssh $< tchaikovsky.exherbo.org:public_html/sydbox/
.PHONY: upload-html
else
sydbox.1:
	@echo "You don't have xsltproc installed!"
	exit 1
sydbox.html:
	@echo "You don't have xsltproc installed!"
	exit 1
upload-html:
	@echo "Not uploading HTML documentation"
	exit 0
endif # HAVE_XSLTPROC