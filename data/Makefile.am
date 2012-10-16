sydboxsharedir= $(datadir)/$(PACKAGE)
sydboxshare_DATA= \
		  paludis

dist_doc_DATA= \
	       poems.txt
	       sydbox-logo.svg \
	       sydbox-jade-hexagram.svg

upload: poems.txt
	rsync --progress -avze ssh $< tchaikovsky.exherbo.org:public_html/sydbox/
.PHONY: upload
