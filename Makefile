#
# Development by Carl J. Nobile
#
# $Author: $
# $Date: $
# $Revision: $
#

PREFIX		= $(shell pwd)
PACKAGE_DIR	= $(shell echo $${PWD\#\#*/})
DOCS_DIR	= $(PREFIX)/docs
TODAY		= $(shell date +"%Y-%m-%d_%H%M")

#----------------------------------------------------------------------
all	: tar

#----------------------------------------------------------------------
tar	: clean
	@(cd ..; tar -czvf $(PACKAGE_DIR).tar.gz --exclude=".git" \
          --exclude="example_site/static" $(PACKAGE_DIR))

api-docs: clean
	@(cd $(DOCS_DIR); make)

#----------------------------------------------------------------------

clean	:
	$(shell cleanDirs.sh clean)

clobber	: clean
	@(cd $(DOCS_DIR); make clobber)
