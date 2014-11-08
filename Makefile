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
          --exclude="logs/*.log" --exclude="data/*.csv" --exclude="dist/*" \
          $(PACKAGE_DIR))

api-docs: clean
	@(cd $(DOCS_DIR); make)

build	: clean
	python setup.py sdist

#----------------------------------------------------------------------

clean	:
	$(shell cleanDirs.sh clean)
	@rm -rf *.egg-info
	@rm -rf python-forensics-1.0
	@rm -rf dist

clobber	: clean
	@(cd $(DOCS_DIR); make clobber)
	@rm data/*.csv
	@rm logs/*.log
