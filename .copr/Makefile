# COPR entry point for the "Make SRPM" build method.
#
# COPR clones this repository into a minimal chroot and runs:
#     make -f <clone>/.copr/Makefile srpm outdir=<dir>
# with network access available, which is what lets the vendoring step below
# reach crates.io. The build of the SRPM itself is then fully offline.
#
# Everything real lives in packaging/rpm/make-srpm.sh, which works the same way
# on a developer's machine.

# Locate the checkout from this makefile's own path, never from the working
# directory. COPR passes -f as an absolute path and runs make from whatever
# directory the package's "Subdirectory" field names, which is not necessarily
# the repository root -- a relative path to the script silently becomes
# <subdir>/packaging/rpm/make-srpm.sh and fails with a bare "No such file or
# directory".
root := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))/..
root := $(abspath $(root))

outdir ?= $(root)/packaging/rpm/out

srpm:
	dnf -y install --setopt=install_weak_deps=False \
	    cargo git-core rpm-build tar gzip
	# COPR checks out as one user and may build as another; without this git
	# refuses to read the repository it just cloned.
	git config --global --add safe.directory "$(root)"
	# Invoked through bash explicitly: a checkout that lost the executable
	# bit would otherwise fail here in a way that looks like a missing file.
	bash "$(root)/packaging/rpm/make-srpm.sh" --outdir "$(outdir)"

.PHONY: srpm
