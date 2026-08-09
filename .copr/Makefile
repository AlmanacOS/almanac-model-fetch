# COPR entry point for the "Make SRPM" build method.
#
# COPR clones this repository into a minimal chroot and runs:
#     make -f .copr/Makefile srpm outdir=<dir>
# with network access available, which is what lets the vendoring step below
# reach crates.io. The build of the SRPM itself is then fully offline.
#
# Everything real lives in packaging/rpm/make-srpm.sh, which works the same way
# on a developer's machine.

outdir ?= $(CURDIR)/packaging/rpm/out

srpm:
	dnf -y install --setopt=install_weak_deps=False \
	    cargo git-core rpm-build tar gzip
	# COPR checks out as one user and may build as another; without this git
	# refuses to read the repository it just cloned.
	git config --global --add safe.directory "$(CURDIR)"
	packaging/rpm/make-srpm.sh --outdir "$(outdir)"

.PHONY: srpm
