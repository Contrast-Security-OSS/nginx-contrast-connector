

# determine this module version. I'm trying to get away from maintaining a
# VERSION file so we will attempt to dynamically make the version from the git
# tag info and commit hashes.

DESCRIBE:=$(shell git describe --always --long)

# Tags should use a 3-part semantic versioning scheme (http://semver.org). This
# is in the form of MAJOR.MINOR.PATCH. While developing on prerelease software,
# the built version will take the form:
#   <3-part-branch-tag>+<commit num>dev.<commit hash>
# This will allow prerelease packages to be created in an identifiable way that
# can allow the packging systems to make packages of a "higher version" than
# the previous published release versions.
#
# During an actual release, we'd want the "+<commit num>.<commit hash>" to be
# dropped. This will be signified by a zero (0) as the commit num indicating a
# fresh tag.

MOD_SEM_VERSION:=$(shell echo "$(DESCRIBE)" | sed -n 's/^\([0-9\.]*\)-\([0-9]*\)-\([a-z0-9]*\)/\1/p')
MOD_DEV_VERSION:=$(shell echo "$(DESCRIBE)" | sed -n 's/^\([0-9\.]*\)-\([0-9]*\)-\([a-z0-9]*\)/\2/p')
MOD_ABBREV_VERSION:=$(shell echo "$(DESCRIBE)" | sed -n 's/^\([0-9\.]*\)-\([0-9]*\)-\([a-z0-9]*\)/\3/p')

# if no tag has been created, the fallback case here will make a version.
ifeq ($(MOD_SEM_VERSION),)
MOD_SEM_VERSION:=0.0.0
MOD_DEV_VERSION:=1
MOD_ABBREV_VERSION:=$(shell echo $(DESCRIBE))
$(info "MODSEM is '$(MOD_ABBREV_VERSION)'")
endif
# if the developmental version is zero, its a fresh release and don't use
# developmental versioning.
ifeq ($(MOD_DEV_VERSION),0)
MOD_VERSION:=$(MODE_SEM_VERSION)
else
MOD_VERSION:=$(MOD_SEM_VERSION)+$(MOD_DEV_VERSION)dev.$(MOD_ABBREV_VERSION)
endif
$(info MVER is '$(MOD_VERSION)') 

.PHONY: all deps

all: VERSION deps 

VERSION:
	echo "$(MOD_VERSION)" > $@

deps: protobuf-c

clean-deps:
	rm -rf build/protobuf-c
	make -C submodules/protobuf-c clean

protobuf-c: 
	cd submodules/protobuf-c; ./autogen.sh
	cd submodules/protobuf-c; ./configure CFLAGS="-fPIC" --disable-protoc --disable-shared --prefix=`pwd`/../../build/protobuf-c
	make -C submodules/protobuf-c -j2
	make -C submodules/protobuf-c install

clean: clean-deps
	rm -f VERSION
