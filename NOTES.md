# Dependencies
The project will manually install build and runtime dependencies via the a mix
of the vagrant machine provisioning and script/bootstrapping script. I'd like to
list out the current dependencies and have a path forward for separating runtime
deps from build/developer deps.

## Runtime Deps
 * The nginx module depends on the nginx server package to be installed.
 * The nginx module depends on speedracer (Contrast Service).

## Developer/Build Deps
 * Standard build tools, make, autoconf/autotools/libtool
 * When developing on the nginx module, our development system should use a
     locally compiled version of NGINX rather than the system's version so that
     its easy to develop against the various versions of NGINX.
 * ruby, rvm, bundler for running the Rakefile and RSpec integration tests.
 * protobuf-c libs which will be statically compiled into the nginx module.
 * iff generating new C files from .proto files, then protoc-c tool will be be
     needed and that carries a dependency of libprotobuf from Google. This is an
     area that is under consideration for changing.
 * speedracer depends on libmodsecurity.so which is provided via the
     build/install script in script/bootstrap in this project.  In the future
     I'd like to move this out since the same dependency would be in place if we
     were making an apache module. Seems like this dep should be encapsulated
     by speedracer only.
 * golang is installed via source from this project using the script/bootstrap
     script.  Once again, this should be encapsulated via speedracer only since
     its just speedracer that needs golang.
 * libmodsecurity depends on owasp CRS. This should also be managed by the
     speedracer project.

Given that this is a new-ish project, things are still settling into place and
some speedracer-only dependencies appear to be stored in this connector module.
We'll likely align this more intuitively in the future.

# nginx module building info
the conf file: https://www.nginx.com/resources/wiki/extending/new_config/

# about the oss pkg builder from nginx
see https://www.nginx.com/blog/creating-installable-packages-dynamic-modules/

info about  nginx oss pkg builder

The build_module.sh includes a template that is put into /tmp/$(builddir)/oss/debian/Makefile.module-contrast

It bascially sets up some of the debian rules when building the package.  This is the way you can
influence how the debhelper scripts builds and represents your package.

When running 'make' in /tmp/$(builddir)/oss/debian

In /tmp/$(builddir)/oss/debian/Makefile:310, the "module rule template" (Makefile.module-contrast) is handled
and sed is used to extrapolate placeholds in debian rules files to place in
real/custom rule data. This fills in the package metadata and allows for one to
augment the package building scripts in certain points. We augement the
pre-build step to compile the libprotobuf-c dependency of our nginx module.

# binary compatibility
Despite nginx advertising dynamically loadable module support in nginx-1.9.?,
in that version the compiled nginx binary must be compiled expecting to load
the outside module.  That is, internally, it's making space in chaining slots
and other various things to be able to accept the loadable module.

It wasn't until nginx-1.11.5 that nginx got support for binary compatibility to
load arbitrary modules without knowing about them ahead of time.

see https://www.nginx.com/blog/compiling-dynamic-modules-nginx-plus/

# ubuntu xenial nginx issues

The ubuntu 16.04 (xenial) distro supplies an outdated version of the nginx
server. At the time of this writting (22JUN2018), it offers nginx 1.10.3 which
was release sometime in 2016. NGINX supplies updated nginx packages for all
major distros and will certainly be the package supplier of their premium
commercial product, NGINX Plus.

To offer the Contrast nginx WAF module as a simple loadable module, customers
must use an nginx version of 1.11.5 or greater. The path for this to all work
properly is to ensure their distro repo supplies a new-enough nginx and if it
doesn't then to point them to the nginx official repos.

see http://nginx.org/en/linux_packages.html
see http://nginx.org/packages/mainline/

# The way packaging workflow _should_ work

Developers of OSS products typically do not perform their own packaging work as
there are just so many distros to keep up with its not an effective use of
their time. Developers will typically create a source distribution of their
product.

This source distribution is referred to as the 'upstream' source. A "Package
Maintainer" for each disto will then pickup the source distribution of the 
product and create a build/package script to package the compiled OSS product
for the specific distro they work on. Distros will sometimes deviate on how to
organize the binaries when installing onto a system so this type of work is 
best handled by a dedicated package maintainer rather than the upstream
developer having to keep track of the specifics between different distros.

The source files that make up the upstream OSS product are generally installed
in the author's repo which is likely on github.com. The source files describing
the package and any distro-specific build flags are generally stored in a
distro-specific repo. The packaging description and source files will point to
the upstream source distribution to be fetched at build/packaging time.

# The Contrast packaging workflow

Since we are not depending on a downstream package maintainer to handle
packaging for us, we perform all the packaging work ourselves. Rather than
split out distro packaging code/defs from the actual source of the project, we
combine the packaging data for all the different distros into repo of the
project itself. This should be acceptable to start with as the end goal is to
create a package for customers. However, its not the normal OSS workflow and in
the future we may want to internalize the workflow and create a repo of just
packaging data for all our projects.

