#!/bin/bash

set -ex

pkgdir=${1}
env=${2}

echo "location of packages ${pkgdir}"
echo "Deploying to environment ${env}"

function check_http_result {
    local result=$1

    if [ ${result} -lt 400 ]; then
        echo "responseCode was ${result}"
    else
        echo "bad http request - response code: $result"
        exit 1
    fi
}

function push_to_repo {
        local repokey=$1
        local repopath=$2
        local targetfile=$3
        local urlbase="https://contrastsecurity.jfrog.io/contrastsecurity"
        local authhdr="Authorization: Bearer $CONTRAST_ARTIFACTORY_ACCESS_TOKEN"

        responseCode=$(curl --silent --output put-result.log  --write-out %{http_code} \
            -H "$authhdr" \
            -X PUT "$urlbase/$repokey/$repopath" \
            -T ${targetfile})
        cat put-result.log
        check_http_result $responseCode
}

function determine_environment {
    local environment=$1
    local distroType=$2

    case "$environment" in
    "staging") environment="${distroType}-staging" ;;
    "public") environment="${distroType}-public" ;;
    esac
    echo "$environment"
}


for p in ${pkgdir}/*.rpm; do
    pkgname=`basename $p`
    el_ver=`echo $pkgname | sed 's/.*el\([[:digit:]]\).*.rpm/\1/'`
    distro="centos-$el_ver"
    environment=$(determine_environment $env "rpm")
    push_to_repo "$environment" "$distro/" $p
done

for p in ${pkgdir}/*.deb; do
    pkgname=`basename $p`
    arch=`echo "$pkgname" | sed 's/.*_\(.*\).deb$/\1/'`
    distro=`echo "$pkgname" | sed 's/.*~\(.*\)_.*.deb$/\1/'`
    environment=$(determine_environment $env "debian")
     push_to_repo "$environment" \
         "pool/${pkgname};deb.distribution=${distro};deb.component=contrast;deb.architecture=${arch}" \
         $p
done

exit 0
