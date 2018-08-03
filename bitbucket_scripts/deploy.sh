#!/bin/bash

set -ex

pkgdir=${1}

echo "location of packages ${pkgdir}"

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


for p in ${pkgdir}/*.rpm; do
    pkgname=`basename $p`
    distro=`echo $pkgname | sed 's/.*\(el[[:digit:]]d\).*.rpm/\1/'`
    push_to_repo "rpm-staging" "$distro/" $p
done

for p in ${pkgdir}/*.deb; do
    pkgname=`basename $p`
    arch=`echo "$pkgname" | sed 's/.*_\(.*\).deb$/\1/'`
    distro=`echo "$pkgname" | sed 's/.*~\(.*\)_.*.deb$/\1/'`
    echo "pushing $pkgname of $arch to $distro"
     push_to_repo "debian-staging" \
         "pool/${pkgname};deb.distribution=${distro};deb.component=contrast;deb.architecture=${arch}" \
         $p
done

exit 0
