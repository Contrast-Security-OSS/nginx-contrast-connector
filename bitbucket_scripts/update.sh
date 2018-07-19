#!/bin/bash

set -e
setup_directory() {
    cp bitbucket_scripts/Dockerfile .
}


build_base_image() {
    local imageId="123";
    docker build --no-cache -t universal-base-image . && \
    imageId=$(docker image ls -q | head -n 1) && \
    echo "About to upload the following image: ${imageId}" && \
    docker tag $imageId contrastsecurity-docker-local.jfrog.io/universal-agent-base
}

push_image() {
    docker push contrastsecurity-docker-local.jfrog.io/universal-agent-base
}

setup_directory
build_base_image
push_image
exit 0