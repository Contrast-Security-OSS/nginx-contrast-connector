# Overview

Make a "bleeding edge" contrast-service + nginx WAF.  Builds everything from
source.

# prep

From _this_ directory, checkout the speedracer version you want to use:

    git clone https://bitbucket.org/contrastsecurity/go-speedracer-go.git

The above cmd will just grab the head of the main branch.  This checkout _must_
be in `nginx-speedracer-connector/docker-builds/go-speedracer-go`.

# build the docker image.

The context of the docker image is the root dir of this project. So:

    cd nginx-speedracer-connector
    docker build -f docker-builds/Dockerfile -t contrast/waf-screener .

# Run and test

This will make an image that will listen on port 80.  You can start it with:

    docker run -p 8884:80 -it contrast/waf-screener

You can test with following from the host system.

    curl http://localhost:8884
