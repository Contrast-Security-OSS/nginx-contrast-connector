#!/bin/bash

if [ -d "/opt/teamserver-data" ]; then
  CONTRAST_DATA_DIR=/opt/teamserver-data
else
  CONTRAST_DATA_DIR=/secure/contrast
fi

CURRENT_ARTIFACT_PATH="$CONTRAST_DATA_DIR"/agents/proxy/nginx/deployedVersion.txt
CURRENT_BUILD_NUMBER=$(cat "$CURRENT_ARTIFACT_PATH")

test -f ${CURRENT_ARTIFACT_PATH}

if [ $? -eq 0 ]; then

    MESSAGE="[$HOSTNAME] => Webserver Agent upgrade to build ${CURRENT_BUILD_NUMBER} succeeded (partyparrot)"
    COLOR=green

    newrelic_env=$(cat /etc/init.d/tomcat  | grep "newrelic.environment" | sed 's/^.*newrelic.environment=//g' | sed 's/ .*$//g' | sed 's/\"//g')
    APPNAME=$(cat /opt/newrelic/newrelic.yml | grep -A 2 "$newrelic_env" | tail -1 | sed 's/^.*app_name: //g')

    raw_appid=$(curl -X GET 'https://api.newrelic.com/v2/applications.json' \
     -H "X-Api-Key:d65102533a14c3db160300b73306514e8f7519426ac8f9f" -i \
     -d "filter[name]=${APPNAME}")

    APPID=$(echo $raw_appid | grep -Po '"id":.*?[^\\]",' | sed 's/^.*id\"://g' | sed 's/,.*$//g' | head -1)

    curl -X POST "https://api.newrelic.com/v2/applications/"$APPID"/deployments.json" \
     -H 'X-Api-Key:d65102533a14c3db160300b73306514e8f7519426ac8f9f' -i \
     -H 'Content-Type: application/json' \
     -d "{ \"deployment\": { \"revision\": \"Webserver-Agent build $CURRENT_BUILD_NUMBER\", \"description\": \"Version $CURRENT_BUILD_NUMBER Deployed by CodeDeploy\",\"user\": \"lambda\" } }"

else
    MESSAGE="[$HOSTNAME] => Webserver-Agent upgrade to build ${CURRENT_BUILD_NUMBER} FAILED (ohno)"
    COLOR=red
fi

ROOM_ID=4280476
AUTH_TOKEN=5jBWGp0rR1EdHE6PeckyiICA3eQ8GrqzPNbrCjJm

curl -H "Content-Type: application/json" \
     -X POST \
     -d "{\"color\": \"$COLOR\", \"message_format\": \"text\", \"message\": \"$MESSAGE\" }" \
     https://api.hipchat.com/v2/room/$ROOM_ID/notification?auth_token=$AUTH_TOKEN
