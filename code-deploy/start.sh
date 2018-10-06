#!/bin/bash

if [ -d "/opt/teamserver-data" ]; then
  CONTRAST_DATA_DIR=/opt/teamserver-data
else
  CONTRAST_DATA_DIR=/secure/contrast
fi

CURRENT_ARTIFACT_PATH="$CONTRAST_DATA_DIR"/agents/proxy/nginx/
if [ -f "$CONTRAST_DATA_DIR"/agents/proxy/nginx/deployedVersion.txt ]
then
CURRENT_BUILD_NUMBER=$(cat "$CONTRAST_DATA_DIR"/agents/proxy/nginx/deployedVersion.txt)
else
CURRENT_BUILD_NUMBER="N/A"
fi

FUTURE_ARTIFACT=/tmp/contrast-webserver-agent-WEBSERVER_BASE_VERSION.zip
FUTURE_BUILD_NUMBER=$(echo ${FUTURE_ARTIFACT} | grep -Eo "([0-9]+\.){2}[0-9]")

ROOM_ID=4280476
AUTH_TOKEN=5jBWGp0rR1EdHE6PeckyiICA3eQ8GrqzPNbrCjJm
MESSAGE="[$HOSTNAME] => Upgrading Webserver Agent from build ${CURRENT_BUILD_NUMBER} to build ${FUTURE_BUILD_NUMBER}"

curl -H "Content-Type: application/json" \
     -X POST \
     -d "{\"color\": \"gray\", \"message_format\": \"text\", \"message\": \"$MESSAGE\" }" \
     https://api.hipchat.com/v2/room/$ROOM_ID/notification?auth_token=$AUTH_TOKEN

unzip ${FUTURE_ARTIFACT} -d ${CURRENT_ARTIFACT_PATH}

echo ${FUTURE_BUILD_NUMBER} > "$CONTRAST_DATA_DIR"/agents/proxy/nginx/deployedVersion.txt
