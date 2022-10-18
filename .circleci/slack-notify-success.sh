#! /bin/sh

BUILD_STEP="$@"

curl -X POST -H 'Content-Type:application/json' -d '{"attachments": [{"color": "#7CD197", "fallback": "'"${BUILD_STEP}"' Notification: '$CIRCLE_BUILD_URL'", "title": "Homebase Garbage Collector '"${BUILD_STEP}"' Notification", "text": ":recycle: Homebase Garbage Collector successful '"${BUILD_STEP}"' :recycle:"}]}' $SLACK_WEBHOOK
