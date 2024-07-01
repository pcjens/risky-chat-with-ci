#!/bin/sh
set -e

echo "[$0] Building server..."
cc riskychat.c -otest_riskychat
echo "[$0] Launching server..."
./test_riskychat 127.0.0.1 12345 >/dev/null &
SERVER_PID=$!
sleep 1 # wait for the server to be functional, since it lacks a "daemonized" mode

echo "[$0] Server forked off, running tests..."


# Create the user
curl -s --no-keepalive -d "name=testuser" http://127.0.0.1:12345/login
# Post a message
curl -s --no-keepalive --cookie "riskyid=1" -d "content=hellooo" http://127.0.0.1:12345/post
sleep 1
# Check that the message is now shown on the page
curl -s --no-keepalive --cookie "riskyid=1" http://127.0.0.1:12345/ | grep 'hellooo' >/dev/null

echo "[$0] Tests passed! Shutting down the server and cleaning up..."
kill -s TERM $SERVER_PID
kill -s KILL $SERVER_PID
sleep 1 # wait for it to really die? port seems to stay bound...

rm test_riskychat
