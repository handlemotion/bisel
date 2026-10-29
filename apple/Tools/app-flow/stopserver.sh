#!/bin/zsh
pkill -f "wrangler dev --port 8790"; pkill -f "workerd.*8790"; sleep 2; echo stopped
