import logging
import os

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

logging.basicConfig(level=logging.DEBUG)

app = App(token=os.environ.get("SLACK_BOT_TOKEN"))

if __name__ == "__main__":
    SocketModeHandler(app, os.environ.get("SLACK_APP_TOKEN")).start()
