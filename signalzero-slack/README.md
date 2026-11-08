# Bolt for Python Blank Template

This is a blank [Bolt for Python](https://docs.slack.dev/tools/bolt-python/) template app used to start building new Slack apps.

## Setup

Before getting started, make sure you have a development workspace where you have permissions to install apps. If you don't have one setup, go ahead and [create one](https://slack.com/create).

### Developer Program

Join the [Slack Developer Program](https://api.slack.com/developer-program) for exclusive access to sandbox environments for building and testing your apps, tooling, and resources created to help you build and grow.

### Claude Code, Codex, Cursor, and Other Coding Agents

Install the [Slack MCP and Skills Plugin](https://docs.slack.dev/ai/slack-skills-plugin/) so your coding agent can create, run, and deploy Slack apps, look up Web API methods and scopes, and build Block Kit without guessing.

#### Claude Code

Run this in a Claude Code session:

```
/plugin install slack@claude-plugins-official
```

#### Codex

Run this in your terminal:

```sh
codex plugin marketplace add slackapi/slack-skills-plugin
codex plugin add slack@slack
```

#### Cursor

Run this in a Cursor Agent chat:

```
/add-plugin slack
```

#### Other agents

Install the skills with `npx skills`, using your [agent's identifier](https://github.com/vercel-labs/skills#supported-agents):

```sh
npx skills add slackapi/slack-skills-plugin -y -a <agent>

# For example, OpenCode
npx skills add slackapi/slack-skills-plugin -y -a opencode
```

## Installation

<details><summary><strong>Using Slack CLI</strong></summary>

Install the latest version of the Slack CLI for your operating system:

- [Slack CLI for macOS & Linux](https://docs.slack.dev/tools/slack-cli/guides/installing-the-slack-cli-for-mac-and-linux/)
- [Slack CLI for Windows](https://docs.slack.dev/tools/slack-cli/guides/installing-the-slack-cli-for-windows/)

You'll also need to log in if this is your first time using the Slack CLI.

```sh
slack login
```

#### Initializing the project

```sh
slack create my-bolt-python-app --template slack-samples/bolt-python-blank-template
cd my-bolt-python-app
```

After cloning, you're all set to start developing!

</details>

<details><summary><strong>Using Terminal</strong></summary>

#### Create Your Slack App

1. Open [https://api.slack.com/apps/new](https://api.slack.com/apps/new) and choose "From an app manifest"
2. Choose the workspace you want to install the application to
3. Copy the contents of [manifest.json](./manifest.json) into the text box that says `*Paste your manifest code here*` (within the JSON tab) and click *Next*
4. Review the configuration and click *Create*
5. Click *Install to Workspace* and *Allow* on the screen that follows. You'll then be redirected to the App Configuration dashboard.

#### Environment Variables

Before you can run the app, you'll need to store some environment variables.

1. Open your apps configuration page from [this list](https://api.slack.com/apps), click **OAuth & Permissions** in the left hand menu, then copy the Bot User OAuth Token. You will store this in your environment as `SLACK_BOT_TOKEN`.
2. Click **Basic Information** from the left hand menu and follow the steps in the App-Level Tokens section to create an app-level token with the `connections:write` scope. Copy this token. You will store this in your environment as `SLACK_APP_TOKEN`.

```zsh
# Replace with your app token and bot token
export SLACK_BOT_TOKEN=<your-bot-token>
export SLACK_APP_TOKEN=<your-app-token>
```

#### Initializing the project

```sh
git clone https://github.com/slack-samples/bolt-python-blank-template.git my-bolt-python-app
cd my-bolt-python-app
```

#### Setup your python virtual environment

```sh
python3 -m venv .venv
source .venv/bin/activate  # for Windows OS, .\.venv\Scripts\Activate instead should work
```

#### Install dependencies

```sh
pip install -e ".[dev]"
```

</details>

## Development

### Starting the app

#### Slack CLI

```sh
slack run
```

#### Terminal

```sh
python3 app.py
```

### Linting

```zsh
# Run ruff from root directory for linting
ruff check

# Run ruff from root directory for code formatting
ruff format
```

## Resources

To learn more about developing Slack apps, visit the following pages:

- [API docs](https://docs.slack.dev)
- [Bolt for Python docs](https://docs.slack.dev/tools/bolt-python/)
