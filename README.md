# Browser Security Bot

A discord bot for (browser) security research. It allows you to monitor for new...
- ...Chrome/Firefox/Safari security advisories
- ...Chrome/Firefox disclosed security bugs (WIP)
- ...arXiv papers of your interest (WIP)
- ...posts in your favorite security blogs (WIP)

## Usage
You will need a token from discord for your bot. Afterwards, it's easiest to use [uv](https://github.com/astral-sh/uv):
```sh
BROWSER_SECURITY_BOT="..." uv run src/main.py
```

## TODO
- Improve logging
- Optionally initialize from configuration file
