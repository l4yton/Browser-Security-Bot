import asyncio
import json
import time
from typing import Dict, Optional

import feedparser
from discord.ext import commands, tasks


class BlogsCog(commands.Cog):
    bot: commands.Bot
    entries: Dict[int, Dict[str, str]]
    latest_run: Optional[int]

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.entries = {}
        self.latest_run = None

        self.check_for_new_blogs.start()

    @commands.Cog.listener()
    async def on_ready(self):
        # We may end up here on a reconnect.
        if len(self.entries) > 0:
            return

        with open("config.json", "r") as f:
            data = json.load(f)

        if not "blogs" in data:
            return

        for (channel_id, blogs) in data["blogs"].items():
            channel_id = int(channel_id)
            self.entries[channel_id] = {}
            for (name, url) in blogs.items():
                self.entries[channel_id][name] = url

    async def cog_unload(self):
        async with asyncio.Lock():
            # This is not super efficient, but we don't really care.
            with open("config.json", "r") as f:
                data = json.load(f)

            data["blogs"] = {}
            for (channel_id, blogs) in self.entries.items():
                data["blogs"][channel_id] = {}
                for (name, url) in blogs.items():
                    data["blogs"][channel_id][name] = url

            with open("config.json", "w") as f:
                json.dump(data, f)

            return await super().cog_unload()

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: commands.Context):
        del self.entries[channel.id]

    @tasks.loop(hours=12)
    async def check_for_new_blogs(self):
        start_time = time.localtime()

        if self.latest_run is None:
            self.latest_run = start_time
            return

        for (channel_id, blogs) in self.entries.items():
            for (name, url) in blogs.items():
                feed = feedparser.parse(url)
                for post in feed["entries"]:
                    if start_time > post["published_parsed"]:
                        channel = self.bot.get_channel(channel_id)
                        link = post["link"]

                        assert channel
                        await channel.send(f"[{name}] <{link}>")

                asyncio.sleep(1)

        self.latest_run = start_time

    @commands.group()
    async def blogs(self, ctx: commands.Context):
        if ctx.invoked_subcommand is None:
            await ctx.send(
                f"Invalid subcommand. Valid values are: add, remove or list")

    @blogs.command(name="add")
    async def blogs_add(self, ctx: commands.Context, name: str, url: str):
        if not ctx.channel.id in self.entries:
            self.entries[ctx.channel.id] = {}

        if name in self.entries[ctx.channel.id]:
            await ctx.send(
                f"An entry for {name} already exists in this channel")
            return

        self.entries[ctx.channel.id][name] = url
        await ctx.send(
            f"Posts from [{name}](<{url}>) will now be sent to this channel")

    @blogs.command(name="remove")
    async def blogs_remove(self, ctx: commands.Context, name: str, url: str):
        if not ctx.channel.id in self.entries:
            self.entries[ctx.channel.id] = {}

        if not name in self.entries[ctx.channel.id]:
            await ctx.send(f"There is no entry for {name} in this channel")
            return

        del self.entries[ctx.channel.id][name]
        await ctx.send(
            f"Posts from [{name}](<{url}>) will no longer be sent to this channel"
        )

    @blogs.command(name="list")
    async def blogs_list(self, ctx: commands.Context):
        if len(self.entries) == 0:
            await ctx.send("There are currently no entries")

        await ctx.send("\n".join([
            f"<#{channel_id}>: " +
            ", ".join([f"[{name}](<{url}>)" for (name, url) in blogs.items()])
            for (channel_id, blogs) in self.entries.items()
        ]))
