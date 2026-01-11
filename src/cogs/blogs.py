import asyncio
import datetime
import json
import logging
import time
from typing import Dict, Optional

import feedparser
from discord.ext import commands, tasks
from discord.utils import escape_markdown


class BlogsCog(commands.Cog):
    bot: commands.Bot
    entries: Dict[int, Dict[str, str]]
    latest_run: Optional[datetime.datetime]

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.entries = {}
        self.latest_run = None

        self.check_for_new_blogs.start()

    @commands.Cog.listener()
    async def on_ready(self):
        if len(self.entries) > 0:
            return

        with open("config.json", "r") as f:
            data = json.load(f)

        if not "blogs" in data:
            return

        # When dumping to JSON, the channel ids are converted to strings,
        # so we need to convert them back.
        for (channel_id, blogs) in data["blogs"].items():
            self.entries[int(channel_id)] = {}
            for (name, url) in blogs.items():
                self.entries[int(channel_id)][name] = url

    async def cog_unload(self):
        async with asyncio.Lock():
            # This is not super efficient, but we don't really care.
            with open("config.json", "r") as f:
                data = json.load(f)

            data["blogs"] = self.entries

            with open("config.json", "w") as f:
                json.dump(data, f)

        return await super().cog_unload()

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: commands.Context):
        if channel.id in self.entries:
            del self.entries[channel.id]

    @tasks.loop(hours=6)
    async def check_for_new_blogs(self):
        start_time = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0, tzinfo=None)

        if self.latest_run is None:
            self.latest_run = start_time
            return

        for (channel_id, blogs) in self.entries.items():
            for (name, url) in blogs.items():
                try:
                    # Avoid feedparser blocking everything if it gets stuck.
                    async with asyncio.timeout(10):
                        feed = await asyncio.to_thread(feedparser.parse, url)
                except Exception as e:
                    logging.error(f"Failed to request blog @ {url}: {e}")
                    continue

                for post in feed["entries"]:
                    published = datetime.datetime.fromtimestamp(
                        time.mktime(post["published_parsed"]))
                    if published > self.latest_run:
                        await self.bot.get_channel(channel_id).send(
                            f"{name}: [{escape_markdown(post['title'])}](<{post['link']}>)"
                        )

                await asyncio.sleep(1)

        self.latest_run = start_time

    @check_for_new_blogs.error
    async def check_for_new_blogs_error(self, error):
        logging.error(
            f"BlogsCog: An error occurred during check_for_new_blogs",
            exc_info=error)

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
    async def blogs_remove(self, ctx: commands.Context, name: str):
        if (not ctx.channel.id
                in self.entries) or (not name in self.entries[ctx.channel.id]):
            await ctx.send(f"There is no entry for {name} in this channel")
            return

        url = self.entries[ctx.channel.id][name]

        del self.entries[ctx.channel.id][name]
        if len(self.entries[ctx.channel.id]) == 0:
            del self.entries[ctx.channel.id]

        await ctx.send(
            f"Posts from [{name}](<{url}>) will no longer be sent to this channel"
        )

    @blogs.command(name="list")
    async def blogs_list(self, ctx: commands.Context):
        if len(self.entries) == 0:
            await ctx.send("There are currently no entries")
            return

        await ctx.send("\n".join([
            f"<#{channel_id}>: " +
            ", ".join([f"[{name}](<{url}>)" for (name, url) in blogs.items()])
            for (channel_id, blogs) in self.entries.items()
        ]))
