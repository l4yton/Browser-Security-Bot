import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Optional

from discord import TextChannel
from discord.utils import escape_markdown
from discord.ext import commands, tasks


@dataclass
class Bug:
    reward: Optional[float]
    severity: Optional[str]
    cve: str
    description: str

    def discord_message(self) -> str:
        message = ""

        if self.reward:
            message += f"[${self.reward}] "
        if self.severity:
            message += f"({self.severity}) "

        assert self.cve
        assert self.description
        message += f"{self.cve}: {escape_markdown(self.description)}."

        return message


@dataclass
class DisclosuresConfig:
    firefox_channel_id: Optional[int]


class DisclosuresTracker(ABC):
    channel: TextChannel
    latest_run: Optional[time.struct_time]

    def __init__(self, channel: TextChannel):
        self.channel = channel
        self.latest_run = None

    async def check_for_new_disclosures(self):
        start_time = time.localtime()

        if self.latest_run is None:
            self.latest_run = start_time
            return

        bugs = await self.find_latest_disclosures()
        for bug in bugs:
            await self.channel.send(bug.discord_message())
            await asyncio.sleep(1)

    @abstractmethod
    async def find_latest_disclosures(self) -> List[Bug]:
        """
        Returns a list of the latest disclosed security bugs.
        """
        raise NotImplementedError


class FirefoxDisclosuresTracker(DisclosuresTracker):

    async def find_latest_disclosures(self) -> List[Bug]:
        return []


class DisclosuresCog(commands.Cog):
    bot: commands.Bot
    firefox: FirefoxDisclosuresTracker

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.firefox = None

        self.check_for_new_disclosures.start()

    @commands.Cog.listener()
    async def on_ready(self):
        # We may end up here on a reconnect.
        if self.firefox:
            return

        with open("config.json", "r") as f:
            data = json.load(f)

        if not "disclosures" in data:
            return

        # The values for this Cog are in "disclosures". Try to initialize
        # with the provided configuration.
        config = DisclosuresConfig(**data["disclosures"])

        channel = self.bot.get_channel(config.firefox_channel_id)
        if channel:
            self.firefox = FirefoxDisclosuresTracker(channel)

    async def cog_unload(self):
        async with asyncio.Lock():
            # This is not super efficient, but we don't really care.
            with open("config.json", "r") as f:
                data = json.load(f)

            firefox_channel_id = self.firefox.channel.id if self.firefox else None

            config = DisclosuresConfig(firefox_channel_id=firefox_channel_id, )
            # Every Cog is responsible for its own values and has to make sure
            # not to override any others.
            data["disclosures"] = asdict(config)

            with open("config.json", "w") as f:
                json.dump(data, f)

            return await super().cog_unload()

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: commands.Context):
        if self.firefox and self.firefox.channel.id == channel.id:
            self.firefox = None

    @tasks.loop(hours=12)
    async def check_for_new_disclosures(self):
        if self.firefox:
            await self.firefox.check_for_new_disclosures()

    # TODO
