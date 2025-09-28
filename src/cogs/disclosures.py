import asyncio
import json
import logging
import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import List, Optional

import httpx
from discord import TextChannel
from discord.utils import escape_markdown
from discord.ext import commands, tasks


@dataclass
class Bug:
    reward: Optional[float]
    severity: Optional[str]
    description: str
    report_link: str

    def discord_message(self) -> str:
        message = ""

        if self.reward:
            message += f"[${self.reward}] "
        if self.severity:
            message += f"({self.severity}) "

        assert self.description
        assert self.report_link
        message += f"[{escape_markdown(self.description)}](<{self.report_link}>)"

        return message


@dataclass
class DisclosuresConfig:
    firefox_channel_id: Optional[int]


class DisclosuresTracker(ABC):
    channel: TextChannel
    latest_run: Optional[datetime.datetime]

    def __init__(self, channel: TextChannel):
        self.channel = channel
        self.latest_run = None

    async def check_for_new_disclosures(self):
        start_time = datetime.datetime.now(datetime.timezone.utc).replace(
            microsecond=0, tzinfo=None)

        if self.latest_run is None:
            self.latest_run = start_time
            return

        bugs = await self.find_latest_disclosures()
        for bug in bugs:
            await self.channel.send(bug.discord_message())
            await asyncio.sleep(1)

        self.latest_run = start_time

    @abstractmethod
    async def find_latest_disclosures(self) -> List[Bug]:
        """
        Returns a list of the latest disclosed security bugs.
        """
        raise NotImplementedError


class FirefoxDisclosuresTracker(DisclosuresTracker):

    async def find_latest_disclosures(self) -> List[Bug]:
        logging.info(
            "FirefoxDisclosureTracker: Finding latest disclosed bugs...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(
                "https://bugzilla.mozilla.org/rest/bug",
                params={
                    "o2": "substring",
                    "j5": "OR",
                    "v7": "core-security-release",
                    "o11": "changedfrom",
                    "v8": "crypto-core-security",
                    "f6": "bug_group",
                    "o14": "changedfrom",
                    "f13": "bug_group",
                    "v3": self.latest_run.isoformat(),
                    "f10": "bug_group",
                    "v15": "mobile-core-security",
                    "f2": "bug_group",
                    "v9": "dom-core-security",
                    "f11": "bug_group",
                    "v16": "network-core-security",
                    "v12": "javascript-core-security",
                    "f14": "bug_group",
                    "o6": "changedfrom",
                    "keywords": "sec-critical sec-high sec-moderate sec-low",
                    "o10": "changedfrom",
                    "o13": "changedfrom",
                    "f1": "OP",
                    "o3": "changedafter",
                    "f5": "OP",
                    "v14": "media-core-security",
                    "f12": "bug_group",
                    "f16": "bug_group",
                    "o8": "changedfrom",
                    "v11": "gfx-core-security",
                    "f4": "CP",
                    "f9": "bug_group",
                    "v2": "core-security",
                    "f15": "bug_group",
                    "o7": "changedfrom",
                    "v10": "firefox-core-security",
                    "f3": "bug_group",
                    "v13": "mail-core-security",
                    "keywords_type": "anywords",
                    "v6": "core-security",
                    "o16": "changedfrom",
                    "f8": "bug_group",
                    "o12": "changedfrom",
                    "f7": "bug_group",
                    "f17": "CP",
                    "j1": "AND_G",
                    "o15": "changedfrom",
                    "n2": "1",
                    "o9": "changedfrom",
                    "resolution": "FIXED"
                })

        bugs = []
        for bug in resp.json()["bugs"]:
            severity = self.extract_severity_from(bug["keywords"])
            description = bug["summary"]
            report_link = "https://bugzilla.mozilla.org/show_bug.cgi?id=" + str(
                bug["id"])

            bugs.append(
                Bug(severity=severity,
                    description=description,
                    report_link=report_link))

        return bugs

    def extract_severity_from(keywords: List[str]) -> Optional[str]:
        if "sec-low" in keywords:
            return "low"
        if "sec-moderate" in keywords:
            return "moderate"
        if "sec-high" in keywords:
            return "high"
        if "sec-critical" in keywords:
            return "critical"

        return None


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

            config = DisclosuresConfig(firefox_channel_id=firefox_channel_id)
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

    @commands.group()
    async def disclosures(self, ctx: commands.Context):
        if ctx.invoked_subcommand is None:
            await ctx.send(
                f"Invalid subcommand. Valid values are: add, remove or list")

    @disclosures.command(name="add")
    async def disclosures_add(self, ctx: commands.Context, arg: str):
        # Check if the tracker is already running.
        if arg == "firefox" and self.firefox:
            await ctx.send(
                f"FirefoxDisclosuresTracker is already running in <#{self.firefox.channel.id}>"
            )
            return

        match arg:
            case "firefox":
                self.firefox = FirefoxDisclosuresTracker(ctx.channel)
                await ctx.send(
                    "Firefox disclosures will now be sent to this channel")
            case _:
                await ctx.send("Invalid argument. Valid values are: firefox")

    @disclosures.command(name="remove")
    async def disclosures_remove(self, ctx: commands.Context, arg: str):
        # Check if the tracker is running in the channel the message
        # originated from.
        if arg == "firefox" and not (self.firefox and self.firefox.channel.id
                                     == ctx.channel.id):
            await ctx.send(
                "There is currently no FirefoxDisclosuresTracker running in this channel"
            )
            return

        match arg:
            case "firefox":
                self.firefox = None
                await ctx.send(
                    "Firefox disclosures will no longer be sent to this channel"
                )
            case _:
                await ctx.send("Invalid argument. Valid values are: firefox")

    @disclosures.command(name="list")
    async def disclosures_list(self, ctx: commands.Context):
        firefox_channel_message = f"<#{self.firefox.channel.id}>" if self.firefox else "null"

        await ctx.send(
            f"- FirefoxDisclosuresTracker: {firefox_channel_message}")
