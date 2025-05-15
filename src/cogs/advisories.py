import asyncio
import json
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, List
from urllib.parse import urlparse, parse_qs, quote

import httpx
from bs4 import BeautifulSoup
from discord import TextChannel
from discord.utils import escape_markdown
from discord.ext import commands, tasks

CHROME_SECURITY_FIX_RE = r"(\[\$(\d+)\])?\[(\d+)\] (Low|Medium|High|Critical) (CVE\-\d+\-\d+): ([^\.]+)"


@dataclass
class Bug:
    reward: Optional[float]
    severity: Optional[str]
    cve: str
    description: str
    report_link: Optional[str]
    commit_link: Optional[str]

    def discord_message(self) -> str:
        message = ""

        if self.reward:
            message += f"[${self.reward}] "
        if self.severity:
            message += f"({self.severity}) "

        assert self.cve
        assert self.description

        message += f"{self.cve}: {escape_markdown(self.description)}."

        if self.report_link:
            message += f" -- [Report](<{self.report_link}>)."
        if self.commit_link:
            message += f" -- [Commit(s)](<{self.commit_link}>)."

        return message


@dataclass
class AdvisoriesConfig:
    chrome_channel_id: Optional[int]
    firefox_channel_id: Optional[int]
    safari_channel_id: Optional[int]


class AdvisoriesTracker(ABC):
    channel: TextChannel
    latest_advisory_url: Optional[str]

    def __init__(self, channel: TextChannel):
        self.channel = channel
        self.latest_advisory_url = None

    async def check_for_new_advisory(self):
        urls = await self.find_latest_advisory_urls()

        if self.latest_advisory_url is None:
            self.latest_advisory_url = urls[0]
            return

        for url in urls:
            if url == self.latest_advisory_url:
                break

            bugs = await self.collect_bugs_from_advisory(url)
            for bug in bugs:
                await self.channel.send(bug.discord_message())
                await asyncio.sleep(1)

        self.latest_advisory_url = urls[0]

    @abstractmethod
    async def find_latest_advisory_urls(self) -> List[str]:
        """
        Returns a list of urls of the latest security advisories, starting
        with the newest.
        """
        raise NotImplementedError

    @abstractmethod
    async def collect_bugs_from_advisory(self, _url: str) -> List[Bug]:
        """
        Returns a list of bugs collected from the given url of a security
        advisory, in no particular order.
        """
        raise NotImplementedError


class ChromeAdvisoriesTracker(AdvisoriesTracker):

    async def find_latest_advisory_urls(self) -> List[str]:
        logging.info(
            "ChromeAdvisoriesTracker: Finding latest advisory URLs...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(
                "https://chromereleases.googleblog.com/search/label/Stable%20updates"
            )

        soup = BeautifulSoup(resp.content, "html.parser")
        urls = []

        for elem in soup.find_all("div", class_="post"):
            if a := elem.find("a"):
                urls.append(a["href"])

        return urls

    async def collect_bugs_from_advisory(self, url: str) -> List[Bug]:
        logging.info(f"ChromeAdvisoriesTracker: Collecting bugs from {url}...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url)

        soup = BeautifulSoup(resp.content, "html.parser")
        bugs = []

        for fix in re.findall(CHROME_SECURITY_FIX_RE, soup.text):
            bugs.append(
                Bug(reward=fix[1],
                    severity=fix[3],
                    cve=fix[4],
                    description=fix[5],
                    report_link="https://issues.chromium.org/issues/" + fix[2],
                    commit_link=
                    "https://chromium-review.googlesource.com/q/message:" +
                    fix[2]))

        return bugs


class FirefoxAdvisoriesTracker(AdvisoriesTracker):

    async def find_latest_advisory_urls(self) -> List[str]:
        logging.info(
            "FirefoxAdvisoriesTracker: Finding latest advisory URLs...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(
                "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/"
            )

        soup = BeautifulSoup(resp.content, "html.parser")
        urls = []

        for elem in soup.find("article").find_all("ul"):
            if a := elem.find("a"):
                urls.append("https://www.mozilla.org" + a["href"])

        return urls

    async def collect_bugs_from_advisory(self, url: str) -> List[Bug]:
        logging.info(
            f"FirefoxAdvisoriesTracker: Collecting bugs from {url}...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url)

        soup = BeautifulSoup(resp.content, "html.parser")
        bugs = []

        for elem in soup.find_all("section", attrs={"class": "cve"}):
            cve = elem.find_next().attrs["id"]
            description = elem.find_next().text.split(":")[1].strip()
            severity = elem.find("span", {"class": "level"}).text
            report_link = elem.find("ul").find("a")["href"]

            # ?id=12345             -- single bug id
            # ?bug_id=12345, 12346  -- multiple bug ids
            query = parse_qs(urlparse(report_link).query)
            bug_qs = query["id"][0] if "id" in query else query["bug_id"][0]
            search = " OR ".join(
                ["\"Bug: " + bug_id + "\"" for bug_id in bug_qs.split(",")])
            commit_link = f"https://github.com/search?q=repo%3amozilla%2fgecko-dev+{quote(search)}&type=commits"

            bugs.append(
                Bug(reward=None,
                    severity=severity,
                    cve=cve,
                    description=description,
                    report_link=report_link,
                    commit_link=commit_link))

        return bugs


class SafariAdvisoriesTracker(AdvisoriesTracker):

    async def find_latest_advisory_urls(self) -> List[str]:
        logging.info(
            "SafariAdvisoriesTracker: Finding latest advisory URLs...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get("https://support.apple.com/en-us/100100")

        soup = BeautifulSoup(resp.content, "html.parser")
        urls = []

        for column in soup.find("table").find_all("tr"):
            rows = column.find_all("td")
            if not (len(rows) == 3 and rows[0].text.startswith("Safari")):
                continue

            if a := rows[0].find("a"):
                urls.append("https://support.apple.com" + a["href"])

        return urls

    async def collect_bugs_from_advisory(self, url: str) -> List[Bug]:
        logging.info(f"SafariAdvisoriesTracker: Collecting bugs from {url}...")
        async with httpx.AsyncClient(follow_redirects=True) as client:
            resp = await client.get(url)

        soup = BeautifulSoup(resp.content, "html.parser")
        bugs = []

        for elem in soup.find_all("h3"):
            report_link = None
            commit_link = None

            impact_elem = elem.find_next().find_next()
            description = impact_elem.text.replace("Impact: ", "").strip()

            # Sanity check that the element is actually for a bug.
            if "Impact" not in impact_elem.text:
                continue

            cve_or_bug_id_elem = impact_elem.find_next().find_next()
            if cve_or_bug_id_elem.name == "div":
                report_link = "https://bugs.webkit.org/show_bug.cgi?id=" + cve_or_bug_id_elem.text.split(
                    ":")[1].strip()
                commit_link = f"https://github.com/search?q=repo:WebKit/WebKit+%22{quote(report_link)}%22&type=commits"

                cve_or_bug_id_elem = cve_or_bug_id_elem.find_next_sibling()

            cve = cve_or_bug_id_elem.text.split(":")[0].strip()
            if not cve.startswith("CVE"):
                break

            bugs.append(
                Bug(reward=None,
                    severity=None,
                    cve=cve,
                    description=description,
                    report_link=report_link,
                    commit_link=commit_link))

        return bugs


class AdvisoriesCog(commands.Cog):
    bot: commands.Bot
    chrome: Optional[ChromeAdvisoriesTracker]
    firefox: Optional[FirefoxAdvisoriesTracker]
    safari: Optional[SafariAdvisoriesTracker]

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.chrome = None
        self.firefox = None
        self.safari = None

        self.check_for_new_advisory.start()

    @commands.Cog.listener()
    async def on_ready(self):
        # We may end up here on a reconnect.
        if self.chrome or self.firefox or self.safari:
            return

        with open("config.json", "r") as f:
            data = json.load(f)

        if not "advisories" in data:
            return

        # The values for this Cog are in "advisories". Try to initialize
        # with the provided configuration.
        config = AdvisoriesConfig(**data["advisories"])

        channel = self.bot.get_channel(config.chrome_channel_id)
        if channel:
            self.chrome = ChromeAdvisoriesTracker(channel)
            await channel.send(
                "Chrome advisories will now be sent to this channel :smiley:")

        channel = self.bot.get_channel(config.firefox_channel_id)
        if channel:
            self.firefox = FirefoxAdvisoriesTracker(channel)
            await channel.send(
                "Firefox advisories will now be sent to this channel :smiley:")

        channel = self.bot.get_channel(config.safari_channel_id)
        if channel:
            self.safari = SafariAdvisoriesTracker(channel)
            await channel.send(
                "Safari advisories will now be sent to this channel :smiley:")

    async def cog_unload(self):
        # This is not super efficient, but we don't really care.
        with open("config.json", "r") as f:
            data = json.load(f)

        chrome_channel_id = self.chrome.channel.id if self.chrome else None
        firefox_channel_id = self.firefox.channel.id if self.firefox else None
        safari_channel_id = self.safari.channel.id if self.safari else None

        config = AdvisoriesConfig(chrome_channel_id=chrome_channel_id,
                                  firefox_channel_id=firefox_channel_id,
                                  safari_channel_id=safari_channel_id)
        # Every Cog is responsible for its own values and has to make sure
        # not to override any others.
        data["advisories"] = asdict(config)

        with open("config.json", "w") as f:
            json.dump(data, f)

        return await super().cog_unload()

    @commands.Cog.listener()
    async def on_guild_channel_delete(self, channel: commands.Context):
        if self.chrome and self.chrome.channel.id == channel.id:
            self.chrome = None

        if self.firefox and self.firefox.channel.id == channel.id:
            self.firefox = None

        if self.safari and self.safari.channel.id == channel.id:
            self.safari = None

    @tasks.loop(hours=12)
    async def check_for_new_advisory(self):
        if self.chrome:
            await self.chrome.check_for_new_advisory()

        if self.firefox:
            await self.firefox.check_for_new_advisory()

        if self.safari:
            await self.safari.check_for_new_advisory()

    @commands.group()
    async def advisories(self, ctx: commands.Context):
        if ctx.invoked_subcommand is None:
            await ctx.send(
                f"Invalid subcommand. Valid values are: add, remove or list")

    @advisories.command(name="add")
    async def advisories_add(self, ctx: commands.Context, arg: str):
        # Check if the tracker is already running.
        if arg == "chrome" and self.chrome:
            await ctx.send(
                f"ChromeAdvisoriesTracker is already running in <#{self.chrome.channel.id}>"
            )
            return

        if arg == "firefox" and self.firefox:
            await ctx.send(
                f"FirefoxAdvisoriesTracker is already running in <#{self.firefox.channel.id}>"
            )
            return

        if arg == "safari" and self.safari:
            await ctx.send(
                f"SafariAdvisoriesTracker is already running in <#{self.safari.channel.id}>"
            )
            return

        match arg:
            case "chrome":
                self.chrome = ChromeAdvisoriesTracker(ctx.channel)
                await ctx.send(
                    "Chrome advisories will now be sent to this channel :smiley:"
                )
            case "firefox":
                self.firefox = FirefoxAdvisoriesTracker(ctx.channel)
                await ctx.send(
                    "Firefox advisories will now be sent to this channel :smiley:"
                )
            case "safari":
                self.safari = SafariAdvisoriesTracker(ctx.channel)
                await ctx.send(
                    "Safari advisories will now be sent to this channel :smiley:"
                )
            case _:
                await ctx.send(
                    "Invalid argument. Valid values are: chrome, firefox or safari"
                )

    @advisories.command(name="remove")
    async def advisories_remove(self, ctx: commands.Context, arg: str):
        # Check if the tracker is running in the channel the message
        # originated from.
        if arg == "chrome" and not (self.chrome and self.chrome.channel.id
                                    == ctx.channel.id):
            await ctx.send(
                "There is currently no ChromeAdvisoriesTracker running in this channel"
            )
            return

        if arg == "firefox" and not (self.firefox and self.firefox.channel.id
                                     == ctx.channel.id):
            await ctx.send(
                "There is currently no FirefoxAdvisoriesTracker running in this channel"
            )
            return

        if arg == "safari" and not (self.safari and self.safari.channel.id
                                    == ctx.channel.id):
            await ctx.send(
                "There is currently no SafariAdvisoriesTracker running in this channel"
            )
            return

        match arg:
            case "chrome":
                self.chrome = None
                await ctx.send(
                    "Chrome advisories will no longer be sent to this channel :pensive:"
                )
            case "firefox":
                self.firefox = None
                await ctx.send(
                    "Firefox advisories will no longer be sent to this channel :pensive:"
                )
            case "safari":
                self.safari = None
                await ctx.send(
                    "Safari advisories will no longer be sent to this channel :pensive:"
                )
            case _:
                await ctx.send(
                    "Invalid argument. Valid values are: chrome, firefox or safari."
                )

    @advisories.command(name="list")
    async def advisories_list(self, ctx: commands.Context):
        chrome_channel_message = f"<#{self.chrome.channel.id}>" if self.chrome else "null"
        firefox_channel_message = f"<#{self.firefox.channel.id}>" if self.firefox else "null"
        safari_channel_message = f"<#{self.safari.channel.id}>" if self.safari else "null"

        await ctx.send(
            f"- ChromeAdvisoriesTracker: {chrome_channel_message}\n" +
            f"- FirefoxAdvisoriesTracker: {firefox_channel_message}\n" +
            f"- SafariAdvisoriesTracker: {safari_channel_message}")
