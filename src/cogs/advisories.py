import asyncio
import logging
import re
from dataclasses import dataclass
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
class AdvisoriesTracker:
    channel: TextChannel
    latest_advisory_url: Optional[str]

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

    async def find_latest_advisory_urls(self) -> List[str]:
        raise NotImplementedError

    async def collect_bugs_from_advisory(self, _url: str) -> List[Bug]:
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

            cve_or_bug_id_elem = impact_elem.find_next().find_next()
            if cve_or_bug_id_elem.name == "div":
                report_link = "https://bugs.webkit.org/show_bug.cgi?id=" + cve_or_bug_id_elem.text.split(
                    ":")[1].strip()
                commit_link = f"https://github.com/search?q=repo:WebKit/WebKit+%22{quote(report_link)}%22&type=commits"

                cve_or_bug_id_elem = cve_or_bug_id_elem.find_next_sibling()

            cve = cve_or_bug_id_elem.text.split(":")[0].strip()

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

    @tasks.loop(hours=12)
    async def check_for_new_advisory(self):
        logging.info("AdvisoriesCog: Checking for any new adivsory...")

        if self.chrome:
            await self.chrome.check_for_new_advisory()

        if self.firefox:
            await self.firefox.check_for_new_advisory()

        if self.safari:
            await self.safari.check_for_new_advisory()

    @commands.command()
    async def advisories(self, ctx: commands.Context, value: str):
        if value == "chrome":
            self.chrome = ChromeAdvisoriesTracker(ctx.channel, None)
            await ctx.send(
                "Chrome advisories will now be sent to this channel :white_check_mark:"
            )
            return

        if value == "firefox":
            self.firefox = FirefoxAdvisoriesTracker(ctx.channel, None)
            await ctx.send(
                "Firefox advisories will now be sent to this channel :white_check_mark:"
            )
            return

        if value == "safari":
            self.safari = SafariAdvisoriesTracker(ctx.channel, None)
            await ctx.send(
                "Safari advisories will now be sent to this channel :white_check_mark:"
            )
            return

        await ctx.send(
            "Unrecognized value. Valid values are \"chrome\", \"firefox\" or \"safari\"."
        )
