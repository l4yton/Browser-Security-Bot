#!/usr/bin/env python

import asyncio
import os

from discord import Intents
from discord.ext import commands

from cogs import advisories, arxiv, blogs, disclosures

TOKEN = os.environ.get("BROWSER_SECURITY_BOT")


async def main():
    bot = commands.Bot(command_prefix="%", intents=Intents.all())

    await bot.add_cog(advisories.AdvisoriesCog(bot))
    await bot.add_cog(arxiv.ArXivCog(bot))
    await bot.add_cog(blogs.BlogsCog(bot))
    await bot.add_cog(disclosures.DisclosuresCog(bot))

    await bot.start(TOKEN)


if __name__ == "__main__":
    asyncio.run(main())
