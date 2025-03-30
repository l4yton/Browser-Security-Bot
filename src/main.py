#!/usr/bin/env python

import asyncio
import logging
import os

from discord import Intents
from discord.ext import commands

from cogs import advisories, arxiv, blogs, disclosures

TOKEN = os.environ.get("BROWSER_SECURITY_BOT")


async def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    bot = commands.Bot(command_prefix="%", intents=Intents.all())
    await bot.add_cog(advisories.AdvisoriesCog(bot))
    await bot.add_cog(arxiv.ArXivCog(bot))
    await bot.add_cog(blogs.BlogsCog(bot))
    await bot.add_cog(disclosures.DisclosuresCog(bot))

    # Handle ctrl-c gracefully and make sure the cogs get unloaded
    # properly :)
    try:
        await bot.start(TOKEN)
    except (asyncio.exceptions.CancelledError, KeyboardInterrupt):
        await bot.close()


if __name__ == "__main__":
    asyncio.run(main())
