from typing import List

from discord.ext import commands, tasks


class ArXivCog(commands.Cog):
    bot: commands.Bot
    categories: List[str]

    def __init__(self, bot: commands.Bot):
        self.bot = bot
        self.categories = []

    @tasks.loop(hours=24)
    async def check_for_new_papers():
        pass
