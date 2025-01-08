from discord.ext import commands, tasks


class BlogsCog(commands.Cog):
    bot: commands.Bot

    def __init__(self, bot: commands.Bot):
        self.bot = bot

    @tasks.loop(hours=12)
    async def check_for_new_blogs():
        pass
