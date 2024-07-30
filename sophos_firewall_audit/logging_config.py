from rich.logging import RichHandler
from rich.highlighter import RegexHighlighter
from rich.theme import Theme
from rich.console import Console
import logging

class DeviceNameHighlighter(RegexHighlighter):
    """Apply style to the device name."""

    base_style = "style."
    highlights = [r"(?P<hostname>[a-z]+-[a-z]+-[a-z]+-[a-z]+-\S+)", r"(?P<hostname>[a-z]+-[a-z]+-[a-z]+-[a-z]+-[a-z]+-\S+)"]

class LoggingSetup:
    """Define logging settings for all modules.
    """
    def __init__(self):
        theme = Theme({"style.hostname": "magenta"})
        console = Console(theme=theme)
        FORMAT = '%(message)s'
        logging.basicConfig(level=logging.INFO, format=FORMAT, handlers=[RichHandler(console=console, 
                                                                                    highlighter=DeviceNameHighlighter(),
                                                                                    show_path=False,
                                                                                    omit_repeated_times=False)])
