"""
Output formatters and report generators.
"""

from .console import render_console_report, render_triage_leaderboard
from .html import generate_html_report

__all__ = [
    "render_console_report",
    "render_triage_leaderboard",
    "generate_html_report",
]
