"""
J.A.R.V.I.S — Web Commands
Search Google, YouTube, Wikipedia, and open websites.
"""

import webbrowser
import urllib.parse


class WebCommands:
    """Handle web search and URL opening commands."""

    def google_search(self, query):
        """Search Google for a query."""
        url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        webbrowser.open(url)
        return f"Yes sir, searching Google for '{query}'."

    def youtube_search(self, query):
        """Search YouTube for a query."""
        url = f"https://www.youtube.com/results?search_query={urllib.parse.quote(query)}"
        webbrowser.open(url)
        return f"Yes sir, searching YouTube for '{query}'."

    def wikipedia_search(self, query):
        """Search Wikipedia for a query."""
        url = f"https://en.wikipedia.org/wiki/Special:Search?search={urllib.parse.quote(query)}"
        webbrowser.open(url)
        return f"Yes sir, searching Wikipedia for '{query}'."

    def open_email(self):
        """Open Gmail."""
        webbrowser.open("https://mail.google.com")
        return "Yes sir, opening your email."

    def open_website(self, site):
        """Open a website by domain."""
        if not site.startswith("http"):
            site = f"https://{site}"
        webbrowser.open(site)
        domain = site.replace("https://", "").replace("http://", "")
        return f"Yes sir, opening {domain}."
