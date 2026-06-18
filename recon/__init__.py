"""Safe recon helpers for the Recon MCP server."""

from importlib.metadata import PackageNotFoundError, version


try:
    __version__ = version("recon-mcp")
except PackageNotFoundError:
    __version__ = "0.1.0"
