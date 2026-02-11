"""PeMCP - Comprehensive PE File Analyzer with MCP Server"""
__version__ = "1.0.0"

# Suppress the pkg_resources deprecation warning emitted by the unicorn package.
# This must happen before angr (which imports unicorn) is loaded anywhere.
import warnings
warnings.filterwarnings(
    "ignore",
    message=r"pkg_resources is deprecated as an API",
    category=UserWarning,
)
