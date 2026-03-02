"""Arkana - AI-Powered Binary Analysis"""
__version__ = "1.0.0"

# Suppress noisy dependency warnings that are harmless in our container environment.
# These must be registered before the relevant packages are imported anywhere.
import warnings

# pkg_resources deprecation warning emitted by the unicorn package
# (unicorn does `import pkg_resources` at import time; setuptools <81 still ships it).
warnings.filterwarnings(
    "ignore",
    message=r"pkg_resources is deprecated as an API",
    category=UserWarning,
)

# requests emits RequestsDependencyWarning when urllib3 or charset_normalizer
# are newer than the versions it was tested against.  The mismatch is harmless.
warnings.filterwarnings(
    "ignore",
    message=r"urllib3.*or chardet.*doesn't match a supported version",
)
