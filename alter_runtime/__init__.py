"""~Alter Identity Runtime.

The local daemon that renders your identity field across the surfaces your
device touches. See the package README for an overview.
"""

from alter_runtime.sdk.client import AlterClient

__version__ = "0.4.13"
__all__ = ["AlterClient", "__version__"]
