"""Scanner adapters.

Importing this package registers every built-in adapter as a side effect, so
`get_adapter` / `all_adapters` see them. Adding a new scanner = add a module
here and import it below.
"""

from .base import Adapter, PlannedCommand, all_adapters, get_adapter, register

# Importing each module runs its @register decorator.
from . import lynis as _lynis  # noqa: F401
from . import nmap as _nmap    # noqa: F401
from . import nuclei as _nuclei  # noqa: F401
from . import testssl as _testssl  # noqa: F401

__all__ = ["Adapter", "PlannedCommand", "all_adapters", "get_adapter", "register"]
