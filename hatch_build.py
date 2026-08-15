"""Build-time hooks for the source distribution.

Hatchling force-includes the repository ``.gitignore`` into the sdist as a VCS
exclusion file, and that force-include bypasses the ``exclude`` list. The local
ignore file is build tooling, not part of the distributed package, so this hook
drops it from the force-include map before the archive is written.
"""

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        force_include = build_data.get("force_include", {})
        for source in list(force_include):
            if force_include[source] == ".gitignore" or source.endswith(".gitignore"):
                del force_include[source]
