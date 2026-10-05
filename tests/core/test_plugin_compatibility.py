from __future__ import annotations

from core.plugins import PluginManifest, PluginRegistry


def manifest(**overrides: object) -> PluginManifest:
    payload: dict[str, object] = {
        "id": "com.example.compat",
        "name": "Compat",
        "version": "1.0.0",
        "api": "resource-editor/v1",
        "entry": "plugin.py",
        "permissions": ["project.read"],
    }
    payload.update(overrides)
    return PluginManifest.from_dict(payload)


def main() -> None:
    registry = PluginRegistry(host_version="1.2.0")
    supported = manifest(minHostVersion="1.0.0", maxHostVersion="2.0.0")
    registry.register(supported)
    assert registry.compatibility(supported) == (True, "compatible")
    registry.ensure_compatible(supported.plugin_id)

    too_new = manifest(id="com.example.too-new", minHostVersion="1.3.0")
    compatible, reason = registry.compatibility(too_new)
    assert not compatible and "requires host >= 1.3.0" in reason
    try:
        registry.register(too_new)
    except ValueError:
        pass
    else:
        raise AssertionError("incompatible plugin was registered")

    try:
        manifest(id="com.example.bad-range", minHostVersion="2.0.0", maxHostVersion="1.0.0")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid host version range was accepted")
    print("plugin-compatibility-tests: passed")


if __name__ == "__main__":
    main()
