from __future__ import annotations

from core.menu_resources import MF_SEPARATOR, MenuItem, MenuResource, MenuResourceError


def main() -> None:
    menu = MenuResource(
        [
            MenuItem(100, "File", children=[MenuItem(101, "Open"), MenuItem(0, "", MF_SEPARATOR), MenuItem(102, "Exit")]),
            MenuItem(200, "Help"),
        ]
    )
    restored = MenuResource.parse(menu.to_bytes())
    assert restored.find_id(101).text == "Open"
    assert restored.find_id(102).text == "Exit"
    assert restored.find_id(200).text == "Help"
    assert restored.find_id(0).is_separator
    assert restored.to_bytes() == menu.to_bytes()
    try:
        MenuResource.parse(b"\x00\x00\x04\x00\x80")
    except MenuResourceError:
        pass
    else:
        raise AssertionError("truncated menu resource was accepted")
    print("menu-resource-tests: passed")


if __name__ == "__main__":
    main()
