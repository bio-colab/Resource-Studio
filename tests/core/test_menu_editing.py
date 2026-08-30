from core.menu_resources import MenuItem, MenuResource, MenuResourceError


def main() -> None:
    menu = MenuResource([MenuItem(10, "File", children=[MenuItem(11, "Open"), MenuItem(12, "Close")]), MenuItem(20, "Help")])
    menu.move_item(20, 10, 0)
    assert [item.item_id for item in menu.find_id(10).children] == [20, 11, 12]
    menu.move_item(12, None, 1)
    assert [item.item_id for item in menu.items] == [10, 12]
    menu.update_item(12, text="Close all", flags=0)
    assert menu.find_id(12).text == "Close all"
    try:
        menu.move_item(10, 11, 0)
    except MenuResourceError:
        pass
    else:
        raise AssertionError("moving a parent below its descendant must be rejected")
    assert MenuResource.from_dict(menu.to_dict()).to_bytes() == menu.to_bytes()
    print("menu-editing-tests: passed")


if __name__ == "__main__":
    main()
