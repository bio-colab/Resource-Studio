from core.pure_loader_oracle import select_language, select_resource


def main() -> None:
    assert select_language(1033, [0, 1033, 1041]) == 1033
    assert select_language(2057, [0, 1033, 1041]) == 1033
    assert select_language(9999, [0, 1041]) == 0
    assert select_language(9999, [1041, 3082]) == 1041
    leaves = [
        {"type": "STRING", "name": "1", "language": 0, "sha256": "neutral"},
        {"type": "STRING", "name": "1", "language": 1033, "sha256": "english"},
    ]
    selected = select_resource(leaves, "STRING", "1", 2057)
    assert selected.status == "FOUND"
    assert selected.selected_language == 1033
    assert selected.resource["sha256"] == "english"
    print("pure-loader-oracle-tests: passed")


if __name__ == "__main__":
    main()
