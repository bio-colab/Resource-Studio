from pathlib import Path

from core.raw_resource_parser import compare_with_graph, parse_raw_resources
from core.verification import ResourceGraph


def main() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "sample.dll"
    report = parse_raw_resources(fixture)
    assert report.issues == ()
    assert report.leaves
    comparison = compare_with_graph(report, ResourceGraph.from_path(fixture).to_dict())
    assert comparison.matches is True
    print("raw-resource-parser-tests: passed")


if __name__ == "__main__":
    main()
