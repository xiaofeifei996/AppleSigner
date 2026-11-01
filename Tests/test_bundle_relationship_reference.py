from pathlib import PurePosixPath


def build_relationships(components):
    by_path = {c["path"]: c for c in components}
    counts = {}
    for c in components:
        counts[c["id"]] = counts.get(c["id"], 0) + 1
    rows = []
    executable_paths = set()
    for c in components:
        path = c["path"]
        parents = [p for p in by_path if p != path and path.startswith(p.rstrip("/") + "/")]
        parent_path = max(parents, key=len) if parents else None
        exe = c.get("executable")
        exe_path = f"{path}/{exe}" if exe else ""
        issues = []
        if counts[c["id"]] > 1:
            issues.append("duplicate-bundle-identifier")
        if exe_path and exe_path in executable_paths:
            issues.append("duplicate-executable-path")
        if exe_path:
            executable_paths.add(exe_path)
        rows.append({"path": path, "parent": parent_path,
                     "parent_id": by_path[parent_path]["id"] if parent_path else None,
                     "depth": len(PurePosixPath(path).parts), "issues": issues})
    return rows


def test_nested_extension_maps_to_nearest_app_parent():
    rows = build_relationships([
        {"path": "Payload/Demo.app", "id": "com.demo", "executable": "Demo"},
        {"path": "Payload/Demo.app/PlugIns/Share.appex", "id": "com.demo.share", "executable": "Share"},
    ])
    assert rows[1]["parent"] == "Payload/Demo.app"
    assert rows[1]["parent_id"] == "com.demo"


def test_same_bundle_basename_under_different_parents_does_not_cross_link():
    rows = build_relationships([
        {"path": "Payload/A.app", "id": "a", "executable": "A"},
        {"path": "Payload/B.app", "id": "b", "executable": "B"},
        {"path": "Payload/A.app/PlugIns/Widget.appex", "id": "widget.a", "executable": "Widget"},
        {"path": "Payload/B.app/PlugIns/Widget.appex", "id": "widget.b", "executable": "Widget"},
    ])
    assert rows[2]["parent"] == "Payload/A.app"
    assert rows[3]["parent"] == "Payload/B.app"


def test_duplicate_bundle_ids_are_reported_without_using_ids_for_parentage():
    rows = build_relationships([
        {"path": "Payload/A.app", "id": "same", "executable": "A"},
        {"path": "Payload/B.app", "id": "same", "executable": "B"},
        {"path": "Payload/A.app/PlugIns/E.appex", "id": "same.ext", "executable": "E"},
    ])
    assert "duplicate-bundle-identifier" in rows[0]["issues"]
    assert rows[2]["parent"] == "Payload/A.app"


def test_orphan_component_is_top_level_not_guessed_from_identifier():
    rows = build_relationships([
        {"path": "Payload/Demo.app", "id": "com.example", "executable": "Demo"},
        {"path": "Payload/Other.app/PlugIns/E.appex", "id": "com.example.extension", "executable": "E"},
    ])
    assert rows[1]["parent"] is None


def test_source_exposes_relationship_audit_and_does_not_claim_signature_validity():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    source = (root / "IPAInspector.m").read_text()
    readme = (root / "README.md").read_text()
    assert 'result[@"BundleRelationships"]' in source
    assert 'result[@"BundleRelationshipIssueCount"]' in source
    assert '不代表已验证 Apple 签名规则' in source
    assert '1.41.0：IPA 嵌套 Bundle 关系与签名依赖盘点' in readme
