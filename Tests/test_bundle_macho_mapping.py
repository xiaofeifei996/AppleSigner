def items_owned_by_bundle(items, bundle_path):
    return [item for item in items
            if isinstance(item.get("BundlePath"), str)
            and item["BundlePath"] == bundle_path]

def test_maps_same_named_bundles_by_full_path():
    items = [
        {"Bundle": "PlugIn.appex", "BundlePath": "/Payload/A.app/PlugIns/PlugIn.appex"},
        {"Bundle": "PlugIn.appex", "BundlePath": "/Payload/B.app/PlugIns/PlugIn.appex"},
    ]
    assert len(items_owned_by_bundle(items, "/Payload/A.app/PlugIns/PlugIn.appex")) == 1
    assert items_owned_by_bundle(items, "/Payload/A.app/PlugIns/PlugIn.appex")[0]["BundlePath"].startswith("/Payload/A.app")

def test_does_not_match_by_basename_only():
    items = [{"Bundle": "Demo.app", "BundlePath": "/Payload/Demo.app"}]
    assert items_owned_by_bundle(items, "/Payload/Other.app") == []

def test_missing_bundle_path_is_not_guessed():
    items = [{"Bundle": "Demo.app", "Report": {}}]
    assert items_owned_by_bundle(items, "/Payload/Demo.app") == []

def test_one_bundle_can_own_multiple_executables():
    items = [
        {"BundlePath": "/Payload/Demo.app", "ExecutablePath": "/Payload/Demo.app/Demo"},
        {"BundlePath": "/Payload/Demo.app", "ExecutablePath": "/Payload/Demo.app/Helper"},
    ]
    assert len(items_owned_by_bundle(items, "/Payload/Demo.app")) == 2
