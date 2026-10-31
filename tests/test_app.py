def test_ui_builds():
    from ransomrag.ui import build_ui

    demo = build_ui()
    assert demo is not None
