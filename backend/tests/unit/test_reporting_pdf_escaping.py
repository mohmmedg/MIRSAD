from app.modules.reporting.exporters import _pdf_paragraph_text


def test_pdf_paragraph_text_escapes_reportlab_markup():
    payload = '<b>injected</b> & "quoted"'
    escaped = _pdf_paragraph_text(payload, language="en")
    assert escaped == '&lt;b&gt;injected&lt;/b&gt; &amp; "quoted"'
    assert '<b>' not in escaped


def test_pdf_paragraph_text_handles_none():
    assert _pdf_paragraph_text(None, language="en") == ''
