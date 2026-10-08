"""Notification rendering must treat scanner and provider text as untrusted."""

from app.services.notification import NotificationContent, _email_html


def test_email_fallback_escapes_subject_body_and_link() -> None:
    html = _email_html(
        NotificationContent(
            subject='<img src=x onerror="alert(1)">',
            body="Issue <b>critical</b> & urgent",
            link='https://example.test/ticket?a=" onclick="alert(2)',
        )
    )

    assert "<img" not in html
    assert "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in html
    assert "Issue &lt;b&gt;critical&lt;/b&gt; &amp; urgent" in html
    assert 'href="https://example.test/ticket?a=&quot; onclick=&quot;alert(2)"' in html
    assert 'href="https://example.test/ticket?a=" onclick=' not in html


def test_email_fallback_drops_unsafe_link_scheme() -> None:
    html = _email_html(
        NotificationContent(
            subject="Ticket created",
            body="Open the ticket",
            link="javascript:alert(1)",
        )
    )
    assert "<a href=" not in html
