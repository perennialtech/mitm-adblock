import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

from mitmproxy import connection, ctx, http, options

from adblock_addon import AdBlock


def flow_for(url, method="GET"):
    flow = http.HTTPFlow(
        connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0)),
        connection.Server(address=("page.test", 443)),
    )
    flow.request = http.Request.make(method, url, headers={"Sec-Fetch-Dest": "document"})
    return flow


class AdBlockTests(unittest.TestCase):
    def setUp(self):
        self.addon = AdBlock()
        ctx.options = options.Options()
        self.addon.load(SimpleNamespace(add_option=ctx.options.add_option))
        work = self.enterContext(tempfile.TemporaryDirectory())
        self.rules = Path(work, "rules.txt")
        ctx.options.update(adblock_lists=str(self.rules), adblock_update_hours=0)

    def load_rules(self, *lines):
        self.rules.write_text("\n".join(lines), encoding="utf-8")
        # The production refresh builds on a worker and serves requests on
        # mitmproxy's main thread.
        with ThreadPoolExecutor(max_workers=1) as worker:
            worker.submit(self.addon.configure, {"adblock_lists"}).result()

    def test_badware_document_block_keeps_rule_text(self):
        self.load_rules("||badware.test^$all")
        flow = flow_for("https://badware.test/")
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.metadata["adblock"], "||badware.test^$all")
        self.assertIn("||badware.test^$all", flow.response.get_text())

    def test_allowed_url_preserves_query(self):
        self.load_rules("||page.test^$removeparam=utm_source")
        url = "https://page.test/path?utm_source=tracking&tag=1&tag=2&flag&value=%2f"
        flow = flow_for(url)
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.url, url)

    def test_redirect_uses_followup_method(self):
        self.load_rules("||page.test/landing^$document,method=get")
        for status in (303, 307):
            with self.subTest(status=status):
                flow = flow_for("https://page.test/start", method="POST")
                self.addon.request(flow)
                self.assertIsNone(flow.response)
                flow.response = http.Response.make(status, b"", {"Location": "/landing"})
                self.addon.response(flow)
                self.assertEqual(flow.response.status_code, 403 if status == 303 else status)

    def test_cross_site_request_without_referrer(self):
        self.load_rules(
            "||target.test/third-party.js^$script,third-party",
            "||target.test/scoped.js^$script,domain=publisher.test",
        )
        for path, site, expected_status in (
            ("third-party.js", "cross-site", 204),
            ("third-party.js", "same-site", None),
            ("scoped.js", "cross-site", None),
        ):
            with self.subTest(path=path, site=site):
                flow = flow_for(f"https://target.test/{path}")
                flow.request.headers["Sec-Fetch-Dest"] = "script"
                flow.request.headers["Sec-Fetch-Site"] = site
                self.addon.request(flow)
                self.assertEqual(flow.response.status_code if flow.response else None, expected_status)

    def test_hyperlink_auditing_ping_and_ordinary_post(self):
        self.load_rules("||target.test/link^$ping,third-party")
        for content_type, expected_status in (("text/ping", 204), ("application/json", None)):
            with self.subTest(content_type=content_type):
                flow = flow_for("https://target.test/link", method="POST")
                flow.request.headers.update({
                    "Content-Type": content_type,
                    "Ping-To": "https://destination.test/",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Site": "cross-site",
                })
                self.addon.request(flow)
                self.assertEqual(flow.response.status_code if flow.response else None, expected_status)

    def test_redirect_preserves_inferred_request_type(self):
        self.load_rules("||target.test/relay.html^$script")
        flow = flow_for("https://page.test/asset.js")
        del flow.request.headers["Sec-Fetch-Dest"]
        self.addon.request(flow)
        self.assertIsNone(flow.response)
        flow.response = http.Response.make(
            302, b"", {"Location": "https://target.test/relay.html"}
        )
        self.addon.response(flow)
        self.assertEqual(flow.response.status_code, 204)
        self.assertIn("adblock_redirect", flow.metadata)

    def test_cosmetic_styles_and_exceptions(self):
        self.load_rules(
            "##.generic-ad",
            "##.keep",
            "page.test#@#.keep",
            "page.test##.sponsor",
            "page.test##.layout:style(margin: 0 !important)",
        )
        flow = flow_for("https://page.test/")
        flow.response = http.Response.make(
            200,
            b'<html><head></head><body class="generic-ad keep sponsor layout"></body></html>',
            {"content-type": "text/html"},
        )
        self.addon.response(flow)
        html = flow.response.get_text()
        self.assertIn(".generic-ad{display:none!important}", html)
        self.assertIn(".sponsor{display:none!important}", html)
        self.assertIn(".layout{margin: 0 !important}", html)
        self.assertNotIn(".keep{", html)


if __name__ == "__main__":
    unittest.main()
