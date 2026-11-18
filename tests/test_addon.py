import io
import os
import tempfile
import zipfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from mitmproxy import connection, ctx, http, options

from adblock_addon import AdBlock, TIF_FULL, TIF_MEDIUM, _cached_list
from threatfox import ThreatFoxSnapshot, snapshot_from_export


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

    def test_unavailable_tif_full_can_use_previous_medium_snapshot(self):
        cache = self.rules.parent
        _cached_list(cache, TIF_MEDIUM).write_text("||known-threat.test^$all", encoding="utf-8")
        ctx.options.update(adblock_lists=TIF_FULL, adblock_cache_dir=str(cache))
        with patch.object(self.addon, "_fetch", return_value=None):
            self.addon.configure({"adblock_lists"})
        flow = flow_for("https://known-threat.test/")
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)

    def test_threatfox_uses_exact_eligible_hosts_and_honors_exceptions(self):
        report = b"""# "first_seen_utc", "last_seen_utc", "ioc_value", "ioc_type", "threat_type", "confidence_level", "is_compromised"
"timestamp", "", "bad.hosted.test", "domain", "botnet_cc", "90", "False"
"timestamp", "", "allow.hosted.test", "domain", "payload_delivery", "90", "False"
"timestamp", "", "compromised.hosted.test", "domain", "botnet_cc", "100", "True"
"timestamp", "", "low.hosted.test", "domain", "botnet_cc", "50", "False"
"""
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as archive:
            archive.writestr("sample.csv", report)
        snapshot = snapshot_from_export(raw.getvalue())
        ctx.options.update(adblock_threatfox_key_file="/unused/key", adblock_cache_dir=str(self.rules.parent))
        with patch("adblock_addon.fetch_snapshot", return_value=snapshot):
            self.load_rules("@@||allow.hosted.test^$document")
        for url, blocked in (
            ("https://bad.hosted.test:443/landing", True),
            ("http://bad.hosted.test/path", True),
            ("https://bad.hosted.test.:8443/path", True),
            ("https://bad.hosted.test:8443@clean.hosted.test/", False),
            ("https://child.bad.hosted.test/", False),
            ("https://hosted.test/", False),
            ("https://compromised.hosted.test/", False),
            ("https://low.hosted.test/", False),
            ("https://allow.hosted.test/", False),
        ):
            with self.subTest(url=url):
                flow = flow_for(url)
                self.addon.request(flow)
                self.assertEqual(flow.response is not None, blocked)
        saved = self.rules.parent / "threatfox.json"
        with saved.open() as file:
            self.assertEqual(ThreatFoxSnapshot.read(file), snapshot)
        with patch("adblock_addon.fetch_snapshot", side_effect=OSError("sensitive response")):
            self.addon._build_engine(force=True)
        flow = flow_for("https://bad.hosted.test/")
        self.addon.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        ctx.options.update(adblock_threatfox_key_file="")
        self.addon.configure({"adblock_threatfox_key_file"})
        flow = flow_for("https://bad.hosted.test/")
        self.addon.request(flow)
        self.assertIsNone(flow.response)

    def test_recent_threatfox_payload_url_blocks_only_the_exact_url(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = now.strftime("%Y-%m-%d %H:%M:%S")
        old = (now - timedelta(days=8)).strftime("%Y-%m-%d %H:%M:%S")
        report = f"""# "first_seen_utc", "last_seen_utc", "ioc_value", "ioc_type", "threat_type", "confidence_level", "is_compromised"
"{old}", "", "dedicated.test", "domain", "botnet_cc", "90", "False"
"{old}", "{stamp}", "https://SHARED.test:443/File?token=A#ignored", "url", "payload_delivery", "100", "True"
"{stamp}", "", "https://allow.test/File", "url", "payload_delivery", "90", "False"
"{stamp}", "", "https://shared.test/", "url", "payload_delivery", "90", "True"
"{stamp}", "", "https://shared.test/low", "url", "payload_delivery", "50", "False"
"{old}", "", "https://shared.test/stale", "url", "payload_delivery", "90", "False"
"""
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as archive:
            archive.writestr("sample.csv", report)
        snapshot = snapshot_from_export(raw.getvalue(), now=now)
        target = "https://shared.test/File?token=A"
        self.assertEqual(set(snapshot.payload_urls), {target, "https://allow.test/File"})
        ctx.options.update(adblock_threatfox_key_file="/unused/key", adblock_cache_dir=str(self.rules.parent))
        with patch("adblock_addon.fetch_snapshot", return_value=snapshot):
            self.load_rules("@@||allow.test^$document")
        for url, blocked in (
            (target, True),
            ("https://shared.test/File?token=a", False),
            ("https://shared.test/file?token=A", False),
            ("https://shared.test/File?token=A&extra=1", False),
            ("https://shared.test/File", False),
            ("https://shared.test:8443/File?token=A", False),
            ("http://shared.test/File?token=A", False),
            ("https://shared.test/", False),
            ("https://allow.test/File", False),
        ):
            with self.subTest(url=url):
                flow = flow_for(url)
                self.addon.request(flow)
                self.assertEqual(flow.response is not None, blocked)
                self.assertEqual(flow.request.url, url)
                if blocked:
                    self.assertEqual(flow.metadata["adblock"], "Exact threat payload URL")
        with patch("adblock_addon.fetch_snapshot", side_effect=OSError):
            self.addon._build_engine(force=True)
        flow = flow_for("https://publisher.test/start")
        flow.response = http.Response.make(302, b"", {"Location": target})
        self.addon.response(flow)
        self.assertTrue(flow.metadata["adblock_redirect"])
        with patch("adblock_addon.time.time", return_value=snapshot.payload_urls[target]):
            flow = flow_for(target)
            self.addon.request(flow)
        self.assertIsNone(flow.response)

    def test_threatfox_upgrade_falls_back_to_recent_domain_cache(self):
        cache = self.rules.parent
        legacy = cache / "threatfox-domains.txt"
        legacy.write_text("dedicated.test\n", encoding="ascii")
        ctx.options.update(adblock_threatfox_key_file="/unused/key", adblock_cache_dir=str(cache))
        with patch("adblock_addon.fetch_snapshot", side_effect=OSError):
            self.load_rules()
            flow = flow_for("https://dedicated.test/")
            self.addon.request(flow)
            self.assertEqual(flow.response.status_code, 403)
            stale = (datetime.now(timezone.utc) - timedelta(days=8)).timestamp()
            os.utime(legacy, (stale, stale))
            self.addon._build_engine(force=True)
        flow = flow_for("https://dedicated.test/")
        self.addon.request(flow)
        self.assertIsNone(flow.response)

    def test_followable_refresh_uses_get_without_rewriting_other_responses(self):
        self.load_rules("/bounce^$document,method=get", "@@/continue^$document")
        ctx.options.update(adblock_cosmetic=False)
        for values, destination, expected in (
            (["0; URL='/bounce'"], "document", 403),
            (["0; URL='/bounce'"], "empty", 200),
            (["5"], "document", 200),
            (["0;url=/continue"], "document", 200),
            (["0;url=about:blank"], "document", 200),
            (["0;url=/bounce", "5"], "document", 200),
        ):
            with self.subTest(values=values, destination=destination):
                flow = flow_for("https://page.test/start", method="POST")
                flow.request.headers["Sec-Fetch-Dest"] = destination
                flow.response = http.Response.make(200, b"publisher content", {"content-type": "text/html"})
                flow.response.headers.set_all("refresh", values)
                self.addon.response(flow)
                self.assertEqual(flow.response.status_code, expected)
                if expected == 200:
                    self.assertEqual(flow.response.headers.get_all("refresh"), values)
                    self.assertEqual(flow.response.raw_content, b"publisher content")
                else:
                    self.assertIn("adblock_refresh", flow.metadata)

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
