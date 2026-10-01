import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import xauth


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, filename in (
            ("TOKEN_PATH", "tokens.txt"),
            ("CODE_PATH", "login-code.txt"),
            ("ERROR_PATH", "login-error.txt"),
        ):
            patcher = patch.object(xauth, name, str(self.root / filename))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.output = io.StringIO()
        redirect = contextlib.redirect_stdout(self.output)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)
        network = patch.object(xauth, "post", side_effect=AssertionError("Unexpected network call"))
        self.post = network.start()
        self.addCleanup(network.stop)

    def cache(self, exp):
        xauth.write_tokens([("exp", str(exp)), ("refresh", "saved-session")])

    def test_status_does_not_sign_in_or_change_cache(self):
        for exp, message in ((0, "expired"), (int(xauth.time.time()) + 3600, "Signed in")):
            self.cache(exp)
            before = Path(xauth.TOKEN_PATH).read_bytes()
            xauth.main(["--status"])
            self.assertIn(message, self.output.getvalue())
            self.assertEqual(Path(xauth.TOKEN_PATH).read_bytes(), before)
        self.post.assert_not_called()

    def test_cached_login_does_not_request_new_code(self):
        self.cache(int(xauth.time.time()) + 3600)
        xauth.main([])
        self.assertIn("Already signed in", self.output.getvalue())
        self.post.assert_not_called()

    def test_force_bypasses_cache_and_refresh(self):
        self.cache(int(xauth.time.time()) + 3600)
        self.post.side_effect = None
        self.post.return_value = {"device_code": "device", "user_code": "CODE"}
        with patch.object(xauth, "refresh_msa") as refresh, \
             patch.object(xauth, "show_code") as show, \
             patch.object(xauth, "poll_msa", return_value={"access_token": "new-session"}), \
             patch.object(xauth, "finish") as finish:
            xauth.main(["--force"])
        refresh.assert_not_called()
        show.assert_called_once_with("https://www.microsoft.com/link", "CODE")
        finish.assert_called_once_with({"access_token": "new-session"})

    def test_expired_login_refreshes_without_browser(self):
        self.cache(0)
        with patch.object(xauth, "refresh_msa", return_value={"access_token": "renewed"}) as refresh, \
             patch.object(xauth, "finish") as finish:
            xauth.main([])
        refresh.assert_called_once_with("saved-session")
        finish.assert_called_once_with({"access_token": "renewed"})
        self.post.assert_not_called()

    def test_logout_removes_cache_and_login_files(self):
        for name in ("tokens.txt", "tokens.txt.tmp", "login-code.txt", "login-error.txt"):
            (self.root / name).write_text("test")
        xauth.main(["--logout"])
        self.assertEqual(list(self.root.iterdir()), [])
        xauth.main(["--logout"])
        self.post.assert_not_called()

    def test_missing_desktop_tools_still_displays_and_saves_code(self):
        with patch.object(xauth.shutil, "which", return_value=None):
            xauth.show_code("https://www.microsoft.com/link", "TEST-CODE")
        self.assertIn("TEST-CODE", self.output.getvalue())
        self.assertIn("open the URL above yourself", self.output.getvalue())
        self.assertEqual(Path(xauth.CODE_PATH).read_text(),
                         "https://www.microsoft.com/link\nTEST-CODE\n")

    def test_browser_preference_supports_quoted_arguments(self):
        with patch.dict(os.environ, {"BROWSER": '"/path with spaces/browser" --new-tab %s'}):
            command = next(xauth._browser_commands("https://www.microsoft.com/link"))
        self.assertEqual(command, ["/path with spaces/browser", "--new-tab", "https://www.microsoft.com/link"])

    def test_failed_browser_spawn_tries_next_launcher(self):
        with patch.dict(os.environ, {"BROWSER": "preferred-browser"}), \
             patch.object(xauth.shutil, "which", side_effect=lambda name: name), \
             patch.object(xauth.subprocess, "Popen") as spawn:
            spawn.side_effect = [OSError("cannot launch"), unittest.mock.Mock(poll=lambda: None)]
            self.assertTrue(xauth.open_browser("https://www.microsoft.com/link", {}))
        self.assertEqual(spawn.call_args_list[1].args[0][0], "xdg-open")

    def test_network_failure_has_readable_error(self):
        # Exercise the real HTTP helper without making a request.
        with patch.object(xauth.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")):
            with self.assertRaisesRegex(SystemExit, "Network error: offline"):
                self.real_post("https://login.live.com/oauth20_connect.srf", form={})

    real_post = staticmethod(xauth.post)

    def test_minecraft_and_playfab_share_device_identity(self):
        document = {"Token": "test", "DisplayClaims": {"xui": [{"uhs": "hash", "xid": "1"}]}}
        with patch.object(xauth, "xbox_user", return_value="user"), \
             patch.object(xauth, "device_token", return_value="shared-device"), \
             patch.object(xauth, "xsts", return_value=(document, None)) as xsts:
            xauth.finish({"access_token": "test"})
        self.assertEqual(xsts.call_args_list[1].args,
                         ("user", "rp://api.minecraftservices.com/", "shared-device"))
        self.assertEqual(xsts.call_args_list[2].args,
                         ("user", xauth.PLAYFAB_RP, "shared-device"))
        self.assertEqual(os.stat(xauth.TOKEN_PATH).st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
