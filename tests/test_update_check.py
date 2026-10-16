import hashlib
import io
import json
import tempfile
import threading
import unittest
from http.client import IncompleteRead
from pathlib import Path
from unittest import mock
from urllib.error import HTTPError, URLError

from utils import update_check
from utils.update_check import _extract_assets, _parse_version_tuple, _version_gt

PAYLOAD = b'payload'
DIGEST = 'sha256:' + hashlib.sha256(PAYLOAD).hexdigest()


class ParseVersionTupleTest(unittest.TestCase):
    def test_plain_and_prefixed_versions(self):
        self.assertEqual(_parse_version_tuple('1.9.1'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple('v1.9.1'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple(' V2.0 '), (2, 0))

    def test_trailing_suffixes_are_truncated_to_digits(self):
        self.assertEqual(_parse_version_tuple('1.9.1rc2'), (1, 9, 1))
        self.assertEqual(_parse_version_tuple('1.9.1-beta'), (1, 9, 1))

    def test_empty_and_non_numeric_segments(self):
        self.assertEqual(_parse_version_tuple(''), (0,))
        self.assertEqual(_parse_version_tuple(None), (0,))
        self.assertEqual(_parse_version_tuple('1.x.3'), (1, 0, 3))


class VersionGtTest(unittest.TestCase):
    def test_newer_versions(self):
        self.assertTrue(_version_gt('1.9.2', '1.9.1'))
        self.assertTrue(_version_gt('1.10.0', '1.9.9'))
        self.assertTrue(_version_gt('2.0', '1.9.9'))

    def test_equal_and_older_versions(self):
        self.assertFalse(_version_gt('1.9.1', '1.9.1'))
        self.assertFalse(_version_gt('1.9.1', '1.9.2'))
        self.assertFalse(_version_gt('1.9', '1.9.0'))

    def test_shorter_version_is_padded_with_zeros(self):
        self.assertTrue(_version_gt('1.9.1', '1.9'))
        self.assertFalse(_version_gt('1.9', '1.9.1'))


class ExtractAssetsTest(unittest.TestCase):
    def test_keeps_name_url_and_digest(self):
        data = {'assets': [{
            'name': 'TgWsProxy_windows.exe',
            'browser_download_url': 'https://example.invalid/a.exe',
            'digest': 'sha256:abc',
        }]}
        self.assertEqual(_extract_assets(data), [{
            'name': 'TgWsProxy_windows.exe',
            'url': 'https://example.invalid/a.exe',
            'digest': 'sha256:abc',
        }])

    def test_drops_entries_without_name_or_url(self):
        data = {'assets': [
            {'name': 'a.exe'},
            {'browser_download_url': 'https://example.invalid/b.exe'},
        ]}
        self.assertEqual(_extract_assets(data), [])

    def test_missing_digest_becomes_empty_string(self):
        data = {'assets': [{
            'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe',
        }]}
        self.assertEqual(_extract_assets(data)[0]['digest'], '')

    def test_empty_input(self):
        self.assertEqual(_extract_assets(None), [])
        self.assertEqual(_extract_assets({}), [])


class _Response(io.BytesIO):
    def __init__(self, body, content_length='auto'):
        super().__init__(body)
        if content_length == 'auto':
            content_length = len(body)
        self.headers = {} if content_length is None else {
            'Content-Length': str(content_length),
        }

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _opener(response):
    opener = mock.Mock()
    opener.open.return_value = response
    return mock.Mock(return_value=opener)


class RunCheckTest(unittest.TestCase):
    def setUp(self):
        self.patch = mock.patch.object(update_check, '_state', update_check.get_status())
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def _check(self, data, current='1.11.1'):
        with mock.patch.object(update_check, 'fetch_latest_release', return_value=data):
            update_check.run_check(current)
        return update_check.get_status()

    def test_versions_are_compared_and_assets_published_together(self):
        release = {'tag_name': ' v2.0 ', 'assets': [{
            'name': 'app.exe', 'browser_download_url': 'https://example.invalid/app.exe', 'digest': DIGEST,
        }]}
        for current, has_update, ahead in (('1.11.1', True, False), ('2.0.0', False, False), ('2.1', False, True)):
            with self.subTest(current=current):
                state = self._check(release, current)
                self.assertTrue(state['checked'])
                self.assertIsNone(state['error'])
                self.assertEqual((state['has_update'], state['ahead_of_release']), (has_update, ahead))
                self.assertEqual(state['latest'], '2.0')
                self.assertEqual(state['html_url'], update_check.RELEASES_PAGE_URL)
                self.assertEqual(state['assets'][0]['digest'], DIGEST)

    def test_invalid_response_is_an_error_not_a_claim_that_the_app_is_current(self):
        for data in (None, [], {}, {'tag_name': None}, {'tag_name': ''}, {'tag_name': 'oops'},
                     {'tag_name': 'v2.0', 'assets': 'invalid'}):
            with self.subTest(data=data):
                state = self._check(data)
                self.assertTrue(state['error'])
                self.assertFalse(state['has_update'])
                self.assertIsNone(state['latest'])
                self.assertEqual(state['assets'], [])

    def test_release_tag_suffixes_keep_the_existing_version_comparison(self):
        state = self._check({'tag_name': 'v1.12.0-hotfix'})
        self.assertIsNone(state['error'])
        self.assertTrue(state['has_update'])
        self.assertEqual(state['latest'], '1.12.0-hotfix')

    def test_network_failure_clears_old_assets_and_does_not_prevent_retry(self):
        errors = (URLError('offline'), HTTPError('https://example.invalid', 403, 'rate limit', {}, None),
                  TimeoutError(), IncompleteRead(b'{', 5), ValueError('bad json'))
        for error in errors:
            with self.subTest(error=error):
                self._check({'tag_name': 'v2.0', 'assets': [{
                    'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe', 'digest': DIGEST,
                }]})
                with mock.patch.object(update_check, 'fetch_latest_release', side_effect=error):
                    update_check.run_check('1.11.1')
                state = update_check.get_status()
                self.assertTrue(state['error'])
                self.assertEqual(state['assets'], [])
                self.assertFalse(state['has_update'])
                self.assertIsNone(self._check({'tag_name': 'v2.1'})['error'])

    def test_readers_do_not_see_partially_updated_status(self):
        previous = self._check({'tag_name': 'v1.11.1'})
        started, finish = threading.Event(), threading.Event()

        def fetch():
            started.set()
            finish.wait(timeout=5)
            return {'tag_name': 'v2.0'}

        with mock.patch.object(update_check, 'fetch_latest_release', side_effect=fetch):
            worker = threading.Thread(target=update_check.run_check, args=('1.11.1',))
            worker.start()
            try:
                self.assertTrue(started.wait(timeout=5))
                self.assertEqual(update_check.get_status(), previous)
            finally:
                finish.set()
                worker.join(timeout=5)
        self.assertEqual(update_check.get_status()['latest'], '2.0')

    def test_asset_and_status_snapshots_cannot_modify_internal_state(self):
        self._check({'tag_name': 'v2.0', 'assets': [{
            'name': 'a.exe', 'browser_download_url': 'https://example.invalid/a.exe', 'digest': DIGEST,
        }]})
        snapshot = update_check.get_status()
        snapshot['assets'][0]['digest'] = 'bad'
        snapshot['assets'].clear()
        self.assertEqual(update_check.get_status()['assets'][0]['digest'], DIGEST)

    def test_old_cache_is_ignored_and_no_new_cache_is_written(self):
        from utils import tray_common

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.update_check_cache.json'
            old = '{"last_attempt_at": "invalid", "assets": "invalid"}'
            path.write_text(old, encoding='utf-8')
            with mock.patch.object(tray_common, 'APP_DIR', Path(tmp)):
                self.assertTrue(self._check({'tag_name': 'v2.0'})['has_update'])
            self.assertEqual(path.read_text(encoding='utf-8'), old)
            self.assertEqual(list(Path(tmp).iterdir()), [path])

    def test_fetch_is_one_request_without_etag_and_with_timeout(self):
        opener = _opener(_Response(json.dumps({'tag_name': 'v2.0'}).encode()))
        with mock.patch.object(update_check, 'build_github_opener', opener):
            self.assertEqual(update_check.fetch_latest_release(timeout=7)['tag_name'], 'v2.0')
        args, kwargs = opener.return_value.open.call_args
        self.assertEqual(args[0].full_url, update_check.RELEASES_LATEST_API)
        self.assertFalse(args[0].has_header('If-none-match'))
        self.assertEqual(kwargs['timeout'], 7)



if __name__ == '__main__':
    unittest.main()
