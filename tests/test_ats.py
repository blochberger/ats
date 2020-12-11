#!/usr/bin/env python

import subprocess
import tempfile
import unittest

from pathlib import Path
from pprint import pprint
from time import sleep
from typing import List, Optional
from random import randint

import ats

from utilities import DiagnoseUtility

from tests import requires_test_environment, TestEnvironment


class TestDiagnostics(unittest.TestCase):

	def setUp(self):
		self._temp_dir = tempfile.TemporaryDirectory(prefix=self.__class__.__name__)

	def tearDown(self):
		self._temp_dir.cleanup()

	@property
	def temp_dir(self) -> Path:
		return Path(self._temp_dir.name)

	def test_unknown_host(self):
		url = 'https://not-reachable'

		target_path = self.temp_dir / 'atsdiag'

		atsdiag = DiagnoseUtility.compile_and_sign(
			target_path=target_path,
		)

		diagnostics_list = atsdiag.run({url})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], url)

		self.assertIn('timestamp', diagnostics)
		self.assertIn('error', diagnostics)

		error = diagnostics['error']

		self.assertIn('code', error)
		self.assertEqual(error['code'], ats.ErrorCodes.DomainNotFound)


class TestDiagnosticsLive(unittest.TestCase):

	@property
	def temp_dir(self) -> Path:
		return Path(self._temp_dir.name)

	@property
	def key_path(self) -> Path:
		return self.temp_dir / 'key.pem'

	@property
	def certificate_path(self) -> Path:
		return self.temp_dir / 'crt.pem'

	def setUp(self):
		self._temp_dir = tempfile.TemporaryDirectory(prefix=self.__class__.__name__)
		TestEnvironment.create_server_certificate(
			key_path=self.key_path,
			certificate_path=self.certificate_path,
		)
		self.server: Optional[subprocess.Popen] = None
		self.port = randint(1024, 65536)

	def tearDown(self):
		self._temp_dir.cleanup()

		# Stop server
		if self.server is not None:
			self.stop_server()

	def start_server(self, opts: Optional[List[str]] = None):
		assert self.server is None

		if opts is None:
			opts = []

		self.server = subprocess.Popen(
			[
				'openssl', 's_server', '-www',
				'-accept', str(self.port),
				'-key', str(self.key_path),
				'-cert', str(self.certificate_path),
				'-no_ticket',
			] + opts,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)

		sleep(2)  # Wait a bit for the server to start up.

		assert self.server.poll() is None, "Server is not running."

	def stop_server(self):
		assert self.server is not None

		self.server.terminate()
		self.server.wait()

		self.server = None

	def compile_helper(self) -> DiagnoseUtility:
		target_path = self.temp_dir / 'atsdiag'

		atsdiag = DiagnoseUtility.compile_and_sign(
			target_path=target_path,
		)

		return atsdiag

	@property
	def url(self) -> str:
		return f'https://localhost:{self.port}'

	@requires_test_environment
	def test_default(self):
		self.start_server(['-tls1_2'])
		atsdiag = self.compile_helper()

		diagnostics_list = atsdiag.run({self.url})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], self.url)

		self.assertIn('timestamp', diagnostics)
		self.assertNotIn('error', diagnostics)

	@requires_test_environment
	def test_default_tlsv1_1(self):
		self.start_server(['-tls1_1'])
		atsdiag = self.compile_helper()

		diagnostics_list = atsdiag.run({self.url})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], self.url)

		self.assertIn('timestamp', diagnostics)
		self.assertIn('error', diagnostics)


if __name__ == '__main__':
	unittest.main()
