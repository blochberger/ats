#!/usr/bin/env python

import subprocess
import tempfile
import unittest

from pathlib import Path
from time import sleep
from typing import List, Optional, Tuple
from random import randint

import ats

from tests import requires_test_environment, TestEnvironment, OPENSSL


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

		atsdiag = ats.DiagnoseUtility.compile_and_sign(
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

	def start_server(
		self,
		tls_version: Optional[ats.TlsVersion] = None,
		opts: Optional[List[str]] = None,
	):
		assert self.server is None

		if opts is None:
			opts = []

		if tls_version is not None:
			if tls_version is ats.TlsVersion.TLSv1_0:
				opts.append('-tls1')
			else:
				opts.append(f'-tls1_{tls_version.value}')

		self.server = subprocess.Popen(
			[
				OPENSSL, 's_server', '-www',
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

	def compile_helper(self) -> ats.DiagnoseUtility:
		target_path = self.temp_dir / 'atsdiag'

		atsdiag = ats.DiagnoseUtility.compile_and_sign(
			target_path=target_path,
		)

		return atsdiag

	@property
	def url(self) -> str:
		return f'https://localhost:{self.port}'

	@requires_test_environment
	def test_default_with_tls_versions(self):
		"""
		Test default ATS configuration with different TLS versions.

		The default ATS configuration should succeed to connect to a server with
		TLSv1.2 or TLSv1.3 support, using modern ciphers with PFS and keys of
		sufficient size. Previous TLS versions should be rejected by ATS.
		"""

		test_data: List[Tuple[ats.TlsVersion, bool]] = [
			(ats.TlsVersion.TLSv1_0, False),
			(ats.TlsVersion.TLSv1_1, False),
			(ats.TlsVersion.TLSv1_2, True),

			# FIXME Will fail on older versions of macOS
			#(ats.TlsVersion.TLSv1_3, True),
		]

		atsdiag = self.compile_helper()  # Uses default ATS configuration

		for tls_version, is_positive in test_data:
			with self.subTest(tls_version=str(tls_version), is_positive=is_positive):

				self.start_server(tls_version=tls_version)

				diagnostics_list = atsdiag.run({self.url})

				self.assertEqual(len(diagnostics_list), 1)

				diagnostics = diagnostics_list[0]

				self.assertIn('url', diagnostics)
				self.assertEqual(diagnostics['url'], self.url)

				self.assertIn('timestamp', diagnostics)

				if is_positive:
					self.assertNotIn('error', diagnostics)
				else:
					self.assertIn('error', diagnostics)

					error = diagnostics['error']

					self.assertIn('code', error)

					code = error['code']

					self.assertEqual(code, ats.ErrorCodes.SSLError)

				self.stop_server()


if __name__ == '__main__':
	unittest.main()
