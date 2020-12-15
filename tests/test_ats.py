#!/usr/bin/env python

import subprocess
import tempfile
import unittest

from pathlib import Path
from time import sleep
from typing import List, Optional
from random import randint

import ddt

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


@ddt.ddt
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
		maximum_tls_version: Optional[ats.TlsVersion] = None,
		opts: Optional[List[str]] = None,
	):
		assert self.server is None

		if opts is None:
			opts = []

		if maximum_tls_version is not None:
			max_protocol = str(maximum_tls_version)
			if maximum_tls_version is ats.TlsVersion.TLSv1_0:
				max_protocol = max_protocol[:-2]
			opts += ['-max_protocol', max_protocol]

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

	def compile_helper(
		self,
		ats_configuration: ats.Configuration,
	) -> ats.DiagnoseUtility:
		target_path = self.temp_dir / 'atsdiag'

		atsdiag = ats.DiagnoseUtility.compile_and_sign_with(
			ats_configuration=ats_configuration,
			exception_domains={'localhost'},
			target_path=target_path,
		)

		return atsdiag

	@property
	def url(self) -> str:
		return f'https://localhost:{self.port}/'

	@requires_test_environment
	@ddt.data(
		(ats.Configuration.Default, ats.TlsVersion.TLSv1_2, []),
		(ats.Configuration.Default, ats.TlsVersion.TLSv1_3, []),
		(
			ats.Configuration.Default.with_tls_version(ats.TlsVersion.TLSv1_3),
			ats.TlsVersion.TLSv1_3,
			[],
		),
		(
			ats.Configuration.Default & ~ats.Configuration.RequiresForwardSecrecy,
			ats.TlsVersion.TLSv1_2,
			[],
		),
		(
			ats.Configuration.Default & ~ats.Configuration.RequiresForwardSecrecy,
			ats.TlsVersion.TLSv1_2,
			['-no_dhe', '-cipher', 'AES256-GCM-SHA384'],  # disable FS
		),
	)
	@ddt.unpack
	def test_atsdiag_positive(
		self,
		configuration: ats.Configuration,
		maximum_tls_version: ats.TlsVersion,
		server_opts: List[str],
	):
		self.start_server(maximum_tls_version=maximum_tls_version, opts=server_opts)

		atsdiag = self.compile_helper(configuration)

		diagnostics_list = atsdiag.run({self.url})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], self.url)

		self.assertIn('timestamp', diagnostics)

		self.assertNotIn('error', diagnostics)

	@requires_test_environment
	@ddt.data(
		(ats.Configuration.Default, ats.TlsVersion.TLSv1_0, -9836, []),
		(ats.Configuration.Default, ats.TlsVersion.TLSv1_1, -9836, []),
		(  # Test certificate is not in CT log
			ats.Configuration.MostSecure, ats.TlsVersion.TLSv1_3, -9802, []),
		(
			ats.Configuration.Default.with_tls_version(ats.TlsVersion.TLSv1_3),
			ats.TlsVersion.TLSv1_2,
			-9836,
			[],
		),
		(
			ats.Configuration.Default,
			ats.TlsVersion.TLSv1_2,  # PFS is enforced in TLSv1.3
			-9824,
			['-no_dhe', '-cipher', 'AES256-GCM-SHA384'],  # disable FS
		),
	)
	@ddt.unpack
	def test_atsdiag_negative(
		self,
		configuration: ats.Configuration,
		maximum_tls_version: ats.TlsVersion,
		error_code: int,  # FIXME
		server_opts: List[str],
	):
		self.start_server(maximum_tls_version=maximum_tls_version, opts=server_opts)

		atsdiag = self.compile_helper(configuration)

		diagnostics_list = atsdiag.run({self.url})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], self.url)

		self.assertIn('timestamp', diagnostics)

		self.assertIn('error', diagnostics)

		error = diagnostics['error']

		self.assertIn('code', error)

		code = error['code']

		self.assertEqual(code, ats.ErrorCodes.SSLError)

		self.assertIn('userInfo', error)

		user_info = error['userInfo']

		self.assertIn('_kCFStreamErrorCodeKey', user_info)

		stream_error_code = int(user_info['_kCFStreamErrorCodeKey'])

		self.assertEqual(stream_error_code, error_code)


if __name__ == '__main__':
	unittest.main()
