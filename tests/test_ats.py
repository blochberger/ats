#!/usr/bin/env python

import subprocess
import tempfile
import unittest

from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional
from random import randint

import ddt

from ats import (
	Configuration,
	DiagnoseUtility,
	Diagnostics,
	DomainConfiguration,
	Endpoint,
	Error,
	SSLError,
	TlsVersion,
	find_best_configuration,
)

from tests import requires_test_environment, TestEnvironment, OPENSSL


@ddt.ddt
class TestEndpoint(unittest.TestCase):

	@ddt.data('foo', 'http://', 'ftp://example.com', 'file:///foo')
	def test_from_url_negative(self, value: str):
		endpoint = Endpoint.from_url(value)
		self.assertIsNone(endpoint)

	@ddt.data(
		('http://example.com', 'http://example.com/'),
		('http://example.com:80/', 'http://example.com/'),
		('http://example.com:1234', 'http://example.com:1234/'),
		('HTTP://EXAMPLE.COM/PATH', 'http://example.com/'),
		('https://example.com', 'https://example.com/'),
		('http://example.com:443', 'http://example.com:443/'),
		('http://example.com/path?key=value#fragment', 'http://example.com/'),
		('http://example.com/foo/..', 'http://example.com/'),
	)
	@ddt.unpack
	def test_from_url(self, value: str, expected: str):
		endpoint = Endpoint.from_url(value)
		self.assertIsNotNone(endpoint)
		self.assertEqual(expected, str(endpoint))

	@ddt.data(
		('http://localhost/', True),
		('https://localhost/', True),
		('http://foo.bar.local', True),
		('https://example.com', False),
	)
	@ddt.unpack
	def test_is_local(self, value: str, expected: bool):
		endpoint = Endpoint.from_url(value)
		assert endpoint is not None
		self.assertEqual(endpoint.is_local, expected)

	@ddt.data(
		('http://localhost/', False),
		('http://127.0.0.1/', True),
		('http://[::1]/', True),
	)
	@ddt.unpack
	def test_is_ip(self, value: str, expected: bool):
		endpoint = Endpoint.from_url(value)
		assert endpoint is not None
		self.assertEqual(endpoint.is_ip, expected)

	@ddt.data(
		('http://example.com', False),
		('https://example.com', True),
	)
	@ddt.unpack
	def test_uses_tls(self, value: str, expected: bool):
		endpoint = Endpoint.from_url(value)
		assert endpoint is not None
		self.assertEqual(endpoint.uses_tls, expected)

	@ddt.data(
		('http://example.com', 'https://example.com/'),
		('https://example.com', 'https://example.com/'),
		('http://example.com:1234', 'https://example.com:1234/'),
	)
	@ddt.unpack
	def test_with_tls(self, value: str, expected_value: str):
		endpoint = Endpoint.from_url(value)
		assert endpoint is not None
		expected = Endpoint.from_url(expected_value)
		assert expected is not None
		self.assertEqual(endpoint.with_tls, expected)

	@ddt.data(
		('http', []),
		('http://', []),
		('http://example.com', ['http://example.com/']),
		('https://example.com', ['https://example.com/']),
		('HTTP://example.com', ['http://example.com/']),
		('Location: https://%s:%d%s', []),
		('http://%@:%@', []),
	)
	@ddt.unpack
	def test_find_instances(self, value: str, expected: List[str]):
		actual = [str(endpoint) for endpoint in Endpoint.find_instances(value)]
		self.assertEqual(expected, actual)


@ddt.ddt
class TestDiagnostics(unittest.TestCase):

	def setUp(self):
		self._temp_dir = tempfile.TemporaryDirectory(prefix=self.__class__.__name__)

	def tearDown(self):
		self._temp_dir.cleanup()

	@property
	def temp_dir(self) -> Path:
		return Path(self._temp_dir.name)

	def test_unknown_host(self):
		endpoint = Endpoint.from_url('https://not-reachable')
		assert endpoint is not None

		target_path = self.temp_dir / 'atsprobe'

		atsprobe = DiagnoseUtility.compile_and_sign(
			target_path=target_path,
		)

		diagnostics_list = atsprobe.run({endpoint})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], str(endpoint))

		self.assertIn('timestamp', diagnostics)
		self.assertIn('error', diagnostics)

		error = diagnostics['error']

		self.assertIn('code', error)
		self.assertEqual(error['code'], Error.CannotFindHost)

	@ddt.data('https://127.0.0.1/', 'https://[::1]:443/')
	def test_find_best_configuration(self, url: str):
		endpoint = Endpoint.from_url(url)
		assert endpoint is not None
		configuration, diagnostics = find_best_configuration(endpoint)
		self.assertEqual(configuration, Configuration())
		self.assertEqual(diagnostics, [Diagnostics(endpoint)])


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
		maximum_tls_version: Optional[TlsVersion] = None,
		opts: Optional[List[str]] = None,
	):
		assert self.server is None

		if opts is None:
			opts = []

		if maximum_tls_version is not None:
			max_protocol = str(maximum_tls_version)
			if maximum_tls_version is TlsVersion.TLSv1_0:
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
		configuration: Configuration,
	) -> DiagnoseUtility:
		target_path = self.temp_dir / 'atsprobe'

		atsprobe = DiagnoseUtility.compile_and_sign_with(
			configuration=configuration,
			target_path=target_path,
		)

		return atsprobe

	@property
	def endpoint(self) -> Endpoint:
		endpoint = Endpoint.from_url(f'https://localhost:{self.port}/')
		assert endpoint is not None
		return endpoint

	@requires_test_environment
	@ddt.data(
		(DomainConfiguration(), TlsVersion.TLSv1_2, []),
		(DomainConfiguration(), TlsVersion.TLSv1_3, []),
		(
			DomainConfiguration(tls_version=TlsVersion.TLSv1_3),
			TlsVersion.TLSv1_3,
			[],
		),
		(
			DomainConfiguration(forward_secrecy=False),
			TlsVersion.TLSv1_2,
			[],
		),
		(
			DomainConfiguration(forward_secrecy=False),
			TlsVersion.TLSv1_2,
			['-no_dhe', '-cipher', 'AES256-GCM-SHA384'],  # disable FS
		),
	)
	@ddt.unpack
	def test_atsprobe_positive(
		self,
		domain_configuration: DomainConfiguration,
		maximum_tls_version: TlsVersion,
		server_opts: List[str],
	):
		configuration = Configuration(
			exceptions={self.endpoint.host: domain_configuration}
		)

		self.start_server(maximum_tls_version=maximum_tls_version, opts=server_opts)

		atsprobe = self.compile_helper(configuration)

		diagnostics_list = atsprobe.run({self.endpoint})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], str(self.endpoint))

		self.assertIn('timestamp', diagnostics)

		self.assertNotIn('error', diagnostics)

	@requires_test_environment
	@ddt.data(
		(DomainConfiguration(), TlsVersion.TLSv1_0, SSLError.PeerProtocolVersion, []),
		(DomainConfiguration(), TlsVersion.TLSv1_1, SSLError.PeerProtocolVersion, []),
		(  # Test certificate is not in CT log
			DomainConfiguration.most_secure(),
			TlsVersion.TLSv1_3,
			SSLError.FatalAlert,
			[],
		),
		(
			DomainConfiguration(tls_version=TlsVersion.TLSv1_3),
			TlsVersion.TLSv1_2,
			SSLError.PeerProtocolVersion,
			[],
		),
		(
			DomainConfiguration(),
			TlsVersion.TLSv1_2,  # PFS is enforced in TLSv1.3
			SSLError.PeerHandshakeFail,
			['-no_dhe', '-cipher', 'AES256-GCM-SHA384'],  # disable FS
		),
	)
	@ddt.unpack
	def test_atsprobe_negative(
		self,
		domain_configuration: DomainConfiguration,
		maximum_tls_version: TlsVersion,
		error_code: SSLError,
		server_opts: List[str],
	):
		configuration = Configuration(
			exceptions={self.endpoint.host: domain_configuration}
		)

		self.start_server(maximum_tls_version=maximum_tls_version, opts=server_opts)

		atsprobe = self.compile_helper(configuration)

		diagnostics_list = atsprobe.run({self.endpoint})

		self.assertEqual(len(diagnostics_list), 1)

		diagnostics = diagnostics_list[0]

		self.assertIn('url', diagnostics)
		self.assertEqual(diagnostics['url'], str(self.endpoint))

		self.assertIn('timestamp', diagnostics)

		self.assertIn('error', diagnostics)

		error = diagnostics['error']

		self.assertIn('code', error)

		code = error['code']

		self.assertEqual(code, Error.SSLError)

		self.assertIn('streamErrorCode', error)

		stream_error_code = int(error['streamErrorCode'])

		self.assertEqual(stream_error_code, error_code)

	@requires_test_environment
	@ddt.data(
		(
			TlsVersion.TLSv1_3,
			[],
			{'NSExceptionDomains': {'localhost': {
				'NSExceptionMinimumTLSVersion': 'TLSv1.3',
			}}},
		),
	)
	@ddt.unpack
	def test_find_best_configuration(
		self,
		maximum_tls_version: TlsVersion,
		server_opts: List[str],
		expected: Optional[Dict[str, Any]],
	):
		self.start_server(maximum_tls_version=maximum_tls_version, opts=server_opts)

		configuration_found, diagnostic_results = find_best_configuration(self.endpoint)

		self.assertIsNotNone(configuration_found)
		self.assertEqual(len(diagnostic_results), 1)

		diagnostics = diagnostic_results[0].json_dict()

		self.assertIn('configuration', diagnostics)

		configuration_used = diagnostics['configuration']

		self.assertEqual(expected, configuration_used)
		self.assertEqual(expected, configuration_found.ats_dict())


if __name__ == '__main__':
	unittest.main()
