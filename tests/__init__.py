import subprocess
import tempfile
import unittest

from pathlib import Path
from typing import List, Optional


OPENSSL = '/usr/local/opt/openssl/bin/openssl'


class TestEnvironment:

	@classmethod
	def path(cls) -> Path:
		return Path(__file__).resolve().parent / '.env'

	@classmethod
	def ca_certificate_path(cls) -> Path:
		return cls.path() / 'ca.crt.pem'

	@classmethod
	def ca_key_path(cls) -> Path:
		return cls.path() / 'ca.key.pem'

	@classmethod
	def ca_serial_path(cls) -> Path:
		return cls.path() / 'ca.crt.srl'

	@classmethod
	def default_keychain_path(cls) -> Path:
		security = subprocess.run(
			['security', 'default-keychain'],
			check=True,
			capture_output=True,
			text=True,
		)
		lines = security.stdout.splitlines(keepends=False)
		assert 1 == len(lines), "No default keychain"
		# Remove whitespace and quotes from output
		return Path(lines[0].strip()[1:-1])

	@classmethod
	def ca_fingerprint(cls) -> str:
		with tempfile.NamedTemporaryFile() as der:
			subprocess.run(
				[
					OPENSSL, 'x509',
					'-in', str(cls.ca_certificate_path()),
					'-inform', 'PEM',
					'-out', der.name,
					'-outform', 'DER',
				],
				check=True,
			)
			dgst = subprocess.run(
				[OPENSSL, 'dgst', '-sha1', der.name],
				check=True,
				capture_output=True,
				text=True,
			)
		lines = dgst.stdout.splitlines(keepends=False)
		assert 1 == len(lines)
		line = lines[0]
		assert 40 < len(line)
		return line[-40:]

	@classmethod
	def create_server_certificate(
		cls,
		key_path: Path,
		certificate_path: Path,
		subjectAltNames: Optional[List[str]] = None,
	):
		if subjectAltNames is None:
			subjectAltNames = ['DNS:localhost']

		exts = [
			'extendedKeyUsage=serverAuth',
			f'subjectAltName={",".join(subjectAltNames)}',
		]

		with tempfile.TemporaryDirectory() as temp_dir:
			temp_path = Path(temp_dir)

			csr_path = temp_path / 'csr.pem'
			ext_path = temp_path / 'ext.cfg'

			# Create certificate request
			subprocess.run(
				[
					OPENSSL, 'req', '-new', '-nodes',
					'-newkey', 'rsa:2048',
					'-keyout', str(key_path),
					'-out', str(csr_path),
					'-subj', f'/O={cls.__name__}',
				],
				check=True,
				capture_output=True,
			)

			ext_path.write_text('\n'.join(exts))

			# Sign certificate request with CA
			subprocess.run(
				[
					OPENSSL, 'x509', '-req',
					'-in', str(csr_path),
					'-CA', str(cls.ca_certificate_path()),
					'-CAkey', str(cls.ca_key_path()),
					'-CAcreateserial',
					'-extfile', str(ext_path),
					'-out', str(certificate_path),
					'-days', '1',
				],
				check=True,
				capture_output=True,
			)

	@classmethod
	def exists(cls) -> bool:
		# TODO Implement more thorough checks
		return cls.path().exists()

	@classmethod
	def setup(cls, days: int):
		assert not cls.exists()

		if not Path(OPENSSL).exists():
			raise Exception("Please install openssl via brew: brew install openssl")

		path = cls.path()
		path.mkdir(mode=0o700)

		# Create self-signed CA certificate
		subprocess.run(
			[
				OPENSSL, 'req', '-x509', '-nodes',
				'-newkey', 'rsa:2048',
				'-keyout', str(cls.ca_key_path()),
				'-out', str(cls.ca_certificate_path()),
				'-subj', f'/O=ats.{cls.__name__}',
				'-extensions', 'v3_ca',
				'-days', str(days),
			],
			check=True,
		)

		# Trust self-signed CA certificate as root CA
		keychain_path = cls.default_keychain_path()
		subprocess.run(
			[
				'security', 'add-trusted-cert',
				'-k', str(keychain_path),
				'-p', 'basic',
				'-p', 'ssl',
				str(cls.ca_certificate_path()),
			],
			check=True,
			capture_output=True,
		)

	@classmethod
	def teardown(cls):
		assert cls.exists()

		fingerprint = cls.ca_fingerprint()

		# Remove CA trust and delete from keychain
		subprocess.run(
			['security', 'delete-certificate', '-t', '-Z', fingerprint],
			check=True,
		)

		# Remove key and certificate from disk
		cls.ca_serial_path().unlink(missing_ok=True)
		cls.ca_key_path().unlink()
		cls.ca_certificate_path().unlink()
		cls.path().rmdir()


requires_test_environment = unittest.skipUnless(
	TestEnvironment.exists(),
	"Requires test environment. Run `ats test-environment setup` first.",
)
