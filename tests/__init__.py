import subprocess
import tempfile
import unittest

from pathlib import Path


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
		return cls.path() / 'ca.srl'

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
					'openssl', 'x509',
					'-in', str(cls.ca_certificate_path()),
					'-inform', 'PEM',
					'-out', der.name,
					'-outform', 'DER',
				],
				check=True,
			)
			dgst = subprocess.run(
				['openssl', 'dgst', '-sha1', der.name],
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
	def create_server_certificate(cls, key_path: Path, certificate_path: Path):
		with tempfile.NamedTemporaryFile() as csr:
			# Create certificate request
			subprocess.run(
				[
					'openssl', 'req', '-new', '-nodes',
					'-newkey', 'rsa:2048',
					'-keyout', str(key_path),
					'-out', csr.name,
					'-subj', f'/O={cls.__name__}/CN=localhost'	,
				],
				check=True,
				capture_output=True,
			)

			# Sign certificate request with CA
			subprocess.run(
				[
					'openssl', 'x509', '-req',
					'-in', csr.name,
					'-CA', str(cls.ca_certificate_path()),
					'-CAkey', str(cls.ca_key_path()),
					'-CAcreateserial',
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

		path = cls.path()
		path.mkdir(mode=0o700)

		# Create self-signed CA certificate
		subprocess.run(
			[
				'openssl', 'req', '-x509', '-nodes',
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
