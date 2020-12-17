import enum
import json
import plistlib
import re
import subprocess
import tempfile

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
from typing_extensions import Protocol

from utilities import CodesigningIdentity, State, Utility


class LogFunc(Protocol):

	def __call__(self, msg: str, nl: bool = True): ...


def no_log(msg: str, nl: bool = True):
	pass


@enum.unique
class ErrorCodes(enum.IntEnum):
	DomainNotFound = -1003

	CouldNotConnect = -1004
	"""
	- Server not running
	"""

	NetworkConnectionLost = -1005
	"""
	- Trying to connect without TLS to a TLS server
	"""

	ATSError = -1022
	"""
	- Occurs for HTTP, even if the URL would redirect to HTTPS
	"""

	SSLError = -1200

	# The codes below were observed from test cases but might not reflect the
	# actual underlying error appropriately.
	# TODO Lookup error codes

	NoCertificateTransparency = -9802
	"""
	SSLError
	- Certificate is not in at least two of Apple-trusted CT logs
	"""

	NoForwardSecrecy = -9824
	"""
	SSLError
	- Connection is not forward secure
	"""

	TlsError = -9836
	"""
	SSLError
	- Invalid TLS version
	- No common ciphers
	- Incorrect subjectAltName?
	"""

	DeprecatedSSL = -9838  # SSLv3
	"""
	SSLError
	- SSLv3
	"""

	InvalidSubjectAltName = -9843
	"""
	SSLError
	- Invalid subjectAltName
	"""


@enum.unique
class TlsVersion(enum.IntEnum):
	TLSv1_0 = 0
	TLSv1_1 = 1
	TLSv1_2 = 2
	TLSv1_3 = 3

	def __str__(self) -> str:
		return f"TLSv1.{self.value}"

	@classmethod
	def from_str(cls, value: str) -> 'TlsVersion':
		rx = re.compile(r'^TLSv1\.([0-3])$')
		m = rx.fullmatch(value)
		if not m:
			raise ValueError(f"Invalid TlsVersion: {value}")
		return cls(int(m.group(1)))


@dataclass(frozen=True)
class Url:
	value: str

	@property
	def hostname(self) -> str:
		hostname = urlparse(self.value).hostname
		assert hostname is not None
		return hostname

	@property
	def is_local(self) -> bool:
		return '.' not in self.hostname or self.hostname.endswith('.local')

	@property
	def is_ip(self) -> bool:
		try:
			ip_address(self.hostname)
		except ValueError:
			return False
		return True

	@property
	def is_http(self) -> bool:
		return urlparse(self.value).scheme == 'http'

	@property
	def with_https(self) -> 'Url':
		if self.is_http:
			return self.__class__('https' + self.value[4:])
		return self

	def __str__(self) -> str:
		return self.value

	@classmethod
	def from_url(cls, url: str) -> Optional['Url']:
		parsed = urlparse(url)
		if parsed.hostname is None:
			return None
		if parsed.scheme not in {'http', 'https'}:
			return None
		return cls(url)


class Configuration(enum.IntFlag):
	AllowsArbitraryLoads = 1 << 0
	AllowsLocalNetworking = 1 << 1
	AllowsInsecureHttpLoads = 1 << 2
	RequiresForwardSecrecy = 1 << 3
	RequiresCertificateTransparency = 1 << 4
	_TLS1 = 1 << 5
	_TLS2 = 1 << 6

	# Convenience flags

	# NOTE `TLSv1_0` is encoded with 0. The convenience flag cannot be set as
	# `TLSv1_0 = 0`, because then `TLSv1_0 in TLSv1_1` would be `True`, which
	# it clearly is not. Better use `Configuration.tls_version`
	# instead of the flags.
	#TLSv1_0 = 0
	TLSv1_1 = _TLS1
	TLSv1_2 = _TLS2
	TLSv1_3 = _TLS1 | _TLS2

	Default = RequiresForwardSecrecy | TLSv1_2
	MostSecure = RequiresForwardSecrecy | TLSv1_3 | RequiresCertificateTransparency

	def with_tls_version(self, tls_version: TlsVersion) -> 'Configuration':
		cls = self.__class__
		cleared = self & ~cls.TLSv1_3
		if tls_version is TlsVersion.TLSv1_0:
			return cleared
		elif tls_version is TlsVersion.TLSv1_1:
			return cleared | cls.TLSv1_1
		elif tls_version is TlsVersion.TLSv1_2:
			return cleared | cls.TLSv1_2
		elif tls_version is TlsVersion.TLSv1_3:
			return cleared | cls.TLSv1_3
		else:
			raise NotImplementedError(f"Unhandled TLS version: {str(tls_version)}")

	@property
	def tls_version(self) -> TlsVersion:
		cls = self.__class__
		if cls._TLS1 | cls._TLS2 in self:
			return TlsVersion.TLSv1_3
		elif cls._TLS2 in self:
			return TlsVersion.TLSv1_2
		elif cls._TLS1 in self:
			return TlsVersion.TLSv1_1
		else:
			return TlsVersion.TLSv1_0

	@property
	def is_default(self) -> bool:
		"""
		Check whether the current configuration is the default configuration.

		The information was obtained from official documentation and is subject
		to change.
		"""

		return self is self.__class__.Default

	@property
	def requires_justification(self) -> bool:
		"""
		Checks whether the current configuration would require a justification
		when submitted to the App Store.

		The information was obtained from official documentation and might not
		reflect actual App Review decisions and is subject to change.
		"""

		cls = self.__class__
		return any([
			cls.AllowsArbitraryLoads in self,
			cls.AllowsInsecureHttpLoads in self,
			self.tls_version < TlsVersion.TLSv1_2,
		])

	@classmethod
	def ats_key(cls, flag: 'Configuration') -> str:
		return {
			cls.AllowsArbitraryLoads: 'NSAllowsArbitraryLoads',
			cls.AllowsLocalNetworking: 'NSAllowsLocalNetworking',
			cls.AllowsInsecureHttpLoads: 'NSExceptionAllowsInsecureHTTPLoads',
			cls.RequiresForwardSecrecy: 'NSExceptionRequiresForwardSecrecy',
			cls.RequiresCertificateTransparency: 'NSRequiresCertificateTransparency',
		}[flag]

	def __str__(self) -> str:
		cls = self.__class__

		flags: List[str] = []
		if cls.AllowsArbitraryLoads in self:
			flags.append("ArbitaryLoads")
		if cls.AllowsLocalNetworking in self:
			flags.append("LocalNetworking")
		if cls.AllowsInsecureHttpLoads in self:
			flags.append("InsecureHTTPLoads")
		if cls.RequiresForwardSecrecy in self:
			flags.append("FS")
		if cls.RequiresCertificateTransparency in self:
			flags.append("CT")
		flags.append(str(self.tls_version))

		result = '+'.join(flags)

		if self is cls.MostSecure:
			result += '=MostSecure'

		if self is cls.Default:
			result += '=Default'

		return result

	def ats_dict(
		self,
		domains: Optional[Set[str]] = None,
		simplify: bool = True,
	) -> Dict[str, Any]:
		if domains is None:
			domains = set()

		cls = self.__class__

		result: Dict[str, Any] = dict()

		def maybe_set(d: Dict[str, Any], flag: 'Configuration'):
			if not simplify or (flag in self) != (flag in cls.Default):
				d[cls.ats_key(flag)] = flag in self

		maybe_set(result, cls.AllowsArbitraryLoads)
		maybe_set(result, cls.AllowsLocalNetworking)

		exceptions: Dict[str, Dict[str, Any]] = dict()
		for domain in domains:
			exception: Dict[str, Any] = dict()

			flags = {
				cls.AllowsInsecureHttpLoads,
				cls.RequiresForwardSecrecy,
				cls.RequiresCertificateTransparency,
			}
			for flag in flags:
				maybe_set(exception, flag)

			if not simplify or self.tls_version != cls.Default.tls_version:
				exception['NSExceptionMinimumTLSVersion'] = str(self.tls_version)

			if not simplify or exception:
				exceptions[domain] = exception

		if not simplify or exceptions:
			result['NSExceptionDomains'] = exceptions

		return result


@dataclass
class DiagnoseUtility(Utility):

	@classmethod
	def name(self) -> str:
		return 'atsdiag'

	@classmethod
	def compile_and_sign_with(
		cls,
		ats_configuration: Configuration,
		exception_domains: Optional[Set[str]] = None,
		target_path: Optional[Path] = None,
		optimize: bool = True,
		identity: Optional[CodesigningIdentity] = None,
	) -> 'DiagnoseUtility':
		if exception_domains is None:
			exception_domains = set()

		with cls.default_info_plist_path().open('rb') as f:
			info_plist = plistlib.load(f)

		info_plist['NSAppTransportSecurity'] = ats_configuration.ats_dict(
			domains=exception_domains,
			simplify=False,
		)

		# Compile
		with tempfile.NamedTemporaryFile() as tmp:
			tmp_path = Path(tmp.name)

			with tmp_path.open('wb') as f:
				plistlib.dump(info_plist, f, fmt=plistlib.FMT_XML)

			atsdiag = cls.start_compilation(
				target_path=target_path,
				optimize=optimize,
				info_plist_path=tmp_path,
			)
			atsdiag.wait()

		assert atsdiag._state is State.Compiled

		# Sign
		atsdiag.start_signing(identity=identity)
		atsdiag.wait()

		assert atsdiag.is_ready

		return atsdiag

	def start(self, urls: Set[Url]):
		assert self.is_ready

		intermediate = subprocess.Popen(
			[str(self.path)] + list({str(url) for url in urls}),
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE,
			text=True,
		)
		self._start(intermediate)

	def take_results(self) -> List[Dict[str, Any]]:
		assert self.is_finished
		assert self._intermediate is not None

		stdout, stderr = self._intermediate.communicate()
		results: List[Dict[str, Any]] = []
		jsonlines = stdout.splitlines(keepends=False)
		for line in jsonlines:
			result: Dict[str, Any] = json.loads(line)
			results.append(result)
		self._finalize()
		return results

	def run(self, urls: Set[Url]) -> List[Dict[str, Any]]:
		self.start(urls)
		self.wait()

		assert self.is_finished

		return self.take_results()


def find_best_configuration(
	url: Url,
	identity: Optional[CodesigningIdentity] = None,
	upgrade_scheme: bool = False,
	log_info: LogFunc = no_log,
	log_error: LogFunc = no_log,
	log_success: LogFunc = no_log,
	log_special: LogFunc = no_log,
) -> Optional[Dict[str, Any]]:
	log_info(f"URL: {url} ", nl=False)

	# Ignore IPv4 and IPv6 addresses
	if url.is_ip:
		log_success("✓ Connections to IP addresses are ignored by ATS")
		return None

	# HTTP -> HTTPS
	if upgrade_scheme and url.is_http:
		log_error("× No TLS")
		log_special("  → ", nl=False)
		new_url = url.with_https
		log_info(f"Upgrading scheme to HTTPS: {new_url}")
		return find_best_configuration(
			url=new_url,
			identity=identity,
			log_info=log_info,
			log_error=log_error,
			log_success=log_success,
			log_special=log_special,
		)
	log_success("✓")

	configuration: Configuration = Configuration.MostSecure
	exception_domains = {url.hostname}

	while configuration != 0:
		with tempfile.TemporaryDirectory(prefix='ats-') as temp_dir_:
			temp_dir = Path(temp_dir_)

			target_path = temp_dir / f'atsdiag-{str(configuration)}'

			log_info(f"Configuration {str(configuration)}")
			log_special("  · ", nl=False)
			log_info("Compiling helper... ", nl=False)
			atsdiag = DiagnoseUtility.compile_and_sign_with(
				ats_configuration=configuration,
				exception_domains=exception_domains,
				target_path=target_path,
				identity=identity,
			)
			log_success("✓")

			log_special("  · ", nl=False)
			log_info("Connecting... ", nl=False)
			diagnostics = atsdiag.run({url})[0]
			error: Dict[str, Any] = diagnostics.get('error', dict())

			if not error:
				log_success("✓")
				return configuration.ats_dict(exception_domains, simplify=True)

			log_error("× ", nl=False)

			code = error.get('code', None)

			if code == ErrorCodes.DomainNotFound:
				log_error("DomainNotFound")
				# TODO Mark URL as finished
			elif code == ErrorCodes.CouldNotConnect:
				log_error("CouldNotConnect")
				# TODO Mark URL as finsihed
			elif code == ErrorCodes.SSLError:
				log_error("SSLError: ", nl=False)
				ssl_error = int(error.get('userInfo', dict()).get('_kCFStreamErrorCodeKey', None))
				if ssl_error == ErrorCodes.TlsError:
					log_error("TLSError")
					tls_version = configuration.tls_version
					if TlsVersion.TLSv1_0 < tls_version:
						new_tls_version = TlsVersion(tls_version - 1)
						log_special("  → ", nl=False)
						log_info(f"Decreasing required TLS version to {new_tls_version}")
						configuration = configuration.with_tls_version(new_tls_version)
						continue
					else:
						# Occurs f. e. if trying to connect with TLS to a
						# non-TLS server.
						if not url.is_http:
							# TODO Try arbitrary loads?
							log_error("Are you trying to establish a TLS connection to a server that does not support TLS?")
							return None
						# TODO Can this occur?
						log_error("UNHANDLED")
				elif ssl_error == ErrorCodes.NoCertificateTransparency:
					log_error("NoCertificateTransparency")
					if Configuration.RequiresCertificateTransparency in configuration:
						log_special("  → ", nl=False)
						log_info("Disabling requirement for certificate transparency")
						configuration &= ~Configuration.RequiresCertificateTransparency
						continue
					else:
						# TODO Can this occur?
						log_error("UNHANDLED")
				elif ssl_error == ErrorCodes.NoForwardSecrecy:
					log_error("NoForwardSecrecy")
					if Configuration.RequiresForwardSecrecy in configuration:
						log_special("  → ", nl=False)
						log_info("Disabling requirement for forward secrecy")
						configuration &= ~Configuration.RequiresForwardSecrecy
						continue
					else:
						# TODO Can this occur?
						log_error("UNHANDLED")
				elif ssl_error == ErrorCodes.DeprecatedSSL:
					log_error("DeprecatedSSL")
					# TODO Can there be other reasons for this to occur?
					# TODO Mark URL as finished
				else:
					log_error(f"Unhandled SSL error code: {ssl_error}")
			elif code == ErrorCodes.ATSError:
				log_error("ATSError: ", nl=False)
				if url.is_http:
					log_error("No TLS")
					assert not upgrade_scheme

					log_special("  → ", nl=False)
					log_info("Allowing insecure HTTP loads")
					# TODO The best configuration for HTTPS-URLs of the same
					# domain still need to be determined.
					configuration = Configuration.Default | Configuration.AllowsInsecureHttpLoads
					continue

				if url.is_local:
					log_error("Local domain")
					log_special("  → ", nl=False)
					log_info("Allowing local networking")
					configuration = Configuration.AllowsLocalNetworking
					exception_domains = set()
					continue

				assert Configuration.AllowsArbitraryLoads not in configuration

				log_error("Unknown error")
				log_special("  → ", nl=False)
				log_info("Disabling ATS")
				configuration = Configuration.AllowsArbitraryLoads
				exception_domains = set()
				continue
			else:
				log_error(f"Unhandled error code: {code}")

			return dict(
				ats=configuration.ats_dict(exception_domains, simplify=True),
				diagnostics=diagnostics,
			)

	assert False, "Should not be reached."
