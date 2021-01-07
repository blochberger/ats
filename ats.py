import enum
import json
import plistlib
import re
import ssl
import subprocess
import tempfile

from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import cached_property
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
from typing_extensions import Protocol
from urllib.parse import urlparse

import OpenSSL

from click import style, unstyle

from utilities import CodesigningIdentity, State, Utility


class LogFunc(Protocol):

	def __call__(self, msg: str, nl: bool = True): ...


def no_log(msg: str, nl: bool = True):
	pass


def timestamp_from_str(value: str) -> datetime:
	# Python cannot handle Z-marker
	if value.endswith('Z'):
		value = value[:-1] + '+00:00'
	return datetime.fromisoformat(value)


@enum.unique
class Error(enum.IntEnum):
	"""
	Defined in Foundation/NSURLError.h
	https://developer.apple.com/documentation/foundation/nserror/1448136-nserror_codes
	"""

	TimedOut = -1001

	CannotFindHost = -1003

	CannotConnectToHost = -1004
	"""
	- Server not running
	"""

	NetworkConnectionLost = -1005
	"""
	- Denied by application firewall
	- Trying to connect without TLS to a TLS server
	"""

	CannotParseResponse = -1017 # TODO Add to atsprobe

	ATSError = -1022
	"""
	- Occurs for HTTP, even if the URL would redirect to HTTPS
	"""

	SSLError = -1200

	@property
	def display(self) -> str:
		rx = re.compile(r'([A-Z][a-z])')
		name = str(self).replace(f'{self.__class__.__name__}.', '')
		return rx.sub(r' \1', name).strip()


@enum.unique
class SSLError(enum.IntEnum):
	"""
	Defined in Security/SecBase.h:
	https://opensource.apple.com/source/Security/Security-59306.140.5/base/SecBase.h.auto.html
	"""

	FatalAlert = -9802
	"""
	- Certificate is not in at least two of Apple-trusted CT logs
	- Certificate is expired
	- https://www.news.com/
	- https://admin2018-pp.homedesign3d.net/
	- https://resources-dev.licenses.adobe.com/
	- https://registration.filezilla-project.org/
	- https://appres.hotmacapp.com/
	- https://store.mindnode.com/
	"""

	ClosedNoNotify = -9816
	"""
	- Unsupported TLS version
	- Certificate is not in at least two of Apple-trusted CT logs?
	- Connection is not forward secure?
	- https://jobssoft.com/
	"""

	PeerHandshakeFail = -9824
	"""
	- Connection is not forward secure
	- Unsupported TLS version
	"""

	PeerProtocolVersion = -9836
	"""
	- Invalid TLS version
	- No common ciphers?
	- Unknown
	"""

	PeerInsufficientSecurity = -9837
	"""
	- Unknown
	"""

	PeerInternalError = -9838
	"""
	- SSLv3
	"""

	HostNameMismatch = -9843
	"""
	- Invalid subjectAltName
	"""

	HandshakeFail = -9858
	"""
	- Unsupported TLS version, e. g., bucket.s3.amazonaws.com
	"""

	@property
	def display(self) -> str:
		rx = re.compile(r'([A-Z][a-z])')
		name = str(self).replace(f'{self.__class__.__name__}.', '')
		return rx.sub(r' \1', name).strip()


class Action(enum.Flag):
	EnableCertificateTransparency = enum.auto()
	DisableCertificateTransparency = enum.auto()
	DecreaseTlsVersion = enum.auto()
	EnableForwardSecrecy = enum.auto()
	DisableForwardSecrecy = enum.auto()
	AllowHttp = enum.auto()
	AllowLocal = enum.auto()
	AllowArbitraryLoads = enum.auto()
	GiveUp = enum.auto()
	Investigate = enum.auto()


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
class Certificate:
	crt: OpenSSL.crypto.X509

	@property
	def expiry_date(self) -> datetime:
		raw = self.crt.get_notAfter().decode()
		assert 14 <= len(raw)
		value = '-'.join([
			raw[:4],  # year
			raw[4:6],  # month
			raw[6:8],  # day
		])
		value += 'T'
		value += ':'.join([
			raw[8:10],  # hour
			raw[10:12],  # minute
			raw[12:14],  # seconds
		])
		value += raw[14:]  # time zone
		return timestamp_from_str(value)

	@property
	def is_expired(self) -> bool:
		return self.expiry_date < datetime.now(timezone.utc)

	@classmethod
	def from_pem(cls, pem: str) -> 'Certificate':
		crt = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem)
		return cls(crt)


@dataclass(frozen=True)
class Endpoint:
	uses_tls: bool
	host: str
	port: int

	@property
	def scheme(self) -> str:
		return 'https' if self.uses_tls else 'http'

	@property
	def is_local(self) -> bool:
		return '.' not in self.host or self.host.endswith('.local')

	@property
	def has_standard_port(self) -> bool:
		if self.uses_tls:
			return self.port == 443
		return self.port == 80

	@property
	def is_ip(self) -> bool:
		try:
			ip_address(self.host)
		except ValueError:
			return False
		return True

	@property
	def reverse_domain_name(self) -> str:
		if self.is_ip:
			return self.host
		return '.'.join(self.host.split('.')[::-1])

	@property
	def with_tls(self) -> 'Endpoint':
		return self.__class__(
			uses_tls=True,
			host=self.host,
			port=443 if self.has_standard_port else self.port,
		)

	@cached_property
	def certificate(self) -> Optional[Certificate]:
		try:
			pem = ssl.get_server_certificate((self.host, self.port))
			return Certificate.from_pem(pem)
		except ssl.SSLError:
			return None

	def __str__(self) -> str:
		result = f'{self.scheme}://{self.host}'
		if not self.has_standard_port:
			result += f':{self.port}'
		result += '/'
		return result

	@classmethod
	def from_url(cls, url: str) -> Optional['Endpoint']:
		parsed = urlparse(url)
		host = parsed.hostname
		if host is None:
			return None
		if parsed.scheme not in {'http', 'https'}:
			return None

		uses_tls = parsed.scheme == 'https'
		host = host.lower()
		port: int
		if parsed.port is None:
			port = 443 if uses_tls else 80
		else:
			port = parsed.port

		return cls(uses_tls=uses_tls, host=host, port=port)

	@classmethod
	def find_instances(cls, value: str) -> Iterator['Endpoint']:
		"""
		Searches for URLs in a string and yields endpoints.
		"""

		scheme_rx = re.compile(r'https?://', re.IGNORECASE)
		path_rx = re.compile(r'/')

		value = value.strip().lower()

		# Remove placeholder that lead to invalid URLs
		for placeholder in ['%@', '%s', '%d', '%i', '%ld', '%li']:
			value = value.replace(placeholder, '')

		def emit_candidate(candidate: str, scheme_end: int) -> Optional['Endpoint']:
			if candidate.endswith(':'):
				candidate = candidate[:-1]

			if len(candidate) <= scheme_end:
				return None

			endpoint = cls.from_url(candidate)
			if endpoint is None:
				import sys
				print(f"\tUnexpected : endpoint{candidate}", file=sys.stderr)
			return endpoint

		while scheme_match := scheme_rx.search(value):
			scheme_start = scheme_match.start()
			value = value[scheme_start:]
			scheme_end = scheme_match.end() - scheme_match.start()
			if path_match := path_rx.search(value[scheme_end:]):
				path_start = scheme_end + path_match.start()
				if endpoint := emit_candidate(value[:path_start], scheme_end):
					yield endpoint
				value = value[path_start + 1:]
				continue
			if endpoint := emit_candidate(value, scheme_end):
				yield endpoint
			break


@dataclass(frozen=True)
class DomainConfiguration:
	includes_subdomains: bool = False
	insecure_http_loads: bool = False
	tls_version: TlsVersion = TlsVersion.TLSv1_2
	forward_secrecy: bool = True
	certificate_transparency: bool = False

	@classmethod
	def most_secure(cls) -> 'DomainConfiguration':
		return cls(
			tls_version=TlsVersion.TLSv1_3,
			certificate_transparency=True,
		)

	@property
	def is_default(self) -> bool:
		"""
		Check whether the configuration is the default configuration.

		The information was obtained from official documentation and is subject
		to change.
		"""
		return self == self.__class__()

	@property
	def requires_justification(self) -> bool:
		"""
		Check whether the configuration requires justification when submitted to
		the App Store.

		The information was obtained from official documentation and might not
		reflect actual App Review decisions and is subject to change.
		"""
		return self.insecure_http_loads or self.tls_version < TlsVersion.TLSv1_2

	@property
	def can_decrease_tls_version(self) -> bool:
		return TlsVersion.TLSv1_0 < self.tls_version

	def __str__(self) -> str:
		return unstyle(self.display())

	def display(self) -> str:
		# Style guide:
		# - neutral = default (white)
		# - secure = green
		# - insecure = red
		# - non-default = bold

		default = self.__class__()

		flags: List[str] = []

		if self.includes_subdomains:
			flags.append(style("Subs", bold=True))

		if self.insecure_http_loads:
			flags.append(style("HTTP", fg='red', bold=True))

		flags.append(style(
			str(self.tls_version),
			fg='red' if self.tls_version < TlsVersion.TLSv1_2 else 'green',
			bold=self.tls_version != default.tls_version,
		))

		if self.forward_secrecy:
			flags.append(style("FS", fg='green'))

		if self.certificate_transparency:
			flags.append(style("CT", fg='green', bold=True))

		result = "+".join(flags)

		if self == self.__class__.most_secure():
			result += "=" + style("MostSecure", fg='green', bold=True)

		if self.is_default:
			result += "=" + style("Default", fg='green')

		return result

	def merged(self, other: 'DomainConfiguration') -> 'DomainConfiguration':
		includes_subdomains = self.includes_subdomains or other.includes_subdomains
		insecure_http_loads = self.insecure_http_loads or other.insecure_http_loads
		tls_version = min([self.tls_version, other.tls_version])
		forward_secrecy = self.forward_secrecy and other.forward_secrecy
		certificate_transparency = self.certificate_transparency and other.certificate_transparency

		return self.__class__(
			includes_subdomains=includes_subdomains,
			insecure_http_loads=insecure_http_loads,
			tls_version=tls_version,
			forward_secrecy=forward_secrecy,
			certificate_transparency=certificate_transparency,
		)

	def ats_dict(self, simplify: bool = True) -> Dict[str, Any]:
		default = self.__class__()

		configuration: Dict[str, Any] = dict()

		if not simplify or self.includes_subdomains != default.includes_subdomains:
			configuration['NSIncludesSubdomains'] = self.includes_subdomains

		if not simplify or self.insecure_http_loads != default.insecure_http_loads:
			configuration['NSExceptionAllowsInsecureHTTPLoads'] = self.insecure_http_loads

		if not simplify or self.tls_version != default.tls_version:
			configuration['NSExceptionMinimumTLSVersion'] = str(self.tls_version)

		if not simplify or self.forward_secrecy != default.forward_secrecy:
			configuration['NSExceptionRequiresForwardSecrecy'] = self.forward_secrecy

		if not simplify or self.certificate_transparency != default.certificate_transparency:
			configuration['NSRequiresCertificateTransparency'] = self.certificate_transparency

		return configuration


@dataclass(frozen=True)
class Configuration:
	arbitrary_loads: bool = False
	local_networking: bool = False
	exceptions: Dict[str, DomainConfiguration] = field(default_factory=dict)

	@property
	def is_default(self) -> bool:
		"""
		Check whether the configuration is the default configuration.

		The information was obtained from official documentation and is subject
		to change.
		"""

		default = self.__class__()

		result = True
		result &= self.arbitrary_loads == default.arbitrary_loads
		result &= self.local_networking == default.local_networking
		result &= all(exception.is_default for exception in self.exceptions.values())

		return result

	@property
	def requires_justification(self) -> bool:
		"""
		Check whether the configuration requires justification when submitted to
		the App Store.

		The information was obtained from official documentation and might not
		reflect actual App Review decisions and is subject to change.
		"""

		if self.arbitrary_loads:
			return True

		return any(
			exception.requires_justification
			for exception in self.exceptions.values()
		)

	def __str__(self) -> str:
		return unstyle(self.display())

	def display(self) -> str:
		# Style guide:
		# - neutral = default (white)
		# - secure = green
		# - insecure = red
		# - non-default = bold

		flags: List[str] = []

		if self.arbitrary_loads:
			flags.append(style("Arbitrary", fg='red', bold=True))

		if self.local_networking:
			flags.append(style("Local", bold=True))

		for domain, exception in self.exceptions.items():
			flags.append(
				style(
					domain,
					fg='blue',
					bold=not (self.is_default and exception.is_default),
				) + ":" + exception.display()
			)

		result = "+".join(flags)

		if self.is_default:
			result += "=" + style("Default", fg='green')

		return result

	def merged(self, other: 'Configuration') -> 'Configuration':
		arbitrary_loads = self.arbitrary_loads or other.arbitrary_loads
		local_networking = self.local_networking or other.local_networking
		exceptions = self.exceptions

		for domain, exception in other.exceptions.items():
			if domain not in exceptions:
				exceptions[domain] = exception
				continue

			exceptions[domain] = exceptions[domain].merged(exception)

		return self.__class__(
			arbitrary_loads=arbitrary_loads,
			local_networking=local_networking,
			exceptions=exceptions,
		)

	def ats_dict(self, simplify: bool = True) -> Dict[str, Dict[str, Any]]:
		configuration: Dict[str, Any] = dict()

		if not simplify or self.arbitrary_loads:
			configuration['NSAllowsArbitraryLoads'] = self.arbitrary_loads

		if not simplify or self.local_networking:
			configuration['NSAllowsLocalNetworking'] = self.local_networking

		exceptions: Dict[str, Dict[str, Any]] = dict()
		for domain, exception in self.exceptions.items():
			exceptions[domain] = exception.ats_dict(simplify=simplify)

		if self.exceptions:
			configuration['NSExceptionDomains'] = exceptions

		return configuration


@dataclass(frozen=True)
class Diagnostics:
	endpoint: Endpoint
	configuration: Optional[Configuration] = None
	redirected: Optional[Endpoint] = None
	timestamp: Optional[datetime] = None
	error: Optional[Dict[str, Any]] = None

	def json_dict(self, simplify: bool = True) -> Dict[str, Any]:
		return {
			'url': str(self.endpoint),
			'redirected_url': None if self.redirected is None else str(self.redirected),
			'configuration': self.configuration.ats_dict(simplify=simplify) if self.configuration else None,
			'timestamp': None if self.timestamp is None else self.timestamp.isoformat(),
			'error': self.error,
		}

	@classmethod
	def success(
		cls,
		endpoint: Endpoint,
		configuration: Configuration,
		timestamp: datetime,
		redirected: Optional[Endpoint] = None,
	) -> 'Diagnostics':
		return cls(
			endpoint=endpoint,
			configuration=configuration,
			redirected=redirected,
			timestamp=timestamp,
		)

	@classmethod
	def erroneous(
		cls,
		endpoint: Endpoint,
		configuration: Configuration,
		timestamp: datetime,
		error: Dict[str, Any],
		redirected: Optional[Endpoint] = None,
	):
		return cls(
			endpoint=endpoint,
			configuration=configuration,
			redirected=redirected,
			timestamp=timestamp,
			error=error,
		)


@dataclass
class DiagnoseUtility(Utility):

	@classmethod
	def name(self) -> str:
		return 'atsprobe'

	@classmethod
	def compile_and_sign_with(
		cls,
		configuration: Configuration,
		target_path: Optional[Path] = None,
		optimize: bool = True,
		identity: Optional[CodesigningIdentity] = None,
	) -> 'DiagnoseUtility':
		with cls.default_info_plist_path().open('rb') as f:
			info_plist = plistlib.load(f)

		info_plist['NSAppTransportSecurity'] = configuration.ats_dict(simplify=True)

		# Compile
		with tempfile.NamedTemporaryFile() as tmp:
			tmp_path = Path(tmp.name)

			with tmp_path.open('wb') as f:
				plistlib.dump(info_plist, f, fmt=plistlib.FMT_XML)

			atsprobe = cls.start_compilation(
				target_path=target_path,
				optimize=optimize,
				info_plist_path=tmp_path,
			)
			atsprobe.wait()

		assert atsprobe._state is State.Compiled

		# Sign
		atsprobe.start_signing(identity=identity)
		atsprobe.wait()

		assert atsprobe.is_ready

		return atsprobe

	def start(self, endpoints: Set[Endpoint]):
		assert self.is_ready

		intermediate = subprocess.Popen(
			[str(self.path)] + list({str(endpoint) for endpoint in endpoints}),
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

	def run(self, endpoints: Set[Endpoint]) -> List[Dict[str, Any]]:
		self.start(endpoints)
		self.wait()

		assert self.is_finished

		return self.take_results()


def determine_action(
	endpoint: Endpoint,
	configuration: Configuration,
	error: Dict[str, Any],
	log_error: LogFunc,
) -> Action:
	code = error.get('code', None)

	try:
		log_error(Error(code).display, nl=False)
	except ValueError:
		log_error(str(code), nl=False)

	# Network layer errors that are not related to transport security issues.
	if code in {
		Error.TimedOut,
		Error.CannotFindHost,
		Error.CannotConnectToHost,
		Error.NetworkConnectionLost,
	}:
		log_error("")  # Newline
		return Action.GiveUp

	log_error(": ", nl=False)

	domain_configuration = configuration.exceptions[endpoint.host]

	if code == Error.ATSError:

		if not endpoint.uses_tls:
			log_error("No TLS")
			return Action.AllowHttp

		if endpoint.is_local:
			log_error("Local domain")
			return Action.AllowLocal

		# Try everything

		if domain_configuration.certificate_transparency:
			log_error("No certificate transparency?")
			return Action.DisableCertificateTransparency

		if domain_configuration.forward_secrecy:
			log_error("No forward secrecy?")
			return Action.EnableCertificateTransparency | Action.DisableForwardSecrecy

		if domain_configuration.can_decrease_tls_version:
			log_error("Unsupported TLS version?")
			return Action.EnableForwardSecrecy | Action.EnableCertificateTransparency | Action.DecreaseTlsVersion

		if configuration.arbitrary_loads:
			log_error("ATS is already disabled, giving up...")
			return Action.GiveUp

		log_error("Unknown")
		return Action.AllowArbitraryLoads

	if code == Error.SSLError:
		ssl_error = int(error.get('streamErrorCode', None))

		try:
			log_error(SSLError(ssl_error).display, nl=False)
		except ValueError:
			log_error(str(ssl_error), nl=False)

		if ssl_error == SSLError.HostNameMismatch:
			log_error("")  # Newline
			return Action.GiveUp

		if ssl_error == SSLError.PeerProtocolVersion:

			if domain_configuration.can_decrease_tls_version:
				log_error("")  # Newline
				return Action.DecreaseTlsVersion

		log_error(": ", nl=False)

		if ssl_error == SSLError.FatalAlert:

			if certificate := endpoint.certificate:

				if certificate.is_expired:
					log_error("Certificate expired")
					return Action.GiveUp

				# TODO Check other certificate issues?

		if ssl_error == SSLError.HandshakeFail:

			if domain_configuration.can_decrease_tls_version:
				log_error("Unsupported TLS version?")
				return Action.DecreaseTlsVersion

		# Try everything

		if domain_configuration.certificate_transparency:
			log_error("No certificate transparency?")
			return Action.DisableCertificateTransparency

		if domain_configuration.forward_secrecy:
			log_error("No forward secrecy?")
			return Action.EnableCertificateTransparency | Action.DisableForwardSecrecy

		if domain_configuration.can_decrease_tls_version:
			log_error("Unsupported TLS version?")
			return Action.EnableCertificateTransparency | Action.EnableForwardSecrecy | Action.DecreaseTlsVersion

	log_error("Unhandled error")
	return Action.Investigate


def find_best_configuration(
	endpoint: Endpoint,
	upgrade_scheme: bool = False,
	identity: Optional[CodesigningIdentity] = None,
	log_info: Optional[LogFunc] = None,
	log_error: Optional[LogFunc] = None,
	log_success: Optional[LogFunc] = None,
	log_special: Optional[LogFunc] = None,
	redirected_from: Optional[Set[Endpoint]] = None,
	level: int = 0,
) -> Tuple[Optional[Configuration], List[Diagnostics]]:
	assert 0 <= level

	def prefix(level: int) -> str:
		return log_info("  " * level, nl=False)

	# TODO Detect if scheme was upgraded from HTTP and fallback to HTTP if
	# the upgraded endpoint does not connect.

	if log_info is None:
		log_info = no_log
	if log_error is None:
		log_error = no_log
	if log_success is None:
		log_success = no_log
	if log_special is None:
		log_special = no_log
	if redirected_from is None:
		redirected_from = set()

	prefix(level)
	log_info(style(f"{endpoint} ", bold=True), nl=False)

	# Ignore IPv4 and IPv6 addresses
	if endpoint.is_ip:
		log_success("✓ Connections to IP addresses are ignored by ATS")
		return (Configuration(), [Diagnostics(endpoint)])

	# HTTP -> HTTPS
	if upgrade_scheme and not endpoint.uses_tls:
		log_error("× No TLS")
		prefix(level)
		log_special("→ ", nl=False)
		new_endpoint = endpoint.with_tls
		log_info(f"Upgrading scheme to HTTPS: {new_endpoint}")
		return find_best_configuration(
			endpoint=new_endpoint,
			identity=identity,
			log_info=log_info,
			log_error=log_error,
			log_success=log_success,
			log_special=log_special,
			redirected_from=redirected_from,
			level=level,
		)
	log_success("✓")

	configuration = Configuration(
		exceptions={endpoint.host: DomainConfiguration.most_secure()}
	)

	diagnostic_results: List[Diagnostics] = []

	while True:
		with tempfile.TemporaryDirectory(prefix='ats-') as temp_dir_:
			temp_dir = Path(temp_dir_)

			target_path = temp_dir / f'atsprobe-{str(configuration)}'

			prefix(level)
			log_special("· ", nl=False)
			log_info(f"Configuration {configuration.display()}")
			prefix(level + 1)
			log_special("· ", nl=False)
			log_info("Compiling helper... ", nl=False)
			atsprobe = DiagnoseUtility.compile_and_sign_with(
				configuration=configuration,
				target_path=target_path,
				identity=identity,
			)
			log_success("✓")

			prefix(level + 1)
			log_special("· ", nl=False)
			log_info("Connecting... ", nl=False)
			probe_results = atsprobe.run({endpoint})[0]

			error: Dict[str, Any] = probe_results.get('error', dict())

			timestamp = timestamp_from_str(probe_results['timestamp'])
			redirected = Endpoint.from_url(probe_results.get('redirectedUrl', ''))

			if redirected is not None:
				# A redirection indicates that an HTTP request was performed.
				# Consequently, the connection to the endpoint did succeed. A
				# reported error is related to the redirection target.
				# However, success only shows that a connection to the
				# redirected target did succeed with the default ATS
				# configuration (if the domain is different and unless the
				# domain is in the list of exception domains) – which is not the
				# most secure.

				log_success("✓")
				prefix(level + 1)
				log_special("· ", nl=False)
				log_info(f"Redirected to: {redirected} ", nl=False)

				diagnostic_results.append(Diagnostics.success(
					endpoint,
					configuration=configuration,
					timestamp=timestamp,
					redirected=redirected,
				))

				if redirected in redirected_from:
					log_error("× Redirection loop, aborting")
					return (configuration, diagnostic_results)

				if endpoint == redirected:
					log_success("✓ (same endpoint)")
					return (configuration, diagnostic_results)

				if endpoint.host == redirected.host:
					log_error("× Same domain, but different scheme or port")
				else:
					log_error("× Different domain")

				# The redirection target is differnt than the endpoint.
				# Consequently, different TLS parameters might be used for the
				# connection to the redirection target. Find the best ATS
				# configuration for the redirection target and merge the
				# configurations later.
				r_configuration, r_diagnostics = find_best_configuration(
					endpoint=redirected,
					identity=identity,
					log_info=log_info,
					log_error=log_error,
					log_success=log_success,
					log_special=log_special,
					redirected_from=redirected_from.union({endpoint}),
					level=level,
				)

				diagnostic_results.extend(r_diagnostics)
				if r_configuration is None:
					return (None, diagnostic_results)

				configuration = configuration.merged(r_configuration)

				if endpoint.host == redirected.host:
					# The endpoint is in the same domain. Hence, the same ATS
					# configuration is used for both, the endpoint and the
					# redirection target. If configurations do not match, a less
					# secure configuration is used for one of the endpoints.
					# TODO Notify the user about the problem.
					pass

				return (configuration, diagnostic_results)

			if not error:
				log_success("✓")
				diagnostic_results.append(Diagnostics.success(
					endpoint,
					timestamp=timestamp,
					configuration=configuration,
					redirected=redirected,
				))
				return (configuration, diagnostic_results)

			log_error("× ", nl=False)

			actions = determine_action(endpoint, configuration, error, log_error)

			assert Action.EnableCertificateTransparency | Action.DisableCertificateTransparency not in actions
			assert Action.EnableForwardSecrecy | Action.DisableForwardSecrecy not in actions

			domain_configuration = configuration.exceptions[endpoint.host]

			insecure_http_loads = domain_configuration.insecure_http_loads
			tls_version = domain_configuration.tls_version
			forward_secrecy = domain_configuration.forward_secrecy
			certificate_transparency = domain_configuration.certificate_transparency

			if Action.EnableCertificateTransparency in actions:
				assert not certificate_transparency
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Re-enabling requirement for certificate transparency")
				certificate_transparency = True

			if Action.DisableCertificateTransparency in actions:
				assert certificate_transparency
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Disabling requirement for certificate transparency")
				certificate_transparency = False

			if Action.EnableForwardSecrecy in actions:
				assert not forward_secrecy
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Re-enabling requirement for forward secrecy")
				forward_secrecy = True

			if Action.DisableForwardSecrecy in actions:
				assert forward_secrecy
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Disabling requirement for forward secrecy")
				forward_secrecy = False

			if Action.DecreaseTlsVersion in actions:
				assert domain_configuration.can_decrease_tls_version
				tls_version = TlsVersion(tls_version - 1)
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info(f"Decreasing required TLS version to {tls_version}")

			if Action.AllowHttp in actions:
				assert not insecure_http_loads
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Allowing insecure HTTP loads")
				insecure_http_loads = True

				# TODO The best configuration for HTTPS-URLs of the same
				# domain still need to be determined.

			local_networking = configuration.local_networking
			arbitrary_loads = configuration.arbitrary_loads
			exceptions = configuration.exceptions

			exceptions[endpoint.host] = DomainConfiguration(
				includes_subdomains=domain_configuration.includes_subdomains,
				insecure_http_loads=insecure_http_loads,
				tls_version=tls_version,
				forward_secrecy=forward_secrecy,
				certificate_transparency=certificate_transparency,
			)

			if Action.AllowLocal in actions:
				assert not local_networking
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Allowing local networking")
				local_networking = True
				del exceptions[endpoint.host]

			if Action.AllowArbitraryLoads in actions:
				assert not arbitrary_loads
				prefix(level + 1)
				log_special("→ ", nl=False)
				log_info("Disabling ATS")
				arbitrary_loads = True
				del exceptions[endpoint.host]

			configuration = Configuration(
				arbitrary_loads=arbitrary_loads,
				local_networking=local_networking,
				exceptions=exceptions,
			)

			if actions in {Action.GiveUp, Action.Investigate}:
				diagnostics = Diagnostics.erroneous(
					endpoint,
					configuration=configuration,
					timestamp=timestamp,
					redirected=redirected,
					error=error,
				)
				diagnostic_results.append(diagnostics)

				if actions is Action.Investigate:
					log_error(json.dumps(diagnostics.json_dict(), indent=2))

				return (None, diagnostic_results)
