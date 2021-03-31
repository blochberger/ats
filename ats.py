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

import tls
from utilities import CodesigningIdentity, State, Utility


INTRODUCED_ON = datetime.fromisoformat('2015-09-01T00:00:00+00:00')
JUSTIFICATIONS_REQUIRED_SINCE = datetime.fromisoformat('2017-01-01T00:00:00+00:00')


class LogFunc(Protocol):

	def __call__(self, msg: str, nl: bool = True): ...


def no_log(msg: str, nl: bool = True):
	pass


def is_ip(value: str) -> bool:
	try:
		ip_address(value)
	except ValueError:
		return False
	return True


def is_localdomain(domain: str) -> bool:
	if domain.endswith('.'):
		domain = domain[:-1]
	return '.' not in domain or domain.endswith('.local')


def is_subdomain(domain: str, of: str) -> bool:
	lhs = domain.split('.')[::-1]
	rhs = of.split('.')[::-1]

	if len(lhs) <= len(rhs):
		return False

	for i in range(len(rhs)):
		if lhs[i] != rhs[i]:
			return False

	return True


def is_valid_host(value: str) -> bool:
	# A trailing dot is allowed, although discouraged
	if value.endswith('.'):
		value = value[:-1]

	if 253 < len(value):
		return False

	parts = value.split('.')

	# The TLD must not be numeric only
	tld = parts[-1]
	if re.fullmatch(r'[0-9]+', tld):
		return False

	# Only lower-case hostnames should be used
	rx = re.compile(r'(?!-)[a-z0-9-]{1,63}(?<!-)$')
	return all(rx.match(part) for part in value.split('.'))


def timestamp_from_str(value: str) -> datetime:
	# Python cannot handle Z-marker
	if value.endswith('Z'):
		value = value[:-1] + '+00:00'
	return datetime.fromisoformat(value)


def key_variants(key: str) -> Iterator[Tuple[str, bool]]:
	assert key.startswith('NSException')
	suffix = key[len('NSException'):]

	assert suffix in {
		'AllowsInsecureHTTPLoads',
		'MinimumTLSVersion',
		'RequiresForwardSecrecy',
	}

	# Order of prefixes is important!
	prefixes = ['', 'ThirdParty', 'Temporary', 'TemporaryThirdParty']

	for i, prefix in enumerate(prefixes):
		variant = 'NS' + prefix + 'Exception' + suffix
		yield (variant, 0 < i)


def get_bool(source: Dict[str, Any], key: str, default: bool, strict: bool = True) -> bool:
	value = source.get(key, default)
	if type(value) is not bool:
		if strict:
			raise ValueError(f"Unexpected value for '{key}': {value}")
		return default
	return bool(value)


def get_str(source: Dict[str, Any], key: str, default: str, strict: bool = True) -> str:
	value = source.get(key, default)
	if type(value) is not str:
		if strict:
			raise ValueError(f"Unexpected value for '{key}': {value}")
		return default
	return value


def get_dict(source: Dict[str, Any], key: str, default: dict, strict: bool = True) -> dict:
	value = source.get(key, default)
	if type(value) is not dict:
		if strict:
			raise ValueError(f"Unexpected value for '{key}': {value}")
		return default
	return value


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

	NotConnectedToInternet = -1009

	ATSError = -1022
	"""
	- Occurs for HTTP, even if the URL would redirect to HTTPS
	"""

	SSLError = -1200

	ServerCertificateUntrusted = -1202

	ClientCertificateRejected = -1205

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

	Protocol = -9800

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
		return is_localdomain(self.host)

	@property
	def has_standard_port(self) -> bool:
		if self.uses_tls:
			return self.port == 443
		return self.port == 80

	@property
	def is_ip(self) -> bool:
		return is_ip(self.host)

	@property
	def is_relevant(self) -> bool:
		return not (self.is_ip or self.is_local)

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
		except ConnectionResetError:
			return None

	def __lt__(self, other: Any) -> bool:
		if type(other) is not Endpoint:
			raise TypeError
		return (self.reverse_domain_name < other.reverse_domain_name or (
			self.reverse_domain_name == other.reverse_domain_name and self.port < other.port
		))

	def __le__(self, other: Any) -> bool:
		return self == other or self < other

	def __gt__(self, other: Any) -> bool:
		return other < self

	def __ge__(self, other: Any) -> bool:
		return self == other or self > other

	def __str__(self) -> str:
		result = f'{self.scheme}://{self.host}'
		if not self.has_standard_port:
			result += f':{self.port}'
		result += '/'
		return result

	@classmethod
	def from_url(cls, url: str) -> Optional['Endpoint']:
		try:
			parsed = urlparse(url)
		except ValueError:
			return None

		host = parsed.hostname
		if host is None:
			return None
		if parsed.scheme not in {'http', 'https'}:
			return None

		host = host.lower()
		if not (is_valid_host(host) or is_ip(host)):
			return None

		uses_tls = parsed.scheme == 'https'

		port: int
		try:
			if parsed.port is None:
				port = 443 if uses_tls else 80
			else:
				port = parsed.port
		except ValueError:
			return None

		return cls(uses_tls=uses_tls, host=host, port=port)

	@classmethod
	def find_instances(cls, value: str, log_error: Optional[LogFunc] = None) -> Iterator['Endpoint']:
		"""
		Searches for URLs in a string and yields endpoints.
		"""

		if log_error is None:
			log_error = no_log

		scheme_rx = re.compile(r'https?://', re.IGNORECASE)
		path_rx = re.compile(r'[/"() ]')

		value = value.strip().lower()

		# Remove placeholder that lead to invalid URLs
		for placeholder in ['%@', '%s', '%d', '%i', '%ld', '%li']:
			value = value.replace(placeholder, '')

		def emit_candidate(candidate: str, scheme_end: int, log_error: LogFunc) -> Optional['Endpoint']:
			if candidate.endswith(':'):
				candidate = candidate[:-1]

			if len(candidate) <= scheme_end:
				return None

			endpoint = cls.from_url(candidate)
			if endpoint is None:
				log_error(f"Unexpected endpoint: {candidate}")
			return endpoint

		while scheme_match := scheme_rx.search(value):
			scheme_start = scheme_match.start()
			value = value[scheme_start:]
			scheme_end = scheme_match.end() - scheme_match.start()
			if path_match := path_rx.search(value[scheme_end:]):
				path_start = scheme_end + path_match.start()
				if endpoint := emit_candidate(value[:path_start], scheme_end, log_error):
					yield endpoint
				value = value[path_start + 1:]
				continue
			if endpoint := emit_candidate(value, scheme_end, log_error):
				yield endpoint
			break


class Encrypted(enum.Flag):
	SupportsForwardSecrecy = enum.auto()
	SupportsCertificateTransparency = enum.auto()
	TLSv1_0 = enum.auto()
	TLSv1_1 = enum.auto()
	TLSv1_2 = enum.auto()
	TLSv1_3 = enum.auto()

	@property
	def tls_version(self) -> tls.Version:
		cls = self.__class__
		tls_mask = cls.TLSv1_0 | cls.TLSv1_1 | cls.TLSv1_2 | cls.TLSv1_3
		flag = self & tls_mask
		if flag is cls.TLSv1_0:
			return tls.v1_0
		elif flag is cls.TLSv1_1:
			return tls.v1_1
		elif flag is cls.TLSv1_2:
			return tls.v1_2
		elif flag is cls.TLSv1_3:
			return tls.v1_3
		else:
			assert False, "Multiple TLS flags set."

	@classmethod
	def for_tls_version(cls, tls_version: tls.Version) -> 'Encrypted':
		return {
			tls.v1_0: cls.TLSv1_0,
			tls.v1_1: cls.TLSv1_1,
			tls.v1_2: cls.TLSv1_2,
			tls.v1_3: cls.TLSv1_3,
		}[tls_version]


class Unencrypted(enum.Flag):
	InsecureHTTPLoads = enum.auto()


class Improvement(enum.Flag):
	CanDisableHTTP = enum.auto()
	CanUpgradeTLS = enum.auto()
	CanEnableFS = enum.auto()
	CanEnableCT = enum.auto()

	RemovesJustification = enum.auto()

	@property
	def http(self) -> 'Improvement':
		cls = self.__class__
		return self & (cls.CanDisableHTTP | cls.RemovesJustification)

	@property
	def https(self) -> 'Improvement':
		cls = self.__class__
		return self & (cls.CanUpgradeTLS | cls.CanEnableFS | cls.CanEnableCT | cls.RemovesJustification)

	def __str__(self) -> str:
		value = re.sub(r'([A-Z][a-z])', r' \1', self.name)
		value = re.sub(r'([a-z])([A-Z])', r'\1 \2', self.name)
		return value.strip()

	@classmethod
	def implicit(cls) -> Iterator['Improvement']:
		for flag in cls:
			if flag in (cls.CanEnableCT | cls.CanUpgradeTLS):
				yield flag

	@classmethod
	def explicit(cls) -> Iterator['Improvement']:
		return iter(cls)


@dataclass(frozen=True)
class DomainConfiguration:
	includes_subdomains: bool = False
	insecure_http_loads: bool = False
	tls_version: tls.Version = tls.v1_2
	forward_secrecy: bool = True
	certificate_transparency: bool = False

	@classmethod
	def most_secure(cls) -> 'DomainConfiguration':
		return cls(
			tls_version=tls.v1_3,
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
		return self.insecure_http_loads or self.tls_version < tls.v1_2

	@property
	def can_decrease_tls_version(self) -> bool:
		return tls.v1_0 < self.tls_version

	def _values_lt(self, other: 'DomainConfiguration') -> Tuple[bool, bool, bool, bool]:
		return (
			self.insecure_http_loads and not other.insecure_http_loads,
			self.tls_version < other.tls_version,
			not self.forward_secrecy and other.forward_secrecy,
			not self.certificate_transparency and other.certificate_transparency,
		)

	def _values_gt(self, other: 'DomainConfiguration') -> Tuple[bool, bool, bool, bool]:
		return (
			not self.insecure_http_loads and other.insecure_http_loads,
			self.tls_version > other.tls_version,
			self.forward_secrecy and not other.forward_secrecy,
			self.certificate_transparency and not other.certificate_transparency,
		)

	def __lt__(self, other: Any) -> bool:

		if type(other) is not self.__class__:
			raise NotImplementedError

		return any(self._values_lt(other)) and not any(self._values_gt(other))

	def __le__(self, other: Any) -> bool:
		return self == other or self < other

	def __gt__(self, other: Any) -> bool:

		if type(other) is not self.__class__:
			raise NotImplementedError

		return any(self._values_gt(other)) and not any(self._values_lt(other))

	def __ge__(self, other: Any) -> bool:
		return self == other or self > other

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
			fg='red' if self.tls_version < tls.v1_2 else 'green',
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

	@classmethod
	def from_ats_dict(cls, ats_dict: Dict[str, Any]) -> 'DomainConfiguration':
		default = cls()

		includes_subdomains = get_bool(
			ats_dict,
			'NSIncludesSubdomains',
			default.includes_subdomains,
		)
		insecure_http_loads = get_bool(
			ats_dict,
			'NSExceptionAllowsInsecureHTTPLoads',
			default.insecure_http_loads,
		)
		forward_secrecy = get_bool(
			ats_dict,
			'NSExceptionRequiresForwardSecrecy',
			default.forward_secrecy,
		)
		certificate_transparency = get_bool(
			ats_dict,
			'NSRequiresCertificateTransparency',
			default.certificate_transparency,
		)

		tls_version_str = get_str(
			ats_dict,
			'NSExceptionMinimumTLSVersion',
			str(default.tls_version),
		)
		tls_version = tls.Version.from_str(tls_version_str)
		if tls_version is None:
			raise ValueError(
				f"Invalid value for 'NSExceptionMinimumTLSVersion': {tls_version_str}"
			)

		return cls(
			includes_subdomains=includes_subdomains,
			insecure_http_loads=insecure_http_loads,
			tls_version=tls_version,
			forward_secrecy=forward_secrecy,
			certificate_transparency=certificate_transparency,
		)


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

		return self.arbitrary_loads or any(
			exception.requires_justification
			for exception in self.exceptions.values()
		)

	def exception_domain_for(self, host: str) -> Optional[str]:
		for domain, exception in self.exceptions.items():
			if domain == host or (
				is_subdomain(host, domain) and exception.includes_subdomains
			):
				return domain
		return None

	def get(self, host: str) -> Tuple[Optional[str], Optional[DomainConfiguration]]:
		if domain := self.exception_domain_for(host):
			return (domain, self.exceptions[domain])

		if not self.arbitrary_loads:
			return (None, DomainConfiguration())

		return (None, None)

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

	@classmethod
	def from_ats_dict(cls, ats_dict: Dict[str, Any]) -> 'Configuration':
		default = cls()

		arbitrary_loads = get_bool(
			ats_dict,
			'NSAllowsArbitraryLoads',
			default.arbitrary_loads,
		)

		local_networking = get_bool(
			ats_dict,
			'NSAllowsLocalNetworking',
			default.local_networking,
		)

		exception_domains = get_dict(ats_dict, 'NSExceptionDomains', dict())
		exceptions: Dict[str, DomainConfiguration] = dict()
		for domain, exception_ats_dict in exception_domains.items():
			exceptions[domain] = DomainConfiguration.from_ats_dict(exception_ats_dict)

		return cls(
			arbitrary_loads=arbitrary_loads,
			local_networking=local_networking,
			exceptions=exceptions,
		)


@dataclass(frozen=True)
class ActualDomainConfiguration:
	includes_subdomains: bool = False
	http: Optional[bool] = None
	fs: Optional[bool] = None
	ct: Optional[bool] = None
	tls: Optional[tls.Version] = None

	@property
	def is_default(self) -> bool:
		return all([
			self.http is None or not self.http,
			self.fs is None or self.fs,
			self.ct is None or not self.ct,
			self.tls is None or self.tls is tls.v1_2,
		])

	def compare_to_diagnosed(
		self,
		other: DomainConfiguration,
	) -> Tuple[Improvement, Improvement]:
		explicit = Improvement(0)
		implicit = Improvement(0)

		if not other.insecure_http_loads and self.http is not None and self.http:
			explicit |= Improvement.CanDisableHTTP

		if other.forward_secrecy and self.fs is not None and not self.fs:
			explicit |= Improvement.CanEnableFS

		if other.certificate_transparency and self.ct is None:
			implicit |= Improvement.CanEnableCT

		if other.certificate_transparency and self.ct is not None and not self.ct:
			explicit |= Improvement.CanEnableCT

		if self.tls is None and tls.v1_2 < other.tls_version:
			implicit |= Improvement.CanUpgradeTLS

		if self.tls is not None and self.tls < other.tls_version:
			explicit |= Improvement.CanUpgradeTLS

		if self.requires_justification and not other.requires_justification:
			explicit |= Improvement.RemovesJustification

		assert all(improvement not in (implicit & explicit) for improvement in Improvement)

		return (explicit, implicit)

	@property
	def requires_justification(self) -> bool:
		return any([
			self.http is not None and self.http,
			self.tls is not None and self.tls < tls.v1_2,
		])

	@classmethod
	def least_secure(cls) -> 'ActualDomainConfiguration':
		return cls(
			includes_subdomains=False,
			http=True,
			fs=False,
			ct=False,
			tls=tls.v1_0,
		)

	@classmethod
	def from_ats_dict(cls, ats_dict: Dict[str, Any]) -> 'ActualDomainConfiguration':
		includes_subdomains = get_bool(ats_dict, 'NSIncludesSubdomains', False, strict=False)

		http: Optional[bool] = None
		for key, is_deprecated in key_variants('NSExceptionAllowsInsecureHTTPLoads'):
			if value := ats_dict.get(key, None):
				if type(value) is bool:
					http = value
					break

		fs: Optional[bool] = None
		for key, is_deprecated in key_variants('NSExceptionRequiresForwardSecrecy'):
			if value := ats_dict.get(key, None):
				if type(value) is bool:
					fs = value
					break

		ct: Optional[bool] = None
		if value := ats_dict.get('NSRequiresCertificateTransparency', None):
			if type(value) is bool:
				ct = value

		tls: Optional[tls.Version] = None
		for key, is_deprecated in key_variants('NSExceptionMinimumTLSVersion'):
			if raw := ats_dict.get(key, None):
				if type(raw) is str:
					try:
						tls = tls.Version.from_str(raw)
						break
					except ValueError:
						pass

		return cls(
			includes_subdomains=includes_subdomains,
			http=http,
			fs=fs,
			ct=ct,
			tls=tls,
		)


@dataclass(frozen=True)
class ActualConfiguration:
	arbitrary: Optional[bool] = None
	arbitrary_media: Optional[bool] = None
	arbitrary_web: Optional[bool] = None
	exceptions: Dict[str, ActualDomainConfiguration] = field(default_factory=dict)

	@property
	def any_arbitrary(self) -> bool:
		return any([
			self.arbitrary is not None and self.arbitrary,
			self.arbitrary_media is not None and self.arbitrary_media,
			self.arbitrary_web is not None and self.arbitrary_web,
		])

	@property
	def is_disabled(self) -> bool:
		return self.any_arbitrary and not self.exceptions

	@property
	def is_default(self) -> bool:
		return not self.any_arbitrary and all(
			exception.is_default for exception in self.exceptions.values()
		)

	@property
	def requires_justification(self) -> bool:
		return self.any_arbitrary or any(
			exception.requires_justification
			for exception in self.exceptions.values()
		)

	def exception_domain_for(self, host: str) -> Optional[str]:
		for domain, exception in self.exceptions.items():
			if domain == host or (
				exception.includes_subdomains and is_subdomain(host, domain)
			):
				return domain
		return None

	def __getitem__(self, key: Any) -> Tuple[Optional[str], Optional[ActualDomainConfiguration]]:
		if type(key) is str:
			host = key
		elif type(key) is Endpoint:
			host = key.host
		else:
			raise TypeError

		if domain := self.exception_domain_for(host):
			return (domain, self.exceptions[domain])

		if not self.any_arbitrary:
			return (None, ActualDomainConfiguration())

		# Anything goes
		return (None, None)

	@classmethod
	def from_ats_dict(cls, ats_dict: Dict[str, Any]) -> 'ActualConfiguration':
		arbitrary: Optional[bool] = None
		if value := ats_dict.get('NSAllowsArbitraryLoads', None):
			if type(value) is bool:
				arbitrary = value

		arbitrary_media: Optional[bool] = None
		if value := ats_dict.get('NSAllowsArbitraryLoadsForMedia', None):
			if type(value) is bool:
				arbitrary_media = value

		arbitrary_web: Optional[bool] = None
		if value := ats_dict.get('NSAllowsArbitraryLoadsForWebContent', None):
			if type(value) is bool:
				arbitrary_web = value

		exceptions: Dict[str, ActualDomainConfiguration] = dict()
		if eds_dict := ats_dict.get('NSExceptionDomains', None):
			if type(eds_dict) is dict:
				for domain, ed_dict in eds_dict.items():
					if type(ed_dict) is dict:
						exceptions[domain] = ActualDomainConfiguration.from_ats_dict(ed_dict)

		return cls(
			arbitrary=arbitrary,
			arbitrary_media=arbitrary_media,
			arbitrary_web=arbitrary_web,
			exceptions=exceptions,
		)


@dataclass(frozen=True)
class Diagnostics:
	endpoint: Endpoint
	configuration: Configuration
	timestamp: datetime
	redirected: Optional[Endpoint] = None
	error: Optional[Dict[str, Any]] = None

	@property
	def did_succeed(self) -> bool:
		return self.error is None

	def json_dict(self, simplify: bool = True) -> Dict[str, Any]:
		return {
			'url': str(self.endpoint),
			'redirected_url': None if self.redirected is None else str(self.redirected),
			'configuration': self.configuration.ats_dict(simplify=simplify),
			'timestamp': self.timestamp.isoformat(),
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

	@classmethod
	def from_dict(cls, data: Dict[str, Any]) -> 'Diagnostics':
		url = data['url']
		endpoint = Endpoint.from_url(url)
		if endpoint is None:
			raise ValueError(f"Invalid endpoint ('url'): {url}")

		redirected: Optional[Endpoint] = None
		if redirected_url := data.get('redirected_url', None):
			redirected = Endpoint.from_url(redirected_url)
			if redirected is None:
				raise ValueError(f"Invalid endpoint ('redirected_url'): {redirected_url}")

		configuration: Configuration
		if ats_dict := data['configuration']:
			configuration = Configuration.from_ats_dict(ats_dict)

		timestamp: Optional[datetime] = None
		if timestamp_str := data.get('timestamp', None):
			timestamp = timestamp_from_str(timestamp_str)
			if timestamp is None:
				raise ValueError(f"Invalid timestamp: {timestamp}")
		assert timestamp is not None

		error: Optional[Dict[str, Any]] = data.get('error', None)

		return cls(
			endpoint=endpoint,
			redirected=redirected,
			configuration=configuration,
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
	identity: Optional[CodesigningIdentity] = None,
	log_info: Optional[LogFunc] = None,
	log_error: Optional[LogFunc] = None,
	log_success: Optional[LogFunc] = None,
	log_special: Optional[LogFunc] = None,
	redirected_from: Optional[Set[Endpoint]] = None,
) -> Diagnostics:
	assert not endpoint.is_ip

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

	def prefix(level: int) -> str:
		assert log_info is not None
		return log_info("  " * level, nl=False)

	configuration = Configuration(
		exceptions={endpoint.host: DomainConfiguration.most_secure()}
	)

	while True:
		with tempfile.TemporaryDirectory(prefix='ats-') as temp_dir_:
			temp_dir = Path(temp_dir_)

			target_path = temp_dir / f'atsprobe-{str(configuration)}'

			log_special("  · ", nl=False)
			log_info(f"Configuration {configuration.display()}")
			log_special("  · ", nl=False)
			log_info("Compiling helper... ", nl=False)
			atsprobe = DiagnoseUtility.compile_and_sign_with(
				configuration=configuration,
				target_path=target_path,
				identity=identity,
			)
			log_success("✓")

			log_special("  · ", nl=False)
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
				log_special("  · ", nl=False)
				log_info(f"Redirected to: {redirected} ", nl=False)

				diagnostics = Diagnostics.success(
					endpoint,
					configuration=configuration,
					timestamp=timestamp,
					redirected=redirected,
				)

				if redirected in redirected_from:
					log_error("× Redirection loop, aborting")
					return diagnostics

				if endpoint == redirected:
					log_success("✓ (same endpoint)")
					return diagnostics

				if endpoint.host == redirected.host:
					log_error("× Same domain, but different scheme or port")
				else:
					log_error("× Different domain")
				return diagnostics

			if not error:
				log_success("✓")
				diagnostics = Diagnostics.success(
					endpoint,
					timestamp=timestamp,
					configuration=configuration,
					redirected=redirected,
				)
				return diagnostics

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
				log_special("  → ", nl=False)
				log_info("Re-enabling requirement for certificate transparency")
				certificate_transparency = True

			if Action.DisableCertificateTransparency in actions:
				assert certificate_transparency
				log_special("  → ", nl=False)
				log_info("Disabling requirement for certificate transparency")
				certificate_transparency = False

			if Action.EnableForwardSecrecy in actions:
				assert not forward_secrecy
				log_special("  → ", nl=False)
				log_info("Re-enabling requirement for forward secrecy")
				forward_secrecy = True

			if Action.DisableForwardSecrecy in actions:
				assert forward_secrecy
				log_special("  → ", nl=False)
				log_info("Disabling requirement for forward secrecy")
				forward_secrecy = False

			if Action.DecreaseTlsVersion in actions:
				assert domain_configuration.can_decrease_tls_version
				tls_version = tls.Version(tls_version - 1)
				log_special("  → ", nl=False)
				log_info(f"Decreasing required TLS version to {tls_version}")

			if Action.AllowHttp in actions:
				assert not insecure_http_loads
				log_special("  → ", nl=False)
				log_info("Allowing insecure HTTP loads")
				insecure_http_loads = True

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
				log_special("  → ", nl=False)
				log_info("Allowing local networking")
				local_networking = True
				del exceptions[endpoint.host]

			if Action.AllowArbitraryLoads in actions:
				assert not arbitrary_loads
				log_special("  → ", nl=False)
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
				if actions is Action.Investigate:
					log_error(json.dumps(diagnostics.json_dict(), indent=2))
				return diagnostics
