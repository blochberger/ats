import enum
import itertools
import re

from typing import Any, Dict, Optional, Set


@enum.unique
class ErrorCodes(enum.IntEnum):
	DomainNotFound = -1003
	ATSError = -1022
	SSLError = -1200


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
		return f'{self.value:02X}'

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
