import enum
import re
import ssl

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

import OpenSSL

from utils import timestamp_from_str


@enum.unique
class Version(enum.IntEnum):
	TLSv1_0 = 0
	TLSv1_1 = 1
	TLSv1_2 = 2
	TLSv1_3 = 3

	def __str__(self) -> str:
		return f"TLSv1.{self.value}"

	@classmethod
	def from_str(cls, value: str) -> 'Version':
		rx = re.compile(r'^TLSv1\.([0-3])$')
		m = rx.fullmatch(value)
		if not m:
			raise ValueError(f"Invalid tls.Version: {value}")
		return cls(int(m.group(1)))


v1_0 = Version.TLSv1_0
v1_1 = Version.TLSv1_1
v1_2 = Version.TLSv1_2
v1_3 = Version.TLSv1_3


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

	@classmethod
	def from_server(cls, host: str, port: int = 443) -> Optional['Certificate']:
		try:
			pem = ssl.get_server_certificate((host, port))
			return cls.from_pem(pem)
		except ssl.SSLError:
			return None
		except ConnectionResetError:
			return None
