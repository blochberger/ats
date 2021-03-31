import enum
import re


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
