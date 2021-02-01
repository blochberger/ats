import enum
import plistlib
import re
import subprocess

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Type, TypeVar
from xml.parsers.expat import ExpatError


U = TypeVar('U', bound='Utility')


@dataclass(frozen=True, init=False)
class CodesigningIdentity:
	sha1_rx = re.compile(r'[0-9A-Fa-f]{40}')

	sha1: str

	def __init__(self, sha1: str) -> None:
		if not self.sha1_rx.fullmatch(sha1):
			raise ValueError
		object.__setattr__(self, 'sha1', sha1)

	def __str__(self) -> str:
		return self.sha1

	@classmethod
	def detect_all(cls) -> List['CodesigningIdentity']:
		security = subprocess.run(
			['security', 'find-identity', '-p', 'codesigning', '-v'],
			check=True,
			capture_output=True,
			text=True,
		)
		lines = security.stdout.splitlines(keepends=False)
		identities: List['CodesigningIdentity'] = []
		for line in lines:
			m: Optional[re.Match] = cls.sha1_rx.search(lines[0])
			if m:
				identities.append(cls(m.group(0)))
		return identities

	@classmethod
	def detect_first(cls) -> Optional['CodesigningIdentity']:
		identities = cls.detect_all()
		if identities:
			return identities[0]
		return None


class State(enum.Enum):
	"""
	# Compiling -> Compiled -> Signing -> Ready -> Running -> Finished
	#                                      ^                    |
	#                                      |                    |
	#                                      +--------------------+
	"""

	Compiling = enum.auto()
	Compiled = enum.auto()
	Signing = enum.auto()
	Ready = enum.auto()
	Running = enum.auto()
	Finished = enum.auto()

	@property
	def next(self) -> 'State':
		cls = self.__class__
		return {
			cls.Compiling: cls.Compiled,
			cls.Compiled: cls.Signing,
			cls.Signing: cls.Ready,
			cls.Ready: cls.Running,
			cls.Running: cls.Finished,
			cls.Finished: cls.Ready,
		}[self]


@dataclass
class Utility:
	path: Path

	_intermediate: Optional[subprocess.Popen]
	_state: State

	@property
	def is_ready(self) -> bool:
		return self._state is State.Ready

	@property
	def is_finished(self) -> bool:
		return self._state is State.Finished

	@classmethod
	def name(cls) -> str:
		raise NotImplementedError

	@classmethod
	def source_dir(cls) -> Path:
		return Path(cls.name())

	@classmethod
	def default_info_plist_path(cls) -> Path:
		return cls.source_dir() / 'Info.plist'

	@classmethod
	def default_target_path(cls) -> Path:
		return cls.source_dir() / cls.name()

	@classmethod
	def start_compilation(
		cls: Type[U],
		target_path: Optional[Path] = None,
		optimize: bool = True,
		info_plist_path: Optional[Path] = None,
	) -> U:
		if target_path is None:
			target_path = cls.default_target_path()

		assert not target_path.is_dir(), f"Invalid target: {target_path}"

		source_dir = cls.source_dir()
		source_path = source_dir / 'main.swift'
		if info_plist_path is None:
			info_plist_path = cls.default_info_plist_path()

		swiftc_cmd = ['swiftc']

		if optimize:
			swiftc_cmd += [
				'-gnone',  # Strip all debug symbols
				'-O',
				'-whole-module-optimization',
			]

		# Embed Info.plist
		# NOTE The order of the arguments is important!
		swiftc_cmd += [
			'-Xlinker', '-sectcreate',
			'-Xlinker', '__TEXT',
			'-Xlinker', '__info_plist',
			'-Xlinker', str(info_plist_path),
		]

		intermediate = subprocess.Popen(
			swiftc_cmd + ['-o', str(target_path), str(source_path)],
		)
		return cls(
			path=target_path,
			_intermediate=intermediate,
			_state=State.Compiling,
		)

	def poll(self) -> State:
		if (
			self._state is not State.Finished and
			self._intermediate is not None and
			self._intermediate.poll() is not None
		):
			self.wait()
		return self._state

	def wait(self, timeout: Optional[float] = None):
		assert self._intermediate is not None

		until = self._state.next

		assert until in {State.Compiled, State.Ready, State.Finished}

		self._intermediate.wait(timeout)

		assert 0 == self._intermediate.returncode

		if until is not State.Finished:
			self._intermediate = None
		self._state = until

	def start_signing(
		self,
		identity: Optional[CodesigningIdentity] = None,
	):
		assert self._state is State.Compiled
		assert self._intermediate is None

		if identity is None:
			identity = CodesigningIdentity.detect_first()

		assert identity is not None, "Could not detect codesigning identity"

		cls = self.__class__
		name = cls.name()
		source_dir = cls.source_dir()
		entitlements_path = source_dir / f'{name}.entitlements'

		self._intermediate = subprocess.Popen(
			[
				'codesign',
				'--force',  # Override existing code signature
				'--sign', str(identity),
				'--entitlements', str(entitlements_path),  # Embed entitlements
				str(self.path)
			],
		)
		self._state = State.Signing

	@classmethod
	def compile_and_sign(
		cls: Type[U],
		target_path: Optional[Path] = None,
		identity: Optional[CodesigningIdentity] = None,
		optimize: bool = True,
		info_plist_path: Optional[Path] = None,
	) -> U:
		# Compile
		obj = cls.start_compilation(
			target_path=target_path,
			optimize=optimize,
			info_plist_path=info_plist_path,
		)
		obj.wait()

		assert obj._state is State.Compiled

		# Sign
		obj.start_signing(identity=identity)
		obj.wait()

		assert obj.is_ready

		return obj

	def _start(self, intermediate: subprocess.Popen):
		assert self.is_ready
		assert self._intermediate is None

		self._intermediate = intermediate
		self._state = State.Running

	def _finalize(self):
		assert self.is_finished
		assert self._intermediate is not None

		self._intermediate = None
		self._state = State.Ready


@dataclass
class PlistSanitizer(Utility):

	def load(self, plist: Path) -> dict:
		assert self.is_ready
		assert plist.exists()

		return self.loads(plist.read_bytes())

	def loads(self, raw: bytes) -> dict:
		assert self.is_ready

		if not raw:
			return dict()

		try:
			return plistlib.loads(raw)
		except plistlib.InvalidFileException:
			pass
		except ExpatError:
			pass
		except ValueError:
			pass

		# Try sanitizing input
		intermediate = subprocess.run(
			[str(self.path)],
			input=raw,
			capture_output=True,
			check=True
		)
		sanitized = intermediate.stdout
		return plistlib.loads(sanitized)

	@classmethod
	def name(self) -> str:
		return 'plsan'

	@classmethod
	def default(cls) -> 'PlistSanitizer':
		target_path = cls.default_target_path()
		assert target_path.exists(), "Please call `ats compile`"
		return cls(
			path=target_path,
			_intermediate=None,
			_state=State.Ready,
		)
