import json
import re
import subprocess

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Set

import lief

from natsort import natsorted

import ats

from utils import timestamp_from_str
from utilities import PlistSanitizer


MAS_SUBMISSIONS_SINCE = datetime.fromisoformat('2010-11-03T00:00:00+00:00')
MAS_SINCE = datetime.fromisoformat('2011-01-06T00:00:00+00:00')
MAAP_UNTIL = datetime.fromisoformat('2018-09-20T00:00:00+00:00')


@dataclass(frozen=True)
class MissingInfo(Exception):
	path: Path


@dataclass(frozen=True)
class MissingMetadata(Exception):
	path: Path


@dataclass(frozen=True)
class Metadata:
	raw: Dict[str, Any]

	@cached_property
	def release_date(self) -> Optional[datetime]:
		value = self.raw.get('releaseDate', None)
		if type(value) is not str:
			return None
		return timestamp_from_str(value)

	@cached_property
	def current_version_release_date(self) -> Optional[datetime]:
		value = self.raw.get('currentVersionReleaseDate', None)
		if type(value) is not str:
			return None
		return timestamp_from_str(value)

	@classmethod
	def from_scrape_dump(cls, path: Path) -> Dict[str, 'Metadata']:
		results: Dict[str, 'Metadata'] = dict()
		lines = path.read_text().splitlines(keepends=False)
		for line in lines:
			raw: Dict[str, Any] = json.loads(line)
			bundle_id = raw.get('bundleId', None)
			if bundle_id is None:
				continue
			results[bundle_id] = cls(raw)
		return results


@dataclass(frozen=True, order=True, init=False)
class MacOS:
	major: int
	minor: int
	patch: int

	@property
	def supports_ats(self) -> bool:
		return self.__class__(10, 11, 0) <= self

	def __init__(self, major: int, minor: int = 0, patch: int = 0):
		if not (0 <= major <= 255 and 0 <= minor <= 255 and 0 <= patch <= 255):
			raise ValueError
		object.__setattr__(self, 'major', major)
		object.__setattr__(self, 'minor', minor)
		object.__setattr__(self, 'patch', patch)

	def __str__(self) -> str:
		return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class App:
	base_path: Path
	bundle_id: str
	version_id: str

	@property
	def path(self) -> Path:
		return self.base_path / self.bundle_id / self.version_id

	@property
	def info_path(self) -> Path:
		return self.path / 'Info.plist'

	@property
	def binary_path(self) -> Path:
		return self.path / 'executable.bin'

	@property
	def endpoints_path(self) -> Path:
		return self.path / 'endpoints.json'

	@property
	def metadata_path(self) -> Path:
		return self.path / 'itunes_metadata.json'

	@cached_property
	def metadata(self) -> Metadata:
		if not self.metadata_path.exists():
			raise MissingMetadata(self.metadata_path)
		with self.metadata_path.open('rb') as f:
			raw: Dict[str, Any] = json.load(f)
		return Metadata(raw)

	@property
	def fatbinary(self) -> lief.MachO.FatBinary:
		return lief.MachO.parse(
			str(self.binary_path),
			config=lief.MachO.ParserConfig.quick,
		)

	@property
	def binary(self) -> lief.MachO.Binary:
		return self.fatbinary[0]

	@cached_property
	def build_sdk_version(self) -> Optional[MacOS]:
		# Try reading the build SDK version from the Info.plist (quick).
		if version_str := self.info.get('DTSDKName', None):
			rx = re.compile(r'^macos(\d+)\.(\d+)(\.(\d+))$')
			if m := rx.fullmatch(version_str):
				major = int(m.group(1))
				minor = int(m.group(2))
				patch = 0 if len(m.groups()) < 4 else int(m.group(4))
				return MacOS(major, minor, patch)

		# Try reading the build SDK version information embedded in the binary (slow).
		binary = self.binary
		if not binary.has_build_version:
			return None

		# FIXME Lief reports the minOS instead of the actual SDK version,
		# see https://github.com/lief-project/LIEF/issues/533
		# BEGIN WORKAROUND
		rx = re.compile(r'SDK: (\d+)\.(\d+)\.(\d+)')
		m = rx.search(str(binary.build_version))
		assert m is not None, str(binary.build_version)
		major, minor, patch = tuple(map(int, m.groups()))
		return MacOS(major, minor, patch)
		# END WORKAROUND

		major, minor, patch = binary.build_version.sdk
		return MacOS(major, minor, patch)

	@cached_property
	def min_sdk_version(self) -> Optional[MacOS]:
		# Try reading minimal supported SDK version from Info.plist (quick).
		if version_str := self.info.get('LSMinimumSystemVersion', None):
			rx = re.compile(r'^(\d+)\.(\d+)(\.(\d+))$')
			if m := rx.fullmatch(version_str):
				major = int(m.group(1))
				minor = int(m.group(2))
				patch = 0 if len(m.groups()) < 4 else int(m.group(4))
				return MacOS(major, minor, patch)

		# Try reading the minimal supported SDK version embedded in the binary (slow).
		binary = self.binary

		if not binary.has_version_min:
			return None

		major, minor, patch = binary.version_min.sdk
		return MacOS(major, minor, patch)

	@cached_property
	def sdk(self) -> Optional[MacOS]:
		if sdk := self.build_sdk_version:
			return sdk
		return self.min_sdk_version

	@cached_property
	def current_version_release_date(self) -> Optional[datetime]:
		"""
		Release date of the current version or the app.

		Returns the release date of the current version, if present, or the
		app's original release date. Returns `None` if both are not present.
		"""

		if result := self.metadata.current_version_release_date:
			return result

		return self.metadata.release_date

	@cached_property
	def supports_ats(self) -> Optional[bool]:
		# Check whether the SDK supports ATS
		if sdk := self.sdk:
			return sdk.supports_ats

		# Check whether the current version was released before ATS was introduced
		if timestamp := self.current_version_release_date:
			if timestamp < ats.INTRODUCED_ON:
				return False

		# Status of ATS support is unknown
		return None

	@cached_property
	def entitlements(self) -> Dict[str, Any]:
		codesign = subprocess.run(
			['codesign', '--display', '--entitlements', ':-', str(self.binary_path)],
			capture_output=True,
			check=True,
		)
		plsan = PlistSanitizer.default()
		plist = plsan.loads(codesign.stdout)
		return plist

	@lru_cache
	def has_entitlement(self, entitlement: str) -> bool:
		if value := self.entitlements.get(entitlement, None):
			if type(value) is bool:
				return value
		return False

	@cached_property
	def has_app_sandbox_entitlement(self) -> bool:
		return self.has_entitlement('com.apple.security.app-sandbox')

	@cached_property
	def has_network_client_entitlement(self) -> bool:
		return self.has_entitlement('com.apple.security.network.client')

	@cached_property
	def can_access_network(self) -> bool:
		if self.has_app_sandbox_entitlement:
			return self.has_network_client_entitlement
		return True

	@cached_property
	def endpoints_dict(self) -> Dict[str, Set[ats.Endpoint]]:
		result: Optional[Dict[str, Set[ats.Endpoint]]] = None

		if not self.endpoints_path.exists():
			# Parse and cache endpoints

			endpoints_from_ats: Set[ats.Endpoint] = set()
			try:
				configuration = self.ats_configuration
				for domain, exception in configuration.exceptions.items():
					if endpoint := ats.Endpoint.from_url(f'https://{domain}'):
						endpoints_from_ats.add(endpoint)
						if exception.http:
							endpoint = ats.Endpoint.from_url(f'http://{domain}')
							assert endpoint is not None
							endpoints_from_ats.add(endpoint)
			except MissingInfo:
				pass

			endpoints_from_bin: Set[ats.Endpoint] = set()
			if self.binary_path.exists():
				strings = subprocess.run(
					['strings', '-', '-a', str(self.binary_path)],
					check=True,
					capture_output=True,
					text=True,
				)
				lines = strings.stdout.splitlines(keepends=False)
				endpoints_from_bin = {
					endpoint
					for line in lines
					for endpoint in ats.Endpoint.find_instances(line)
				}

			result = {
				'ats': endpoints_from_ats,
				'bin': endpoints_from_bin,
			}

			self.endpoints_path.write_text(json.dumps({
				k: [str(v) for v in sorted(vs)] for k, vs in result.items()
			}))

		# Return parsed endpoints
		if result is not None:
			return result  # Avoid superfluous read from disk

		raw: Dict[str, List[str]] = json.loads(self.endpoints_path.read_text())
		result = defaultdict(set)
		for source, urls in raw.items():
			for url in urls:
				if endpoint := ats.Endpoint.from_url(url):
					result[source].add(endpoint)
		return result

	@cached_property
	def endpoints_from_ats(self) -> Set[ats.Endpoint]:
		return self.endpoints_dict.get('ats', set())

	@cached_property
	def endpoints_from_binary(self) -> Set[ats.Endpoint]:
		return self.endpoints_dict.get('bin', set())

	@cached_property
	def endpoints(self) -> Set[ats.Endpoint]:
		return self.endpoints_from_ats.union(self.endpoints_from_binary)

	@cached_property
	def relevant_endpoints(self) -> Set[ats.Endpoint]:
		return {endpoint for endpoint in self.endpoints if endpoint.is_relevant}

	@cached_property
	def info(self) -> Dict[str, Any]:
		if not self.info_path.exists():
			raise MissingInfo(self.info_path)

		plsan = PlistSanitizer.default()
		result: Dict[str, Any] = plsan.load(self.info_path)

		return result

	@cached_property
	def ats_dict(self) -> Optional[Dict[str, Any]]:
		return self.info.get('NSAppTransportSecurity', None)

	@cached_property
	def ats_configuration(self) -> ats.ActualConfiguration:
		if ats_dict := self.ats_dict:
			return ats.ActualConfiguration.from_ats_dict(ats_dict)
		return ats.ActualConfiguration()

	def __str__(self) -> str:
		return f"{self.bundle_id}/{self.version_id}"

	def __lt__(self, other: Any) -> bool:
		if not isinstance(other, self.__class__):
			raise TypeError
		if self.bundle_id < other.bundle_id:
			return True
		return self.bundle_id == other.bundle_id and self.version_id < other.version_id

	def __le__(self, other: Any) -> bool:
		return self == other or self < other

	def __gt__(self, other: Any) -> bool:
		if not isinstance(other, self.__class__):
			raise TypeError
		if self.bundle_id > other.bundle_id:
			return True
		return self.bundle_id == other.bundle_id and self.version_id < other.version_id

	def __ge__(self, other: Any) -> bool:
		return self == other or self > other


@dataclass(frozen=True)
class Dataset:
	apps: Set[App]

	@cached_property
	def endpoints(self) -> Set[ats.Endpoint]:
		return {
			endpoint
			for app in self.apps
			for endpoint in app.endpoints
		}

	def app(self, bundle_id: str) -> Optional[App]:
		for app in sorted(self.apps, reverse=True):
			if app.bundle_id == bundle_id:
				return app
		return None

	@classmethod
	def from_path(
		cls,
		path: Path,
		matches_criteria: Callable[[App], bool],
		latest: bool = False,
	) -> 'Dataset':
		apps: Set[App] = set()

		for app in walk(path, matches_criteria, latest):
			apps.add(app)

		return cls(apps)


def walk(
	path: Path,
	matches_criteria: Callable[[App], bool],
	latest: bool = True,
) -> Iterator[App]:
	assert path.is_dir()
	assert path.exists()

	for bundle_path in path.iterdir():
		bundle_id = bundle_path.name

		if bundle_path.is_file() or bundle_id.startswith('.') or bundle_id == 'b.UNKNOWN':
			continue

		version_ids = natsorted([
			version_path.name
			for version_path in bundle_path.iterdir()
			if version_path.is_dir() and not version_path.name.startswith('.')
		], reverse=latest)

		if not version_ids:
			continue

		for version_id in version_ids:
			app = App(path, bundle_id, version_id)
			if matches_criteria(app):
				yield app
				if latest:
					break
