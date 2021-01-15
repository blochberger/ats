import json
import subprocess
import sys

from collections import defaultdict
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Set

from natsort import natsorted

import ats

from utilities import PlistSanitizer


@dataclass(frozen=True)
class MissingInfo(Exception):
	path: Path


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

	@classmethod
	def from_path(cls, path: Path, all_versions: bool = False) -> 'Dataset':
		apps: Set[App] = set()

		for app in walk(path, all_versions):

			if not app.info_path.exists():
				print(f"Missing: {app.info_path}", file=sys.stderr)
				continue
			if not app.binary_path.exists():
				print(f"Missing: {app.binary_path}", file=sys.stderr)

			apps.add(app)

		return cls(apps)


def walk(path: Path, all_versions: bool = False) -> Iterator[App]:
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
		])

		if not version_ids:
			continue

		if all_versions:
			for version_id in version_ids:
				yield App(path, bundle_id, version_id)
		else:
			yield App(path, bundle_id, version_ids[-1])
