import re

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Set, Tuple

import pickle
import requests


@dataclass(frozen=True)
class Trackers:
	signatures: Dict[str, re.Pattern]

	def get(self, host: str) -> Set[str]:
		results: Set[str] = set()
		for name, rx in self.signatures.items():
			if rx.search(host):
				results.add(name)
		return results

	@classmethod
	def load(cls, max_age_in_days: int = 7) -> 'Trackers':
		# Try to load object from cache
		cache_path = Path('exodus_trackers.pickle')
		if cache_path.exists():
			with cache_path.open('rb') as f:
				cache: Tuple[datetime, 'Trackers'] = pickle.load(f)
			timestamp, obj = cache
			age = datetime.now(timezone.utc) - timestamp
			if age < timedelta(days=max_age_in_days):
				return obj

		# Fetch trackers
		url = 'https://reports.exodus-privacy.eu.org/api/trackers'
		response = requests.get(url)
		response.raise_for_status()
		raw: Dict[str, Dict[str, Any]] = response.json()['trackers']
		signatures: Dict[str, re.Pattern] = dict()
		for tracker in raw.values():
			name = tracker['name']
			signature = tracker['network_signature']
			if 0 == len(signature):
				continue
			rx = re.compile(signature, re.IGNORECASE)
			signatures[name] = rx
		obj = cls(signatures)

		# Cache fetched trackers
		cache = (datetime.now(timezone.utc), obj)
		with cache_path.open('wb') as f:
			pickle.dump(cache, f)

		# Return result
		return obj
