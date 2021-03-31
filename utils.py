from datetime import datetime


def timestamp_from_str(value: str) -> datetime:
	# Python cannot handle Z-marker
	if value.endswith('Z'):
		value = value[:-1] + '+00:00'
	return datetime.fromisoformat(value)
