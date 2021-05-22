from typing import Iterator, Tuple


IncludesSubdomains = 'NSIncludesSubdomains'
InsecureHTTPLoads = 'NSExceptionAllowsInsecureHTTPLoads'
MinimumTlsVersion = 'NSExceptionMinimumTLSVersion'
RequiresForwardSecrecy = 'NSExceptionRequiresForwardSecrecy'
RequiresCertificateTransparency = 'NSRequiresCertificateTransparency'


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
