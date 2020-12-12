import json
import plistlib
import sys
import tempfile

from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import click

from tqdm import tqdm

import ats
from utilities import (
	CodesigningIdentity,
	DiagnoseUtility,
	PlistSanitizer,
	State,
	Utility,
)
from tests import TestEnvironment


class CodesigningIdentityParam(click.ParamType):
	name = 'identity'

	def convert(self, value: str, param: Optional[Any], ctx: Optional[Any]) -> CodesigningIdentity:
		if value == 'auto':
			identity = CodesigningIdentity.detect_first()
			if identity:
				return identity
		try:
			return CodesigningIdentity(value)
		except ValueError:
			self.fail(f"Invalid codesigning identity: {value}")


@click.group()
def cli():
	pass


@cli.command()
@click.option(
	'--codesigning-identity',
	type=CodesigningIdentityParam(),
	default='auto',
	show_default=True,
	help="""
	The SHA-1 hash of the identity used for signing code.
	All valid identities can be listed with:

		security find-identity -p codesigning -v

	Set to 'auto' in order to determine the codesigning identity automatically.
	""",
)
def compile(
	codesigning_identity: CodesigningIdentity,
):
	"""
	Compile the `atsdiag` and `plsan` helper utilities.
	"""

	utility_classes = [DiagnoseUtility, PlistSanitizer]

	with tqdm(
		desc="Compiling utilities",
		total=len(utility_classes) * 2,
		leave=False,
	) as progress:
		utilities: List[Utility] = []
		for cls in [DiagnoseUtility, PlistSanitizer]:
			utility = cls.start_compilation()
			utilities.append(utility)

		to_process = utilities
		while to_process:
			for utility in to_process:
				state = utility.poll()
				if state is State.Compiled:
					utility.start_signing(identity=codesigning_identity)
				if state in {State.Compiled, State.Ready}:
					progress.update()
			sleep(.1)
			to_process = [utility for utility in to_process if not utility.is_ready]


@cli.command()
@click.option(
	'--codesigning-identity',
	type=CodesigningIdentityParam(),
	default='auto',
	show_default=True,
	help="""
	The SHA-1 hash of the identity used for signing code.
	All valid identities can be listed with:

		security find-identity -p codesigning -v

	Set to 'auto' in order to determine the codesigning identity automatically.
	""",
)
@click.option(
	'--skip-tlsv1_3/--no-skip-tlsv1_3',
	default=True,
	show_default=True
)
@click.argument('url_', metavar='URL', required=True)
def diagnose(
	codesigning_identity: CodesigningIdentity,
	skip_tlsv1_3: bool,
	url_: str,
):
	url = urlparse(url_)
	domain = url.hostname

	if domain is None:
		click.BadArgumentUsage(f"Invalid URL: {url_}")
	assert domain is not None

	with DiagnoseUtility.default_info_plist_path().open('rb') as fp:
		info_plist = plistlib.load(fp)

	configuration: Optional[ats.Configuration] = ats.Configuration.MostSecure

	assert configuration is not None
	if skip_tlsv1_3 and configuration.tls_version is ats.TlsVersion.TLSv1_3:
		configuration = configuration.with_tls_version(ats.TlsVersion.TLSv1_2)

	while configuration:
		with tempfile.TemporaryDirectory(prefix='ats-') as temp_dir_:
			temp_dir = Path(temp_dir_)

			target_path = temp_dir / f'atsdiag-{str(configuration)}'
			info_plist_path = temp_dir / 'atsdiag-{str(configuration)}.plist'

			info_plist['NSAppTransportSecurity'] = configuration.ats_dict(
				{domain},
				simplify=False,
			)

			with info_plist_path.open('wb') as fp:
				plistlib.dump(info_plist, fp, fmt=plistlib.FMT_XML)

			click.secho(f"Compiling {target_path}... ", nl=False, err=True)
			atsdiag = DiagnoseUtility.compile_and_sign(
				target_path=target_path,
				info_plist_path=info_plist_path,
				identity=codesigning_identity,
			)
			click.secho("✓", fg='green', bold=True, err=True)

			click.secho("Trying configuration ", nl=False, err=True)
			click.secho(str(configuration), bold=True, nl=False, err=True)
			click.secho("... ", nl=False, err=True)
			diagnostics = atsdiag.run({url.geturl()})[0]
			error: Dict[str, Any] = diagnostics.get('error', dict())

			if not error:
				click.secho("✓", fg='green', bold=True, err=True)
				diagnostics['ats'] = configuration.ats_dict({domain}, simplify=True)
				click.echo(json.dumps(diagnostics))
				return

			click.secho("× ", fg='red', bold=True, err=True, nl=False)

			# TODO Detect local domains?

			# TODO Check whether URL has HTTP scheme
			# - try upgrading to HTTPS (check for redirect or simply modify scheme)
			# - try AllowsInsecureHttpLoads as fallback or alternative?

			code = error.get('code', None)

			if code == ats.ErrorCodes.SSLError:
				tls_version = configuration.tls_version
				if ats.TlsVersion.TLSv1_0 < tls_version:
					new_tls_version = ats.TlsVersion(tls_version - 1)
					click.secho(f"Decreasing required TLS version: {new_tls_version}", err=True)
					configuration = configuration.with_tls_version(new_tls_version)
					continue

			if code == ats.ErrorCodes.DomainNotFound:
				# TODO Try with AllowsLocalNetworking
				# - still use MostSecure? or is anything allowed locally?
				# - if the host is still not found, mark it as finished
				pass

			if code == ats.ErrorCodes.ATSError:
				# TODO Disable CT, if enabled
				# TODO Enable CT and disable FS, if enabled
				# TODO Disable FS and CT
				# TODO Try AllowsArbitraryLoads
				pass

			click.secho("unhandled", fg='red', err=True)
			results = {
				'ats': configuration.ats_dict({domain}, simplify=False),
				'diagnostics': diagnostics,
			}
			click.echo(json.dumps(results))
			configuration = None


@cli.group()
def test_environment():
	"""
	A test environment is required for some tests, namely tests involing a live
	server. Without a test environment, these tests will fail, as the `atsdiag`
	utility will not be able to establish an encrypted connection to the test
	server.
	"""
	pass


@test_environment.command()
def status():
	"""
	Check whether a test environment is available.
	"""
	sys.exit(not TestEnvironment.exists())


@test_environment.command()
@click.option(
	'--days',
	type=click.INT,
	default=28,
	show_default=True,
	help="""
	The duration for which the test environment is valid. After that duration
	the created root certificate will be invalid and tests will fail.
	""",
)
def setup(days: int):
	"""
	Set the current user of the current machine up for testing.

	See the help for the `test-environment` command for additional details why
	a test environment is required.

	This command will create a self-signed root certificate authority (CA) and
	adds the CA to the default keychain of the current user. This will result in
	a password prompt (GUI). Therefore, this command should not be run in a
	non-GUI context such as SSH.

	Attention: The key of the CA should be kept private, else someone possessing
	the key can create certificates for ANY web site which will be trusted by
	the system for the current user.

	In order to remove the created CA, use the `tear-down` command.
	"""

	if TestEnvironment.exists():
		raise click.ClickException("Test environment is already set up.")

	TestEnvironment.setup(days=days)


@test_environment.command()
def teardown():
	"""
	Removes the current test environment.

	fail, see `setup` command for a more detailed descirptio

	In detail:
	"""

	if not TestEnvironment.exists():
		raise click.ClickException("There is no test environment.")

	TestEnvironment.teardown()
