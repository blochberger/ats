import json
import sys

from dataclasses import dataclass
from time import sleep
from typing import Any, List, Optional

import click

from tqdm import tqdm

import ats
from utilities import (
	CodesigningIdentity,
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


@dataclass(frozen=True)
class Context:
	identity: CodesigningIdentity


@click.group()
@click.option(
	'--codesigning-identity',
	type=CodesigningIdentityParam(),
	default='auto',
	envvar="CODESIGN_IDENTITY",
	show_default=True,
	help="""
	The SHA-1 hash of the identity used for signing code.
	All valid identities can be listed with:

		security find-identity -p codesigning -v

	Set to 'auto' in order to determine the codesigning identity automatically.
	""",
)
@click.pass_context
def cli(ctx: click.Context, codesigning_identity: CodesigningIdentity):
	ctx.obj = Context(
		identity=codesigning_identity,
	)


@cli.command()
@click.pass_obj
def compile(ctx: Context):
	"""
	Compile the `atsdiag` and `plsan` helper utilities.
	"""

	utility_classes = [ats.DiagnoseUtility, PlistSanitizer]

	with tqdm(
		desc="Compiling utilities",
		total=len(utility_classes) * 2,  # Compile and sign each utility
		leave=False,
	) as progress:
		utilities: List[Utility] = []
		for cls in [ats.DiagnoseUtility, PlistSanitizer]:
			utility = cls.start_compilation()
			utilities.append(utility)

		to_process = utilities
		while to_process:
			for utility in to_process:
				state = utility.poll()
				if state is State.Compiled:
					utility.start_signing(ctx.identity)
				if state in {State.Compiled, State.Ready}:
					progress.update()
			sleep(.1)
			to_process = [utility for utility in to_process if not utility.is_ready]


@cli.command()
@click.argument('url_', metavar='URL', required=True)
@click.pass_obj
def determine(ctx: Context, url_: str):

	def log_info(msg: str, nl: bool = True):
		click.secho(msg, nl=nl, err=True)

	def log_error(msg: str, nl: bool = True):
		click.secho(msg, fg='red', nl=nl, err=True)

	def log_success(msg: str, nl: bool = True):
		click.secho(msg, fg='green', nl=nl, err=True)

	def log_special(msg: str, nl: bool = True):
		click.secho(msg, fg='blue', nl=nl, err=True)

	url = ats.Url.from_url(url_)

	if url is None:
		raise click.BadOptionUsage('url', f"Invalid URL: {url}")

	result = ats.find_best_configuration(
		url=url,
		identity=ctx.identity,
		log_info=log_info,
		log_error=log_error,
		log_success=log_success,
		log_special=log_special,
	)

	click.echo(json.dumps(result))


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

	Without a test environment, some tests will fail, see `setup` command for
	a more detailed description.
	"""

	if not TestEnvironment.exists():
		raise click.ClickException("There is no test environment.")

	TestEnvironment.teardown()
