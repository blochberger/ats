import json
import sys

from dataclasses import dataclass
from pathlib import Path
from io import TextIOWrapper
from time import sleep
from typing import Any, List, Optional, Set

import click

from tqdm import tqdm
from tqdm._utils import _term_move_up as term_move_up

import ats
from utilities import (
	CodesigningIdentity,
	PlistSanitizer,
	State,
	Utility,
)
from tests import TestEnvironment


_tqdm_buf = ''


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
	Compile the `atsprobe` and `plsan` helper utilities.
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
@click.option('--upgrade-scheme/--no-upgrade-scheme', default=False)
@click.argument('url_', metavar='URL', required=True)
@click.pass_obj
def determine(ctx: Context, upgrade_scheme: bool, url_: str):

	def log_info(msg: str, nl: bool = True):
		click.secho(msg, nl=nl, err=True)

	def log_error(msg: str, nl: bool = True):
		click.secho(msg, fg='red', nl=nl, err=True)

	def log_success(msg: str, nl: bool = True):
		click.secho(msg, fg='green', nl=nl, err=True)

	def log_special(msg: str, nl: bool = True):
		click.secho(msg, fg='blue', nl=nl, err=True)

	endpoint = ats.Endpoint.from_url(url_)

	if endpoint is None:
		raise click.BadOptionUsage('url', f"Invalid endpoint: {endpoint}")

	configuration, diagnostics = ats.find_best_configuration(
		endpoint=endpoint,
		upgrade_scheme=upgrade_scheme,
		identity=ctx.identity,
		log_info=log_info,
		log_error=log_error,
		log_success=log_success,
		log_special=log_special,
	)

	if configuration is None:
		click.secho("Failed to determine configuration:", fg='red', err=True)
		click.echo(json.dumps([entry.json_dict() for entry in diagnostics]))
		exit(1)

	click.echo(json.dumps(configuration.ats_dict()))


@cli.command()
@click.argument(
	'output_dir',
	type=click.Path(file_okay=False, dir_okay=True, readable=True, writable=True),
	required=True,
)
@click.argument(
	'urls_',
	metavar='URL',
	type=click.File('r'),
	required=True,
)
@click.pass_obj
def collect_diagnostics(ctx: Context, output_dir: str, urls_: TextIOWrapper):
	global _tqdm_buf
	_tqdm_buf = ''

	output_path = Path(output_dir)

	output_path.mkdir(parents=True, exist_ok=True)

	endpoints: Set[ats.Endpoint] = set()
	for line in urls_.read().splitlines(keepends=False):
		endpoint = ats.Endpoint.from_url(line)
		if endpoint is None:
			raise click.BadOptionUsage('urls', f"Invalid endpoint: {line}")
		endpoints.add(endpoint)

	failing: Set[ats.Endpoint] = set()

	with tqdm(
		desc="Analyzing URLs",
		total=len(endpoints),
		leave=True,
		file=sys.stderr,
	) as progress:

		def log(msg: str, nl: bool = True):
			global _tqdm_buf

			prefix = ''
			if _tqdm_buf:
				prefix = term_move_up() + '\r'

			_tqdm_buf += msg
			progress.write(prefix + _tqdm_buf, file=sys.stderr)

			if nl:
				_tqdm_buf = ''

			# Does not work, see https://github.com/tqdm/tqdm/issues/737
			#progress.write(msg, file=sys.stderr, end='\n' if nl else '')

		def log_info(msg: str, nl: bool = True):
			log(msg, nl)

		def log_error(msg: str, nl: bool = True):
			log(click.style(msg, fg='red'), nl)

		def log_success(msg: str, nl: bool = True):
			log(click.style(msg, fg='green'), nl)

		def log_special(msg: str, nl: bool = True):
			log(click.style(msg, fg='blue'), nl)

		def log_warn(msg: str, nl: bool = True):
			log(click.style(msg, fg='yellow'), nl)

		for endpoint in endpoints:
			path = output_path / f'{endpoint.reverse_domain_name}.json'
			relpath = path.relative_to(output_path)

			log_info(click.style(f"{endpoint}", bold=True))

			if not endpoint.is_ip and endpoint.is_local:
				log_special("  → ", nl=False)
				log_warn("Local domain, skipping.")
				progress.update()
				continue

			if path.exists():
				log_special("  → ", nl=False)
				log_warn("Result already exists, skipping.")
				progress.update()
				continue

			configuration, diagnostics = ats.find_best_configuration(
				endpoint=endpoint,
				upgrade_scheme=False,
				identity=ctx.identity,
				log_info=log_info,
				log_error=log_error,
				log_success=log_success,
				log_special=log_special,
				level=1,
			)
			result = {
				'configuration': configuration.ats_dict() if configuration else None,
				'diagnostics': [entry.json_dict() for entry in diagnostics],
			}
			path.write_text(json.dumps(result))
			log_special("  · ", nl=False)
			log_success(f"Results written to {relpath}")
			if configuration is None:
				failing.add(endpoint)
			progress.update()

	# Summarize failures
	click.secho("Failing:", fg='red', bold=True, err=True)
	for endpoint in failing:
		click.secho(f"  {endpoint}", fg='red', err=True)


@cli.command()
@click.argument(
	'data_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def find_endpoints(data_dir: str):
	import os
	import subprocess

	for current, dirs, files in os.walk(data_dir):
		for fn in files:
			if fn == 'executable.bin':
				path = os.path.join(current, fn)
				app = os.path.dirname(os.path.relpath(path, data_dir))
				click.echo(app, err=True)
				strings = subprocess.run(
					['strings', '-', '-a', path],
					check=True,
					capture_output=True,
					text=True,
				)
				lines = strings.stdout.splitlines(keepends=False)
				for line in lines:
					for endpoint in ats.Endpoint.find_instances(line):
						click.echo(endpoint)


@cli.group()
def test_environment():
	"""
	A test environment is required for some tests, namely tests involing a live
	server. Without a test environment, these tests will fail, as the `atsprobe`
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
