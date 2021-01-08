import json
import os
import subprocess
import sys

from dataclasses import dataclass
from datetime import datetime
from functools import cached_property
from pathlib import Path
from io import TextIOWrapper
from time import sleep
from typing import Any, Dict, List, Optional, Set, Tuple

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


def percentage(value: int, total: int) -> float:
	if total == 0:
		return 0
	return (value / total) * 100.0


@dataclass(frozen=True)
class DiagnosticResults:
	endpoints: Set[ats.Endpoint]
	redirections: Dict[ats.Endpoint, ats.Endpoint]
	configurations: Dict[str, ats.Configuration]
	date_range: Tuple[datetime, datetime]

	@cached_property
	def transitive_redirects(self) -> List[List[ats.Endpoint]]:
		results: List[List[ats.Endpoint]] = []

		for source, target in self.redirections.items():

			# Only start with root sources
			if source in self.redirections.values():
				continue

			path = [source]
			transitive_target: Optional[ats.Endpoint] = target

			while transitive_target is not None:
				was_in_path = transitive_target in path
				path.append(transitive_target)
				transitive_target = self.redirections.get(transitive_target, None)
				if was_in_path:
					break

			results.append(path)

		return results

	@classmethod
	def parse(cls, diagnostics_path: Path) -> 'DiagnosticResults':
		endpoints: Set[ats.Endpoint] = set()
		redirections: Dict[ats.Endpoint, ats.Endpoint] = dict()
		configurations: Dict[str, ats.Configuration] = dict()
		first: Optional[datetime] = None
		last: Optional[datetime] = None

		# Parse diagnostics
		for entry in diagnostics_path.iterdir():
			if not entry.is_file():
				continue

			reverse_domain_name = entry.stem

			with entry.open('r') as f:
				data: Dict[str, Any] = json.load(f)

			ats_dict: Optional[Dict[str, Any]] = data.get('configuration', None)
			diagnostic_results: List[Dict[str, Any]] = data.get('diagnostics', [])

			for diagnostics in diagnostic_results:
				endpoint = ats.Endpoint.from_url(diagnostics.get('url', ''))
				assert endpoint is not None
				endpoints.add(endpoint)

				redirected = ats.Endpoint.from_url(diagnostics.get('redirected_url', ''))
				if redirected is not None:
					endpoints.add(redirected)
					redirections[endpoint] = redirected

				if timestamp_str := diagnostics.get('timestamp', None):
					timestamp = ats.timestamp_from_str(timestamp_str)
					if first is None or timestamp < first:
						first = timestamp
					if last is None or last < timestamp:
						last = timestamp

			if ats_dict is not None:
				configuration = ats.Configuration.from_ats_dict(ats_dict)
				configurations[reverse_domain_name] = configuration

		assert first is not None
		assert last is not None

		return cls(
			endpoints=endpoints,
			redirections=redirections,
			configurations=configurations,
			date_range=(first, last),
		)


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


@cli.command()
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_diagnostics(diagnostics_dir: str):

	diagnostics = DiagnosticResults.parse(Path(diagnostics_dir))

	hosts = {endpoint.host for endpoint in diagnostics.endpoints}
	hosts_ats = {endpoint.host for endpoint in diagnostics.endpoints if not endpoint.is_ip}
	hosts_noats = hosts - hosts_ats
	hosts_local = {endpoint.host for endpoint in diagnostics.endpoints if endpoint.is_local}

	# Evaluate diagnostics
	endpoints_with_standard_port = {
		endpoint for endpoint in diagnostics.endpoints if endpoint.has_standard_port
	}
	endpoints_with_tls = {
		endpoint for endpoint in diagnostics.endpoints if endpoint.uses_tls
	}

	redirects_to_https = {
		source: target
		for source, target in diagnostics.redirections.items()
		if not source.uses_tls and target.uses_tls
	}
	redirects_https_upgrade = {
		source: target
		for source, target in redirects_to_https.items()
		if source.host == target.host
	}
	redirects_to_http = {
		source: target
		for source, target in diagnostics.redirections.items()
		if source.uses_tls and not target.uses_tls
	}

	transitive_redirects_to_https = [
		path
		for path in diagnostics.transitive_redirects
		if not path[0].uses_tls and path[-1].uses_tls
	]
	transitive_redirects_to_http = [
		path
		for path in diagnostics.transitive_redirects
		if path[0].uses_tls and not path[-1].uses_tls
	]
	transitive_redirects_pure_https = [
		path
		for path in diagnostics.transitive_redirects
		if all(endpoint.uses_tls for endpoint in path)
	]
	transitive_redirects_pure_http = [
		path
		for path in diagnostics.transitive_redirects
		if all(not endpoint.uses_tls for endpoint in path)
	]

	transitive_redirects_http_prefix: List[List[ats.Endpoint]] = []
	for path in transitive_redirects_to_https:
		assert not path[0].uses_tls
		assert path[-1].uses_tls

		in_suffix = False
		http_in_suffix = False
		for endpoint in path[1:-1]:
			in_suffix |= endpoint.uses_tls
			if in_suffix and not endpoint.uses_tls:
				http_in_suffix = True
				break
		if not http_in_suffix:
			transitive_redirects_http_prefix.append(path)

	configurations_j = {
		k: v
		for k, v in diagnostics.configurations.items()
		if v.requires_justification
	}
	configurations_nd = {
		k: v
		for k, v in diagnostics.configurations.items()
		if not v.is_default
	}
	configurations_noats = {
		k: v
		for k, v in diagnostics.configurations.items()
		if not v.arbitrary_loads and 0 == len(v.exceptions)
	}
	configurations_local = {
		k: v
		for k, v in diagnostics.configurations.items()
		if v.local_networking
	}

	http = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.insecure_http_loads
	}
	fs = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.forward_secrecy
	}
	ct = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.certificate_transparency
	}
	tls1_0 = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.tls_version is ats.TlsVersion.TLSv1_0
	}
	tls1_1 = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.tls_version is ats.TlsVersion.TLSv1_1
	}
	tls1_2 = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.tls_version is ats.TlsVersion.TLSv1_2
	}
	tls1_3 = {
		domain
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.tls_version is ats.TlsVersion.TLSv1_3
	}
	non_default = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if not exception.is_default
	}
	most_secure = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception == ats.DomainConfiguration.most_secure()
	}
	more_secure = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if ats.DomainConfiguration() < exception
	}
	less_secure = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception < ats.DomainConfiguration()
	}
	mixed = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if not (exception < ats.DomainConfiguration() or exception > ats.DomainConfiguration())
	}
	requires_justification = {
		domain: exception
		for k, configuration in diagnostics.configurations.items()
		for domain, exception in configuration.exceptions.items()
		if exception.requires_justification
	}

	def pp(value: int, total: int) -> str:
		return f"{value:5d} ({percentage(value, total):6.2f} %)"

	# Output results
	click.secho(f"Results from {diagnostics.date_range[0]} – {diagnostics.date_range[1]}", fg='blue', bold=True)

	click.secho(f"Endpoints:                {len(diagnostics.endpoints):5d}", bold=True)
	click.echo(f"  with standard port:     {pp(len(endpoints_with_standard_port), len(diagnostics.endpoints))}")
	click.echo(f"  with TLS:               {pp(len(endpoints_with_tls), len(diagnostics.endpoints))}")
	click.echo(f"  domains:                {pp(len(hosts), len(diagnostics.endpoints))}")

	click.secho(f"Direct redirections:      {len(diagnostics.redirections):5d}", bold=True)
	click.echo(f"  HTTP -> HTTPS:          {pp(len(redirects_to_https), len(diagnostics.redirections))}")
	click.echo(f"  HTTP -> HTTPS upgrade:  {pp(len(redirects_https_upgrade), len(diagnostics.redirections))}")
	click.echo(f"  HTTPS -> HTTP:          {pp(len(redirects_to_http), len(diagnostics.redirections))}")

	click.secho(f"Transitive redirections:  {len(diagnostics.transitive_redirects):5d}", bold=True)
	click.echo(f"  HTTP -> HTTPS:          {pp(len(transitive_redirects_to_https), len(diagnostics.transitive_redirects))}")
	click.echo(f"    upgrade only:         {pp(len(transitive_redirects_http_prefix), len(transitive_redirects_to_https))}")
	click.echo(f"  HTTPS -> HTTP:          {pp(len(transitive_redirects_to_http), len(diagnostics.transitive_redirects))}")
	click.echo(f"  pure HTTPS:             {pp(len(transitive_redirects_pure_https), len(diagnostics.transitive_redirects))}")
	click.echo(f"  pure HTTP:              {pp(len(transitive_redirects_pure_http), len(diagnostics.transitive_redirects))}")

	click.secho(f"Configurations:           {len(diagnostics.configurations):5d}", bold=True)
	click.echo(f"  requires justification: {pp(len(configurations_j), len(diagnostics.configurations))}")
	click.echo(f"  non-default:            {pp(len(configurations_nd), len(diagnostics.configurations))}")
	click.echo(f"  ATS disabled:           {pp(len(configurations_noats), len(diagnostics.configurations))}")
	click.echo(f"  local:                  {pp(len(configurations_local), len(diagnostics.configurations))}")

	click.secho(f"Domains:                  {len(hosts):5d}", bold=True)
	click.echo(f"  not affected by ATS:    {pp(len(hosts_noats), len(hosts))}")
	click.echo(f"  local:                  {pp(len(hosts_local), len(hosts))}")

	click.secho(f"Domain diagnostics:       {len(hosts_ats):5d}", bold=True)
	click.echo(f"  non-default             {pp(len(non_default), len(hosts_ats))}")
	click.echo(f"  most-secure             {pp(len(most_secure), len(hosts_ats))}")
	click.echo(f"  better than default:    {pp(len(more_secure), len(hosts_ats))}")
	click.echo(f"  worse than default:     {pp(len(less_secure), len(hosts_ats))}")
	click.echo(f"  mixed:                  {pp(len(mixed), len(hosts_ats))}")
	click.echo(f"  requires justification: {pp(len(requires_justification), len(hosts_ats))}")
	click.echo(f"  HTTP:                   {pp(len(http), len(hosts_ats))}")
	click.echo(f"  FS:                     {pp(len(fs), len(hosts_ats))}")
	click.echo(f"  CT:                     {pp(len(ct), len(hosts_ats))}")
	click.echo(f"  TLSv1.0:                {pp(len(tls1_0), len(hosts_ats))}")
	click.echo(f"  TLSv1.1:                {pp(len(tls1_1), len(hosts_ats))}")
	click.echo(f"  TLSv1.2:                {pp(len(tls1_2), len(hosts_ats))}")
	click.echo(f"  TLSv1.3:                {pp(len(tls1_3), len(hosts_ats))}")


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
