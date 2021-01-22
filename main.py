import json
import sys

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import cached_property
from pathlib import Path
from time import sleep
from typing import Any, Dict, List, Optional, Set, Tuple

import click

from natsort import natsorted
from tqdm import tqdm
from tqdm._utils import _term_move_up as term_move_up

import ats
import maap

from maap import App
from utilities import (
	CodesigningIdentity,
	PlistSanitizer,
	State,
	Utility,
)
from tests import TestEnvironment


_tqdm_buf = ''


def tqdm_log(progress: tqdm, msg: str, nl: bool = True):
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


def percentage(value: int, total: int) -> float:
	if total == 0:
		return 0
	return (value / total) * 100.0


def pp(value: int, total: int) -> str:
	return f"{value:5d} ({percentage(value, total):6.2f} %)"


@dataclass
class Table:
	columns: List[str] = field(default_factory=list)
	groups: List[str] = field(default_factory=list)
	rows_per_group: Dict[str, List[str]] = field(
		default_factory=lambda: defaultdict(list),
	)
	values: Dict[str, Dict[str, Dict[str, int]]] = field(
		default_factory=lambda: defaultdict(lambda: defaultdict(dict)),
	)

	def add_group(self, group: str, value: int, column: str = '') -> str:
		if group not in self.groups:
			self.groups.append(group)
		self.values[group][''][column] = value
		return group

	def add_row(self, group: str, row: str, value: int, column: str = ''):
		assert group in self.groups, f"Group does not exist: {group}"
		assert row != ''
		if row not in self.rows_per_group[group]:
			self.rows_per_group[group].append(row)
		if column not in self.columns:
			self.columns.append(column)
		self.values[group][row][column] = value

	def display(self, prefix: str = ""):
		# Print column headers
		if 1 < len(self.columns) and self.columns != ['']:
			click.echo(prefix, nl=False)
			click.echo(" " * 42, nl=False)
			for column in self.columns:
				click.secho(f" {column:15s}", bold=True, nl=False)
			click.echo("")

		for group in self.groups:
			rows = [''] + self.rows_per_group[group]

			# Print rows
			for row in rows:
				is_group = row == ''
				values = self.values[group][row]

				# Print row header
				click.echo(prefix, nl=False)
				if is_group:
					click.secho(f"{group:42s}", bold=True, nl=False)
				else:
					click.echo(f"  {row:40s}", nl=False)

				# Print columns
				for column in self.columns:
					total = self.values[group][''].get(column, None)
					value = values.get(column, None)
					if not (total is None or value is None):
						click.secho(f" {value:5d}", bold=is_group, nl=False)
						if is_group:
							click.echo(" " * 10, nl=False)
						else:
							click.echo(f" ({percentage(value, total):6.2f}%)", nl=False)
					else:
						click.echo(" " * 16, nl=False)

				# If there are exactly two columns, print differences
				if 2 == len(self.columns):
					first = values.get(self.columns[0], None)
					second = values.get(self.columns[1], None)
					if not (first is None or second is None):
						diff = second - first
						fg: Optional[str] = None
						if 0 < diff:
							fg = 'green'
							click.secho(" + ", fg=fg, bold=is_group, nl=False)
						elif 0 > diff:
							fg = 'red'
							click.secho(" - ", fg=fg, bold=is_group, nl=False)
						else:
							click.secho(" = ", bold=is_group, nl=False)
						click.secho(f"{abs(diff):5d}", fg=fg, bold=is_group, nl=False)

				# End row
				click.echo("")

	def markdown(self):
		def bold(value: str) -> str:
			return "**" + value + "**"

		# Print column headers
		if 1 < len(self.columns) and self.columns != ['']:
			click.echo("|| " + (" | ".join(map(bold, self.columns))) + " |")
			click.echo("| " + (" | ".join(["---"] * (len(self.columns) + 1))) + " |")

		for group in self.groups:
			rows = [''] + self.rows_per_group[group]

			# Print rows
			for row in rows:
				is_group = row == ''
				values = self.values[group][row]

				# Print row header
				if is_group:
					click.echo(f"| {bold(group)}", nl=False)
				else:
					click.echo(f"| {row}", nl=False)

				# Print columns
				for column in self.columns:
					total = self.values[group][''].get(column, None)
					value = values.get(column, None)
					if not (total is None or value is None):
						if is_group:
							click.echo(f" | {bold(str(value))}", nl=False)
						else:
							click.echo(f" | {value} ({percentage(value, total):.2f}%)", nl=False)
					else:
						click.echo(" | ", nl=False)

				# End row
				click.echo(" |")


@dataclass(frozen=True)
class DiagnosticResults:
	diagnostics: Dict[ats.Endpoint, ats.Diagnostics]

	@cached_property
	def succeeding(self) -> 'DiagnosticResults':
		return self.__class__({
			endpoint: diagnostics
			for endpoint, diagnostics in self.diagnostics.items()
			if diagnostics.did_succeed
		})

	@cached_property
	def failing(self) -> 'DiagnosticResults':
		return self.__class__({
			endpoint: diagnostics
			for endpoint, diagnostics in self.diagnostics.items()
			if not diagnostics.did_succeed
		})

	@cached_property
	def configurations(self) -> Dict[ats.Endpoint, ats.Configuration]:
		return {
			endpoint: diagnostics.configuration
			for endpoint, diagnostics in self.diagnostics.items()
		}

	@cached_property
	def hsts_preload(self) -> Set[ats.Endpoint]:
		return {
			endpoint
			for endpoint, configuration in self.succeeding.configurations.items()
			if not endpoint.uses_tls and not configuration.exceptions[endpoint.host].insecure_http_loads
		}

	@cached_property
	def normalized_configurations(self) -> Dict[ats.Endpoint, ats.Configuration]:
		result: Dict[ats.Endpoint, ats.Configuration] = dict()
		for endpoint, configuration in self.succeeding.configurations.items():
			https_configuration = self.succeeding.configurations.get(endpoint.with_tls, None)

			if https_configuration is None or endpoint.uses_tls:
				result[endpoint] = configuration
				continue

			assert https_configuration is not None
			assert 1 == len(configuration.exceptions) == len(https_configuration.exceptions)

			http_exception = configuration.exceptions[endpoint.host]
			https_exception = https_configuration.exceptions[endpoint.host]

			# The configuration for a non-TLS endpoint might not require to
			# allow insecure HTTP loads if the host is in the HSTS preload list.
			# Since `atsprobe` uses an ephemeral configuration, this only
			# applies to the pre-defined HSTS preload list in the Foundation
			# framework.

			assert not https_exception.insecure_http_loads
			assert not http_exception.includes_subdomains
			assert not https_exception.includes_subdomains

			assert not configuration.arbitrary_loads
			assert not https_configuration.arbitrary_loads
			assert not configuration.local_networking
			assert not https_configuration.local_networking

			# Sanitize that the non-TLS configuration uses most secure, because
			# no TLS parameters were probed.
			most_secure = ats.DomainConfiguration.most_secure()
			assert all([
				http_exception.tls_version == most_secure.tls_version,
				http_exception.forward_secrecy == most_secure.forward_secrecy,
				http_exception.certificate_transparency == most_secure.certificate_transparency,
			])

			normalized = ats.Configuration(
				exceptions={endpoint.host: ats.DomainConfiguration(
					includes_subdomains=False,
					insecure_http_loads=http_exception.insecure_http_loads,
					tls_version=https_exception.tls_version,
					forward_secrecy=https_exception.forward_secrecy,
					certificate_transparency=https_exception.certificate_transparency,
				)},
			)
			result[endpoint] = normalized

		return result

	@cached_property
	def endpoints(self) -> Set[ats.Endpoint]:
		return set(self.diagnostics.keys())

	@cached_property
	def date_range(self) -> Tuple[datetime, datetime]:
		first: Optional[datetime] = None
		last: Optional[datetime] = None
		for diagnostics in self.diagnostics.values():
			timestamp = diagnostics.timestamp
			if first is None or timestamp < first:
				first = timestamp
			if last is None or last < timestamp:
				last = timestamp
		assert not (first is None or last is None)
		return (first, last)

	@cached_property
	def redirections(self) -> Dict[ats.Endpoint, ats.Endpoint]:
		return {
			endpoint: diagnostics.redirected
			for endpoint, diagnostics in self.diagnostics.items()
			if diagnostics.redirected is not None
		}

	@cached_property
	def transitive_redirections(self) -> List[List[ats.Endpoint]]:
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
		diagnostic_results: Dict[ats.Endpoint, ats.Diagnostics] = dict()

		# Parse diagnostics
		for entry in diagnostics_path.iterdir():
			if not entry.suffix == '.jsonl':
				continue

			lines = entry.read_text().splitlines(keepends=False)
			for line in lines:
				d: Dict[str, Any] = json.loads(line)
				diagnostics = ats.Diagnostics.from_dict(d)
				diagnostic_results[diagnostics.endpoint] = diagnostics

		return cls(diagnostic_results)


@dataclass(frozen=True)
class Evaluation:
	dataset: maap.Dataset
	diagnostics: DiagnosticResults

	@cached_property
	def endpoints(self) -> Set[ats.Endpoint]:
		return self.dataset.endpoints.union(self.diagnostics.endpoints)

	@cached_property
	def app_endpoints(self) -> Dict[App, Set[ats.Endpoint]]:
		results: Dict[App, Set[ats.Endpoint]] = dict()
		for app in self.dataset.apps:
			result: Set[ats.Endpoint] = app.endpoints
			queue = app.relevant_endpoints  # Diagnostics only exist for relevant
			while queue:
				source = queue.pop()
				if target := self.diagnostics.redirections.get(source, None):
					if target in result:
						continue  # Redirection loop
					queue.add(target)
					result.add(target)
			assert len(app.endpoints) <= len(result)
			results[app] = result
		return results

	@cached_property
	def endpoint_apps(self) -> Dict[ats.Endpoint, Set[App]]:
		results: Dict[ats.Endpoint, Set[App]] = defaultdict(set)
		for app, app_endpoints in self.app_endpoints.items():
			for endpoint in app_endpoints:
				results[endpoint].add(app)
		return results


def endpoint_statistics(
	endpoints: Set[ats.Endpoint],
	table: Table,
	column: str = ''
):
	with_standard_port = {
		endpoint for endpoint in endpoints if endpoint.has_standard_port
	}
	with_tls = {endpoint for endpoint in endpoints if endpoint.uses_tls}
	hosts = {endpoint.host for endpoint in endpoints}
	ats = {endpoint.host for endpoint in endpoints if not endpoint.is_ip}
	no_ats = hosts - ats
	local = {endpoint.host for endpoint in endpoints if endpoint.is_local}

	grp = table.add_group("Endpoints", len(endpoints), column)
	table.add_row(grp, "with standard port", len(with_standard_port), column)
	table.add_row(grp, "with TLS", len(with_tls), column)
	table.add_row(grp, "unique hosts", len(hosts), column)

	grp = table.add_group("Hosts", len(hosts), column)
	table.add_row(grp, "not affected by ATS", len(no_ats), column)
	table.add_row(grp, "local", len(local), column)


def redirection_statistics(
	diagnostics: DiagnosticResults,
	table: Table,
	column: str = ''
):
	to_https = {
		source: target
		for source, target in diagnostics.redirections.items()
		if not source.uses_tls and target.uses_tls
	}
	https_upgrade = {
		source: target
		for source, target in to_https.items()
		if source.host == target.host
	}
	to_http = {
		source: target
		for source, target in diagnostics.redirections.items()
		if source.uses_tls and not target.uses_tls
	}

	t_to_https = [
		path
		for path in diagnostics.transitive_redirections
		if not path[0].uses_tls and path[-1].uses_tls
	]
	t_to_http = [
		path
		for path in diagnostics.transitive_redirections
		if path[0].uses_tls and not path[-1].uses_tls
	]
	pure_https = [
		path
		for path in diagnostics.transitive_redirections
		if all(endpoint.uses_tls for endpoint in path)
	]
	pure_http = [
		path
		for path in diagnostics.transitive_redirections
		if all(not endpoint.uses_tls for endpoint in path)
	]

	http_prefix: List[List[ats.Endpoint]] = []
	for path in t_to_https:
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
			http_prefix.append(path)

	grp = table.add_group("Redirections", len(diagnostics.redirections), column)
	table.add_row(grp, "HTTP -> HTTPS", len(to_https), column)
	table.add_row(grp, "HTTP -> HTTPS (same host)", len(https_upgrade), column)
	table.add_row(grp, "HTTPS -> HTTP", len(to_http), column)

	grp = table.add_group("Transitive redirections", len(diagnostics.transitive_redirections), column)
	table.add_row(grp, "pure HTTPS", len(pure_https), column)
	table.add_row(grp, "HTTP -> HTTPS (upgrade only)", len(http_prefix), column)
	table.add_row(grp, "HTTP -> HTTPS", len(t_to_https), column)
	table.add_row(grp, "HTTPS -> HTTP", len(t_to_http), column)
	table.add_row(grp, "pure HTTP", len(pure_http), column)


def configuration_statistics(
	configurations: List[ats.Configuration],
	table: Table,
	column: str = ''
):
	global_requires_justification = [
		configuration
		for configuration in configurations
		if configuration.requires_justification
	]
	global_non_default = [
		configuration
		for configuration in configurations
		if not configuration.is_default
	]
	no_ats = [
		configuration
		for configuration in configurations
		if not configuration.arbitrary_loads and 0 == len(configuration.exceptions)
	]
	no_ats_with_exceptions = [
		configuration
		for configuration in configurations
		if not configuration.arbitrary_loads and 0 < len(configuration.exceptions)
	]

	domain_configurations = [
		(domain, domain_configuration)
		for configuration in configurations
		for domain, domain_configuration in configuration.exceptions.items()
	]

	non_default = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if not configuration.is_default
	]
	most_secure = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration == ats.DomainConfiguration.most_secure()
	]
	more_secure = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if ats.DomainConfiguration() < configuration
	]
	less_secure = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration < ats.DomainConfiguration()
	]
	mixed = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if not any([
			configuration < ats.DomainConfiguration(),
			configuration > ats.DomainConfiguration(),
		])
	]
	requires_justification = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration.requires_justification
	]

	http = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration.insecure_http_loads
	]
	fs = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration.forward_secrecy
	]
	ct = [
		(domain, configuration)
		for domain, configuration in domain_configurations
		if configuration.certificate_transparency
	]
	tls: Dict[ats.TlsVersion, Set[str]] = dict()
	for tls_version in ats.TlsVersion:
		tls[tls_version] = [
			(domain, configuration)
			for domain, configuration in domain_configurations
			if configuration.tls_version is tls_version
		]

	grp = table.add_group("Configurations", len(configurations), column)
	table.add_row(grp, "non-default", len(global_non_default), column)
	table.add_row(grp, "requires justification", len(global_requires_justification), column)
	table.add_row(grp, "ATS disabled completely", len(no_ats), column)
	table.add_row(grp, "ATS disabled with exceptions", len(no_ats_with_exceptions), column)

	grp = table.add_group("Domain configurations", len(domain_configurations), column)
	table.add_row(grp, "non-default", len(non_default), column)
	table.add_row(grp, "most-secure", len(most_secure), column)
	table.add_row(grp, "better than default", len(more_secure), column)
	table.add_row(grp, "worse than default", len(less_secure), column)
	table.add_row(grp, "mixed", len(mixed), column)
	table.add_row(grp, "requires justification", len(requires_justification), column)
	table.add_row(grp, "HTTP", len(http), column)
	table.add_row(grp, "FS", len(fs), column)
	table.add_row(grp, "CT", len(ct), column)
	for tls_version in ats.TlsVersion:
		table.add_row(grp, str(tls_version), len(tls[tls_version]), column)


def failure_statistics(
	diagnostic_results: DiagnosticResults,
	table: Table,
	column: str = '',
):
	errors: Dict[int, int] = defaultdict(int)
	ssl_errors: Dict[int, int] = defaultdict(int)
	for diagnostics in diagnostic_results.diagnostics.values():
		if error_dict := diagnostics.error:
			code = error_dict['code']
			errors[code] += 1
			if code == ats.Error.SSLError:
				ssl_error_code = int(error_dict['streamErrorCode'])
				ssl_errors[ssl_error_code] += 1

	grp = table.add_group("Errors", sum(errors.values()), column)
	for code, count in errors.items():
		try:
			row = ats.Error(code).display
		except ValueError:
			row = str(code)
		table.add_row(grp, row, count, column)

	grp = table.add_group("SSL Errors", errors[ats.Error.SSLError.value], column)
	for code, count in ssl_errors.items():
		try:
			row = ats.SSLError(code).display
		except ValueError:
			row = str(code)
		table.add_row(grp, row, count, column)


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

	endpoint = ats.Endpoint.from_url(url_)

	if endpoint is None:
		raise click.BadOptionUsage('url', f"Invalid endpoint: {endpoint}")

	if endpoint.is_ip:
		click.secho(f"Endpoint is not affected by ATS: {endpoint}", fg='red', err=True)
		exit(1)

	diagnostics = ats.find_best_configuration(
		endpoint=endpoint,
		identity=ctx.identity,
		log_info=log_info,
		log_error=log_error,
		log_success=log_success,
		log_special=log_special,
	)

	click.echo(json.dumps(diagnostics.json_dict()))
	if not diagnostics.did_succeed:
		exit(1)


@cli.command()
@click.option(
	'--upgrade-scheme/--no-upgrade-scheme',
	default=True,
	show_default=True,
)
@click.argument(
	'urls_file',
	type=click.Path(dir_okay=False, file_okay=True, readable=True),
)
@click.argument(
	'output_dir',
	type=click.Path(file_okay=False, dir_okay=True, readable=True, writable=True),
	required=True,
)
@click.pass_obj
def collect_diagnostics(
	ctx: Context,
	upgrade_scheme: bool,
	urls_file: str,
	output_dir: str,
):
	urls_path = Path(urls_file)
	output_path = Path(output_dir)
	output_path.mkdir(parents=True, exist_ok=True)

	pending: Set[ats.Endpoint] = set()
	finished: Dict[ats.Endpoint, ats.Diagnostics] = dict()
	skipped: Set[ats.Endpoint] = set()
	upgraded: Set[ats.Endpoint] = set()

	# Parse URLs
	for idx, url in enumerate(urls_path.read_text().splitlines(keepends=False)):
		if endpoint := ats.Endpoint.from_url(url):
			if not endpoint.is_relevant:
				click.secho(f"Skipping irrelevant endpoint: {url}")
				continue
			pending.add(endpoint)
		else:
			click.secho(f"Invalid endpoint at line {idx}: {url}", fg='red', err=True)
			exit(1)

	# Add HTTPS variants for HTTP-only URLs
	if upgrade_scheme:
		upgraded = {
			endpoint.with_tls
			for endpoint in pending
			if not endpoint.uses_tls and endpoint.with_tls not in pending
		}
		pending = pending.union(upgraded)

	# Collect diagnostics
	with tqdm(
		desc="Analyzing URLs",
		total=len(pending),
		leave=True,
		file=sys.stderr,
	) as progress:

		def log_info(msg: str, nl: bool = True):
			tqdm_log(progress, msg, nl)

		def log_error(msg: str, nl: bool = True):
			tqdm_log(progress, click.style(msg, fg='red'), nl)

		def log_success(msg: str, nl: bool = True):
			tqdm_log(progress, click.style(msg, fg='green'), nl)

		def log_special(msg: str, nl: bool = True):
			tqdm_log(progress, click.style(msg, fg='blue'), nl)

		def log_warn(msg: str, nl: bool = True):
			tqdm_log(progress, click.style(msg, fg='yellow'), nl)

		while pending:
			endpoint = pending.pop()
			log_info(click.style(f"{endpoint}", bold=True))

			path = output_path / f'{endpoint.reverse_domain_name}.jsonl'
			relpath = path.relative_to(output_path)

			# TODO Append diagnostics, if old results are old enough or if old
			# result is erroneous and current is not.
			if path.exists():
				parsed: List[ats.Diagnostics] = []
				lines = path.read_text().splitlines(keepends=False)
				for line in lines:
					d: Dict[str, Any] = json.loads(line)
					parsed.append(ats.Diagnostics.from_dict(d))
				existing = DiagnosticResults({x.endpoint: x for x in parsed})

				# Add unfinished or erroneous redirection targets
				redirections = set(existing.succeeding.redirections.values())
				redirections -= set(existing.succeeding.endpoints)
				redirections -= set(finished.keys())
				redirections -= set(skipped)
				redirections -= {endpoint}
				if redirections:
					pending = pending.union(redirections)
					progress.reset(total=len(pending) + len(finished) + len(skipped) + 1)
					progress.update(len(finished) + len(skipped))

				# Skip endpoints that were diagnosed recently
				if endpoint in existing.diagnostics:
					diagnostics = existing.diagnostics[endpoint]
					age = datetime.now(timezone.utc) - diagnostics.timestamp
					if age < timedelta(days=7):
						log_special("  → ", nl=False)
						log_warn("Recent result exists, skipping.")
						progress.update()
						skipped.add(endpoint)
						continue

			diagnostics = ats.find_best_configuration(
				endpoint=endpoint,
				identity=ctx.identity,
				log_info=log_info,
				log_error=log_error,
				log_success=log_success,
				log_special=log_special,
			)

			if redirected := diagnostics.redirected:
				if (
					redirected != endpoint and
					redirected not in pending and
					redirected not in finished and
					redirected not in skipped
				):
					pending.add(redirected)
					progress.reset(total=len(pending) + len(finished) + len(skipped) + 1)
					progress.update(len(finished) + len(skipped))

			with path.open('a') as f:
				f.write(json.dumps(diagnostics.json_dict()))
				f.write('\n')
			log_special("  · ", nl=False)
			log_success(f"Results written to {relpath}")
			finished[endpoint] = diagnostics
			progress.update()

	# Summarize failures
	failing = {
		endpoint
		for endpoint, diagnostics in finished.items()
		if not diagnostics.did_succeed
	}
	if failing:
		click.secho("Failing:", fg='red', bold=True, err=True)
		for endpoint in sorted(failing - upgraded):
			click.secho(f"  {endpoint}", fg='red', err=True)

	if upgraded:
		click.secho("Upgrades: ", bold=True, err=True)
		for endpoint in sorted(upgraded):
			if endpoint in skipped:
				fg = 'yellow'
			elif endpoint in failing:
				fg = 'red'
			else:
				fg = 'blue'
			click.secho(f"  {endpoint}", fg=fg, err=True)


@cli.command()
@click.argument(
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_configurations(maap_dir: str, diagnostics_dir: str):
	e = Evaluation(
		dataset=maap.Dataset.from_path(Path(maap_dir)),
		diagnostics=DiagnosticResults.parse(Path(diagnostics_dir)),
	)

	# Basic overview of both data sources
	click.secho(f"Apps: {len(e.dataset.apps)}", fg='blue', bold=True)
	click.secho(f"Diagnostics from {e.diagnostics.date_range[0]} – {e.diagnostics.date_range[1]}", fg='blue', bold=True)
	table = Table()
	endpoint_statistics(e.dataset.endpoints, table, "App")
	endpoint_statistics(e.diagnostics.endpoints, table, "Diagnostics")
	#configuration_statistics([app.ats_configuration for app in e.dataset.apps], table, "App")
	#configuration_statistics(list(e.diagnostics.configurations.values()), table, "Diagnostics")
	redirection_statistics(e.diagnostics, table, "Diagnostics")
	table.display()

	# Evaluate possible improvements
	app_can_improve_explicit: Dict[ats.Improvement, Set[App]] = defaultdict(set)
	app_can_improve_implicit: Dict[ats.Improvement, Set[App]] = defaultdict(set)

	ep_can_improve_explicit: Dict[ats.Improvement, Set[ats.Endpoint]] = defaultdict(set)
	ep_can_improve_implicit: Dict[ats.Improvement, Set[ats.Endpoint]] = defaultdict(set)
	d_can_improve_explicit: Dict[ats.Improvement, Set[str]] = defaultdict(set)
	d_can_improve_implicit: Dict[ats.Improvement, Set[str]] = defaultdict(set)

	num_implicit_cfgs: int = 0
	num_explicit_cfgs: int = 0

	explicit_endpoints: Set[ats.Endpoint] = set()
	implicit_endpoints: Set[ats.Endpoint] = set()
	explicit_domains: Set[str] = set()
	implicit_domains: Set[str] = set()

	c_app_explicit: Dict[str, Set[App]] = defaultdict(set)
	c_app_implicit: Dict[str, Set[App]] = defaultdict(set)

	c_ep_explicit: Dict[str, Set[ats.Endpoint]] = defaultdict(set)
	c_ep_implicit: Dict[str, Set[ats.Endpoint]] = defaultdict(set)
	c_d_explicit: Dict[str, Set[str]] = defaultdict(set)
	c_d_implicit: Dict[str, Set[str]] = defaultdict(set)

	for app, endpoints in e.app_endpoints.items():

		for name, value in [
			("Arbitrary", app.ats_configuration.arbitrary),
			("Arbitrary (Media)", app.ats_configuration.arbitrary_media),
			("Arbitrary (Web)", app.ats_configuration.arbitrary_web),
		]:
			if value is None:
				name = name + " False"
				c_app_implicit[name].add(app)
			else:
				name = name + f" {value}"
				c_app_explicit[name].add(app)

		if app.ats_configuration.requires_justification:
			c_app_explicit["Requires justification"].add(app)

		for endpoint in endpoints:

			if not (endpoint.is_relevant and endpoint in e.diagnostics.succeeding.endpoints):
				continue

			domain, configured = app.ats_configuration[endpoint]
			host, diagnosed = e.diagnostics.succeeding.configurations[endpoint].get(endpoint.host)

			if domain is None:
				num_implicit_cfgs += 1
				implicit_endpoints.add(endpoint)
				implicit_domains.add(endpoint.host)
			else:
				num_explicit_cfgs += 1
				explicit_endpoints.add(endpoint)
				explicit_domains.add(domain)

			explicit = ats.Improvement(0)
			implicit = ats.Improvement(0)
			if diagnosed is not None:

				if configured is not None:
					explicit, implicit = configured.compare_to_diagnosed(diagnosed)
				else:
					assert app.ats_configuration.any_arbitrary
					# No exception for endpoint: anything goes
					# Hence, the diagnosed configuration is compared to the
					# least secure configuration. Since the configuration was
					# not actually read from file, all improvements are implicit.
					least_secure = ats.ActualDomainConfiguration.least_secure()
					implicit, _ = least_secure.compare_to_diagnosed(diagnosed)

			# Normalize
			if endpoint.uses_tls:
				explicit = explicit.https
				implicit = implicit.https
			else:
				explicit = explicit.http
				implicit = implicit.http

			if configured:
				for name_true, name_false, value, default in [
					("HTTP allowed", "HTTP prohibited", configured.http, False),
					("FS required", "FS optional", configured.fs, True),
					("CT required", "CT optional", configured.ct, False),
				]:
					if value is not None:
						name = name_true if value else name_false
						c_app_explicit[name].add(app)
						c_ep_explicit[name].add(endpoint)
						c_d_explicit[name].add(domain if domain else endpoint.host)
					if value is None:
						name = name_true if default else name_false
						c_app_implicit[name].add(app)
						c_ep_implicit[name].add(endpoint)
						c_d_implicit[name].add(domain if domain else endpoint.host)
				if tls := configured.tls:
					name = f"Min {tls}"
					c_app_explicit[name].add(app)
					c_ep_explicit[name].add(endpoint)
					c_d_explicit[name].add(domain if domain else endpoint.host)
				if configured.tls is None:
					name = f"Min {ats.TlsVersion.TLSv1_2}"
					c_app_implicit[name].add(app)
					c_ep_implicit[name].add(endpoint)
					c_d_implicit[name].add(domain if domain else endpoint.host)
				if configured.requires_justification:
					name = "Requires justification"
					c_ep_explicit[name].add(endpoint)
					c_d_explicit[name].add(domain if domain else endpoint.host)
			else:
				assert app.ats_configuration.any_arbitrary
				name = "Arbitrary w/o exception"
				c_app_implicit[name].add(app)
				c_ep_implicit[name].add(endpoint)
				c_d_implicit[name].add(domain if domain else endpoint.host)

			for improvement in ats.Improvement:
				if improvement in implicit:
					app_can_improve_implicit[improvement].add(app)
					ep_can_improve_implicit[improvement].add(endpoint)
					d_can_improve_implicit[improvement].add(domain if domain else endpoint.host)
				if improvement in explicit:
					app_can_improve_explicit[improvement].add(app)
					ep_can_improve_explicit[improvement].add(endpoint)
					d_can_improve_explicit[improvement].add(domain if domain else endpoint.host)

	table = Table()

	# Applications
	keys = sorted(set(c_app_explicit.keys()).union(c_app_implicit.keys()))
	grp = table.add_group("Applications", len(e.dataset.apps), "Explicit")
	for key in keys:
		table.add_row(grp, key, len(c_app_explicit[key]), "Explicit")
	for improvement in ats.Improvement.explicit():
		table.add_row(grp, str(improvement), len(app_can_improve_explicit[improvement]), "Explicit")
	grp = table.add_group(grp, len(e.dataset.apps), "Implicit")
	for key in keys:
		table.add_row(grp, key, len(c_app_implicit[key]), "Implicit")
	for improvement in ats.Improvement.implicit():
		table.add_row(grp, str(improvement), len(app_can_improve_implicit[improvement]), "Implicit")

	# Endpoints
	keys = sorted(set(c_ep_explicit.keys()).union(c_ep_implicit.keys()))
	grp = table.add_group("Endpoints", len(explicit_endpoints), "Explicit")
	for key in keys:
		table.add_row(grp, key, len(c_ep_explicit[key]), "Explicit")
	for improvement in ats.Improvement.explicit():
		table.add_row(grp, str(improvement), len(ep_can_improve_explicit[improvement]), "Explicit")
	grp = table.add_group(grp, len(implicit_endpoints), "Implicit")
	for key in keys:
		table.add_row(grp, key, len(c_ep_implicit[key]), "Implicit")
	for improvement in ats.Improvement.implicit():
		table.add_row(grp, str(improvement), len(ep_can_improve_implicit[improvement]), "Implicit")

	# Domains
	keys = sorted(set(c_d_explicit.keys()).union(c_d_implicit.keys()))
	grp = table.add_group("Domains", len(explicit_domains), "Explicit")
	for key in keys:
		table.add_row(grp, key, len(c_d_explicit[key]), "Explicit")
	for improvement in ats.Improvement.explicit():
		table.add_row(grp, str(improvement), len(d_can_improve_explicit[improvement]), "Explicit")
	grp = table.add_group(grp, len(implicit_domains), "Implicit")
	for key in keys:
		table.add_row(grp, key, len(c_d_implicit[key]), "Implicit")
	for improvement in ats.Improvement.implicit():
		table.add_row(grp, str(improvement), len(d_can_improve_implicit[improvement]), "Implicit")

	table.display()
	return


@cli.command()
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_diagnostics(diagnostics_dir: str):
	diagnostics_path = Path(diagnostics_dir)

	diagnostics = DiagnosticResults.parse(diagnostics_path)
	succeeding = diagnostics.succeeding
	failing = diagnostics.failing

	# Output results
	click.secho(
		f"Results from {diagnostics.date_range[0]} – {diagnostics.date_range[1]}",
		fg='blue',
		bold=True,
	)

	table = Table()

	endpoint_statistics(succeeding.endpoints, table, "Succeeding")
	redirection_statistics(succeeding, table, "Succeeding")
	configuration_statistics(
		list(succeeding.configurations.values()),
		table,
		"Succeeding",
	)

	endpoint_statistics(failing.endpoints, table, "Failing")
	redirection_statistics(failing, table, "Failing")
	configuration_statistics(
		list(failing.configurations.values()),
		table,
		"Failing",
	)

	failure_statistics(failing, table, "Failing")

	table.display()


@cli.command()
@click.argument(
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True, writable=True),
)
def print_endpoints(maap_dir: str):
	dataset = maap.Dataset.from_path(Path(maap_dir), all_versions=True)

	for app in tqdm(dataset.apps, unit='app', file=sys.stderr):
		tqdm.write(str(app), file=sys.stderr)
		for endpoint in app.endpoints:
			if endpoint.is_relevant:
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
