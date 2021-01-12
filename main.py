import json
import plistlib
import subprocess
import sys

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from functools import cached_property
from pathlib import Path
from time import sleep
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple

import click

from natsort import natsorted
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

			#click.secho(entry.stem, dim=True)

			lines = entry.read_text().splitlines(keepends=False)
			for line in lines:
				d: Dict[str, Any] = json.loads(line)
				diagnostics = ats.Diagnostics.from_dict(d)
				diagnostic_results[diagnostics.endpoint] = diagnostics

		return cls(diagnostic_results)


@dataclass(frozen=True)
class AppResults:
	configurations: Dict[str, ats.Configuration]
	versions: Dict[str, str]
	endpoints_from_binary: Dict[str, Set[ats.Endpoint]]
	endpoints_from_ats: Dict[str, Set[ats.Endpoint]]

	@property
	def bundle_ids(self) -> Set[str]:
		return set(self.versions.keys())

	@cached_property
	def endpoints(self) -> Dict[str, Set[ats.Endpoint]]:
		return {
			bundle_id: self.endpoints_from_binary[bundle_id].union(
				self.endpoints_from_ats[bundle_id]
			)
			for bundle_id in self.bundle_ids
		}

	@classmethod
	def parse(cls, maap_path: Path) -> 'AppResults':
		configurations: Dict[str, ats.Configuration] = dict()
		versions: Dict[str, str] = dict()
		endpoints_from_binary: Dict[str, Set[ats.Endpoint]] = defaultdict(set)
		endpoints_from_ats: Dict[str, Set[ats.Endpoint]] = defaultdict(set)

		for path, bundle_id, version_id in maap_walk(maap_path):
			versions[bundle_id] = version_id

			#click.secho(f"{bundle_id} / {version_id}", dim=True)

			info_path = path / 'Info.plist'
			endpoints_path = path / 'endpoints.json'

			# Parse ATS configuration
			if info_path.exists():
				with info_path.open('rb') as f:
					info: Dict[str, Any] = plistlib.load(f)

				configuration: ats.Configuration
				if ats_dict := info.get('NSAppTransportSecurity', None):
					configuration = ats.Configuration.from_info_plist(ats_dict)
				else:
					# If there is no explicit ATS configuration, the default
					# configuration applies.
					configuration = ats.Configuration()

				configurations[bundle_id] = configuration

			# Parse endpoints
			if endpoints_path.exists():
				with endpoints_path.open('rb') as f:
					endpoints_dict: Dict[str, List[str]] = json.load(f)
				if urls := endpoints_dict.get('executable', list()):
					for url in urls:
						endpoint = ats.Endpoint.from_url(url)
						assert endpoint is not None, f"Invalid endpoint: {url}"
						endpoints_from_binary[bundle_id].add(endpoint)
				if urls := endpoints_dict.get('ats', list()):
					for url in urls:
						endpoint = ats.Endpoint.from_url(url)
						assert endpoint is not None, f"Invalid endpoint: {url}"
						endpoints_from_ats[bundle_id].add(endpoint)

		return cls(
			configurations=configurations,
			versions=versions,
			endpoints_from_binary=endpoints_from_binary,
			endpoints_from_ats=endpoints_from_ats,
		)


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


def maap_walk(
	maap_path: Path,
	include_all_versions: bool = False,
) -> Iterator[Tuple[Path, str, str]]:
	ignored = {'.DS_Store', 'b.UNKNOWN'}

	for maap_bundle in maap_path.iterdir():
		if not maap_bundle.is_dir() or maap_bundle.name in ignored:
			continue

		bundle_id = maap_bundle.name

		version_ids = natsorted([
			maap_version.name
			for maap_version in maap_bundle.iterdir()
			if maap_version.is_dir()
		])
		if not version_ids:
			continue

		if include_all_versions:
			for version_id in version_ids:
				yield (maap_path / bundle_id / version_id, bundle_id, version_id)
		else:
			version_id = version_ids[-1]
			yield (maap_path / bundle_id / version_id, bundle_id, version_id)


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

	if endpoint.is_ip:
		click.secho(f"Endpoint is not affected by ATS: {endpoint}", fg='red', err=True)
		exit(1)

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
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
@click.argument(
	'output_dir',
	type=click.Path(file_okay=False, dir_okay=True, readable=True, writable=True),
	required=True,
)
@click.pass_obj
def collect_diagnostics(ctx: Context, maap_dir: str, output_dir: str):
	maap_path = Path(maap_dir)
	output_path = Path(output_dir)

	app_results = AppResults.parse(maap_path)

	output_path.mkdir(parents=True, exist_ok=True)

	pending: Set[ats.Endpoint] = set()
	upgraded: Set[ats.Endpoint] = set()
	for bundle_id, bundle_endpoints in app_results.endpoints.items():
		for endpoint in bundle_endpoints:
			pending.add(endpoint)
			with_tls = endpoint.with_tls
			if not endpoint.uses_tls and not with_tls in app_results.endpoints.values():
				pending.add(with_tls)
				upgraded.add(with_tls)
	finished: Dict[ats.Endpoint, ats.Diagnostics] = dict()
	skipped: Set[ats.Endpoint] = set()

	# XXX
	#pending = {ats.Endpoint(uses_tls=True, host='goo.gl', port=443)}
	#upgraded = set()

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

			if endpoint.is_ip:
				log_special("  → ", nl=False)
				log_warn("Not affected by ATS, skipping.")
				progress.update()
				skipped.add(endpoint)
				continue

			if endpoint.is_local:
				log_special("  → ", nl=False)
				log_warn("Local domain, skipping.")
				progress.update()
				skipped.add(endpoint)
				continue

			# TODO Append diagnostics, if old results are old enough or if old
			# result is erroneous and current is not.
			if path.exists():
				parsed: List[ats.Diagnostics] = []
				lines = path.read_text().splitlines(keepends=False)
				for line in lines:
					d: Dict[str, Any] = json.loads(line)
					parsed.append(ats.Diagnostics.from_dict(d))
				existing = DiagnosticResults({x.endpoint: x for x in parsed})
				if endpoint in existing.succeeding.endpoints:
					log_special("  → ", nl=False)
					log_warn("Result already exists, skipping.")
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
		successful_upgrades = upgraded - failing
		#failing_upgrades = upgraded.intersection(failing)
		click.secho("Upgrades: ", bold=True, err=True)
		for endpoint in sorted(upgraded):
			if endpoint in successful_upgrades:
				fg = 'blue'
			elif endpoint in skipped:
				fg = 'yellow'
			elif endpoint in failing:
				fg = 'red'
			else:
				fg = None
			click.secho(f"  {endpoint}", fg=fg, err=True)


@cli.command()
@click.argument(
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True, writable=True),
)
def extract_endpoints(maap_dir: str):
	apps: List[Tuple[Path, str, str]] = list(maap_walk(Path(maap_dir)))
	endpoints: Set[ats.Endpoint] = set()

	with tqdm(apps, unit="app", file=sys.stderr, leave=True) as progress:
		for path, bundle_id, version_id in progress:
			tqdm_log(progress, f"{bundle_id} / {version_id}")

			endpoints_path = path / 'endpoints.json'

			# Skip existing
			if endpoints_path.exists():
				tqdm_log(progress, click.style("\tskipped", fg='yellow'))
				continue

			def log_error(msg: str, nl: bool = True):
				tqdm_log(progress, "\t" + click.style(msg, fg='red'))

			endpoints_from_binary: Set[ats.Endpoint] = set()
			endpoints_from_ats: Set[ats.Endpoint] = set()

			binary_path = path / 'executable.bin'
			if binary_path.exists():
				strings = subprocess.run(
					['strings', '-', '-a', str(binary_path)],
					check=True,
					capture_output=True,
					text=True,
				)
				lines = strings.stdout.splitlines(keepends=False)
				endpoints_from_binary = {
					endpoint
					for line in lines
					for endpoint in ats.Endpoint.find_instances(line, log_error)
				}

			info_path = path / 'Info.plist'
			if info_path.exists():
				with info_path.open('rb') as f:
					info = plistlib.load(f)
				if ats_dict := info.get('NSAppTransportSecurity', None):

					# Extract valid domains
					configuration = ats.Configuration.from_info_plist(ats_dict)
					for domain, exception in configuration.exceptions.items():
						endpoint = ats.Endpoint.from_url(f'https://{domain}')
						assert endpoint is not None
						endpoints_from_ats.add(endpoint)
						if exception.includes_subdomains:
							endpoint = ats.Endpoint.from_url(f'http://{domain}')
							assert endpoint is not None
							endpoints_from_ats.add(endpoint)

					# Report invalid domains
					exception_domains: Dict[str, Any] = ats_dict.get('NSExceptionDomains', dict())
					for domain in exception_domains.keys():
						if ats.Endpoint.from_url(f'https://{domain}/') is None:
							log_error(f"Unexpected endpoint: {domain}")

			result = {
				'executable': [str(endpoint) for endpoint in sorted(endpoints_from_binary)],
				'ats': [str(endpoint) for endpoint in sorted(endpoints_from_ats)],
			}
			with endpoints_path.open('w') as f:
				json.dump(result, f, indent=2)

			endpoints_bundle = endpoints_from_binary.union(endpoints_from_ats)
			tqdm_log(progress, click.style(f"\tFound {len(endpoints_bundle):5d} unique endpoints.", fg='green'))
			tqdm_log(progress, click.style(f"\t      {pp(len(endpoints_from_binary), len(endpoints_bundle))} in executable", fg='green'))
			tqdm_log(progress, click.style(f"\t      {pp(len(endpoints_from_ats), len(endpoints_bundle))} in ATS configuration", fg='green'))

			endpoints = endpoints.union(endpoints_bundle)

	click.secho(f"Found {len(endpoints)} unique endpoints in total.", fg='green')


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
	diagnostics = DiagnosticResults.parse(Path(diagnostics_dir))
	app_results = AppResults.parse(Path(maap_dir))

	click.secho(f"Apps: {len(app_results.configurations)}", fg='blue', bold=True)
	click.secho(
		f"Diagnostics from {diagnostics.date_range[0]} – {diagnostics.date_range[1]}",
		fg='blue',
		bold=True,
	)

	# Basic overview of both data sources
	app_endpoints = {
		endpoint
		for endpoints in app_results.endpoints.values()
		for endpoint in endpoints
	}
	app_configurations = list(app_results.configurations.values())
	d_configurations = list(diagnostics.configurations.values())

	table = Table()

	endpoint_statistics(app_endpoints, table, column="App")
	endpoint_statistics(diagnostics.endpoints, table, column="Diagnostics")

	configuration_statistics(app_configurations, table, column="App")
	configuration_statistics(d_configurations, table, column="Diagnostics")

	redirection_statistics(diagnostics, table, column="Diagnostics")

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
