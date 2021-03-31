import json
import pickle
import sys

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import cached_property, partial
from pathlib import Path
from time import sleep
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, TypeVar

import click
import lief
import matplotlib
import matplotlib.pyplot as plt

from matplotlib.patches import Patch
from natsort import natsorted
from tqdm import tqdm
from tqdm._utils import _term_move_up as term_move_up

import ats
import exodus
import maap

from maap import App
from utilities import (
	CodesigningIdentity,
	PlistSanitizer,
	State,
	Utility,
)
from tests import TestEnvironment


T = TypeVar('T')


_tqdm_buf = ''


# Setup plots
matplotlib.rcParams['text.usetex'] = True
matplotlib.rcParams['text.latex.preamble'] = r'''
	\usepackage[tt=false,type1=true]{libertine}
	\usepackage[libertine]{newtxmath}
	\usepackage{inconsolata}
'''


class Tomorrow:
	base00 = '#ffffff'
	base01 = '#e0e0e0'
	base02 = '#d6d6d6'
	base03 = '#8e908c'
	base04 = '#969896'
	base05 = '#4d4d4c'
	base06 = '#282a2e'
	base07 = '#1d1f21'
	base08 = '#c82829'  # red
	base09 = '#f5871f'  # orange
	base0A = '#eab700'  # yellow
	base0B = '#718c00'  # green
	base0C = '#3e999f'  # turqoise
	base0D = '#4271ae'  # blue
	base0E = '#8959a8'  # purple
	base0F = '#a3685a'  # brown


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


def month_marker(value: datetime) -> str:
	date = value.date()
	return f"{date.year:4d}-{date.month:02d}"


def cumulate_sets(values: Dict[str, Set[T]], keys: List[str]) -> Dict[str, Set[T]]:
	results: Dict[str, Set[T]] = dict()
	previous: Set[T] = set()
	for key in keys:
		current = values.get(key, set())
		results[key] = previous.union(current)
		previous = results[key]
	return results


def percentages(values: List[int], totals: List[int]) -> List[float]:
	assert len(values) == len(totals)
	return [percentage(value, total) for value, total in zip(values, totals)]


def dmap(
	func: Callable[[T, T], T],
	lhs: Dict[str, T],
	rhs: Dict[str, T],
	default: Callable[[], T],
) -> Dict[str, T]:
	return {
		key: func(lhs.get(key, default()), rhs.get(key, default()))
		for key in set(lhs.keys()).union(rhs.keys())
	}


def dmap_set(
	func: Callable[[Set[T], Set[T]], Set[T]],
	lhs: Dict[str, Set[T]],
	rhs: Dict[str, Set[T]],
) -> Dict[str, Set[T]]:
	return dmap(func, lhs, rhs, default=set)


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
	column: str = '',
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
#	t_to_http = [
#		path
#		for path in diagnostics.transitive_redirections
#		if path[0].uses_tls and not path[-1].uses_tls
#	]
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

	grp = table.add_group("Direct Redirections", len(diagnostics.redirections), column)
	table.add_row(grp, "HTTP -> HTTPS", len(to_https), column)
	table.add_row(grp, "HTTP -> HTTPS (same host)", len(https_upgrade), column)
	table.add_row(grp, "HTTPS -> HTTP", len(to_http), column)

	contains_https_to_http = len(diagnostics.transitive_redirections) - len(pure_https) - len(pure_http) - len(http_prefix)

	grp = table.add_group("Transitive redirections", len(diagnostics.transitive_redirections), column)
	table.add_row(grp, "pure HTTPS", len(pure_https), column)
	table.add_row(grp, "HTTP -> HTTPS (upgrade only)", len(http_prefix), column)
	table.add_row(grp, "contains HTTPS -> HTTP", contains_https_to_http, column)
	table.add_row(grp, "pure HTTP", len(pure_http), column)
	#table.add_row(grp, "HTTP -> HTTPS", len(t_to_https), column)
	#table.add_row(grp, "HTTPS -> HTTP", len(t_to_http), column)


def configuration_statistics(
	configurations: Dict[ats.Endpoint, ats.Configuration],
	table: Table,
	column: str = ''
):
	global_requires_justification = 0
	global_non_default = 0
	arbitrary = 0

	for configuration in configurations.values():
		if configuration.requires_justification:
			global_requires_justification += 1
		if not configuration.is_default:
			global_non_default += 1
		if configuration.arbitrary_loads:
			arbitrary += 1

	grp = table.add_group("Configurations", len(configurations), column)
	table.add_row(grp, "non-default", global_non_default, column)
	table.add_row(grp, "requires justification", global_requires_justification, column)
	table.add_row(grp, "arbitrary loads", arbitrary, column)

	domain_configurations: Dict[ats.Endpoint, ats.DomainConfiguration] = {
		endpoint: configuration.exceptions[endpoint.host]
		for endpoint, configuration in configurations.items()
	}

	unencrypted = 0
	encrypted = 0

	default = 0
	most_secure = 0
	more_secure = 0
	less_secure = 0
	encrypted_less_secure = 0
	mixed = 0
	requires_justification = 0
	encrypted_justify = 0
	http = 0
	fs: Set[ats.Endpoint] = set()
	ct: Set[ats.Endpoint] = set()
	hsts = 0
	tls: Dict[ats.TlsVersion, Set[ats.Endpoint]] = defaultdict(set)
	for endpoint, cfg in domain_configurations.items():
		if cfg.is_default:
			default += 1
		if cfg.requires_justification:
			requires_justification += 1

		if endpoint.uses_tls:
			encrypted += 1
			if cfg < ats.DomainConfiguration():
				less_secure += 1
				encrypted_less_secure += 1
			if cfg.forward_secrecy:
				fs.add(endpoint)
			if cfg.certificate_transparency:
				ct.add(endpoint)
			tls[cfg.tls_version].add(endpoint)
			if not (cfg < ats.DomainConfiguration() or ats.DomainConfiguration() < cfg):
				mixed += 1
			if cfg.requires_justification:
				encrypted_justify += 1
			if cfg == ats.DomainConfiguration.most_secure():
				most_secure += 1
			if ats.DomainConfiguration() < cfg:
				more_secure += 1
		else:
			unencrypted += 1
			if cfg.insecure_http_loads:
				less_secure += 1
				http += 1
			else:
				hsts += 1

	total = encrypted + unencrypted
	non_default = total - default

	grp = table.add_group("Domain configurations (all)", total, column)
	table.add_row(grp, "default", default, column)
	table.add_row(grp, "non-default", non_default, column)
	table.add_row(grp, "most-secure", most_secure, column)
	table.add_row(grp, "better than default", more_secure, column)
	table.add_row(grp, "worse than default", less_secure, column)
	table.add_row(grp, "mixed", mixed, column)
	table.add_row(grp, "requires justification", requires_justification, column)

	grp = table.add_group("Domain configurations (HTTP)", unencrypted, column)
	table.add_row(grp, "HTTP", http, column)
	table.add_row(grp, "HSTS", hsts, column)

	grp = table.add_group("Domain configurations (HTTPS)", encrypted, column)
	table.add_row(grp, "FS", len(fs), column)
	table.add_row(grp, "CT", len(ct), column)
	for tls_version in ats.TlsVersion:
		table.add_row(grp, str(tls_version), len(tls[tls_version]), column)
	table.add_row(grp, "Most secure", most_secure, column)
	table.add_row(grp, "Default", default, column)
	table.add_row(grp, "better than default", more_secure, column)
	table.add_row(grp, "worse than default", encrypted_less_secure, column)
	table.add_row(grp, "mixed", mixed, column)
	table.add_row(grp, "Requires justification", encrypted_justify, column)


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


def plot_ats_history(
	markers: List[str],
	data: List[Tuple[str, List[float], List[float], str]],
	ylabel: str,
):
	fig, ax = plt.subplots()

	series: List[str] = []
	plots: Dict[str, List[plt.Line2D]] = dict()

	for title, perc, error, color in data:
		plots[title] = plt.plot(markers, perc, color=color, alpha=.75)
		series.append(title)
		if error:
			assert len(error) == len(perc)
			ax.fill_between(
				markers,
				[min(p + e, 100) for p, e in zip(perc, error)],
				[max(p - e, 0) for p, e in zip(perc, error)],
				color=color,
				alpha=.1,
			)

	# Mark ATS-specific dates
	plt.axvline(
		x=month_marker(ats.INTRODUCED_ON),
		linewidth=1,
		color=Tomorrow.base0B,
	)
	plt.axvline(
		x=month_marker(ats.JUSTIFICATIONS_REQUIRED_SINCE),
		linewidth=1,
		color=Tomorrow.base08,
	)

	# X axis
	major_labels = [
		marker
		for marker in markers
		if marker.endswith('-06') or marker.endswith('-12')
	]
	plt.xticks(major_labels, rotation=30, ha='right')

	# Y axis
	ax.yaxis.set_label_position("right")
	ax.yaxis.tick_right()
	plt.ylabel(ylabel)

	# Legend
	plt.legend((plots[t][0] for t in series), series)

	# Layout
	ax.margins(x=0.01)
	plt.tight_layout()

	plt.show()


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
	'output_dir',
	type=click.Path(file_okay=False, dir_okay=True, readable=True, writable=True),
	required=True,
)
@click.argument(
	'urls_file',
	type=click.Path(dir_okay=False, file_okay=True, readable=True),
	nargs=-1,
	required=True,
)
@click.pass_obj
def collect_diagnostics(
	ctx: Context,
	upgrade_scheme: bool,
	output_dir: str,
	urls_file: Tuple[str, ...],
):
	ignored = {
		# Crashes `atsprobe` utility
		'www.sno.phy.queensu.ca',
		'microwaveformac.com',
		'mymovies.dk',
		# Time out
		'blog.codeobsession.com',
	}

	output_path = Path(output_dir)
	output_path.mkdir(parents=True, exist_ok=True)

	pending: Set[ats.Endpoint] = set()
	finished: Dict[ats.Endpoint, ats.Diagnostics] = dict()
	skipped: Set[ats.Endpoint] = set()
	upgraded: Set[ats.Endpoint] = set()

	# Parse URLs
	for path in [Path(fn) for fn in urls_file]:
		for idx, url in enumerate(path.read_text().splitlines(keepends=False)):
			if endpoint := ats.Endpoint.from_url(url):
				if not endpoint.is_relevant:
					click.secho(f"Skipping irrelevant endpoint in '{path}': {url}")
					continue
				pending.add(endpoint)
			else:
				click.secho(f"Invalid endpoint in '{path}' at line {idx}: {url}", fg='red', err=True)
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
		unit='URL',
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

			if any([
				endpoint.host == domain or ats.is_subdomain(endpoint.host, domain)
				for domain in ignored
			]):
				log_special("  → ", nl=False)
				log_warn("Result is ignored, skipping.")
				progress.update()
				skipped.add(endpoint)
				continue

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
@click.option(
	'--verbose',
	is_flag=True,
	default=False,
	show_default=True,
)
@click.option(
	'--cache/--no-cache',
	'use_cached',
	default=True,
	show_default=True,
)
@click.option(
	'--mode',
	type=click.Choice({'configurations', 'support'}),
	required=True,
)
@click.argument(
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_history(
	verbose: bool,
	use_cached: bool,
	mode: str,
	maap_dir: str,
):
	maap_path = Path(maap_dir)

	apps: Dict[str, Set[str]] = defaultdict(set)
	apps_with_network_access: Dict[str, Set[str]] = defaultdict(set)
	apps_with_ats_support: Dict[str, Set[str]] = defaultdict(set)
	apps_without_ats_support: Dict[str, Set[str]] = defaultdict(set)
	apps_with_ats_disabled: Dict[str, Set[str]] = defaultdict(set)
	apps_with_ats_explicit: Dict[str, Set[str]] = defaultdict(set)
	apps_with_ats_justify: Dict[str, Set[str]] = defaultdict(set)
	apps_with_ats_default: Dict[str, Set[str]] = defaultdict(set)

	cache: Dict[str, Tuple[
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
		Dict[str, Set[str]],
	]] = dict()
	cache_path = Path('evaluate_history.pickle')
	cache_key = str(maap_path.absolute())
	use_cached &= cache_path.exists()
	if use_cached:
		click.secho(f"Loading cache from '{cache_path}'... ", dim=True, err=True, nl=False)
		with cache_path.open('rb') as f:
			cache = pickle.load(f)

		if cache_key in cache:
			(
				apps,
				apps_with_network_access,
				apps_with_ats_support,
				apps_without_ats_support,
				apps_with_ats_disabled,
				apps_with_ats_explicit,
				apps_with_ats_justify,
				apps_with_ats_default,
			) = cache[cache_key]
			click.secho("✓", fg='green', dim=True, err=True)
		else:
			use_cached = False
			click.secho("×", fg='red', dim=True, err=True)

	if not use_cached:
		# Takes about 10 minutes for MAS dataset

		def matches_criteria(app: App) -> bool:
			return all([
				app.info_path.exists(),
				app.binary_path.exists(),
				app.metadata_path.exists(),
			])
		maap_apps = list(maap.walk(maap_path, matches_criteria))

		# Count
		for app in tqdm(maap_apps, unit='app', leave=True):
			# Only analyze apps, where the required information is present
			assert app.info_path.exists()
			assert app.binary_path.exists()
			assert app.metadata_path.exists()

			if verbose:
				tqdm.write(click.style(f"{app}", dim=True))

			initial = app.metadata.release_date
			if initial is None:
				continue
			assert maap.MAS_SUBMISSIONS_SINCE <= initial
			initial = max(initial, maap.MAS_SINCE)  # Normalize

			marker = month_marker(initial)

			apps[marker].add(app.bundle_id)

			current = app.current_version_release_date
			assert current is not None
			assert maap.MAS_SUBMISSIONS_SINCE <= initial
			current = max(current, maap.MAS_SINCE)  # Normalize

			marker = month_marker(current)

			if app.can_access_network:
				apps_with_network_access[marker].add(app.bundle_id)

			configuration = app.ats_configuration
			if app.supports_ats is not None:
				if app.supports_ats:
					apps_with_ats_support[marker].add(app.bundle_id)

					if configuration.is_default:
						apps_with_ats_default[marker].add(app.bundle_id)
				else:
					apps_without_ats_support[marker].add(app.bundle_id)

			if app.ats_dict is not None:
				apps_with_ats_explicit[marker].add(app.bundle_id)

			if configuration.is_disabled:
				apps_with_ats_disabled[marker].add(app.bundle_id)

			if configuration.requires_justification:
				apps_with_ats_justify[marker].add(app.bundle_id)

		cache[cache_key] = (
			apps,
			apps_with_network_access,
			apps_with_ats_support,
			apps_without_ats_support,
			apps_with_ats_disabled,
			apps_with_ats_explicit,
			apps_with_ats_justify,
			apps_with_ats_default,
		)
		with cache_path.open('wb') as f:
			pickle.dump(cache, f)
		click.secho(f"Cached in '{cache_path}'", dim=True, err=True)

	markers: List[str] = [
		f"{year:4d}-{month:02d}"
		for year in range(maap.MAS_SINCE.date().year, 2019)
		for month in range(1, 13)
	]
	# MAS accepts submissions since 2010-11
	#markers = markers[10:]

	# Dataset only contains apps until Sep. 2018
	markers = markers[:-3]

	# Cumulate
	apps = cumulate_sets(apps, markers)
	apps_with_network_access = cumulate_sets(apps_with_network_access, markers)
	apps_with_ats_support = cumulate_sets(apps_with_ats_support, markers)
	apps_without_ats_support = cumulate_sets(apps_without_ats_support, markers)
	apps_with_ats_disabled = cumulate_sets(apps_with_ats_disabled, markers)
	apps_with_ats_explicit = cumulate_sets(apps_with_ats_explicit, markers)
	apps_with_ats_justify = cumulate_sets(apps_with_ats_justify, markers)
	apps_with_ats_default = cumulate_sets(apps_with_ats_default, markers)

	# Normalize
	for marker in markers:
		if month_marker(ats.INTRODUCED_ON) <= marker:
			break
		apps_without_ats_support[marker] = apps[marker]

	def count(source: Dict[str, Set[Any]]) -> List[int]:
		return [len(source.get(marker, set())) for marker in markers]

	def intersect(lhs: Dict[str, Set[T]], rhs: Dict[str, Set[T]]) -> Dict[str, Set[T]]:
		return dmap_set(set.intersection, lhs, rhs)

	base = intersect(apps_with_network_access, apps_with_ats_support)
	num_base = count(base)

	if mode == 'configurations':
		# Normalize
		apps_with_ats_disabled = intersect(base, apps_with_ats_disabled)
		apps_with_ats_explicit = intersect(base, apps_with_ats_explicit)
		apps_with_ats_justify = intersect(base, apps_with_ats_justify)
		apps_with_ats_default = intersect(base, apps_with_ats_default)

		num_disabled = count(apps_with_ats_disabled)
		num_explicit = count(apps_with_ats_explicit)
		num_justify = count(apps_with_ats_justify)
		num_default = count(apps_with_ats_default)

		# Write values to terminal
		for idx, marker in enumerate(markers):
			if 0 == num_base[idx]:
				continue
			table = Table()
			grp = table.add_group(marker, num_base[idx])
			table.add_row(grp, "Disabled", num_disabled[idx])
			table.add_row(grp, "Explicit", num_explicit[idx])
			table.add_row(grp, "Justify", num_justify[idx])
			table.add_row(grp, "Default", num_default[idx])
			table.display()

		# Plot
		plot_ats_history(
			markers=markers,
			data=[(
				"disabled",
				percentages(num_disabled, num_base),
				[],
				Tomorrow.base09,
			), (
				"configured",
				percentages(num_explicit, num_base),
				[],
				Tomorrow.base0E,
			), (
				"requires justification",
				percentages(num_justify, num_base),
				[],
				Tomorrow.base0A,
			), (
				"default",
				percentages(num_default, num_base),
				[],
				Tomorrow.base0C,
			)],
			ylabel=r'\% of free apps with ATS support and network access',
		)

	elif mode == 'support':
		noats = intersect(apps_with_network_access, apps_without_ats_support)
		support_unknown = dmap_set(
			set.difference,
			apps,
			dmap_set(set.union, apps_with_ats_support, apps_without_ats_support)
		)

		num_apps = count(apps)
		num_network = count(apps_with_network_access)
		num_support = count(apps_with_ats_support)
		num_noats = count(noats)
		num_nosupport = count(apps_without_ats_support)
		num_support_unknown = count(support_unknown)

		ats_support_error = percentages(num_support_unknown, num_apps)

		# Write values to terminal
		for idx, marker in enumerate(markers):
			if 0 == num_apps[idx]:
				continue
			table = Table()
			grp = table.add_group(marker, num_apps[idx])
			table.add_row(grp, "Network access", num_network[idx])
			table.add_row(grp, "ATS support", num_support[idx])
			table.add_row(grp, "No ATS support", num_nosupport[idx])
			table.add_row(grp, "ATS support unknown", num_support_unknown[idx])
			table.add_row(grp, "Network access ∧ ATS support", num_base[idx])
			table.add_row(grp, "Network access ∧ no ATS support", num_noats[idx])
			table.display()

		# Plot
		plot_ats_history(
			markers=markers,
			data=[(
				"network access",
				percentages(num_network, num_apps),
				[],
				Tomorrow.base0E,
			), (
				"ATS support",
				percentages(num_support, num_apps),
				ats_support_error,
				Tomorrow.base0D,
			), (
				"no ATS support",
				percentages(num_nosupport, num_apps),
				ats_support_error,
				Tomorrow.base0A,
#			), (
#				"ATS support unknown",
#				ats_support_error,
#				[],
#				Tomorrow.base08,
			), (
				r"network access $\land$ ATS support",
				percentages(num_base, num_apps),
				ats_support_error,
				Tomorrow.base0C,
			), (
				r"network access $\land$ no ATS support",
				percentages(num_noats, num_apps),
				ats_support_error,
				Tomorrow.base09,
			)],
			ylabel=r'\% of free apps',
		)

	else:
		raise NotImplementedError(f"Unhandled mode: {mode}")


@cli.command()
@click.option(
	'--mas', 'mas_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	required=True,
)
@click.option(
	'--mu', 'mu_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	required=True,
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def compare_configurations(
	mas_dir: str,
	mu_dir: str,
	diagnostics_dir: str,
):
	def matches_criteria(app: App) -> bool:
		return app.info_path.exists()

	mas = maap.Dataset.from_path(Path(mas_dir), matches_criteria, latest=True)
	mu = maap.Dataset.from_path(Path(mu_dir), matches_criteria, latest=True)
	diagnostics = DiagnosticResults.parse(Path(diagnostics_dir))


	# Basic overview of both data sources
	click.secho(f"Diagnostics from {diagnostics.date_range[0]} – {diagnostics.date_range[1]}", fg='blue', bold=True)
	table = Table()
	endpoint_statistics(mas.endpoints, table, "MAS")
	endpoint_statistics(mu.endpoints, table, "MU")
	table.display()


def do_evaluate_configurations(
	maap_path: Path,
	diagnostics: DiagnosticResults,
	name: str,
	include_domain: Optional[Callable[[str], bool]] = None,
) -> Tuple[
	int,
	int,
	Dict[str, int],
	Dict[ats.Improvement, int],
	Dict[ats.Improvement, int],
	int,
	Dict[str, int],
	Dict[ats.Improvement, int],
	Dict[ats.Improvement, int],
]:
	assert diagnostics == diagnostics.succeeding

	if include_domain is None:
		def include_all(value: str) -> bool:
			return True
		include_domain = include_all
	assert include_domain is not None

	diagnosed_https: Dict[ats.Encrypted, Set[ats.Endpoint]] = defaultdict(set)
	for endpoint, dcfg in diagnostics.configurations.items():
		if not endpoint.uses_tls:
			continue
		cfg = dcfg.exceptions[endpoint.host]
		if cfg.forward_secrecy:
			diagnosed_https[ats.Encrypted.SupportsForwardSecrecy].add(endpoint)
		if cfg.certificate_transparency:
			diagnosed_https[ats.Encrypted.SupportsCertificateTransparency].add(endpoint)
		diagnosed_https[ats.Encrypted.for_tls_version(cfg.tls_version)].add(endpoint)

	def matches_criteria(app: App) -> bool:
		return app.info_path.exists()

	apps = list(maap.walk(maap_path, matches_criteria))

	per_app: Dict[str, Set[App]] = defaultdict(set)
	with_cfg: Set[App] = set()
	improvements_any_per_app: Dict[ats.Improvement, Set[App]] = defaultdict(set)
	improvements_all_per_app: Dict[ats.Improvement, Set[App]] = defaultdict(set)
	per_domain: Dict[str, Set[str]] = defaultdict(set)
	improvements_any_per_domain: Dict[ats.Improvement, Set[str]] = defaultdict(set)
	improvements_all_per_domain: Dict[ats.Improvement, Set[str]] = defaultdict(set)

	for app in tqdm(apps, unit="app", desc=name, leave=True):

		# Interesting endpoints for an application are all endpoints that were
		# found within that application, all transitive redirections found
		# during diagnosing each endpoint and the HTTPS-variants that might
		# HTTP -> HTTPS upgrades. All endpoints that could not be diagnosed are
		# ignored.
		app_endpoints: Set[ats.Endpoint] = set()
		for endpoint in app.endpoints:
			app_endpoints.add(endpoint)
			app_endpoints.add(endpoint.with_tls)
			current: Optional[ats.Endpoint] = endpoint
			current_path = [endpoint]
			while current := diagnostics.redirections.get(current, None):
				app_endpoints.add(current)
				app_endpoints.add(current.with_tls)
				if current in current_path:
					break  # Avoid redirection loops
				current_path.append(current)
		app_endpoints = app_endpoints.intersection(diagnostics.endpoints)

		if app.ats_dict is not None:
			with_cfg.add(app)

		configuration = app.ats_configuration

		if configuration.arbitrary is not None:
			per_app[f"arbitrary {configuration.arbitrary}"].add(app)

		if configuration.arbitrary_media is not None:
			per_app[f"arbitrary media {configuration.arbitrary_media}"].add(app)

		if configuration.arbitrary_web is not None:
			per_app[f"arbitrary web {configuration.arbitrary_web}"].add(app)

		if configuration.requires_justification:
			per_app["requires justificiation"].add(app)

		endpoints_for_domain: Dict[str, Set[ats.Endpoint]] = defaultdict(set)
		for domain, exception in configuration.exceptions.items():

			if not include_domain(domain):
				continue

			for key_prefix, value in [
				("includes subdomains", exception.includes_subdomains),
				("insecure HTTP", exception.http),
				("requires FS", exception.fs),
				("requires CT", exception.ct),
			]:
				if value is not None:
					key = f"{key_prefix} {value}"
					per_app[key].add(app)
					per_domain[key].add(domain)

			if exception.tls is not None:
				key = f"min {exception.tls}"
				per_app[key].add(app)
				per_domain[key].add(domain)

			if exception.requires_justification:
				per_domain["requires justification"].add(domain)

			for endpoint in app_endpoints:

				if not include_domain(endpoint.host):
					continue

				host = endpoint.host
				if domain == host or (
					exception.includes_subdomains and ats.is_subdomain(host, domain)
				):
					endpoints_for_domain[domain].add(endpoint)

		endpoint_improvements: Dict[
			ats.Improvement, Dict[str, Set[ats.Endpoint]]
		] = defaultdict(lambda: defaultdict(set))
		for endpoint in app_endpoints:

			if not include_domain(endpoint.host):
				continue

			domain, configured = app.ats_configuration[endpoint]
			h, diagnosed = diagnostics.configurations[endpoint].get(endpoint.host)

			if domain is None:
				# There is no explicit configuration affecting the endpoint
				# TODO Handle implicit improvements?
				continue

			if configured is None:
				assert app.ats_configuration.any_arbitrary
				# TODO Handle arbitrary loads?
				continue

			if diagnosed is None:
				continue

			explicit, implicit = configured.compare_to_diagnosed(diagnosed)
			improvements = explicit | implicit

			# Normalize
			improvements = improvements.https if endpoint.uses_tls else improvements.http

			for improvement in ats.Improvement:
				if improvement in improvements:
					endpoint_improvements[improvement][domain].add(endpoint)

			if not endpoint.uses_tls and endpoint.with_tls in diagnostics.endpoints:
				endpoint_improvements[ats.Improvement.CanDisableHTTP][domain].add(endpoint)

		for improvement in endpoint_improvements.keys():
			for domain, endpoints in endpoint_improvements[improvement].items():

				if 0 < len(endpoints):
					improvements_any_per_domain[improvement].add(domain)
					improvements_any_per_app[improvement].add(app)

				# Only look at all the domains affected by this improvement that
				# do not already support the parameter that can be improved.
				domain_endpoints = endpoints_for_domain[domain]
				if improvement is ats.Improvement.RemovesJustification:
					domain_endpoints -= {
						endpoint
						for endpoint in domain_endpoints
						if (
							configuration[endpoint][1] is not None and
							not configuration[endpoint][1].requires_justification
						)
					}
					if ats.Improvement.CanDisableHTTP in endpoint_improvements:
						domain_endpoints -= endpoint_improvements[ats.Improvement.CanDisableHTTP][domain]
				elif improvement.https != ats.Improvement(0):
					domain_endpoints = {e for e in domain_endpoints if e.uses_tls}
					if improvement is ats.Improvement.CanEnableFS:
						domain_endpoints -= {
							endpoint
							for endpoint in domain_endpoints
							if (
								configuration[endpoint][1] is not None and
								(
									configuration[endpoint][1].fs is None or
									configuration[endpoint][1].fs is True
								)
							)
						}
					if improvement is ats.Improvement.CanEnableCT:
						domain_endpoints -= {
							endpoint
							for endpoint in domain_endpoints
							if (
								configuration[endpoint][1] is not None and
								configuration[endpoint][1].ct is True
							)
						}
					if improvement is ats.Improvement.CanUpgradeTLS:
						domain_endpoints -= {
							endpoint
							for endpoint in domain_endpoints
							if (
								configuration[endpoint][1] is None and
								ats.TlsVersion.TLSv1_2 < configuration[endpoint][1].tls
							)
						}
				elif improvement.http != ats.Improvement(0):
					domain_endpoints = {e for e in domain_endpoints if not e.uses_tls}
				if endpoints == domain_endpoints:
					improvements_all_per_domain[improvement].add(domain)
					improvements_all_per_app[improvement].add(app)

	return (
		len(apps),
		len(with_cfg),
		{key: len(values) for key, values in per_app.items()},
		{key: len(values) for key, values in improvements_any_per_app.items()},
		{key: len(values) for key, values in improvements_all_per_app.items()},
		len(set.union(*per_domain.values())),
		{key: len(values) for key, values in per_domain.items()},
		{key: len(values) for key, values in improvements_any_per_domain.items()},
		{key: len(values) for key, values in improvements_all_per_domain.items()},
	)


@cli.command()
@click.option(
	'--per',
	type=click.Choice(['app', 'app-with-cfg', 'domain']),
	required=True,
)
@click.option(
	'--mas', 'mas_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	required=True,
)
@click.option(
	'--mu', 'mu_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	required=True,
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_configurations(
	per: str,
	mas_dir: str,
	mu_dir: str,
	diagnostics_dir: str,
):
	# TODO `--per app` or `--per app-with-cfg` do not make much sense, yet.
	# TODO Add `--per endpoint`?

	mas_path = Path(mas_dir)
	mu_path = Path(mu_dir)
	diagnostics_path = Path(diagnostics_dir)

	mas = 'MAS'
	mu = 'MU'

	apps: Dict[str, int] = dict()
	with_cfg: Dict[str, int] = dict()
	per_app: Dict[str, Dict[str, int]] = dict()
	improvements_any_per_app: Dict[str, Dict[ats.Improvement, int]] = dict()
	improvements_all_per_app: Dict[str, Dict[ats.Improvement, int]] = dict()

	domains: Dict[str, int] = dict()
	per_domain: Dict[str, Dict[str, int]] = dict()
	improvements_any_per_domain: Dict[str, Dict[ats.Improvement, int]] = dict()
	improvements_all_per_domain: Dict[str, Dict[ats.Improvement, int]] = dict()

	diagnostics: Optional[DiagnosticResults] = None

	cache: Dict[str, Tuple[
		int,
		int,
		Dict[str, int],
		Dict[ats.Improvement, int],
		Dict[ats.Improvement, int],
		int,
		Dict[str, int],
		Dict[ats.Improvement, int],
		Dict[ats.Improvement, int],
	]] = dict()
	cache_path = Path('evaluate_configurations.pickle')
	click.secho(f"Loading cache from '{cache_path}'... ", dim=True, err=True, nl=False)
	if cache_path.exists():
		with cache_path.open('rb') as f:
			cache = pickle.load(f)
		click.secho("✓", fg='green', dim=True, err=True)
	else:
		click.secho("×", fg='red', dim=True, err=True)

	for maap_path, name in [(mas_path, mas), (mu_path, mu)]:
		cache_key = str(maap_path.absolute())
		click.secho(f"Looking up {name} in cache... ", dim=True, err=True, nl=False)
		if cache_key in cache:
			(
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			) = cache[cache_key]
			click.secho("✓", fg='green', dim=True, err=True)
		else:
			click.secho("×", fg='red', dim=True, err=True)
			if diagnostics is None:
				diagnostics = DiagnosticResults.parse(diagnostics_path).succeeding
			assert diagnostics is not None
			(
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			) = do_evaluate_configurations(maap_path, diagnostics, name)
			cache[cache_key] = (
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			)
			with cache_path.open('wb') as f:
				pickle.dump(cache, f)
			click.secho(f"Cached in '{cache_path}'", dim=True, err=True)

	table = Table()

	keys = sorted(set.union(set(per_app[mas].keys()), set(per_app[mu].keys())))
	for dataset in [mas, mu]:
		for grp, base in [
			("Applications", apps[dataset]),
			("Applications with configuration", with_cfg[dataset]),
		]:
			table.add_group(grp, base, dataset)
			for key in keys:
				table.add_row(grp, key, per_app[dataset].get(key, 0), dataset)
			if grp == "Applications":
				table.add_row(grp, "with configuration", with_cfg[dataset], dataset)
			for improvement in ats.Improvement:
				table.add_row(
					grp,
					f"{improvement} (any)",
					improvements_any_per_app[dataset].get(improvement, 0),
					dataset,
				)
				table.add_row(
					grp,
					f"{improvement} (all)",
					improvements_all_per_app[dataset].get(improvement, 0),
					dataset,
				)

	keys = sorted(set.union(set(per_domain[mas].keys()), set(per_domain[mu].keys())))
	for dataset in [mas, mu]:
		grp = table.add_group("Configured exception domains", domains[dataset], dataset)
		for key in keys:
			table.add_row(grp, key, per_domain[dataset].get(key, 0), dataset)
		for improvement in ats.Improvement:
			table.add_row(
				grp,
				f"{improvement} (any)",
				improvements_any_per_domain[dataset].get(improvement, 0),
				dataset,
			)
			table.add_row(
				grp,
				f"{improvement} (all)",
				improvements_all_per_domain[dataset].get(improvement, 0),
				dataset,
			)

	table.display()

	# Plot
	is_per_app: bool = False
	totals: Dict[str, int]
	values: Dict[str, Dict[str, int]]
	improvements_any: Dict[str, Dict[ats.Improvement, int]]
	improvements_all: Dict[str, Dict[ats.Improvement, int]]
	ylabel: str
	if per == 'app':
		is_per_app = True
		totals = apps
		ylabel = r"\% of apps"
	elif per == 'app-with-cfg':
		is_per_app = True
		totals = with_cfg
		ylabel = r"\% of apps with explicit ATS configuration"
	elif per == 'domain':
		totals = domains
		values = per_domain
		improvements_any = improvements_any_per_domain
		improvements_all = improvements_all_per_domain
		ylabel = r"\% of configured exception domains"
	else:
		raise NotImplementedError(f"Unhandled value for '--per': {per}")

	if is_per_app:
		values = per_app
		improvements_any = improvements_any_per_app
		improvements_all = improvements_all_per_app

	fig, ax = plt.subplots()

	width = .4
	hatch_density = 5

	labels = []
	if is_per_app:
		labels += [
			"arbitrary", "arbitrary media", "arbitrary web",
			None,
		]
	labels += [
		"TLS optional", r"\textbf{TLS required}", r"\textit{could require}",
		None,
		"FS optional", r"\textbf{FS required}", r"\textit{could require}",
		None,
		r"\textbf{CT optional}", "CT required", r"\textit{could require}",
		None,
		r"min.\ TLSv1.0", r"min.\ TLSv1.1", r"\textbf{min.\ TLSv1.2}",
		r"min.\ TLSv1.3", r"\textit{could increase}",
		None,
		"justification", r"\textit{could avoid}",
	]
	explicit: Dict[str, List[int]] = defaultdict(list)
	implicit: Dict[str, List[int]] = defaultdict(list)
	improve_any: Dict[str, List[int]] = defaultdict(list)
	improve_all: Dict[str, List[int]] = defaultdict(list)

	cmas = Tomorrow.base0D
	cmu = Tomorrow.base0A

	for dataset in [mas, mu]:
		if is_per_app:
			for key in ['', ' media', ' web']:
				key = f'arbitrary{key}'
				explicit_true = values[dataset].get(f"{key} True", 0)
				explicit_false = values[dataset].get(f"{key} False", 0)
				explicit[dataset].append(explicit_true)
				implicit[dataset].append(0)
				improve_all[dataset].append(0)
				improve_any[dataset].append(0)
			explicit[dataset].append(0)
			implicit[dataset].append(0)
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)

		for key, default, flip, improvement in [
			('insecure HTTP', False, True, ats.Improvement.CanDisableHTTP),
			('requires FS', True, False, ats.Improvement.CanEnableFS),
			('requires CT', False, False, ats.Improvement.CanEnableCT),
		]:
			explicit_true = values[dataset].get(f"{key} True", 0)
			explicit_false = values[dataset].get(f"{key} False", 0)
			implicit_num = totals[dataset] - explicit_true - explicit_false

			explicit[dataset].append(explicit_true if flip else explicit_false)
			explicit[dataset].append(explicit_false if flip else explicit_true)
			explicit[dataset].append(0)

			implicit[dataset].append(implicit_num if not (default or flip) else 0)
			implicit[dataset].append(implicit_num if default or flip else 0)
			implicit[dataset].append(0)

			i_all = improvements_all[dataset].get(improvement, 0)
			i_any = improvements_any[dataset].get(improvement, 0)

			improve_all[dataset].append(0)
			improve_all[dataset].append(0)
			improve_all[dataset].append(i_all)
			improve_any[dataset].append(0)
			improve_any[dataset].append(0)
			improve_any[dataset].append(i_any - i_all)

			explicit[dataset].append(0)
			implicit[dataset].append(0)
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)

		for tls in ats.TlsVersion:
			explicit_num = values[dataset].get(f"min {tls}", 0)
			explicit[dataset].append(explicit_num)
			implicit[dataset].append(
				totals[dataset] - explicit_num if tls is ats.TlsVersion.TLSv1_2 else 0
			)
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)
		explicit[dataset].append(0)
		implicit[dataset].append(0)
		i_all = improvements_all[dataset].get(ats.Improvement.CanUpgradeTLS, 0)
		i_any = improvements_any[dataset].get(ats.Improvement.CanUpgradeTLS, 0)
		improve_all[dataset].append(i_all)
		improve_any[dataset].append(i_any - i_all)

		explicit[dataset].append(0)
		implicit[dataset].append(0)
		improve_all[dataset].append(0)
		improve_any[dataset].append(0)

		num = values[dataset].get("requires justification", 0)
		explicit[dataset].append(num)
		implicit[dataset].append(0)
		improve_all[dataset].append(0)
		improve_any[dataset].append(0)
		improvement = ats.Improvement.RemovesJustification
		i_all = improvements_all[dataset].get(improvement, 0)
		i_any = improvements_any[dataset].get(improvement, 0)
		explicit[dataset].append(0)
		implicit[dataset].append(0)
		improve_all[dataset].append(i_all)
		improve_any[dataset].append(i_any - i_all)

		assert len(labels) == len(explicit[dataset]), f"{dataset}: {len(labels)} ≠ {len(explicit[dataset])}"
		assert len(labels) == len(implicit[dataset]), f"{dataset}: {len(labels)} ≠ {len(implicit[dataset])}"
		assert len(labels) == len(improve_all[dataset]), f"{dataset}: {len(labels)} ≠ {len(improve_all[dataset])}"
		assert len(labels) == len(improve_any[dataset]), f"{dataset}: {len(labels)} ≠ {len(improve_any[dataset])}"

	xs = list(range(len(labels)))
	xticks = [x for x, label in enumerate(labels) if label is not None]

	for dataset, color, side in [(mas, cmas, -1), (mu, cmu, 1)]:
		pos = [x + side / 30 + side * width / 2 for x in xs]

		ts = [totals[dataset]] * len(labels)

		ax.bar(
			pos,
			percentages(explicit[dataset], ts),
			width,
			color=color,
			alpha=.75,
			edgecolor=color,
		)
		ax.bar(
			pos,
			percentages(implicit[dataset], ts),
			width,
			bottom=percentages(explicit[dataset], ts),
			color=color,
			alpha=.25,
			edgecolor=color,
		)

		# If filled, PDF export of hatches will fail,
		# see https://stackoverflow.com/q/5195466/5082444
		ax.bar(
			pos,
			percentages(improve_all[dataset], ts),
			width,
			fill=False,
			alpha=.75,
			edgecolor=color,
			hatch='/' * hatch_density,
		)
		ax.bar(
			pos,
			percentages(improve_any[dataset], ts),
			width,
			bottom=percentages(improve_all[dataset], ts),
			fill=False,
			alpha=.25,
			edgecolor=color,
			hatch='/' * hatch_density,
		)

	ax.set_ylabel(ylabel)
	ax.set_xticks(xticks)
	ax.set_xticklabels(
		[label for label in labels if label is not None],
		rotation=45,
		ha='right',
	)
	plt.axhline(y=0, linewidth=.5, color='black')

	# Add legend
	c = Tomorrow.base05
	plt.legend(
		handles=[
			Patch(color=cmas, alpha=.75, label="MAS"),
			Patch(color=cmu, alpha=.75, label="MU"),
			Patch(color=c, alpha=.25, label="implicit"),
			Patch(color=c, alpha=.75, label="explicit"),
			Patch(edgecolor=c, fill=False, alpha=.25, hatch='/' * hatch_density, label="improvement (any)"),
			Patch(edgecolor=c, fill=False, alpha=.75, hatch='/' * hatch_density, label="improvement (all)"),
		],
		ncol=3,
	)

	# Layout
	ax.margins(x=0.01)
	plt.tight_layout()

	plt.show()


@cli.command()
@click.option(
	'--per',
	type=click.Choice(['app', 'app-with-cfg', 'domain']),
	required=True,
)
@click.argument(
	'maap_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	required=True,
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_trackers(
	per: str,
	maap_dir: str,
	diagnostics_dir: str,
):
	# TODO `--per app` or `--per app-with-cfg` do not make much sense, yet.
	# TODO Add `--per endpoint`?

	maap_path = Path(maap_dir)
	diagnostics_path = Path(diagnostics_dir)
	trackers = exodus.Trackers.load()

	apps: Dict[str, int] = dict()
	with_cfg: Dict[str, int] = dict()
	per_app: Dict[str, Dict[str, int]] = dict()
	improvements_any_per_app: Dict[str, Dict[ats.Improvement, int]] = dict()
	improvements_all_per_app: Dict[str, Dict[ats.Improvement, int]] = dict()

	domains: Dict[str, int] = dict()
	per_domain: Dict[str, Dict[str, int]] = dict()
	improvements_any_per_domain: Dict[str, Dict[ats.Improvement, int]] = dict()
	improvements_all_per_domain: Dict[str, Dict[ats.Improvement, int]] = dict()

	diagnostics: Optional[DiagnosticResults] = None

	ts = "trackers"
	nts = "non-trackers"

	cache: Dict[str, Tuple[
		int,
		int,
		Dict[str, int],
		Dict[ats.Improvement, int],
		Dict[ats.Improvement, int],
		int,
		Dict[str, int],
		Dict[ats.Improvement, int],
		Dict[ats.Improvement, int],
	]] = dict()
	cache_path = Path('evaluate_trackers.pickle')
	click.secho(f"Loading cache from '{cache_path}'... ", dim=True, err=True, nl=False)
	if cache_path.exists():
		with cache_path.open('rb') as f:
			cache = pickle.load(f)
		click.secho("✓", fg='green', dim=True, err=True)
	else:
		click.secho("×", fg='red', dim=True, err=True)

	def include(trackers: exodus.Trackers, revert: bool, domain: str) -> bool:
		is_tracker = 0 < len(trackers.get(domain)) + len(trackers.get(f".{domain}"))
		if revert:
			return not is_tracker
		return is_tracker

	for include_domain, name in [
		(partial(include, trackers, False), ts),
		(partial(include, trackers, True), nts),
	]:
		cache_key = (str(maap_path.absolute()), name)
		click.secho(f"Looking up {name} in cache... ", dim=True, err=True, nl=False)
		if cache_key in cache:
			(
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			) = cache[cache_key]
			click.secho("✓", fg='green', dim=True, err=True)
		else:
			click.secho("×", fg='red', dim=True, err=True)
			if diagnostics is None:
				diagnostics = DiagnosticResults.parse(diagnostics_path).succeeding
			assert diagnostics is not None
			(
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			) = do_evaluate_configurations(maap_path, diagnostics, name, include_domain)
			cache[cache_key] = (
				apps[name],
				with_cfg[name],
				per_app[name],
				improvements_any_per_app[name],
				improvements_all_per_app[name],
				domains[name],
				per_domain[name],
				improvements_any_per_domain[name],
				improvements_all_per_domain[name],
			)
			with cache_path.open('wb') as f:
				pickle.dump(cache, f)
			click.secho(f"Cached in '{cache_path}'", dim=True, err=True)

	table = Table()

	keys = sorted(set.union(set(per_app[ts].keys()), set(per_app[nts].keys())))
	for dataset in [ts, nts]:
		for grp, base in [
			("Applications", apps[dataset]),
			("Applications with configuration", with_cfg[dataset]),
		]:
			table.add_group(grp, base, dataset)
			for key in keys:
				table.add_row(grp, key, per_app[dataset].get(key, 0), dataset)
			if grp == "Applications":
				table.add_row(grp, "with configuration", with_cfg[dataset], dataset)
			for improvement in ats.Improvement:
				table.add_row(
					grp,
					f"{improvement} (any)",
					improvements_any_per_app[dataset].get(improvement, 0),
					dataset,
				)
				table.add_row(
					grp,
					f"{improvement} (all)",
					improvements_all_per_app[dataset].get(improvement, 0),
					dataset,
				)

	keys = sorted(set.union(set(per_domain[ts].keys()), set(per_domain[nts].keys())))
	for dataset in [ts, nts]:
		grp = table.add_group("Configured exception domains", domains[dataset], dataset)
		for key in keys:
			table.add_row(grp, key, per_domain[dataset].get(key, 0), dataset)
		for improvement in ats.Improvement:
			table.add_row(
				grp,
				f"{improvement} (any)",
				improvements_any_per_domain[dataset].get(improvement, 0),
				dataset,
			)
			table.add_row(
				grp,
				f"{improvement} (all)",
				improvements_all_per_domain[dataset].get(improvement, 0),
				dataset,
			)

	table.display()

	# Plot
	is_per_app: bool = False
	totals: Dict[str, int]
	values: Dict[str, Dict[str, int]]
	improvements_any: Dict[str, Dict[ats.Improvement, int]]
	improvements_all: Dict[str, Dict[ats.Improvement, int]]
	ylabel: str
	if per == 'app':
		is_per_app = True
		totals = apps
		ylabel = r"\% of apps"
	elif per == 'app-with-cfg':
		is_per_app = True
		totals = with_cfg
		ylabel = r"\% of apps with explicit ATS configuration"
	elif per == 'domain':
		totals = domains
		values = per_domain
		improvements_any = improvements_any_per_domain
		improvements_all = improvements_all_per_domain
		ylabel = r"\% of configured exception domains"
	else:
		raise NotImplementedError(f"Unhandled value for '--per': {per}")

	if is_per_app:
		values = per_app
		improvements_any = improvements_any_per_app
		improvements_all = improvements_all_per_app

	fig, ax = plt.subplots()

	width = .4
	hatch_density = 5

	labels = []
	if is_per_app:
		labels += [
			"arbitrary", "arbitrary media", "arbitrary web",
			None,
		]
	labels += [
		"TLS optional", r"\textbf{TLS required}", r"\textit{could require}",
		None,
		"FS optional", r"\textbf{FS required}", r"\textit{could require}",
		None,
		r"\textbf{CT optional}", "CT required", r"\textit{could require}",
		None,
		r"min.\ TLSv1.0", r"min.\ TLSv1.1", r"\textbf{min.\ TLSv1.2}",
		r"min.\ TLSv1.3", r"\textit{could increase}",
		None,
		"justification", r"\textit{could avoid}",
	]
	explicit: Dict[str, List[int]] = defaultdict(list)
	implicit: Dict[str, List[int]] = defaultdict(list)
	improve_any: Dict[str, List[int]] = defaultdict(list)
	improve_all: Dict[str, List[int]] = defaultdict(list)

	cts = Tomorrow.base0F
	cnts = Tomorrow.base0C

	for dataset in [ts, nts]:
		if is_per_app:
			for key in ['', ' media', ' web']:
				key = f'arbitrary{key}'
				explicit_true = values[dataset].get(f"{key} True", 0)
				explicit_false = values[dataset].get(f"{key} False", 0)
				explicit[dataset].append(explicit_true)
				implicit[dataset].append(0)
				improve_all[dataset].append(0)
				improve_any[dataset].append(0)
			explicit[dataset].append(0)
			implicit[dataset].append(0)
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)

		for key, default, flip, improvement in [
			('insecure HTTP', False, True, ats.Improvement.CanDisableHTTP),
			('requires FS', True, False, ats.Improvement.CanEnableFS),
			('requires CT', False, False, ats.Improvement.CanEnableCT),
		]:
			explicit_true = values[dataset].get(f"{key} True", 0)
			explicit_false = values[dataset].get(f"{key} False", 0)
			implicit_num = totals[dataset] - explicit_true - explicit_false

			explicit[dataset].append(explicit_true if flip else explicit_false)
			explicit[dataset].append(explicit_false if flip else explicit_true)
			explicit[dataset].append(0)

			implicit[dataset].append(implicit_num if not (default or flip) else 0)
			implicit[dataset].append(implicit_num if default or flip else 0)
			implicit[dataset].append(0)

			i_all = improvements_all[dataset].get(improvement, 0)
			i_any = improvements_any[dataset].get(improvement, 0)

			improve_all[dataset].append(0)
			improve_all[dataset].append(0)
			improve_all[dataset].append(i_all)
			improve_any[dataset].append(0)
			improve_any[dataset].append(0)
			improve_any[dataset].append(i_any - i_all)

			explicit[dataset].append(0)
			implicit[dataset].append(0)
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)

		explicit_tls = 0
		for tls in ats.TlsVersion:
			explicit_num = values[dataset].get(f"min {tls}", 0)
			explicit[dataset].append(explicit_num)
			explicit_tls += explicit_num
			improve_all[dataset].append(0)
			improve_any[dataset].append(0)
		for tls in ats.TlsVersion:
			implicit[dataset].append(
				totals[dataset] - explicit_tls if tls is ats.TlsVersion.TLSv1_2 else 0
			)
		explicit[dataset].append(0)
		implicit[dataset].append(0)
		i_all = improvements_all[dataset].get(ats.Improvement.CanUpgradeTLS, 0)
		i_any = improvements_any[dataset].get(ats.Improvement.CanUpgradeTLS, 0)
		improve_all[dataset].append(i_all)
		improve_any[dataset].append(i_any - i_all)

		explicit[dataset].append(0)
		implicit[dataset].append(0)
		improve_all[dataset].append(0)
		improve_any[dataset].append(0)

		num = values[dataset].get("requires justification", 0)
		explicit[dataset].append(num)
		implicit[dataset].append(0)
		improve_all[dataset].append(0)
		improve_any[dataset].append(0)
		improvement = ats.Improvement.RemovesJustification
		i_all = improvements_all[dataset].get(improvement, 0)
		i_any = improvements_any[dataset].get(improvement, 0)
		explicit[dataset].append(0)
		implicit[dataset].append(0)
		improve_all[dataset].append(i_all)
		improve_any[dataset].append(i_any - i_all)

		assert len(labels) == len(explicit[dataset]), f"{dataset}: {len(labels)} ≠ {len(explicit[dataset])}"
		assert len(labels) == len(implicit[dataset]), f"{dataset}: {len(labels)} ≠ {len(implicit[dataset])}"
		assert len(labels) == len(improve_all[dataset]), f"{dataset}: {len(labels)} ≠ {len(improve_all[dataset])}"
		assert len(labels) == len(improve_any[dataset]), f"{dataset}: {len(labels)} ≠ {len(improve_any[dataset])}"

	xs = list(range(len(labels)))
	xticks = [x for x, label in enumerate(labels) if label is not None]

	for dataset, color, side in [
		(ts, cts, -1),
		(nts, cnts, 1),
	]:
		pos = [x + side / 30 + side * width / 2 for x in xs]

		tots = [totals[dataset]] * len(labels)

		ax.bar(
			pos,
			percentages(explicit[dataset], tots),
			width,
			color=color,
			alpha=.75,
			edgecolor=color,
		)
		ax.bar(
			pos,
			percentages(implicit[dataset], tots),
			width,
			bottom=percentages(explicit[dataset], tots),
			color=color,
			alpha=.25,
			edgecolor=color,
		)

		# If filled, PDF export of hatches will fail,
		# see https://stackoverflow.com/q/5195466/5082444
		ax.bar(
			pos,
			percentages(improve_all[dataset], tots),
			width,
			fill=False,
			alpha=.75,
			edgecolor=color,
			hatch='/' * hatch_density,
		)
		ax.bar(
			pos,
			percentages(improve_any[dataset], tots),
			width,
			bottom=percentages(improve_all[dataset], tots),
			fill=False,
			alpha=.25,
			edgecolor=color,
			hatch='/' * hatch_density,
		)

	ax.set_ylabel(ylabel)
	ax.set_xticks(xticks)
	ax.set_xticklabels(
		[label for label in labels if label is not None],
		rotation=45,
		ha='right',
	)
	plt.axhline(y=0, linewidth=.5, color='black')

	# Add legend
	c = Tomorrow.base05
	plt.legend(
		handles=[
			Patch(color=cts, alpha=.75, label=ts),
			Patch(color=cnts, alpha=.75, label=nts),
			Patch(color=c, alpha=.25, label="implicit"),
			Patch(color=c, alpha=.75, label="explicit"),
			Patch(edgecolor=c, fill=False, alpha=.25, hatch='/' * hatch_density, label="improvement (any)"),
			Patch(edgecolor=c, fill=False, alpha=.75, hatch='/' * hatch_density, label="improvement (all)"),
		],
		ncol=3,
	)

	# Layout
	ax.margins(x=0.01)
	plt.tight_layout()

	plt.show()


@cli.command()
@click.option(
	'--top',
	type=click.INT,
	default=10,
	show_default=True,
)
@click.option(
	'--show',
	type=click.Choice({'domain', 'host', 'tracker', 'tex'}),
	required=True,
)
@click.argument(
	'maap_dirs',
	metavar="MAAP_DIR",
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
	nargs=-1,
	required=True,
)
def evaluate_domains(
	top: int,
	show: str,
	maap_dirs: Tuple[str, ...],
):
	def matches_criteria(app: App) -> bool:
		return app.info_path.exists() and app.binary_path.exists() and app.can_access_network

	maap_paths = [Path(maap_dir) for maap_dir in maap_dirs]

	trackers = exodus.Trackers.load()

	domain_list: List[str] = []
	host_list: List[str] = []
	tracker_list: List[str] = []

	tracker_used_by_apps: Dict[str, Set[App]] = defaultdict(set)
	tracker_configured_by_apps: Dict[str, Set[App]] = defaultdict(set)

	apps: List[App] = []
	for maap_path in maap_paths:
		apps.extend(list(maap.walk(maap_path, matches_criteria, latest=True)))

	for app in tqdm(apps, unit='app', leave=True):

		for domain in app.ats_configuration.exceptions:
			domain_list.append(domain)
			app_trackers = trackers.get(f".{domain}")
			for tracker in app_trackers:
				tracker_configured_by_apps[tracker].add(app)
		app_endpoints = app.endpoints

		# TODO Include transitive redirects

		app_hosts: Set[str] = set()
		for endpoint in app_endpoints:
			app_hosts.add(endpoint.host)
		host_list.extend(app_hosts)
		app_trackers = set()
		for host in app_hosts:
			app_trackers = app_trackers.union(trackers.get(host))
			for tracker in app_trackers:
				tracker_used_by_apps[tracker].add(app)
			if app.ats_configuration.exception_domain_for(host) is not None:
				tracker_configured_by_apps[tracker].add(app)
		tracker_list.extend(app_trackers)

	# TODO Filter by reachability?

	if show == 'host':
		h_counts = Counter(host_list)
		for place, (host, count) in enumerate(h_counts.most_common(top), start=1):
			is_tracker = 0 < len(trackers.get(host))
			click.secho(f"{place:3d} {count:5d} {host}", fg='red' if is_tracker else None)
	elif show == 'domain':
		d_counts = Counter(domain_list)
		for place, (domain, count) in enumerate(d_counts.most_common(top), start=1):
			is_tracker = 0 < len(trackers.get(f".{domain}"))
			click.secho(f"{place:3d} {count:5d} {domain}", fg='red' if is_tracker else None)
	elif show == 'tracker':
		t_counts = Counter(tracker_list)
		for place, (tracker, count) in enumerate(t_counts.most_common(top), start=1):
			click.secho(f"{place:3d} {count:5d} {tracker}")
	elif show == 'tex':
		t_counts = Counter(tracker_list)
		total = len(apps)
		for tracker, used in t_counts.most_common(top):
			assert used == len(tracker_used_by_apps[tracker]), f"{tracker}: {count} ≠ {len(tracker_used_by_apps[tracker])}"
			configured = len(tracker_configured_by_apps[tracker])
			click.echo(f"{tracker}", nl=False)
			click.echo(f" & \\num{{{used}}}", nl=False)
			click.echo(f" & \\SI{{{percentage(used, total):.2f}}}{{\\percent}}", nl=False)
			click.echo(f" & \\num{{{configured}}} & \\SI{{{percentage(configured, total):.2f}}}{{\\percent}}\\\\")
	else:
		raise NotImplementedError(f"Unhandled case for '--show': {show}")


@cli.command()
@click.option(
	'--redirects/--no-redirects', 'show_redirects',
	default=True,
	show_default=True,
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def evaluate_diagnostics(
	show_redirects: bool,
	diagnostics_dir: str,
):
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
	endpoint_statistics(succeeding.endpoints, table)
	table.display()

	table = Table()
	failure_statistics(failing, table)
	table.display()

	if show_redirects:
		table = Table()
		redirection_statistics(succeeding, table)
		table.display()

	table = Table()
	configuration_statistics(succeeding.configurations, table)
	table.display()


@cli.command()
@click.option(
	'--format',
	'output_format',
	type=click.Choice(['text', 'json']),
	required=True,
	default='text',
)
@click.option(
	'--reverse-domain-name/--no-reverse-domain-name',
	default=False,
)
@click.argument(
	'diagnostics_dir',
	type=click.Path(dir_okay=True, file_okay=False, readable=True),
)
def hsts_preload_list(
	output_format: str,
	reverse_domain_name: bool,
	diagnostics_dir: str,
):
	diagnostics_path = Path(diagnostics_dir)
	diagnostics = DiagnosticResults.parse(diagnostics_path)

	hsts: List[str] = [
		endpoint.reverse_domain_name if reverse_domain_name else endpoint.host
		for endpoint in diagnostics.hsts_preload
	]

	if output_format == 'text':
		for host in hsts:
			click.echo(host)
	elif output_format == 'json':
		click.echo(json.dumps(hsts))
	else:
		raise NotImplementedError(f"Unsupported output format: {output_format}")


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
