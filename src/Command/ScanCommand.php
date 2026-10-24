<?php

declare(strict_types=1);

namespace Php2Shell\Command;

use Amp\Sync\LocalSemaphore;
use Php2Shell\Detection\ProbeBuilder;
use Php2Shell\Http\Scanner;
use Php2Shell\Output\JsonWriter;
use Php2Shell\Output\Reporter;
use Php2Shell\Target\Target;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use function Amp\async;
use function Amp\Future\await;

#[AsCommand(
	name: 'scan',
	description: 'php2shell scanner for CVE-2026-109618 / CVE-2026-109619',
)]
final class ScanCommand extends Command
{
	protected function configure(): void
	{
		$this
			->addOption('url', 'u', InputOption::VALUE_REQUIRED, 'Single URL/host')
			->addOption('list', 'l', InputOption::VALUE_REQUIRED, 'File with hosts (one per line)')
			->addOption('threads', 't', InputOption::VALUE_REQUIRED, 'Maximum concurrent target scans', '10')
			->addOption('timeout', null, InputOption::VALUE_REQUIRED, 'Per-request timeout in seconds', '60')
			->addOption('output', 'o', InputOption::VALUE_REQUIRED, 'JSON output file')
			->addOption('all-results', null, InputOption::VALUE_NONE, 'Include non-vulnerable hosts in JSON')
			->addOption('insecure', 'k', InputOption::VALUE_NONE, 'Disable TLS certificate verification')
			->addOption('follow-redirects', null, InputOption::VALUE_NONE, 'Follow up to 10 redirects')
			->addOption('header', 'H', InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, "Custom header 'Key: Value' (repeatable)")
			->addOption('path', null, InputOption::VALUE_REQUIRED | InputOption::VALUE_IS_ARRAY, 'Custom path to test (repeatable)')
			->addOption('path-file', null, InputOption::VALUE_REQUIRED, 'File with paths, one per line')
			->addOption('sapi', null, InputOption::VALUE_REQUIRED, 'auto|mod_php|fpm', 'auto')
			->addOption('no-color', null, InputOption::VALUE_NONE, 'Disable ANSI colors');
		// Note: -v/--verbose and -q/--quiet are provided by Symfony's Application.
	}

	protected function execute(InputInterface $input, OutputInterface $output): int
	{
		$threadsRaw = $this->intOption($input, 'threads', 10, 1);
		$threads = $threadsRaw > 0 ? $threadsRaw : 1;

		$timeout = $this->intOption($input, 'timeout', 60, 1);
		$quiet = $output->isQuiet();
		$verbose = $output->isVerbose() || $output->isVeryVerbose() || $output->isDebug();
		$color = !$this->boolOption($input, 'no-color') && !$output->isQuiet() && stream_isatty(STDOUT);
		$reporter = new Reporter($quiet, $verbose, $color);

		$url = $this->stringOption($input, 'url');
		$listFile = $this->stringOption($input, 'list');
		if (($url === null) === ($listFile === null)) {
			$reporter->error('Exactly one of --url or --list is required');
			return 3;
		}

		$sapi = $this->stringOption($input, 'sapi') ?? 'auto';
		if (!in_array($sapi, ['auto', 'mod_php', 'fpm'], true)) {
			$reporter->error('--sapi must be one of: auto, mod_php, fpm');
			return 3;
		}

		try {
			$customHeaders = $this->parseHeaders($this->stringListOption($input, 'header'));
		} catch (\InvalidArgumentException $e) {
			$reporter->error($e->getMessage());
			return 3;
		}

		$paths = $this->resolvePaths($input, $reporter);
		if ($paths === false) {
			return 3;
		}

		if ($url !== null) {
			$hosts = [$url];
		} else {
			$hosts = $this->loadLines((string) $listFile, 'host');
			if ($hosts === null) {
				$reporter->error("could not read list file: {$listFile}");
				return 3;
			}
		}
		$hosts = $this->deduplicate($hosts);
		if ($hosts === []) {
			$reporter->error('No hosts to scan');
			return 3;
		}

		$reporter->info('Loaded ' . count($hosts) . ' host(s) to scan');
		if ($paths !== null) {
			$reporter->info('Testing ' . count($paths) . ' custom path(s)');
		} else {
			$reporter->info('Default path: ' . Target::DEFAULT_PATH);
		}
		$reporter->info('Using ' . $threads . ' thread(s)');
		$reporter->info('Timeout: ' . $timeout . 's');
		$reporter->info('SAPI rules: ' . $sapi);
		if ($this->boolOption($input, 'insecure')) {
			$reporter->warn('TLS verification disabled');
		}
		if (!$quiet) {
			echo "\n";
		}

		// Pre-warm probe bodies so a build error surfaces before any network I/O.
		foreach (ProbeBuilder::PROBES as $probe) {
			ProbeBuilder::build(...$probe);
		}

		$scanner = Scanner::build(
			timeout: $timeout,
			sapi: $sapi,
			customHeaders: $customHeaders,
			followRedirects: $this->boolOption($input, 'follow-redirects'),
			insecure: $this->boolOption($input, 'insecure'),
		);

		$semaphore = new LocalSemaphore($threads);

		/** @var array<string, \Amp\Future<array<string,mixed>>> $futures */
		$futures = [];
		foreach ($hosts as $host) {
			$futures[$host] = async(function () use ($host, $scanner, $paths, $semaphore): array {
				$lock = $semaphore->acquire();
				try {
					return $this->scanHost($scanner, $host, $paths);
				} finally {
					$lock->release();
				}
			});
		}

		/** @var array<int,array<string,mixed>> $results */
		$results = [];
		foreach (await($futures) as $result) {
			/** @var array<string,mixed> $result */
			$results[] = $result;
			$reporter->result($result);
		}

		$vulnerable = count(array_filter(
			$results,
			static fn (array $r): bool => ($r['vulnerable'] ?? null) === true,
		));
		$errors = count(array_filter(
			$results,
			static fn (array $r): bool => ($r['vulnerable'] ?? null) === null,
		));
		$reporter->summary(count($results), $vulnerable, $errors);

		$outputFile = $this->stringOption($input, 'output');
		if ($outputFile !== null) {
			$ok = JsonWriter::save($results, $outputFile, !$this->boolOption($input, 'all-results'));
			if (!$ok) {
				return 3;
			}
			if (!$quiet) {
				echo "\n[+] Results saved to: {$outputFile}\n";
			}
		}

		return $vulnerable > 0 ? 1 : 0;
	}

	private function boolOption(InputInterface $input, string $name): bool
	{
		return $input->getOption($name) === true;
	}

	private function intOption(InputInterface $input, string $name, int $default, int $min = PHP_INT_MIN): int
	{
		$raw = $input->getOption($name);
		$value = is_numeric($raw) ? (int) $raw : $default;
		return max($min, $value);
	}

	private function stringOption(InputInterface $input, string $name): ?string
	{
		$raw = $input->getOption($name);
		return is_string($raw) && $raw !== '' ? $raw : null;
	}

	/**
	 * @return array<int,string>
	 */
	private function stringListOption(InputInterface $input, string $name): array
	{
		$raw = $input->getOption($name);
		if (!is_array($raw)) {
			return [];
		}
		return array_values(array_filter(
			$raw,
			static fn ($v): bool => is_string($v),
		));
	}

	private function stringOr(mixed $value, string $default): string
	{
		return is_string($value) ? $value : $default;
	}

	/**
	 * @param string[]|null $paths
	 *
	 * @return array<string,mixed>
	 */
	private function scanHost(Scanner $scanner, string $host, ?array $paths): array
	{
		try {
			$target = Target::fromUrl($host);
		} catch (\InvalidArgumentException $e) {
			return $this->errorResult($host, $e->getMessage());
		}

		$targets = $paths !== null
			? array_map(static fn (string $p): Target => $target->withPath($p), $paths)
			: [$target];

		/** @var array<string,mixed>|null $fallback */
		$fallback = null;
		/** @var string|null $fallbackVerdict */
		$fallbackVerdict = null;
		$priority = ['NO SIGNAL' => 0, 'FIXED' => 1, 'INCONCLUSIVE' => 2, 'ERROR' => 2];

		foreach ($targets as $candidate) {
			try {
				$result = $scanner->check($candidate);
			} catch (\Throwable $e) {
				$result = $this->errorResult(
					$candidate->label(),
					'unexpected error: ' . $e->getMessage(),
				);
			}
			if (($result['vulnerable'] ?? null) === true) {
				return $result;
			}
			$verdict = $this->stringOr($result['verdict'] ?? null, 'ERROR');
			$currentPriority = $priority[$verdict] ?? 0;
			$bestPriority = $fallbackVerdict !== null ? ($priority[$fallbackVerdict] ?? 0) : -1;

			if ($fallback === null || $currentPriority > $bestPriority) {
				$fallback = $result;
				$fallbackVerdict = $verdict;
			}
		}

		return $fallback ?? $this->errorResult($target->label(), 'no targets were tested');
	}

	/**
	 * @param string[] $rawHeaders
	 *
	 * @return array<string,string>
	 */
	private function parseHeaders(array $rawHeaders): array
	{
		$headers = [];
		$namePattern = '/^[!#$%&\'*+\-.^_`|~0-9A-Za-z]+$/';

		foreach ($rawHeaders as $raw) {
			if (!str_contains($raw, ':')) {
				throw new \InvalidArgumentException(
					"invalid header {$raw}; expected 'Key: Value'",
				);
			}
			[$name, $value] = explode(':', $raw, 2);
			$name = trim($name);
			$value = ltrim($value);

			if ($name === '') {
				throw new \InvalidArgumentException(
					"invalid header {$raw}; header name is empty",
				);
			}
			if (!preg_match($namePattern, $name)) {
				throw new \InvalidArgumentException("invalid header name {$name}");
			}
			if (str_contains($value, "\r") || str_contains($value, "\n")) {
				throw new \InvalidArgumentException(
					"invalid value for header {$name}; CR/LF not allowed",
				);
			}

			$headers[$name] = $value;
		}

		return $headers;
	}

	/**
	 * @return list<string>|null|false
	 */
	private function resolvePaths(InputInterface $input, Reporter $reporter): array|null|false
	{
		$pathFile = $this->stringOption($input, 'path-file');
		$paths = $this->stringListOption($input, 'path');
		$hadFile = false;

		if ($pathFile !== null) {
			$hadFile = true;
			$fromFile = $this->loadLines($pathFile, 'path');
			if ($fromFile === null) {
				$reporter->error("could not read path file: {$pathFile}");
				return false;
			}
			$paths = array_merge($paths, $fromFile);
		}

		if ($paths === []) {
			if ($hadFile) {
				$reporter->error('No paths to scan');
				return false;
			}
			return null;
		}

		$normalised = [];
		foreach ($paths as $p) {
			$p = trim($p);
			if ($p === '') {
				continue;
			}
			if ($p[0] !== '/') {
				$p = '/' . $p;
			}
			$normalised[] = $p;
		}

		if ($normalised === []) {
			$reporter->error('No valid paths after normalisation');
			return false;
		}

		return $normalised;
	}

	/**
	 * @return list<string>|null null on I/O failure
	 */
	private function loadLines(string $path, string $label): ?array
	{
		$lines = [];
		$handle = @fopen($path, 'r');
		if ($handle === false) {
			return null;
		}
		try {
			while (($line = fgets($handle)) !== false) {
				$value = trim($line);
				if ($value === '' || str_starts_with($value, '#')) {
					continue;
				}
				$lines[] = $value;
			}
		} finally {
			fclose($handle);
		}
		return $lines;
	}

	/**
	 * @param list<string> $hosts
	 *
	 * @return list<string>
	 */
	private function deduplicate(array $hosts): array
	{
		$seen = [];
		$out = [];
		foreach ($hosts as $host) {
			try {
				$t = Target::fromUrl($host);
				$key = strtolower($t->scheme) . '://' . strtolower($t->host)
					. ':' . $t->port . $t->path;
			} catch (\InvalidArgumentException) {
				$key = 'invalid:' . $host;
			}
			if (!isset($seen[$key])) {
				$seen[$key] = true;
				$out[] = $host;
			}
		}
		return $out;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function errorResult(string $host, string $message): array
	{
		return [
			'host' => $host,
			'vulnerable' => null,
			'verdict' => 'ERROR',
			'status_code' => null,
			'error' => $message,
			'reason' => $message,
			'sapi' => null,
			'powered_by' => null,
			'tested_url' => $host,
			'final_url' => $host,
			'control' => null,
			'probes' => [],
			'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
		];
	}
}
