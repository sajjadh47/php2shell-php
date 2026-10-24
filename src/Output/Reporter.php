<?php

declare(strict_types=1);

namespace Php2Shell\Output;

final class Reporter
{
	public function __construct(
		private readonly bool $quiet = false,
		private readonly bool $verbose = false,
		private readonly bool $color = true,
	) {
	}

	private function paint(string $text, string $code): string
	{
		return $this->color ? "\033[{$code}m{$text}\033[0m" : $text;
	}

	public function info(string $msg): void
	{
		if (!$this->quiet) {
			echo $this->paint('[*] ' . $msg, '96') . "\n";
		}
	}

	public function warn(string $msg): void
	{
		if (!$this->quiet) {
			echo $this->paint('[!] ' . $msg, '93') . "\n";
		}
	}

	public function error(string $msg): void
	{
		echo $this->paint('[ERROR] ' . $msg, '91') . "\n";
	}

	/**
	 * @param array<string,mixed> $result
	 */
	public function result(array $result): void
	{
		$vulnerable = $result['vulnerable'] ?? null;
		if ($this->quiet && $vulnerable !== true) {
			return;
		}

		$verdict = $this->str($result['verdict'] ?? null);
		$status = match (true) {
			$vulnerable === true => $this->paint('[VULNERABLE]', '1;91'),
			$vulnerable === false => $this->paint('[NOT VULNERABLE]', '92'),
			$verdict === 'INCONCLUSIVE' => $this->paint('[INCONCLUSIVE]', '93'),
			default => $this->paint('[ERROR]', '93'),
		};

		$details = [];
		$statusCode = $result['status_code'] ?? null;
		if (is_int($statusCode)) {
			$details[] = 'Status: ' . $statusCode;
		}
		$sapi = $this->str($result['sapi'] ?? null);
		if ($sapi !== '') {
			$details[] = 'SAPI: ' . $sapi;
		}
		if ($verdict !== '') {
			$details[] = 'Verdict: ' . $verdict;
		}
		$suffix = $details ? ' - ' . implode(' - ', $details) : '';

		$host = $this->sanitize($this->str($result['host'] ?? null));
		echo "{$status} {$this->paint($host, '97')}{$suffix}\n";

		$finalUrl = $this->str($result['final_url'] ?? null);
		$testedUrl = $this->str($result['tested_url'] ?? null);
		if ($finalUrl !== $testedUrl) {
			echo '  -> Retargeted to: ' . $this->sanitize($finalUrl) . "\n";
		}
		if ($this->verbose) {
			$reason = $this->str($result['reason'] ?? null);
			if ($reason !== '') {
				echo '  -> ' . $this->sanitize($reason) . "\n";
			}
			$response = $this->str($result['response'] ?? null);
			if ($response !== '') {
				echo $this->paint('  Response snippet:', '96') . "\n";
				$lines = explode("\r\n", $response);
				foreach (array_slice($lines, 0, 10) as $line) {
					echo '    ' . $this->sanitize($line) . "\n";
				}
			}
		}
	}

	public function summary(int $total, int $vuln, int $error): void
	{
		if ($this->quiet) {
			return;
		}
		$line = str_repeat('=', 60);
		echo "\n" . $this->paint($line, '96') . "\n";
		echo $this->paint('SCAN SUMMARY', '1') . "\n";
		echo $this->paint($line, '96') . "\n";
		echo "  Total hosts scanned: {$total}\n";
		$vulnLine = "Vulnerable: {$vuln}";
		echo '  ' . ($vuln > 0 ? $this->paint($vulnLine, '1;91') : $vulnLine) . "\n";
		echo '  Not vulnerable: ' . ($total - $vuln - $error) . "\n";
		echo "  Inconclusive/errors: {$error}\n";
		echo $this->paint($line, '96') . "\n";
	}

	private function str(mixed $value): string
	{
		return is_string($value) ? $value : '';
	}

	private function sanitize(string $s): string
	{
		return preg_replace_callback('/[\x00-\x1f\x7f]/', static function (array $m): string {
			return sprintf('\\x%02x', ord($m[0]));
		}, $s) ?? $s;
	}
}
