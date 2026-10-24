<?php

declare(strict_types=1);

namespace Php2Shell\Output;

final class JsonWriter
{
	/**
	 * @param array<int,array<string,mixed>> $results
	 */
	public static function save(array $results, string $path, bool $vulnerableOnly = true): bool
	{
		$selected = $vulnerableOnly
			? array_values(array_filter($results, static fn ($r) => ($r['vulnerable'] ?? null) === true))
			: array_values($results);

		$payload = [
			'scan_time' => gmdate('Y-m-d\TH:i:s\Z'),
			'total_results' => count($selected),
			'results' => $selected,
		];
		$json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
		if ($json === false) {
			fwrite(STDERR, 'Failed to encode JSON: ' . json_last_error_msg() . "\n");
			return false;
		}
		if (file_put_contents($path, $json) === false) {
			fwrite(STDERR, "Failed to write {$path}\n");
			return false;
		}
		return true;
	}
}
