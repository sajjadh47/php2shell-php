<?php

declare(strict_types=1);

namespace Php2Shell\Detection;

final class ProbeBuilder
{
	public const NESTED_KEYS = 62;
	public const CONTROL_BOUNDARY = 'x';
	public const PROBE_BOUNDARY = '';
	public const CONTROL_BODY = "--x\nContent-Disposition:name=a;filename=\n\n";

	/** @var array<int,array{int,int}> */
	public const PROBES = [[1, 4000], [8, 1020], [20, 1020]];

	public static function build(int $sizeMiB, int $parts): string
	{
		$size = $sizeMiB << 20;
		$name = 'a[]' . str_repeat('[a]', self::NESTED_KEYS);
		$part = "--\nContent-Disposition:name={$name};filename=\n\n";
		$base = str_repeat($part, $parts);

		// Body shape after the reference strip: "--\n" . filler . substr($base, 3), with
		// the final byte removed. So the pre-strip body must be exactly $size + 1 bytes.
		$prefix = "--\n";
		$tail = substr($base, 3);
		$budget = $size + 1 - strlen($prefix) - strlen($tail);

		if ($budget < 0) {
			throw new \InvalidArgumentException(sprintf(
				'php2shell probe of %d bytes cannot hold %d parts (%d bytes)',
				$size,
				$parts,
				strlen($base),
			));
		}

		$filler = intdiv($budget, 3);
		$remainder = $budget - $filler * 3;

		// $remainder is mathematically in {0, 1, 2}; the lookup keeps PHPStan happy
		// without an unreachable default branch in a match expression.
		$pad = ['', 'x', 'x:'][$remainder];

		return substr($prefix . str_repeat("x:\n", $filler) . $pad . $tail, 0, -1);
	}
}
