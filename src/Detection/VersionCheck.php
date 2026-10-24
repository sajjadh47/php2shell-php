<?php

declare(strict_types=1);

namespace Php2Shell\Detection;

final class VersionCheck
{
	/** @var array<string,int> branch => first fixed patch */
	private const FIXED_VERSIONS = [
		'8.2' => 35,
		'8.3' => 36,
		'8.4' => 27,
		'8.5' => 12,
	];

	public static function against(string $poweredBy): ?string
	{
		if (!preg_match('#PHP/(\d+)\.(\d+)\.(\d+)#', $poweredBy, $m)) {
			return null;
		}
		[$major, $minor, $patch] = [(int) $m[1], (int) $m[2], (int) $m[3]];

		if ($major < 8) {
			return 'VULNERABLE';
		}
		if ($major === 8 && $minor < 2) {
			return 'VULNERABLE';
		}

		$branch = "{$major}.{$minor}";
		$fixed = self::FIXED_VERSIONS[$branch] ?? null;
		if ($fixed === null) {
			return null;
		}
		return $patch >= $fixed ? 'FIXED' : 'VULNERABLE';
	}
}
