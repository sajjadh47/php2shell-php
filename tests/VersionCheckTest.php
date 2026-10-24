<?php

declare(strict_types=1);

namespace Php2Shell\Tests;

use Php2Shell\Detection\VersionCheck;
use PHPUnit\Framework\TestCase;

final class VersionCheckTest extends TestCase
{
	/** @return array<string,array{string,?string}> */
	public static function cases(): array
	{
		return [
			'no version' => ['Apache/2.4', null],
			'empty' => ['', null],
			'php 7.4 eol' => ['PHP/7.4.33', 'VULNERABLE'],
			'php 8.0 eol' => ['PHP/8.0.30', 'VULNERABLE'],
			'php 8.1 eol' => ['PHP/8.1.31', 'VULNERABLE'],
			'php 8.2 vulnerable' => ['PHP/8.2.30', 'VULNERABLE'],
			'php 8.2 fixed' => ['PHP/8.2.35', 'FIXED'],
			'php 8.3 vulnerable' => ['PHP/8.3.20', 'VULNERABLE'],
			'php 8.3 fixed' => ['PHP/8.3.36', 'FIXED'],
			'php 8.4 vulnerable' => ['PHP/8.4.26', 'VULNERABLE'],
			'php 8.4 fixed' => ['PHP/8.4.27', 'FIXED'],
			'php 8.5 vulnerable' => ['PHP/8.5.11', 'VULNERABLE'],
			'php 8.5 fixed' => ['PHP/8.5.12', 'FIXED'],
			'php 9.0 unknown' => ['PHP/9.0.0', null],
			'with suffix' => ['PHP/8.3.20 (cli)', 'VULNERABLE'],
		];
	}

	/**
	 * @dataProvider cases
	 */
	public function testAgainst(string $header, ?string $expected): void
	{
		self::assertSame($expected, VersionCheck::against($header));
	}
}
