<?php

declare(strict_types=1);

namespace Php2Shell\Tests;

use Php2Shell\Detection\ProbeBuilder;
use PHPUnit\Framework\TestCase;

final class ProbeBuilderTest extends TestCase
{
	public function testControlBodyIsExact(): void
	{
		$expected = "--x\nContent-Disposition:name=a;filename=\n\n";
		self::assertSame($expected, ProbeBuilder::CONTROL_BODY);
	}

	/**
	 * @dataProvider probeSizes
	 */
	public function testProbeHasExpectedSize(int $sizeMiB, int $parts): void
	{
		$body = ProbeBuilder::build($sizeMiB, $parts);
		self::assertSame($sizeMiB << 20, strlen($body));
	}

	/**
	 * @dataProvider probeSizes
	 */
	public function testProbeStartsWithBoundaryPrefix(int $sizeMiB, int $parts): void
	{
		$body = ProbeBuilder::build($sizeMiB, $parts);
		self::assertSame("--\nx:\n", substr($body, 0, 6));
	}

	/**
	 * @dataProvider probeSizes
	 */
	public function testProbeEndsWithSingleNewline(int $sizeMiB, int $parts): void
	{
		$body = ProbeBuilder::build($sizeMiB, $parts);
		self::assertSame("\n", substr($body, -1), 'final byte must be a single newline');
		self::assertNotSame(
			"\n",
			substr($body, -2, 1),
			'the second-to-last byte must not be a newline',
		);
	}

	/**
	 * @dataProvider probeSizes
	 */
	public function testProbeContainsNestedKeys(int $sizeMiB, int $parts): void
	{
		$body = ProbeBuilder::build($sizeMiB, $parts);
		$nested = 'a[]' . str_repeat('[a]', ProbeBuilder::NESTED_KEYS);
		$needle = "Content-Disposition:name={$nested};filename=";
		self::assertTrue(
			str_contains($body, $needle),
			'probe body must contain the nested multipart part header',
		);
	}

	/**
	 * @dataProvider probeSizes
	 */
	public function testProbePartCount(int $sizeMiB, int $parts): void
	{
		$body = ProbeBuilder::build($sizeMiB, $parts);
		$nested = 'a[]' . str_repeat('[a]', ProbeBuilder::NESTED_KEYS);
		$needle = "Content-Disposition:name={$nested};filename=";
		self::assertSame($parts, substr_count($body, $needle));
	}

	public function testNestedKeyCountMatches(): void
	{
		self::assertSame(62, ProbeBuilder::NESTED_KEYS);
	}

	public function testProbesListMatches(): void
	{
		self::assertSame([[1, 4000], [8, 1020], [20, 1020]], ProbeBuilder::PROBES);
	}

	public function testTooSmallSizeThrows(): void
	{
		$this->expectException(\InvalidArgumentException::class);
		ProbeBuilder::build(0, 4000);
	}

	/** @return array<string,array{int,int}> */
	public static function probeSizes(): array
	{
		return [
			'probe 1' => [1, 4000],
			'probe 2' => [8, 1020],
			'probe 3' => [20, 1020],
		];
	}
}
