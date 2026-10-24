<?php

declare(strict_types=1);

namespace Php2Shell\Tests;

use Php2Shell\Detection\Verdict;
use Php2Shell\Http\HttpResult;
use PHPUnit\Framework\TestCase;

final class VerdictTest extends TestCase
{
	public function testInBandMemoryErrorIsModPhp(): void
	{
		$probe = new HttpResult(
			statusCode: 200,
			body: 'Fatal error: Allowed memory size of 134217728 bytes exhausted '
				. '(tried to allocate 20480 bytes) in Unknown on line 0',
		);
		[$sapi, $signal] = Verdict::crashSignal(
			new HttpResult(statusCode: 200, body: 'ok'),
			$probe,
			'auto',
		);
		self::assertSame('mod_php/PHP-FPM', $sapi);
		self::assertStringContainsString('memory exhausted', (string) $signal);
	}

	public function testEmpty500IsSignal(): void
	{
		[$sapi, $signal] = Verdict::crashSignal(
			new HttpResult(statusCode: 200, body: 'ok'),
			new HttpResult(statusCode: 500, body: ''),
			'fpm',
		);
		self::assertSame('PHP-FPM', $sapi);
		self::assertNotNull($signal);
	}

	public function testFpm503IsSignal(): void
	{
		[$sapi, $signal] = Verdict::crashSignal(
			new HttpResult(statusCode: 200, body: 'ok'),
			new HttpResult(statusCode: 503, body: ''),
			'auto',
		);
		self::assertSame('PHP-FPM', $sapi);
		self::assertStringContainsString('503', (string) $signal);
	}

	public function testModPhpSkipsFpmHeuristics(): void
	{
		[$sapi, $signal] = Verdict::crashSignal(
			new HttpResult(statusCode: 200, body: 'ok'),
			new HttpResult(statusCode: 503, body: ''),
			'mod_php',
		);
		self::assertNull($sapi);
		self::assertNull($signal);
	}

	public function testNormalResponseIsNotSignal(): void
	{
		[$sapi, $signal] = Verdict::crashSignal(
			new HttpResult(statusCode: 200, body: 'ok'),
			new HttpResult(statusCode: 200, body: 'ok'),
			'auto',
		);
		self::assertNull($sapi);
		self::assertNull($signal);
	}

	public function testRejectedStatusesAreCovered(): void
	{
		self::assertContains(400, Verdict::REJECTED_STATUSES);
		self::assertContains(413, Verdict::REJECTED_STATUSES);
		self::assertContains(429, Verdict::REJECTED_STATUSES);
	}
}
