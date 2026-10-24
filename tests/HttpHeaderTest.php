<?php

declare(strict_types=1);

namespace Php2Shell\Tests;

use Php2Shell\Http\HttpResult;
use PHPUnit\Framework\TestCase;

final class HttpHeaderTest extends TestCase
{
	public function testPoweredByIsCaseInsensitive(): void
	{
		$r = new HttpResult(headers: ['x-POWERED-by' => 'PHP/8.3.20']);
		self::assertSame('PHP/8.3.20', $r->poweredBy());
	}

	public function testHeaderLookupIsCaseInsensitive(): void
	{
		$r = new HttpResult(headers: ['Content-Type' => 'text/html']);
		self::assertSame('text/html', $r->header('content-type'));
		self::assertSame('', $r->header('nonexistent'));
	}
}
