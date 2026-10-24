<?php

declare(strict_types=1);

namespace Php2Shell\Http;

use Amp\Cancellation;
use Amp\Http\Client\ApplicationInterceptor;
use Amp\Http\Client\DelegateHttpClient;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;

final class StripSensitiveOnCrossOrigin implements ApplicationInterceptor
{
	private const SENSITIVE = [
		'authorization',
		'cookie',
		'proxy-authorization',
		'x-api-key',
	];

	public function request(
		Request $request,
		Cancellation $cancellation,
		DelegateHttpClient $httpClient,
	): Response {
		$originalHost = $request->getUri()->getHost();
		$response = $httpClient->request($request, $cancellation);

		$status = $response->getStatus();
		if ($status < 300 || $status >= 400) {
			return $response;
		}

		$location = $response->getHeader('location');
		if ($location === null) {
			return $response;
		}

		$nextHost = parse_url($location, PHP_URL_HOST);
		if ($nextHost === null || $nextHost === false || $nextHost === $originalHost) {
			return $response;
		}

		foreach (self::SENSITIVE as $name) {
			$request->removeHeader($name);
		}
		return $response;
	}
}
