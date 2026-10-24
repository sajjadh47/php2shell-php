<?php

declare(strict_types=1);

namespace Php2Shell\Http;

final class HttpResult
{
	public readonly ?int $statusCode;
	public readonly string $reason;

	/** @var array<string,string> */
	public readonly array $headers;

	public readonly string $body;
	public readonly int $bytesSent;
	public readonly ?string $error;

	/**
	 * @param array<string,string> $headers
	 */
	public function __construct(
		?int $statusCode = null,
		string $reason = '',
		array $headers = [],
		string $body = '',
		int $bytesSent = 0,
		?string $error = null,
	) {
		$this->statusCode = $statusCode;
		$this->reason = $reason;
		$this->headers = $headers;
		$this->body = $body;
		$this->bytesSent = $bytesSent;
		$this->error = $error;
	}

	public function poweredBy(): string
	{
		foreach ($this->headers as $name => $value) {
			if (strcasecmp($name, 'x-powered-by') === 0) {
				return $value;
			}
		}
		return '';
	}

	public function header(string $name): string
	{
		foreach ($this->headers as $key => $value) {
			if (strcasecmp($key, $name) === 0) {
				return $value;
			}
		}
		return '';
	}
}
