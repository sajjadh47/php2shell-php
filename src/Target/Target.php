<?php

declare(strict_types=1);

namespace Php2Shell\Target;

final class Target
{
	public const DEFAULT_PATH = '/index.php';

	public function __construct(
		public readonly string $scheme,
		public readonly string $host,
		public readonly int $port,
		public readonly string $path = self::DEFAULT_PATH,
		public readonly string $query = '',
	) {
	}

	public static function fromUrl(string $raw): self
	{
		$raw = trim($raw);
		if ($raw === '') {
			throw new \InvalidArgumentException('invalid or empty URL');
		}
		if (!str_contains($raw, '://')) {
			$raw = 'https://' . $raw;
		}

		$parts = parse_url($raw);
		if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
			throw new \InvalidArgumentException('invalid HTTP URL');
		}
		$scheme = strtolower($parts['scheme']);
		if (!in_array($scheme, ['http', 'https'], true)) {
			throw new \InvalidArgumentException('invalid HTTP URL');
		}
		if (isset($parts['user']) || isset($parts['pass'])) {
			throw new \InvalidArgumentException(
				'credentials in URLs are not supported; use an Authorization header',
			);
		}
		$path = $parts['path'] ?? '';
		if ($path === '' || $path === '/') {
			$path = self::DEFAULT_PATH;
		}
		$port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

		return new self($scheme, $parts['host'], (int) $port, $path, $parts['query'] ?? '');
	}

	public function withPath(string $path): self
	{
		return new self($this->scheme, $this->host, $this->port, $path, '');
	}

	public function url(): string
	{
		$authority = $this->host;
		if (($this->scheme === 'https' && $this->port !== 443)
			|| ($this->scheme === 'http' && $this->port !== 80)) {
			$authority .= ':' . $this->port;
		}
		$url = $this->scheme . '://' . $authority . $this->path;
		if ($this->query !== '') {
			$url .= '?' . $this->query;
		}
		return $url;
	}

	public function label(): string
	{
		return $this->url();
	}
}
