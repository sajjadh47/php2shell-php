<?php

declare(strict_types=1);

namespace Php2Shell\Http;

use Amp\CancelledException;
use Amp\Http\Client\Connection\DefaultConnectionFactory;
use Amp\Http\Client\Connection\UnlimitedConnectionPool;
use Amp\Http\Client\HttpClient;
use Amp\Http\Client\HttpClientBuilder;
use Amp\Http\Client\Request;
use Amp\Http\Client\Response;
use Amp\Socket\ClientTlsContext;
use Amp\Socket\ConnectContext;
use Amp\TimeoutCancellation;
use Php2Shell\Detection\ProbeBuilder;
use Php2Shell\Detection\Verdict;
use Php2Shell\Detection\VersionCheck;
use Php2Shell\Target\Target;

final class Scanner
{
	private const BODY_READ_LIMIT = 1 << 20;
	private const PHPMYADMIN_PATH = '/show_config_errors.php';
	private const PHPMYADMIN_MARKER = 'phpMyAdmin';
	private const RESPONSE_EXCERPT = 2048;
	private const DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
		. 'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 '
		. 'Safari/537.36 PHP2Shell-php/1.0.0';
	private const SENSITIVE_HEADERS = [
		'authorization',
		'cookie',
		'proxy-authorization',
		'set-cookie',
		'x-api-key',
	];

	private HttpClient $client;
	private int $timeout;
	private string $sapi;

	/** @var array<string,string> */
	private array $customHeaders;

	/**
	 * @param array<string,string> $customHeaders
	 */
	public function __construct(
		HttpClient $client,
		int $timeout = 60,
		string $sapi = 'auto',
		array $customHeaders = [],
	) {
		$this->client = $client;
		$this->timeout = $timeout;
		$this->sapi = $sapi;
		$this->customHeaders = $customHeaders;
	}

	/**
	 * @param array<string,string> $customHeaders
	 */
	public static function build(
		int $timeout = 60,
		string $sapi = 'auto',
		array $customHeaders = [],
		bool $followRedirects = false,
		bool $insecure = false,
	): self {
		$builder = (new HttpClientBuilder())
			->retry(0)
			->followRedirects($followRedirects ? 10 : 0)
			->intercept(new StripSensitiveOnCrossOrigin());

		if ($insecure) {
			$tls = (new ClientTlsContext(''))->withoutPeerVerification();
			$connect = (new ConnectContext())->withTlsContext($tls);
			$builder = $builder->usingPool(
				new UnlimitedConnectionPool(new DefaultConnectionFactory(null, $connect)),
			);
		}

		return new self($builder->build(), $timeout, $sapi, $customHeaders);
	}

	/**
	 * @return array<string,mixed>
	 */
	public function check(Target $target): array
	{
		/** @var list<array<string,mixed>> $probes */
		$probes = [];
		$result = [
			'host' => $target->label(),
			'vulnerable' => null,
			'verdict' => 'ERROR',
			'status_code' => null,
			'error' => null,
			'reason' => null,
			'sapi' => null,
			'powered_by' => null,
			'tested_url' => $target->url(),
			'final_url' => $target->url(),
			'control' => null,
			'probes' => $probes,
			'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
		];

		$control = $this->post($target, ProbeBuilder::CONTROL_BODY, ProbeBuilder::CONTROL_BOUNDARY);
		$result['control'] = $this->metadata($control);
		$this->apply($result, $control);

		if ($control->error !== null) {
			$result['error'] = 'control request failed: ' . $control->error;
			$result['reason'] = $result['error'];
			$result['probes'] = $probes;
			return $result;
		}
		if ($control->statusCode !== null && $control->statusCode >= 500) {
			$result['verdict'] = 'INCONCLUSIVE';
			$result['error'] = "control request returned HTTP {$control->statusCode}";
			$result['reason'] = $result['error'];
			$result['probes'] = $probes;
			return $result;
		}

		if (stripos($control->body, self::PHPMYADMIN_MARKER) !== false) {
			$target = $target->withPath(self::PHPMYADMIN_PATH);
			$result['final_url'] = $target->url();
			$control = $this->post($target, ProbeBuilder::CONTROL_BODY, ProbeBuilder::CONTROL_BOUNDARY);
			$result['control'] = $this->metadata($control);
			$this->apply($result, $control);
			if ($control->error !== null) {
				$result['error'] = 'phpMyAdmin control request failed: ' . $control->error;
				$result['reason'] = $result['error'];
				$result['probes'] = $probes;
				return $result;
			}
		}

		$poweredBy = $control->poweredBy();
		$rejected = null;

		foreach (ProbeBuilder::PROBES as $i => [$sizeMiB, $parts]) {
			$index = $i + 1;
			$body = ProbeBuilder::build($sizeMiB, $parts);
			$probe = $this->post($target, $body, ProbeBuilder::PROBE_BOUNDARY);

			$meta = $this->metadata($probe);
			$meta['probe'] = $index;
			$meta['size_mib'] = $sizeMiB;
			$meta['parts'] = $parts;
			$probes[] = $meta;
			$result['probes'] = $probes;
			$this->apply($result, $probe);

			if ($probe->poweredBy() !== '') {
				$poweredBy = $probe->poweredBy();
			}
			$result['powered_by'] = $poweredBy !== '' ? $poweredBy : null;

			if ($probe->error !== null) {
				$result['verdict'] = 'INCONCLUSIVE';
				$result['error'] = "probe {$index} failed before a response was read: {$probe->error}";
				$result['reason'] = $result['error'];
				return $result;
			}

			if (in_array($probe->statusCode, Verdict::REJECTED_STATUSES, true)) {
				$rejected = "probe {$index} was rejected with HTTP {$probe->statusCode} before PHP parsed it";
				break;
			}

			[$detectedSapi, $signal] = Verdict::crashSignal($control, $probe, $this->sapi);
			if ($signal !== null) {
				$result['vulnerable'] = true;
				$result['verdict'] = 'VULNERABLE';
				$result['sapi'] = $detectedSapi;
				$result['reason'] = "probe {$index} ({$sizeMiB} MiB, {$parts} parts) "
					. "crashed the request handler: {$signal}";
				return $result;
			}

			if (VersionCheck::against($poweredBy) === 'FIXED') {
				$result['vulnerable'] = false;
				$result['verdict'] = 'FIXED';
				$result['reason'] = 'no crash observed and X-Powered-By reports '
					. 'a patched release: ' . $poweredBy;
				return $result;
			}
		}

		$byVersion = VersionCheck::against($poweredBy);
		if ($byVersion === 'VULNERABLE') {
			$result['vulnerable'] = true;
			$result['verdict'] = 'VULNERABLE';
			$result['sapi'] = match ($this->sapi) {
				'auto' => 'unknown',
				'fpm' => 'PHP-FPM',
				default => 'mod_php',
			};
			$result['reason'] = 'no crash observed; X-Powered-By reports an '
				. 'unpatched release: ' . $poweredBy;
		} elseif ($byVersion === 'FIXED') {
			$result['vulnerable'] = false;
			$result['verdict'] = 'FIXED';
			$result['reason'] = 'no crash observed and X-Powered-By reports '
				. 'a patched release: ' . $poweredBy;
		} elseif ($rejected !== null) {
			$result['verdict'] = 'INCONCLUSIVE';
			$result['error'] = $rejected;
			$result['reason'] = $rejected;
		} else {
			$result['vulnerable'] = false;
			$result['verdict'] = 'NO SIGNAL';
			$result['reason'] = 'no crash observed and no PHP version advertised';
		}
		$result['probes'] = $probes;
		return $result;
	}

	private function post(Target $target, string $body, string $boundary): HttpResult
	{
		$request = new Request($target->url(), 'POST', $body);
		$request->setHeader('Content-Type', "multipart/form-data; boundary={$boundary}");
		$request->setHeader('Connection', 'close');
		$request->setHeader('Accept-Encoding', 'identity');

		$userAgent = self::DEFAULT_UA;
		foreach ($this->customHeaders as $name => $value) {
			$lower = strtolower($name);
			if (in_array($lower, ['content-length', 'transfer-encoding', 'content-type', 'connection', 'accept-encoding'], true)) {
				continue;
			}
			if ($lower === 'user-agent') {
				$userAgent = $value;
				continue;
			}
			if ($name === '') {
				continue;
			}
			$request->setHeader($name, $value);
		}
		$request->setHeader('User-Agent', $userAgent);
		$request->setBodySizeLimit(self::BODY_READ_LIMIT);

		$cancellation = new TimeoutCancellation($this->timeout);

		try {
			$response = $this->client->request($request, $cancellation);
			return $this->fromResponse($response, strlen($body));
		} catch (CancelledException) {
			return new HttpResult(bytesSent: strlen($body), error: 'request timed out');
		} catch (\Throwable $e) {
			return new HttpResult(bytesSent: strlen($body), error: $e->getMessage());
		}
	}

	private function fromResponse(Response $response, int $bytesSent): HttpResult
	{
		try {
			$body = $response->getBody()->buffer();
		} catch (\Throwable $e) {
			return new HttpResult(
				statusCode: $response->getStatus(),
				reason: $response->getReason(),
				headers: $this->flattenHeaders($response),
				bytesSent: $bytesSent,
				error: 'response read failed: ' . $e->getMessage(),
			);
		}
		return new HttpResult(
			statusCode: $response->getStatus(),
			reason: $response->getReason(),
			headers: $this->flattenHeaders($response),
			body: $body,
			bytesSent: $bytesSent,
		);
	}

	/**
	 * @return array<string,string>
	 */
	private function flattenHeaders(Response $response): array
	{
		$out = [];
		foreach ($response->getHeaders() as $name => $values) {
			/** @var string $name */
			$out[$name] = implode(', ', $values);
		}
		return $out;
	}

	/**
	 * @param array<string,mixed> $result
	 */
	private function apply(array &$result, HttpResult $response): void
	{
		$result['status_code'] = $response->statusCode;
		if ($response->statusCode === null) {
			return;
		}
		$lines = ["HTTP/1.1 {$response->statusCode} {$response->reason}"];
		foreach (array_keys($response->headers) as $name) {
			$value = $response->headers[$name];
			if (in_array(strtolower($name), self::SENSITIVE_HEADERS, true)) {
				$value = '<redacted>';
			}
			$lines[] = "{$name}: {$value}";
		}
		$excerpt = substr($response->body, 0, self::RESPONSE_EXCERPT);
		$result['response'] = implode("\r\n", $lines) . "\r\n\r\n" . $excerpt;
	}

	/**
	 * @return array<string,mixed>
	 */
	private function metadata(HttpResult $r): array
	{
		return [
			'status_code' => $r->statusCode,
			'response_bytes' => strlen($r->body),
			'bytes_sent' => $r->bytesSent,
			'error' => $r->error,
			'description' => $r->error !== null
				? "request failed after sending {$r->bytesSent} bytes: {$r->error}"
				: "HTTP {$r->statusCode}, " . strlen($r->body)
					. " byte response (sent {$r->bytesSent} bytes)",
		];
	}
}
