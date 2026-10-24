<?php

declare(strict_types=1);

namespace Php2Shell\Detection;

use Php2Shell\Http\HttpResult;

final class Verdict
{
	public const REJECTED_STATUSES = [400, 403, 411, 413, 414, 417, 422, 429, 431];

	/**
	 * @return array{0:?string,1:?string} [detectedSapi, signal]
	 */
	public static function crashSignal(
		HttpResult $control,
		HttpResult $probe,
		string $sapi,
	): array {
		if (str_contains($probe->body, 'Allowed memory size of ')
			&& str_contains($probe->body, ' bytes exhausted')
			&& str_contains($probe->body, 'Unknown')
		) {
			$mode = match ($sapi) {
				'fpm' => 'PHP-FPM',
				'mod_php' => 'mod_php',
				default => 'mod_php/PHP-FPM',
			};
			return [$mode, 'in-band PHP fatal error (memory exhausted in Unknown) '
				. 'raised while parsing the multipart body'];
		}

		if ($probe->statusCode === 500 && $control->body !== '' && $probe->body === '') {
			$mode = match ($sapi) {
				'fpm' => 'PHP-FPM',
				'mod_php' => 'mod_php',
				default => 'mod_php/PHP-FPM',
			};
			return [$mode, 'HTTP 500 with an empty body although the control '
				. 'request produced output'];
		}

		if ($sapi === 'mod_php') {
			return [null, null];
		}

		if (in_array($probe->statusCode, [502, 503, 504], true)) {
			return ['PHP-FPM', "HTTP {$probe->statusCode} from the web server "
				. 'fronting PHP-FPM (worker died mid-request)'];
		}
		if ($probe->statusCode === 200 && $control->body !== '' && $probe->body === '') {
			return ['PHP-FPM', 'HTTP 200 with an empty body although the control '
				. 'request produced output (worker died mid-request)'];
		}
		return [null, null];
	}
}
