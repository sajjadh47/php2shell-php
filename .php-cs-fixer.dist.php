<?php

declare(strict_types=1);

use PhpCsFixer\Config;
use PhpCsFixer\Finder;

$finder = Finder::create()
	->in([
		__DIR__ . '/src',
		__DIR__ . '/tests',
	])
	->append([__DIR__ . '/bin/php2shell']);

return (new Config())
	// The codebase is tab-indented with Unix line endings; these two calls
	// affect the whitespace *fixers themselves* (array alignment, closing
	// braces, etc.), separately from any rule below.
	->setIndent("\t")
	->setLineEnding("\n")
	->setRiskyAllowed(true)
	->setRules([
		'@PSR12' => true,

		// Risky rules the project already follows (declare(strict_types=1)
		// everywhere, strict comparisons, no loose type juggling in calls).
		'declare_strict_types' => true,
		'strict_comparison' => true,
		'strict_param' => true,

		// Array / string conventions already in use.
		'array_syntax' => ['syntax' => 'short'],
		'single_quote' => true,
		'concat_space' => ['spacing' => 'one'],
		'explicit_string_variable' => true,
		'no_unused_imports' => true,
		'ordered_imports' => [
			'sort_algorithm' => 'alpha',
			'imports_order' => ['class', 'function', 'const'],
		],
		'global_namespace_import' => [
			'import_classes' => false,
			'import_constants' => false,
			'import_functions' => true,
		],
		'trailing_comma_in_multiline' => [
			'elements' => ['arrays', 'arguments', 'parameters', 'match'],
		],
		'binary_operator_spaces' => [
			'default' => 'single_space',
		],
		'blank_line_after_opening_tag' => true,
		'blank_line_after_namespace' => true,
		'no_empty_statement' => true,
		'no_leading_import_slash' => true,
		'no_whitespace_in_blank_line' => true,
		'single_blank_line_at_eof' => true,
		'ternary_to_null_coalescing' => true,
		'method_argument_space' => [
			'on_multiline' => 'ensure_fully_multiline',
			'keep_multiple_spaces_after_comma' => false,
		],
		'class_attributes_separation' => [
			'elements' => [
				'method' => 'one',
				'property' => 'none',
				'const' => 'none',
			],
		],

		// PHPDoc hygiene — keep the array-shape docblocks (e.g.
		// "@return array<string,mixed>") the codebase relies on for
		// phpstan, but don't force alignment changes on every edit.
		'phpdoc_scalar' => true,
		'phpdoc_separation' => true,
		'no_superfluous_phpdoc_tags' => [
			'allow_mixed' => true,
			'remove_inheritdoc' => false,
		],

		// Leave these off: the project intentionally uses named/positional
		// mixes and doesn't follow Yoda conditions or forced native-function
		// prefixing (\strlen() etc.) anywhere in src/.
		'yoda_style' => false,
		'native_function_invocation' => false,
	])
	->setFinder($finder);
