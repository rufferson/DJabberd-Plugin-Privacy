#!/usr/bin/perl
use 5.008;
use ExtUtils::MakeMaker;
WriteMakefile(
	NAME => 'DJabberd::Plugin::Privacy',
	VERSION_FROM => 'lib/DJabberd/Plugin/Privacy.pm',
	ABSTRACT_FROM => 'lib/DJabberd/Plugin/Privacy.pm',
	PREREQ_PM => {
		'DJabberd' => '0.85',
	},
	AUTHOR => 'Ruslan N. Marchenko <me@ruff.mobi>',
);
