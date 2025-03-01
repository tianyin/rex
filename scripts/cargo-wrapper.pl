#!/usr/bin/env perl

use strict;
use warnings;

my ($build_dir, @cmd) = @ARGV;
my $cargo_bin = "$build_dir/cargo";

exec($cargo_bin, @cmd);
