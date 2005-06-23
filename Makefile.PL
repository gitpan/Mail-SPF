use 5.006;
use ExtUtils::MakeMaker;

if (0) {
# Thanks to YAML
my @programs = ();
for (split "\n", <<'QUERIES') {
srs|y|SRS command line interface
srsd|y|SRS address translation daemon
srsc|y|SRS daemon commandline client
QUERIES
	my ($program, $default, $description) = split /\|/, $_;
	if (prompt("Do you want to install '$program', the $description?", 
			   $default) =~ /^y/) {
		push(@programs, $program);
	}
}
}

WriteMakefile(
    'NAME'		=> 'Mail::SPF',
    'VERSION_FROM'	=> 'lib/Mail/SPF.pm', # finds $VERSION
    'PREREQ_PM'		=> {
				'Test::More'		=> 0.40,
				'Net::DNS'			=> 0,
				'Carp'				=> 0,
				'Exporter'			=> 0,
				'Getopt::Long'		=> 2.30,
			}, # e.g., Module::Name => 1.1
	ABSTRACT_FROM => 'lib/Mail/SPF.pm', # retrieve abstract from module
	AUTHOR     => 'Shevek <cpan@anarres.org>',
	# EXE_FILES	=> \@programs,
	clean		=> { FILES => 'test.db' },
);

sub MY::postamble {
	my $self = shift;
	my $old = $self->MM::postamble(@_);
	chomp($old);
	my $new = <<'EON';

.PHONY : aux readme

aux : readme

readme : lib/Mail/SPF.pm
	perldoc -t lib/Mail/SPF.pm > README

EON
	return $old . $new;
}
