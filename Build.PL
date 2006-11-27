#
# Module::Build build script for Mail::SPF
#
# (C) 2005-2006 Julian Mehnle <julian@mehnle.net>
# $Id: Build.PL 28 2006-11-19 20:58:45Z Julian Mehnle $
#
##############################################################################

use Module::Build 0.26;
use version;

my $class = Module::Build->subclass( code => <<'EOF' );

    sub process_extra_files {
        my ($self, $dir) = @_;
        $dir ||= $element;
        File::Find::find(
            {
                wanted      => sub {
                    $File::Find::prune = 1 if -d and /\.svn$/;  # Exclude .svn/ dirs.
                    return if not -f;                           # Handle files only.
                    
                    my $destination = $self->copy_if_modified(
                        from    => $File::Find::name,
                        to      => File::Spec->catfile($self->blib, $File::Find::name)
                    );
                    return if not defined($destination);        # Already up to date?
                    
                    chmod((stat($File::Find::name))[2], $destination)
                        or warn("Cannot set permissions on $destination: $!");
                },
                no_chdir    => 1
            },
            $dir
        );
    }
    
    sub process_sbin_files    { shift->process_extra_files('sbin')    }

EOF

my $build = $class->new(
    module_name     => 'Mail::SPF',
    dist_author     => [
        'Julian Mehnle <julian@mehnle.net>',
        'Shevek <cpan@anarres.org>'
    ],
    license         => 'bsd',
    requires        => {
        # Core requirements:
        perl            => '5.006',
        version         => 0,
        Getopt::Long    => 0,
        Error           => 0,
        NetAddr::IP     => '4.0',
        Net::DNS        => '0.58',
        URI             => '1.13'
    },
    recommends      => {
    },
    build_requires  => {
        # Build requirements:
        Module::Build   => '0.26',
        Test::More      => 0,
        Net::DNS::Resolver::Programmable
                        => qv('0.002.1')->numify,
    },
    script_files    => [
        'bin/spfquery'
    ],
    install_path    => {
        'sbin'          => '/usr/sbin'
    },
    create_makefile_pl
                    => 'passthrough',
    sign            => 1
);

$build->add_build_element($_)
    foreach qw(sbin);

$build->create_build_script();
