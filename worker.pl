use strict;
use warnings;
use utf8;

use Log::Minimal;
use AnyEvent;

use File::Spec;
use File::Basename 'dirname';
use lib (
    File::Spec->catdir(dirname(__FILE__), 'lib'),
    File::Spec->catdir(dirname(__FILE__), 'local', 'lib'),
    glob(File::Spec->catdir(dirname(__FILE__), 'submodule', '*', 'lib')),
);
use Unruly;
use Net::Whois::Parser;

sub fetch {
    my $value = shift; 
    ref $value eq 'ARRAY' ? $value->[0] : $value;
}

sub work {
    my ($target) = @_;

    my $info = parse_whois(domain => $target);

    my $cidr = fetch($info->{cidr}) || 'unknown';
    my $city = fetch($info->{city}) || 'unknown city';
    my $country = fetch($info->{country}) || 'unknown country';
    my $descr = fetch($info->{descr}) || 'unknown descr';

    sprintf('[CIDR: %s] %s %s %s', $cidr, $city, $country, $descr);
}


my $bot_name = 'whois';

my $bot = Unruly->new(
    url  => 'http://yancha.hachiojipm.org',
    tags => {BOT => 1},
    ping_intervals => 15,
);

unless( $bot->login($bot_name) ) {
    critf('Login failure');
    exit;
}

my $cv = AnyEvent->condvar;

$bot->run(sub {
    my ($client, $socket) = @_;

    infof('runnings at pid %s', $$);

    $socket->on('user message' => sub {
        my ($_socket, $message) = @_;

        if ($message->{is_message_log}) {
            ### ++などに反応させたい場合はここにロジックを書く
        }
        else {
            unless ($message->{nickname} eq $bot_name) {
                infof('received "%s" (from:%s)', $message->{text}, $message->{nickname});

                my $text = $message->{text};
                $text =~ s/\A\[NoRec\] //;
                my ($target) = $text =~ /\Awhois (.+)/;
                ($target) = split('\s', $target); 
                infof('target = %s', $target);

                my $response = work($target);
                $bot->hidden_post($response, @{$message->{tags}});
            }
        }
    });

});

$cv->wait;


