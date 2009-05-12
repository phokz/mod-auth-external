#!/usr/bin/perl -Tw
# MySQL-auth version 1.0
# Anders Nordby <anders@fix.no>, 2002-01-20
# This script is usable for authenticating users against a MySQL database with
# the Apache module mod_auth_external or mod_authnz_external. See
# http://unixpapa.com/mod_auth_external/ for mod_auth_external.
#
# Updates to this script will be made available on:
# http://anders.fix.no/software/#unix

my $dbhost="localhost";
my $dbuser="validator";
my $dbpw="whatagoodpassword";
my $dbname="funkydb";
my $dbport="3306";
my $mychars="01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_,.";

# Below this, only the SQL query should be interesting to modify for users.

use DBI;

sub validchars
{
	# 0: string 1: valid characters
	my $streng = $_[0];

	my $ok = 1;
	my $i = 0;
	while ($ok && $i < length($_[0])) {
		if (index($_[1], substr($_[0],$i,1)) == -1) {
			$ok = 0;
		}
		$i++;
	}
	return($ok);
}

# Get the name of this program
$prog= join ' ',$0,@ARGV;
$logprefix='[' . scalar localtime . '] ' . $prog;

# Get the user name
$user= <STDIN>;
chomp $user;

# Get the password name
$pass= <STDIN>;
chomp $pass;

# check for valid characters
if (!validchars($user, $mychars) || !validchars($pass, $mychars)) {
	print STDERR "$logprefix: invalid characters used in login/password - Rejected\n";
	exit 1;
}

# check for password in mysql database
#if 
my $dbh = DBI->connect("DBI:mysql:database=$dbname:host=$dbhost:port=$dbport",$dbuser,$dbpw,{PrintError=>0});

if (!$dbh) {
	print STDERR "$logprefix: could not connect to database - Rejected\n";
	exit 1;
}

my $dbq = $dbh->prepare("select username as username, password as password from users where username=\'$user\';");
$dbq->execute;
my $row = $dbq->fetchrow_hashref();

if ($row->{username} eq "") {
	print STDERR "$logprefix: could not find user $user - Rejected\n";
	exit 1;
}
if ($row->{password} eq "") {
	print STDERR "$logprefix: empty password for user $user - Rejected\n";
	exit 1;
}

if ($row->{password} eq crypt($pass,substr($row->{password},0,2))) {
	print STDERR "$logprefix: password for user $user matches - Accepted\n";
	exit 0;
} else {
	print STDERR "$logprefix: password for user $user does not match - Rejected\n";
	exit 1;
}

$dbq->finish;
$dbh->disconnect;
