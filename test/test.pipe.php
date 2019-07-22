#!/usr/bin/php
<?php

// Test authenticator using pipe method.  Logins will be accepted if the
// login and the password are identical, and will be rejected otherwise.
//
// This authenticator does copious logging by writing all sorts of stuff to
// STDERR.  A production authenticator would not normally do this, and it
// *especially* would not write the plain text password out to the log file.

// Get the name of this program
$prog = $argv[0];

// Get the user name
$user = trim(fgets(STDIN));

// Get the password
$pass = trim(fgets(STDIN));

// Print them to the error_log file
fwrite(STDERR, $prog . ": user='" . $user . "' pass='" . $pass . "'\n");

// NOTE: $_ENV is only populated if the "variables_order" php.ini setting 
//       contains "E". Alternatively use getenv(). See GitHub issue #16.
foreach ($_ENV as $k => $v)
{
	fwrite(STDERR, $prog . ': ' . $k . '=' . $v . "\n");
}

// Accept the login if the user name matchs the password
if ($user == $pass)
{
	fwrite(STDERR, $prog . ": login matches password - Accepted\n");
	exit(0);
}
else
{
	fwrite(STDERR, $prog . ": login doesn't match password - Rejected\n");
	exit(1);
}

?>
