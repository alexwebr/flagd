flagd
=====

In 'hacker CTF' challenges, participants must crack into various systems and recover
flags (simply hard-to-guess strings) to prove that they have completed a challenge. flagd allows participants to
turn in these flags without any administrator effort (beyond an initial configuration) in
a simple, standardized way.

flagd logs captures to a file different from other logs - if you want to make a show of your
CTF challenge, just `tailf` this log file and hook up your machine to a projector.

Assumptions made by flagd
-----------------------
Flags (the things that teams are trying to recover) are strings of arbitrary length, that are
secret and unguessable.
A good candidate for a flag is `head -c 100 /dev/urandom | sha256sum`

Participants are organized into teams

MD5 is not so terrible that the output of MD5(TEAM_NAME:TEAM_PASS:FLAG_STRING), where TEAM_NAME is known, allows for recovery of FLAG_STRING or TEAM_PASS in any reasonable amount of time.

Teams know how to use netcat, md5sum, etc.

The protocol
----------
When a team finds a flag, they produce the following hash: MD5(TEAM_NAME:TEAM_PASS:FLAG_STRING), and they
send it as a simple UDP datagram to the flagd server. The flagd server responds with a
message (on the same port the client sent the packet from), indicating that the flag was
captured (or not)

In bash:
`echo -n "MyTeamName:hunter2:flag_string" | md5sum | nc -u <ip> <port>`

How it works
-------------
flagd calculates all of the hashes for all of the configured team_name:team_pass:flag_string combinations.
When a user submits an MD5 hash, it's used as a key into a hash table - if it matches,
it's a valid flag for _some_ flag - the value pointed to in the hash
table is a Lua table that has that information. This makes flagd very fast. The use of hash tables in this way
also prevents many timing attacks.

flagd prevents brute force attacks by allowing an IP to make one submission per X number
(the value is configurable) of seconds.

flagd uses an all-Lua configuration file, and the program itself is also written in Lua.
It requires Luasocket and liblua-md5.
