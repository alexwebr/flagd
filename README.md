flagd
=====

In 'hacker CTF' challenges, participants must crack into various systems and recover
'flags' (keys) to prove that they have completed a challenge. flagd allows participants to
turn in these flags without any administrator effort (beyond an initial configuration) in
a simple, standardized way.

flagd logs captures to a file different from other logs - if you want to make a show of your
CTF challenge, just `tailf` this log file and hook up your machine to a projector.

Assumptions made by flagd
-----------------------
Keys (the things that teams are trying to recover) are strings of arbitrary length, that are
secret an unguessable.
A good candidate for a key is `head -c 100 /dev/urandom | sha256sum`

Participants are organized into teams

MD5 is not so terrible that the output of MD5(TEAM:KEY), where TEAM is known, allows for recovery of KEY in any reasonable amount of time.

Teams know how to use netcat, md5sum, etc.

The protocol
----------
When a team finds a key, they produce the following hash: MD5(TEAM_NAME:KEY), and they
send it as a simple UDP datagram to the flagd server. The flagd server responds with a
message (on the same port the client sent the packet from), indicating that the key was
captured, or not.

In bash:
`echo -n "MyTeamName:"$(cat keyfile) | md5sum | nc -u <ip> <port>

How it works
-------------
flagd calculates all of the hashes for all of the configured team:key combinations.
When a user submits an MD5 hash, that's used as an key into a hash table - if it matches,
it's a valid key for SOME combination of key and team - the value pointed to in the hash
table has that information. This makes flagd very fast. The use of hashtables in this way
also prevents many timing attacks.

flagd prevents brute force attacks by allowing an IP to make one submission per X number
(the value is configurable) of seconds - exceeding this rate prevents any submissions from
being processed.

flagd uses an all-Lua configuration file, and the program itself is also written in Lua.
It requires Luasocket and liblua-md5.
