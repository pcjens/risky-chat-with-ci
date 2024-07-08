# Risky Chat

Risky Chat is a global chatroom implemented as a web
application, for the [Cyber Security Base 2020 course][course].

Users identify themselves by a unique name which expires after the
user has not posted anything in 5 minutes, making a nice tradeoff
between transient identity and anonymity, and being able to ensure two
sequential posts are from the same person.

## Fullstack Part 11 (CI/CD) note

This is a copy of the [pcjens/risky-chat](https://github.com/pcjens/risky-chat)
repository for the purposes of the CI/CD course, with the following steps done
in a GitHub Actions workflow:
- Code formatting is checked against clang-format.
- The code is built, with warnings as errors to serve as a linting step.
- The code is tested by the testing script [test.sh](test.sh), which starts up
  the application and makes a few requests to it to ensure that a user can enter
  the chat, post something, and see it appear.
  - There's no unit tests, since the code is quite messy, and I think these e2e
    tests are quite enough for the purposes of the exercise. See below anecdote
    for where I already spent hours!
- Unless skipped by including "#skip" in the commit message, the code is
  additionally built, tagged as a new version, and deployed at:
  <https://risky-chat-8f8d4484.fly.dev/>
- Notably, there's no discord notifications since I'd rather not publicize the
  deployment URL further (the chat app *is* entirely unrestricted and public).
  And I think they are trivial enough to add that I don't think that their
  omission is a big issue.

The main repository for the CI/CD course is
[pcjens/full-stack-open-pokedex](https://github.com/pcjens/full-stack-open-pokedex).

As a fun anecdote, I did run into some issues that the exercise description
warned about, regarding "legacy code"! When I wrote this server for the cyber
security course, I only tested it locally, probably only on Firefox, so I had
entirely forgotten that the header handling code (much like... basically all of
the code) was very naive, in this case comparing header names
*case-sensitively*.

This led to very odd issues in fly.io where the app launched and seemed to work
initially, but you couldn't log in. Turns out, since the app wasn't reading the
headers correctly, it couldn't read the Content-Length, and assumed that the
login form simply sent an empty body, and this eventually resulted in the server
crashing from a *malloc* failing! I think the malloc failed due to the size
being passed to it being "-5", thanks to some intentionally non-defensive code
assuming that you'd send it a properly formatted body with the /login request.
That was a tough one to debug!

## Important security note

This application has intentionally designed security risks, including
one very major one: being implemented in C without using any tools or
checks to ensure secure memory management. Avoid this.

## Why C?

It's the one time I can write an incredibly insecure server in C with
a good conscience. Ignoring the numerous security risks it raises, C
is a really fun programming language to use.

## Building and running

Requirements:

- a C compiler
- one of the following:
  - a POSIX.1-2001 compliant system (e.g. Linux, probably macOS)
  - a system with winsock2 (e.g. Windows)

Just compile [riskychat.c](riskychat.c) into an executable. Basic
example:

```shell
# Build with cc:
cc -o riskychat riskychat.c
# Run:
./riskychat
```

Risky Chat also compiles with TCC, so you can run it like a script if
you have [tcc][tcc]:

```shell
# Compile and run (doesn't leave an executable lying around):
tcc -run riskychat.c
```

For development, I use the following incantation:

```shell
# Enable a lot of warnings and whatever static analysis is available, and create a static binary.
# Runs on Arch Linux with the community/musl package. Build:
musl-gcc -static -std=c89 -Wall -Werror -Wpedantic -fanalyzer -O3 -o riskychat riskychat.c
# Run:
./riskychat
```

Finally, compiling for Windows works too, simply run the following in
a Developer Command Prompt (from a Visual Studio installation):

```batchfile
REM Build:
cl.exe /Feriskychat riskychat.c
REM Run:
riskychat.exe
```

## Some notes

Here's some general notes about the program, so you don't need to
figure this out by reverse engineering or wading through the code:

- Connection handling is very simple, there's no keep-alive, the TCP
  connection is closed after delivering the response. This just made
  the implementation simpler, but keep-alive could be added in without
  too much effort.
- The networking code uses [Berkeley
  sockets](https://en.wikipedia.org/wiki/Berkeley_sockets) as
  standardized by POSIX, but does not use
  [select()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/select.html).
  Instead, it just keeps calling
  [accept()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html),
  [recv()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html),
  and
  [send()](https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html)
  with a very short timeout (1 microsecond). Surprisingly enough, this
  doesn't seem to hog the CPU that badly, at least on my system.
- For some reason, SIGPIPEs seem to be prevalent. I don't know why, but I
  didn't have time to fix them either. The server probably closes the
  socket too soon in some cases.

## License

This software is distributed under the [GNU AGPL 3.0][license]
license. Though I really recommend against using it, it's very
insecure.

[course]: https://cybersecuritybase.mooc.fi/
[license]: LICENSE.md
[tcc]: https://bellard.org/tcc/
