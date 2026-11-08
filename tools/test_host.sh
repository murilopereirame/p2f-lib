#!/usr/bin/env bash
# End-to-end tests of the C client against tools/mock_server.mjs.
set -u
cd "$(dirname "$0")/.."
CLI=build/host/p2f-cli
T=$(mktemp -d)
TOKEN=p2f_testtoken
PORT=18765
URL=http://127.0.0.1:$PORT
PASS=0; FAIL=0
ok()   { echo "PASS  $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL  $1"; FAIL=$((FAIL+1)); }

mkdir -p "$T/root/Show Name/Season 01" "$T/root/empty-dir"
head -c 37        /dev/urandom > "$T/root/small.bin"
head -c 1048581   /dev/urandom > "$T/root/Show Name/Season 01/ep 01 ção.mkv"
head -c 20971520  /dev/urandom > "$T/root/Show Name/Season 01/ep02.mkv"
: > "$T/root/Show Name/zero.txt"
echo "hello" > "$T/root/Show Name/notes & stuff.txt"

flip() { python3 -I -c 'import sys;f=open(sys.argv[1],"r+b");o=int(sys.argv[2]);f.seek(o);b=f.read(1);f.seek(o);f.write(bytes([b[0]^255]))' "$1" "$2"; }
start_server() { env "$@" node tools/mock_server.mjs "$T/root" $PORT $TOKEN >/dev/null 2>&1 & SRV=$!; sleep 0.6; }
stop_server()  { kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; }

# 1. Whole folder.
start_server
$CLI $URL $TOKEN "Show Name" "$T/out1" >/dev/null 2>&1 && diff -r "$T/root/Show Name" "$T/out1/Show Name" >/dev/null \
  && ok "folder download" || bad "folder download"

# 2. Single file, nested path with spaces and UTF-8.
$CLI $URL $TOKEN "Show Name/Season 01/ep 01 ção.mkv" "$T/out2" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep 01 ção.mkv" "$T/out2/ep 01 ção.mkv" \
  && ok "single file" || bad "single file"

# 3. Listing.
$CLI $URL $TOKEN "" x --ls 2>/dev/null | grep -q "small.bin" && ok "listing" || bad "listing"

# 4. Wrong token.
out=$($CLI $URL p2f_wrong small.bin "$T/out4" 2>/dev/null); echo "$out" | grep -q "401" && ok "bad token -> 401" || bad "bad token ($out)"

# 5. Missing path.
out=$($CLI $URL $TOKEN nope.bin "$T/out5" 2>/dev/null); echo "$out" | grep -q "not found" && ok "missing path" || bad "missing path ($out)"

# 6. Abort by callback, then resume.
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out6" --abort-at 7000001 >/dev/null 2>&1
sz=$(stat -c %s "$T/out6/ep02.mkv")
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out6" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep02.mkv" "$T/out6/ep02.mkv" \
  && ok "abort at $sz then resume" || bad "abort/resume"
stop_server

# 7. Connection cut at an odd offset, then resume (mid-block).
start_server CUT_AFTER=3333339
out=$($CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out7" 2>/dev/null)
sz=$(stat -c %s "$T/out7/ep02.mkv")
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out7" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep02.mkv" "$T/out7/ep02.mkv" \
  && ok "cut at $sz ($out) then resume" || bad "cut/resume"
stop_server

# 8. Server ignores Range (200 instead of 206) -> restart from zero.
head -c 5000001 "$T/root/Show Name/Season 01/ep02.mkv" > "$T/part.mkv"; mkdir -p "$T/out8"; cp "$T/part.mkv" "$T/out8/ep02.mkv"
start_server IGNORE_RANGE=1
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out8" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep02.mkv" "$T/out8/ep02.mkv" \
  && ok "range ignored -> full rewrite" || bad "range ignored"
stop_server

start_server
# 9. Local file bigger than remote -> rewrite.
mkdir -p "$T/out9"; head -c 100 /dev/urandom > "$T/out9/small.bin"
$CLI $URL $TOKEN small.bin "$T/out9" >/dev/null 2>&1 && cmp "$T/root/small.bin" "$T/out9/small.bin" \
  && ok "oversized local -> rewrite" || bad "oversized local"

# 10. Corrupt partial, --no-repair -> checksum fail, file removed, next try OK.
mkdir -p "$T/out10"; head -c 4000000 /dev/urandom > "$T/out10/ep02.mkv"
out=$($CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out10" --no-repair 2>/dev/null)
echo "$out" | grep -q "checksum" && [ ! -e "$T/out10/ep02.mkv" ] \
  && $CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out10" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep02.mkv" "$T/out10/ep02.mkv" \
  && ok "corrupt partial, no repair -> checksum -> clean retry" || bad "corrupt partial ($out)"

# 10b. Resume from an odd offset (mid AES block: 5000001 = 312500*16 + 1).
mkdir -p "$T/out10b"; cp "$T/part.mkv" "$T/out10b/ep02.mkv"
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out10b" >/dev/null 2>&1 \
  && cmp "$T/root/Show Name/Season 01/ep02.mkv" "$T/out10b/ep02.mkv" \
  && ok "resume from odd offset 5000001" || bad "resume odd offset"

# 11. Already complete -> skip (no rewrite).
before=$(stat -c %Y "$T/out1/Show Name/Season 01/ep02.mkv"); sleep 1
$CLI $URL $TOKEN "Show Name" "$T/out1" >/dev/null 2>&1
after=$(stat -c %Y "$T/out1/Show Name/Season 01/ep02.mkv")
[ "$before" = "$after" ] && ok "complete file skipped" || bad "complete file rewritten"

# 12. Speed of a 20 MB file (decrypt + hash + write, loopback).
rm -rf "$T/out12"; s=$(date +%s.%N)
$CLI $URL $TOKEN "Show Name/Season 01/ep02.mkv" "$T/out12" >/dev/null 2>&1
e=$(date +%s.%N); echo "INFO  20 MB in $(echo "$e - $s" | bc) s"
stop_server

# ---- Repair: fetch only the missing or damaged pieces again ---------------
# The mock torrent has 256 KiB pieces: ep02.mkv (20 MiB) has 80, the
# 1048581-byte file has 5 (the last one is 5 bytes).
F2="Show Name/Season 01/ep02.mkv"; SRC2="$T/root/$F2"
F1="Show Name/Season 01/ep 01 ção.mkv"; SRC1="$T/root/$F1"
LOG="$T/ranges.log"
bounded() { grep -c -- '-[0-9]' "$LOG" 2>/dev/null || true; }
whole()   { grep -c -v -- '-[0-9]' "$LOG" 2>/dev/null || true; }
start_server RANGE_LOG="$LOG"

# R1. A corrupt partial: the finished download fails the checksum and is
#     healed (pieces 0-15 fetched again), not removed.
: > "$LOG"; mkdir -p "$T/r1"; head -c 4000000 /dev/urandom > "$T/r1/ep02.mkv"
out=$($CLI $URL $TOKEN "$F2" "$T/r1" 2>/dev/null)
cmp "$SRC2" "$T/r1/ep02.mkv" && echo "$out" | grep -q "repaired 16 pieces" && [ "$(bounded)" = 16 ] \
  && ok "corrupt partial healed: 16 pieces fetched again" || bad "corrupt partial heal ($out, $(bounded) ranges)"

# R2. A full-size file on disk with one bad byte: checked, one piece fetched.
: > "$LOG"; mkdir -p "$T/r2"; cp "$SRC2" "$T/r2/ep02.mkv"; flip "$T/r2/ep02.mkv" 7000000
out=$($CLI $URL $TOKEN "$F2" "$T/r2" 2>/dev/null)
cmp "$SRC2" "$T/r2/ep02.mkv" && echo "$out" | grep -q "repaired 1 pieces" && [ "$(bounded)" = 1 ] && [ "$(whole)" = 0 ] \
  && grep -q "bytes=6815744-7077887" "$LOG" \
  && ok "full-size file with a bad byte: 1 piece fetched" || bad "full-size heal ($out, $(cat "$LOG"))"

# R3. The short last piece.
: > "$LOG"; mkdir -p "$T/r3"; cp "$SRC1" "$T/r3/"; flip "$T/r3/ep 01 ção.mkv" 1048580
out=$($CLI $URL $TOKEN "$F1" "$T/r3" 2>/dev/null)
cmp "$SRC1" "$T/r3/ep 01 ção.mkv" && grep -q "bytes=1048576-1048580" "$LOG" && [ "$(bounded)" = 1 ] \
  && ok "short last piece healed" || bad "last piece ($out, $(cat "$LOG"))"

# R4. Right bytes plus junk at the end: trimmed, nothing fetched.
: > "$LOG"; mkdir -p "$T/r4"; { cat "$SRC1"; head -c 777 /dev/urandom; } > "$T/r4/ep 01 ção.mkv"
out=$($CLI $URL $TOKEN "$F1" "$T/r4" 2>/dev/null)
cmp "$SRC1" "$T/r4/ep 01 ção.mkv" && [ ! -s "$LOG" ] \
  && ok "trailing junk trimmed, nothing fetched" || bad "trailing junk ($out, $(cat "$LOG"))"

# R5. Several pieces, scattered.
: > "$LOG"; mkdir -p "$T/r5"; cp "$SRC2" "$T/r5/ep02.mkv"
for o in 0 300000 10000000 20971519; do flip "$T/r5/ep02.mkv" $o; done
out=$($CLI $URL $TOKEN "$F2" "$T/r5" 2>/dev/null)
cmp "$SRC2" "$T/r5/ep02.mkv" && echo "$out" | grep -q "repaired 4 pieces" \
  && ok "4 scattered bad pieces healed" || bad "scattered ($out)"

# R6. A good full-size file: checked, nothing fetched, not rewritten.
: > "$LOG"; before=$(stat -c %Y "$T/r5/ep02.mkv"); sleep 1
out=$($CLI $URL $TOKEN "$F2" "$T/r5" 2>/dev/null)
[ "$before" = "$(stat -c %Y "$T/r5/ep02.mkv")" ] && [ ! -s "$LOG" ] && echo "$out" | grep -q "checked 80 pieces" \
  && ok "good file checked, not fetched" || bad "good file ($out)"

# R7. --no-repair: a bad full-size file is removed (the next call downloads it).
mkdir -p "$T/r7"; cp "$SRC2" "$T/r7/ep02.mkv"; flip "$T/r7/ep02.mkv" 123
out=$($CLI $URL $TOKEN "$F2" "$T/r7" --no-repair 2>/dev/null)
echo "$out" | grep -q "error -9" && [ ! -e "$T/r7/ep02.mkv" ] \
  && ok "no repair: bad full-size file removed" || bad "no repair ($out)"
stop_server

# R8. Bad data on the wire: the piece fails its hash, is fetched again, and
#     is never written while wrong.
: > "$LOG"; start_server RANGE_LOG="$LOG" CORRUPT_RANGES=2
mkdir -p "$T/r8"; cp "$SRC2" "$T/r8/ep02.mkv"; flip "$T/r8/ep02.mkv" 5555555
out=$($CLI $URL $TOKEN "$F2" "$T/r8" 2>/dev/null)
cmp "$SRC2" "$T/r8/ep02.mkv" && [ "$(bounded)" = 3 ] \
  && ok "bad piece data on the wire retried" || bad "wire corruption ($out, $(bounded) ranges)"
stop_server

# R9. A server with no torrent: fall back to remove + checksum error.
start_server NO_TORRENT=1
mkdir -p "$T/r9"; cp "$SRC2" "$T/r9/ep02.mkv"; flip "$T/r9/ep02.mkv" 99
out=$($CLI $URL $TOKEN "$F2" "$T/r9" 2>/dev/null)
echo "$out" | grep -q "error -9" && [ ! -e "$T/r9/ep02.mkv" ] \
  && $CLI $URL $TOKEN "$F2" "$T/r9" >/dev/null 2>&1 && cmp "$SRC2" "$T/r9/ep02.mkv" \
  && ok "no torrent: removed, clean retry" || bad "no torrent ($out)"
stop_server

# R10. Over TLS is covered by the same code path; a stop while checking
#      keeps the file.
start_server
mkdir -p "$T/r10"; cp "$SRC2" "$T/r10/ep02.mkv"; flip "$T/r10/ep02.mkv" 1
out=$($CLI $URL $TOKEN "$F2" "$T/r10" --abort-at 0 2>/dev/null)
[ -e "$T/r10/ep02.mkv" ] && $CLI $URL $TOKEN "$F2" "$T/r10" >/dev/null 2>&1 && cmp "$SRC2" "$T/r10/ep02.mkv" \
  && ok "stop, then heal on the next call" || bad "stop during repair ($out)"
stop_server

# ---- Large files: the server "prepares" a file before it has metadata ------
# The real server reads and hashes a whole file before /api/torrent answers.
# For a big file that is minutes; the client must wait it out, not fail.

# P1. New server: 202 "preparing" with progress, then the metadata.
start_server PREPARE_MS=3000
err=$($CLI $URL $TOKEN "$F2" "$T/prep1" 2>&1 >/dev/null)
cmp "$T/root/$F2" "$T/prep1/ep02.mkv" 2>/dev/null && echo "$err" | grep -q "preparing on the server" \
  && ok "large file: waits while the server prepares (202)" || bad "prepare 202 ($err)"
stop_server

# P2. Old server: the request stays open while it prepares. No short timeout.
start_server PREPARE_MS=7000 OLD_SERVER=1
$CLI $URL $TOKEN "$F2" "$T/prep2" >/dev/null 2>&1 && cmp "$T/root/$F2" "$T/prep2/ep02.mkv" \
  && ok "large file: old server holds the request 7 s" || bad "old server hold"
stop_server

# P3. Dropped connection, then a 404 page from a proxy: retried, then OK.
start_server TORRENT_FAIL=drop,404html
$CLI $URL $TOKEN small.bin "$T/prep3" >/dev/null 2>&1 && cmp "$T/root/small.bin" "$T/prep3/small.bin" \
  && ok "metadata: drop + proxy 404 retried" || bad "metadata retry"
stop_server

# P4. The server's own 404 is final (no retry loop).
start_server TORRENT_FAIL=404json
s=$(date +%s); out=$($CLI $URL $TOKEN small.bin "$T/prep4" 2>/dev/null); e=$(date +%s)
echo "$out" | grep -q "404" && [ $((e - s)) -lt 2 ] && ok "metadata: server 404 is final" || bad "server 404 ($out)"
stop_server

# P5. prepare_timeout_ms gives up with a retryable error.
start_server PREPARE_MS=60000
s=$(date +%s); out=$($CLI $URL $TOKEN small.bin "$T/prep5" --prepare-timeout 3000 2>/dev/null); e=$(date +%s)
echo "$out" | grep -q "error -2: the server is still preparing" && [ $((e - s)) -lt 8 ] \
  && ok "prepare timeout -> retryable error" || bad "prepare timeout ($out)"

# P6. Stop while preparing.
out=$(timeout 10 $CLI $URL $TOKEN small.bin "$T/prep6" --abort-preparing 2>/dev/null)
echo "$out" | grep -q "error -7" && ok "stop while preparing" || bad "stop while preparing ($out)"
stop_server

# ---- HTTPS ----------------------------------------------------------------
C="$T/certs"
python3 -I tools/make_test_certs.py "$C"
FILE="Show Name/Season 01/ep02.mkv"
SRCF="$T/root/$FILE"
tls() { start_server TLS_CERT="$C/$1.pem" TLS_KEY="$C/$1.key" "${@:2}"; }

# 13. RSA certificate from a private CA, host name.
tls rsa
$CLI https://localhost:$PORT $TOKEN "Show Name" "$T/tls1" --ca "$C/ca.pem" >/dev/null 2>&1 \
  && diff -r "$T/root/Show Name" "$T/tls1/Show Name" >/dev/null \
  && ok "https folder download (RSA, private CA)" || bad "https folder download"

# 14. IP address in the URL (IP SAN).
$CLI https://127.0.0.1:$PORT $TOKEN small.bin "$T/tls2" --ca "$C/ca.pem" >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/tls2/small.bin" && ok "https with IP address" || bad "https with IP address"

# 15. Built-in Mozilla bundle does not trust the test CA.
out=$($CLI https://localhost:$PORT $TOKEN small.bin "$T/tls3" 2>/dev/null)
echo "$out" | grep -q "not trusted" && [ ! -e "$T/tls3/small.bin" ] \
  && ok "unknown CA rejected" || bad "unknown CA ($out)"

# 16. Abort and resume over TLS.
$CLI https://localhost:$PORT $TOKEN "$FILE" "$T/tls4" --ca "$C/ca.pem" --abort-at 9000000 >/dev/null 2>&1
sz=$(stat -c %s "$T/tls4/ep02.mkv")
$CLI https://localhost:$PORT $TOKEN "$FILE" "$T/tls4" --ca "$C/ca.pem" >/dev/null 2>&1 \
  && cmp "$SRCF" "$T/tls4/ep02.mkv" && ok "https abort at $sz then resume" || bad "https resume"

# 17. Speed over TLS.
s=$(date +%s.%N)
$CLI https://localhost:$PORT $TOKEN "$FILE" "$T/tls5" --ca "$C/ca.pem" >/dev/null 2>&1
e=$(date +%s.%N); echo "INFO  20 MB over HTTPS in $(echo "$e - $s" | bc) s"
stop_server

# 18. Connection cut over TLS, then resume from an odd offset.
tls rsa CUT_AFTER=4444449
$CLI https://localhost:$PORT $TOKEN "$FILE" "$T/tls6" --ca "$C/ca.pem" >/dev/null 2>&1
sz=$(stat -c %s "$T/tls6/ep02.mkv")
$CLI https://localhost:$PORT $TOKEN "$FILE" "$T/tls6" --ca "$C/ca.pem" >/dev/null 2>&1 \
  && cmp "$SRCF" "$T/tls6/ep02.mkv" && ok "https cut at $sz then resume" || bad "https cut/resume"
stop_server

# 19. ECDSA certificate.
tls ec
$CLI https://localhost:$PORT $TOKEN small.bin "$T/tls7" --ca "$C/ca.pem" >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/tls7/small.bin" && ok "https ECDSA certificate" || bad "https ECDSA"
stop_server

# 20. Wrong host name.
tls other
out=$($CLI https://localhost:$PORT $TOKEN small.bin "$T/tls8" --ca "$C/ca.pem" 2>/dev/null)
echo "$out" | grep -qi "not trusted" && ok "wrong host name rejected" || bad "wrong host ($out)"
stop_server

# 21. Expired certificate (the error mentions the console clock).
tls old
out=$($CLI https://localhost:$PORT $TOKEN small.bin "$T/tls9" --ca "$C/ca.pem" 2>/dev/null)
echo "$out" | grep -q "date and time" && ok "expired certificate rejected" || bad "expired ($out)"
stop_server

# 22. Self-signed server certificate as the CA file.
tls self
$CLI https://localhost:$PORT $TOKEN small.bin "$T/tls10" --ca "$C/self.pem" >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/tls10/small.bin" && ok "self-signed certificate as CA" || bad "self-signed"

# 23. Missing CA file.
out=$($CLI https://localhost:$PORT $TOKEN small.bin "$T/tls11" --ca "$C/nope.pem" 2>/dev/null)
echo "$out" | grep -q "cannot read CA file" && ok "missing CA file reported" || bad "missing CA file ($out)"

# 24. Plain HTTP to an HTTPS port fails cleanly (no hang).
out=$(timeout 20 $CLI http://localhost:$PORT $TOKEN small.bin "$T/tls12" 2>/dev/null); rc=$?
[ $rc -ne 124 ] && [ $rc -ne 0 ] && ok "http to https port fails ($out)" || bad "http to https port (rc $rc)"
stop_server

# ---- Built-in DNS client --------------------------------------------------
DNSPORT=18853
node tools/mock_dns.mjs $DNSPORT >/dev/null 2>&1 & DNS=$!; sleep 0.4
start_server

# 25. A record.
$CLI http://myserver.test:$PORT $TOKEN small.bin "$T/dns1" --dns 127.0.0.1:$DNSPORT >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/dns1/small.bin" && ok "dns: A record" || bad "dns: A record"

# 26. CNAME then A, with compressed names.
$CLI http://alias.test:$PORT $TOKEN small.bin "$T/dns2" --dns 127.0.0.1:$DNSPORT >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/dns2/small.bin" && ok "dns: CNAME chain" || bad "dns: CNAME chain"

# 27. NXDOMAIN gives a clear message.
out=$($CLI http://nope.test:$PORT $TOKEN small.bin "$T/dns3" --dns 127.0.0.1:$DNSPORT 2>/dev/null)
echo "$out" | grep -q "NXDOMAIN" && ok "dns: NXDOMAIN reported" || bad "dns: NXDOMAIN ($out)"

# 28. No A record.
out=$($CLI http://v6only.test:$PORT $TOKEN small.bin "$T/dns4" --dns 127.0.0.1:$DNSPORT 2>/dev/null)
echo "$out" | grep -q "no IPv4 address" && ok "dns: no A record reported" || bad "dns: no A ($out)"

# 29. DNS server does not answer: a timeout, not a hang.
s=$(date +%s)
out=$(timeout 30 $CLI http://myserver.test:$PORT $TOKEN small.bin "$T/dns5" --dns 127.0.0.1:18999 2>/dev/null)
e=$(date +%s)
echo "$out" | grep -q "no answer" && [ $((e - s)) -lt 15 ] \
  && ok "dns: no answer after $((e - s)) s" || bad "dns: timeout ($out)"

# 30. The system resolver still works without --dns.
$CLI http://localhost:$PORT $TOKEN small.bin "$T/dns6" >/dev/null 2>&1 \
  && cmp "$T/root/small.bin" "$T/dns6/small.bin" && ok "system resolver (localhost)" || bad "system resolver"
stop_server
kill $DNS 2>/dev/null; wait $DNS 2>/dev/null

rm -rf "$T"
echo "$PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
