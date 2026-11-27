#!/usr/bin/env bash
# Runs the whole G3/G4/G5 matrix. Usage: run-all.sh <results-dir> <work-dir>
# <work-dir> receives disposable SECRET keys; it is NOT inside the repository results.
# Expects ./target/debug/{seq,rpgp} to exist (see README.md for the build commands).
set -u
RES="${1:?results dir}"
WORK="${2:?work dir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
S="$HERE/target/debug/seq"
R="$HERE/target/debug/rpgp"
mkdir -p "$RES/artifacts" "$WORK"
LOG="$RES/g3-matrix.txt"
: > "$LOG"
PASS=0
FAIL=0

say() { echo "$@" | tee -a "$LOG"; }

# check ID EXPECT(ok|fail) cmd...   : runs cmd, records exit status against expectation
check() {
  local id="$1" expect="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  local actual=ok; [ $rc -ne 0 ] && actual=fail
  local verdict=PASS; [ "$expect" != "$actual" ] && verdict=FAIL
  [ $verdict = PASS ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
  {
    echo "### $id  expect=$expect actual=$actual => $verdict"
    echo "\$ ${*//$WORK/\$WORK}"
    echo "$out" | sed "s|$WORK|\$WORK|g" | cut -c1-400
    echo
  } | tee -a "$LOG" >/dev/null
  echo "RESULT $id expect=$expect actual=$actual $verdict" | tee -a "$RES/g3-summary.txt"
}

: > "$RES/g3-summary.txt"
say "# G3 matrix, run $(date -u +%FT%TZ), host $(uname -sm), debug build"
say "$($S version)"
say "$($R version)"

# ---------------------------------------------------------------- identities
for n in alice bob carol mallory; do $S gen --name "$n" --out "$WORK" --enc-validity-days 365 > /dev/null; done   # X-made certs
for n in yal ybo; do $R gen --name "$n" --out "$WORK" > /dev/null; done                                           # Y-made certs
# special fixtures made by X
$S gen --name bob_expired --out "$WORK" --enc-validity-days 1 --created-days-ago 10 > /dev/null
$S cert revoke-subkey --sec "$WORK/bob.sec.asc" --out "$WORK/bob_subkey_revoked.pub.asc"
$S cert revoke-cert --sec "$WORK/bob.sec.asc" --out "$WORK/bob_cert_revoked.pub.asc"
$S cert revoke-cert --sec "$WORK/alice.sec.asc" --out "$WORK/alice_cert_revoked.pub.asc"
$S cert strip-binding --pub "$WORK/bob.pub.asc" --out "$WORK/bob_stripped.pub.asc"
$S cert graft --victim "$WORK/bob.pub.asc" --attacker "$WORK/mallory.pub.asc" --out "$WORK/bob_grafted.pub.asc"
for n in alice bob carol mallory yal ybo; do cp "$WORK/$n.pub.asc" "$RES/artifacts/"; done
for f in bob_expired.pub.asc bob_subkey_revoked.pub.asc bob_cert_revoked.pub.asc alice_cert_revoked.pub.asc bob_stripped.pub.asc bob_grafted.pub.asc; do cp "$WORK/$f" "$RES/artifacts/"; done

{
  echo "# fingerprints (v6, 32 bytes = 64 hex)"
  for n in alice bob carol mallory yal ybo; do echo "$n $($S fpr --cert "$WORK/$n.pub.asc")"; done
  echo "# cert state as seen by X (sequoia)"
  for f in bob.pub.asc bob_expired.pub.asc bob_subkey_revoked.pub.asc bob_cert_revoked.pub.asc bob_stripped.pub.asc bob_grafted.pub.asc ybo.pub.asc; do echo "-- $f"; $S cert info --pub "$WORK/$f"; done
  echo "# cert state as seen by Y (rpgpie)"
  for f in bob.pub.asc bob_expired.pub.asc bob_subkey_revoked.pub.asc bob_cert_revoked.pub.asc bob_stripped.pub.asc bob_grafted.pub.asc ybo.pub.asc; do echo "-- $f"; $R cert-info --pub "$WORK/$f"; done
} > "$RES/certs-info.txt" 2>&1

# ---------------------------------------------------------------- positive round trips (8 cases)
say "## positive round trips"
for set in X Y; do
  if [ $set = X ]; then A=alice; B=bob; else A=yal; B=ybo; fi
  for prod in S R; do
    for cons in S R; do
      PB=$([ $prod = S ] && echo "$S" || echo "$R"); CB=$([ $cons = S ] && echo "$S" || echo "$R")
      id="P_${set}certs_${prod}_to_${cons}"
      check "$id.seal" ok "$PB" seal --from "$WORK/$A.sec.asc" --to "$WORK/$B.pub.asc" --body 100 --out "$WORK/$id.pgp"
      check "$id.open" ok "$CB" open --me "$WORK/$B.sec.asc" --sender "$WORK/$A.pub.asc" --in "$WORK/$id.pgp"
      cp "$WORK/$id.pgp" "$RES/artifacts/"
    done
  done
done

# ---------------------------------------------------------------- negative tests (consumer = each implementation)
say "## negative tests"
$S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --out "$WORK/a2b.pgp" > /dev/null
$S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --no-intended --out "$WORK/a2b_nointended.pgp" > /dev/null
$S forward --me "$WORK/bob.sec.asc" --to "$WORK/carol.pub.asc" --in "$WORK/a2b.pgp" --out "$WORK/fwd.pgp"
$S forward --me "$WORK/bob.sec.asc" --to "$WORK/carol.pub.asc" --in "$WORK/a2b_nointended.pgp" --out "$WORK/fwd_nointended.pgp"
$S seal --from "$WORK/mallory.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --out "$WORK/m2b.pgp" > /dev/null
$S seal --from "$WORK/mallory.sec.asc" --to "$WORK/bob.pub.asc" --unsigned --body 100 --out "$WORK/unsigned.pgp" > /dev/null
# mallory signs a payload that CLAIMS to be from alice
python3 -I - "$($S fpr --cert "$WORK/alice.pub.asc")" "$($S fpr --cert "$WORK/bob.pub.asc")" > "$WORK/claim_alice.json" <<'EOF'
import json,sys,time
print(json.dumps({"v":1,"message_id":"00000000-0000-4000-8000-000000000001","sender":sys.argv[1],"recipient":sys.argv[2],"created_at":int(time.time()*1000),"ttl_s":3600,"type":"message","body":"forged claim"},separators=(',',':')),end='')
EOF
$S seal --from "$WORK/mallory.sec.asc" --to "$WORK/bob.pub.asc" --payload "$WORK/claim_alice.json" --out "$WORK/m_claims_alice.pgp" > /dev/null
cp "$WORK/a2b.pgp" "$WORK/fwd.pgp" "$WORK/m2b.pgp" "$WORK/a2b_nointended.pgp" "$WORK/fwd_nointended.pgp" "$WORK/unsigned.pgp" "$WORK/m_claims_alice.pgp" "$RES/artifacts/"

for cons in S R; do
  CB=$([ $cons = S ] && echo "$S" || echo "$R"); c=$cons
  check "N1_wrong_recipient_carol_cannot_open_[$c]" fail "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/a2b.pgp"
  check "N2_forwarded_to_carol_intended_recipient_check_(crypto layer only)_[$c]" fail "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/fwd.pgp" --crypto-only
  check "N2a_forwarded_to_carol_full_check_[$c]" fail "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/fwd.pgp"
  check "N2b_CONTROL_forward_without_intended_recipient_crypto_layer_accepts_(attack works)_[$c]" ok "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/fwd_nointended.pgp" --allow-no-intended --crypto-only
  check "N2b2_CONTROL_same_forward_stopped_only_by_the_application_payload.recipient_check_[$c]" fail "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/fwd_nointended.pgp" --allow-no-intended
  check "N2c_forward_without_intended_rejected_by_strict_receiver_[$c]" fail "$CB" open --me "$WORK/carol.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/fwd_nointended.pgp"
  check "N4a_signature_by_other_key_rejected_[$c]" fail "$CB" open --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/m2b.pgp"
  check "N4b_signed_by_mallory_claiming_alice_rejected_[$c]" fail "$CB" open --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/m_claims_alice.pgp"
  check "N4c_signed_by_mallory_claiming_alice_opened_as_mallory_rejected_by_payload_check_[$c]" fail "$CB" open --me "$WORK/bob.sec.asc" --sender "$WORK/mallory.pub.asc" --in "$WORK/m_claims_alice.pgp"
  check "N4d_unsigned_message_rejected_[$c]" fail "$CB" open --me "$WORK/bob.sec.asc" --sender "$WORK/mallory.pub.asc" --in "$WORK/unsigned.pgp"
  check "N5_revoked_signing_cert_rejected_[$c]" fail "$CB" open --me "$WORK/bob.sec.asc" --sender "$WORK/alice_cert_revoked.pub.asc" --in "$WORK/a2b.pgp"
done
for prod in S R; do
  PB=$([ $prod = S ] && echo "$S" || echo "$R"); c=$prod
  check "N6_seal_to_revoked_subkey_refused_[$c]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_subkey_revoked.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "N6b_seal_to_revoked_cert_refused_[$c]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_cert_revoked.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "N7_seal_to_expired_subkey_refused_[$c]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_expired.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "N8_seal_to_stripped_binding_refused_[$c]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_stripped.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "N9_seal_to_grafted_foreign_subkey_refused_[$c]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_grafted.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "N10_CONTROL_seal_to_valid_cert_ok_[$c]" ok "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 10 --out "$WORK/x.pgp"
done

# exhaustive single-bit flips and truncations, both consumers, on an X-made message and a Y-made message
say "## tamper scans (every byte offset flipped once; every truncation length)"
$S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --out "$WORK/scan_x.pgp" > /dev/null
$R seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --out "$WORK/scan_y.pgp" > /dev/null
{
  for m in scan_x scan_y; do
    echo "## message $m ($(wc -c < "$WORK/$m.pgp") bytes)"
    $S scan --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/$m.pgp" 2>&1 | cut -c1-600
    $R scan --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/$m.pgp" 2>&1 | cut -c1-600
  done
} | tee "$RES/g3-tamper-scan.txt" >/dev/null
cp "$WORK/scan_x.pgp" "$WORK/scan_y.pgp" "$RES/artifacts/"

# ---------------------------------------------------------------- padding acceptance
say "## padding (Sequoia produces; both consume)"
for pad in none pow2; do
  for len in 0 100 1024 16384 65536; do
    $S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body $len --pad $pad --out "$WORK/pad_${pad}_$len.pgp" > /dev/null
    check "PAD_${pad}_${len}_open_[S]" ok "$S" open --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/pad_${pad}_$len.pgp"
    check "PAD_${pad}_${len}_open_[R]" ok "$R" open --me "$WORK/bob.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/pad_${pad}_$len.pgp"
  done
done
check "PAD_rpgp_cannot_send_padding" fail "$R" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 10 --pad pow2 --out "$WORK/x.pgp"

# ---------------------------------------------------------------- rotation / revocation / contact update (G4)
say "## key rotation and revocation expressed as certificate updates"
cp "$WORK/bob.sec.asc" "$WORK/bob_v1.sec.asc"; cp "$WORK/bob.pub.asc" "$WORK/bob_v1.pub.asc"
$S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_v1.pub.asc" --body 50 --out "$WORK/before_rotation.pgp" > /dev/null
$S cert rotate --sec "$WORK/bob_v1.sec.asc" --days 90 --retire-old-days 0 --out-sec "$WORK/bob_v2.sec.asc" --out-pub "$WORK/bob_v2.pub.asc"
sleep 2
cp "$WORK/bob_v2.pub.asc" "$RES/artifacts/"
{ echo "-- rotated cert as seen by X"; $S cert info --pub "$WORK/bob_v2.pub.asc"; echo "-- rotated cert as seen by Y"; $R cert-info --pub "$WORK/bob_v2.pub.asc"; } > "$RES/rotation-cert-info.txt" 2>&1
# contact update = merge the new public cert into the stored one
$S cert merge --a "$WORK/bob_v1.pub.asc" --b "$WORK/bob_v2.pub.asc" --out "$WORK/bob_merged.pub.asc"
check "ROT1_old_message_still_opens_with_rotated_secret_[S]" ok "$S" open --me "$WORK/bob_v2.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/before_rotation.pgp"
check "ROT1_old_message_still_opens_with_rotated_secret_[R]" ok "$R" open --me "$WORK/bob_v2.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/before_rotation.pgp"
for prod in S R; do
  PB=$([ $prod = S ] && echo "$S" || echo "$R")
  check "ROT2_sealing_with_stale_contact_still_targets_old_subkey_[$prod]" ok "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_v1.pub.asc" --body 50 --out "$WORK/stale_$prod.pgp"
  check "ROT3_sealing_after_contact_update_merge_[$prod]" ok "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_merged.pub.asc" --body 50 --out "$WORK/new_$prod.pgp"
done
check "ROT4_new_message_opens_with_rotated_secret_[S]" ok "$S" open --me "$WORK/bob_v2.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/new_S.pgp"
check "ROT4_new_message_opens_with_rotated_secret_[R]" ok "$R" open --me "$WORK/bob_v2.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/new_R.pgp"
check "ROT5_new_message_does_NOT_open_with_old_secret_only_[S]" fail "$S" open --me "$WORK/bob_v1.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/new_S.pgp"
check "ROT5_new_message_does_NOT_open_with_old_secret_only_[R]" fail "$R" open --me "$WORK/bob_v1.sec.asc" --sender "$WORK/alice.pub.asc" --in "$WORK/new_R.pgp"
# revocation distributed as a cert update: merge the subkey-revoked cert into the stored contact
$S cert merge --a "$WORK/bob_v1.pub.asc" --b "$WORK/bob_subkey_revoked.pub.asc" --out "$WORK/bob_merged_rev.pub.asc"
$S cert merge --a "$WORK/bob_v1.pub.asc" --b "$WORK/bob_cert_revoked.pub.asc" --out "$WORK/bob_merged_certrev.pub.asc"
for prod in S R; do
  PB=$([ $prod = S ] && echo "$S" || echo "$R")
  check "REV1_seal_refused_after_subkey_revocation_merged_[$prod]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_merged_rev.pub.asc" --body 10 --out "$WORK/x.pgp"
  check "REV2_seal_refused_after_cert_revocation_merged_[$prod]" fail "$PB" seal --from "$WORK/alice.sec.asc" --to "$WORK/bob_merged_certrev.pub.asc" --body 10 --out "$WORK/x.pgp"
done
cp "$WORK/bob_merged.pub.asc" "$RES/artifacts/bob_merged_after_rotation.pub.asc"

# ---------------------------------------------------------------- restart / migration (G4)
say "## stateless restart and migration: new process, new directory, only the key file"
mkdir -p "$WORK/fresh_host"
cp "$WORK/bob_v1.sec.asc" "$WORK/fresh_host/identity.asc"
cp "$WORK/alice.pub.asc" "$WORK/fresh_host/contact.asc"
check "RESTART_open_in_fresh_dir_[S]" ok "$S" open --me "$WORK/fresh_host/identity.asc" --sender "$WORK/fresh_host/contact.asc" --in "$WORK/before_rotation.pgp"
check "RESTART_open_in_fresh_dir_[R]" ok "$R" open --me "$WORK/fresh_host/identity.asc" --sender "$WORK/fresh_host/contact.asc" --in "$WORK/before_rotation.pgp"
check "REPLAY_same_message_opens_again_(replay guard stays application level)_[S]" ok "$S" open --me "$WORK/fresh_host/identity.asc" --sender "$WORK/fresh_host/contact.asc" --in "$WORK/before_rotation.pgp"

# ---------------------------------------------------------------- sizes and timings (G4)
say "## sizes and timings (debug build)"
{
  echo "# certificate sizes (bytes): X-made, Y-made"
  $S sizes "$WORK/bob.sec.asc" "$WORK/bob.pub.asc" "$WORK/bob_v2.pub.asc"
  $R sizes "$WORK/bob.pub.asc" "$WORK/ybo.pub.asc" "$WORK/bob_v2.pub.asc"
  echo "# armored text sizes"
  wc -c "$WORK/bob.pub.asc" "$WORK/bob.sec.asc" "$WORK/ybo.pub.asc"
  echo
  echo "# per-message (binary) sizes and mean seal/open time, 20 iterations"
  $S bench --alice-sec "$WORK/alice.sec.asc" --bob-sec "$WORK/bob.sec.asc" --iters 20
  $R bench --alice-sec "$WORK/alice.sec.asc" --bob-sec "$WORK/bob.sec.asc" --iters 20
} > "$RES/g4-sizes-timings.txt" 2>&1

# ---------------------------------------------------------------- metadata (G5)
say "## metadata: what an observer of the ciphertext sees"
{
  echo "=== message Alice->Bob, anonymous recipient, intended-recipient set (made by X)"
  echo "--- X packet dump, no key:"; $S dump --in "$WORK/a2b.pgp"
  echo "--- Y packet dump, no key:"; $R dump --in "$WORK/a2b.pgp" 2>&1 | cut -c1-500
  echo "--- X packet dump WITH Bob's key (what only Bob can see):"; $S dump --in "$WORK/a2b.pgp" --me "$WORK/bob.sec.asc"
  echo
  echo "=== message made by Y (rPGP), anonymous recipient"
  echo "--- X packet dump, no key:"; $S dump --in "$WORK/scan_y.pgp"
  echo "--- Y packet dump, no key:"; $R dump --in "$WORK/scan_y.pgp" 2>&1 | cut -c1-500
  echo "--- X packet dump WITH Bob's key:"; $S dump --in "$WORK/scan_y.pgp" --me "$WORK/bob.sec.asc"
  echo
  echo "=== CONTROL: same message with a NAMED recipient (shows what anonymity hides)"
  $S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --named-recipient --out "$WORK/named.pgp" > /dev/null
  $S dump --in "$WORK/named.pgp"
  echo "--- subkey fingerprint of Bob (for comparison):"; $S cert info --pub "$WORK/bob.pub.asc"
  echo
  echo "=== hex of the first 96 bytes of the anonymous message"
  xxd -l 96 "$WORK/a2b.pgp"
} > "$RES/g5-packet-dumps.txt" 2>&1
cp "$WORK/named.pgp" "$RES/artifacts/"
# linkability: 20 messages Alice->Bob and 20 Alice->Carol: which byte positions are constant?
mkdir -p "$WORK/link"
for i in $(seq 1 20); do
  $S seal --from "$WORK/alice.sec.asc" --to "$WORK/bob.pub.asc" --body 100 --pad pow2 --out "$WORK/link/b$i.pgp" > /dev/null
  $S seal --from "$WORK/alice.sec.asc" --to "$WORK/carol.pub.asc" --body 100 --pad pow2 --out "$WORK/link/c$i.pgp" > /dev/null
done
python3 -I - "$WORK/link" > "$RES/g5-linkability.txt" <<'EOF'
import sys,glob
d=sys.argv[1]
def load(p): return [open(f,'rb').read() for f in sorted(glob.glob(f'{d}/{p}*.pgp'))]
b=load('b'); c=load('c')
def const(ms):
    n=min(len(m) for m in ms)
    return [i for i in range(n) if len({m[i] for m in ms})==1]
cb,cc=const(b),const(c)
print("messages: 20 Alice->Bob, 20 Alice->Carol, same sender, 100-byte bodies, pow2 padding")
print("lengths Bob:",sorted({len(m) for m in b}),"Carol:",sorted({len(m) for m in c}))
print("byte offsets constant across all 20 to Bob  :",len(cb),cb)
print("byte offsets constant across all 20 to Carol:",len(cc),cc)
both=[i for i in cb if i in cc and b[0][i]==c[0][i]]
print("offsets constant AND equal between Bob-group and Carol-group:",len(both))
only=[i for i in cb if not (i in cc and b[0][i]==c[0][i])]
print("offsets constant within Bob-group but different from Carol-group (would identify recipient):",only)
EOF

say "PASS=$PASS FAIL=$FAIL"
echo "PASS=$PASS FAIL=$FAIL" >> "$RES/g3-summary.txt"
