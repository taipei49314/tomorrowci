#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 5 ]]; then
  echo "usage: replay-receipts.sh BINARY EVIDENCE_ROOT SUITE_REPORT FIXTURES_ROOT LOG_ROOT" >&2
  exit 2
fi

binary="$1"
evidence_root="$2"
suite_report="$3"
fixtures_root="$4"
log_root="$5"
mkdir -p "$log_root"

for fixture_id in \
  baseline-fail \
  flaky-project \
  node-dependency-break \
  python-dependency-break \
  python-runtime-break \
  rust-msrv-break; do
  run_id="$(jq -er --arg fixture "$fixture_id" \
    '.fixtures[] | select(.id == $fixture) | .run_id' "$suite_report")"
  run_dir="$evidence_root/runs/$run_id"
  qualification="$(find "$run_dir/scenarios" -mindepth 2 -maxdepth 2 \
    -type f -name replay-qualification.json -print | sort | sed -n '1p')"
  if [[ -n "$qualification" ]]; then
    scenario_dir="$(dirname "$qualification")"
  else
    result="$(find "$run_dir/scenarios" -mindepth 2 -maxdepth 2 \
      -type f -name result.json -print | sort | sed -n '1p')"
    if [[ -z "$result" ]]; then
      echo "$fixture_id has no sealed replayable scenario" >&2
      exit 1
    fi
    scenario_dir="$(dirname "$result")"
  fi
  scenario_id="$(basename "$scenario_dir")"
  target_exit="$(jq -er '.exit_code | select(type == "number")' "$scenario_dir/result.json")"
  if [[ "$target_exit" -eq 0 ]]; then
    expected_cli_exit=0
  else
    expected_cli_exit=3
  fi

  for ordinal in 1 2; do
    log="$log_root/$fixture_id-replay-$ordinal.log"
    set +e
    "$binary" --evidence-root "$evidence_root" \
      replay "$run_id" \
      --scenario "$scenario_id" \
      --workspace "$fixtures_root/$fixture_id" 2>&1 | tee "$log"
    pipeline_status=("${PIPESTATUS[@]}")
    status=${pipeline_status[0]}
    set -e
    if [[ "${pipeline_status[1]}" -ne 0 ]]; then
      echo "$fixture_id replay $ordinal log capture failed" >&2
      exit 1
    fi
    printf '%s\n' "$status" > "$log_root/$fixture_id-replay-$ordinal.exit-code"
    if [[ "$fixture_id" == "flaky-project" ]]; then
      if [[ "$status" -ne 0 && "$status" -ne 3 ]]; then
        echo "$fixture_id replay $ordinal returned dishonest status $status" >&2
        exit 1
      fi
    elif [[ "$status" -ne "$expected_cli_exit" ]]; then
      echo "$fixture_id replay $ordinal returned $status, expected $expected_cli_exit" >&2
      exit 1
    fi
    if [[ "$(grep -c '^REPLAY_RECEIPT ' "$log")" -ne 1 ]]; then
      echo "$fixture_id replay $ordinal did not emit exactly one receipt record" >&2
      exit 1
    fi
  done

  receipt_directories=()
  while IFS= read -r receipt_directory; do
    receipt_directories[${#receipt_directories[@]}]="$receipt_directory"
  done < <(find "$evidence_root/replay-receipts/$run_id/$scenario_id" \
    -mindepth 1 -maxdepth 1 -type d -print | sort)
  if [[ "${#receipt_directories[@]}" -ne 2 ]]; then
    echo "$fixture_id did not produce exactly two detached receipts" >&2
    exit 1
  fi
  for receipt_directory in "${receipt_directories[@]}"; do
    "$binary" verify "$receipt_directory"
    if [[ "$fixture_id" == "flaky-project" ]]; then
      jq -e '
        .equivalent_to_original == false
        and (.mismatches | type == "array" and length > 0)
      ' "$receipt_directory/public-replay-receipt.json" >/dev/null
    else
      jq -e '
        .equivalent_to_original == true
        and .mismatches == []
      ' "$receipt_directory/public-replay-receipt.json" >/dev/null
    fi
  done
  set +e
  "$binary" replay-qualify \
    --original-run "$run_dir" \
    "${receipt_directories[0]}" "${receipt_directories[1]}" \
    2>&1 | tee "$log_root/$fixture_id-replay-pair.log"
  pair_pipeline_status=("${PIPESTATUS[@]}")
  pair_status=${pair_pipeline_status[0]}
  set -e
  if [[ "${pair_pipeline_status[1]}" -ne 0 ]]; then
    echo "$fixture_id pair log capture failed" >&2
    exit 1
  fi
  if [[ "$fixture_id" == "flaky-project" ]]; then
    if [[ "$pair_status" -ne 1 ]]; then
      echo "flaky pair gate returned $pair_status instead of an evidence-verification failure" >&2
      exit 1
    fi
    if ! grep -Fq \
      'origin verdict: Flaky cannot be promoted to an exact replay qualification' \
      "$log_root/$fixture_id-replay-pair.log"; then
      echo "flaky pair gate failed for an unexpected reason" >&2
      exit 1
    fi
  elif [[ "$pair_status" -ne 0 ]]; then
    echo "$fixture_id exact replay pair did not qualify" >&2
    exit 1
  fi
  "$binary" --evidence-root "$evidence_root" verify "$run_id"
done

receipt_count="$(find "$evidence_root/replay-receipts" \
  -type f -name public-replay-receipt.json -print | wc -l)"
if [[ "$receipt_count" -ne 12 ]]; then
  echo "expected twelve sealed public replay receipts, found $receipt_count" >&2
  exit 1
fi
echo "PASS replay_receipts=12 fixtures=6 qualified_pairs=5 honest_nonqualification=1"
