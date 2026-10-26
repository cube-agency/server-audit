# Summarize Grype's native JSON after its configured ignore rules have been applied.
def rank:
  {unknown: 0, negligible: 1, low: 2, medium: 3, high: 4, critical: 5}[ascii_downcase]
  // error("Unrecognized vulnerability severity");
def fixed: .vulnerability.fix.state == "fixed" and (.vulnerability.fix.versions | length) > 0;
def unbounded:
  (.matchDetails | length) > 0 and
  all(.matchDetails[]; .found.versionConstraint == "none (unknown)");
def kernel_note:
  .artifact.name as $name |
  if $kernel != "" and ($name | test("^linux-(image(-unsigned)?|modules(-extra)?)-[0-9]")) then
    if ($name | sub("^linux-(image(-unsigned)?|modules(-extra)?)-"; "")) == $kernel
    then " [running kernel]" else " [not the running kernel]" end
  else "" end;
def packages:
  group_by([.artifact.name, .artifact.version]) |
  map(unique_by([.vulnerability.namespace, .vulnerability.id]) |
    {name: .[0].artifact.name, version: .[0].artifact.version, note: (.[0] | kernel_note),
     count: length, severity: (max_by(.vulnerability.severity | rank).vulnerability.severity),
     fixes: ([.[].vulnerability.fix.versions[]] | unique | join(", ")),
     unbounded: (map(select(unbounded)) | length)}) |
  sort_by([(.note == " [not the running kernel]"), -(.severity | rank), -.count, .name]);
def section($title; $rows; $show_fixes):
  "\n\($title) (\($rows | length) packages):",
  (if ($rows | length) == 0 then "  none"
   else $rows[:10][] |
     "  \(.name) \(.version)\(.note): \(.count) \(if .count == 1 then "advisory" else "advisories" end), highest \(.severity)" +
     (if $show_fixes then "; fixed in \(.fixes)"
      elif .unbounded > 0 then "; \(.unbounded) without affected-version bounds" else "" end)
   end),
  (if ($rows | length) > 10 then "  ... \(($rows | length) - 10) more packages; use --verbose" else empty end);

if (.matches | type) != "array" then error("Invalid Grype report: matches must be an array") else . end |
.matches as $all |
(.ignoredMatches // [] | length) as $ignored |
($threshold | rank) as $minimum |
($all | map(select(fixed)) | packages) as $fixes |
($all | map(select((fixed | not) and (.vulnerability.severity | rank) >= $minimum)) | packages) as $unfixed |
section("Published fixes"; $fixes; true),
section("No published fix, \($threshold) or higher"; $unfixed; false),
"\nOther findings without published fixes: \($all | map(select((fixed | not) and (.vulnerability.severity | rank) < $minimum)) | length).",
"Total: \($all | length) package/advisory matches. Full CVE list: --verbose.",
(if $ignored > 0 then "Ignored by policy: \($ignored) package/advisory matches; use --verbose to inspect." else empty end),
(if any($all[]; unbounded) then "Matches without affected-version bounds need applicability review." else empty end)
