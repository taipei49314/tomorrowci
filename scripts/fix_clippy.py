from pathlib import Path

p = Path("crates/runner/src/lib.rs")
t = p.read_text(encoding="utf-8")
t = t.replace(
    "store.write_verdicts(&[verdict.clone()])",
    "store.write_verdicts(std::slice::from_ref(&verdict))",
)
# Fix nested format! for clippy::format_in_format_args
needle = 'format!("{from} -> {to}")'
if needle in t:
    # Replace the whole Minimal-changed-axis block carefully
    old_snip = """if let (Some(from), Some(to)) = (&frontier.from_label, &frontier.to_label) {
            out.push_str(&format!(
                "Minimal changed axis: {} -> {}\\n",
                frontier
                    .axis
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|| "unknown".into()),
                format!("{from} -> {to}")
            ));
        }"""
    new_snip = """if let (Some(from), Some(to)) = (&frontier.from_label, &frontier.to_label) {
            let axis = frontier
                .axis
                .as_ref()
                .map(|a| a.to_string())
                .unwrap_or_else(|| "unknown".into());
            let axis_msg = format!("{axis}: {from} -> {to}");
            out.push_str(&format!("Minimal changed axis: {axis_msg}\\n"));
        }"""
    if old_snip in t:
        t = t.replace(old_snip, new_snip)
        print("block replaced")
    else:
        # looser: just avoid nested format by precomputing
        t = t.replace(
            """                format!("{from} -> {to}")
            ));""",
            """                {
                    let axis = frontier
                        .axis
                        .as_ref()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "unknown".into());
                    format!("{axis}: {from} -> {to}")
                }
            ));""",
        )
        print("nested format patched loosely")
else:
    print("no nested format found")

p.write_text(t, encoding="utf-8")
print("from_ref", t.count("from_ref(&verdict)"))
print("clone slice", t.count("&[verdict.clone()]"))
