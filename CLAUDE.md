## Machine-specific setup
Paths and layout specific to this machine live in `CLAUDE.machine.md`, which is gitignored and may not exist on other checkouts; if it is missing, there is nothing to load.

@CLAUDE.machine.md

## Git
- Do NOT commit unless the user explicitly asks to commit
- When the user says "commit", do the commit FIRST, then address any other instructions in the same message
- Commit through the `commit` skill (`.claude/skills/commit`); its script stages everything by default (or, with `--staged`, commits only what you staged, for "commit this and that" requests), adds the only attribution line (`Assisted-by: <model id>`) and pushes. Never add `Co-Authored-By:` or `Assisted-by:` lines by hand.
- **Always push when committing.** "commit" implies "commit and push" — do not leave commits sitting local. Push with `git push --force-with-lease --force-if-includes`, which refuses when the remote has commits you have not integrated locally. **Never** plain `--force`, and never a `+branch` refspec (`git push origin +main`, a `remote.*.push` line with a leading `+`) — those overwrite unconditionally. If the push is rejected, stop and report it rather than escalating to a stronger form.

## Markdown / prose
- Do NOT hard-wrap prose. Write each paragraph and bullet as one unbroken line and let the editor soft-wrap. No manual newlines mid-sentence, no fixed column width.
- Do NOT number sections, headings, or requirement/list items (no `## 1.`, no `R12`, no `S3`, no `§4`). When you need to refer to another part of a doc, reference it by its header name in free-form prose (just mention the name — do NOT write a Markdown link), and prefer loose but grammatical wording like "as the Terms section above explains" or "described more fully below" over any numeric label.
