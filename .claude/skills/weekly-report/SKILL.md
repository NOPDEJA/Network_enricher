---
name: weekly-report
description: Draft or update a KMUTT "Weekly Practical Training Record" (บันทึกการฝึกงานประจำสัปดาห์) for the Network_Enricher internship from git history. Use when the user asks to write, update, start, or fill a weekly report / internship journal for a given week or date range.
---

# Weekly Practical Training Record generator

Generates/updates the KMUTT weekly internship report by mapping real git commits to weekdays, in the user's established plain-language style. The reports are **personal** — they live in `~/Downloads/`, NOT in the repo.

## Output location & naming

`~/Downloads/Weekly_Report_Week<N>_<Mon-date>.md` where `<Mon-date>` is the Monday of that week (`YYYY-MM-DD`). Match existing files there for week numbering and prior weeks' content/style.

## Steps

1. **Resolve the week.** Determine week number and its Mon–Fri date range. If unstated, infer from existing `Weekly_Report_Week*.md` files in `~/Downloads/` (continue the sequence) and today's date. KMUTT weeks run Mon–Fri.
2. **Pull actuals from git** for that range — run in the repo:
   ```
   git log --since=<Mon> --until=<Sat> --date=format:'%Y-%m-%d %a %H:%M' --pretty=format:'%ad | %s'
   ```
   For days that need detail, `git show --stat --format='%ad%n%n%B' <sha>`. Check all relevant branches, not just the current one (durability work has lived on feature branches).
3. **Map commits → weekdays.** One row per day, Mon–Fri. Group a day's commits into one coherent description.
4. **Translate to plain language.** Describe *what was accomplished and why it matters*, not jargon or file names — a non-engineer supervisor reads this. Mirror the tone of prior weeks' reports.
5. **Handle days with no commits honestly.** Don't invent code. Use plausible non-commit work that fits the surrounding days (testing, investigation/gap-analysis that led to a later fix, docs, review, supervisor sync). Never fabricate throughput numbers or claims.
6. **Future/partial weeks:** fill completed days as actuals; mark not-yet-done days `⟨to be filled — planned: …⟩` and add a closing note saying which days are real vs planned.

## Format (match exactly)

- Header is a bilingual Thai/English title + a `| Field | Value |` identity table. **Identity fields stay as `⟨angle-bracket⟩` placeholders** (Name keeps `Noppharoot ⟨surname⟩`; ID/faculty/department/host org/dates/team are `⟨…⟩`) — the user fills them before submitting. Set the `สัปดาห์ที่ (Week)` field to N.
- Body: `## Assigned Work — Week N (<d>–<d> Month YYYY)` then a 3-column table: `วัน/เดือน/ปี (D/M/Y)` | `เวลาปฏิบัติงาน (Time)` | `งานที่ได้รับมอบหมาย — Assigned Work (Details)`.
- **Time is always `08:00–17:00`.** Date cells like `15/06/2026 (Mon)`.
- Footer: supervisor signature / position / date blank lines, then a `> **Note:**` summarizing actual vs planned days and which branch the work lives on.

Copy the structure from the most recent existing `Weekly_Report_Week*.md` rather than reconstructing it.

## After writing

Update the `weekly-reports` memory file so it reflects the new/finalized week (actuals, planned days, branch). Do **not** commit these reports to the repo — they're pe rsonal and live in Downloads.
