export function publicSummary(rows) {
  return rows.map((row) => `${row.department}: ${row.publicTotal}`).join("\n");
}
