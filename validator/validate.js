#!/usr/bin/env node
// Validates KQL queries with Microsoft's own Kusto parser (Kusto.Language,
// published to npm as @kusto/language-service-next) against a table schema.
//
// Usage:  node validator/validate.js <schema.json>  < queries.json  > results.json
//
// schema.json : { "TableName": { "Column": "kusto_type", ... }, ... }
// queries.json: [ { "id": "...", "query": "..." }, ... ]
// results.json: [ { "id": "...", "errors": ["..."], "warnings": ["..."] }, ... ]

const fs = require("fs");
const path = require("path");

const pkg = path.dirname(require.resolve("@kusto/language-service-next/package.json"));
require(path.join(pkg, "bridge.min.js"));
require(path.join(pkg, "Kusto.Language.Bridge.min.js"));

const K = global.Kusto.Language;
const S = K.Symbols;

function buildGlobals(schema) {
  const tables = [];
  for (const [table, columns] of Object.entries(schema)) {
    const cols = Object.entries(columns)
      .map(([name, type]) => `['${name.replace(/'/g, "\\'")}']:${type}`)
      .join(", ");
    tables.push(new S.TableSymbol.$ctor7(table, `(${cols})`, ""));
  }
  const db = new S.DatabaseSymbol.ctor("sigma", tables);
  return K.GlobalState.Default.WithDatabase(db);
}

function diagnostics(code) {
  const out = { errors: [], warnings: [] };
  const d = code.GetDiagnostics();
  for (let i = 0; i < d.Count; i++) {
    const x = d.getItem(i);
    const msg = `${x.Message} (at ${x.Start})`;
    if (String(x.Severity).toLowerCase() === "error") out.errors.push(msg);
    else out.warnings.push(msg);
  }
  return out;
}

function main() {
  const schemaPath = process.argv[2];
  if (!schemaPath) {
    console.error("usage: validate.js <schema.json> < queries.json");
    process.exit(2);
  }
  const globals = buildGlobals(JSON.parse(fs.readFileSync(schemaPath, "utf8")));
  const queries = JSON.parse(fs.readFileSync(0, "utf8"));
  const results = queries.map(({ id, query }) => {
    try {
      return { id, ...diagnostics(K.KustoCode.ParseAndAnalyze(query, globals)) };
    } catch (e) {
      return { id, errors: [`validator crashed: ${e.message}`], warnings: [] };
    }
  });
  process.stdout.write(JSON.stringify(results));
}

main();
