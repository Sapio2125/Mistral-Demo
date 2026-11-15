import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";

const EXEMPLE_ALERTE = JSON.stringify(
  {
    id: "ALRT-2026-0421",
    type: "phishing",
    severity: "high",
    source: "email_gateway",
    timestamp: "2026-11-15T08:47:12Z",
    description: "Alerte de phishing fictive (exemple).",
  },
  null,
  2,
);

const SocTriagePage = () => {
  const [alerte, setAlerte] = useState(EXEMPLE_ALERTE);
  const [rapport, setRapport] = useState("");
  const [enCours, setEnCours] = useState(false);
  const [erreur, setErreur] = useState("");

  const lancerTriage = async () => {
    setEnCours(true);
    setErreur("");
    setRapport("");
    try {
      const resp = await fetch("/api/soc/triage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alerte }),
      });
      const data = await resp.json();
      if (!resp.ok) {
        throw new Error(data?.detail ?? `Erreur HTTP ${resp.status}`);
      }
      setRapport(data.rapport);
    } catch (e) {
      setErreur(e instanceof Error ? e.message : String(e));
    } finally {
      setEnCours(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-full max-w-3xl flex-col gap-4 p-8">
      <h1 className="text-3xl font-semibold">SOC Alert Triage</h1>
      <p className="text-sm">
        Collez une alerte JSON, le workflow <code>soc-alert-triage</code> la classe et produit un
        rapport.
      </p>
      <textarea
        className="min-h-48 w-full rounded border p-3 font-mono text-sm"
        value={alerte}
        onChange={(e) => setAlerte(e.target.value)}
      />
      <button
        type="button"
        className="self-start rounded bg-black px-4 py-2 text-white disabled:opacity-50"
        onClick={lancerTriage}
        disabled={enCours || alerte.trim() === ""}
      >
        {enCours ? "Triage en cours…" : "Lancer le triage"}
      </button>
      {erreur && <p className="text-red-600">{erreur}</p>}
      {rapport && (
        <section className="rounded border p-4">
          <h2 className="mb-2 text-xl font-semibold">Rapport</h2>
          <pre className="whitespace-pre-wrap text-sm">{rapport}</pre>
        </section>
      )}
    </main>
  );
};

export const Route = createFileRoute("/soc")({
  component: SocTriagePage,
});
