"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import {
  WifiOff, Wifi, ScanLine, ShieldCheck, UserX, UserCheck, Loader2, CheckCircle2, XCircle,
} from "lucide-react";

type Status = "idle" | "busy" | "ok" | "err";

interface Props {
  incidentId: string;
  alertId?: string; // Graph alert id — prefilled for the write-back
}

function StatusIcon({ s }: { s?: Status }) {
  if (s === "busy") return <Loader2 size={14} className="animate-spin" />;
  if (s === "ok") return <CheckCircle2 size={14} className="text-positive" />;
  if (s === "err") return <XCircle size={14} className="text-danger" />;
  return null;
}

export function DefenderActions({ incidentId, alertId }: Props) {
  const [machineId, setMachineId] = useState("");
  const [justification, setJustification] = useState("");
  const [alert, setAlert] = useState(alertId ?? "");
  const [classification, setClassification] = useState("truePositive");
  const [userId, setUserId] = useState("");
  const [status, setStatus] = useState<Record<string, Status>>({});
  const [msg, setMsg] = useState<Record<string, string>>({});

  async function run(key: string, fn: () => Promise<unknown>) {
    setStatus((s) => ({ ...s, [key]: "busy" }));
    setMsg((m) => ({ ...m, [key]: "" }));
    try {
      await fn();
      setStatus((s) => ({ ...s, [key]: "ok" }));
      setMsg((m) => ({ ...m, [key]: "Done" }));
    } catch (e: unknown) {
      setStatus((s) => ({ ...s, [key]: "err" }));
      setMsg((m) => ({ ...m, [key]: e instanceof Error ? e.message : "Failed" }));
    }
  }

  const machineReady = !!(machineId.trim() && justification.trim());
  const btn =
    "flex items-center justify-center gap-2 px-3 py-2 text-sm border rounded-md disabled:opacity-40";

  return (
    <Panel title="Microsoft Defender Actions">
      <div className="space-y-4 text-sm">
        <p className="text-xs text-muted">
          Analyst-gated Defender for Endpoint response actions. Each requires a justification and is
          audit-logged. Isolation cuts the device&apos;s network.
        </p>

        {/* machine actions */}
        <div className="space-y-2">
          <input
            value={machineId}
            onChange={(e) => setMachineId(e.target.value)}
            placeholder="Defender device id (machine_id)"
            className="w-full px-3 py-2 bg-surface border border-line rounded-md font-mono text-xs"
          />
          <textarea
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            placeholder="Justification (required)"
            rows={2}
            className="w-full px-3 py-2 bg-surface border border-line rounded-md text-xs"
          />
        </div>

        <div className="grid grid-cols-3 gap-2">
          <button
            disabled={!machineReady || status.isolate === "busy"}
            onClick={() =>
              run("isolate", () =>
                api.defender.isolate(incidentId, {
                  machine_id: machineId.trim(),
                  justification: justification.trim(),
                }),
              )
            }
            className={`${btn} border-danger/50 hover:border-danger`}
          >
            {status.isolate ? <StatusIcon s={status.isolate} /> : <WifiOff size={14} />}
            <span>Isolate</span>
          </button>
          <button
            disabled={!machineReady || status.unisolate === "busy"}
            onClick={() =>
              run("unisolate", () =>
                api.defender.unisolate(incidentId, {
                  machine_id: machineId.trim(),
                  justification: justification.trim(),
                }),
              )
            }
            className={`${btn} border-line hover:border-accent`}
          >
            {status.unisolate ? <StatusIcon s={status.unisolate} /> : <Wifi size={14} />}
            <span>Release</span>
          </button>
          <button
            disabled={!machineReady || status.scan === "busy"}
            onClick={() =>
              run("scan", () =>
                api.defender.scan(incidentId, {
                  machine_id: machineId.trim(),
                  justification: justification.trim(),
                }),
              )
            }
            className={`${btn} border-line hover:border-accent`}
          >
            {status.scan ? <StatusIcon s={status.scan} /> : <ScanLine size={14} />}
            <span>AV Scan</span>
          </button>
        </div>
        {(msg.isolate || msg.unisolate || msg.scan) && (
          <p className="text-[11px] text-muted">{msg.isolate || msg.unisolate || msg.scan}</p>
        )}

        {/* alert write-back */}
        <div className="pt-3 border-t border-line space-y-2">
          <p className="text-xs text-muted">Write the decision back to the Defender alert.</p>
          <input
            value={alert}
            onChange={(e) => setAlert(e.target.value)}
            placeholder="Graph alert id"
            className="w-full px-3 py-2 bg-surface border border-line rounded-md font-mono text-xs"
          />
          <div className="flex gap-2">
            <select
              value={classification}
              onChange={(e) => setClassification(e.target.value)}
              className="flex-1 px-3 py-2 bg-surface border border-line rounded-md text-xs"
            >
              <option value="truePositive">True positive</option>
              <option value="falsePositive">False positive</option>
              <option value="informationalExpectedActivity">Informational / expected</option>
            </select>
            <button
              disabled={!(alert.trim() && justification.trim()) || status.writeback === "busy"}
              onClick={() =>
                run("writeback", () =>
                  api.defender.updateAlert(incidentId, {
                    alert_id: alert.trim(),
                    justification: justification.trim(),
                    status: "resolved",
                    classification,
                  }),
                )
              }
              className={`${btn} border-line hover:border-accent`}
            >
              {status.writeback ? <StatusIcon s={status.writeback} /> : <ShieldCheck size={14} />}
              <span>Write back</span>
            </button>
          </div>
          {msg.writeback && <p className="text-[11px] text-muted">{msg.writeback}</p>}
        </div>

        {/* identity containment */}
        <div className="pt-3 border-t border-line space-y-2">
          <p className="text-xs text-muted">
            Identity containment — disable / re-enable an Entra user account.
          </p>
          <input
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            placeholder="Entra user id or UPN"
            className="w-full px-3 py-2 bg-surface border border-line rounded-md font-mono text-xs"
          />
          <div className="grid grid-cols-2 gap-2">
            <button
              disabled={!(userId.trim() && justification.trim()) || status.disableUser === "busy"}
              onClick={() =>
                run("disableUser", () =>
                  api.defender.disableUser(incidentId, {
                    user_id: userId.trim(),
                    justification: justification.trim(),
                  }),
                )
              }
              className={`${btn} border-danger/50 hover:border-danger`}
            >
              {status.disableUser ? <StatusIcon s={status.disableUser} /> : <UserX size={14} />}
              <span>Disable user</span>
            </button>
            <button
              disabled={!(userId.trim() && justification.trim()) || status.enableUser === "busy"}
              onClick={() =>
                run("enableUser", () =>
                  api.defender.enableUser(incidentId, {
                    user_id: userId.trim(),
                    justification: justification.trim(),
                  }),
                )
              }
              className={`${btn} border-line hover:border-accent`}
            >
              {status.enableUser ? <StatusIcon s={status.enableUser} /> : <UserCheck size={14} />}
              <span>Enable</span>
            </button>
          </div>
          {(msg.disableUser || msg.enableUser) && (
            <p className="text-[11px] text-muted">{msg.disableUser || msg.enableUser}</p>
          )}
        </div>
      </div>
    </Panel>
  );
}
