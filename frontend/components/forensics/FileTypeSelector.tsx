"use client";

import { cn } from "@/lib/utils";
import { FileCode, FileText, FileArchive, Cpu, Apple, Terminal, HelpCircle } from "lucide-react";

/**
 * File-type chip selector. The selected value is passed to the backend as
 * `file_type_hint` and short-circuits auto-detection. Set to `null` (the
 * default) to let the backend auto-detect from `file` command output.
 *
 * The set of types matches FILE_TYPES in backend/adapters/remnux_adapter.py.
 */

export type FileTypeHint =
  | null
  | "pe" | "elf" | "macho"
  | "ole" | "ooxml"
  | "pdf"
  | "script_ps1" | "script_js" | "script_vbs" | "script_sh" | "script_py"
  | "archive";

interface TypeOption {
  value: FileTypeHint;
  label: string;
  icon: React.ReactNode;
  hint?: string;
}

const OPTIONS: TypeOption[] = [
  { value: null,         label: "Auto",        icon: <HelpCircle  size={12}/>, hint: "Detect from `file` command" },
  { value: "pe",         label: "PE / EXE",    icon: <Cpu         size={12}/>, hint: "Windows executable" },
  { value: "elf",        label: "ELF",         icon: <Cpu         size={12}/>, hint: "Linux executable" },
  { value: "macho",      label: "Mach-O",      icon: <Apple       size={12}/>, hint: "macOS executable" },
  { value: "ole",        label: "Office (legacy)", icon: <FileText size={12}/>, hint: "doc/xls/ppt (OLE/CDFV2)" },
  { value: "ooxml",      label: "Office (modern)", icon: <FileText size={12}/>, hint: "docx/xlsx/pptx (OOXML)" },
  { value: "pdf",        label: "PDF",         icon: <FileText    size={12}/>, hint: "PDF document" },
  { value: "script_ps1", label: "PowerShell",  icon: <Terminal    size={12}/>, hint: ".ps1 / .psm1" },
  { value: "script_js",  label: "JavaScript",  icon: <FileCode    size={12}/>, hint: ".js / .jse" },
  { value: "script_vbs", label: "VBScript",    icon: <FileCode    size={12}/>, hint: ".vbs" },
  { value: "script_sh",  label: "Shell",       icon: <Terminal    size={12}/>, hint: ".sh / bash" },
  { value: "script_py",  label: "Python",      icon: <FileCode    size={12}/>, hint: ".py" },
  { value: "archive",    label: "Archive",     icon: <FileArchive size={12}/>, hint: "zip / 7z / tar" },
];

export function FileTypeSelector({
  value,
  onChange,
  compact,
}: {
  value: FileTypeHint;
  onChange: (v: FileTypeHint) => void;
  compact?: boolean;
}) {
  return (
    <div className={compact ? "" : "mt-2"}>
      <div className="text-[10px] uppercase tracking-wider text-muted mb-1.5">
        File type {value ? <span className="text-accent">— override</span> : <span className="text-muted">— auto-detect</span>}
      </div>
      <div className="flex flex-wrap gap-1.5">
        {OPTIONS.map(opt => (
          <button
            key={String(opt.value)}
            onClick={() => onChange(opt.value)}
            title={opt.hint}
            className={cn(
              "inline-flex items-center gap-1 px-2 py-1 rounded-md border text-[11px] transition-colors",
              value === opt.value
                ? "bg-accent/15 border-accent/60 text-accent"
                : "border-line text-muted hover:text-text hover:border-line/80",
            )}
          >
            {opt.icon}
            {opt.label}
          </button>
        ))}
      </div>
    </div>
  );
}
