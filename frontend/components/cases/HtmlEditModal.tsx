"use client";

import { useState } from "react";
import { Editor } from "@tinymce/tinymce-react";
import { X, Save, Loader2 } from "lucide-react";

/**
 * WYSIWYG editor for the final customer-notification HTML.
 *
 * Self-hosted TinyMCE (GPL) — assets are served from /tinymce (copied into
 * public/ by the package.json postinstall), so there are no external calls and
 * no API key. `valid_elements: "*[*]"` + `verify_html: false` keep the email's
 * inline styles + table layout intact rather than reformatting them.
 */
export function HtmlEditModal({
  initialHtml,
  busy,
  onSave,
  onClose,
}: {
  initialHtml: string;
  busy: boolean;
  onSave: (html: string) => void;
  onClose: () => void;
}) {
  const [html, setHtml] = useState(initialHtml);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="bg-surface border border-line rounded-xl shadow-cyber w-full max-w-5xl p-4 space-y-3"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-2">
          <h3 className="text-text font-semibold">Edit notification HTML</h3>
          <span className="text-xs text-muted">
            Overrides the generated content until you regenerate.
          </span>
          <button onClick={onClose} className="ml-auto text-muted hover:text-text" title="Close (Esc)">
            <X size={16} />
          </button>
        </div>

        <Editor
          tinymceScriptSrc="/tinymce/tinymce.min.js"
          licenseKey="gpl"
          initialValue={initialHtml}
          onEditorChange={(content) => setHtml(content)}
          init={{
            height: 560,
            // ISOC dark theme — dark chrome + dark content canvas (navy #0b1220).
            skin: "oxide-dark",
            content_css: "dark",
            menubar: "edit view insert format table",
            plugins: "code table lists link image autolink",
            toolbar: "undo redo | bold italic | bullist numlist | link image | code",
            branding: false,
            promotion: false,
            // Preserve the email markup exactly — don't strip styles or reflow tables.
            valid_elements: "*[*]",
            verify_html: false,
            content_style: "body{font-family:Arial,Helvetica,sans-serif; background:#0b1220; color:#e6edf7;}",
          }}
        />

        <div className="flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-sm text-muted border border-line rounded-md hover:border-accent"
          >
            Cancel
          </button>
          <button
            onClick={() => onSave(html)}
            disabled={busy}
            className="flex items-center gap-1.5 px-4 py-1.5 text-sm rounded-md bg-accent/10 border border-accent/40 text-accent hover:bg-accent/20 disabled:opacity-40"
          >
            {busy ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Save HTML
          </button>
        </div>
      </div>
    </div>
  );
}
