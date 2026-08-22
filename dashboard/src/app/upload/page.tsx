"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Upload, FileUp, CheckCircle, AlertCircle } from "lucide-react";
import { uploadValidationError } from "@/lib/upload-validation";

export default function UploadPage() {
  const router = useRouter();
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState<{
    success: boolean;
    scanId?: string;
    findingsCount?: number;
    error?: string;
  } | null>(null);

  const handleUpload = useCallback(
    async (file: File) => {
      setUploading(true);
      setResult(null);

      try {
        const uploadError = uploadValidationError(file, "sarif");
        if (uploadError) {
          setResult({ success: false, error: uploadError });
          return;
        }
        const text = await file.text();
        const sarif = JSON.parse(text);

        const res = await fetch("/api/upload", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(sarif),
        });

        const data = await res.json();

        if (res.ok) {
          setResult({
            success: true,
            scanId: data.scanId,
            findingsCount: data.findingsCount,
          });
        } else {
          setResult({ success: false, error: data.error });
        }
      } catch (e) {
        setResult({
          success: false,
          error: e instanceof Error ? e.message : "Upload failed",
        });
      } finally {
        setUploading(false);
      }
    },
    []
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleUpload(file);
    },
    [handleUpload]
  );

  const onFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleUpload(file);
    },
    [handleUpload]
  );

  return (
    <div className="space-y-6 max-w-2xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold">Upload SARIF</h1>
        <p className="text-muted-foreground">
          Import scan results from Aegify CLI
        </p>
      </div>

      <Card>
        <CardContent className="pt-6">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={`border-2 border-dashed rounded-lg p-12 text-center transition-colors ${
              dragging
                ? "border-primary bg-primary/5"
                : "border-border hover:border-muted-foreground"
            }`}
          >
            <Upload className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <p className="text-lg font-medium mb-2">
              Drop your SARIF file here
            </p>
            <p className="text-sm text-muted-foreground mb-4">
              or click to browse
            </p>
            <label>
              <input
                type="file"
                accept=".sarif,.json"
                onChange={onFileSelect}
                className="hidden"
              />
              <Button variant="outline" asChild disabled={uploading}>
                <span>
                  <FileUp className="h-4 w-4 mr-2" />
                  {uploading ? "Uploading..." : "Select File"}
                </span>
              </Button>
            </label>
          </div>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardContent className="pt-6">
            {result.success ? (
              <div className="flex items-center gap-3">
                <CheckCircle className="h-6 w-6 text-[var(--status-fixed)]" />
                <div>
                  <p className="font-medium text-[var(--status-fixed)]">Upload successful</p>
                  <p className="text-sm text-muted-foreground">
                    {result.findingsCount} findings imported
                  </p>
                </div>
                <Button
                  className="ml-auto"
                  onClick={() => router.push(`/scans/${result.scanId}`)}
                >
                  View Scan
                </Button>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <AlertCircle className="h-6 w-6 text-destructive" />
                <div>
                  <p className="font-medium text-destructive">Upload failed</p>
                  <p className="text-sm text-muted-foreground">{result.error}</p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">CLI Usage</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-muted rounded-md p-4 font-mono text-sm space-y-2">
            <p className="text-muted-foreground"># Generate SARIF output</p>
            <p>aegify scan ./src --output sarif -f results.sarif</p>
            <p className="text-muted-foreground mt-4"># Upload via curl</p>
            <p>
              curl -X POST http://localhost:3000/api/upload \
            </p>
            <p className="pl-4">
              -H &quot;Content-Type: application/json&quot; \
            </p>
            <p className="pl-4">-d @results.sarif</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
