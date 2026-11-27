import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { publishWorkerHeartbeat } from "./worker-heartbeat.ts";

for (const worker of ["ai", "scan"] as const) {
  test(`${worker} heartbeat atomically replaces an existing entry`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "aegify-heartbeat-test-"));
    try {
      const name = worker === "ai" ? "aegify-ai-worker-health" : "aegify-worker-health";
      const path = join(directory, name);
      const other = join(directory, "other-file");
      await writeFile(other, "original contents");
      await symlink(other, path);
      await Promise.all([publishWorkerHeartbeat(worker, directory), publishWorkerHeartbeat(worker, directory)]);
      const info = await lstat(path);
      assert.ok(info.isFile());
      assert.equal(info.mode & 0o777, 0o600);
      assert.equal(await readFile(other, "utf8"), "original contents");
      assert.ok(Number.isFinite(Date.parse(await readFile(path, "utf8"))));
      assert.deepEqual((await readdir(directory)).sort(), [name, "other-file"].sort());
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
