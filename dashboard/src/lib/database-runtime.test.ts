import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { PrismaClient } from "@prisma/client";
import { configureDatabase, writeTransaction } from "./database-runtime.ts";

test("a contending writer reads the previous commit once and reserves no setting rows", async () => {
  const directory = await mkdtemp(join(tmpdir(), "aegify-write-queue-"));
  const url = "file:" + join(directory, "owned.db");
  const connect = () => new PrismaClient({ adapter: new PrismaLibSql({ url }) });
  const first = connect(),
    second = connect();
  try {
    await configureDatabase(first);
    await first.$executeRaw`CREATE TABLE "Setting" (key TEXT PRIMARY KEY, value TEXT)`;
    await first.$executeRaw`INSERT INTO "Setting" VALUES ('version', 'before')`;
    await first.$executeRaw`CREATE TABLE changes (value TEXT)`;
    await first.$executeRaw`CREATE TRIGGER changed AFTER UPDATE ON "Setting" BEGIN INSERT INTO changes(value) VALUES (new.value); END`;
    const hold = Promise.withResolvers<void>(),
      entered = Promise.withResolvers<void>();
    const writer = writeTransaction(first, async (tx) => {
      await tx.$executeRaw`UPDATE "Setting" SET value='after' WHERE key='version'`;
      entered.resolve();
      await hold.promise;
    });
    await entered.promise;
    let calls = 0;
    const contender = writeTransaction(second, async (tx) => {
      calls++;
      return tx.$queryRaw<{ value: string }[]>`SELECT value FROM "Setting" WHERE key='version'`;
    });
    try {
      await delay(75);
      assert.equal(calls, 0);
    } finally {
      hold.resolve();
    }
    await writer;
    assert.deepEqual(await contender, [{ value: "after" }]);
    assert.equal(calls, 1);
    assert.deepEqual(await first.$queryRaw`SELECT value FROM changes`, [{ value: "after" }]);
    let rejected = 0;
    await assert.rejects(
      writeTransaction(second, async () => {
        rejected++;
        throw new Error("Invalid input");
      }),
      /Invalid input/,
    );
    assert.equal(rejected, 1);
  } finally {
    await Promise.allSettled([first.$disconnect(), second.$disconnect()]);
    await rm(directory, { recursive: true, force: true });
  }
});
