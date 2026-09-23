import process from "node:process";
import { prisma } from "../src/lib/prisma.ts";
import { configureDatabase } from "../src/lib/database-runtime.ts";

if (!process.env.DATABASE_URL?.startsWith("file:")) throw new Error("Set DATABASE_URL to the local SQLite file before preparing it.");
try { await configureDatabase(prisma); }
finally { await prisma.$disconnect(); }
