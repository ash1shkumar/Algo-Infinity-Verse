import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getFirestore } from "firebase-admin/firestore";
import crypto from "crypto";

let db = null;
let useFirestore = false;

function initFirebase() {
  if (getApps().length > 0) {
    db = getFirestore();
    useFirestore = true;
    return;
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n");

  if (!projectId || !clientEmail || !privateKey) {
    console.warn("Firebase credentials not set.");
    return;
  }

  try {
    initializeApp({
      credential: cert({
        projectId,
        clientEmail,
        privateKey,
      }),
    });

    db = getFirestore();
    useFirestore = true;
  } catch (e) {
    console.error(e);
  }
}

initFirebase();

const SESSION_COOKIE = "aiv_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 7;
const PBKDF2_ITERATIONS = 210000;
const PASSWORD_KEY_LENGTH = 32;

function sessionSecret() {
  return (
    process.env.SESSION_SECRET ||
    "dev-only-change-me-with-SESSION_SECRET-before-deploying"
  );
}

function sign(value) {
  return crypto
    .createHmac("sha256", sessionSecret())
    .update(value)
    .digest("base64url");
}

function b64u(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function createSessionToken(user) {
  const header = b64u(
    JSON.stringify({
      alg: "HS256",
      typ: "JWT",
    })
  );

  const payload = b64u(
    JSON.stringify({
      sub: user.id,
      name: user.name,
      email: user.email,
      exp: Math.floor(Date.now() / 1000) + SESSION_MAX_AGE_SECONDS,
    })
  );

  return `${header}.${payload}.${sign(`${header}.${payload}`)}`;
}

function hashPassword(
  password,
  salt = crypto.randomBytes(16).toString("hex")
) {
  return {
    salt,
    hash: crypto
      .pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATIONS,
        PASSWORD_KEY_LENGTH,
        "sha256"
      )
      .toString("hex"),
    iterations: PBKDF2_ITERATIONS,
    digest: "sha256",
  };
}

function sessionCookie(token) {
  const secure = process.env.VERCEL === "1";

  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "HttpOnly",
    "SameSite=Lax",
    "Path=/",
    `Max-Age=${SESSION_MAX_AGE_SECONDS}`,
    secure ? "Secure" : "",
  ]
    .filter(Boolean)
    .join("; ");
}

async function readUsers() {
  if (!useFirestore) return [];

  try {
    const snapshot = await db.collection("users").get();

    return snapshot.docs.map((doc) => ({
      id: doc.id,
      ...doc.data(),
    }));
  } catch (e) {
    console.error(e);
    return [];
  }
}

async function createUserTransaction(user) {
  if (!useFirestore) {
    throw new Error("Firestore unavailable");
  }

  const existing = await db
    .collection("users")
    .where("email", "==", user.email)
    .limit(1)
    .get();

  if (!existing.empty) {
    throw new Error("DUPLICATE_USER");
  }

  const docRef = await db.collection("users").add(user);

  return docRef;
}

async function rollbackUserCreation(docRef) {
  if (!docRef) return;

  try {
    await docRef.delete();
  } catch (error) {
    console.error("Rollback failed:", error);
  }
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({
      error: "Method not allowed",
    });
  }

  try {
    const {
      name,
      email,
      password,
      confirmPassword,
    } = req.body;

    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "")
      .trim()
      .toLowerCase();

    const rawPassword = String(password || "");
    const rawConfirmPassword = String(confirmPassword || "");

    if (cleanName.length < 2) {
      return res.status(400).json({
        error: "Name must be at least 2 characters.",
      });
    }

    if (
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)
    ) {
      return res.status(400).json({
        error: "Enter a valid email address.",
      });
    }

    if (rawPassword.length < 8) {
      return res.status(400).json({
        error: "Password must be at least 8 characters.",
      });
    }

    if (
      !/[a-z]/.test(rawPassword) ||
      !/[A-Z]/.test(rawPassword) ||
      !/\d/.test(rawPassword)
    ) {
      return res.status(400).json({
        error:
          "Password must include uppercase, lowercase, and a number.",
      });
    }

    if (rawPassword !== rawConfirmPassword) {
      return res.status(400).json({
        error: "Passwords do not match.",
      });
    }

    const users = await readUsers();

    if (
      users.some(
        (user) => user.email === cleanEmail
      )
    ) {
      return res.status(409).json({
        error:
          "An account with this email already exists.",
      });
    }

    const user = {
      id: crypto.randomUUID(),
      name: cleanName,
      email: cleanEmail,
      password: hashPassword(rawPassword),
      xp: 0,
      level: 1,
      avatar: "🚀",
      createdAt: new Date().toISOString(),
    };

    let createdUserDoc = null;

    try {
      if (useFirestore) {
        createdUserDoc = await createUserTransaction(user);
      }

      const token = createSessionToken(user);

      return res
        .status(201)
        .setHeader(
          "Set-Cookie",
          sessionCookie(token)
        )
        .json({
          user: {
            id: user.id,
            name: user.name,
            email: user.email,
          },
        });
    } catch (error) {
      await rollbackUserCreation(createdUserDoc);

      if (error.message === "DUPLICATE_USER") {
        return res.status(409).json({
          error:
            "An account with this email already exists.",
        });
      }

      throw error;
    }
  } catch (e) {
    console.error(e);

    return res.status(500).json({
      error: "Internal server error",
    });
  }
}