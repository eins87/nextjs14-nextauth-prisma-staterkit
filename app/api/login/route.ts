import { NextRequest, NextResponse } from "next/server";
import prisma from "@/utils/db";
import { compare } from "@/utils/hash";
import * as jose from "jose";
import { z } from "zod";

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

export async function POST(req: NextRequest) {
  const { email, password } = await req.json();
  const secret = process.env.NEXTAUTH_SECRET as string;

  // validate email and password
  const result = loginSchema.safeParse({ email, password });
  if (!result.success) {
    const error = result.error.issues.map(
      (issue) => issue.path + ": " + issue.message,
    );
    return NextResponse.json({ message: error }, { status: 400 });
  }
  // find the user
  const user = await prisma.user.findUnique({ where: { email }, include: { role: true} });
  // return an error if the user is not found
  if (!user) {
    return NextResponse.json(
      { message: "User Not Found!" },
      { status: 401 },
    );
  }
  // compare the password
  const isPasswordValid = await compare(password, user?.password || "");
  if (!isPasswordValid) {
    return NextResponse.json(
      { message: "Invalid username or password" },
      { status: 401 },
    );
  }
  // create a session and generate a token
  if (user) {
    const { password, createdAt, updatedAt, ...userSession } = user;
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + 15 * 60; // 15 minutes
    const userUint8Array = new TextEncoder().encode(
      JSON.stringify({ user: user, iat: iat, exp: exp }),
    );
    const secretUint8Array = new TextEncoder().encode(secret);
    const token = await new jose.CompactEncrypt(userUint8Array)
      .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
      .encrypt(secretUint8Array);
    return NextResponse.json(
      { user: { ...userSession }, accessToken: token },
      { status: 200 },
    );
  }
  // return an error if the user is not found
  return NextResponse.json(
    { message: "Invalid username or password" },
    { status: 401 },
  );
}