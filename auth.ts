import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { PrismaAdapter } from "@next-auth/prisma-adapter";
import prisma from "@/utils/db";
import hash from "@/utils/hash";
import * as jose from "jose";

export const authOptions = {
  adapter: PrismaAdapter(prisma),
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {},
        password: {},
      },
      async authorize(credentials) {
        // using prisma adapter
        const userData = await prisma.user.findUnique({
          where: {
            email: credentials?.email 
          },
          include: {
            role: true,
          },
        });

        if (userData) {
          const isPasswordValid = await hash.compare(
            credentials?.password as string,
            userData?.password || "",
          );
          if (!isPasswordValid) return null;
        }

        const { password, ...user } = userData as any;
        return user;
      },
    }),
  ],
  session: { strategy: "jwt", maxAge: 15 * 60 },
  callbacks: {
    async jwt({ token, user }) {
      if (user) token.user = user as any;
      // console.log("token", token);
      return token;
    },
    async session({ session, token }) {
      session.user = token.user;
      // console.log("session", session);
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
  jwt: {
    async encode({ token, secret, maxAge }) {
      const iat = Math.floor(Date.now() / 1000);
      const exp = iat + maxAge!;
      // console.log("enc", exp);
      const stringToken = JSON.stringify({ ...token, iat, exp });
      const tokenUint8Array = new TextEncoder().encode(stringToken);
      const secretUint8Array = new TextEncoder().encode(secret as string);
      // create jwe token using jose
      const accessToken = await new jose.CompactEncrypt(tokenUint8Array)
        .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
        .encrypt(secretUint8Array);
      return accessToken;
    },
    async decode({ token, secret }) {
      const secretUint8Array = new TextEncoder().encode(secret as string);
      const decodedToken = await jose.compactDecrypt(
        token as string,
        secretUint8Array,
      );
      const decodedText = new TextDecoder().decode(decodedToken.plaintext);
      const data = JSON.parse(decodedText);
      return data;
    },
  },
  pages: {
    signIn: "/login",
    error: "/error",
    // verifyRequest: '/auth/verify-request',
  },
} satisfies NextAuthOptions;
