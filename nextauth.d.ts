import NextAuth, { DefaultSession } from "next-auth";
import { DefaultJWT } from "next-auth/jwt";
import { User } from "@/types/user";

declare module "next-auth" {
  interface Session {
    user: User;
    expires: string;
    accessToken: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    user: User;
    expires: string;
    accessToken: string;
  }
}
