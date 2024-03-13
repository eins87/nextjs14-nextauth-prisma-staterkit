import { NextRequest, NextResponse } from "next/server";
import * as jose from "jose";

export { default } from "next-auth/middleware";

export async function middleware(req: NextRequest) {
  console.log("middleware: ", req.nextUrl.pathname);

  // API routes
  if (req.nextUrl.pathname.startsWith("/api")) {
    const authHeader = req.headers.get("Authorization");
    // console.log("authHeader", authHeader);
    if (!authHeader) {
      return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
    }
    // get authorization token
    const token = authHeader.replace("Bearer ", "");
    // verify token
    const user = await validateToken(token);
    // console.log("user", user);
    if (user === null)
      return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
    if ((user.exp as number) < Math.floor(Date.now() / 1000))
      return NextResponse.json({ message: "Token Expired" }, { status: 401 });

    return NextResponse.next();
  }

  // web routes
  // if (req.nextUrl.pathname.startsWith("/home")) {
  //   // check is token is present
  //   if (!req.cookies.get("next-auth.session-token")) {
  //     console.log("No Token");
  //     return NextResponse.rewrite(new URL("/login", req.nextUrl.origin), {
  //       status: 302,
  //     });
  //   }
  //   // get the token from the cookie
  //   const token = req.cookies.get("next-auth.session-token")?.value;
  //   // decode the token
  //   const secretUint8Array = new TextEncoder().encode(
  //     process.env.NEXTAUTH_SECRET as string,
  //   );
  //   try {
  //     const decodedToken = await jose.compactDecrypt(
  //       token as string,
  //       secretUint8Array,
  //     );
  //     const decodedText = new TextDecoder().decode(decodedToken.plaintext);
  //     // check if the exp is not expired
  //     if (
  //       (JSON.parse(decodedText).exp as number) < Math.floor(Date.now() / 1000)
  //     ) {
  //       console.log("Token Expired");
  //       return NextResponse.rewrite(
  //         new URL("/login", req.nextUrl.origin),
  //         {
  //           status: 302,
  //         },
  //       );
  //     }
  //     return NextResponse.next();
  //   } catch (e) {
  //     console.error("Error verifying token", e);
  //     return NextResponse.rewrite(new URL("/login", req.nextUrl.origin), {
  //       status: 302,
  //     });
  //   }
  // }
  NextResponse.next();
}

/*
 * Match all request paths except for the ones starting with:
 * - api/auth (API routes)
 * - api/login (API routes)
 * - _next/static (static files)
 * - _next/image (image optimization files)
 * - images (image files)
 * - favicon.ico (favicon file)
 */
export const config = {
  matcher: [
    "/((?!api/auth|api/login|login|_next/static|_next/image|images|favicon.ico).*)",
  ],
};

// validate token
async function validateToken(token: string) {
  const secret = new TextEncoder().encode(process.env.NEXTAUTH_SECRET);
  const tokenUint8Array = new TextEncoder().encode(token);
  try {
    const decodedToken = await jose.compactDecrypt(tokenUint8Array, secret);
    const decodedText = new TextDecoder().decode(decodedToken.plaintext);
    // console.log("decodedToken", decodedText);
    if (!decodedText) {
      return null;
    }
    return JSON.parse(decodedText);
  } catch (e) {
    // console.error("Error verifying token or token expired", e);
    return null;
  }
}
