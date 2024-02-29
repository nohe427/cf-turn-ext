/*
 * This template contains a HTTP function that responds
 * with a greeting when called
 *
 * Reference PARAMETERS in your functions code with:
 * `process.env.<parameter-name>`
 * Learn more about building extensions in the docs:
 * https://firebase.google.com/docs/extensions/publishers
 */

export interface SiteVerifyResponse {
  success: boolean;
  "error-codes": string[];
  challenge_ts: Date;
  hostname: string;
  action: string;
  cdata: string;
}

import { onRequest } from "firebase-functions/v2/https";
import { appCheck } from "firebase-admin";
import { applicationDefault, initializeApp } from "firebase-admin/app";
import axios from "axios";
import { AppCheckToken } from "firebase-admin/app-check";
import { logger } from "firebase-functions/v2";
initializeApp({
  credential: applicationDefault(),
});

const appId = process.env.APPID || "";
const SECRET_KEY = process.env.SECRETKEY;
const ttlMinutes = process.env.ttlMinutes || 30;

const verifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

exports.tokenExchange = onRequest(
  {
    cors: true,
  },
  async (request, response) => {
    const cloudFlareToken = request.body.cloudflaretoken;
    // For use in the future when the admin sdk supports
    // limited use token minting.
    // const limiteduse = request.body.limiteduse;
    logger.log("cloud flare token recieved", cloudFlareToken);
    const result = await axios.post(
      verifyUrl,
      {
        secret: SECRET_KEY,
        response: cloudFlareToken,
      },
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      }
    );

    const outcome = (await result.data) as SiteVerifyResponse;
    if (outcome.success) {
      const appCheckToken: AppCheckToken = await appCheck().createToken(
        appId,
        /* 30 minutes until expiration */
        { ttlMillis: 60000 * (ttlMinutes as number) }
      );
      response.status(200).send({
        token: appCheckToken.token,
        expireTimeMillis: appCheckToken.ttlMillis + Date.now(),
      });
      return;
    } else {
      response.status(400).send({ token: "", expireTimeMillis: 0 });
      return;
    }
  }
);
