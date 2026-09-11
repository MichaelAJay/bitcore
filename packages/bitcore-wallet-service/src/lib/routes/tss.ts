import express from 'express';
import * as Types from '../../types/expressapp';
import { TssKeyGen, TssSign } from '../tss';
import { authRequest } from './middleware/authRequest';
import { authTssRequest } from './middleware/authTssRequest';
import { createWalletLimiter } from './middleware/createWalletLimiter';
import { verifyTssMessage } from './middleware/verifyTssMessage';


interface TssRouterOpts {
  returnError: Types.ReturnErrorFn;
  opts: {
    ignoreRateLimiter?: boolean;
  };
};

export class TssRouter {
  router: express.Router;

  constructor(params: TssRouterOpts) {
    const { returnError, opts } = params;
    const router = express.Router();
    
    /** Key generation methods */

    router.post('/v1/tss/keygen/:id', createWalletLimiter(opts), verifyTssMessage, async function(req, res) {
      try {
        const id = req.params.id;
        // version was not given by client until 1.1, so fallback to 1.0
        const { message, n, password, version = 1.0, timeLimit } = req.body;
        const copayerId = req.headers['x-identity'];
        await TssKeyGen.processMessage({ id, message, n, password, copayerId, version, timeLimit });
        return res.send();
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });

    router.get('/v1/tss/keygen/:id/:round', authTssRequest(), async function(req, res) {
      let interval: NodeJS.Timeout;
      const controller = new AbortController();
      const onClose = () => {
        clearInterval(interval);
        // Stopping heartbeats alone leaves the broker subscription and poll timeout alive.
        controller.abort();
      };
      // IncomingMessage.close describes completion of the request, not the response.
      // Register before the first await so disconnects during validation are not missed.
      res.once('close', onClose);
      try {
        if (res.destroyed) return;
        const { id, round } = req.params as { [key: string]: string };
        const { maxWaitTime } = req.query as { [key: string]: string };
        const copayerId = req.headers['x-identity'];
        if (round === 'secret') {
          const secret = await TssKeyGen.getBwsJoinSecret({ id, copayerId });
          if (res.destroyed || controller.signal.aborted) return;
          return res.json({ secret });
        }

        // Validate access and fetch session before committing to a streaming response, so that errors like
        //   "session not found" or "not a participant" can still be returned with a proper
        //   HTTP status instead of silently becoming an empty 200 (see below).
        const session = await TssKeyGen.getSessionForCopayer({ id, copayerId });
        // The response may have closed while the database lookup was pending. Do not
        // start a heartbeat or subscription for a client that has already gone away.
        if (res.destroyed || controller.signal.aborted) return;

        // Keep the connection alive while waiting for a session update.
        // Headers must be finalized before writing the first heartbeat byte.
        // Flush ensures the heartbeat is sent immediately to keep the connection alive.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        interval = setInterval(() => { res.write('\n'); res.flush(); }, 1000);

        const { messages, publicKey } = await TssKeyGen.getMessagesForParty({ session, round: parseInt(round), copayerId, maxWaitTimeSec: parseInt(maxWaitTime), signal: controller.signal });
        if (res.destroyed || controller.signal.aborted) return;
        return res.end(JSON.stringify({ messages, publicKey }));
      } catch (err) {
        if (res.destroyed || controller.signal.aborted) return;
        return returnError(err ?? 'unknown', res, req);
      } finally {
        clearInterval(interval);
        // Normal completion and failures also release our response listener.
        res.removeListener('close', onClose);
      }
    });

    router.post('/v1/tss/keygen/:id/store', authTssRequest(), async function(req, res) {
      try {
        const id = req.params.id;
        const copayerId = req.headers['x-identity'];
        const message = req.body;

        await TssKeyGen.storeKey({ id, message, copayerId });
        return res.send();
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });

    router.post('/v1/tss/keygen/:id/secret', authTssRequest(), async function(req, res) {
      try {
        const id = req.params.id;
        const { secret } = req.body;
        const copayerId = req.headers['x-identity'];
        await TssKeyGen.storeBwsJoinSecret({ id, secret, copayerId });
        return res.send();
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });

    router.get('/v1/tss/keygen/:id/secret', authTssRequest(), async function(req, res) {
      try {
        const id = req.params.id;
        const copayerId = req.headers['x-identity'];
        const secret = await TssKeyGen.getBwsJoinSecret({ id, copayerId });
        return res.json({ secret });
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });


    /** Signature Methods */

    router.post('/v1/tss/sign/:id', authRequest(), verifyTssMessage, async function(req, res) {
      try {
        const id = req.params.id;
        // version was not given by client until 1.1, so fallback to 1.0
        const { message, m, version = 1.0, timeLimit } = req.body;
        const copayerId = req.headers['x-identity'];
        await TssSign.processMessage({ id, message, m, copayerId, version, timeLimit });
        return res.send();
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });

    router.get('/v1/tss/sign/:id/:round', authTssRequest(), async function(req, res) {
      let interval: NodeJS.Timeout;
      const controller = new AbortController();
      const onClose = () => {
        clearInterval(interval);
        // Stopping heartbeats alone leaves the broker subscription and poll timeout alive.
        controller.abort();
      };
      // IncomingMessage.close describes completion of the request, not the response.
      // Register before the first await so disconnects during validation are not missed.
      res.once('close', onClose);
      try {
        if (res.destroyed) return;
        const { id, round } = req.params as { [key: string]: string };
        const { maxWaitTime } = req.query as { [key: string]: string };
        const copayerId = req.headers['x-identity'];

        // Validate access and fetch session before committing to a streaming response, so that errors like
        //   "session not found" or "not a participant" can still be returned with a proper
        //   HTTP status instead of silently becoming an empty 200 (see below).
        const session = await TssSign.getSessionForCopayer({ id, copayerId });
        // The response may have closed while the database lookup was pending. Do not
        // start a heartbeat or subscription for a client that has already gone away.
        if (res.destroyed || controller.signal.aborted) return;

        // Keep the connection alive while waiting for a session update.
        // Headers must be finalized before writing the first heartbeat byte.
        // Flush ensures the heartbeat is sent immediately to keep the connection alive.
        res.writeHead(200, { 'Content-Type': 'application/json' });
        interval = setInterval(() => { res.write('\n'); res.flush(); }, 1000);

        const { messages, signature, participants } = await TssSign.getMessagesForParty({ session, round: parseInt(round), copayerId, maxWaitTimeSec: parseInt(maxWaitTime), signal: controller.signal });
        if (res.destroyed || controller.signal.aborted) return;
        return res.end(JSON.stringify({ messages, signature, participants }));
      } catch (err) {
        if (res.destroyed || controller.signal.aborted) return;
        return returnError(err ?? 'unknown', res, req);
      } finally {
        clearInterval(interval);
        // Normal completion and failures also release our response listener.
        res.removeListener('close', onClose);
      }
    });

    router.post('/v1/tss/sign/:id/store', authTssRequest(), async function(req, res) {
      try {
        const id = req.params.id;
        const { signature } = req.body;
        await TssSign.storeSignature({ id, signature });
        return res.send();
      } catch (err) {
        return returnError(err ?? 'unknown', res, req);
      }
    });

    this.router = router;
  }
}