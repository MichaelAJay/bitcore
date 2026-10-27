import { expect } from 'chai';
import sinon from 'sinon';
import { MessageBroker } from '../src/lib/messagebroker';
import { TssKeyGenModel } from '../src/lib/model/tsskeygen';
import { TssSigGenModel } from '../src/lib/model/tsssign';
import { WalletService } from '../src/lib/server';
import { Storage } from '../src/lib/storage';

describe('TSS session subscriptions', function() {
  const sandbox = sinon.createSandbox();
  const broker = new MessageBroker(null);
  let TssKeyGen: typeof import('../src/lib/tss').TssKeyGen;
  let TssSign: typeof import('../src/lib/tss').TssSign;
  let storage: Storage;
  let clock: sinon.SinonFakeTimers;
  let session: TssKeyGenModel;
  let fetchSession: sinon.SinonStub;

  function poll(maxWaitTimeSec = 20) {
    return TssKeyGen.getMessagesForParty({ session, round: 0, copayerId: 'alice', maxWaitTimeSec });
  }

  function completeSession() {
    return Object.assign(new TssKeyGenModel(), session, {
      rounds: [[{
        fromPartyId: 1,
        messages: { partyId: 1, round: 0, publicKey: '', broadcastMessages: [], p2pMessages: [] }
      }]]
    });
  }

  before(async function() {
    const modulePath = require.resolve('../src/lib/tss');
    const cachedModule = require.cache[modulePath];
    delete require.cache[modulePath];
    try {
      ({ TssKeyGen, TssSign } = await import(modulePath));
    } finally {
      if (cachedModule) {
        require.cache[modulePath] = cachedModule;
      } else {
        delete require.cache[modulePath];
      }
    }
  });

  beforeEach(function() {
    clock = sandbox.useFakeTimers();
    storage = new Storage();
    sandbox.stub(WalletService, 'getMessageBroker').returns(broker);
    sandbox.stub(WalletService, 'getStorage').returns(storage);
    session = Object.assign(new TssKeyGenModel(), {
      id: 'session', n: 2, participants: ['alice', 'bob'], rounds: [[]]
    });
    fetchSession = sandbox.stub(storage, 'fetchTssKeyGenSession').resolves(session);
  });

  afterEach(function() {
    sandbox.restore();
  });

  it('uses one broker listener for 20 polls and removes completed subscriptions', async function() {
    const existingHandler = sandbox.stub();
    broker.onMessage(existingHandler);
    try {
      const polls = Array.from({ length: 20 }, () => poll());
      expect(broker.listenerCount('msg')).to.equal(2);

      fetchSession.resolves(completeSession());
      broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
      const results = await Promise.all(polls);
      expect(results.every(result => result.messages.length === 1)).to.equal(true);
      expect(existingHandler.calledOnce).to.equal(true);
      expect(clock.countTimers()).to.equal(0);

      fetchSession.resetHistory();
      broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
      expect(fetchSession.called).to.equal(false);
      expect(broker.listenerCount('msg')).to.equal(2);
    } finally {
      broker.offMessage(existingHandler);
    }
  });

  it('routes by session ID and message type for keygen and signing', async function() {
    const signingSession = Object.assign(new TssSigGenModel(), {
      id: session.id, m: 2, participants: [{ partyId: 0, copayerId: 'alice' }], rounds: [[]]
    });
    const fetchSigning = sandbox.stub(storage, 'fetchTssSigSession').resolves(signingSession);
    const keygenPoll = poll(1);
    const signingPoll = TssSign.getMessagesForParty({
      session: signingSession, round: 0, copayerId: 'alice', maxWaitTimeSec: 1
    });
    fetchSession.resetHistory();
    fetchSigning.resetHistory();

    broker.emit('msg', { type: 'TssKeyGenMessage', id: 'other-session' });
    broker.emit('msg', { type: 'unrelated', id: session.id });
    expect(fetchSession.called).to.equal(false);
    expect(fetchSigning.called).to.equal(false);
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    expect(fetchSession.calledOnce).to.equal(true);
    expect(fetchSigning.called).to.equal(false);
    broker.emit('msg', { type: 'TssSigMessage', id: session.id });
    expect(fetchSigning.calledOnce).to.equal(true);
    expect(fetchSession.calledOnce).to.equal(true);
    expect(broker.listenerCount('msg')).to.equal(1);

    clock.tick(1000);
    await Promise.all([keygenPoll, signingPoll]);
    fetchSession.resetHistory();
    fetchSigning.resetHistory();
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    broker.emit('msg', { type: 'TssSigMessage', id: session.id });
    expect(fetchSession.called).to.equal(false);
    expect(fetchSigning.called).to.equal(false);
    expect(broker.listenerCount('msg')).to.equal(1);
  });

  it('removes only the timed-out poll and allows later subscriptions', async function() {
    const shortPoll = poll(1);
    const longPoll = poll(2);
    clock.tick(1000);
    expect(await shortPoll).to.deep.equal({});
    expect(broker.listenerCount('msg')).to.equal(1);
    fetchSession.resetHistory();
    fetchSession.resolves(completeSession());
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    expect((await longPoll).messages).to.have.length(1);
    expect(fetchSession.calledOnce).to.equal(true);
    expect(broker.listenerCount('msg')).to.equal(1);

    fetchSession.resolves(session);
    const laterPoll = poll(1);
    expect(broker.listenerCount('msg')).to.equal(1);
    fetchSession.resolves(completeSession());
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    expect((await laterPoll).messages).to.have.length(1);
    expect(broker.listenerCount('msg')).to.equal(1);
    expect(clock.countTimers()).to.equal(0);
  });

  it('cleans up when the final database recheck finds a complete round', async function() {
    fetchSession.resolves(completeSession());
    expect((await poll()).messages).to.have.length(1);
    expect(broker.listenerCount('msg')).to.equal(1);
    expect(clock.countTimers()).to.equal(0);
    fetchSession.resetHistory();
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    expect(fetchSession.called).to.equal(false);
  });

  it('cleans up when the final database recheck rejects', async function() {
    const failure = new Error('database unavailable');
    fetchSession.rejects(failure);
    const result = await poll().then(() => undefined, err => err);
    expect(result).to.equal(failure);
    expect(broker.listenerCount('msg')).to.equal(1);
    expect(clock.countTimers()).to.equal(0);
    fetchSession.resetHistory();
    broker.emit('msg', { type: 'TssKeyGenMessage', id: session.id });
    expect(fetchSession.called).to.equal(false);
  });

});

describe('KeyGen admission', function() {
  const sandbox = sinon.createSandbox();
  let TssKeyGen: typeof import('../src/lib/tss').TssKeyGen;
  let storage: Storage;
  let updateOne: sinon.SinonStub;
  let insertOne: sinon.SinonStub;
  let brokerSend: sinon.SinonStub;
  let fetchSession: sinon.SinonStub;

  const N = 3;
  const broadcast = (partyId: number, round = 0, publicKey = 'key' + partyId) => ({
    round, partyId, publicKey,
    broadcastMessages: [{ from: partyId, payload: { message: 'm', signature: 's' } }],
    p2pMessages: []
  });
  const p2p = (partyId: number, round = 1, publicKey = 'key' + partyId) => ({
    round, partyId, publicKey,
    broadcastMessages: [],
    p2pMessages: [0, 1, 2].filter(to => to !== partyId).map(to => ({
      from: partyId, to, commitment: 'c', payload: { encryptedMessage: 'e', signature: 's' }
    }))
  });
  const makeSession = (opts: { version?: number; joined?: number[]; registered?: number[]; participants?: string[] } = {}) => {
    const { version = 1.1, joined = [], registered = [] } = opts;
    const session = Object.assign(new TssKeyGenModel(), {
      id: 'session',
      n: N,
      schemeVersion: version,
      participants: opts.participants ?? ['alice', null, null],
      authPublicKeys: ['key0', null, null],
      rounds: [[{ fromPartyId: 0, messages: broadcast(0) }]],
      __v: 0
    });
    for (const partyId of registered) session.authPublicKeys[partyId] = 'key' + partyId;
    for (const partyId of joined) {
      session.authPublicKeys[partyId] = 'key' + partyId;
      session.participants[partyId] = ['alice', 'bob', 'carol'][partyId];
      session.rounds[0].push({ fromPartyId: partyId, messages: broadcast(partyId) });
    }
    return session;
  };
  const submit = (message: any, copayerId = 'bob', extra: { version?: number; password?: string } = {}) =>
    TssKeyGen.processMessage({ id: 'session', message, copayerId, version: extra.version ?? 1.1, password: extra.password });
  const rejection = (p: Promise<any>) => p.then(() => undefined, err => err);
  /** Writes that reached the database, whatever the storage method that issued them */
  const writes = () => updateOne.getCalls().concat(insertOne.getCalls());
  const expectRefused = async (p: Promise<any>) => {
    const err = await rejection(p);
    expect(err, 'expected a rejection').to.not.equal(undefined);
    expect(err).to.not.be.instanceOf(TypeError);
    expect(writes(), 'a write reached the database').to.have.length(0);
    expect(brokerSend.called, 'a notification was published').to.equal(false);
    return err;
  };

  before(async function() {
    ({ TssKeyGen } = await import('../src/lib/tss'));
  });

  beforeEach(function() {
    storage = new Storage();
    updateOne = sandbox.stub().resolves({ result: { ok: 1 }, matchedCount: 1 });
    insertOne = sandbox.stub().resolves({ result: { ok: 1 } });
    (storage as any).db = { collection: () => ({ updateOne, insertOne, countDocuments: sandbox.stub().resolves(1) }) };
    brokerSend = sandbox.stub();
    sandbox.stub(WalletService, 'getStorage').returns(storage);
    sandbox.stub(WalletService, 'getMessageBroker').returns({ send: brokerSend } as any);
    fetchSession = sandbox.stub(storage, 'fetchTssKeyGenSession').resolves(makeSession());
  });

  afterEach(function() {
    sandbox.restore();
  });

  describe('direct service boundaries', function() {
    it('should reject a partyId equal to n before any write', async function() {
      await expectRefused(submit(broadcast(N)));
    });

    it('should reject a non-canonical partyId before any write', async function() {
      await expectRefused(submit(broadcast(NaN)));
    });

    it('should reject a p2p recipient equal to n before any write', async function() {
      fetchSession.resolves(makeSession({ joined: [1, 2] }));
      const message = p2p(1);
      message.p2pMessages[0].to = N;
      await expectRefused(submit(message));
    });

    it('should reject a later-round message for a vacant slot without enrolling it', async function() {
      await expectRefused(submit(p2p(1)));
    });

    it('should reject a round 0 message for a vacant slot whose round 0 message exists', async function() {
      const session = makeSession({ joined: [1] });
      session.participants[1] = null;
      fetchSession.resolves(session);
      await expectRefused(submit(broadcast(1)));
    });
  });

  describe('ownership and key binding', function() {
    it('should reject another copayer for an enrolled slot', async function() {
      fetchSession.resolves(makeSession({ joined: [1] }));
      await expectRefused(submit(broadcast(1), 'mallory'));
    });

    it('should reject an enrolled copayer claiming a second slot', async function() {
      fetchSession.resolves(makeSession({ joined: [1] }));
      await expectRefused(submit(broadcast(2), 'bob'));
    });

    it('should reject an enrolled sender submitting a different wrapper key', async function() {
      fetchSession.resolves(makeSession({ joined: [1, 2] }));
      await expectRefused(submit(p2p(1, 1, 'other-key'), 'bob'));
    });

    it('should reject a v1.2 joiner whose key is not the registered key for the slot', async function() {
      fetchSession.resolves(makeSession({ version: 1.2, registered: [1] }));
      await expectRefused(submit(broadcast(1, 0, 'other-key'), 'bob', { version: 1.2 }));
    });

    it('should reject a wrong join password', async function() {
      const session = makeSession();
      session.joinPassword = 'not-the-hash';
      fetchSession.resolves(session);
      await expectRefused(submit(broadcast(1), 'bob', { password: 'wrong' }));
    });
  });

  describe('atomic admission', function() {
    it('should commit an enrollment and its first message with one write', async function() {
      await submit(broadcast(1));
      expect(writes(), 'enrollment and message must share one write').to.have.length(1);
      expect(brokerSend.calledOnce).to.equal(true);
    });

    it('should not leave a participant enrolled when the message cannot be stored', async function() {
      updateOne.callsFake(async (_filter, update) => {
        if (update.$push) throw new Error('injected failure');
        return { result: { ok: 1 }, matchedCount: 1 };
      });
      const err = await rejection(submit(broadcast(1)));
      expect(err?.message).to.equal('injected failure');
      const enrolled = updateOne.getCalls().filter(c => Object.keys(c.args[1].$set || {}).some(k => k.startsWith('participants.')));
      expect(enrolled, 'a participant write succeeded without its message').to.have.length(0);
      expect(brokerSend.called).to.equal(false);
    });
  });

  describe('retries after a version conflict', function() {
    const conflictOnce = () => updateOne.onFirstCall().resolves({ result: { ok: 1 }, matchedCount: 0 });
    const statesInOrder = (...states: any[]) => {
      fetchSession.callsFake(async () => states.length > 1 ? states.shift() : states[0]);
    };

    it('should admit after another slot joined meanwhile', async function() {
      conflictOnce();
      statesInOrder(makeSession(), makeSession({ joined: [2] }));
      await submit(broadcast(1));
      expect(brokerSend.calledOnce).to.equal(true);
      expect(updateOne.callCount).to.equal(2);
    });

    it('should reject when another copayer took the slot meanwhile', async function() {
      conflictOnce();
      statesInOrder(makeSession(), makeSession({ joined: [1], participants: ['alice', 'carol', null] }));
      const err = await rejection(submit(broadcast(1)));
      expect(err).to.not.equal(undefined);
      expect(updateOne.callCount).to.equal(1);
      expect(brokerSend.called).to.equal(false);
    });

    it('should reject a pending v1.2 join when the creator changed the registered key meanwhile', async function() {
      conflictOnce();
      const replaced = makeSession({ version: 1.2, registered: [1] });
      replaced.authPublicKeys[1] = 'replacement-key';
      statesInOrder(makeSession({ version: 1.2, registered: [1] }), replaced);
      const err = await rejection(submit(broadcast(1), 'bob', { version: 1.2 }));
      expect(err).to.not.equal(undefined);
      expect(updateOne.callCount).to.equal(1);
      expect(brokerSend.called).to.equal(false);
    });

    it('should reject when the session expired meanwhile', async function() {
      conflictOnce();
      const expired = makeSession();
      expired.createdOn = Date.now() - 2 * 60 * 60 * 1000;
      expired.timeLimit = 60 * 1000;
      statesInOrder(makeSession(), expired);
      const err = await rejection(submit(broadcast(1)));
      expect(err?.code).to.equal('TSS_SESSION_EXPIRED');
      expect(updateOne.callCount).to.equal(1);
    });
  });
});
