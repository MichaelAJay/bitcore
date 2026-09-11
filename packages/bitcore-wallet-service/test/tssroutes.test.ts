import { EventEmitter } from 'events';
import { expect } from 'chai';
import sinon from 'sinon';
import { TssRouter } from '../src/lib/routes/tss';
import { TssKeyGen, TssSign } from '../src/lib/tss';

// Invoke the final route handler directly: authentication and database behavior are
// separate concerns, while these tests exercise response lifetime across awaits.
describe('TSS polling route cleanup', function() {
  const sandbox = sinon.createSandbox();
  for (const type of ['keygen', 'sign']) {
    describe(type, function() {
      let clock: sinon.SinonFakeTimers;
      let handler: Function;
      let req: any;
      let res: any;
      let getSession: sinon.SinonStub;
      let getMessages: sinon.SinonStub;
      let returnError: sinon.SinonStub;

      beforeEach(function() {
        clock = sandbox.useFakeTimers();
        const service = type === 'keygen' ? TssKeyGen : TssSign;
        getSession = sandbox.stub(service, 'getSessionForCopayer').resolves({});
        getMessages = sandbox.stub(service, 'getMessagesForParty').resolves({});
        returnError = sandbox.stub();
        const router = new TssRouter({ opts: { ignoreRateLimiter: true }, returnError }).router;
        const route = router.stack.find(layer => layer.route?.path === `/v1/tss/${type}/:id/:round`).route;
        handler = route.stack[route.stack.length - 1].handle;
        req = Object.assign(new EventEmitter(), {
          params: { id: 'session', round: '0' }, query: {}, headers: { 'x-identity': 'alice' }
        });
        res = Object.assign(new EventEmitter(), {
          destroyed: false, writeHead: sandbox.stub(), write: sandbox.stub(),
          flush: sandbox.stub(), end: sandbox.stub()
        });
      });

      afterEach(function() { sandbox.restore(); });

      it('keeps heartbeats after request completion and cancels on response close', async function() {
        getMessages.callsFake(({ signal }) => new Promise(resolve => {
          signal.addEventListener('abort', () => resolve({}), { once: true });
        }));
        const pending = handler(req, res);
        await Promise.resolve();
        req.emit('close');
        clock.tick(1000);
        expect(res.write.calledOnceWithExactly('\n')).to.equal(true);
        res.destroyed = true;
        res.emit('close');
        await pending;
        expect(getMessages.firstCall.args[0].signal.aborted).to.equal(true);
        expect(res.end.called).to.equal(false);
        expect(returnError.called).to.equal(false);
        expect(clock.countTimers()).to.equal(0);
        expect(res.listenerCount('close')).to.equal(0);
      });

      it('does not start polling when the response closes during validation', async function() {
        let release: (session: any) => void;
        getSession.returns(new Promise(resolve => { release = resolve; }));
        const pending = handler(req, res);
        res.destroyed = true;
        res.emit('close');
        release({});
        await pending;
        expect(getMessages.called).to.equal(false);
        expect(res.writeHead.called).to.equal(false);
        expect(clock.countTimers()).to.equal(0);
        expect(res.listenerCount('close')).to.equal(0);
      });

      it('cleans up on normal completion', async function() {
        await handler(req, res);
        expect(res.end.calledOnceWithExactly('{}')).to.equal(true);
        expect(clock.countTimers()).to.equal(0);
        expect(res.listenerCount('close')).to.equal(0);
      });

      it('cleans up and reports a polling failure while the response is open', async function() {
        const failure = new Error('database failed');
        getMessages.rejects(failure);
        await handler(req, res);
        expect(returnError.calledOnceWithExactly(failure, res, req)).to.equal(true);
        expect(clock.countTimers()).to.equal(0);
        expect(res.listenerCount('close')).to.equal(0);
      });
    });
  }
});
