import { Application } from '@feathersjs/feathers';

const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const { BasicStrategy } = require('../lib');
const { createApplication } = require('./fixture');
const merge = require('lodash/merge');

chai.use(chaiAsPromised);
const assert = chai.assert;

describe('authentication/basic', () => {
  let app: Application;
  let user;
  let userToken;

  beforeEach(async () => {
    app = createApplication();
    userToken = Buffer.from('David:password').toString('base64');
  });

  it('throw error when configuration is not set', () => {
    const auth = app.service('authentication');

    try {
      auth.register('something', new BasicStrategy());
      assert.fail('Should never get here');
    } catch (error) {
      assert.strictEqual(error.message,
        '\'something\' authentication strategy requires a \'usernameField\' setting'
      );
    }
  });

  describe('with authenticate hook', () => {
    it('fails for protected service and external call when not set', async () => {
      try {
        await app.service('protected').get('test', {
          provider: 'rest'
        });
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.name, 'NotAuthenticated');
        assert.strictEqual(error.message, 'Not authenticated');
      }
    });

    it('fails for protected service and external call when not strategy', async () => {
      try {
        await app.service('protected').get('test', {
          provider: 'rest',
          authentication: {
            username: 'David',
            password: 'password'
          }
        });
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.name, 'NotAuthenticated');
        assert.strictEqual(error.message, 'Invalid authentication information (no `strategy` set)');
      }
    });

    it('fails when entity service was not found', async () => {
      delete app.services.users;

      await assert.isRejected(app.service('protected').get('test', {
        provider: 'rest',
        authentication: {
          strategy: 'basic',
          accessToken: userToken
        }
      }), {
        message: 'Can not find service \'users\''
      });
    });

    it('fails when accessToken is not set', async () => {
      try {
        await app.service('protected').get('test', {
          provider: 'rest',
          authentication: {
            strategy: 'basic'
          }
        });
        assert.fail('Should never get here');
      } catch (error) {
        assert.strictEqual(error.name, 'NotAuthenticated');
        assert.strictEqual(error.message, 'No access token');
      }
    });

    it('passes when authentication is set and merges params', async () => {
      const params = {
        provider: 'rest',
        authentication: {
          strategy: 'basic',
          accessToken: userToken
        }
      };

      const result = await app.service('protected').get('test', params);

      assert.strictEqual(Object.keys(result.params).length, 4);
      assert.ok(!result.params.accessToken, 'Did not merge accessToken');
      assert.deepStrictEqual(result, {
        id: 'test',
        params: merge({}, params, {
          user,
          authentication: {
            strategy: 'basic',
            accessToken: userToken
          },
          authenticated: true
        })
      });
    });
  });

  describe('parse', () => {
    const res = {};

    it('returns null when header not set', async () => {
      const req = {};

      const result = await app.service('authentication').parse(req, res, 'basic');

      assert.strictEqual(result, null);
    });

    it('return null when scheme does not match', async () => {
      const req = {
        headers: {
          authorization: ' jwt something'
        }
      };

      const result = await app.service('authentication').parse(req, res, 'basic');

      assert.strictEqual(result, null);
    });
  });
});
