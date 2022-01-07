const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const { AuthenticationService } = require('@feathersjs/authentication');
const { BasicStrategy } = require('../lib/strategy');
const { authenticate } = require('@feathersjs/authentication').hooks;
const memory = require('feathers-memory');
const merge = require('lodash/merge');
const feathers = require('@feathersjs/feathers');
chai.use(chaiAsPromised);
const assert = chai.assert;

describe('authentication/basic', () => {
  let user;
  let userToken;
  const app = feathers();

  beforeEach(async () => {
    const authService = new AuthenticationService(app, 'authentication', {
      entity: 'user',
      service: 'users',
      secret: 'supersecret',
      authStrategies: ['basic'],
      basic: {
        usernameField: 'username',
        passwordField: 'password'
      }
    });

    app.use('users', memory());
    app.use('protected', {
      async get (id, params) {
        return {
          id, params
        };
      }
    });
    authService.register('basic', new BasicStrategy());

    app.service('protected').hooks({
      before: {
        all: [authenticate('basic')]
      }
    });

    app.service('users').hooks({
      after: {
        get: [context => {
          if (context.params.provider) {
            context.result.isExternal = true;
          }

          return context;
        }]
      }
    });

    user = await app.service('users').create({
      username: 'David',
      password: 'password'
    });

    userToken = Buffer.from('David:password').toString('base64');
    app.use('authentication', authService);
    app.setup();
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
      assert.deepEqual(result, {
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
