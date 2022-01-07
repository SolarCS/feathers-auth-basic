const feathers = require('@feathersjs/feathers');
const memory = require('feathers-memory');
const { AuthenticationService } = require('@feathersjs/authentication');
const BasicStrategy = require('../lib/strategy.ts');
const { hashPassword, protect } = hooks;

module.exports = (app = feathers()) => {
  const authentication = new AuthenticationService(app);

  app.set('authentication', {
    entity: 'user',
    service: 'users',
    secret: 'supersecret',
    authStrategies: ['basic'],
    parseStrategies: ['basic'],
    basic: {
      usernameField: 'username',
      passwordField: 'password'
    }
  });

  authentication.register('basic', new BasicStrategy());

  app.use('/authentication', authentication);
  app.use('/users', memory({
    multi: ['create'],
    paginate: {
      default: 10,
      max: 20
    }
  }));

  app.service('users').hooks({
    before: {
      create: hashPassword('password')
    },
    after: {
      all: protect('password'),
      get: [context => {
        if (context.params.provider) {
          context.result.fromGet = true;
        }

        return context;
      }]
    }
  });

  return app;
};
