const { AuthenticationBaseStrategy } = require('@feathersjs/authentication');
const { NotAuthenticated } = require('@feathersjs/errors');
const omit = require('lodash/omit');
const get = require('lodash/get');
const bcryptjs = require('bcryptjs');
const SPLIT_HEADER = /(\S+)\s+(\S+)/;

export class BasicStrategy extends AuthenticationBaseStrategy {
  get configuration () {
    const authConfig = (this.authentication || {}).configuration;
    const config = super.configuration || {};
    const { passwordField, usernameField } = authConfig.basic;

    return Object.assign({
      hashSize: 10,
      service: authConfig.service,
      entity: authConfig.entity,
      entityId: authConfig.entityId,
      errorMessage: 'Invalid login',
      entityPasswordField: passwordField,
      entityUsernameField: usernameField,
      header: 'Authorization',
      schemes: ['Basic']
    }, config);
  }

  /**
   * Generate a query for retrieving an entity
   * @param {Object} query The entity object to be queried for
   * @return {Object} A query object
   */
  async getEntityQuery (query) {
    return Object.assign({ $limit: 1 }, query);
  }

  /**
   * Checks to see if a username exists and validates it
   * If the username field is empty we throw a NotAuthenticated exception
   * @param {String} username The username to verify
   * @param {*} params The request headers
   * @returns The found entity
   */
  async findEntity (username, params) {
    const { entityUsernameField, errorMessage } = this.configuration;
    if (!username) {
      throw new NotAuthenticated(errorMessage);
    }
    const query = await this.getEntityQuery({
      [entityUsernameField]: username
    });
    const findParams = Object.assign({}, params, { query });
    const result = await this.entityService.find(findParams);
    const list = Array.isArray(result) ? result : result.data;
    if (!Array.isArray(list) || list.length === 0) {
      throw new NotAuthenticated(errorMessage);
    }
    const [entity] = list;
    return entity;
  }

  /**
   * Splits the incoming token into the username and password
   * @param {String} token The incoming auth string to be brokem down
   * @returns {String} Returns both the username and password
   */
  async splitToken (token) {
    const { errorMessage } = this.configuration;
    const buff = Buffer.from(token, 'base64');
    const text = buff.toString('ascii');
    if (text.search(/:/) === -1) {
      throw new NotAuthenticated(errorMessage);
    }
    const [username, password] = text.split(':');
    return {
      username, password
    };
  }

  /**
   * Compares the provided password to the saved version
   * @param {Object} entity The object to authenticate against
   * @param {String} password The password being provided
   * @returns Returns the entity if valid or throws an error if invalid
   */
  async comparePassword (entity, password) {
    const { entityPasswordField, errorMessage } = this.configuration;
    // find password in entity, this allows for dot notation
    const hash = get(entity, entityPasswordField);
    // console.log('comparePassword', password, entity, entityPasswordField, hash);
    if (!hash) {
      // debug(`Record is missing the '${entityPasswordField}' password field`);
      throw new NotAuthenticated(errorMessage);
    }
    // debug('Verifying password');
    const result = await bcryptjs.compare(password, hash);
    // console.log(result);
    if (result) {
      return entity;
    }
    // console.log('');
    throw new NotAuthenticated(errorMessage);
  }

  /**
   * Authenticates the incoming user
   * @param {Object} authentication The authentication object which consists of an accessToken
   * @param {Object} params The headers to parse
   * @returns An authenticated session
   */
  async authenticate (authentication, params) {
    const { entity } = this.configuration;
    // console.log('authenticate', authentication);
    if (!authentication.accessToken) {
      // console.log('authenticate.accessToken');
      throw new NotAuthenticated('No access token');
    }
    const { username, password } = await this.splitToken(authentication.accessToken);
    const result = await this.findEntity(username, omit(params, 'provider'));
    this.comparePassword(result, password);
    // console.log('authenticate.comparePassword');
    const found = await this.getEntity(result, params).catch(e => console.log(e));
    return {
      authentication: { ...authentication },
      [entity]: found
    };
  }

  /**
   * Retrieves the entity
   * @param {Object} foundEntity The entity that was found using findEntity
   * @param {Object} params The headers of the request
   * @returns An entity if one is found
   */
  async getEntity (foundEntity, params) {
    const entityService = this.entityService;
    const { entityId = entityService.id, entity } = this.configuration;

    if (!entityId || foundEntity[`${entityId}`] === undefined) {
      throw new NotAuthenticated('Could not get local entity');
    }

    if (!params.provider) {
      return foundEntity;
    }
    return entityService.get(foundEntity[`${entityId}`], Object.assign(Object.assign({}, params), { [entity]: foundEntity }));
  }

  /**
   * Detect the headers and add the keys to the authentication param
   * @param {Object} req The request headers
   * @returns The parsed version of the request headers
   */
  parse (req) {
    const { header, schemes } = this.configuration;
    const headerValue = req.headers && req.headers[header.toLowerCase()];
    if (!headerValue || typeof headerValue !== 'string') {
      return null;
    }

    const [, scheme, schemeValue] = headerValue.match(SPLIT_HEADER) || [];
    const hasScheme = scheme && schemes.some(current => new RegExp(`${current}`, 'i').test(scheme));
    if (scheme && !hasScheme) {
      return null;
    }

    return {
      strategy: this.name,
      accessToken: hasScheme ? schemeValue : headerValue
    };
  }
}
