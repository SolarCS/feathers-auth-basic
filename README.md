# feathers-auth-basic

[![Build Status](https://travis-ci.org/feathersjs/authentication-basic.png?branch=master)](https://travis-ci.org/feathersjs/authentication-basic)
[![Code Climate](https://codeclimate.com/github/feathersjs/authentication-basic/badges/gpa.svg)](https://codeclimate.com/github/feathersjs/authentication-basic)
[![Test Coverage](https://codeclimate.com/github/feathersjs/authentication-basic/badges/coverage.svg)](https://codeclimate.com/github/feathersjs/authentication-basic/coverage)
[![Dependency Status](https://img.shields.io/david/feathersjs/authentication-basic.svg?style=flat-square)](https://david-dm.org/feathersjs/authentication-basic)
[![Download Status](https://img.shields.io/npm/dm/feathers-auth-basic.svg?style=flat-square)](https://www.npmjs.com/package/feathers-auth-basic)

> A way to handle basic authenticatioin on the feathers platform.

## Installation

```
npm install feathers-auth-basic --save
```

## Documentation

TBD

## Complete Example

Here's an example of a Feathers server that uses `feathers-auth-basic`. 

```js
const feathers = require('@feathersjs/feathers');
const plugin = require('feathers-auth-basic');

// Initialize the application
const app = feathers();

// Initialize the plugin
app.configure(plugin());
```

## License

Copyright (c) 2018

Licensed under the [MIT license](LICENSE).
