var Buffer = require('buffer').Buffer
var sha256 = require('./sha256')
var rng = require('./rng')

var algorithms = {
  sha256: {
    hex: sha256.hex,
    base64: sha256.base64,
    binary: sha256.binary,
    buffer: sha256.buffer
  }
}

var algorithmsHmac = {
  sha256: {
    hex: sha256.hmac_hex,
    base64: sha256.hmac_base64,
    binary: sha256.hmac_binary,
    buffer: sha256.hmac_buffer
  }
}


function error () {
  var m = [].slice.call(arguments).join(' ')
  throw new Error([
    m,
    'we accept pull requests',
    'http://github.com/dominictarr/crypto-browserify'
    ].join('\n'))
}

exports.createHash = function (alg) {
  alg = alg || 'sha1'
  if(!algorithms[alg]) {
    error('algorithm:', alg, 'is not yet supported')
  }
  var s = new Buffer(0);
  var _alg = algorithms[alg];
  return {
    update: function (data, enc) {
      if (! Buffer.isBuffer(data)) {
        enc = enc || 'buffer';
        if (enc === 'buffer' && typeof data === 'string') {
          enc = 'binary';
        }
        data = new Buffer(data, enc);
      }
      s = Buffer.concat([s, data]);
      return this;
    },
    digest: function (enc) {
      enc = enc || 'buffer';
      var fn;
      if(!(fn = _alg[enc])) {
        error('encoding:', enc , 'is not yet supported for algorithm', alg);
      }
      var r = fn(s);
      s = null //not meant to use the hash after you've called digest.
      return r
    }
  }
}

exports.createHmac = function (alg, key) {
  if (!algorithmsHmac[alg]) {
    error('algorithm:', alg, 'is not yet supported')
  }
  var s = new Buffer(0);
  var _alg = algorithmsHmac[alg];

  return {
    update: function (data, enc) {
      if (! Buffer.isBuffer(data)) {
        enc = enc || 'buffer';
        if (enc === 'buffer' && typeof data === 'string') {
          enc = 'binary';
        }
        data = new Buffer(data, enc);
      }
      s = Buffer.concat([s, data]);
      return this;
    },
    digest: function (enc) {
      enc = enc || 'buffer';
      var fn;
      if (!(fn = _alg[enc])) {
        error('encoding:', enc, 'is not yet support for algorithm', alg);
      }
      var r = fn(key, s);
      s = null;
      return r;
    }
  }
}

exports.randomBytes = function(size, callback) {
  if (callback && callback.call) {
    try {
      callback.call(this, undefined, new Buffer(rng(size)));
    } catch (err) { callback(err); }
  } else {
    return new Buffer(rng(size));
  }
}

function each(a, f) {
  for(var i in a)
    f(a[i], i)
}

// the least I can do is make error messages for the rest of the node.js/crypto api.
each(['createCredentials'
, 'createCipher'
, 'createCipheriv'
, 'createDecipher'
, 'createDecipheriv'
, 'createSign'
, 'createVerify'
, 'createDiffieHellman'
, 'pbkdf2'], function (name) {
  exports[name] = function () {
    error('sorry,', name, 'is not implemented yet')
  }
})
