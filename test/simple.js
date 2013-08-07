var test = require("tape")
var Buffer = require("buffer").Buffer;

var crypto = require('crypto')
var cryptoB = require('../')

function assertSame (fn) {
  test(fn.name, function (t) {
    t.plan(1)
    fn(crypto, function (err, expected) {
      fn(cryptoB, function (err, actual) {
        t.equal(actual, expected)
        t.end()
      })
    })
  })
}

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update('hello').update('there').digest('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update(new Buffer('cafe', 'hex')).digest('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update(Buffer.concat([Buffer('dead', 'hex'), Buffer('beef', 'hex')])).digest('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update(new Buffer('dead', 'hex')).update(new Buffer('beef', 'hex')).digest('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update('hellø', 'utf8').digest('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update('hello', 'utf8').digest().toString('hex'));
})

assertSame(function sha256 (crypto, cb) {
  cb(null, crypto.createHash('sha256').update('hellø', 'utf8').digest('binary'));
})

assertSame(function sha256hmac (crypto, cb) {
  cb(null, crypto.createHmac('sha256', 'secret').update('hello', 'utf8').digest('hex'))
})

test('randomBytes', function (t) {
  t.plan(5)
  t.equal(cryptoB.randomBytes(10).length, 10)
  t.ok(cryptoB.randomBytes(10) instanceof Buffer)
  cryptoB.randomBytes(10, function(ex, bytes) {
    t.error(ex)
    t.equal(bytes.length, 10)
    t.ok(bytes instanceof Buffer)
    t.end()
  })
})
