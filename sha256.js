var sjcl = require('sjcl');
var bytes = require('sjcl-codec-bytes');
var Buffer = require('buffer').Buffer;

var bits2hex = sjcl.codec.hex.fromBits;
var bits2base64 = sjcl.codec.base64.fromBits;
var bits2bytes = bytes.fromBits;

var str2bits = sjcl.codec.utf8String.toBits;
var hex2bits = sjcl.codec.hex.toBits;
var b642bits = sjcl.codec.base64.toBits;
var bytes2bits = bytes.toBits;

var Hash = sjcl.hash.sha256;

function bits2str (arr) {
  var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
  for (i=0; i<bl/8; i++) {
    if ((i&3) === 0) {
      tmp = arr[i/4];
    }
    out += String.fromCharCode(tmp >>> 24);
    tmp <<= 8;
  }
  return out;
}


function hmac(key, data) {
  data = bytes2bits(data);
  key = typeof key === 'string' ? str2bits(key) : bytes2bits(key);
  var m = new sjcl.misc.hmac(key, Hash);
  return m.mac(data);
}

function hex(data) {
  data = bytes2bits(data);
  return bits2hex(Hash.hash(data));
}

function base64(data) {
  data = bytes2bits(data);
  return bits2base64(Hash.hash(data));
}

function buffer(data) {
  data = bytes2bits(data);
  return new Buffer(bits2bytes(Hash.hash(data)));
}

function hmac_hex(key, data) {
  return bits2hex(hmac(key, data));
}

function hmac_base64(key, data) {
  return bits2base64(hmac(key, data));
}

function hmac_buffer(key, data) {
  return new Buffer(bits2bytes(hmac(key, data)));
}

function hmac_binary(key, data) {
  data = bytes2bits(data);
  return bits2str(hmac(key, data));
}

function binary(data) {
  data = bytes2bits(data);
  return bits2str(Hash.hash(data));
}

exports.hex = hex;
exports.base64 = base64;
exports.buffer = buffer;
exports.binary = binary;

exports.hmac_hex = hmac_hex;
exports.hmac_base64 = hmac_base64;
exports.hmac_buffer = hmac_buffer;
exports.hmac_binary = hmac_binary;
