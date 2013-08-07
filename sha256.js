var sjcl = require('./sjcl');
var Buffer = require('buffer').Buffer;

var bits2hex = sjcl.codec.hex.fromBits;
var bits2bytes = sjcl.codec.bytes.fromBits;

var str2bits = sjcl.codec.utf8String.toBits;
var hex2bits = sjcl.codec.hex.toBits;
var bytes2bits = sjcl.codec.bytes.toBits;

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
  var m = new sjcl.misc.hmac(str2bits(key), Hash);
  return m.mac(data);
}

function hex(data) {
  data = bytes2bits(data);
  return bits2hex(Hash.hash(data));
}

function buffer(data) {
  data = bytes2bits(data);
  return new Buffer(bits2bytes(Hash.hash(data)));
}

function hmac_hex(key, data) {
  return bits2hex(hmac(key, data));
}

function binary(data) {
  data = bytes2bits(data);
  return bits2str(Hash.hash(data));
}

exports.hex = hex;
exports.buffer = buffer;
exports.binary = binary;

exports.hmac_hex = hmac_hex;
