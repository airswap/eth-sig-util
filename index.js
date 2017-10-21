'use strict';

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var ethUtil = require('ethereumjs-util');
var ethAbi = require('ethereumjs-abi');

module.exports = {

  concatSig: function concatSig(v, r, s) {
    var rSig = ethUtil.fromSigned(r);
    var sSig = ethUtil.fromSigned(s);
    var vSig = ethUtil.bufferToInt(v);
    var rStr = padWithZeroes(ethUtil.toUnsigned(rSig).toString('hex'), 64);
    var sStr = padWithZeroes(ethUtil.toUnsigned(sSig).toString('hex'), 64);
    var vStr = ethUtil.stripHexPrefix(ethUtil.intToHex(vSig));
    return ethUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex');
  },

  normalize: function normalize(input) {
    if (!input) return;

    if (typeof input === 'number') {
      var buffer = ethUtil.toBuffer(input);
      input = ethUtil.bufferToHex(buffer);
    }

    if (typeof input !== 'string') {
      var msg = 'eth-sig-util.normalize() requires hex string or integer input.';
      msg += ' received ' + (typeof input === 'undefined' ? 'undefined' : _typeof(input)) + ': ' + input;
      throw new Error(msg);
    }

    return ethUtil.addHexPrefix(input.toLowerCase());
  },

  personalSign: function personalSign(privateKey, msgParams) {
    var message = ethUtil.toBuffer(msgParams.data);
    var msgHash = ethUtil.hashPersonalMessage(message);
    var sig = ethUtil.ecsign(msgHash, privateKey);
    var serialized = ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s));
    return serialized;
  },

  recoverPersonalSignature: function recoverPersonalSignature(msgParams) {
    var publicKey = getPublicKeyFor(msgParams);
    var sender = ethUtil.publicToAddress(publicKey);
    senderHex = ethUtil.bufferToHex(sender);
    return senderHex;
  },

  extractPublicKey: function extractPublicKey(msgParams) {
    var publicKey = getPublicKeyFor(msgParams);
    return '0x' + publicKey.toString('hex');
  },

  typedSignatureHash: function typedSignatureHash(typedData) {
    var hashBuffer = _typedSignatureHash(typedData);
    return ethUtil.bufferToHex(hashBuffer);
  },

  signTypedData: function signTypedData(privateKey, msgParams) {
    var msgHash = _typedSignatureHash(msgParams.data);
    var sig = ethUtil.ecsign(msgHash, privateKey);
    return ethUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s));
  },

  recoverTypedSignature: function recoverTypedSignature(msgParams) {
    var msgHash = _typedSignatureHash(msgParams.data);
    var publicKey = recoverPublicKey(msgHash, msgParams.sig);
    var sender = ethUtil.publicToAddress(publicKey);
    return ethUtil.bufferToHex(sender);
  }

  /**
   * @param typedData - Array of data along with types, as per EIP712.
   * @returns Buffer
   */
};function _typedSignatureHash(typedData) {
  var error = new Error('Expect argument to be non-empty array');
  if ((typeof typedData === 'undefined' ? 'undefined' : _typeof(typedData)) !== 'object' || !typedData.length) throw error;

  var data = typedData.map(function (e) {
    return e.value;
  });
  var types = typedData.map(function (e) {
    return e.type;
  });
  var schema = typedData.map(function (e) {
    if (!e.name) throw error;
    return e.type + ' ' + e.name;
  });

  return ethAbi.soliditySHA3(['bytes32', 'bytes32'], [ethAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema), ethAbi.soliditySHA3(types, data)]);
}

function recoverPublicKey(hash, sig) {
  var signature = ethUtil.toBuffer(sig);
  var sigParams = ethUtil.fromRpcSig(signature);
  return ethUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s);
}

function getPublicKeyFor(msgParams) {
  var message = ethUtil.toBuffer(msgParams.data);
  var msgHash = ethUtil.hashPersonalMessage(message);
  return recoverPublicKey(msgHash, msgParams.sig);
}

function padWithZeroes(number, length) {
  var myString = '' + number;
  while (myString.length < length) {
    myString = '0' + myString;
  }
  return myString;
}
