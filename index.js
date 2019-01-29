'use strict';

const assert = require('assert');
const Promise = require('bluebird');
const crypto = require('crypto');
const keypairs = require('casinocoin-libjs-keypairs')

function sha512(msg) {
  return crypto.createHash("sha512").update(msg).digest();
}

function aes256CbcEncrypt(iv, key, plaintext) {
  var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(plaintext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function aes256CbcDecrypt(iv, key, ciphertext) {
  var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
  var firstChunk = cipher.update(ciphertext);
  var secondChunk = cipher.final();
  return Buffer.concat([firstChunk, secondChunk]);
}

function hmacSha256(key, msg) {
  return crypto.createHmac("sha256", key).update(msg).digest();
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
  if (b1.length !== b2.length) {
    return false;
  }
  var res = 0;
  for (var i = 0; i < b1.length; i++) {
    res |= b1[i] ^ b2[i];  // jshint ignore:line
  }
  return res === 0;
}

/**
 * Derive shared secret for given private and public keys.
 * @param {Buffer} privateKeyA - Sender's private key (32 bytes)
 * @param {Buffer} publicKeyB - Recipient's public key (33 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived
 * shared secret (Px, 32 bytes) and rejects on bad key.
 */
function derive(privateKeyA, publicKeyB) {
  return new Promise(function(resolve) {
	  const cryptoECDH = crypto.createECDH('secp256k1');
	  cryptoECDH.setPrivateKey(privateKeyA);
	  resolve(cryptoECDH.computeSecret(publicKeyB));
  });
}

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - public key of message recipient
 * @param {Buffer} msg - The message being encrypted
 * @param {string} secretFrom - base58 encoded seed OPTIONAL
 * @return {Promise.<Buffer>} - A promise that resolves with the 
 * {Buffer} consisting of 33 byte pubKey, 16byte IV, 32byte encrypted mac for integrity check 
 * and encrypted message payload on successful encryption and rejects on failure.
 */
exports.encrypt = function(publicKeyTo, msg, secretFrom) {
    if (typeof secretFrom === 'undefined') { 
      var seedGenOptions = { "algorithm": 'secp256k1' }
      secretFrom = keypairs.generateSeed(seedGenOptions); 
    }
	var keyPairFrom = keypairs.deriveKeypair(secretFrom);  
	var privateKeyFrom = keyPairFrom.privateKey.slice(2)
	var publicKeyFrom = keyPairFrom.publicKey
  return new Promise(function(resolve) {
    resolve(derive(Buffer.from(privateKeyFrom, 'hex'), publicKeyTo));
  })
  .then(function(Px) {
    var hash = sha512(Px);
	var iv = crypto.randomBytes(16);
    var encryptionKey = hash.slice(0, 32);
    var macKey = hash.slice(32);
    var mac = hmacSha256(macKey, msg);
    var ciphertext = aes256CbcEncrypt(iv, encryptionKey, Buffer.concat([mac,msg]));
    return Buffer.concat([Buffer.from(publicKeyFrom, 'hex'), iv, ciphertext]);
  });
};	

/**
 * Decrypt message using given private key.
 * @param {string} secretTo - base58 encoded seed
 * @param {Buffer} ciphertext - encrypted message 
 * (consists of 33 byte pubKey, 16byte IV, 32byte encrypted mac for integrity check and encrypted message payload)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
exports.decrypt = function(secretTo, ciphertext) {
	var keyPairTo = keypairs.deriveKeypair(secretTo);  
	var privateKeyTo = keyPairTo.privateKey.slice(2)
	var publicKeyTo = keyPairTo.publicKey
  return derive(Buffer.from(privateKeyTo, 'hex'), ciphertext.slice(0, 33)).then(function(Px) {
    var hash = sha512(Px);	
    var encryptionKey = hash.slice(0, 32);
	var macKey = hash.slice(32);
    var iv = ciphertext.slice(33, 33 + 16);
	var ret = aes256CbcDecrypt(iv, encryptionKey, ciphertext.slice(33 + 16));
	var mac = ret.slice(0,32);
	var msg = ret.slice(32);
    var realMac = hmacSha256(macKey, msg);
    assert(equalConstTime(mac, realMac), "Bad MAC");
    return msg;
  });
};
