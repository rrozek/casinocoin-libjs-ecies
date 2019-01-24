'use strict';
const assert = require('assert');
const api = require('../');
const keypairs = require('casinocoin-libjs-keypairs')
const fixtures = require('./fixtures/api.json');

var resolveEncrypt = function(encryptedMsg) {
	api.decrypt(fixtures.secp256k1.receiver.master_seed, 
                Buffer.from(fixtures.secp256k1.sender.master_seed.public_key_hex, 'hex'), 
                encryptedMsg)
                .then( function(decryptedMsg) {
                    return decryptedMsg;
                });
}

function encryptDecryptFunc(msgContent) {

};
    
describe('api', () => {
    it('encrypt-decrypt', async () => {
        for (var i = 0, len = fixtures.message; i < len; i++) {
            var decryptedMsg = 
                api.encrypt(
                    fixtures.secp256k1.sender.master_seed, 
                    Buffer.from(fixtures.secp256k1.receiver.master_seed.public_key_hex, 'hex'), 
                    Buffer.from(msgContent))
                    .then( function(encryptedMsg) {
                        return api.decrypt(
                            fixtures.secp256k1.receiver.master_seed, 
                            Buffer.from(fixtures.secp256k1.sender.master_seed.public_key_hex, 'hex'), 
                            encryptedMsg);
                    });
            assert(decryptedMsg === msgContent);
        }
    });
});



