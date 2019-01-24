'use strict';
const assert = require('assert');
const api = require('../');
const keypairs = require('casinocoin-libjs-keypairs')
const fixtures = require('./fixtures/api.json');
    
describe('api', () => {
    it('encrypt-decrypt', async () => {
        for (var i = 0, len = fixtures.message.length; i < len; i++) {
            var msgContent = fixtures.message[i];
            var decryptedMsg = 
                await api.encrypt(
                    fixtures.secp256k1.sender.master_seed, 
                    Buffer.from(fixtures.secp256k1.receiver.public_key_hex, 'hex'), 
                    Buffer.from(msgContent))
                    .then( function(encryptedMsg) {
                        return api.decrypt(
                            fixtures.secp256k1.receiver.master_seed, 
                            Buffer.from(fixtures.secp256k1.sender.public_key_hex, 'hex'), 
                            encryptedMsg);
                    });
            assert(decryptedMsg == msgContent);
        }
    });
});



