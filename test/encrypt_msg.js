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
                    Buffer.from(fixtures.secp256k1.receiver.public_key_hex, 'hex'), 
                    Buffer.from(msgContent))
                    .then( function(encryptedMsg) {
                        return api.decrypt(
                            fixtures.secp256k1.receiver.master_seed, 
                            encryptedMsg);
                    });
            assert(decryptedMsg == msgContent);
        }
    });
    
    it('decryptFromDaemon', async () => {
        var decrypted = await api.decrypt(
                            'shAEE8pLJQofwqDK4xRqx94eEgnAa',
                            Buffer.from('0249B2F8191FB1CC6B8284C3647B960A1CB6F914EEADF41816D7492457AB9ADA6918CF4C7694B71101BF0C1D2A60D7CFC4BDEF611511245CD92C1475D313C4F20C14896E4F0017B2A1B67669CCDFEF753941284BB6C88873AFE7EED5566416D405', 'hex'));
        assert(decrypted == 'abc')
    });
});



