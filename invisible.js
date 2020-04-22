var invisible = require('./util.js');
// var key = 'secret key 12345secret key 12345' // Secret key for 256 bit AES is 32 characters
// var message = 'my message my message my message my message'


function inject(message, key, cover) {

    let comB = invisible.compress(message);

    let compliment = invisible.not(invisible.byarr(comB));

    let encryptB = invisible.aes_encrypt(key, compliment);

    let payload = invisible.dataToZWC(invisible.bytobin(invisible.byarr(encryptB)));

    return payload + cover;
}


function eject(str,key){
    
    let payload = invisible.binToByte(invisible.ZWCToData(str.slice(0,invisible.getIndexOfCM(str))));

    let decrypt = invisible.aes_decrypt(key,payload);

    let compliment = invisible.not(invisible.byarr(decrypt));

    return message = invisible.decompress(invisible.buff(compliment));
}