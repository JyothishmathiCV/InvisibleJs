const { not,
    aes_encrypt,
    aes_decrypt,
    buff,
    byarr,
    compress,
    decompress,
    ZWCToData,
    dataToZWC,
    getSM,
    byteToBin,
    binToByte,embed} = require('./util.js');
    
var key = 'secret key 12345secret key 12345' // Secret key for 256 bit AES is 32 characters
var message = 'my message my message my message my message'


function inject(message, key, cover) {

    let comB = compress(message);

    let compliment = not(byarr(comB));

    let encryptB = aes_encrypt(key, compliment);

    let payload = dataToZWC(byteToBin(byarr(encryptB)));

    return embed(cover,payload);
}


function eject(str,key){    

    let payload = binToByte(ZWCToData(getSM(str)));

    let decrypt = aes_decrypt(key,payload);

    let compliment = not(byarr(decrypt));

    return decompress(buff(compliment));

}


var payload=inject(message,key,"This is a confidential message");


console.log(payload);

console.log(eject(payload,key));