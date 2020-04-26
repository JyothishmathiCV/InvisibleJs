const { not,
    encrypt,
    decrypt,
    buff,
    byarr,
    compress,
    decompress,
    ZWCToData,
    dataToZWC,
    getSM,
    byteToBin,
    binToByte,embed} = require('./util.js');
    
var key = 'pass!!!' // Secret key for 256 bit AES is 32 characters
var message = "shhhh!"


function inject(message, key, cover,integrity) {

    let comB = compress(message);

    let compliment = not(byarr(comB));

    let encryptB = encrypt({password:key,data:compliment,integrity});

    let payload = dataToZWC(byteToBin(byarr(encryptB)));

    return embed(cover,payload)
}


function eject(str,key,integrity){    

    let payload = binToByte(ZWCToData(getSM(str)));

    let decryptB = decrypt({password:key,data:payload,integrity});

    let compliment = not(byarr(decryptB));

    return decompress(buff(compliment));

}


var payload=inject(message,key,'This is a confidential text',true);

console.log(payload.length);

console.log(eject(payload,key,true));

