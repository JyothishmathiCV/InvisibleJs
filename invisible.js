const R=require('ramda');
const {encrypt,decrypt,compress,decompress,embed,detach,toConceal,toConcealHmac,concealToData}=require('./components.js');
const {byteToBin,compliment,buff} = require('./util.js');
    
var key = 'pass!!!' ;
var message = "shhhh!";



function inject(message, key, cover,integrity) {

    const secret=R.pipe(compress,compliment)(message);

    const encryptStream = encrypt({password:key,data:secret,integrity});
    
    const invisibleStream = R.pipe(byteToBin,integrity?toConcealHmac:toConceal)(encryptStream);

    return embed(cover,invisibleStream);
}



function eject(str,key){    

    const encryptStream=R.pipe(detach,concealToData)(str);


    let decryptStream = decrypt({password:key,data:encryptStream.data,integrity:encryptStream.integrity});


    return R.pipe(compliment,buff,decompress)(decryptStream);


}


var payload=inject(message,key,'This is a confidential text',true);

console.log("payload",payload);

console.log(eject(payload,key));

