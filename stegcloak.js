const R=require('ramda');

const {encrypt,decrypt}=require("./encrypt");

const {embed,detach,toConceal,toConcealHmac,concealToData}=require("./message");

const {compress,decompress}=require("./compact");

const {byteToBin,compliment} = require('./util');



function inject(message, key, cover,integrity) {

    const secret=R.pipe(compress,compliment)(message);

    const encryptStream = encrypt({password:key,data:secret,integrity});
    
    const invisibleStream = R.pipe(byteToBin,integrity?toConcealHmac:toConceal)(encryptStream);

    return embed(cover,invisibleStream);
}



function eject(str,key){    

    const encryptStream=R.pipe(detach,concealToData)(str);


    let decryptStream = decrypt({password:key,data:encryptStream.data,integrity:encryptStream.integrity});

    return R.pipe(compliment,decompress)(decryptStream);

}



console.log(eject("This ‌‌‍‍‎‎‎‍‌​‎‎‎‎​‌‍‍‍‍‌​​‌‎​‍​‎‍‎​‎​‎‌‍​‎​‌‌‍​‍‌‌​‎‌‍‎‎‌‌‌‍​‌‍​​‎‍‌‌‌​‌‍‌‍​‌‍​​is a confidential text.",'mypass'));

