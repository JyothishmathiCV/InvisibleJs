const crypto=require('crypto');
const R=require('ramda');
const lzutf8 = require('lzutf8');
const timeSafeCheck=require('timing-safe-equal');
const {
    buff,concat_buff,buff_slice,zeroPad,nTobin,binToByte
}=require('./util.js');

const zwc = ['‌', '​', '‍', '‎'] //00-200C, 01-200B, 10-200D, 11-200E Where the magic happens !


//---------------------------------Encryption operations --------------------------------------


//Key generation
const _genKey = (password, salt) => crypto.pbkdf2Sync(password, salt, 100000, 48, 'sha512');

const _extract = (mode, config, salt) => {
    const data = buff(config.data);
    const output={};
    if (mode === 'encrypt') {
        output.secret=data;
    } else if (mode === 'decrypt') {
        salt= buff_slice(data,0, 16);
        if (config.integrity) {
            output.hmac_data=buff_slice(data,16,48);
            output.secret=buff_slice(data,48);
        } else {
            output.secret=buff_slice(data,16)
        }
    }
    const iv_key = _genKey(config.password, salt);
    output.iv = buff_slice(iv_key, 0, 16);
    output.key = buff_slice(iv_key, 16);
    return output;
}

const _bootEncrypt=R.curry(_extract)('encrypt');


const _bootDecrypt=R.curry(_extract)('decrypt');

// Aes encrypt an array -- {password,text,integrity:bool} -- key gen, ctr, encrypted

const encrypt = config => {
    const salt = crypto.randomBytes(16);
    const {iv,key,secret}=_bootEncrypt(config,salt);
    const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
    const payload = concat_buff([cipher.update(secret, 'utf8'), cipher.final()])
    if (config.integrity) {
        const hmac = crypto.createHmac('sha256', key).update(secret).digest();
        return concat_buff([salt, hmac, payload]);
    }
    return concat_buff([salt, payload]);
}


const decrypt = (config) => {
    const {iv,key,secret,hmac_data}=_bootDecrypt(config,null);
    const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
    const decrypted = concat_buff([decipher.update(secret, 'utf8'), decipher.final()]);
    if (config.integrity) {
        const v_hmac = crypto.createHmac('sha256', key).update(secret).digest();
        if (timeSafeCheck(hmac_data, v_hmac)) {
            return 'HMAC_assertion_failed';
        }
    }
    return decrypted;
}


//--------------------------------------------------------------------------------------------



//---------------------------------Cover message operations --------------------------------------


// Map binary to ZWC 
const _binToZWC = str => zwc[parseInt(str, 2)];


// Map ZWC to binary
const _ZWCTobin = inp => zeroPad(nTobin(zwc.indexOf(inp)), 2);


// Data to ZWC hidden string
const dataToZWC = (integrity,str) => {
    let ZWCstr = integrity ? zwc[1]:zwc[0];
    for (let i = 0; i < str.length; i += 2) {
        ZWCstr += _binToZWC(str[i] + str[i + 1])
    }
    return ZWCstr;
}

const isHmac=x=>Boolean(zwc.indexOf(x[0]))

const toConcealHmac=R.curry(dataToZWC)(true);

const toConceal=R.curry(dataToZWC)(false);


//ZWC string to data 
const concealToData = (str) => {
    const integrity=isHmac(str);
    return {
        integrity,
        data:binToByte(str.slice(1).split('').map(x => _ZWCTobin(x)).join(''))
    }
}

const embed = (cover, secret) => {
    let arr = cover.split(' ');
    return [arr[0]].concat([secret + arr[1]]).concat(arr.slice(2, arr.length)).join(' ');
}


const detach = (str) => {
    var output;
    str.split(' ')[1].split('').every((x, i) => {
        if (!(~zwc.indexOf(x))) {
            output = str.split(' ')[1].slice(0, i);
            return false;
        }
        return true;
    });
    return output;
}

//---------------------------------------------------------------------------------------------


//---------------------------------Compression operations ------------------------------------------



const compress = x => lzutf8.compress(x, {
    outputEncoding: "Buffer"
});

// Decompress a buffer using LZ decompression
const decompress = x => lzutf8.decompress(x, {
    inputEncoding: "Buffer",
    outputEncoding: "String"
});
//----------------------------------------------------------------------------------------------


module.exports={encrypt,decrypt,compress,decompress,embed,detach,toConceal,toConcealHmac,concealToData}