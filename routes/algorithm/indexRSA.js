const NodeRSA = require('node-rsa');
const fs = require('fs');
const sha256 = require('sha256');
const sha1 = require('sha1');
const md5 = require('md5');

const encryptFileRSA = (filePath,keyPublicPemString,userPath) => {

    try{
        const public_key = new NodeRSA(keyPublicPemString);
    
        const file = fs.readFileSync(filePath);
        const encryptedFile = public_key.encrypt(file);
        
        const arrPath = filePath.split('\\');
        const newPath = userPath + arrPath[arrPath.length-1] + '.enc';
    
        fs.writeFileSync(newPath,encryptedFile);
        return true;
    }
    catch (err){
        return false;
    }
}

const decryptFileRSA = (filePath,keyPrivatePemString,userPath) => {
    try{
        const private_key = new NodeRSA(keyPrivatePemString);

        const file = fs.readFileSync(filePath);
        const encryptedFile = private_key.decrypt(file);
        
        const arrPath = filePath.split('\\');
        let newPath = userPath + 'Dec_'+ arrPath[arrPath.length-1];
        newPath = newPath.replace(/\.enc$/, '');
    
        fs.writeFileSync(newPath,encryptedFile);
        return true;
    }
    catch (err){
        return false;
    }
}

const checkIntegrity = (filePath1,filePath2,modeHash) => {

    const file1 = fs.readFileSync(filePath1);
    const file2 = fs.readFileSync(filePath2);

    let hashFile1;
    let hashFile2;

    if(modeHash==='sha256'){
        hashFile1 = sha256(file1);
        hashFile2 = sha256(file2);
    }
    else if(modeHash==='sha1'){
        hashFile1= sha1(file1);
        hashFile2=sha1(file2);
    }
    else{
        hashFile1 = md5(file1);
        hashFile2 = md5(file2);
    }

    let result = [];
    result.push(hashFile1);
    result.push(hashFile2);

    if(hashFile1 === hashFile2){
        result.push(true);
    }
    else{
        result.push(false);
    }
    
    return result;
}

module.exports = {
    encryptFileRSA,
    decryptFileRSA,
    checkIntegrity
}