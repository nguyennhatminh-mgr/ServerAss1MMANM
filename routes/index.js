var express = require('express');
var router = express.Router();
var path = require('path');
const multer=require('multer');
const { v1: uuidv1 } = require('uuid');

router.use(express.static("public"));

const AES = require('./algorithm/indexAes');
const {encryptFileRSA,decryptFileRSA,checkIntegrity} = require('./algorithm/indexRSA');

//Cau hinh noi luu tru file sau khi tai len
var storage =multer.diskStorage({
  destination: (req,file,cb)=>{
      cb(null,'./routes/containfile')
  },
  filename: (req,file,cb)=>{
      cb(null,file.originalname)
  }
});
var upload=multer({storage:storage});

// Storage for hash
var storageForHash = multer.diskStorage({
  destination: (req,file,cb)=>{
    cb(null,'./routes/filesforhash')
  },
  filename: (req,file,cb)=>{
      cb(null,uuidv1()+file.originalname)
  }
});
var uploadForHash = multer({storage:storageForHash});


/* GET home page. */
router.get('/', function(req, res, next) {
  // var filePath = path.join(__dirname,'./algorithm/girl_xinh_154.jpg');
  // let k = new AES();
  // const mypath = filePath;
  
  // const key = "NhatMinh";
  // k.encryptFile(mypath,key);
  
  res.render('index', { title: 'Express' });
});

router.post('/encrypt/aes_algorithm',upload.array("file_to_encrypt"),(req,res,next) => {
  
  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    
    let k = new AES();
    const mypath = filePath;
    
    k.encryptFile(mypath,key,pathToReceiveFile);
  }
  
  res.send(pathToReceiveFile);
  // res.send("Hello");
});

router.post('/decrypt/aes_algorithm',upload.array("file_to_encrypt"),(req,res,next) => {
  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";
  console.log(req.body.content_key);
  
  var get_mac_check_fail = [];

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    let k = new AES();
    const mypath = filePath;
    
    const mac_check_fail = k.decryptFile(mypath,key,pathToReceiveFile);
    get_mac_check_fail.push(mac_check_fail);
  }

  var isFailed = get_mac_check_fail.filter((element) => {
    return !element;
  });

  if(isFailed.length < 1){
    res.send(pathToReceiveFile);
  }
  else{
    res.send("Mac check fail, please check your key or file!!!");
  }
});

router.post('/encrypt/rsa_algorithm',upload.array("file_to_encrypt"),(req,res,next) => {

  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";

  var get_mac_check_fail = [];

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    
    const mypath = filePath;
    
    const mac_check_fail = encryptFileRSA(mypath,key,pathToReceiveFile);
    get_mac_check_fail.push(mac_check_fail);
  }
  
  var isFailed = get_mac_check_fail.filter((element) => {
    return !element;
  });

  if(isFailed.length < 1){
    res.send(pathToReceiveFile);
  }
  else{
    res.send("Key is invalid , please check your key file!!!");
  }
});

router.post('/decrypt/rsa_algorithm',upload.array("file_to_encrypt"),(req,res,next) => {
  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";
  
  var get_mac_check_fail = [];

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    
    const mypath = filePath;
    
    const mac_check_fail = decryptFileRSA(mypath,key,pathToReceiveFile);
    get_mac_check_fail.push(mac_check_fail);
  }

  var isFailed = get_mac_check_fail.filter((element) => {
    return !element;
  });

  if(isFailed.length < 1){
    res.send(pathToReceiveFile);
  }
  else{
    res.send("Mac check fail, please check your key or file!!!");
  }
});

router.post('/checkintegrity/:modehash',uploadForHash.array("file_to_check_integrity"),(req,res,next) => {
  let filePath1 = handlePath(req.files[0].path);
  filePath1 = path.join(__dirname,filePath1);

  let filePath2 = handlePath(req.files[1].path);
  filePath2 = path.join(__dirname,filePath2);

  const modehash = req.params.modehash;

  const checked = checkIntegrity(filePath1,filePath2,modehash);
  if(checked[2]===true){
    res.send({
      message: "Nice, file is integrity !!!",
      hashFile1: checked[0],
      hashFile2: checked[1],
      fileName1:req.files[0].filename,
      fileName2: req.files[1].filename,
      result:true
    });
  }
  else{
    res.send({
      message: "Bad, file is not integrity !!!",
      hashFile1: checked[0],
      hashFile2: checked[1],
      fileName1:req.files[0].filename,
      fileName2: req.files[1].filename,
      result:false
    });
  }
});

module.exports = router;

const handlePath = (path) => {
  var newPath = path.split('\\');
  var result = "";
  for(var i = 1 ; i < newPath.length -1; i++){
    result += newPath[i] + "/";
  }
  result += newPath[newPath.length - 1];
  return result;
}