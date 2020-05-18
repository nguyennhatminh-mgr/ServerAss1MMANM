var express = require('express');
var router = express.Router();
var path = require('path');
const multer=require('multer');

router.use(express.static("public"));

const KriptaAES = require('./algorithm/indexAes');

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

/* GET home page. */
router.get('/', function(req, res, next) {
  // var filePath = path.join(__dirname,'./algorithm/girl_xinh_154.jpg');
  // let k = new KriptaAES();
  // const mypath = filePath;
  
  // const key = "NhatMinh";
  // k.encryptFile(mypath,key);
  
  res.render('index', { title: 'Express' });
});

router.post('/encrypt',upload.array("file_to_encrypt",12),(req,res,next) => {
  // console.log(req.files);
  // console.log(req.body.content_key);
  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    
    let k = new KriptaAES();
    const mypath = filePath;
    
    k.encryptFile(mypath,key,pathToReceiveFile);
  }
  
  res.send(pathToReceiveFile);
  // res.send("Hello");
});

router.post('/decrypt',upload.array("file_to_encrypt",12),(req,res,next) => {
  const cutDirname = __dirname.split('\\');
  const pathToReceiveFile = cutDirname[0] + "\\" + cutDirname[1]+"\\";
  console.log(req.body.content_key);
  
  var get_mac_check_fail = [];

  for(var i = 0; i<req.files.length;i++){
    var filePath = handlePath(req.files[i].path);
    const key = req.body.content_key;
    filePath = path.join(__dirname,'./',filePath);
    let k = new KriptaAES();
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