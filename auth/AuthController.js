var express=require('express');
var router=express.Router();
var bodyparser=require('body-parser');
router.use(bodyparser.urlencoded({extended : true}));
router.use(bodyparser.json());
var User=require('../user/User');
var jwt=require('jsonwebtoken');
var bcrypt=require('bcryptjs');
var config=require('../config.js');
var VerifyToken = require('./VerifyToken');

router.post('/register',function(req,res){
    console.log('hey i m in register');
    console.log('req.headers',req.headers);
    console.log('req.body',req.body);
    var hashedPassword = bcrypt.hashSync(req.body.password,8);
    User.create({
        name : req.body.name,
        email : req.body.email,
        password : hashedPassword
    },
    function(err,user){
        if(err) return res.status(500).send('There was a problem registering the user');
        var token=jwt.sign({ id : user._id}, config.secret, {
            expiresIn : 86400
        });
        console.log('token',token);
        res.status(200).send({data :token,auth :true , token : token});
    });
}
);

router.get('/me',VerifyToken, function(req,res){
    console.log('hey i m in me');
    // var token=req.headers['x-access-token'];
    // if(!token) return res.status(401).send({auth : false,message : 'No token provided'});

    // jwt.verify(token,config.secret,function(err,decoded){
    //     if(err) return req.status(500).send({auth :false , message : 'Failed to authenticate token'})

        User.findById(req.userId,{password : 0},(err,user)=>{
            if (err) return res.status(500).send('There is some problem finding the user');
            if(!user) return res.status(404).send('no user found');
             res.status(200).send(user);
        })
    })


router.post('/login',(req,res)=>{
    User.findOne({email : req.body.email},(err,user)=>{
        if(err) return res.status(500).send('There is Some problem while Login');
        if(!user) return res.status(404).send('No User found');

        var passwordIsValid=bcrypt.compareSync(req.body.password,user.password);
        if(!passwordIsValid) return res.status(401).send({auth : false, token : null});

        var token =jwt.sign({id : user._id},config.secret,{
            expiresIn : 86400
        });
        res.status(200).send({auth : true,token : token});
    })
})
router.get('/logout', (res)=>{
    res.status(200).send({ auth: false, token: null });
  });

module.exports= router;