// All Require;
const express = require('express');
const mongoDB = require('mongodb');
const MongoClient = mongoDB.MongoClient;
const bcrypt = require('bcrypt');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const API = express();
require("dotenv").config();
const URL =process.env.LINK;
const DB =process.env.DB;
var nodemailer = require('nodemailer');
const FROM = process.env.FROM;
const PASSWORD = process.env.PASSWORD



//Middleware;
API.use(express.json());
API.use(cors({ origin: "https://password-reset-app-1.netlify.app" }))


//Conform to Working API;
API.get("/", function (req, res) {
    res.send('Never Give Up..')
});


//New User registration;
API.post("/Registration", async function (req, res) {
    try {
        let connection = await MongoClient.connect(URL);
        let db = connection.db(DB);
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.Password, salt)
        req.body.Password = hash
        await db.collection("Users").insertOne(req.body);
        res.status(200).json({ Message: 'New user Add Successfully' });
        
    } catch (error) {
        res.status(500).json({ Message: 'Something Went Wrong' })
        console.log(error);
    }

})

//Data Get Authentication;
// let authentication = (req,res,next)=>{
//     console.log(req.headers);
//     if(req.headers.authentication){
//         let decode = jwt.verify(req.headers.authentication,process.env.SEC);
//         if(decode){
//             next()
//         }else{
//             res.status(401).json({message:"Unauthorized"});
//         }
//     }else{
//         res.status(401).json({message:"Unauthorized"});
//     }
// }

//Login Verification;
API.post("/Login", async function (req, res) {
    try {
        let connection = await MongoClient.connect(URL);
        let db = connection.db(DB);

        //User Verification;
        let user = await db.collection("Users").findOne({ Email: req.body.Email });
        if (user) {
            if (user) {
                let compare = await bcrypt.compare(req.body.Password, user.Password);
                console.log(compare);
                if (compare) {
                    let token = jwt.sign({ _id: user._id }, process.env.SEC, { expiresIn: '5m' });
                    res.json({ token });
                } else {
                    res.json({ Message: 'Email or Password Wrong' });
                }
            }
        } else {
            res.json({ Message: 'Email or Password Wrong' })
        }
        
    } catch (error) {
        res.status(500).json({ Message: 'Something Went Wrong' });
        console.log(error);
    }
    
})


//Forget Password;
//Mail get and Checking;
API.post("/Reset", async function (req, res) {
    try {
        let connection = await MongoClient.connect(URL);
        let db = connection.db(DB);

        let id = await db.collection("Users").findOne({ Email: req.body.Email });
        let Email = req.body.Email
        if (!id) {
            res.status(404).json({ message: "User Not Exists" });
        }
        let token = jwt.sign({ _id: id._id }, process.env.SEC, { expiresIn: '5m' });

        const link = `https://password-reset-app-1.netlify.app/Reset-Password/${id._id}/${token}`;
        console.log(link);
        
        //Send a link Via mail;
        var transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user:"rowdyram779@gmail.com",
                pass:PASSWORD
            }
        });

        var mailOptions = {
            from:"rowdyram779@gmail.com",
            to: Email,
            subject: 'Password Reset',
            text:"Click this Link Reset Your Password",
            html:`<Link to=${link} target="_blank">${link}</Link>`,
        };

        transporter.sendMail(mailOptions, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log('Email sent:' + info.response);
            }
        });
        res.send(link);

    } catch (error) {
        res.status(500).json({ Message: 'Something Went Wrong' });
        console.log(error);
    }
})


//Update New Password;
API.post("/Reset-Password/:id/:token", async function (req, res) {
    const id = req.params.id
    const token = req.params.token
    try {

        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.Password, salt);
        let connection = await MongoClient.connect(URL);
        let db = connection.db(DB);

        let compare = jwt.verify(token,process.env.SEC);
        console.log(compare);
        if (compare) {
            let Person = await db.collection("Users").findOne({ _id: mongoDB.ObjectId(`${id}`) })
            if (!Person) {
                return res.json({ Message: "User Exists!!" });
            }
            await db.collection("Users").updateOne({ _id: mongoDB.ObjectId(`${id}`) }, { $set: { Password: hash } });
            res.json({ Message: "Password Updated" });
        } 
        else {
            res.json({ Message: "URL TimeOut" })
        }
    } catch (error) {
        res.status(500).json({ Message: 'URL TimeOut' });
        console.log(error);
    }

})


//PORT Listen;
API.listen(process.env.PORT||3005);