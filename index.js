const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");  // to hash the password
const jwt = require("jsonwebtoken"); 
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());




//mysql connection(it creates a db connection object)
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
})

//it exteablishes the connection to mysql db
db.connect((err) => {
    if (err) throw err;
    console.log("connected to mysql database")
});


// JWT Secret key (stored in .env file for security)
const JWT_SECRET = process.env.JWT_SECRET ;

//Registration Route
app.post("/register",  (req,res) => {
    const {username, password, email, mobile} = req.body;
    //console.log(username)

    //checking if user already exist or not
    db.query("select * from car_rent_users where username = ?" , [username],  (err,result) => {
        if(err){
        return  res.status(500).json({ message: 'Database error' })
       
        }
        if(result.length > 0) {
          return  res.status(400).json({ message: 'User already exists' });
            
        }

         // If user does not exist, hash the password and insert into the database
         bcrypt.hash(password,10,(err,hashedPassword) => {
            if(err){
             return  res.status(500).send("Error hashing password: " +err);
                 
            }

             // Insert the new user into the database
             const insertQuery = "insert into car_rent_users (username, password, email, mobile) values (?, ?, ?, ?)";
             db.query(insertQuery,[username,hashedPassword,email,mobile], (err,result) => {
                if(err) {
                return  res.status(500).send("Error inserting user into database" + err);
                  
                }
               return   res.status(201).json({message: "User registered successfully"});
                 
                
             })
         })
    })
});


    //Login Route
    app.post("/login",(req,res) => {
    const {username, password} = req.body;

    //finding user in the database
    db.query("select * from car_rent_users where username = ?",[username],(err,result) => {
        if(err) {
            return res.status(500).json({message: "Database error"});
        }
       // console.log(result)
        if(result.length === 0){
             return res.status(404).json({message:"user not found"});
           
        }
       
        
        const user = result[0];

         // Comparing the passwords using bcrypt 
         bcrypt.compare(password, user.password,(err, isMatch) => {
            if(err){
                return res.status(500).json({message: 'Error comparing passwords'});
            }
            if(!isMatch){
                return res.status(400).json({message: 'Invalid credentials'})
            }

             // Generating JWT token 
             const token = jwt.sign({userId:user.id, username:user.username},JWT_SECRET, {expiresIn: "1h"});

             // Sending the token  to the frontend
             res.json({token})
         })
    })
});



app.listen(process.env.PORT,() => {
    console.log("sever is running on "+ process.env.PORT)
});



