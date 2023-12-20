const express = require('express')
const cors = require('cors')
const dotenv = require('dotenv');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const mysql =require('mysql')
const app = express();

//middlewares
app.use(cors());
app.use(bodyParser.json());

//configure env
dotenv.config();

//setup connection
const con = mysql.createConnection({
    user: process.env.USER,
    host: process.env.HOST,
    password: process.env.PASSWORD,
    database: process.env.DATABASE
})
if(con){
    console.log('connection sucessful');
}else{
    console.log('connection failed');
}

//signup route
app.post("/signup",(req,res)=>{
    const { username, email,phoneNumber, password } = req.body;
    
    con.query('SELECT * FROM users WHERE email = ?', [email], async (error, results) => {
        if(error){
            console.error('Error checking preexistence of email : ', error);
            res.status(500).json({ success : false, message : 'failed to check for preexistence of email'});
        } else {
            if(results.length > 0){
                // this email already exists
                console.error('Error: User already registered');
                res.status(500).json({ success : false, message : 'User already registered'});
            } else {
                await bcrypt.hash(password, 10, (error, hash)=>{

                    if(error){

                        console.error('Error generating hash: ', error);
                        res.status(500).json({ success: false, message : 'Error Generating Hash'});
                    } else {
                        const query = 'INSERT INTO users (username, email,phoneNumber,password) VALUES (?, ?, ?, ?)';
                        con.query(query, [username, email,phoneNumber, hash], (error, results)=>{
                            if(error){
                                console.error('Error Inserting User: ', error);

                                res.status(500).json({ success : false, message : 'Error Inserting User' });
                            } else {
                                console.log('User Inserted successfully');
                                res.status(201).json({ success: true, message: 'User Inserted Successfully' })
                            }
                        })
                    }
                });

                
            }   
        }
    })
})

//login route
app.post("/login", async (req,res)=>{
        const { email, password } = req.body;
        const query = 'SELECT * FROM users WHERE email = ?';
        await con.query(query, [email], async (error, results) => {
            if (error) {
                console.log('err1');
                console.error('Error executing login query: ', error);
                res.status(500).json({ success: false, message: 'Internal Server Error' });
            } else {
                if (results.length > 0) {
                    await bcrypt.compare(password, results[0].password, (errormatch, passwordmatch)=>{
                        if(errormatch){
                            console.log('invalid creds');
                            res.status(500).json({ success: false, message: 'invalid credentials'});
                        } else {
                            if(passwordmatch){
                                res.status(200).json({ success: true, message: 'Login successful', welcomeMsg : 'Welcome ' + results[0].username.toUpperCase() + '!'});
                            } else {
                                res.status(500).json({ success: false, message: 'Invalid credentials'});
                            }
                        }
                    })
                } else {
                    // Invalid credentials
                    res.status(500).json({ success: false, message: 'no such user exists please register' });
                }
            }
        });
    }
)


app.listen(process.env.PORT || 5000, (req, res)=>{
    console.log(`Server started on Port ${process.env.PORT || 5000}`)
})