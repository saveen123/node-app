const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt')

const app = express();
app.use(express.json());
app.use(cors());

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'admin',
  database: 'mydb',
  password: 'admin'
});

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to MySQL:', err.message);
    process.exit(1); // Exit if connection fails
  }
  console.log('Connected to MySQL database');
});

async function compareHash(data){
    
}

async function hashdData(data){
    try{
        const res = await bcrypt.hash(data, 10);
        return res;
    }catch(err){
        console.log('Hashing error')
    }
}

function findUser(email){
    connection.query('SELECT * FROM `user` WHERE email = ?',[email],(err,res)=>{
        return res[0];
    })
}

function insertData(email, pass){
    connection.query(
        'INSERT INTO `user` (email,password) VALUES (?,?)',[email, pass],
        function (err, results, fields) {
        
        }
    );

}


app.get('/',(req,res)=>{
    const {email, password} = req.body;
    res.send('api working')
    console.log(findUser(email))
    
})
app.listen(3000,()=>{
    console.log('server up and running')
})

