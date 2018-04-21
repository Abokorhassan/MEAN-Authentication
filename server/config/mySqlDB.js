const mysql = require('mysql')
const config = require('./config.js')

var con = mysql.createConnection( {
    host:config.mysqlhost,
    port:3306,
    user:config.mysqluser,
    password:config.mysqlpassword,
    database:config.mysqldb
}, (err)=>{
  if(err) throw err
  console.log("mysql connected!")
})

con.connect(function(err) {
    if (err) {
        console.log(err)
        throw err
    } 
    console.log("mysql connected!")
})

module.exports=con