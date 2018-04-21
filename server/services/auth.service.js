const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const User = require('../models/user')
const config = require('../config/config')
const authSvc = {}
const mySqlDb = require("../config/mySqlDB")

module.exports = authSvc



//define functions





authSvc.register = function(req, res){
    let user = req.body
    mySqlDb.query('select email from users where email = ?', [user.email], (err, rows) =>{
        if(err){
            console.log(err)
            res.status(401).send("registration failed")
        }else{
            if(rows.length === 0){
                let hash = authSvc.createHash(user.password)
                mySqlDb.query('insert into users (email, password) values(?, ?)', [user.email, hash], (err, rows) =>{
                    if(err){
                        console.log(err)
                        res.status(401).send("registration failed")
                    }else{
                        mySqlDb.query('select ID from users where email = ?', [user.email], (err, row) =>{
                            if(err){
                                console.log(err)
                                res.status(401).send("registration failed")
                            }else{
                                let token = authSvc.createToken(row[0])
                                res.status(200).send({token})
                            }
                        })
                    }
                })
            }else{
                res.status(401).send("user already exist")
            }
        }
    })
}
    



authSvc.login = function(req, res){
    let user = req.body
    mySqlDb.query('select * from users where email = ?', [user.email], (err, row) =>{  
       if(err){
        console.log(err)
        res.status(401).send("login failed")
       }else{
           if(row.length !== 0){
                if(bcrypt.compareSync(user.password, row[0].password)){
                    let token = authSvc.createToken(row[0].ID)
                    res.status(200).send({ token })
                }else{
                    res.status(401).send("unauthorized")
                }
           }else{
            res.status(401).send("unauthorized")
           }
       }
    })
}

authSvc.createHash = function(password){
  return bcrypt.hashSync(password, 10)
}

authSvc.createToken = function(userId){
    return jwt.sign({ user: userId }, config.secretKey)
}
