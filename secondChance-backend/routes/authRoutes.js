const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const logger = require('../logger.js')

const connectToDatabase = require('../models/db.js')

const router = express.Router()

router.post('/register', async (req, res) => {
    
    try {
        const db = await connectToDatabase()
        const collection = await db.collection('users')

        const {email, password, firstName, lastName } = req.body

        const user = await collection.findOne({email: req.body.email})
        if(user){
            logger.error('User already exist')
            return res.status(400).json({error: 'User already exist.'})
        }
        
        const salt = await bcrypt.genSalt(10)
        const hashed_password = await bcrypt.hash(password, salt)

        const data = await collection.insertOne({
            email: email,
            password: hashed_password,
            firstName: firstName,
            lastName: lastName,
            createdAt: new Date().toDateString()
        })

        const JWT_SECRET = proces.env.JWT_SECRET
        const payload = {
            user: {
                id: data.insertedId
            }
        }
        const token = jwt.sign(payload, JWT_SECRET, {expiresIn: '24h'})

        logger.log('User successfully registered.')
        res.status(200).json({email: email, token: token})
        
    } catch (error) {
        logger.error('Error when register: ' + error)
        res.status(500).json({error: 'Error when register: ' + error})
    }

})

module.exports = router